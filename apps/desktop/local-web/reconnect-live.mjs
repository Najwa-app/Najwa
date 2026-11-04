// Isolated finished-package check. Never attaches to a user's browser or profile.
import { chromium, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { once } from 'node:events';

const executable = resolve(process.argv[2] ?? '');
if (!process.argv[2]) throw new Error('Supply the packaged Najwa executable.');
const root = await mkdtemp(resolve('../../target/browser-reconnect-live-'));
const results = [];
for (const channel of ['chrome','msedge']) {
  const server = createServer();
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const profile = join(root,channel);
  let child, record, browser;
  async function start() {
    child = spawn(executable,['--no-browser','--profile',profile,'--port',String(port)],{stdio:'ignore',windowsHide:true});
    const deadline = Date.now()+15_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error('Synthetic service exited during startup.');
      try {
        const candidate = JSON.parse(await readFile(join(profile,'web-instance.json'),'utf8'));
        const response = await fetch(origin+'/api/status',{headers:{'X-Najwa-Session':candidate.token}});
        if (!response.ok) throw new Error('Waiting for current instance.');
        const status = await response.json();
        if (status.ok.session !== candidate.session) throw new Error('Instance mismatch.');
        record = candidate; return;
      } catch { await delay(100); }
    }
    throw new Error('Synthetic service did not become available.');
  }
  async function stop() {
    if (!child || child.exitCode !== null) return;
    const response = await fetch(origin+'/api/status',{headers:{'X-Najwa-Session':record.token}});
    const {ok:status} = await response.json();
    const stopped = once(child,'exit');
    const quit = await fetch(origin+'/api/quit',{method:'POST',headers:{'Content-Type':'application/json','X-Najwa-Session':record.token},body:JSON.stringify({session:status.session,generation:status.generation})});
    if (!quit.ok || (await quit.json()).error) throw new Error('Synthetic service refused graceful quit.');
    await stopped;
  }
  try {
    await start();
    browser = await chromium.launch({channel});
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(origin);
    await expect(page.getByRole('heading',{name:'Connect this browser',exact:true})).toBeVisible();
    // A same-document navigation used to leave the rejected promise cached.
    await page.goto(origin+'/#'+record.token);
    await expect(page.getByRole('heading',{name:'Make yourself at home.'})).toBeVisible();
    expect(new URL(page.url()).hash).toBe('');
    const cookie = (await context.cookies(origin+'/api/bootstrap')).find(cookie => cookie.name === `Najwa-Launch-${port}`);
    expect(cookie?.httpOnly).toBe(true); expect(cookie?.sameSite).toBe('Strict');
    expect(cookie?.expires).toBeGreaterThan(Date.now()/1000);
    expect(cookie?.value).not.toBe(record.token);
    await page.getByLabel('New passphrase',{exact:true}).fill('unfinished local passphrase');
    const oldSession = record.session;
    await stop(); await start();
    expect(record.session).not.toBe(oldSession);
    await expect(page.getByLabel('New passphrase',{exact:true})).toHaveValue('',{timeout:15_000});
    await expect(page.getByRole('alert')).toHaveCount(0);
    await page.reload();
    await expect(page.getByRole('heading',{name:'Make yourself at home.'})).toBeVisible();
    expect(await page.evaluate(() => [localStorage.length,sessionStorage.length])).toEqual([0,0]);
    const stranger = await browser.newContext();
    const unpaired = await stranger.newPage(); await unpaired.goto(origin);
    await expect(unpaired.getByRole('heading',{name:'Connect this browser',exact:true})).toBeVisible();
    await stranger.close(); await context.close();
    results.push({browser:channel,passed:true,recoveredWhileOpen:true,reloadedWithoutGrant:true,unpairedRejected:true});
  } finally {
    await browser?.close();
    try { await stop(); } catch { child?.kill(); }
  }
}
await writeFile(join(root,'result.json'),JSON.stringify({passed:true,results},null,2));
console.log(JSON.stringify({passed:true,results,report:join(root,'result.json')}));
