// Real browser → Rust → embedded Arti → onion mailbox → independent Rust → browser.
import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import {createWriteStream} from 'node:fs';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
const [executable,onion,profileA,profileB,output] = process.argv.slice(2);
if (!executable || !/^[a-z2-7]{56}\.onion$/.test(onion) || !profileA || !profileB || !output) throw new Error('expected executable, onion, two synthetic profiles and report directory');
await mkdir(output,{recursive:true});
const password = 'synthetic release orchard lantern';
const report=JSON.parse(await readFile(path.join(output,'result.json'),'utf8'));
report.continuedAt=new Date().toISOString();
async function progress(stage) {
  report.stages.push({stage,at:new Date().toISOString()});
  console.log(stage);
  await writeFile(path.join(output,'result.json'),JSON.stringify(report,null,2));
}
const delay = ms => new Promise(resolve => setTimeout(resolve,ms));
async function until(check,description,timeout=300_000) {
  const deadline=Date.now()+timeout;
  let last;
  while (Date.now()<deadline) {
    try { const value=await check(); if(value) return value; } catch(error) { last=error?.code ?? error?.message; }
    await delay(1000);
  }
  throw new Error(`${description} timed out${last ? ` (${last})` : ''}`);
}
async function freePort() {
  const server=createServer(); await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
async function launch(profile,name) {
  const port=await freePort();
  const child=spawn(executable,['--no-browser','--profile',profile,'--port',String(port)],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  let diagnostics=''; child.stderr.on('data',data => {diagnostics=(diagnostics+data.toString()).slice(-4000);}); child.stdout.pipe(createWriteStream(path.join(output,`${path.basename(profile)}-${Date.now()}.stdout.log`)));child.stderr.pipe(createWriteStream(path.join(output,`${path.basename(profile)}-${Date.now()}.stderr.log`)));
  let instance;
  await until(async () => {
    if (child.exitCode !== null) throw new Error(`${name} exited: ${diagnostics}`);
    instance=JSON.parse(await readFile(path.join(profile,'web-instance.json'),'utf8'));
    return instance.port === port;
  },`${name} startup`,30_000);
  const peer={name,profile,child,origin:`http://127.0.0.1:${port}`,token:instance.token,instance};
  peer.api=async (route,body) => {
    const response=await fetch(peer.origin+route,{method:body===undefined?'GET':'POST',headers:{'X-Najwa-Session':peer.token,...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)}),signal:AbortSignal.timeout(660_000)});
    const result=await response.json(); if(!response.ok) throw {code:`http_${response.status}`}; if(result.error) throw result.error; return result.ok;
  };
  peer.identity=() => peer.api('/api/status');
  peer.network=() => peer.api('/api/invoke',{command:'messaging_status',args:{}});
  peer.operation=async operation => { const id=await peer.identity(); return peer.api('/api/invoke',{command:'messaging_request',args:{request:{session:id.session,generation:id.generation,operation}}}); };
  return peer;
}
async function quit(peer) {
  if (!peer) return;
  clearInterval(peer.activityTimer);
  if (peer.child.exitCode !== null) return;
  try { const id=await peer.identity(); await peer.api('/api/quit',{session:id.session,generation:id.generation}); await until(() => peer.child.exitCode!==null,'app quit',10_000); }
  catch { peer.child.kill(); }
}
async function open(peer,context,create) {
  const page=await context.newPage(); page.setDefaultTimeout(120_000); peer.page=page;
  await page.goto(`${peer.origin}/#${peer.token}`);
  if (create) {
    await page.getByLabel('New passphrase',{exact:true}).fill(password);
    await page.getByLabel('Confirm passphrase').fill(password);
    await page.getByRole('button',{name:'Create my identity',exact:true}).click();
    await page.getByRole('heading',{name:'Save your recovery kit.'}).waitFor();
    await page.getByRole('button',{name:'Reveal recovery words'}).click();
    const download=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download recovery file',exact:true}).click(); await download;
    await page.getByLabel('I saved the words somewhere safe.').check();
    await page.getByRole('button',{name:'I’ve saved both — continue'}).click();
  } else {
    await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
    await page.getByLabel('Passphrase',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Unlock Najwa',exact:true}).click();
  }
  await until(async () => (await peer.identity()).phase === 'unlocked',`${peer.name} unlock`,120_000);
  const id=await peer.identity(); peer.fingerprint=id.fingerprint;
  await page.getByRole('checkbox',{name:'Keep unlocked',exact:true}).check();
  return page;
}
async function choose(peer,contact) {
  await peer.page.getByRole('button',{name:'Chats',exact:true}).click();
  if(!contact.name) contact=(await peer.operation({kind:'contacts'})).find(c=>c.id===contact.id);
  if(!contact)throw new Error('saved test contact missing');
  const row=peer.page.locator('.conversation').filter({hasText:contact.name});
  await row.click(); await peer.page.getByLabel('Write a message').waitFor();
}
let a,b,browser,contextA,contextB;
try {
  await progress('Continuing the exact 256 MiB test from durable profiles on the final package');
  a=await launch(profileA,'Alice continued');b={profile:profileB,child:{exitCode:0}};
  browser=await chromium.launch({channel:process.env.NAJWA_BROWSER_CHANNEL || 'msedge'});
  contextA=await browser.newContext({viewport:{width:1280,height:800}});contextB=await browser.newContext({viewport:{width:1280,height:800}});
  await open(a,contextA,false);const contact=(await a.operation({kind:'contacts'})).find(c=>c.ready);if(!contact)throw new Error('saved contact not ready');
  await choose(a,contact);
  const {continueLargeTransfers}=await import('./large-files.mjs');
  await continueLargeTransfers(a,b,[contact,{id:'1'}],{output,report,until,progress,choose,quit,launch,open,contextA,contextB,replaceA:peer=>a=peer,replaceB:peer=>b=peer});
  delete report.error;report.passed=true;report.finishedAt=new Date().toISOString();await progress('PASS: exact-limit offline transfer, persistent resume and final browser integrity');
} catch(error){report.passed=false;report.error=error?.message ?? error?.code ?? String(error);await progress(`FAIL: ${report.error}`);process.exitCode=1;
} finally {await quit(a);await quit(b);if(browser)await browser.close();await writeFile(path.join(output,'result.json'),JSON.stringify(report,null,2));}
