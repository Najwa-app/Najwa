// Real browser → Rust → embedded Arti → onion mailbox → independent Rust → browser.
import { chromium } from '@playwright/test';
import { spawn } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';
const [executable,onion,profileA,profileB,output] = process.argv.slice(2);
if (!executable || !/^[a-z2-7]{56}\.onion$/.test(onion) || !profileA || !profileB || !output) throw new Error('expected executable, onion, two synthetic profiles and report directory');
await mkdir(output,{recursive:true});
const password = 'synthetic release orchard lantern';
const report = {startedAt:new Date().toISOString(),mailbox:onion,stages:[],messages:[],checks:[]};
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
  let diagnostics=''; child.stderr.on('data',data => {diagnostics=(diagnostics+data.toString()).slice(-4000);}); child.stdout.resume();
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
  // Model an active test operator while slow Tor setup is under observation.
  // Production idle locking is unchanged; close/quit stops this test heartbeat.
  peer.activityTimer=setInterval(async()=>{
    if(process.env.NAJWA_LARGE_FILES==='1') return;
    if(!peer.page || peer.page.isClosed()) return;
    try { const id=await peer.identity(); if(id.phase==='unlocked') await peer.api('/api/activity',{session:id.session,generation:id.generation}); } catch {}
  },30_000);
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
    await page.locator('.words li').nth(23).waitFor();
    const recoveryWords=await page.locator('.words li').allTextContents();
    const download=page.waitForEvent('download');
    await page.getByRole('button',{name:'Download recovery file',exact:true}).click(); await download;
    await page.getByLabel('I saved the words somewhere safe.').check();
    await page.getByRole('button',{name:'Check my recovery words'}).click();
    await page.locator('.word-check input').nth(2).waitFor();
    const labels=await page.locator('.word-check label').allTextContents();
    for(let i=0;i<labels.length;i++) await page.locator('.word-check input').nth(i).fill(recoveryWords[Number(labels[i].match(/\d+/)[0])-1]);
    await page.getByRole('button',{name:'Check words',exact:true}).click();
    await page.getByRole('button',{name:'I’ve saved both — continue'}).click();
  } else {
    await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
    await page.getByLabel('Passphrase',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Unlock Najwa',exact:true}).click();
  }
  await until(async () => (await peer.identity()).phase === 'unlocked',`${peer.name} unlock`,120_000);
  const id=await peer.identity(); peer.fingerprint=id.fingerprint;
  if(process.env.NAJWA_LARGE_FILES==='1') await page.getByRole('checkbox',{name:'Keep unlocked',exact:true}).check();
  return page;
}
async function register(peer) {
  await until(async () => (await peer.network()).connection === 'connected',`${peer.name} embedded Tor`,900_000);
  await peer.page.getByLabel('Tor v3 mailbox',{exact:true}).fill(onion);
  let success=false;
  for(let attempt=0;attempt<3;attempt++) {
    const response=peer.page.waitForResponse(async response => {
      if(!response.url().endsWith('/api/invoke')) return false;
      try { return response.request().postDataJSON()?.args?.request?.operation?.kind === 'add_mailbox' && (await response.json()).error?.code !== 'busy'; } catch { return false; }
    },{timeout:660_000});
    if(attempt===0) await peer.page.getByRole('button',{name:'Add mailbox',exact:true}).click();
    else {
      await peer.page.getByRole('button',{name:'Settings',exact:true}).click();
      await peer.page.getByRole('button',{name:'Retry registration',exact:true}).click();
    }
    const result=await (await response).json();
    if(!result.error) { success=true; break; }
    await progress(`${peer.name} registration attempt ${attempt+1}: ${result.error.code}`);
    // The mailbox is registered and enabled before prekeys are published; a
    // failed publication returns sync_failed and every receive poll retries it.
    if(result.error.code==='sync_failed') { success=true; break; }
    if(!['busy','registration_transport','registration_limited','registration_pow','not_connected'].includes(result.error.code)) throw result.error;
    await delay(2000);
  }
  if(!success) throw new Error(`${peer.name} mailbox registration could not complete after three attempts`);
  await until(async () => {
    const network=await peer.network(); return network.mailboxDetails?.some(box => box.onion===onion && box.registered);
  },`${peer.name} mailbox registration`,600_000);
  await peer.page.getByRole('button',{name:'Chats',exact:true}).click();
  await peer.page.getByRole('button',{name:'Create an invitation',exact:true}).waitFor();
}
async function choose(peer,contact) {
  await peer.page.getByRole('button',{name:'Chats',exact:true}).click();
  const row=peer.page.locator('.conversation').filter({hasText:contact.name});
  await row.click(); await peer.page.getByLabel('Write a message').waitFor();
}
async function send(sender,receiver,contact,text,label) {
  await sender.page.bringToFront();
  const started=performance.now();
  await sender.page.getByLabel('Write a message').fill(text);
  await sender.page.getByRole('button',{name:'Send message',exact:true}).click();
  await receiver.page.bringToFront();
  await receiver.page.getByText(text,{exact:true}).and(receiver.page.locator('.message-text')).waitFor({timeout:300_000});
  const latencyMs=Math.round(performance.now()-started);
  report.messages.push({label,latencyMs});
  await until(async () => (await sender.operation({kind:'messages',contact:contact.id})).some(message => message.text===text && (process.env.NAJWA_READ_RECEIPTS==='1' ? message.status==='read' : ['delivered','read'].includes(message.status))),`${label} receipt`,240_000);
  await progress(`${label}: visible in ${latencyMs} ms; encrypted receipt confirmed`);
}
let a,b,browser,contextA,contextB;
try {
  await progress('Starting independent persistent native profiles');
  a=await launch(profileA,'Alice'); b=await launch(profileB,'Bob');
  browser=await chromium.launch({channel:process.env.NAJWA_BROWSER_CHANNEL || 'msedge'});
  contextA=await browser.newContext({viewport:{width:1280,height:800}}); contextB=await browser.newContext({viewport:{width:1280,height:800}});
  await open(a,contextA,true); await open(b,contextB,true);
  await progress('Both identities created through the real browser recovery-kit flow');
  await Promise.all([register(a),register(b)]);
  await progress('Both mailboxes registered through embedded Arti on public Tor');
  await a.page.getByRole('button',{name:'Create an invitation',exact:true}).click();
  await a.page.getByLabel('Your display name to share').fill('Alice Release');
  await a.page.getByRole('button',{name:'Generate invitation',exact:true}).click();
  await progress('Generating signed invitation through Alice’s mailbox');
  const invitation=await Promise.race([
    a.page.getByLabel('Invitation to share').inputValue({timeout:660_000}),
    a.page.locator('dialog .messenger-error').waitFor({timeout:660_000}).then(async()=>{throw new Error(`invitation: ${await a.page.locator('dialog .messenger-error').textContent()}`);})
  ]);
  let qrImage;
  if(process.env.NAJWA_CONTACT_FEATURES === '1') {
    qrImage=path.join(output,'invitation-qr.png');
    await a.page.locator('.invitation-qr img').screenshot({path:qrImage});
  }
  await a.page.getByRole('button',{name:'Close',exact:true}).click();
  if(process.env.NAJWA_ASYNC_CONTACT_SETUP === '1') {
    const {verifyAsynchronousContact}=await import('./async-contact.mjs');
    await verifyAsynchronousContact({a,b,invitation,qrImage,contextA,contextB},{launch,quit,open,until,progress,report,replaceA:peer=>a=peer,replaceB:peer=>b=peer});
  } else {
    await b.page.getByRole('button',{name:'Add a contact',exact:true}).click();
    await b.page.getByLabel('Your display name to share').fill('Bob Release');
    await b.page.getByLabel('Signed invitation').fill(invitation);
    await b.page.getByRole('button',{name:'Accept invitation',exact:true}).click();
  }
  const contacts=await until(async () => {
    const aa=await a.operation({kind:'contacts'}),bb=await b.operation({kind:'contacts'});
    return aa[0]?.ready && bb[0]?.ready ? [aa[0],bb[0]] : null;
  },'reciprocal encrypted contact setup',900_000);
  if(contacts[0].safetyNumber!==contacts[1].safetyNumber) throw new Error('safety numbers differ');
  report.checks.push('Matching safety numbers after reciprocal contact setup');
  if(process.env.NAJWA_SECOND_MAILBOX) {
    const {verifyMultipleMailboxes}=await import('./multi-mailbox.mjs');
    await verifyMultipleMailboxes(a,{onion,output,report,until,delay,progress});
  }
  await choose(a,contacts[0]); await choose(b,contacts[1]);
  const marker=Date.now();
  await progress('Contact setup complete; measuring real browser delivery');
  await send(a,b,contacts[0],`Release A to B ${marker}`,'Alice to Bob');
  await send(b,a,contacts[1],`Release B to A ${marker}`,'Bob to Alice');
  if(process.env.NAJWA_READ_RECEIPTS==='1') {
    const {verifyOfflineReadReceipts}=await import('./read-receipts.mjs');
    await verifyOfflineReadReceipts(a,b,contacts,{choose,until,progress,report,quit,launch,open,contextA,replaceA:peer=>a=peer});
  }
  await a.page.screenshot({path:path.join(output,'alice-conversation.png')});
  await b.page.screenshot({path:path.join(output,'bob-conversation.png')});
  if(process.env.NAJWA_LARGE_FILES==='1') {
    const {verifyLargeTransfers}=await import('./large-files.mjs');
    await verifyLargeTransfers(a,b,contacts,{output,report,until,progress,choose,quit,launch,open,contextA,contextB,replaceA:peer=>a=peer,replaceB:peer=>b=peer});
  } else {
  const originalFingerprint=b.fingerprint;
  await b.page.close(); await quit(b);
  let attachment;
  if(process.env.NAJWA_CONTACT_FEATURES === '1') {
    const {prepareOfflineFeatures}=await import('./contact-features.mjs');
    attachment=await prepareOfflineFeatures(a,b,contacts[0],{until,progress,report});
  }
  const offlineText=`Offline delivery after restart ${marker}`;
  await a.page.getByLabel('Write a message').fill(offlineText);
  await a.page.getByRole('button',{name:'Send message',exact:true}).click();
  await until(async () => (await a.operation({kind:'messages',contact:contacts[0].id})).some(message => message.text===offlineText && message.status==='deposited'),'offline mailbox deposit',300_000);
  await progress('Bob stopped; Alice’s offline message deposited in the mailbox');
  b=await launch(profileB,'Bob after restart'); await open(b,contextB,false);
  if(b.fingerprint!==originalFingerprint) throw new Error('identity changed across process restart');
  await until(async () => (await b.network()).connection==='connected','restored Tor connection',900_000);
  const restored=await until(async () => (await b.operation({kind:'contacts'})).find(contact => contact.ready),'restored contact');
  await choose(b,restored);
  await b.page.getByText(offlineText,{exact:true}).and(b.page.locator('.message-text')).waitFor({timeout:300_000});
  await b.page.getByText(`Release A to B ${marker}`,{exact:true}).and(b.page.locator('.message-text')).waitFor();
  report.checks.push('Persistent identity, contacts, message history and queued offline delivery survived restart');
  await send(b,a,restored,`Reply after restart ${marker}`,'Bob after restart to Alice');
  if(process.env.NAJWA_CONTACT_FEATURES === '1') {
    const {finishOfflineFeatures}=await import('./contact-features.mjs');
    await finishOfflineFeatures(a,b,contacts[0],restored,attachment,{until,progress,report,quit,launch,open,contextA,replaceA:peer=>a=peer});
  }
  }
  report.passed=true; report.finishedAt=new Date().toISOString();
  await progress('PASS: real browser messaging, receipts and persistent restart verified');
} catch(error) {
  report.passed=false; report.error=error?.message ?? error?.code ?? String(error);
  await progress(`FAIL: ${report.error}`);
  for(const peer of [a,b]) if(peer?.page && !peer.page.isClosed()) await peer.page.screenshot({path:path.join(output,`${peer.name.replace(/\W/g,'-')}-failure.png`)}).catch(()=>{});
  process.exitCode=1;
} finally {
  await quit(a); await quit(b); if(browser) await browser.close();
  await writeFile(path.join(output,'result.json'),JSON.stringify(report,null,2));
}
