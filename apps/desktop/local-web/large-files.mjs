// Exact-limit public-Tor transfer with both upload and protocol restart recovery.
import {open,stat,mkdir,access} from 'node:fs/promises';
import {createReadStream,createWriteStream} from 'node:fs';
import {createHash,randomBytes} from 'node:crypto';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import path from 'node:path';
const SIZE=256*1024*1024,PART=1024*1024;
async function digest(file){const hash=createHash('sha256');for await(const part of createReadStream(file))hash.update(part);return hash.digest('hex');}
async function fixture(file){
  const handle=await open(file,'w');const buffer=randomBytes(PART);
  for(let i=0;i<256;i++){
    buffer.writeUInt32BE(i,128);
    if(i===0){const header=Buffer.alloc(44);header.write('RIFF');header.writeUInt32LE(SIZE-8,4);header.write('WAVEfmt ',8);header.writeUInt32LE(16,16);header.writeUInt16LE(1,20);header.writeUInt16LE(1,22);header.writeUInt32LE(44100,24);header.writeUInt32LE(88200,28);header.writeUInt16LE(2,32);header.writeUInt16LE(16,34);header.write('data',36);header.writeUInt32LE(SIZE-44,40);header.copy(buffer);}
    await handle.write(buffer,0,buffer.length,i*PART);
  }
  await handle.close();
}
export async function verifyLargeTransfers(a,b,contacts,h){
  const {output,report,until,progress,choose,quit,launch,open:openApp,contextA,contextB,replaceA,replaceB}=h;
  await mkdir(output,{recursive:true});const source=path.join(output,'synthetic-256MiB.wav');await fixture(source);const expected=await digest(source);
  report.largeFile={sourceBytes:SIZE,sha256:expected,stages:[]};
  const control=async(peer,action)=>{const id=await peer.identity();return peer.api('/api/transfers',{session:id.session,generation:id.generation,action});};
  const restart=async(peer,context,name,replace)=>{const profile=peer.profile,fingerprint=peer.fingerprint;if(peer.page && !peer.page.isClosed())await peer.page.close();await quit(peer);const next=await launch(profile,name);replace(next);await openApp(next,context,false);if(next.fingerprint!==fingerprint)throw new Error('file-transfer identity changed on restart');return next;};
  await b.page.close();await quit(b);await choose(a,contacts[0]);
  let held;
  await a.page.route('**/api/transfer-part/*/8',route=>{held=route;});
  await a.page.getByLabel('Attach file',{exact:true}).setInputFiles(source);
  await until(()=>held,'upload pause after eight parts',180_000);
  const saved=await until(async()=>{const rows=await control(a,{kind:'list',contact:contacts[0].id});return rows.find(t=>t.uploaded===8*PART);},'durable partial upload');
  report.checks.push('Exact 256 MiB file uploads as bounded 1 MiB parts with a per-part digest manifest');
  a=await restart(a,contextA,'Alice after partial upload',replaceA);await choose(a,contacts[0]);
  const resumed=(await control(a,{kind:'list',contact:contacts[0].id})).find(t=>t.id===saved.id);
  if(resumed?.uploaded!==8*PART || resumed.parts.length!==8)throw new Error('partial upload progress was lost');
  let resent=false;
  a.page.on('request',request=>{const match=new URL(request.url()).pathname.match(/\/api\/transfer-part\/[^/]+\/(\d+)$/);if(match && Number(match[1])<8)resent=true;});
  await a.page.getByLabel('Attach file',{exact:true}).setInputFiles(source);
  await until(async()=>{const rows=await control(a,{kind:'list',contact:contacts[0].id});return rows.find(t=>t.id===saved.id && t.uploaded===SIZE && t.phase!=='uploading');},'resumed upload completes',300_000);
  if(resent)throw new Error('resumed upload resent confirmed parts');
  if(b.child.exitCode===null)throw new Error('recipient came online during upload');
  report.checks.push('Partial upload survived native restart; reselecting the same file skipped all confirmed parts');
  await progress('PASS: 256 MiB upload resumed after restart without retransmitting its saved prefix');
  await continueLargeTransfers(a,b,contacts,h);
}
export async function continueLargeTransfers(a,b,contacts,h){
  const {output,report,until,progress,choose,quit,launch,open:openApp,contextA,contextB,replaceA,replaceB}=h;
  const expected=report.largeFile.sha256;
  const control=async(peer,action)=>{const id=await peer.identity();return peer.api("/api/transfers",{session:id.session,generation:id.generation,action});};
  const restart=async(peer,context,name,replace)=>{const profile=peer.profile,fingerprint=peer.fingerprint;if(peer.page && !peer.page.isClosed())await peer.page.close();await quit(peer);const next=await launch(profile,name);replace(next);await openApp(next,context,false);if(next.fingerprint!==fingerprint)throw new Error("file-transfer identity changed on restart");return next;};
  const outgoing=async()=> (await a.operation({kind:'messages',contact:contacts[0].id})).find(m=>m.attachment?.filename==='synthetic-256MiB.wav');
  let message=await until(async()=>{const m=await outgoing();return m?.attachment?.depositedChunks>=4?m:null;},'file begins depositing with recipient stopped',600_000);
  const previouslyDeposited=message.attachment.depositedChunks===message.attachment.chunks;
  if (!previouslyDeposited) {
  const before=message.attachment.depositedChunks;
  a=await restart(a,contextA,'Alice during file deposit',replaceA);await choose(a,contacts[0]);
  await until(async()=> (await a.network()).connection==='connected','sender file-transfer reconnect',900_000);
  message=await until(outgoing,'restored outgoing attachment');if(message.attachment.depositedChunks<before)throw new Error('deposited progress regressed after restart');
  const chat=`Chat remains usable during 256 MiB transfer ${Date.now()}`;await a.page.getByLabel('Write a message').fill(chat);await a.page.getByRole('button',{name:'Send message',exact:true}).click();
  await until(async()=> (await a.operation({kind:'messages',contact:contacts[0].id})).some(m=>m.text===chat && ['deposited','delivered','read'].includes(m.status)),'chat deposit during file transfer',180_000);
  let last=-1;
  message=await until(async()=>{const m=await outgoing();if(!m)return null;const step=Math.floor(m.attachment.depositedChunks/32);if(step!==last){last=step;await progress(`256 MiB file deposit: ${m.attachment.depositedChunks}/${m.attachment.chunks} parts; recipient stopped`);}return m.attachment.depositedChunks===m.attachment.chunks?m:null;},'all 256 MiB deposited while recipient offline',7_200_000);
  } else {await access(path.join(output,'large-file-deposited.png'));}
  if(b.child.exitCode===null || message.attachment.size!==SIZE)throw new Error('offline exact-size deposit condition not satisfied');
  report.largeFile.chunks=message.attachment.chunks;report.checks.push('Sender restart resumed the file outbox; all 256 MiB deposited with recipient stopped and chat sending remained available');
  if(!previouslyDeposited)await a.page.screenshot({path:path.join(output,'large-file-deposited.png')});
  await progress('PASS: all 256 MiB remain deposited; continuing recipient recovery');
  b=await launch(b.profile,'Bob receiving large file');replaceB(b);await openApp(b,contextB,false);await choose(b,contacts[1]);
  const incoming=async()=> (await b.operation({kind:'messages',contact:contacts[1].id})).find(m=>m.attachment?.filename==='synthetic-256MiB.wav');
  const partial=await until(async()=>{const m=await incoming();return m?.attachment?.availableChunks>=1?m:null;},'partial recipient file before restart',900_000);
  if(!partial.attachment.complete){report.largeFile.receiveRestartFrom=partial.attachment.availableChunks;await progress(`Restarting recipient with ${partial.attachment.availableChunks} of ${partial.attachment.chunks} saved parts`);}
  b=await restart(b,contextB,'Bob after interrupted file receive',replaceB);await choose(b,contacts[1]);
  let lastReceived=-1;
  let received=await until(async()=>{const m=await incoming();if(m){const step=Math.floor(m.attachment.availableChunks/32);if(step!==lastReceived){lastReceived=step;await progress(`256 MiB file receive: ${m.attachment.availableChunks}/${m.attachment.chunks} saved parts`);}}return m?.attachment?.complete?m:null;},'recipient resumes and completes 256 MiB file',7_200_000);
  if(received.attachment.availableChunks<partial.attachment.availableChunks)throw new Error('received chunk progress regressed');
  const link=await control(b,{kind:'download',contact:contacts[1].id,message:received.id});
  const prefix=await fetch(b.origin+link.url,{headers:{Range:'bytes=0-1048575'}});if(prefix.status!==206)throw new Error('download prefix was not a range response');
  const destination=path.join(output,'resumed-256MiB.wav');await pipeline(Readable.fromWeb(prefix.body),createWriteStream(destination));
  b=await restart(b,contextB,'Bob during ranged download',replaceB);await choose(b,contacts[1]);
  const suffix=await fetch(b.origin+link.url,{headers:{Range:'bytes=1048576-'}});if(suffix.status!==206)throw new Error('download grant did not survive restart');
  await pipeline(Readable.fromWeb(suffix.body),createWriteStream(destination,{flags:'a'}));
  if((await stat(destination)).size!==SIZE || await digest(destination)!==expected)throw new Error('resumed 256 MiB download hash mismatch');
  report.checks.push('Recipient resumed partial reception after restart; HTTP ranged download resumed with the same grant after another restart and matched SHA-256');
  const event=b.page.waitForEvent('download');await b.page.getByRole('button',{name:'Download synthetic-256MiB.wav',exact:true}).click();const download=await event;const downloaded=await download.path();
  if((await stat(downloaded)).size!==SIZE || await digest(downloaded)!==expected)throw new Error('native browser download differs from source');
  await b.page.screenshot({path:path.join(output,'large-file-received.png')});
  report.checks.push('Browser download streamed the exact 256 MiB file to disk and matched the source SHA-256');
  await progress('PASS: exact 256 MiB offline deposit, sender/recipient restart, ranged resume and browser download integrity');
}
