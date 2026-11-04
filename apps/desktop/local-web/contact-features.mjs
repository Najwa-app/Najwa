// Destructive controls are exercised only against the harness's fresh profiles.
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {deflateSync} from 'node:zlib';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
function multiChunkPng() {
  // Deterministic synthetic pixels, so sanitization still leaves several real
  // transport chunks. No external/user image or metadata enters this fixture.
  const width=1536,height=1536,rows=Buffer.alloc((width*3+1)*height);let seed=173;
  for(let y=0;y<height;y++) for(let x=1;x<=width*3;x++) {seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;rows[y*(width*3+1)+x]=seed&255;}
  const chunk=(type,data)=>{
    const name=Buffer.from(type);let crc=0xffffffff;
    for(const value of Buffer.concat([name,data])) {crc^=value;for(let i=0;i<8;i++) crc=(crc>>>1)^((crc&1)?0xedb88320:0);}
    const size=Buffer.alloc(4),check=Buffer.alloc(4);size.writeUInt32BE(data.length);check.writeUInt32BE((crc^0xffffffff)>>>0);return Buffer.concat([size,name,data,check]);
  };
  const header=Buffer.alloc(13);header.writeUInt32BE(width);header.writeUInt32BE(height,4);header[8]=8;header[9]=2;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(rows)),chunk('IEND',Buffer.alloc(0))]);
}
export async function prepareOfflineFeatures(a,b,contact,{until,progress,report}) {
  if(b.child.exitCode===null) throw new Error('Recipient must be stopped');
  const id=await a.identity();
  const headers={'X-Najwa-Session':a.token,'X-Najwa-Identity':id.session,'X-Najwa-Generation':String(id.generation),'X-Najwa-Contact':contact.id,'X-Najwa-Filename':Buffer.from('boundary.png').toString('base64'),'Content-Type':'application/octet-stream'};
  for(const extra of [{'X-Najwa-Session':'0'.repeat(64)},{Origin:'https://untrusted.invalid'},{'Content-Type':'application/json'}]) {
    if((await fetch(a.origin+'/api/attachment',{method:'POST',headers:{...headers,...extra},body:Buffer.from([1])})).status!==403) throw new Error('Attachment boundary accepted an untrusted request');
  }
  if((await fetch(a.origin+'/api/attachment',{method:'POST',headers,body:Buffer.alloc(8*1024*1024+1)})).status!==413) throw new Error('Attachment body limit was not enforced');
  const stale=await (await fetch(a.origin+'/api/attachment',{method:'POST',headers:{...headers,'X-Najwa-Generation':String(id.generation+1)},body:Buffer.from([1])})).json();
  if(stale.error?.code!=='stale_operation') throw new Error('Stale upload was not refused');
  report.checks.push('Legacy binary endpoint enforces browser token, origin, content type, its 8 MiB body cap and identity generation; the UI uses resumable uploads');
  await a.page.getByRole('button',{name:'Contact details',exact:true}).click();
  if(process.env.NAJWA_LIVE_REPORT) await a.page.screenshot({path:path.join(process.env.NAJWA_LIVE_REPORT,'contact-details.png')});
  await a.page.getByLabel('Contact name on this computer').fill('Offline Bob');
  await a.page.getByRole('button',{name:'Save name',exact:true}).click();
  await until(async()=> (await a.operation({kind:'contacts'}))[0]?.name==='Offline Bob','offline rename');
  await a.page.getByRole('button',{name:'Contact details',exact:true}).click();
  await a.page.getByRole('button',{name:'Block contact',exact:true}).click();
  await until(async()=> (await a.operation({kind:'contacts'}))[0]?.blocked,'offline block');
  const rejected=await a.operation({kind:'send',contact:contact.id,text:'must not send while blocked'}).then(()=>false,error=>error.code==='contact_blocked');
  if(!rejected) throw new Error('Blocked send was not rejected');
  await a.page.getByRole('button',{name:'Contact details',exact:true}).click();
  await a.page.getByRole('button',{name:'Unblock contact',exact:true}).click();
  await until(async()=> !(await a.operation({kind:'contacts'}))[0]?.blocked,'offline unblock');
  if(b.child.exitCode===null) throw new Error('Recipient came online during local controls');
  report.checks.push('Rename/block/unblock applied while peer process stopped; blocked send refused');
  await a.page.getByLabel('Attach file',{exact:true}).setInputFiles({name:'synthetic-pixels.png',mimeType:'image/png',buffer:multiChunkPng()});
  const file=await until(async()=> (await a.operation({kind:'messages',contact:contact.id})).find(m=>m.attachment?.complete),'sanitized attachment prepared');
  if(file.attachment.chunks<2) throw new Error('Attachment fixture must exercise multiple transport chunks');
  await until(async()=> {const messages=await a.operation({kind:'messages',contact:contact.id}); const m=messages.find(m=>m.id===file.id); return m?.attachment?.depositedChunks===m?.attachment?.chunks && (await a.network()).pendingDeposits===0;},'all attachment chunks deposited while recipient is offline',600_000);
  const downloaded=await a.operation({kind:'download_file',contact:contact.id,message:file.id});
  if(process.env.NAJWA_LIVE_REPORT) await a.page.screenshot({path:path.join(process.env.NAJWA_LIVE_REPORT,'offline-file-deposited.png')});
  const bytes=Buffer.from(downloaded.data,'base64');
  report.attachment={sha256:hash(bytes),bytes:bytes.length,chunks:file.attachment.chunks,filename:downloaded.filename};
  if(bytes.subarray(8,12).toString()!=='WEBP') throw new Error('Image was not sanitized to WebP');
  const original=(await a.operation({kind:'messages',contact:contact.id})).find(m=>!m.outgoing && !m.attachment);
  await a.page.locator(`[data-message-id="${original.id}"]`).getByRole('button',{name:'Message actions',exact:true}).click();
  await a.page.getByRole('button',{name:'Reply',exact:true}).click();
  const text=`Offline quoted reply ${Date.now()}`;
  await a.page.getByLabel('Write a message').fill(text);await a.page.getByRole('button',{name:'Send message',exact:true}).click();
  await until(async()=> (await a.operation({kind:'messages',contact:contact.id})).some(m=>m.text===text && m.replyTo===original.msgId && m.status==='deposited'),'offline quoted reply deposit');
  report.checks.push('Sanitized attachment and quoted reply deposited with recipient process stopped');
  await progress('PASS: offline contact controls, quoted reply and sanitized file deposit');
  return {sha256:hash(bytes),filename:downloaded.filename,text,replyTo:original.msgId};
}
export async function finishOfflineFeatures(a,b,contactA,contactB,file,{until,progress,report,quit,launch,open,contextA,replaceA}) {
  const received=await until(async()=> (await b.operation({kind:'messages',contact:contactB.id})).find(m=>!m.outgoing && m.attachment?.complete),'recipient receives complete attachment',600_000);
  const event=b.page.waitForEvent('download');
  await b.page.getByRole('button',{name:`Download ${received.attachment.filename}`,exact:true}).click();
  const download=await event;
  if(hash(await readFile(await download.path()))!==file.sha256) throw new Error('Receiver download differs from sanitized sender copy');
  if(process.env.NAJWA_LIVE_REPORT) await b.page.screenshot({path:path.join(process.env.NAJWA_LIVE_REPORT,'received-file.png')});
  await until(async()=> (await b.operation({kind:'messages',contact:contactB.id})).some(m=>m.text===file.text && m.replyTo===file.replyTo),'offline quoted reply received');
  report.checks.push('Recipient restarted with same identity; attachment UI download matches sender SHA-256; quoted reply received');
  await b.page.close();await quit(b);
  await a.page.getByRole('button',{name:'Contact details',exact:true}).click();
  await a.page.getByRole('button',{name:'Delete contact…',exact:true}).click();
  await a.page.getByRole('button',{name:'Delete contact and history',exact:true}).click();
  await until(async()=> (await a.operation({kind:'contacts'})).length===0,'offline deletion');
  if((await a.operation({kind:'messages',contact:contactA.id})).length || (await a.network()).pendingDeposits!==0) throw new Error('Deleted contact retained history or queued work');
  const profile=a.profile,fingerprint=a.fingerprint;
  await a.page.close();await quit(a);a=await launch(profile,'Alice after contact deletion');replaceA(a);await open(a,contextA,false);
  if(a.fingerprint!==fingerprint || (await a.operation({kind:'contacts'})).length) throw new Error('Deletion did not persist or identity changed');
  report.checks.push('Contact deletion removed local history/queued work while peer stopped and persisted across restart');
  await progress('PASS: attachment download integrity and persistent offline contact deletion');
}
