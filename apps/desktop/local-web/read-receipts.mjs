// Real native receipts: fetch is not read, and the sender may be offline.
export async function verifyOfflineReadReceipts(a,b,contacts,h) {
  const {choose,until,progress,report,quit,launch,open,contextA,replaceA}=h;
  await b.page.getByRole('button',{name:'Settings',exact:true}).click();
  await a.page.bringToFront();
  const text=`Read while sender offline ${Date.now()}`;
  await a.page.getByLabel('Write a message').fill(text);
  await a.page.getByRole('button',{name:'Send message',exact:true}).click();
  await until(async()=> (await a.operation({kind:'messages',contact:contacts[0].id})).some(m=>m.text===text && m.status==='delivered'),'unread delivery');
  await new Promise(resolve=>setTimeout(resolve,2500));
  const before=(await a.operation({kind:'messages',contact:contacts[0].id})).find(m=>m.text===text);
  if(before?.status!=='delivered') throw new Error('a closed conversation was marked read');
  report.checks.push('Fetching an unopened conversation confirms delivery without marking it read');
  const fingerprint=a.fingerprint;
  const profile=a.profile;
  await a.page.close();await quit(a);
  await choose(b,contacts[1]);await b.page.bringToFront();
  await b.page.getByText(text,{exact:true}).and(b.page.locator('.message-text')).waitFor();
  await until(async()=> (await b.operation({kind:'contacts'})).find(c=>c.id===contacts[1].id)?.unread===0,'visible reader acknowledgement');
  await progress('Sender stopped; recipient opened the message and queued its encrypted read receipt');
  a=await launch(profile,'Alice read-receipt restart');replaceA(a);await open(a,contextA,false);
  if(a.fingerprint!==fingerprint) throw new Error('sender identity changed after restart');
  await until(async()=> (await a.network()).connection==='connected','read-receipt sender reconnect',900_000);
  await choose(a,contacts[0]);await a.page.bringToFront();
  await until(async()=> (await a.operation({kind:'messages',contact:contacts[0].id})).some(m=>m.text===text && m.status==='read'),'offline read receipt recovery',300_000);
  const bubble=a.page.locator('.message').filter({has:a.page.getByText(text,{exact:true})});
  await bubble.getByRole('img',{name:'Read',exact:true}).waitFor();
  report.checks.push('Encrypted read receipt reached the restarted sender and displayed blue double ticks');
  await progress('PASS: offline sender recovered the read receipt and blue double ticks');
}
