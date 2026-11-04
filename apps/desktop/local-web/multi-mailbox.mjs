// Optional extension of the real Tor browser test. Both operators are test fixtures.
import path from 'node:path';
export async function verifyMultipleMailboxes(peer,{onion,output,report,until,delay,progress}) {
  const second=process.env.NAJWA_SECOND_MAILBOX;
  if(!/^[a-z2-7]{56}\.onion$/.test(second) || second===onion) throw new Error('independent second mailbox is required');
  await peer.page.getByRole('button',{name:'Settings',exact:true}).click();
  await peer.page.getByLabel('Tor v3 mailbox',{exact:true}).fill(second);
  let registered=false;
  for(let attempt=0;attempt<6;attempt++) {
    const response=peer.page.waitForResponse(async response=>{
      if(!response.url().endsWith('/api/invoke')) return false;
      try { return response.request().postDataJSON()?.args?.request?.operation?.kind==='add_mailbox' && (await response.json()).error?.code!=='busy'; } catch { return false; }
    },{timeout:660_000});
    if(attempt===0 || await peer.page.getByLabel('Tor v3 mailbox',{exact:true}).inputValue()===second) await peer.page.getByRole('button',{name:'Add mailbox',exact:true}).click();
    else await peer.page.locator('.mailbox-row').filter({hasText:second}).getByRole('button',{name:'Retry registration',exact:true}).click();
    const result=await (await response).json();
    if(!result.error) {registered=true;break;}
    if(!['busy','registration_transport','registration_limited','registration_pow','not_connected'].includes(result.error.code)) throw result.error;
    await progress(`Second mailbox attempt ${attempt+1}: ${result.error.code}`); await delay(2000);
  }
  if(!registered) throw new Error('second mailbox registration failed');
  await until(async()=> (await peer.network()).mailboxDetails.filter(m=>m.registered).length===2,'two registered mailboxes');
  const synchronize=()=>until(async()=>{
    try {await peer.operation({kind:'sync'});return true;}
    catch(error) {if(error.code==='busy') return false;throw error;}
  },'signed mailbox update',600_000);
  await synchronize(); // First complete A with both routes, then test A -> B -> A.
  for(const target of [second,onion]) {
    await peer.page.locator('.mailbox-row').filter({hasText:target}).getByRole('button',{name:'Make primary',exact:true}).click();
    await until(async()=> (await peer.network()).mailboxDetails.some(m=>m.onion===target && m.primary),'selected primary');
    await synchronize();
  }
  const network=await peer.network();
  if(network.mailboxDetails.filter(m=>m.registered).length!==2 || !network.mailboxDetails.some(m=>m.onion===onion && m.primary)) throw new Error('primary did not return to the original mailbox');
  report.checks.push('Second test operator registered through the UI; primary changed A to B to A with successful signed-update synchronization');
  await peer.page.screenshot({path:path.join(output,'two-mailboxes-primary-return.png')});
  await progress('PASS: two mailbox registrations and primary A to B to A through the real UI');
}
