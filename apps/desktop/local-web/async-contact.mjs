// Exercise a fresh contact without overlapping online sessions after invitation creation.
export async function verifyAsynchronousContact(peers, tools) {
  let {a,b} = peers;
  const {launch,quit,open,until,progress,report,replaceA,replaceB} = tools;
  const fingerprintA = a.fingerprint, fingerprintB = b.fingerprint;
  const profileA = a.profile, profileB = b.profile;
  const assertStopped = peer => {
    if (peer.child.exitCode === null) throw new Error(`${peer.name} must be offline for this phase`);
  };
  const stop = async peer => {
    await peer.page.close();
    await quit(peer);
    await until(() => peer.child.exitCode !== null,`${peer.name} process stopped`,10_000);
    assertStopped(peer);
  };
  const waitForDeposit = async peer => {
    await until(async () => (await peer.network()).pendingDeposits === 0,
      `${peer.name} setup reaches the mailbox before the app stops`,900_000);
  };

  await stop(a);
  await progress('Async contact: inviter stopped before the other person accepts');
  await b.page.getByRole('button',{name:'Add a contact',exact:true}).click();
  await b.page.getByLabel('Your display name to share').fill('Bob Release');
  if(peers.qrImage) {
    await b.page.locator('.upload-qr input').setInputFiles(peers.qrImage);
    await until(async()=> (await b.page.getByLabel('Signed invitation').inputValue()).startsWith('NAJWA:'),'QR image scan while inviter is offline',30_000);
    report.checks.push('Invitation QR rendered and scanned from an image while inviter was stopped');
  } else await b.page.getByLabel('Signed invitation').fill(peers.invitation);
  const accepted = b.page.waitForResponse(async response => {
    if (!response.url().endsWith('/api/invoke')) return false;
    try {
      return response.request().postDataJSON()?.args?.request?.operation?.kind === 'accept_invitation'
        && (await response.json()).error?.code !== 'busy';
    } catch { return false; }
  },{timeout:660_000});
  await b.page.getByRole('button',{name:'Accept invitation',exact:true}).click();
  const acceptance = await (await accepted).json();
  if (acceptance.error) throw new Error(`offline invitation acceptance failed: ${acceptance.error.code}`);
  assertStopped(a);
  const pending = (await b.operation({kind:'contacts'}))[0];
  if (!pending || pending.ready) throw new Error('Expected a pending contact while the inviter is offline');
  await waitForDeposit(b);
  await progress('Async contact: invitation accepted and request deposited while inviter was offline');

  await stop(b);
  a = await launch(profileA,'Alice after offline acceptance'); replaceA(a);
  await open(a,peers.contextA,false);
  if (a.fingerprint !== fingerprintA) throw new Error('Inviter identity changed after restart');
  const contactA = await until(async () => {
    assertStopped(b);
    return (await a.operation({kind:'contacts'})).find(contact => contact.ready);
  },'inviter receives offline contact request',900_000);
  // Observe the background worker's durable deposit stamp. Never request a sync:
  // this phase must prove automatic delivery while the other app is stopped.
  await waitForDeposit(a);
  assertStopped(b);
  await progress('Async contact: inviter received request and published confirmation while acceptor was stopped');

  await stop(a);
  b = await launch(profileB,'Bob after offline confirmation'); replaceB(b);
  await open(b,peers.contextB,false);
  if (b.fingerprint !== fingerprintB) throw new Error('Acceptor identity changed after restart');
  const contactB = await until(async () => {
    assertStopped(a);
    return (await b.operation({kind:'contacts'})).find(contact => contact.ready);
  },'acceptor receives offline confirmation',900_000);
  if (contactA.safetyNumber !== contactB.safetyNumber) throw new Error('Async contact safety numbers differ');
  report.checks.push('Fresh contact established automatically without manual sync through non-overlapping online sessions: inviter offline at acceptance, acceptor offline at confirmation, inviter offline at completion');
  await progress('PASS: fresh contact completed without both apps being online at the same time');

  // Return to the ordinary live messaging/receipt/restart checks after this proof.
  a = await launch(profileA,'Alice after asynchronous contact setup'); replaceA(a);
  await open(a,peers.contextA,false);
  if (a.fingerprint !== fingerprintA) throw new Error('Inviter identity changed after asynchronous setup');
  await until(async () => (await a.network()).connection === 'connected','inviter reconnects after asynchronous setup',900_000);
}
