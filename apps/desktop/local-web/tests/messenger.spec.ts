import {test,expect,type Page,type Route} from '@playwright/test';
// Shared messenger behaviour, driven through LocalWeb with the native service
// mocked at its HTTP API. Fixture state lives in the test process.
const session='a'.repeat(32);
const mailbox='a'.repeat(56)+'.onion';
const ok=(route:Route,value:unknown)=>route.fulfill({json:{ok:value}});
const ada={id:'2',name:'Ada',verified:false,blocked:false,unread:0,ready:true,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};

async function fixture(page:Page,{pending=false,mailboxSetup=false,extraContacts=[] as typeof ada[]}={}) {
  const identity={enabled:true,session,generation:1,phase:'unlocked',hardware:'protected',protection:'hardware',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false};
  const bob={id:'1',name:'Real fixture Bob',verified:false,blocked:false,unread:1,ready:!pending,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};
  const contacts=[bob,...extraContacts.map(c=>({...c}))];
  const messages:Record<string,unknown>[]=[{id:'1',msgId:'c'.repeat(32),text:'Incoming encrypted fixture',outgoing:false,timestamp:Date.parse('2026-10-04T12:34:00Z')/1000,status:'delivered',expiresAt:null}];
  const pausedMailboxes:string[]=[];
  const mailboxes=mailboxSetup ? [] : [mailbox];
  let finishSetup=()=>{};
  const fx={calls:[] as any[],messages,invitationErrors:[] as string[],invitationAttempts:0,
    lock:()=>{identity.phase='locked';identity.generation++;},
    acknowledgeTimer:()=>{bob.timerPending=false;},
    deliver:()=>{messages.push({id:'2',msgId:'e'.repeat(32),text:'Incoming behind modal',outgoing:false,timestamp:Math.floor(Date.now()/1000),status:'delivered',expiresAt:null});},
    pauseMailbox:()=>{pausedMailboxes.push(mailbox);},recoverMailbox:()=>{pausedMailboxes.length=0;},
    finishMailboxSetup:()=>finishSetup()};
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session}});
    if(path==='/api/status')return ok(route,{...identity});
    if(path==='/api/lock'){fx.lock();return ok(route,{...identity});}
    if(path==='/api/identity'){
      if(route.request().postDataJSON().operation.kind==='unlock'){identity.phase='unlocked';identity.generation++;}
      return ok(route,{identity:{...identity},value:null});
    }
    if(path!=='/api/invoke')return ok(route,null);
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status')return ok(route,{enabled:true,unlocked:identity.phase==='unlocked',connection:identity.phase==='unlocked'?'connected':'locked',coverRunning:true,mailboxes:[...mailboxes],pausedMailboxes:[],retryingMailboxes:[...pausedMailboxes]});
    if(command!=='messaging_request')return ok(route,null);
    fx.calls.push(structuredClone(args.request));
    const op=args.request.operation;
    if(op.kind==='add_mailbox'){
      // Native setup saves the address before registration/key publication finishes.
      mailboxes.push(op.onion);
      await new Promise<void>(resolve=>{finishSetup=resolve;});
      return ok(route,null);
    }
    if(op.kind==='contacts')return ok(route,contacts);
    if(op.kind==='messages')return ok(route,op.contact===bob.id ? [...messages].reverse() : []);
    if(op.kind==='displayed'&&op.contact===bob.id)bob.unread=0;
    if(op.kind==='send'){messages.push({id:String(messages.length+1),msgId:'d'.repeat(32),text:op.text,outgoing:true,timestamp:Math.floor(Date.now()/1000),status:'queued',expiresAt:null});return ok(route,'d'.repeat(32));}
    if(op.kind==='verify')bob.verified=op.verified;
    if(op.kind==='set_timer'){bob.timerSeconds=op.seconds;bob.timerPending=true;}
    if(op.kind==='retry_mailbox')pausedMailboxes.length=0;
    if(op.kind==='invitation'){
      const error=fx.invitationErrors[fx.invitationAttempts++];
      if(error)return route.fulfill({json:{error:{code:error}}});
      return ok(route,'najwa://contact?data=fixture');
    }
    return ok(route,null);
  });
  await page.goto('/');
  return fx;
}
async function unlock(page:Page) {
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa',exact:true}).click();
}

test('timer controls queue updates and pause sending until the peer acknowledges', async ({page}) => {
  const fx=await fixture(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill('preserved draft');
  await page.getByRole('button',{name:'Disappearing messages',exact:true}).click();
  await page.getByLabel('Message timer',{exact:true}).selectOption('custom');
  await page.getByLabel('Custom timer in seconds',{exact:true}).fill('29');
  await page.getByRole('button',{name:'Save timer',exact:true}).click();
  expect(fx.calls.filter(c=>c.operation.kind==='set_timer').length).toBe(0);
  await page.getByLabel('Custom timer in seconds',{exact:true}).fill('30');
  await page.getByRole('button',{name:'Save timer',exact:true}).click();
  await expect(page.getByText('Timer update awaiting your contact.',{exact:false})).toBeVisible();
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeDisabled();
  await expect(page.getByRole('textbox',{name:'Write a message',exact:true})).toHaveValue('preserved draft');
  fx.acknowledgeTimer();
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Disappearing messages',exact:true}).click();
  await page.getByLabel('Message timer',{exact:true}).selectOption('0');
  await page.getByRole('button',{name:'Save timer',exact:true}).click();
  await expect.poll(()=>fx.calls.filter(c=>c.operation.kind==='set_timer').map(c=>c.operation.seconds)).toEqual([30,0]);
});

test('connected chats use typed native commands and distinguish queued messages', async ({page}) => {
  const fx=await fixture(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toBeVisible();
  const expectedTime = await page.evaluate(() => new Intl.DateTimeFormat(undefined,
    {hour:'2-digit',minute:'2-digit'}).format(new Date('2026-10-04T12:34:00Z')));
  await expect(page.locator('.message:not(.outgoing) time')).toHaveText(expectedTime);
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill('<img src="https://fixture.invalid/x">');
  await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.getByText('<img src="https://fixture.invalid/x">',{exact:true})).toBeVisible();
  await expect(page.getByRole('img',{name:'Queued',exact:true})).toBeVisible();
  await expect(page.locator('img[src*="fixture.invalid"]')).toHaveCount(0);
  await page.getByRole('button',{name:'Safety number',exact:true}).click();
  await expect(page.getByText('abcd abcd abcd abcd abcd abcd abcd abcd',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'I compared the numbers',exact:true}).click();
  await expect(page.getByText('Identity verified · Timer: Off',{exact:true})).toBeVisible();
  expect(fx.calls.find(c=>c.operation.kind==='send').operation.text).toContain('<img');
  expect(fx.calls.every(c=>Object.keys(c).sort().join(',')==='generation,operation,session')).toBe(true);
});

test('Tor connection does not hide missing, pending or paused mailbox setup', async ({page}) => {
  const fx=await fixture(page,{mailboxSetup:true});
  const connection = page.locator('.demo-note.tor-connection');
  await expect(connection.locator('b')).toHaveText('Mailbox setup needed');
  await expect(connection).toContainText('Tor: connected');
  await expect(connection.locator('svg')).toHaveCSS('color', 'rgb(37, 115, 76)');
  await page.getByRole('button', {name:'Settings',exact:true}).click();
  await page.getByLabel('Tor v3 mailbox', {exact:true}).fill(mailbox);
  await page.getByRole('button', {name:'Add mailbox',exact:true}).click();
  await expect(page.locator('.mailbox-state')).toHaveText('Mailbox setup in progress');
  await expect(page.locator('.settings-page').getByText('Registering mailbox and publishing keys… Mailbox setup is not complete yet.', {exact:true})).toBeVisible();
  await page.getByRole('button', {name:'Chats',exact:true}).click();
  await expect(connection.locator('b')).toHaveText('Mailbox setup in progress');
  await expect(connection).toContainText('Registering mailbox and publishing keys…');
  await expect(connection).toContainText('Tor: connected');
  fx.finishMailboxSetup();
  await expect(connection.locator('b')).toHaveText('Mailbox configured');
  await expect(connection).not.toContainText('Mailbox connected');
  fx.pauseMailbox();
  await expect(connection.locator('b')).toHaveText('Retrying mailbox connection');
});

test('temporary mailbox failures recover without a manual retry and chats remain usable', async ({page}) => {
  const fx=await fixture(page);
  fx.pauseMailbox();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Retrying mailbox connections'})).toBeVisible();
  await expect(page.getByText('Temporary connection failures. Najwa retries automatically while unlocked; queued messages and contact requests are kept.',{exact:true})).toBeVisible();
  expect(fx.calls.filter(c=>c.operation.kind==='retry_mailbox').length).toBe(0);
  await expect(page.getByRole('button',{name:'Retry '+mailbox,exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Chats',exact:true}).click();
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill('queue during temporary outage');
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeEnabled();
  fx.recoverMailbox();
  await expect(page.locator('.demo-note.tor-connection').locator('b')).toHaveText('Mailbox configured');
  expect(fx.calls.filter(c=>c.operation.kind==='retry_mailbox')).toHaveLength(0);
});

test('invitation dialog shows its lifetime and retries a temporary mailbox failure while Tor stays connected', async ({page}) => {
  const fx=await fixture(page);
  fx.invitationErrors=['registration_transport'];
  await page.getByRole('button', {name:'Create invitation',exact:true}).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText('valid for up to 48 hours from creation');
  await page.getByLabel('Your display name to share', {exact:true}).fill('Fixture Alice');
  await page.getByRole('button', {name:'Generate invitation',exact:true}).click();
  await expect(dialog.getByRole('status')).toContainText('Retrying your invitation automatically');
  await expect(dialog.getByRole('button', {name:'Generate invitation',exact:true})).toBeDisabled();
  await expect(page.locator('.demo-note.tor-connection')).toContainText('Tor: connected');
  await expect(dialog.getByLabel('Invitation to share', {exact:true})).toHaveValue('najwa://contact?data=fixture');
  expect(fx.invitationAttempts).toBe(2);
  await expect(dialog.getByRole('button', {name:'Generate invitation',exact:true})).toBeEnabled();
});

test('pending contacts cannot send and an OS lock removes decrypted views and drafts', async ({page}) => {
  const fx=await fixture(page,{pending:true});
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeDisabled();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toBeVisible();
  fx.lock();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toHaveCount(0);
});

test('Lock clears real messages and reopening requires unlock', async ({page}) => {
  await fixture(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill('unsent fixture');
  await page.getByRole('button',{name:'Lock',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toHaveCount(0);
  await expect(page.getByText('unsent fixture',{exact:true})).toHaveCount(0);
  await unlock(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toBeVisible();
  await expect(page.getByRole('textbox',{name:'Write a message',exact:true})).toHaveValue('');
});

test('messages arriving behind a modal are acknowledged only after it closes', async ({page}) => {
  const fx=await fixture(page);
  await page.bringToFront();
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.getByText('Incoming encrypted fixture',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Safety number',exact:true}).click();
  fx.deliver();
  await expect(page.getByText('Incoming behind modal',{exact:true})).toBeVisible();
  await page.waitForTimeout(1200);
  const acknowledged = () => fx.calls.some(c => c.operation.kind === 'displayed' && c.operation.ids.includes('2'));
  expect(acknowledged()).toBe(false);
  await page.getByRole('button',{name:'Close',exact:true}).click();
  await expect.poll(acknowledged).toBe(true);
});

test('messages remain plain text, including HTML and URLs', async ({page}) => {
  const remoteRequests: string[] = [];
  await page.route('**/*', route => {
    if (new URL(route.request().url()).hostname !== '127.0.0.1') {
      remoteRequests.push(route.request().url());
      return route.abort();
    }
    return route.fallback();
  });
  await fixture(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  const payload = '<img src="https://najwa-probe.invalid/secret" onerror="alert(1)"> https://najwa-probe.invalid/';
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill(payload);
  await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.locator('.message').last()).toContainText(payload);
  await expect(page.locator('.message img, .message a, .message script')).toHaveCount(0);
  expect(remoteRequests).toEqual([]);
});

test('drafts belong to their conversation and locking discards local session data', async ({page}) => {
  await fixture(page,{extraContacts:[ada]});
  const input = page.getByRole('textbox',{name:'Write a message',exact:true});
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await input.fill('Unsent Bob draft');
  await page.getByRole('button',{name:/Ada/}).click();
  await expect(input).toHaveValue('');
  await input.fill('Unsent Ada draft');
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(input).toHaveValue('Unsent Bob draft');
  await input.press('Enter');
  await expect(page.locator('.message').last()).toContainText('Unsent Bob draft');
  await page.getByRole('button',{name:'Lock',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.locator('.message, textarea')).toHaveCount(0);
  await unlock(page);
  await page.getByRole('button',{name:/Ada/}).click();
  await expect(input).toHaveValue('');
  await expect(page.getByText('Unsent Ada draft',{exact:true})).toHaveCount(0);
  const stores = await page.evaluate(async () => ({
    local: localStorage.length, session: sessionStorage.length,
    databases: (await indexedDB.databases()).length
  }));
  expect(stores).toEqual({local:0,session:0,databases:0});
});

test('search and unread filtering have usable empty states', async ({page}) => {
  await fixture(page,{extraContacts:[ada]});
  await page.bringToFront();
  await page.getByRole('button',{name:'Unread 1',exact:true}).click();
  await expect(page.locator('.conversation')).toHaveCount(1);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.getByText('All caught up')).toBeVisible();
  await page.getByRole('button',{name:/^All chats/}).click();
  await page.getByRole('textbox',{name:'Find a real contact'}).fill('no such nickname');
  await expect(page.getByText('No matching contacts')).toBeVisible();
});

test('a new contact dialog restores focus on Escape and the composer accepts multiline entry', async ({page}) => {
  const fx=await fixture(page);
  const trigger = page.getByRole('button',{name:'Add contact invitation',exact:true});
  await trigger.click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(trigger).toBeFocused();
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  const input = page.getByRole('textbox',{name:'Write a message',exact:true});
  await input.fill('First line');
  await input.press('Shift+Enter');
  await input.pressSequentially('Second line');
  await expect(page.locator('.message')).toHaveCount(1);
  await input.press('Enter');
  await expect(page.locator('.message').last().locator('.message-text')).toHaveText('First line\nSecond line');
  expect(fx.calls.find(c=>c.operation.kind==='send').operation.text).toBe('First line\nSecond line');
});

test('the composer does not send on IME composition confirmation', async ({page}) => {
  const fx=await fixture(page);
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  const input = page.getByRole('textbox',{name:'Write a message',exact:true});
  await input.fill('مرحبا');
  await input.dispatchEvent('keydown',{key:'Enter',isComposing:true});
  await page.waitForTimeout(300);
  await expect(input).toHaveValue('مرحبا');
  await expect(page.locator('.message')).toHaveCount(1);
  expect(fx.calls.some(c=>c.operation.kind==='send')).toBe(false);
  // A plain Enter still sends, so only the composition guard held the message back.
  await input.press('Enter');
  await expect(page.locator('.message')).toHaveCount(2);
});

test('layouts and bidirectional content render without page overflow', async ({page}) => {
  const fx=await fixture(page);
  fx.messages.push({id:'2',msgId:'f'.repeat(32),text:'مرحبا، هل نلتقي غدًا؟',outgoing:false,timestamp:Math.floor(Date.now()/1000),status:'delivered',expiresAt:null});
  await page.screenshot({path:'test-results/messenger-wide.png',fullPage:true});
  await page.getByRole('button',{name:/Real fixture Bob/}).click();
  await expect(page.locator('.message')).toHaveCount(2);
  await expect(page.locator('.message .message-text').first()).toHaveAttribute('dir','auto');
  for (const width of [1280,1024,900]) {
    await page.setViewportSize({width,height:720});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.getByRole('textbox',{name:'Write a message',exact:true})).toBeInViewport();
  }
  await page.screenshot({path:'test-results/messenger-small.png',fullPage:true});
});
