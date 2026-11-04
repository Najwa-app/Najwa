import {test,expect,type Page,type Route} from '@playwright/test';
// First run, mailbox settings and invitations in the shared messenger, with the
// native service mocked at its HTTP API. Fixture state lives in the test process.
const a='a'.repeat(56)+'.onion', b='b'.repeat(56)+'.onion';
const ok=(route:Route,value:unknown)=>route.fulfill({json:{ok:value}});
type Request={session:string;generation:number;operation:any};

async function usableFixture(page:Page, fresh=false) {
  const identity={enabled:true,session:'a'.repeat(32),generation:1,phase:'unlocked',hardware:'protected',protection:'hardware',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false};
  const state={identity,calls:[] as any[],deliveryMode:'responsive',contacts:[] as any[],
    mailboxes:fresh ? [] : [{onion:a,registered:true,primary:true},{onion:b,registered:true,primary:false}],
    failRegistration:false,messages:[] as any[],finish:()=>{},statusReads:0,
    // Returns a response body to replace the normal handling of one request.
    intercept:undefined as undefined | ((request:Request)=>object|undefined)};
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session:identity.session}});
    if(path==='/api/status'){state.statusReads++;return ok(route,{...identity});}
    if(path!=='/api/invoke')return ok(route,null);
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status')return ok(route,{enabled:true,unlocked:true,connection:'connected',coverRunning:true,mailboxes:state.mailboxes.map(m=>m.onion),mailboxDetails:state.mailboxes,pausedMailboxes:[],deliveryMode:state.deliveryMode});
    if(command!=='messaging_request')return ok(route,null);
    const replaced=state.intercept?.(args.request);
    if(replaced)return route.fulfill({json:replaced});
    const op=args.request.operation;
    state.calls.push(op);
    if(op.kind==='contacts')return ok(route,state.contacts);
    if(op.kind==='messages')return ok(route,[...state.messages].reverse());
    if(op.kind==='select_mailbox')state.mailboxes.forEach(m=>m.primary=m.onion===op.onion);
    if(op.kind==='forget_mailbox')state.mailboxes=state.mailboxes.filter(m=>m.onion!==op.onion);
    if(op.kind==='set_delivery_mode')state.deliveryMode=op.mode;
    if(op.kind==='add_mailbox'){
      let box=state.mailboxes.find(m=>m.onion===op.onion);
      if(!box){box={onion:op.onion,registered:false,primary:!state.mailboxes.length};state.mailboxes.push(box);}
      if(state.failRegistration)return route.fulfill({json:{error:{code:'registration_transport'}}});
      box.registered=true;
    }
    if(op.kind==='invitation')return ok(route,'najwa://contact?data=synthetic-invitation');
    if(op.kind==='sync')await new Promise<void>(resolve=>{state.finish=resolve;});
    if(op.kind==='send'){state.messages.push({id:'1',msgId:'d'.repeat(32),text:op.text,outgoing:true,timestamp:Math.floor(Date.now()/1000),status:'queued',expiresAt:null});return ok(route,'d'.repeat(32));}
    return ok(route,null);
  });
  await page.goto('/');
  return state;
}

test('first run registers a pasted mailbox URL without a Settings detour', async ({page}) => {
  const state=await usableFixture(page, true);
  await expect(page.getByRole('heading',{name:'A private place to keep in touch.'})).toBeVisible();
  await page.screenshot({path:'../../target/usability-onboarding.png'});
  await page.getByLabel('Tor v3 mailbox',{exact:true}).fill('https://'+'A'.repeat(56)+'.ONION/');
  await page.getByRole('button',{name:'Add mailbox',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Make your first connection.'})).toBeVisible();
  expect(state.calls.find(c=>c.kind==='add_mailbox').onion).toBe(a);
});

test('one invitation click waits for background network work without losing the form', async ({page}) => {
  const state=await usableFixture(page);
  const attempts:Request[]=[];
  state.intercept=request=>{
    if(request.operation.kind!=='invitation')return;
    attempts.push(structuredClone(request));
    if(attempts.length<=2)return {error:{code:'busy'}};
  };
  await page.getByRole('button',{name:'Create invitation',exact:true}).click();
  await page.getByLabel('Your display name to share').fill('Alice');
  await page.getByRole('button',{name:'Generate invitation',exact:true}).click();
  await expect(page.getByLabel('Invitation to share')).toHaveValue('najwa://contact?data=synthetic-invitation');
  expect(attempts).toHaveLength(3);
  expect(state.calls.filter(op=>op.kind==='invitation')).toHaveLength(1);
  expect(attempts.every(request=>request.operation.name==='Alice' && request.generation===1)).toBe(true);
});

test('waiting setup cannot move to a new unlocked identity generation', async ({page}) => {
  const state=await usableFixture(page);
  const waiting={generations:[] as number[],accepted:false};
  const reads=state.statusReads;
  state.intercept=request=>{
    if(request.operation.kind!=='invitation')return;
    waiting.generations.push(request.generation);
    if(waiting.generations.length===1){state.identity.generation=2;return {error:{code:'busy'}};}
    if(request.generation!==state.identity.generation)return {error:{code:'stale_operation'}};
    waiting.accepted=true;return {ok:'unexpected'};
  };
  await expect.poll(()=>state.statusReads).toBeGreaterThan(reads);
  await page.getByRole('button',{name:'Create invitation',exact:true}).click();
  await page.getByLabel('Your display name to share').fill('Alice');
  await page.getByRole('button',{name:'Generate invitation',exact:true}).click();
  await expect.poll(()=>waiting.generations.length).toBe(2);
  expect(waiting).toEqual({generations:[1,1],accepted:false});
});

test('mailbox input validates locally and failed registration remains retryable', async ({page}) => {
  const state=await usableFixture(page, true);
  await page.getByLabel('Tor v3 mailbox',{exact:true}).fill('example.com');
  await page.getByRole('button',{name:'Add mailbox',exact:true}).click();
  await expect(page.getByRole('main').getByRole('alert')).toContainText('complete 56-character');
  expect(state.calls.filter(c=>c.kind==='add_mailbox')).toHaveLength(0);
  state.failRegistration=true;
  await page.getByLabel('Tor v3 mailbox',{exact:true}).fill(a);
  await page.getByRole('button',{name:'Add mailbox',exact:true}).click();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.getByText('Setup incomplete',{exact:true})).toBeVisible();
  state.failRegistration=false;
  await page.getByRole('button',{name:'Retry registration',exact:true}).click();
  await expect(page.getByText('Registered',{exact:true})).toBeVisible();
});

test('mistyped incomplete mailboxes can be removed so setup can restart', async ({page}) => {
  const state=await usableFixture(page,true);
  state.failRegistration=true;
  await page.getByLabel('Tor v3 mailbox',{exact:true}).fill(a);
  await page.getByRole('button',{name:'Add mailbox',exact:true}).click();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('button',{name:'Remove incomplete setup',exact:true}).click();
  await expect(page.locator('.mailbox-row')).toHaveCount(0);
  await expect(page.getByRole('main')).toContainText('Incomplete mailbox setup removed.');
  await page.getByRole('button',{name:'Back to conversations',exact:true}).click();
  await expect(page.getByRole('heading',{name:'A private place to keep in touch.'})).toBeVisible();
});

test('an incomplete backup does not hide the configured primary mailbox', async ({page}) => {
  const state=await usableFixture(page);
  state.mailboxes[1].registered=false;
  await expect(page.locator('.demo-note.tor-connection')).toContainText('1 mailbox configured · 1 setup incomplete');
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.locator('.mailbox-row').filter({hasText:b})).toContainText('Mailbox setup');
  await expect(page.locator('.mailbox-row').filter({hasText:a})).toContainText('Primary mailbox');
});

test('users select a primary mailbox and can opt into timing privacy', async ({page}) => {
  await usableFixture(page);
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('button',{name:'Make primary',exact:true}).click();
  const row = page.locator('.mailbox-row').filter({hasText:b});
  await expect(row).toContainText('Primary mailbox');
  await page.screenshot({path:'../../target/usability-settings.png'});
  await page.getByRole('button',{name:/^Timing privacy/}).click();
  await expect(page.getByRole('button',{name:/^Timing privacy/})).toHaveAttribute('aria-pressed','true');
  await page.getByRole('button',{name:/^Responsive/}).click();
  await expect(page.getByRole('button',{name:/^Responsive/})).toHaveAttribute('aria-pressed','true');
  await page.getByRole('button',{name:'Back to conversations',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Make your first connection.'})).toBeVisible();
});

test('invitations show all registered mailboxes and provide a copy action', async ({page,context}) => {
  await context.grantPermissions(['clipboard-read','clipboard-write']);
  await usableFixture(page);
  await page.getByRole('button',{name:'Create invitation',exact:true}).click();
  await page.getByLabel('Your display name to share',{exact:true}).fill('Test Alice');
  await page.getByRole('button',{name:'Generate invitation',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText('Includes 2 registered mailboxes');
  await page.getByRole('button',{name:'Copy invitation',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText('Invitation copied');
  expect(await page.evaluate(()=>navigator.clipboard.readText())).toBe('najwa://contact?data=synthetic-invitation');
});

test('an existing conversation can send while synchronization is busy', async ({page}) => {
  const state=await usableFixture(page);
  state.contacts.push({id:'1',name:'Test Bob',verified:false,blocked:false,unread:0,ready:true,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false});
  await page.getByRole('button',{name:/Test Bob/}).click();
  await page.getByRole('textbox',{name:'Write a message',exact:true}).fill('While sync runs');
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('button',{name:'Synchronize now',exact:true}).click();
  await expect(page.locator('.settings-page').getByText('Synchronizing with your mailboxes through Tor…',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Chats',exact:true}).click();
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.getByText('While sync runs',{exact:true})).toBeVisible();
  state.finish();
});

test('onboarding and settings fit a small laptop and narrow browser', async ({page}) => {
  await page.setViewportSize({width:1024,height:700});
  await usableFixture(page,true);
  await expect(page.getByRole('button',{name:'Add mailbox',exact:true})).toBeInViewport();
  await page.setViewportSize({width:600,height:800});
  await expect(page.getByRole('button',{name:'Add mailbox',exact:true})).toBeInViewport();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
});
