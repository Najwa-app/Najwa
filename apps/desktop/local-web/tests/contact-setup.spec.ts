import { test, expect, type Page } from '@playwright/test';

async function contactApp(page:Page, setupState='waiting', connection='connected', paused=false) {
  const contact = {id:'1',name:'Existing friend',ready:true,verified:false,blocked:false,unread:0,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};
  const state = {contacts:[contact,{...contact,id:'2',name:'Pending person',ready:false,setupState,setupExpiresAt:Math.floor(Date.now()/1000)+(setupState === 'waiting' ? 3600 : -1)}],paused:paused ? ['b'.repeat(56)+'.onion'] : [],accepted:0,retried:0,limit:false};
  const session='a'.repeat(32);
  await page.route('**/api/**',async route => {
    const path=new URL(route.request().url()).pathname;
    if(path==='/api/bootstrap') return route.fulfill({json:{token:'c'.repeat(64),session}});
    if(path==='/api/status') return route.fulfill({json:{ok:{enabled:true,session,generation:1,phase:'unlocked',hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false}}});
    if(path!=='/api/invoke') return route.fulfill({json:{ok:null}});
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status') return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection,coverRunning:false,mailboxes:['a'.repeat(56)+'.onion'],mailboxDetails:[{onion:'a'.repeat(56)+'.onion',registered:true,primary:true}],pausedMailboxes:[],retryingMailboxes:state.paused,deliveryMode:'responsive',pendingDeposits:0}}});
    const operation=args.request.operation;
    let ok:unknown=null;
    if(operation.kind==='contacts') ok=state.contacts;
    if(operation.kind==='messages') ok=[];
    if(operation.kind==='accept_invitation') {
      if(state.limit && operation.confirmed!==true) return route.fulfill({json:{error:{code:'contact_limit_confirm'}}});
      state.accepted++;
      state.contacts[1]={...state.contacts[1],setupState:'queued',setupExpiresAt:Math.floor(Date.now()/1000)+3600};
      ok='2';
    }
    if(operation.kind==='retry_mailbox') {state.retried++;state.paused=[];}
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');
  await expect(page.getByRole('button',{name:/Existing friend/})).toBeVisible();
  return state;
}

test('acceptance saves a pending contact while Tor is offline and closes the modal',async ({page}) => {
  const state=await contactApp(page,'waiting','offline');
  await page.getByRole('button',{name:'Add contact invitation',exact:true}).click();
  await page.getByLabel('Your display name to share',{exact:true}).fill('Local person');
  await page.getByLabel('Signed invitation',{exact:true}).fill('najwa://contact?data=synthetic');
  await expect(page.getByRole('button',{name:'Accept invitation',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Accept invitation',exact:true}).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.getByRole('main')).toContainText('Contact request queued');
  await expect(page.getByRole('main')).toContainText('other person can be offline');
  expect(state.accepted).toBe(1);
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Settings',exact:true})).toBeVisible();
});

test('after ten contacts in a day another acceptance needs explicit confirmation',async ({page}) => {
  const state=await contactApp(page);
  state.limit=true;
  await page.getByRole('button',{name:'Add contact invitation',exact:true}).click();
  await page.getByLabel('Your display name to share',{exact:true}).fill('Local person');
  await page.getByLabel('Signed invitation',{exact:true}).fill('najwa://contact?data=synthetic');
  const accept=page.getByRole('button',{name:'Accept invitation',exact:true});
  await accept.click();
  await expect(page.getByRole('dialog')).toContainText('Adding many contacts in a short time can make you easier to identify.');
  await expect(accept).toBeDisabled();
  expect(state.accepted).toBe(0);
  await page.getByLabel('I understand. Add this contact anyway.',{exact:true}).check();
  await accept.click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.accepted).toBe(1);
});

test('a deposited contact request waits without blocking an existing conversation',async ({page}) => {
  await contactApp(page);
  await page.getByRole('button',{name:/Pending person/}).click();
  await expect(page.getByRole('main')).toContainText('Contact request deposited');
  await expect(page.getByRole('main')).toContainText('Your introduction is deposited in the mailbox.');
  await expect(page.getByRole('main')).toContainText('You can close Najwa now.');
  await page.getByRole('button',{name:/Existing friend/}).click();
  await expect(page.getByRole('textbox',{name:'Write a message',exact:true})).toBeEnabled();
});

for(const [state,label] of [['expired','Contact request expired'],['unconfirmed','No reply yet']]) {
  test(`${state} contact setup has a clear outcome without an active spinner`,async ({page}) => {
    await contactApp(page,state);
    await page.getByRole('button',{name:/Pending person/}).click();
    await expect(page.getByRole('main')).toContainText(label);
    await expect(page.getByRole('main')).not.toContainText('Establishing the contact');
    await expect(page.getByRole('main')).not.toContainText('Keep both apps');
  });
}

test('temporary delivery failures show automatic recovery without a retry button',async ({page}) => {
  const state=await contactApp(page,'waiting','connected',true);
  await expect(page.getByText('Temporary connection failures. Retrying automatically while Najwa is unlocked.',{exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'Retry paused delivery',exact:true})).toHaveCount(0);
  state.paused=[];
  await expect(page.getByText('Temporary connection failures. Retrying automatically while Najwa is unlocked.',{exact:true})).toHaveCount(0);
  expect(state.retried).toBe(0);
});
