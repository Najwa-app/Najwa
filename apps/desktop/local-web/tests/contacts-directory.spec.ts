import {test,expect,type Page} from '@playwright/test';
import path from 'node:path';
async function app(page:Page,offline=false) {
  const person={ready:true,verified:false,blocked:false,unread:0,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};
  const state={contacts:[{...person,id:'1',name:'Zed',unread:3,preview:'A recent message',lastMessageAt:1700000000},{...person,id:'2',name:'Ada',verified:true},{...person,id:'3',name:'Blocked friend',blocked:true}],calls:[] as any[]};
  const session='a'.repeat(32);
  await page.route('**/api/**',async route=>{
    const endpoint=new URL(route.request().url()).pathname;
    if(endpoint==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session}});
    if(endpoint==='/api/status')return route.fulfill({json:{ok:{enabled:true,session,generation:1,phase:'unlocked',hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false}}});
    if(endpoint!=='/api/invoke')return route.fulfill({json:{ok:null}});
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status')return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection:offline?'offline':'connected',coverRunning:false,mailboxes:['a'.repeat(56)+'.onion'],mailboxDetails:[{onion:'a'.repeat(56)+'.onion',registered:true,primary:true}],pausedMailboxes:[],deliveryMode:'responsive',pendingDeposits:0}}});
    const op=args.request.operation;state.calls.push(op);let ok:unknown=null;
    if(op.kind==='contacts')ok=state.contacts;
    if(op.kind==='messages')ok=op.contact==='1'?[{id:'1',msgId:'d'.repeat(32),text:'A recent message',outgoing:false,timestamp:1700000000,status:'delivered',expiresAt:null}]:[];
    if(op.kind==='manage_contact') {const contact=state.contacts.find(c=>c.id===op.contact)!;if(op.action==='rename')contact.name=op.name;else if(op.action==='block'||op.action==='unblock')contact.blocked=op.action==='block';}
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');await expect(page.getByRole('button',{name:/Zed/})).toBeVisible();return state;
}

test('Contacts is an alphabetical directory and browsing it never fetches or displays messages',async({page})=>{
  const state=await app(page);
  await page.getByRole('button',{name:/Zed/}).click();await expect(page.getByText('A recent message',{exact:true}).and(page.locator('.message-text'))).toBeVisible();
  await page.getByRole('button',{name:'Contacts',exact:true}).click();
  const directory=page.getByRole('main',{name:'Contact directory'});
  await expect(directory.getByRole('heading',{level:2})).toHaveText(['Ada','Blocked friend','Zed']);
  await expect(page.getByLabel('Write a message')).toHaveCount(0);
  await expect(directory.getByText('A recent message',{exact:true})).toHaveCount(0);
  state.calls.length=0;await page.bringToFront();await page.waitForTimeout(1300);
  expect(state.calls.some(c=>c.kind==='messages'||c.kind==='displayed')).toBe(false);
  await page.getByLabel('Find a contact',{exact:true}).fill('ada');
  await expect(directory.getByRole('heading',{level:2})).toHaveText(['Ada']);
});

test('Open chat leaves the directory and clears a stale unread filter',async({page})=>{
  await app(page);await page.getByRole('button',{name:/^Unread/}).click();
  await page.getByRole('button',{name:'Contacts',exact:true}).click();
  await page.getByRole('button',{name:'Open chat with Ada',exact:true}).click();
  await expect(page.getByRole('main',{name:'Conversation with Ada'})).toBeVisible();
  await expect(page.getByLabel('Write a message')).toBeEnabled();
  await expect(page.getByRole('button',{name:/^All chats/})).toHaveClass(/chosen/);
  await expect(page.getByRole('main',{name:'Contact directory'})).toHaveCount(0);
});

test('directory management can unblock and rename a person while Tor is offline',async({page})=>{
  const state=await app(page,true);await page.getByRole('button',{name:'Contacts',exact:true}).click();
  await page.getByRole('button',{name:/^Blocked/}).click();
  await expect(page.locator('.contact-row h2')).toHaveText(['Blocked friend']);
  await page.getByRole('button',{name:'Manage Blocked friend',exact:true}).click();
  await page.getByRole('button',{name:'Unblock contact',exact:true}).click();
  await expect(page.getByRole('heading',{name:'No blocked contacts',exact:true})).toBeVisible();
  await page.getByRole('button',{name:/^All contacts/}).click();
  await page.getByRole('button',{name:'Manage Blocked friend',exact:true}).click();
  await page.getByLabel('Contact name on this computer').fill('Renamed person');await page.getByRole('button',{name:'Save name',exact:true}).click();
  await expect(page.locator('.contact-row h2')).toHaveText(['Ada','Renamed person','Zed']);
  expect(state.calls.filter(c=>c.kind==='manage_contact').map(c=>c.action)).toEqual(['unblock','rename']);
});

test('the directory and long names fit a narrow screen',async({page})=>{
  await page.setViewportSize({width:390,height:720});const state=await app(page);
  state.contacts[1].name='A long contact name '.repeat(5);
  await page.getByRole('button',{name:'Contacts',exact:true}).click();
  await expect(page.locator('.contact-row h2').first()).toHaveText(state.contacts[1].name.trim());
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await expect(page.getByRole('button',{name:'Open chat with '+state.contacts[1].name,exact:true})).toBeInViewport();
  await page.screenshot({path:path.resolve('..','..','target','contacts-directory-mobile.png')});
});
