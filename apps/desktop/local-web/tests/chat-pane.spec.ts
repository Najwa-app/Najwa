import {test,expect,type Page} from '@playwright/test';
import type {Message} from '../../src/messaging';
import {liveMessagePage} from '../../src/chatView';
import path from 'node:path';
const row=(id:string,text:string,timestamp:number,outgoing=false,status:Message['status']='delivered'):Message=>({id,msgId:BigInt(id).toString(16).padStart(32,'0'),text,timestamp,outgoing,status,expiresAt:null});

async function app(page:Page,rows:Message[]=[row('1','Can we meet at six?',100),row('2','Yes, see you there.',200,true)]) {
  const state={rows,calls:[] as any[]};
  const friend={id:'1',name:'Mira',ready:true,verified:false,blocked:false,unread:0,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};
  await page.route('**/api/**',async route=>{
    const endpoint=new URL(route.request().url()).pathname;
    if(endpoint==='/api/bootstrap') return route.fulfill({json:{token:'c'.repeat(64),session:'a'.repeat(32)}});
    if(endpoint==='/api/status') return route.fulfill({json:{ok:{enabled:true,session:'a'.repeat(32),generation:1,phase:'unlocked',hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false}}});
    if(endpoint!=='/api/invoke') return route.fulfill({json:{ok:null}});
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status') return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection:'connected',coverRunning:false,mailboxes:['a'.repeat(56)+'.onion'],pausedMailboxes:[],deliveryMode:'responsive',pendingDeposits:0}}});
    const op=args.request.operation;state.calls.push(op);let ok:unknown=null;
    if(op.kind==='contacts') ok=[friend,{...friend,id:'2',name:'Sam'}];
    if(op.kind==='messages') ok=op.contact==='1' ? [...state.rows].sort((a,b)=>b.timestamp-a.timestamp || Number(BigInt(b.id)-BigInt(a.id))) : [];
    if(op.kind==='send') {const id=String(state.rows.length+1);state.rows.push({...row(id,op.text,Math.floor(Date.now()/1000),true,'queued'),replyTo:op.reply_to});ok=id;}
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');await page.getByRole('button',{name:/Mira/}).click();
  await expect(page.locator('.message')).toHaveCount(rows.length);return state;
}
test('compact bubbles keep sent time and accurate delivery icons inside the bubble',async({page})=>{
  const state=await app(page);
  const message=page.locator('[data-message-id="2"]');
  await expect(message.getByRole('img',{name:'Delivered',exact:true})).toBeVisible();
  await expect(message.locator('.bubble footer time')).toBeVisible();
  expect(await message.evaluate(e=>e.getBoundingClientRect().height)).toBeLessThan(50);
  const gap=await page.locator('.message').evaluateAll(rows=>rows[1].getBoundingClientRect().top-rows[0].getBoundingClientRect().bottom);expect(gap).toBeLessThanOrEqual(8);
  await expect(page.getByRole('button',{name:'Reply',exact:true})).toHaveCount(0);
  const confirmation=page.getByRole('status',{name:'Latest outgoing message status'});
  state.rows[1].status='queued';await expect(message.getByRole('img',{name:'Queued',exact:true})).toBeVisible();
  await expect(confirmation).toContainText('Queued on this device');await expect(confirmation).not.toContainText('Deposited');
  state.rows[1].status='deposited';await expect(message.getByRole('img',{name:'Deposited',exact:true})).toBeVisible();
  await expect(confirmation).toContainText('Deposited in mailbox');
  state.rows[1].status='read';await expect(message.getByRole('img',{name:'Read',exact:true})).toBeVisible();
  await expect(message.locator('.delivery-status')).toHaveCSS('color','rgb(22, 130, 196)');
  await expect(confirmation).toContainText('Read by contact');
});
test('delayed arrivals append in the open chat and reopen in normal sent-time order',async({page})=>{
  const state=await app(page,[row('1','Earlier incoming',100),row('2','My first send',200,true),row('3','My second send',300,true)]);
  state.rows.push(row('4','Delayed response',50));
  await expect(page.locator('.message-text')).toHaveText(['Earlier incoming','My first send','My second send','Delayed response']);
  state.rows[1].status='read';await expect(page.locator('[data-message-id="2"] [aria-label="Read"]')).toBeVisible();
  await expect(page.locator('.message-text')).toHaveText(['Earlier incoming','My first send','My second send','Delayed response']);
  state.rows.push(row('5','Another late response',150),row('6','My next send',310,true));
  await expect(page.locator('.message-text')).toHaveText(['Earlier incoming','My first send','My second send','Delayed response','Another late response','My next send']);
  await page.getByRole('button',{name:/Sam/}).click();await expect(page.locator('.message')).toHaveCount(0);
  await page.getByRole('button',{name:/Mira/}).click();
  await expect(page.locator('.message-text')).toHaveText(['Delayed response','Earlier incoming','Another late response','My first send','My second send','My next send']);
});

test('a file confirms mailbox deposit only after every part has arrived',async({page})=>{
  const attachment={filename:'offline-file.webp',size:2048,chunks:2,availableChunks:2,depositedChunks:1,complete:true,supported:true};
  const state=await app(page,[{...row('1','offline-file.webp',100,true,'deposited'),attachment}]);
  const confirmation=page.getByRole('status',{name:'Latest outgoing message status'});
  await expect(confirmation).toContainText('1 of 2 parts deposited');
  await expect(confirmation).not.toContainText('File deposited in mailbox');
  state.rows[0].attachment!.depositedChunks=2;
  await expect(confirmation).toContainText('File deposited in mailbox');
});
test('an open empty chat uses local arrival order for its first batch',()=>{
  const high=row('9007199254740993','Arrived second',20),low=row('9007199254740992','Arrived first',30);
  expect(liveMessagePage([], [high,low],true).map(m=>m.text)).toEqual(['Arrived first','Arrived second']);
  expect(liveMessagePage([], [high,low],false).map(m=>m.text)).toEqual(['Arrived second','Arrived first']);
});
test('quoted cards show author and preview, jump to the original and live in the bubble',async({page})=>{
  const rows=[row('1','Can we meet at six?',100),{...row('2','Yes, see you there.',200,true),replyTo:'1'.padStart(32,'0')}];
  await app(page,rows);
  const quote=page.locator('[data-message-id="2"] .bubble .quoted-message');
  await expect(quote).toContainText('Mira');await expect(quote).toContainText('Can we meet at six?');
  await quote.click();await expect(page.locator('[data-message-id="1"]')).toBeFocused();await expect(page.locator('[data-message-id="1"]')).toHaveClass(/highlighted/);
  await page.screenshot({path:path.resolve('..','..','target','chat-pane-quoted.png')});
});
test('message actions support keyboard dismissal, replies and status details',async({page})=>{
  const state=await app(page);
  const trigger=page.locator('[data-message-id="2"]').getByRole('button',{name:'Message actions',exact:true});
  await trigger.click();await expect(page.getByRole('button',{name:'Reply',exact:true})).toBeFocused();
  await page.keyboard.press('Escape');await expect(trigger).toBeFocused();await expect(page.locator('.message-menu')).toHaveCount(0);
  await trigger.click();await page.getByRole('button',{name:'Message info',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText('Your contact received this message.');await page.getByRole('button',{name:'Close',exact:true}).click();
  await trigger.click();await page.getByRole('button',{name:'Reply',exact:true}).click();
  await expect(page.getByLabel('Write a message')).toBeFocused();await expect(page.locator('.reply-preview')).toContainText('yourself');
  await page.getByLabel('Write a message').fill('A quoted follow-up');await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.locator('[data-message-id="3"] .quoted-message')).toContainText('You');expect(state.calls.find(c=>c.kind==='send').reply_to).toBe('2'.padStart(32,'0'));
});
test('new incoming messages do not move a reader away from history',async({page})=>{
  const state=await app(page,Array.from({length:35},(_,i)=>row(String(i+1),`Message ${i+1}\nMore detail for the conversation`,100+i,i%2===0)));
  await page.locator('.messages').evaluate(e=>e.scrollTop=0);
  state.rows.push(row('36','A delayed arrival at the bottom',50));
  await expect(page.getByRole('button',{name:'1 new message',exact:true})).toBeVisible();
  expect(await page.locator('.messages').evaluate(e=>e.scrollTop)).toBeLessThan(20);
  await page.getByRole('button',{name:'1 new message',exact:true}).click();
  await expect(page.getByRole('button',{name:'1 new message',exact:true})).toHaveCount(0);
  await expect(page.locator('[data-message-id="36"]')).toBeInViewport();
});
test('quotes and message actions fit narrow screens and expired originals are not retained',async({page})=>{
  await page.setViewportSize({width:390,height:720});
  const state=await app(page,[row('1','Long original message '.repeat(20),100),{...row('2','My reply',200,true),replyTo:'1'.padStart(32,'0')}]);
  await page.locator('[data-message-id="2"]').getByRole('button',{name:'Message actions',exact:true}).click();
  const bounds=await page.locator('.message-menu').boundingBox();expect(bounds!.x).toBeGreaterThanOrEqual(0);expect(bounds!.x+bounds!.width).toBeLessThanOrEqual(390);expect(bounds!.y+bounds!.height).toBeLessThanOrEqual(720);
  await page.keyboard.press('Escape');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await expect(page.getByRole('status',{name:'Latest outgoing message status'})).toBeVisible();
  state.rows[0].expiresAt=Date.now()-1;
  await expect(page.locator('.quote-text')).toHaveText('Original message unavailable');
  await expect(page.locator('[data-message-id="1"]')).toHaveCount(0);
  await page.screenshot({path:path.resolve('..','..','target','chat-pane-mobile.png')});
});

test('only messages scrolled into the visible conversation are displayed',async({page})=>{
  const state=await app(page,Array.from({length:35},(_,i)=>row(String(i+1),`History ${i+1}\nConversation detail`,100+i)));
  await page.bringToFront();
  await page.locator('.messages').evaluate(e=>e.scrollTop=0);
  state.rows.push(row('36','Unread below the viewport',200));
  await expect(page.getByRole('button',{name:'1 new message',exact:true})).toBeVisible();
  await page.waitForTimeout(1300);
  const displayed=()=>state.calls.some(c=>c.kind==='displayed' && c.ids.includes('36'));
  expect(displayed()).toBe(false);
  await page.getByRole('button',{name:'1 new message',exact:true}).click();
  await expect.poll(displayed).toBe(true);
});

test('a browser reporting no focus does not mark newly received messages as displayed',async({page})=>{
  const state=await app(page);
  await page.evaluate(()=>Object.defineProperty(document,'hasFocus',{configurable:true,value:()=>false}));
  state.rows.push(row('3','Waiting for the reader to return',300));
  await expect(page.locator('[data-message-id="3"]')).toBeAttached();
  await page.waitForTimeout(1300);
  const displayed=()=>state.calls.some(c=>c.kind==='displayed' && c.ids.includes('3'));
  expect(displayed()).toBe(false);
  await page.evaluate(()=>Object.defineProperty(document,'hasFocus',{configurable:true,value:()=>true}));
  await expect.poll(displayed).toBe(true);
});
