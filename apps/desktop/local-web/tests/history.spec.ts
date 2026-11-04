import {test,expect,type Page} from '@playwright/test';
import type {Contact,Message} from '../../src/messaging';
import path from 'node:path';

const row=(n:number,text=`History ${n}`):Message=>({id:String(n),msgId:n.toString(16).padStart(32,'0'),text,timestamp:1000+n,outgoing:false,status:'delivered',expiresAt:null});
async function app(page:Page,count=230) {
  const friend:Contact={id:'1',name:'Mira',ready:true,verified:false,blocked:false,unread:17,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false,
    preview:'Latest conversation preview',lastMessageAt:1230};
  const state={rows:Array.from({length:count},(_,i)=>row(i+1)),friend,connection:'connected',ready:true,calls:[] as any[],holdSearch:false,releaseSearch:()=>{}};
  await page.route('**/api/**',async route=>{
    const endpoint=new URL(route.request().url()).pathname;
    if(endpoint==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session:'a'.repeat(32)}});
    if(endpoint==='/api/status')return route.fulfill({json:{ok:{enabled:true,session:'a'.repeat(32),generation:1,phase:'unlocked',hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,busy:false}}});
    if(endpoint!=='/api/invoke')return route.fulfill({json:{ok:null}});
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status')return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection:state.connection,coverRunning:true,mailboxes:['a'.repeat(56)+'.onion'],pausedMailboxes:[],deliveryMode:'responsive'}}});
    const op=args.request.operation;state.calls.push(op);let ok:unknown=null;
    if(op.kind==='contacts')ok=[state.friend,{...friend,id:'2',name:'Sam',unread:0,preview:null,lastMessageAt:null}];
    if(op.kind==='messages') {
      if(op.query && state.holdSearch) await new Promise<void>(resolve=>{state.releaseSearch=resolve;});
      ok=op.contact==='1'?state.rows.filter(m=>(m.expiresAt===null || m.expiresAt>Date.now())
        && (!op.before || m.timestamp<op.before[0] || m.timestamp===op.before[0] && BigInt(m.id)<BigInt(op.before[1]))
        && (!op.query || m.expiresAt===null && m.text.toLowerCase().includes(op.query.toLowerCase())))
        .sort((a,b)=>b.timestamp-a.timestamp || (BigInt(a.id)<BigInt(b.id)?1:-1)).slice(0,200):[];
    }
    if(op.kind==='send') {
      if(!state.ready)return route.fulfill({json:{error:{code:'not_connected'}}});
      const n=state.rows.length+1;state.rows.push({...row(n,op.text),outgoing:true,status:'queued',replyTo:op.reply_to});ok=String(n);
    }
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');await page.getByRole('button',{name:/Mira/}).click();
  await expect(page.locator('.message')).toHaveCount(Math.min(count,200));return state;
}

test('older history stays loaded across polls, keeps the scroll anchor and receives new messages',async({page})=>{
  const state=await app(page);
  await page.locator('.messages').evaluate(e=>e.scrollTop=0);
  const anchor=page.locator('[data-message-id="31"]');const top=(await anchor.boundingBox())!.y;
  await page.getByRole('button',{name:'Load older messages',exact:true}).click();
  await expect(page.locator('.message')).toHaveCount(230);
  expect(Math.abs((await anchor.boundingBox())!.y-top)).toBeLessThan(5);
  state.rows[0].status='read';state.rows[0].outgoing=true;
  await expect(page.locator('[data-message-id="1"] [aria-label="Read"]')).toHaveCount(1);
  state.rows.push(row(231,'New message after loading history'));
  await expect(page.locator('.message')).toHaveCount(231);
  await expect(page.locator('[data-message-id="1"]')).toContainText('History 1');
  expect(state.calls.find(op=>op.before).before).toEqual([1031,'31']);
  await page.getByRole('button',{name:/Sam/}).click();await page.getByRole('button',{name:/Mira/}).click();
  await expect(page.locator('.message')).toHaveCount(200);
});

test('message search reaches old history, excludes disappearing messages and supports replies',async({page})=>{
  const state=await app(page);state.rows[0].text='A needle in old history';state.rows[1].text='needle disappearing';state.rows[1].expiresAt=Date.now()+60_000;
  await page.getByRole('button',{name:'Search messages',exact:true}).click();
  await page.getByLabel('Search this conversation').fill('NEEDLE');await page.getByRole('button',{name:'Search',exact:true}).click();
  await expect(page.locator('.message-text')).toHaveText(['A needle in old history']);
  await expect(page.getByRole('status').filter({hasText:'1 matching message'})).toBeVisible();
  await page.screenshot({path:path.resolve('..','..','target','ui-history-search.png')});
  await page.locator('[data-message-id="1"]').getByRole('button',{name:'Message actions',exact:true}).click();
  await page.getByRole('button',{name:'Reply',exact:true}).click();
  await expect(page.locator('.reply-preview')).toContainText('A needle in old history');
  await expect(page.getByLabel('Search this conversation')).toHaveCount(0);
  await page.waitForTimeout(1200);
  await expect(page.locator('.reply-preview')).toContainText('A needle in old history');
  await page.getByLabel('Write a message').fill('Replying from search');await page.getByRole('button',{name:'Send message',exact:true}).click();
  expect(state.calls.find(op=>op.kind==='send').reply_to).toBe('1'.padStart(32,'0'));
});

test('late search responses cannot appear in another conversation',async({page})=>{
  const state=await app(page);state.holdSearch=true;
  await page.getByRole('button',{name:'Search messages',exact:true}).click();
  await page.getByLabel('Search this conversation').fill('History');await page.getByRole('button',{name:'Search',exact:true}).click();
  await expect.poll(()=>state.calls.some(op=>op.query==='History')).toBe(true);
  await page.getByRole('button',{name:/Sam/}).click();state.releaseSearch();
  await expect(page.locator('.message')).toHaveCount(0);await expect(page.getByLabel('Search this conversation')).toHaveCount(0);
});

test('established chats can queue while reconnecting and show real unread counts and previews',async({page})=>{
  const state=await app(page,3);state.connection='connecting';state.friend.repairStatus='repairing';
  await expect(page.getByRole('button',{name:/Mira/})).toContainText('17');
  await expect(page.getByRole('button',{name:/Mira/})).toContainText('Repairing encrypted session');
  await page.getByLabel('Write a message').fill('Save during reconnection');
  await expect(page.getByRole('button',{name:'Send message',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.getByLabel('Write a message')).toHaveValue('');
  await expect(page.locator('.message').last()).toContainText('Save during reconnection');
  await expect(page.locator('.message').last().getByRole('img',{name:'Queued',exact:true})).toBeVisible();
  state.friend.repairStatus=null;
  await expect(page.getByRole('button',{name:/Mira/})).toContainText('Latest conversation preview');
});

test('startup refusal keeps the draft and never claims a message was queued',async({page})=>{
  const state=await app(page,3);state.connection='offline';state.ready=false;
  await page.getByLabel('Write a message').fill('Keep this draft');await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText('has not been queued');
  await expect(page.getByLabel('Write a message')).toHaveValue('Keep this draft');await expect(page.locator('.message')).toHaveCount(3);
  state.ready=true;await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.getByLabel('Write a message')).toHaveValue('');await expect(page.locator('.message')).toHaveCount(4);
});

test('history and search controls fit a narrow screen',async({page})=>{
  await page.setViewportSize({width:390,height:800});await app(page,3);
  await page.getByRole('button',{name:'Search messages',exact:true}).click();
  await expect(page.getByLabel('Search this conversation')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.screenshot({path:path.resolve('..','..','target','ui-history-mobile.png')});
});
