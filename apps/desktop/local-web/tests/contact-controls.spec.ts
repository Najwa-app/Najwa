import {test,expect,type Page} from '@playwright/test';
async function app(page:Page) {
  const contact={id:'1',name:'Offline friend',ready:true,verified:false,blocked:false,unread:0,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false};
  const state={contacts:[contact],calls:[] as any[],uploads:0,messages:[{id:'1',msgId:'d'.repeat(32),text:'Original message',outgoing:false,timestamp:1700000000,status:'delivered',expiresAt:null}] as any[]};
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==='/api/bootstrap') return route.fulfill({json:{token:'c'.repeat(64),session:'a'.repeat(32)}});
    if(path==='/api/status') return route.fulfill({json:{ok:{enabled:true,session:'a'.repeat(32),generation:1,phase:'unlocked',hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false}}});
    if(path.startsWith('/api/transfer-part/')) {state.uploads++;expect(route.request().headers()['content-type']).toBe('application/octet-stream');expect(route.request().headers()['x-najwa-identity']).toBe('a'.repeat(32));return route.fulfill({json:{ok:null}});}
    if(path==='/api/transfers') {const action=route.request().postDataJSON().action;return route.fulfill({json:{ok:action.kind==='list'?[]:action.kind==='begin'?{id:'e'.repeat(32),phase:'uploading',uploaded:0,parts:[]}:action.kind==='download'?{url:'/api/download/'+'e'.repeat(64),filename:'safe.webp'}:null}});}
    if(path.startsWith('/api/download/'))return route.fulfill({headers:{'content-type':'application/octet-stream','content-disposition':'attachment; filename="safe.webp"'},body:Buffer.from('RIFF')});
    if(path!=='/api/invoke') return route.fulfill({json:{ok:null}});
    const {command,args}=route.request().postDataJSON();
    if(command==='messaging_status') return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection:'connected',coverRunning:false,mailboxes:['a'.repeat(56)+'.onion'],mailboxDetails:[{onion:'a'.repeat(56)+'.onion',registered:true,primary:true}],pausedMailboxes:[],deliveryMode:'responsive',pendingDeposits:0}}});
    const op=args.request.operation;state.calls.push(op);let ok:unknown=null;
    if(op.kind==='contacts') ok=state.contacts;
    if(op.kind==='messages') ok=[...state.messages].reverse();
    if(op.kind==='manage_contact') {if(op.action==='delete') {state.contacts=[];state.messages=[];} else if(op.action==='rename') contact.name=op.name; else contact.blocked=op.action==='block';}
    if(op.kind==='send') state.messages.push({id:'2',msgId:'e'.repeat(32),text:op.text,replyTo:op.reply_to,outgoing:true,timestamp:1700000001,status:'queued',expiresAt:null});
    if(op.kind==='download_file') ok={filename:'safe.webp',data:'UklGRg=='};
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');await page.getByRole('button',{name:/Offline friend/}).click();return state;
}
test('rename, block, unblock and confirmed deletion work while the peer is offline',async({page})=>{
  const state=await app(page);
  await page.getByRole('button',{name:'Contact details',exact:true}).click();
  await page.getByLabel('Contact name on this computer').fill('Renamed friend');await page.getByRole('button',{name:'Save name',exact:true}).click();
  await expect(page.locator('.chat-title')).toContainText('Renamed friend');
  await page.getByRole('button',{name:'Contact details',exact:true}).click();await page.getByRole('button',{name:'Block contact',exact:true}).click();
  await expect(page.getByLabel('Write a message',{exact:true})).toBeDisabled();
  await page.getByRole('button',{name:'Contact details',exact:true}).click();await page.getByRole('button',{name:'Unblock contact',exact:true}).click();
  await expect(page.getByLabel('Write a message',{exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Contact details',exact:true}).click();await page.getByRole('button',{name:'Delete contact…',exact:true}).click();
  await expect(page.getByRole('dialog')).toContainText("removes the conversation from the other person's Najwa when their app receives the notice");
  await expect(page.getByRole('dialog')).toContainText('cannot remove copies they made themselves');
  await page.getByRole('button',{name:'Keep contact',exact:true}).click();expect(state.contacts).toHaveLength(1);
  await page.getByRole('button',{name:'Delete contact…',exact:true}).click();await page.getByRole('button',{name:'Delete contact and history',exact:true}).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();await expect(page.getByText('Original message',{exact:true})).toHaveCount(0);
  expect(state.contacts).toHaveLength(0);expect(state.calls.filter(c=>c.kind==='manage_contact').map(c=>c.action)).toEqual(['rename','block','unblock','delete']);
});
test('quoted replies preserve the original reference and render escaped text',async({page})=>{
  const state=await app(page);await page.getByRole('button',{name:'Message actions',exact:true}).first().click();await page.getByRole('button',{name:'Reply',exact:true}).click();
  await expect(page.locator('.reply-preview')).toContainText('Original message');
  await page.getByLabel('Write a message',{exact:true}).fill('<script>plain text</script>');await page.getByRole('button',{name:'Send message',exact:true}).click();
  await expect(page.locator('.quoted-message')).toContainText('Original message');
  expect(state.calls.find(c=>c.kind==='send').reply_to).toBe('d'.repeat(32));await expect(page.locator('.message script')).toHaveCount(0);
});
test('file controls upload a bounded binary body and offer completed downloads',async({page})=>{
  const state=await app(page);
  await page.getByLabel('Attach file',{exact:true}).setInputFiles({name:'photo.png',mimeType:'image/png',buffer:Buffer.from([1,2,3])});
  await expect(page.getByRole('status').filter({hasText:'File saved in the encrypted queue'})).toBeVisible();expect(state.uploads).toBe(1);
  state.messages.push({id:'3',msgId:'f'.repeat(32),text:'',outgoing:false,timestamp:1700000002,status:'delivered',expiresAt:null,attachment:{filename:'safe.webp',size:1024,chunks:2,availableChunks:1,complete:false,supported:true}});
  await expect(page.getByRole('button',{name:'Download safe.webp',exact:true})).toBeDisabled();
  state.messages[1].attachment.availableChunks=2;state.messages[1].attachment.complete=true;
  const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download safe.webp',exact:true}).click();expect((await download).suggestedFilename()).toBe('safe.webp');
});
test('QR scanner provides an image fallback and closes cleanly after camera denial',async({page})=>{
  await app(page);await page.getByRole('button',{name:'Add contact invitation',exact:true}).click();
  await expect(page.getByText('Upload QR image',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Scan with camera',exact:true}).click();
  await expect(page.getByRole('alert').filter({hasText:'Camera unavailable or permission denied'})).toBeVisible();
  await page.getByRole('button',{name:'Close',exact:true}).click();await expect(page.locator('video')).toHaveCount(0);
});
test('a quoted draft releases an expired original without retaining its text',async({page})=>{
  const state=await app(page);
  state.messages[0].expiresAt=Date.now()+2500;
  await expect(page.getByLabel('Disappearing message',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Message actions',exact:true}).first().click();await page.getByRole('button',{name:'Reply',exact:true}).click();
  await expect(page.locator('.reply-preview')).toContainText('Original message');
  state.messages=[];
  await expect(page.locator('.reply-preview')).toHaveCount(0);
  await expect(page.getByText('Original message',{exact:true})).toHaveCount(0);
});
