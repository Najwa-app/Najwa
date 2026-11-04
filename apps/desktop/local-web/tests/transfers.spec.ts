import {test,expect,type Page} from '@playwright/test';
import {createHash} from 'node:crypto';
import {open,mkdir} from 'node:fs/promises';
import path from 'node:path';
const PART=1024*1024;
async function app(page:Page,{resume=false,pause=false}={}) {
  const state={parts:resume?[0]:[] as number[],posts:[] as number[],begins:[] as any[],finished:0,busy:!pause,held:null as any,link:'/api/download/'+'e'.repeat(64),activity:0,phase:'unlocked',generation:1};
  const identity=()=>({enabled:true,session:'a'.repeat(32),generation:state.generation,phase:state.phase,hardware:'unverified',protection:'os-keystore',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false});
  let manifest:any=null;
  await page.route('**/api/**',async route=>{
    const pathname=new URL(route.request().url()).pathname;
    if(pathname==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session:'a'.repeat(32)}});
    if(pathname==='/api/status')return route.fulfill({json:{ok:identity()}});
    if(pathname==='/api/activity'){state.activity++;return route.fulfill({json:{ok:null}});}
    if(pathname==='/api/lock'){state.phase='locked';state.generation++;return route.fulfill({json:{ok:identity()}});}
    if(pathname==='/api/transfers'){
      const action=route.request().postDataJSON().action;
      if(action.kind==='begin'){manifest=action.manifest;state.begins.push(manifest);return route.fulfill({json:{ok:{id:'f'.repeat(32),filename:manifest.name,size:manifest.size,uploaded:state.parts.reduce((n,i)=>n+Math.min(PART,manifest.size-i*PART),0),phase:'uploading',parts:state.parts,error:null}}});}
      if(action.kind==='finish'){state.finished++;return route.fulfill({json:{ok:null}});}
      if(action.kind==='download')return route.fulfill({json:{ok:{url:state.link,filename:'ready.wav'}}});
      return route.fulfill({json:{ok:manifest && !state.finished?[{id:'f'.repeat(32),filename:manifest.name,size:manifest.size,uploaded:state.parts.length*PART,phase:'uploading',error:null}]:[]}});
    }
    if(pathname.startsWith('/api/transfer-part/')){
      const part=Number(pathname.split('/').pop());state.posts.push(part);
      const body=route.request().postDataBuffer()!;expect(body.length).toBeLessThanOrEqual(PART);expect(createHash('sha256').update(body).digest('hex')).toBe(manifest.hashes[part]);
      if(state.busy){state.busy=false;return route.fulfill({json:{error:{code:'busy'}}});}
      if(pause && part===1 && state.begins.length===1){state.held=route;return;}
      state.parts.push(part);return route.fulfill({json:{ok:null}});
    }
    if(pathname.startsWith('/api/download/'))return route.fulfill({body:Buffer.from('streamed'),headers:{'content-type':'application/octet-stream','content-disposition':'attachment; filename="ready.wav"'}});
    if(pathname==='/api/invoke'){
      const {command,args}=route.request().postDataJSON();
      if(command==='messaging_status')return route.fulfill({json:{ok:{enabled:true,unlocked:true,connection:'connected',coverRunning:false,mailboxes:['a'.repeat(56)+'.onion'],pausedMailboxes:[],deliveryMode:'responsive',pendingDeposits:0}}});
      const op=args.request.operation;
      return route.fulfill({json:{ok:op.kind==='contacts'?[{id:'1',name:'Transfer friend',ready:true,verified:false,blocked:false,unread:0,safetyNumber:'abcd abcd abcd abcd abcd abcd abcd abcd',timerSeconds:0,timerPending:false}]:op.kind==='messages'?[{id:'1',msgId:'d'.repeat(32),text:'',outgoing:false,timestamp:1700000000,status:'delivered',expiresAt:null,attachment:{filename:'ready.wav',size:4096,chunks:1,availableChunks:1,complete:true,supported:true}}]:null}});
    }
    return route.fulfill({json:{ok:null}});
  });
  await page.goto('/');await page.getByRole('button',{name:/Transfer friend/}).click();return state;
}
test('upload skips persisted parts, verifies all part hashes and retries a temporary failure',async({page})=>{
  const state=await app(page,{resume:true});const file={name:'large.wav',mimeType:'audio/wav',buffer:Buffer.alloc(2*PART+17,3)};
  await page.getByLabel('Attach file',{exact:true}).setInputFiles(file);
  await expect.poll(()=>state.finished).toBe(1);expect(state.begins[0].hashes).toHaveLength(3);expect(state.posts).toEqual([1,1,2]);
  await expect(page.getByRole('status').filter({hasText:'File saved in the encrypted queue'})).toBeVisible();
});
test('paused upload can reselect the same file and resume without resending saved parts',async({page})=>{
  const state=await app(page,{pause:true});const file={name:'resumable.wav',mimeType:'audio/wav',buffer:Buffer.alloc(2*PART+17,5)};
  await page.getByLabel('Attach file',{exact:true}).setInputFiles(file);await expect.poll(()=>!!state.held).toBe(true);
  await page.getByRole('button',{name:'Pause upload',exact:true}).click();await expect(page.getByRole('button',{name:'Pause upload',exact:true})).toHaveCount(0);
  await state.held.fulfill({json:{ok:null}}).catch(()=>{});
  await page.getByLabel('Attach file',{exact:true}).setInputFiles(file);await expect.poll(()=>state.finished).toBe(1);
  expect(state.begins[0]).toEqual(state.begins[1]);expect(state.posts.filter(v=>v===0)).toHaveLength(1);expect(state.parts).toEqual([0,1,2]);
});
test('files beyond 256 MiB are refused before upload',async({page},info)=>{
  const state=await app(page);const file=info.outputPath('too-large.wav');await mkdir(path.dirname(file),{recursive:true});const handle=await open(file,'w');await handle.truncate(256*PART+1);await handle.close();
  await page.getByLabel('Attach file',{exact:true}).setInputFiles(file);await expect(page.getByRole('alert')).toContainText('up to 256 MB');expect(state.begins).toHaveLength(0);
});
test('downloads use the browser stream and refuse an unexpected download URL',async({page})=>{
  const state=await app(page);const download=page.waitForEvent('download');await page.getByRole('button',{name:'Download ready.wav',exact:true}).click();expect((await download).suggestedFilename()).toBe('ready.wav');
  state.link='https://invalid.example/file';await page.getByRole('button',{name:'Download ready.wav',exact:true}).click();await expect(page.getByRole('alert')).toContainText('integrity');
});

test('keep unlocked is opt-in, stops when unchecked and resets at lock',async({page})=>{
  await page.clock.install();const state=await app(page);const toggle=page.getByRole('checkbox',{name:'Keep unlocked',exact:true});
  await page.setViewportSize({width:390,height:844});await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:test.info().outputPath('large-files-mobile.png')});
  await expect(toggle).not.toBeChecked();await page.clock.runFor(31_000);const idle=state.activity;await page.clock.runFor(31_000);expect(state.activity).toBe(idle);
  await toggle.check();await page.clock.runFor(31_000);await expect.poll(()=>state.activity).toBeGreaterThan(idle);
  await toggle.uncheck();const stopped=state.activity;await page.clock.runFor(45_000);expect(state.activity).toBe(stopped);
  await toggle.check();await page.getByRole('button',{name:'Lock',exact:true}).click();await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  const locked=state.activity;await page.clock.runFor(45_000);expect(state.activity).toBe(locked);
  state.phase='unlocked';state.generation++;await page.clock.runFor(1600);await expect(toggle).not.toBeChecked();
});
