import {test,expect,type Page} from '@playwright/test';
const session='a'.repeat(32);
async function app(page:Page,phase='unlocked',rejectBridges=false){
  let status={enabled:true,session,generation:1,phase,hardware:'protected',protection:'hardware',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false,lockTimeoutSeconds:300};
  let preferences={lockTimeoutSeconds:300,bridges:[] as string[]};
  const mutations:{path:string;data:any}[]=[];
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;let ok:unknown=null;
    if(path==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session}});
    if(path==='/api/status')ok=status;
    if(path==='/api/preferences'){
      if(route.request().method()==='POST'){
        const data=route.request().postDataJSON();mutations.push({path,data});
        if(rejectBridges&&data.preferences.bridges.length)return route.fulfill({json:{error:{code:'invalid_bridges'}}});
        const changed=JSON.stringify(preferences.bridges)!==JSON.stringify(data.preferences.bridges);
        preferences=data.preferences;status={...status,lockTimeoutSeconds:preferences.lockTimeoutSeconds,...(changed?{phase:'locked',generation:status.generation+1}:{})};
        ok={preferences,identity:status};
      }else ok=preferences;
    }
    if(path==='/api/erase'){mutations.push({path,data:route.request().postDataJSON()});ok={...status,phase:'erased'};}
    if(path==='/api/invoke'){const data=route.request().postDataJSON();ok=data.command==='messaging_status'?{enabled:true,unlocked:true,connection:'offline',coverRunning:false,mailboxes:[],pausedMailboxes:[],mailboxDetails:[],deliveryMode:'responsive'}:[];}
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');return mutations;
}
test('saves a profile lock timeout and shows it in Identity',async({page})=>{
  const calls=await app(page);await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByLabel('Lock after inactivity').selectOption('900');await page.getByRole('button',{name:'Save settings',exact:true}).click();
  await expect(page.getByText('Settings saved.',{exact:true})).toBeVisible();
  expect(calls[0].data.preferences).toEqual({lockTimeoutSeconds:900,bridges:[]});
  await page.getByRole('button',{name:'Identity',exact:true}).click();
  await expect(page.getByText(/Najwa locks after 15 minutes/)).toBeVisible();
  expect(await page.evaluate(()=>[localStorage.length,sessionStorage.length])).toEqual([0,0]);
});
test('bridge changes lock and do not silently retry with direct Tor',async({page})=>{
  const calls=await app(page);await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByLabel('Tor connection',{exact:true}).selectOption({label:'Use bridges'});
  await page.getByRole('button',{name:'Save settings',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText('Paste at least one bridge');expect(calls).toHaveLength(0);
  await page.getByLabel('Bridge lines').fill('Bridge 127.0.0.1:9 0123456789ABCDEF0123456789ABCDEF01234567');
  await expect(page.getByText('Changing bridges locks Najwa', {exact:false})).toBeVisible();
  await page.getByRole('button',{name:'Save and lock',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  expect(calls[0].data.preferences.bridges).toHaveLength(1);expect(calls).toHaveLength(1);
});
test('invalid bridges remain editable and never trigger a fallback save',async({page})=>{
  const calls=await app(page,'unlocked',true);await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByLabel('Tor connection',{exact:true}).selectOption({label:'Use bridges'});
  await page.getByLabel('Bridge lines').fill('obfs4 invalid');await page.getByRole('button',{name:'Save and lock'}).click();
  await expect(page.getByRole('alert')).toContainText('Check your bridge lines');
  await expect(page.getByLabel('Bridge lines')).toHaveValue('obfs4 invalid');expect(calls).toHaveLength(1);
});
test('erasure works offline only after an explicit checkbox and typed confirmation',async({page})=>{
  const calls=await app(page);await page.getByRole('button',{name:'Identity',exact:true}).click();
  await page.getByRole('button',{name:'Erase local profile…',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Erase this local profile?'});const erase=dialog.getByRole('button',{name:'Erase local profile',exact:true});
  await expect(erase).toBeDisabled();await dialog.getByLabel('Type ERASE to confirm').fill('ERASE');await expect(erase).toBeDisabled();
  await dialog.getByRole('checkbox').check();await expect(erase).toBeEnabled();
  await page.keyboard.press('Escape');await expect(dialog).not.toBeVisible();expect(calls).toHaveLength(0);
  await page.getByRole('button',{name:'Erase local profile…',exact:true}).click();await expect(erase).toBeDisabled();
  await dialog.getByRole('checkbox').check();await dialog.getByLabel('Type ERASE to confirm').fill('ERASE');await erase.click();
  await expect(page.getByRole('heading',{name:'Local profile erased.'})).toBeVisible();
  expect(calls).toHaveLength(1);expect(calls[0].data).toEqual({session,generation:1,confirmed:true,confirmation:'ERASE'});
  await expect(page.getByRole('button',{name:'Unlock Najwa'})).toHaveCount(0);
});
test('interrupted erasure has a retry screen with no unlock or creation',async({page})=>{
  await app(page,'wiping');await expect(page.getByRole('heading',{name:'Finish local erasure'})).toBeVisible();
  await expect(page.getByLabel('Passphrase',{exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Retry Erase local profile'}).click();
  await expect(page.getByRole('dialog',{name:'Erase this local profile?'})).toBeVisible();
});
test('settings and erase confirmation fit a narrow window',async({page})=>{
  await page.setViewportSize({width:390,height:740});await app(page);
  await page.getByRole('button',{name:'Settings',exact:true}).click();await page.getByLabel('Tor connection',{exact:true}).selectOption({label:'Use bridges'});
  await expect(page.getByLabel('Bridge lines')).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.getByRole('button',{name:'Identity',exact:true}).click();await page.getByRole('button',{name:'Erase local profile…',exact:true}).click();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'../../target/ui-profile-erasure-mobile.png'});
});
