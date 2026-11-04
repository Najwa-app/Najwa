import {test,expect,type Page} from '@playwright/test';
async function app(page:Page) {
  let status={enabled:true,session:'a'.repeat(32),generation:1,phase:'absent',hardware:'unverified',protection:'hardware',fingerprint:null as string|null,recoveryAvailable:false,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false,softwareFallbackAvailable:false,softwareFallbackApproved:false};
  const calls:Record<string,unknown>[]=[];
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;
    if(path==='/api/bootstrap') return route.fulfill({json:{token:'c'.repeat(64),session:status.session}});
    if(path==='/api/status') return route.fulfill({json:{ok:status}});
    if(path==='/api/invoke') {
      const data=route.request().postDataJSON();
      return route.fulfill({json:{ok:data.command==='messaging_status'?{enabled:true,unlocked:true,connection:'connecting',coverRunning:false,mailboxes:[],pausedMailboxes:[],mailboxDetails:[],deliveryMode:'responsive'}:[]}});
    }
    if(path==='/api/identity') {
      const {operation}=route.request().postDataJSON(); calls.push(operation);
      status={...status,generation:status.generation+1};
      if(operation.kind==='create'&&!status.softwareFallbackApproved) {
        status={...status,softwareFallbackAvailable:true};
        return route.fulfill({json:{error:{code:'keystore_unavailable'}}});
      }
      if(operation.kind==='approve_software_storage') status={...status,softwareFallbackApproved:true,softwareFallbackAvailable:false};
      if(operation.kind==='create') status={...status,phase:'unlocked',fingerprint:'b'.repeat(64),hardware:'unavailable',protection:'os-keystore',recoveryAvailable:true,recoveryPending:true};
      return route.fulfill({json:{ok:{identity:status,value:null}}});
    }
    return route.fulfill({json:{ok:null}});
  });
  await page.goto('/');
  return {calls};
}
async function create(page:Page) {
  await page.getByLabel('New passphrase',{exact:true}).fill('orchard software storage consent');
  await page.getByLabel('Confirm passphrase').fill('orchard software storage consent');
  await page.getByRole('button',{name:'Create my identity',exact:true}).click();
}
test('declining software storage does not approve it or replay creation',async({page})=>{
  const {calls}=await app(page);
  await expect(page.getByRole('button',{name:'Use system key storage instead…'})).toHaveCount(0);
  await create(page);
  await page.getByRole('button',{name:'Use system key storage instead…'}).click();
  const dialog=page.getByRole('dialog');
  await expect(dialog.getByRole('checkbox')).not.toBeChecked();
  await expect(dialog.getByRole('button',{name:'Use system key storage',exact:true})).toBeDisabled();
  await dialog.getByRole('button',{name:'Keep hardware protection'}).click();
  await expect(dialog).toHaveCount(0);
  expect(calls.map(call=>call.kind)).toEqual(['create']);
  await create(page);
  await expect(page.getByRole('alert')).toBeVisible();
  expect(calls.map(call=>call.kind)).toEqual(['create','create']);
});
test('software storage requires confirmation, leaves secrets cleared and displays its actual protection',async({page})=>{
  const {calls}=await app(page);
  await create(page);
  await page.getByRole('button',{name:'Use system key storage instead…'}).click();
  const dialog=page.getByRole('dialog');
  await dialog.getByRole('checkbox').check();
  await dialog.getByRole('button',{name:'Use system key storage',exact:true}).click();
  await expect(dialog).toHaveCount(0);
  expect(calls.map(call=>call.kind)).toEqual(['create','approve_software_storage']);
  expect(calls[1]).toEqual({kind:'approve_software_storage',confirmed:true});
  await expect(page.getByLabel('New passphrase',{exact:true})).toHaveValue('');
  await create(page);
  await expect(page.getByRole('heading',{name:'Save your recovery kit.'})).toBeVisible();
  await expect(page.getByText('Using system key storage — approved by you.',{exact:false})).toBeVisible();
  expect(await page.evaluate(()=>[localStorage.length,sessionStorage.length])).toEqual([0,0]);
});
test('the approval dialog supports keyboard cancellation without granting consent',async({page})=>{
  const {calls}=await app(page);
  await create(page);
  await page.getByRole('button',{name:'Use system key storage instead…'}).click();
  const dialog=page.getByRole('dialog');
  await expect(dialog.getByRole('checkbox')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  expect(calls.map(call=>call.kind)).toEqual(['create']);
});
