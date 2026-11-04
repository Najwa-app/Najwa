import {test,expect,type Page} from '@playwright/test';
async function app(page:Page,errors:string[]){
  const session='a'.repeat(32);let attempts=0;
  const status={enabled:true,session,generation:1,phase:'unlocked',hardware:'protected',protection:'hardware',fingerprint:'b'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false};
  await page.route('**/api/**',async route=>{
    const path=new URL(route.request().url()).pathname;let ok:unknown=null;
    if(path==='/api/bootstrap')return route.fulfill({json:{token:'c'.repeat(64),session}});
    if(path==='/api/status')ok=status;
    if(path==='/api/invoke'){
      const data=route.request().postDataJSON();const op=data.args?.request?.operation;
      if(data.command==='messaging_status')ok={enabled:true,unlocked:true,connection:'connected',coverRunning:true,mailboxes:['d'.repeat(56)+'.onion'],pausedMailboxes:[],mailboxDetails:[{onion:'d'.repeat(56)+'.onion',registered:true,primary:true}],deliveryMode:'responsive'};
      else if(op?.kind==='invitation'){const error=errors[attempts++];if(error)return route.fulfill({json:{error:{code:error}}});ok='signed synthetic invitation';}
      else if(op?.kind==='invitation_details')ok={qrSvg:'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"></svg>',expiresAt:2000000000};
      else ok=[];
    }
    return route.fulfill({json:{ok}});
  });
  await page.goto('/');await page.getByRole('button',{name:'Create an invitation',exact:true}).click();
  await page.getByLabel('Your display name to share').fill('Synthetic User');await page.getByRole('button',{name:'Generate invitation',exact:true}).click();
  return ()=>attempts;
}
test('temporary invitation failures retry automatically with a clear progress message',async({page})=>{
  const attempts=await app(page,['registration_transport']);
  await expect(page.getByRole('dialog')).toContainText('Retrying your invitation automatically');
  await expect(page.getByLabel('Invitation to share')).toHaveValue('signed synthetic invitation');expect(attempts()).toBe(2);
});
test('closing the invitation stops scheduled retries',async({page})=>{
  const attempts=await app(page,['registration_transport']);
  await expect(page.getByRole('dialog')).toContainText('Retrying your invitation automatically');
  await page.getByRole('button',{name:'Close',exact:true}).click();await page.waitForTimeout(2400);expect(attempts()).toBe(1);
  await expect(page.getByLabel('Invitation to share')).toHaveCount(0);
});
test('permanent invitation errors stop without replaying the operation',async({page})=>{
  const attempts=await app(page,['mailbox_required']);
  await expect(page.getByRole('dialog').getByRole('alert')).toBeVisible();expect(attempts()).toBe(1);
});
test('repeated temporary failures stop after three attempts and leave a usable retry control',async({page})=>{
  const attempts=await app(page,['registration_transport','registration_transport','registration_transport']);
  await expect(page.getByRole('dialog').getByRole('alert')).toBeVisible({timeout:15_000});expect(attempts()).toBe(3);
  await expect(page.getByRole('button',{name:'Generate invitation',exact:true})).toBeEnabled();
});
