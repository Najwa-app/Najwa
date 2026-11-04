import { test, expect, type Page } from '@playwright/test';
const session = 'a'.repeat(32);
const fingerprint = 'b'.repeat(64);
const phrase = 'abandon '.repeat(23)+'about';
async function app(page:Page, phase='absent') {
  let status = {enabled:true,session,generation:1,phase,hardware:'unverified',protection:'os-keystore',fingerprint:phase === 'absent' ? null : fingerprint,
    recoveryAvailable:phase !== 'absent',recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false};
  const calls:Record<string,unknown>[] = [];
  await page.route('**/api/**',async route => {
    const path = new URL(route.request().url()).pathname;
    let ok:unknown = null;
    if (path === '/api/bootstrap') return route.fulfill({json:{token:'c'.repeat(64),session}});
    if (path === '/api/status') ok = status;
    if (path === '/api/lock') { status = {...status,phase:'locked',generation:status.generation+1,recoveryPending:false}; ok = status; }
    if (path === '/api/identity') {
      const {operation} = route.request().postDataJSON(); calls.push(operation);
      status = {...status,generation:status.generation+1};
      if (operation.kind === 'create' || operation.kind === 'unlock') status = {...status,phase:'unlocked',fingerprint,recoveryAvailable:true,recoveryPending:operation.kind === 'create'};
      if (operation.kind === 'acknowledge_recovery') status = {...status,recoveryPending:false};
      ok = {identity:status,value:operation.kind === 'recovery_words' ? {words:phrase} : operation.kind === 'export_recovery' ? {record:btoa('x'.repeat(105))} : null};
    }
    if (path === '/api/invoke') {
      const data = route.request().postDataJSON();
      ok = data.command === 'messaging_status' ? {enabled:true,unlocked:true,connection:'connecting',coverRunning:false,mailboxes:[],pausedMailboxes:[],mailboxDetails:[],deliveryMode:'responsive'} : [];
    }
    return route.fulfill({json:{ok}});
  });
  await page.goto('/'); return {calls};
}
test('creates an identity and requires both recovery-kit parts before continuing',async ({page}) => {
  const {calls} = await app(page);
  await expect(page.getByRole('heading',{name:'Make yourself at home.'})).toBeVisible();
  await page.getByLabel('New passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByLabel('Confirm passphrase').fill('orchard river lantern local');
  await page.getByRole('button',{name:'Create my identity'}).click();
  await expect(page.getByRole('heading',{name:'Save your recovery kit.'})).toBeVisible();
  const continueButton = page.getByRole('button',{name:'I’ve saved both — continue'});
  await expect(continueButton).toBeDisabled();
  await page.getByRole('button',{name:'Reveal recovery words'}).click();
  await expect(page.locator('.words li')).toHaveCount(24);
  const download = page.waitForEvent('download');
  await page.getByRole('button',{name:'Download recovery file'}).click();
  expect((await download).suggestedFilename()).toContain('.recovery');
  await expect(continueButton).toBeDisabled();
  await page.getByLabel('I saved the words somewhere safe.').check();
  await expect(continueButton).toBeDisabled();
  await page.getByRole('button',{name:'Check my recovery words'}).click();
  await expect(page.locator('.words li')).toHaveCount(0);
  const fields=page.locator('.word-check input');
  await expect(fields).toHaveCount(3);
  for(const input of await fields.all()) await input.fill('wrong');
  await page.getByRole('button',{name:'Check words',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText('These words do not match');
  expect(calls.some(call=>call.kind==='acknowledge_recovery')).toBe(false);
  const indices=await page.locator('.word-check label').allTextContents();
  expect(new Set(indices).size).toBe(3);
  for(let i=0;i<indices.length;i++) await fields.nth(i).fill(phrase.split(' ')[Number(indices[i].match(/\d+/)![0])-1]);
  await page.getByRole('button',{name:'Check words',exact:true}).click();
  await expect(page.getByRole('status')).toContainText('Your three recovery words match.');
  await continueButton.click();
  await expect(page.getByRole('heading',{name:'A private place to keep in touch.'})).toBeVisible();
  expect(calls.map(c => c.kind)).toEqual(['create','recovery_words','export_recovery','acknowledge_recovery']);
  expect(await page.evaluate(() => [localStorage.length,sessionStorage.length])).toEqual([0,0]);
});
test('a weak new passphrase is refused with a plain explanation and the estimator hint',async ({page}) => {
  await app(page);
  await page.route('**/api/identity',route => route.fulfill({json:{error:{code:'weak_passphrase',hint:'This is a very common password.'}}}));
  await page.getByLabel('New passphrase',{exact:true}).fill('password1234');
  await page.getByLabel('Confirm passphrase').fill('password1234');
  await page.getByRole('button',{name:'Create my identity'}).click();
  await expect(page.getByRole('alert')).toContainText('This passphrase is too easy to guess. Try four or more unrelated words. This is a very common password.');
  await expect(page.getByRole('heading',{name:'Make yourself at home.'})).toBeVisible();
});
test('unlocks an existing profile and clears the passphrase on lock',async ({page}) => {
  await app(page,'locked');
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa'}).click();
  await expect(page.getByRole('heading',{name:'A private place to keep in touch.'})).toBeVisible();
  await page.getByRole('button',{name:'Lock',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByLabel('Passphrase',{exact:true})).toHaveValue('');
});
test('recovery stays tied to this profile and asks for a new passphrase',async ({page}) => {
  const {calls} = await app(page,'locked');
  await page.getByRole('button',{name:'Forgot your passphrase?'}).click();
  await page.getByLabel('Recovery words').fill(phrase);
  await page.getByLabel('New passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByLabel('Confirm passphrase').fill('orchard river lantern local');
  await page.getByRole('button',{name:'Recover identity',exact:true}).click();
  expect(calls[0].kind).toBe('recover');
  await expect(page.getByLabel('Recovery words')).toHaveCount(0);
});
test('the account gate fits a narrow browser without horizontal scrolling',async ({page}) => {
  await page.setViewportSize({width:390,height:700}); await app(page);
  await expect(page.getByRole('button',{name:'Create my identity'})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
test('a fresh profile can import an encrypted recovery file and its matching words',async ({page}) => {
  const {calls} = await app(page);
  await page.getByRole('button',{name:'I already have a recovery kit'}).click();
  await page.getByLabel('Encrypted recovery file').setInputFiles({name:'najwa.recovery',mimeType:'application/octet-stream',buffer:Buffer.alloc(105)});
  await page.getByLabel('Recovery words').fill(phrase);
  await page.getByLabel('New passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByLabel('Confirm passphrase').fill('orchard river lantern local');
  await page.getByRole('button',{name:'Recover identity',exact:true}).click();
  expect(calls[0].kind).toBe('restore');
  expect((calls[0].record as string).length).toBe(140);
});
test('a stopped local service gives a reconnect instruction',async ({page}) => {
  await page.route('**/api/bootstrap',route => route.abort()); await page.goto('/');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('Start Najwa');
  await expect(page.getByRole('button',{name:'Reload',exact:true})).toBeVisible();
});
test('attempt limits and key storage failures are presented without raw errors',async ({page}) => {
  await app(page,'locked');
  let attempts = 0;
  await page.route('**/api/identity',route => route.fulfill({json:{error:++attempts === 1
    ? {code:'rate_limited',retryAfterMs:2100,detail:'do not render fixture'} : {code:'keystore_unavailable',detail:'do not render fixture'}}}));
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa'}).click();
  await expect(page.getByRole('alert')).toContainText('Too many attempts. Wait 3 seconds before trying again.');
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa'}).click();
  await expect(page.getByRole('alert')).toContainText('Key storage is unavailable.');
  await expect(page.getByText('do not render fixture')).toHaveCount(0);
  expect(attempts).toBe(2);
});
