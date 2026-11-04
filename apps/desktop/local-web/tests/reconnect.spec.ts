import { test, expect, type Page } from '@playwright/test';

const initialToken = 'c'.repeat(64);
const replacementToken = 'd'.repeat(64);
const initialSession = 'a'.repeat(32);
const replacementSession = 'b'.repeat(32);

async function reconnectService(page:Page) {
  const service = {online:true,token:initialToken,session:initialSession,paired:false,writes:0,restartOnWrite:false};
  await page.route('**/api/**',async route => {
    const request = route.request();
    if (!service.online) return route.abort();
    const path = new URL(request.url()).pathname;
    if (path === '/api/bootstrap') {
      if (!service.paired && request.headers()['x-najwa-launch'] !== service.token) return route.fulfill({status:403,json:{error:{code:'forbidden'}}});
      service.paired = true;
      return route.fulfill({json:{token:service.token,session:service.session}});
    }
    if (request.method() === 'POST') {
      service.writes++;
      if (service.restartOnWrite) {
        service.restartOnWrite = false;
        service.token = replacementToken; service.session = replacementSession;
      }
    }
    if (request.headers()['x-najwa-session'] !== service.token) return route.fulfill({status:403,json:{error:{code:'forbidden'}}});
    if (path === '/api/status') return route.fulfill({json:{ok:{enabled:true,session:service.session,generation:1,phase:'locked',hardware:'unverified',protection:'os-keystore',fingerprint:'e'.repeat(64),recoveryAvailable:true,recoveryPending:false,prekeyRefreshRequired:false,unavailableReason:null,busy:false}}});
    return route.fulfill({json:{ok:null}});
  });
  return service;
}

test('a fresh launch link reconnects an already open unpaired tab',async ({page}) => {
  await reconnectService(page);
  await page.goto('/');
  await expect(page.getByRole('alert')).toBeVisible();
  await page.goto('/#'+initialToken);
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(new URL(page.url()).hash).toBe('');
});

test('an open paired browser reconnects after restart and clears its passphrase',async ({page}) => {
  const service = await reconnectService(page);
  await page.goto('/#'+initialToken);
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await page.getByLabel('Passphrase',{exact:true}).fill('unfinished local passphrase');
  service.token = replacementToken; service.session = replacementSession;
  await expect(page.getByLabel('Passphrase',{exact:true})).toHaveValue('',{timeout:10_000});
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(await page.evaluate(() => [localStorage.length,sessionStorage.length])).toEqual([0,0]);
});

test('a temporary startup failure recovers without reloading the page',async ({page}) => {
  const service = await reconnectService(page);
  service.online = false;
  await page.goto('/#'+initialToken);
  await expect(page.getByRole('alert')).toContainText('Start Najwa');
  service.online = true;
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible({timeout:10_000});
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('a restart does not replay a passphrase submission',async ({page}) => {
  const service = await reconnectService(page);
  await page.goto('/#'+initialToken);
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  service.restartOnWrite = true;
  await page.getByRole('button',{name:'Unlock Najwa',exact:true}).click();
  await expect.poll(() => service.writes).toBe(1);
  await expect(page.getByRole('heading',{name:'Welcome back.'})).toBeVisible();
  await expect(page.getByLabel('Passphrase',{exact:true})).toHaveValue('');
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(service.writes).toBe(1);
});
