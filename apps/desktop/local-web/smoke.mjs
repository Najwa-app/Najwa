// Real loopback service smoke test, called by the Rust persistence test.
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
const origin = process.argv[2];
if (!/^http:\/\/127\.0\.0\.1:\d+\/#\w{64}$/.test(origin)) throw new Error('expected local launch URL');
const browser = await chromium.launch({channel:'msedge'});
const page = await browser.newPage({viewport:{width:1280,height:800}});
const errors=[]; page.on('pageerror',error => errors.push(error.message));
await mkdir('../../target/local-web-review',{recursive:true});
try {
  await page.goto(origin);
  await page.getByRole('heading',{name:'A private place to keep in touch.'}).waitFor();
  if (new URL(page.url()).hash) throw new Error('launch grant must be removed from browser history');
  await page.reload();
  await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa'}).click();
  await page.getByRole('heading',{name:'A private place to keep in touch.'}).waitFor({timeout:90_000});
  await page.screenshot({path:'../../target/local-web-review/onboarding.png'});
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('heading',{name:'Settings',exact:true}).waitFor();
  await page.screenshot({path:'../../target/local-web-review/settings.png'});
  await page.getByRole('button',{name:'Identity',exact:true}).click();
  await page.getByRole('heading',{name:'Always you.'}).waitFor();
  await page.getByRole('button',{name:'Lock',exact:true}).click();
  await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
  await page.screenshot({path:'../../target/local-web-review/unlock.png'});
  await page.getByLabel('Passphrase',{exact:true}).fill('orchard river lantern local');
  await page.getByRole('button',{name:'Unlock Najwa'}).click();
  await page.getByRole('heading',{name:'Always you.'}).waitFor({timeout:90_000});
  if (await page.evaluate(() => localStorage.length+sessionStorage.length)) throw new Error('browser storage must remain empty');
  if (errors.length) throw new Error(errors.join('\n'));
  await page.getByRole('button',{name:'Lock',exact:true}).click();
  await page.getByRole('heading',{name:'Welcome back.'}).waitFor();
} finally { await browser.close(); }
