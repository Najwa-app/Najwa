import { defineConfig } from '@playwright/test';
import { fileURLToPath } from 'node:url';
export default defineConfig({testDir:'./tests',fullyParallel:true,retries:0,workers:2,reporter:'list',
  use:{baseURL:'http://127.0.0.1:4175',channel:'msedge',viewport:{width:1280,height:800},trace:'retain-on-failure'},
  webServer:{cwd:fileURLToPath(new URL('..',import.meta.url)),command:'npx vite preview --config local-web/vite.config.ts --host 127.0.0.1 --port 4175 --strictPort',url:'http://127.0.0.1:4175',reuseExistingServer:false}
});
