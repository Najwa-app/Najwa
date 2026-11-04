import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  root:fileURLToPath(new URL('.',import.meta.url)),plugins:[svelte()],
  define:{__NAJWA_LOCAL_WEB__:true},
  resolve:{alias:{'najwa:bridge':fileURLToPath(new URL('./bridge.ts',import.meta.url))}},
  build:{outDir:'../../../target/local-web-ui',emptyOutDir:true,target:'es2022',assetsInlineLimit:0,sourcemap:false}
});
