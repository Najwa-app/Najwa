import { mount } from 'svelte';
import LocalWeb from './LocalWeb.svelte';
import '../src/app.css';
mount(LocalWeb,{target:document.getElementById('app')!});
