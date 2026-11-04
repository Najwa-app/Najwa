import { mount } from 'svelte';
import Demo from './Demo.svelte';
import '../src/app.css';
import { connect } from './bridge';

const connection = await connect();
document.title = `Najwa — ${connection.username} — local test`;
mount(Demo, {target:document.getElementById('app')!, props:{connection}});
