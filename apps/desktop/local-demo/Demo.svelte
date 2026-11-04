<script lang="ts">
  import { onMount } from 'svelte';
  import Messenger from '../src/Messenger.svelte';
  import logo from '../src/assets/najwa-mark.png';
  import { messagingStatus, unavailableNetwork, type NetworkStatus } from '../src/messaging';
  import type { IdentityStatus } from '../src/identity';
  import { invoke, type Bootstrap } from './bridge';
  let { connection }: {connection:Bootstrap} = $props();
  const identity: IdentityStatus = $derived({ enabled:true, session:connection.session, generation:1,
    phase:'unlocked', hardware:'unverified', fingerprint:connection.fingerprint,
    recoveryAvailable:false, recoveryPending:false, prekeyRefreshRequired:false, unavailableReason:null });
  let network = $state<NetworkStatus>({...unavailableNetwork,enabled:true,unlocked:true,connection:'connecting'});
  let section = $state<'chats' | 'contacts' | 'settings'>('chats');
  let phase = $state('Starting independent Rust peers…');
  let checking = false;
  onMount(() => {
    const refresh = async () => {
      if (checking) return;
      checking = true;
      try {
        network = await messagingStatus();
        phase = await invoke<string>('demo_status');
      } catch { phase = 'Local peer unavailable'; }
      finally { checking = false; }
    };
    void refresh();
    const interval = setInterval(() => void refresh(), 2000);
    return () => clearInterval(interval);
  });
</script>

<div class="app-shell">
  <header class="brandbar"><div class="brand"><img src={logo} alt="Najwa"/>Najwa</div><b>{connection.username}</b><span class="local-label">Local test · synthetic identity · Docker mailbox via Tor</span></header>
  <div class="demo-progress" role="status">{phase}. Identity keys live in Rust memory; this test has no TPM or recovery flow.</div>
  <div class="workspace"><nav class="rail" aria-label="Navigation">
    <button class:active={section === 'chats'} onclick={() => section = 'chats'}>Chats</button>
    <button class:active={section === 'contacts'} onclick={() => section = 'contacts'}>Contacts</button>
    <button class:active={section === 'settings'} onclick={() => section = 'settings'}>Settings</button>
  </nav><Messenger {identity} {network} {section} navigate={value => section = value}/></div>
</div>

<style>
  .demo-progress { padding:8px 24px; background:var(--accent-soft); color:var(--ink); font-size:12px; border-bottom:1px solid var(--line); }
  .brandbar { gap:20px; }
</style>
