<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './bridge';
  import type { IdentityStatus } from '../src/identity';
  type Preferences = {lockTimeoutSeconds:number;bridges:string[]};
  let {identity,onchange}:{identity:IdentityStatus;onchange:(identity:IdentityStatus)=>void} = $props();
  let saved = $state<Preferences | null>(null);
  let timeout = $state(300); let useBridges = $state(false); let lines = $state('');
  let busy = $state(false); let error = $state(''); let note = $state(''); let active = true;
  const changed = $derived(saved && (timeout !== saved.lockTimeoutSeconds || useBridges !== (saved.bridges.length>0) || JSON.stringify(bridgeLines()) !== JSON.stringify(saved.bridges)));
  const routingChanged = $derived(saved && JSON.stringify(bridgeLines()) !== JSON.stringify(saved.bridges));
  function bridgeLines() { return useBridges ? lines.split('\n').map(line=>line.trim()).filter(Boolean) : []; }
  function failure(value:unknown) {
    return ({invalid_preferences:'Choose a lock timeout between 1 and 60 minutes.',invalid_bridges:'Check your bridge lines. Use up to 8 plain, obfs4 or Snowflake bridges, one per line.',
      bridge_helper_unavailable:'The bundled bridge helper is missing or damaged. Reinstall a complete Najwa package. Your saved connection settings have not changed.',
      stale_operation:'Your identity was locked or changed. Unlock it before saving settings.',lock_failed:'Settings were saved, but locking could not finish. Use Retry Lock now before continuing.'} as Record<string,string>)[(value as {code?:string})?.code??''] ?? 'Settings could not be read or saved. Try again.';
  }
  async function load() {
    error='';
    try { const value=await api<Preferences>('/api/preferences'); if(!active)return;
      saved=value;timeout=value.lockTimeoutSeconds;useBridges=value.bridges.length>0;lines=value.bridges.join('\n');
    } catch(value) {if(active)error=failure(value);}
  }
  async function save(event:SubmitEvent) {
    event.preventDefault();if(busy||!saved)return;
    const bridges=bridgeLines();
    if(useBridges&&!bridges.length){error='Paste at least one bridge line, or choose Direct Tor.';return;}
    busy=true;error='';note='';
    try {
      const result=await api<{preferences:Preferences;identity:IdentityStatus}>('/api/preferences',{
        session:identity.session,generation:identity.generation,preferences:{lockTimeoutSeconds:timeout,bridges}
      });
      saved=result.preferences;note='Settings saved.';onchange(result.identity);
    } catch(value) {error=failure(value);} finally {busy=false;}
  }
  onMount(()=>{void load();return()=>{active=false;};});
</script>
<section class="local-preferences">
  <h2>Privacy &amp; connection</h2>
  {#if saved}<form onsubmit={save}><fieldset disabled={busy}>
    <label for="lock-timeout">Lock after inactivity</label>
    <select id="lock-timeout" bind:value={timeout}>
      <option value={60}>1 minute</option><option value={300}>5 minutes (default)</option><option value={900}>15 minutes</option><option value={1800}>30 minutes</option><option value={3600}>1 hour</option>
      {#if ![60,300,900,1800,3600].includes(timeout)}<option value={timeout}>{timeout} seconds</option>{/if}
    </select>
    <p>Closing this page also locks your identity. Keep unlocked pauses the timer for a long transfer; that choice resets when you lock or restart.</p>
    <label for="tor-routing">Tor connection</label>
    <select id="tor-routing" bind:value={useBridges}><option value={false}>Direct Tor</option><option value={true}>Use bridges</option></select>
    {#if useBridges}
      <label for="tor-bridges">Bridge lines</label>
      <textarea id="tor-bridges" bind:value={lines} rows="5" maxlength="16384" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Paste bridge lines, one per line"></textarea>
      <p>Up to 8 plain, obfs4 or Snowflake bridges. Bridge settings are saved with your encrypted profile. Get bridge lines from <a href="https://bridges.torproject.org/" target="_blank" rel="noreferrer">Tor Project</a> or your trusted operator.</p>
      <p>Najwa keeps using these bridges after a restart. If they fail, it retries through them. It never silently switches to Direct Tor.</p>
    {/if}
    {#if routingChanged}<p class="change-notice">Changing bridges locks Najwa and closes the current Tor connection. Unlock again to connect with the new settings. Queued messages and file transfers are kept.</p>{/if}
    <button class="secondary" type="submit" disabled={!changed}>{busy?'Saving…':routingChanged?'Save and lock':'Save settings'}</button>
  </fieldset></form>{:else if !error}<p>Loading saved settings…</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{#if !saved}<button class="secondary" onclick={load}>Retry settings</button>{/if}{/if}
  {#if note}<p role="status">{note}</p>{/if}
</section>
<style>
  .local-preferences{margin-top:30px;border-top:1px solid var(--line);padding-top:26px;max-width:720px;}
  h2{font-size:20px;margin-bottom:18px;}fieldset{border:0;padding:0;margin:0;min-width:0;}label{display:block;font-size:13px;font-weight:600;margin:18px 0 8px;}
  select,textarea{max-width:100%;width:100%;padding:11px 12px;border:1px solid var(--input-line);border-radius:7px;background:var(--surface);color:var(--ink);font:inherit;}select{max-width:360px;}textarea{font-size:12px;overflow-wrap:anywhere;resize:vertical;}
  p{color:var(--muted);font-size:13px;line-height:1.7;margin:10px 0 16px;}a{color:var(--accent);text-decoration:underline;}.change-notice{color:var(--ink);}.error{color:var(--warning);}
</style>
