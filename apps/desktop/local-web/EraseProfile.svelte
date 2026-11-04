<script lang="ts">
  import { api } from './bridge';
  import type { IdentityStatus } from '../src/identity';
  type Mailboxes = {deactivated:string[];unreachable:string[]};
  let {identity,onerased,onbusy=()=>{}}:{identity:IdentityStatus;onerased:(mailboxes?:Mailboxes)=>void;onbusy?:(value:boolean)=>void} = $props();
  let dialog = $state<HTMLDialogElement>();
  let confirmation=$state('');let checked=$state(false);let busy=$state(false);let error=$state('');
  function open(){confirmation='';checked=false;error='';dialog?.showModal();}
  function cancel(){if(!busy){dialog?.close();confirmation='';checked=false;}}
  async function erase(event:SubmitEvent){
    event.preventDefault();if(busy||!checked||confirmation!=='ERASE')return;
    busy=true;error='';onbusy(true);
    try {
      const result=await api<{mailboxes?:Mailboxes}>('/api/erase',{session:identity.session,generation:identity.generation,confirmed:checked,confirmation});
      confirmation='';checked=false;dialog?.close();onerased(result?.mailboxes);
    } catch(value){
      error=(value as {code?:string})?.code==='wipe_incomplete'
        ? 'Local erasure is incomplete. Unlock and creation are blocked. Retry erasure to finish cleanup. You can also reopen Najwa and retry.'
        : 'Erasure could not be confirmed. Check the current profile state and try again.';
    } finally {busy=false;onbusy(false);}
  }
</script>
<button class="secondary danger" onclick={open}>{identity.phase==='wiping'?'Retry Erase local profile':'Erase local profile…'}</button>
<dialog bind:this={dialog} aria-labelledby="erase-title" oncancel={event=>{if(busy)event.preventDefault();else cancel();}}>
  <h2 id="erase-title">Erase this local profile?</h2>
  <p>This removes this profile’s identity keys, conversations, contacts, settings and unfinished file transfers from this computer. It works while offline.</p>
  {#if identity.phase==='unlocked'}<p>First, Najwa spends up to 20 seconds asking your mailboxes to stop accepting messages for this profile. A mailbox it cannot reach keeps accepting your contacts’ messages for it until 30 days pass without any. Afterwards you see which mailboxes were reached.</p>
  {:else}<p>This profile is not unlocked, so Najwa cannot ask your mailboxes to stop accepting messages for it. They keep accepting your contacts’ messages until 30 days pass without any. To stop them, unlock before erasing.</p>{/if}
  <p>Files you downloaded or exported outside the profile, recovery-kit copies and your contacts’ copies are kept. Messages already held by other people, or by mailboxes Najwa cannot reach, are not deleted.</p>
  <p>You cannot undo this. A complete recovery kit can restore the identity, but it cannot restore erased conversations.</p>
  <form onsubmit={erase}>
    <label class="check"><input type="checkbox" bind:checked={checked} disabled={busy}/>I understand that this permanently erases this local profile.</label>
    <label for="erase-confirmation">Type ERASE to confirm</label>
    <input id="erase-confirmation" bind:value={confirmation} disabled={busy} autocomplete="off" spellcheck="false" maxlength="5"/>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    {#if busy}<p role="status">Erasing this local profile… Keep Najwa open until cleanup finishes.</p>{/if}
    <div class="actions"><button class="secondary" type="button" disabled={busy} onclick={cancel}>Cancel</button><button class="primary danger" type="submit" disabled={busy||!checked||confirmation!=='ERASE'}>{busy?'Erasing…':'Erase local profile'}</button></div>
  </form>
</dialog>
<style>
  dialog::backdrop{background:#11182780;}dialog{width:min(520px,calc(100% - 40px));max-height:calc(100dvh - 40px);overflow:auto;border:0;padding:28px;border-radius:16px;background:var(--surface);color:var(--ink);box-shadow:0 16px 64px #0003;}h2{font-size:22px;}p{font-size:13px;line-height:1.7;color:var(--muted);margin:14px 0;}label{display:block;font-size:13px;margin:16px 0 8px;}input:not([type=checkbox]){width:100%;border:1px solid var(--input-line);border-radius:7px;padding:12px;background:var(--surface);color:var(--ink);font:inherit;}.check{display:flex;align-items:flex-start;gap:9px;line-height:1.6;}.check input{margin-top:3px;}.actions{display:flex;justify-content:flex-end;flex-wrap:wrap;gap:10px;margin-top:24px;}.danger{color:var(--warning);}button.primary.danger{background:var(--warning);color:#fff;}.error{color:var(--warning);}
</style>
