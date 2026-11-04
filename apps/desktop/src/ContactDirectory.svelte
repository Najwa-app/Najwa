<script lang="ts">
  import { MagnifyingGlass, Plus, DotsThree, Users } from 'phosphor-svelte';
  import { contactSetupStatus, type Contact } from './messaging';
  let { contacts, loading, error, note, onchat, onmanage, onaccept, oninvite }: {
    contacts:Contact[]; loading:boolean; error:string; note:string;
    onchat:(contact:Contact)=>void|Promise<void>; onmanage:(contact:Contact)=>void|Promise<void>;
    onaccept:()=>void; oninvite:()=>void;
  } = $props();
  let query=$state('');
  let blockedOnly=$state(false);
  const blockedCount=$derived(contacts.filter(contact=>contact.blocked).length);
  const people=$derived(contacts.filter(contact=>
    contact.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()) && (!blockedOnly || contact.blocked)
  ).sort((a,b)=>a.name.localeCompare(b.name)));
</script>

<main class="page-view contacts-page" aria-label="Contact directory">
  <div class="page-heading"><div><h1>Contacts</h1><p>Find someone to chat with, or manage their details.</p></div>
    <div class="directory-actions"><button class="primary" onclick={onaccept}><Plus size={17}/>Add contact</button><button class="secondary" onclick={oninvite}>Create invitation</button></div>
  </div>
  <div class="directory-tools"><label class="search"><MagnifyingGlass size={18}/><input aria-label="Find a contact" placeholder="Find a contact" bind:value={query} autocomplete="off"/></label>
    <div class="directory-filters" role="group" aria-label="Contact filter"><button class:chosen={!blockedOnly} aria-pressed={!blockedOnly} onclick={()=>blockedOnly=false}>All contacts <span>{contacts.length}</span></button><button class:chosen={blockedOnly} aria-pressed={blockedOnly} onclick={()=>blockedOnly=true}>Blocked <span>{blockedCount}</span></button></div>
  </div>
  <div class="directory-list" aria-label="People">
    {#each people as contact (contact.id)}
      <article class="contact-row">
        <span class="avatar sand" aria-hidden="true">{contact.name.slice(0,1).toUpperCase()}</span>
        <div class="contact-copy"><h2><bdi>{contact.name}</bdi></h2><p>{contact.blocked ? 'Blocked' : !contact.ready ? contactSetupStatus(contact).label : contact.verified ? 'Identity verified' : 'Identity not verified'}</p></div>
        <div class="contact-actions"><button class="secondary" aria-label={'Open chat with '+contact.name} onclick={()=>onchat(contact)}>Open chat</button><button class="icon-button" aria-label={'Manage '+contact.name} title="Manage contact" onclick={()=>onmanage(contact)}><DotsThree size={23}/></button></div>
      </article>
    {:else}<div class="directory-empty"><Users size={32}/><h2>{loading ? 'Loading contacts…' : query.trim() ? 'No matching contacts' : blockedOnly ? 'No blocked contacts' : 'No contacts yet'}</h2><p>{loading ? 'Opening your encrypted store.' : query.trim() ? 'Try another name.' : blockedOnly ? 'People you block will appear here.' : 'Add an invitation or share your own to connect with someone.'}</p>{#if query.trim() || blockedOnly}<button class="text-button" onclick={()=>{query='';blockedOnly=false;}}>Show all contacts</button>{/if}</div>{/each}
  </div>
  {#if error}<p class="messenger-error" role="alert">{error}</p>{/if}
  {#if note}<p class="directory-note" role="status">{note}</p>{/if}
</main>

<style>
  .contacts-page {min-width:0;}.page-heading{gap:24px;}.directory-actions{display:flex;gap:10px;flex-wrap:wrap;}.directory-actions .primary{display:flex;align-items:center;gap:7px;}
  .directory-tools{display:flex;align-items:center;justify-content:space-between;gap:18px;margin:28px 0 12px;flex-wrap:wrap;}.directory-tools .search{margin:0;flex:1 1 220px;max-width:400px;}
  .directory-filters{display:flex;gap:6px;}.directory-filters button{padding:9px 11px;border-radius:6px;color:var(--muted);font-size:12px;}.directory-filters .chosen{background:var(--accent-soft);color:var(--accent);}.directory-filters span{margin-left:5px;font-variant-numeric:tabular-nums;}
  .contact-row{display:flex;align-items:center;gap:14px;padding:18px 0;border-bottom:1px solid var(--line);}.contact-copy{flex:1;min-width:0;}.contact-copy h2{font-size:15px;font-weight:600;overflow-wrap:anywhere;}.contact-copy p{font-size:12px;line-height:1.5;color:var(--muted);margin-top:5px;}.contact-actions{display:flex;align-items:center;gap:10px;flex-shrink:0;}.contact-actions .secondary{font-size:12px;white-space:nowrap;}
  .directory-empty{display:flex;flex-direction:column;align-items:center;gap:14px;padding:60px 20px;text-align:center;color:var(--muted);}.directory-empty h2{font-size:18px;color:var(--ink);}.directory-empty p{font-size:13px;line-height:1.7;max-width:340px;}.directory-note{font-size:13px;margin-top:18px;}
  @media(max-width:600px){.contacts-page{padding:24px 18px;}.directory-tools{gap:14px;}.directory-tools .search{max-width:none;}.contact-row{flex-wrap:wrap;gap:10px;}.contact-row .avatar{width:36px;height:36px;font-size:17px;}.contact-copy{flex-basis:calc(100% - 48px);}.contact-actions{margin-left:46px;}.directory-actions{gap:8px;}}
</style>
