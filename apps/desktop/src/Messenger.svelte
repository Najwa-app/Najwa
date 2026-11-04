<script lang="ts">
  import { onMount, tick } from 'svelte';
  import type { Snippet } from 'svelte';
  import { invoke } from 'najwa:bridge';
  import QrScanner from './QrScanner.svelte';
  import ContactDirectory from './ContactDirectory.svelte';
  import MessageBubble from './MessageBubble.svelte';
  import { liveMessagePage, messageDelivery } from './chatView';
  import { ChatCircle, WarningCircle, ShieldCheck, PaperPlaneTilt, NotePencil, WifiHigh, WifiSlash, Clock, ArrowLeft, ArrowDown, Check, Copy, Plus, Lightning, MagnifyingGlass, DotsThree, Paperclip, ArrowBendUpLeft, X } from 'phosphor-svelte';
  import type { IdentityStatus } from './identity';
  import { checkedContacts, checkedMessages, mailboxSummary, messagingRequest, messagingError, contactSetupStatus,
    type Contact, type Message, type NetworkStatus } from './messaging';
  let { identity, section, network, navigate = () => {}, localSettings }: { identity: IdentityStatus; section: 'chats' | 'contacts' | 'settings'; network: NetworkStatus; navigate?: (section: 'chats' | 'settings') => void; localSettings?: Snippet } = $props();
  let contacts = $state<Contact[]>([]);
  let selectedId = $state('');
  let messages = $state<Message[]>([]);
  let historyLoaded = false;
  let historyBefore: [number,string] | undefined;
  let hasOlder = $state(false);
  let historyLoading = $state(false);
  let searchOpen = $state(false);
  let messageQuery = $state('');
  let activeSearch = $state('');
  let searchResults = $state<Message[]>([]);
  let searchBefore: [number,string] | undefined;
  let moreSearchResults = $state(false);
  let searching = $state(false);
  let searchEpoch = 0;
  let searchField = $state<HTMLInputElement>();
  const visibleMessages = $derived(activeSearch ? searchResults : messages);
  let drafts = $state<Record<string,string>>({});
  let query = $state('');
  let error = $state('');
  let note = $state('');
  const progressMessages = {
    add_mailbox: 'Registering mailbox and publishing keys… Mailbox setup is not complete yet.',
    invitation: 'Creating a signed invitation through your mailbox…',
    accept_invitation: 'Saving the contact request on this computer…',
    send: 'Queueing your encrypted message…',
    set_timer: 'Saving the timer and queueing its encrypted update…',
    verify: 'Saving identity verification…',
    retry_mailbox: 'Re-enabling delivery to the mailbox…',
    reconnect: 'Requesting a Tor connection…',
    sync: 'Synchronizing with your mailboxes through Tor…',
    select_mailbox: 'Saving your primary mailbox…', set_delivery_mode: 'Saving delivery preference…',
    forget_mailbox: 'Removing incomplete mailbox setup…', manage_contact:'Saving contact changes on this computer…'
  } as const;
  let pendingOperation = $state<keyof typeof progressMessages | null>(null);
  let invitationRetry = $state(false);
  const busy = $derived(pendingOperation !== null);
  const progress = $derived(pendingOperation === 'invitation' && invitationRetry ? 'Temporary mailbox connection failure. Retrying your invitation automatically…' : pendingOperation ? progressMessages[pendingOperation] : '');
  const mailboxState = $derived(pendingOperation === 'add_mailbox' ? 'Mailbox setup in progress' : mailboxSummary(network));
  let onion = $state('');
  let name = $state('');
  let invitation = $state('');
  let exported = $state('');
  let sending = $state(false);
  let loading = $state(true);
  let unreadOnly = $state(false);
  let invitationField = $state<HTMLTextAreaElement>();
  const acknowledged = new Set<string>();
  const mailboxRows = $derived(network.mailboxDetails ?? network.mailboxes.map((onion, index) => ({onion, registered: true, primary: index === 0})));
  const readyMailboxes = $derived(mailboxRows.filter(m => m.registered));
  const deliveryMode = $derived(network.deliveryMode ?? 'responsive');
  let mode = $state<'accept' | 'invite' | 'verify' | 'timer' | 'manage' | 'message_info'>('accept');
  let rename = $state('');
  let confirmDelete = $state(false);
  // S05 §8.1: after 10 contacts in 24 hours the service asks for explicit consent.
  let limitWarning = $state(false); let limitConfirmed = $state(false);
  let qr = $state<{qrSvg:string;expiresAt:number} | null>(null);
  let replying = $state<Message | null>(null);
  let replyFromSearch = false;
  let attaching = $state(false);
  let uploadController:AbortController|undefined;
  let uploadProgress=$state('');
  let uploadContact=$state('');
  let fileInput=$state<HTMLInputElement>();
  let transfers=$state<{id:string;filename:string;size:number;uploaded:number;phase:string;error:string|null}[]>([]);
  let downloading = $state('');
  let viewInitialized = false;
  let newIncoming = $state(0);
  let messageMenu = $state('');
  let menuPosition = $state({top:0,left:0});
  let highlighted = $state('');
  let highlightTimeout: ReturnType<typeof setTimeout>;
  let infoMessageId = $state('');
  const infoMessage = $derived(visibleMessages.find(m=>m.msgId===infoMessageId));
  const messageById = $derived(new Map([...messages,...searchResults].map(m=>[m.msgId,m])));
  let previousSection: typeof section | undefined;
  $effect(() => {
    if(previousSection !== undefined && previousSection !== section) {
      revision++; viewInitialized=false; messages=[]; transfers=[];replying=null; newIncoming=0; messageMenu='';
      resetHistory();
    }
    previousSection=section;
  });
  const fileSupported = typeof __NAJWA_LOCAL_WEB__!=='undefined' && __NAJWA_LOCAL_WEB__ && location.protocol === 'http:' && location.hostname === '127.0.0.1';
  let timerChoice = $state('0');
  let customSeconds = $state<number | undefined>(30);
  const timers = [{value:0,label:'Off'},{value:30,label:'30 seconds'},{value:300,label:'5 minutes'},
    {value:3600,label:'1 hour'},{value:86400,label:'1 day'},{value:604800,label:'7 days'},{value:2592000,label:'30 days'}];
  let dialog: HTMLDialogElement;
  let dialogOpen = $state(false);
  let list = $state<HTMLDivElement>();
  let compose = $state<HTMLTextAreaElement>();
  let active = true;
  let reading = false;
  let revision = 0;
  const selected = $derived(contacts.find(c => c.id === selectedId));
  const latestOutgoing = $derived([...messages].reverse().find(message => message.outgoing));
  const latestDelivery = $derived(latestOutgoing ? messageDelivery(latestOutgoing) : undefined);
  const filtered = $derived(contacts.filter(c => c.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()) && (!unreadOnly || c.unread > 0)));
  const draft = $derived(drafts[selectedId] ?? '');

  async function request<T>(operation: Parameters<typeof messagingRequest>[1]): Promise<T> {
    const result = await messagingRequest<T>(identity, operation);
    if (!active) throw { code: 'stale_operation' };
    return result;
  }
  async function refresh() {
    if (reading || !active) return;
    reading = true;
    const current = selectedId;
    const version = revision;
    try {
      const rows = checkedContacts(await request<Contact[]>({kind:'contacts'}));
      if (!active || version !== revision) return;
      contacts = rows;
      if (current && rows.some(c => c.id === current)) {
        if (section !== 'chats') return;
        const page = checkedMessages(await request<Message[]>({ kind:'messages', contact:current }));
        if (!active || version !== revision || selectedId !== current) return;
        const refreshed = [...page];
        let oldestPage = page;
        if (historyLoaded && messages.length) {
          const floor = messages.reduce((a,b)=>comesBefore(b,a) ? b : a);
          while(oldestPage.length===200 && comesBefore(floor,oldestPage[0])) {
            const older=checkedMessages(await request<Message[]>({kind:'messages',contact:current,before:cursor(oldestPage)}));
            if(!active || version!==revision || selectedId!==current)return;
            if(older.length && !comesBefore(older[older.length-1],oldestPage[0]))break;
            refreshed.push(...older);oldestPage=older;
          }
        }
        const wasAtBottom = !list || list.scrollHeight - list.scrollTop - list.clientHeight < 60;
        const known = new Set(messages.map(m=>m.id));
        const arrivals = viewInitialized ? page.filter(m=>!m.outgoing && !known.has(m.id) && (m.expiresAt===null || m.expiresAt>Date.now())).length : 0;
        historyBefore=cursor(oldestPage);hasOlder=oldestPage.length===200;
        messages = liveMessagePage(messages,refreshed,viewInitialized);
        if(fileSupported) {
          const transferRows=await invoke<typeof transfers>('attachment_transfers',{session:identity.session,generation:identity.generation,contact:current});
          if(!active || version!==revision || selectedId!==current)return;
          transfers=Array.isArray(transferRows)?transferRows:[];
        }
        viewInitialized = true;
        if(!wasAtBottom) newIncoming += arrivals;
        if(replying) replying=messageById.get(replying.msgId) ?? (replyFromSearch ? replying : null);
        await tick();
        if (wasAtBottom && !activeSearch) { list?.scrollTo({ top:list.scrollHeight }); newIncoming=0; }
        await acknowledge();
      } else if (current) { leaveConversation(); }
    } catch (failure) {
      if (active && (failure as {code?:string})?.code !== 'busy') error = messagingError(failure);
    } finally { reading = false; loading = false; }
  }
  async function acknowledge() {
    if (!active || dialog?.open || section !== 'chats' || !selectedId || document.visibilityState !== 'visible' || !document.hasFocus() || !list) return;
    const viewport = list.getBoundingClientRect();
    const ids = Array.from(list.querySelectorAll<HTMLElement>('[data-message-id]')).filter(element => {
      const rect = element.getBoundingClientRect();
      return rect.bottom > viewport.top && rect.top < viewport.bottom && rect.right > viewport.left && rect.left < viewport.right;
    }).map(e => e.dataset.messageId!).filter(id => !acknowledged.has(id));
    if (ids.length) { await request({kind:'displayed',contact:selectedId,ids}); ids.forEach(id => acknowledged.add(id)); }
  }
  async function choose(contact: Contact) {
    resetHistory();
    selectedId = contact.id; revision++; messages = [];transfers=[]; viewInitialized=false; newIncoming=0; messageMenu=''; highlighted=''; error = ''; replying = null;
    if (!reading) await refresh();
    await tick();
    list?.scrollTo({top:list.scrollHeight});
  }
  async function openContactChat(contact: Contact) {
    query = ''; unreadOnly = false;
    navigate('chats');
    await tick();
    await choose(contact);
  }
  async function perform(work: () => Promise<void>, operation: keyof typeof progressMessages) {
    if (busy) return;
    pendingOperation = operation; error = ''; note = '';
    try { await work(); } catch (failure) { if (active) error = messagingError(failure); }
    finally { pendingOperation = null; if (active) void refresh(); }
  }
  async function createInvitation() {
    const epoch=`${identity.session}:${identity.generation}`;
    const displayName=name.trim();
    const stillOpen=()=>active && dialog?.open && mode==='invite' && `${identity.session}:${identity.generation}`===epoch;
    try {
      for(let attempt=0;attempt<3;attempt++) {
        if(!stillOpen())return;
        try {
          const value=await request<string>({kind:'invitation',name:displayName});
          if(!stillOpen())return;
          exported=value;qr=null;
          try {const details=await request<{qrSvg:string;expiresAt:number}>({kind:'invitation_details',invitation:value});if(stillOpen())qr=details;}
          catch {if(stillOpen())note='Invitation ready. QR preview unavailable; you can copy the link.';}
          return;
        } catch(failure) {
          if(!stillOpen())return;
          if(attempt===2 || !['registration_transport','not_connected','busy'].includes((failure as {code?:string})?.code??''))throw failure;
          invitationRetry=true;
          await new Promise(resolve=>setTimeout(resolve,attempt===0?2000:5000));
        }
      }
    } finally {invitationRetry=false;}
  }
  async function send(event?: SubmitEvent) {
    event?.preventDefault();
    if (!selected || !selected.ready || selected.blocked || selected.timerPending || !draft.trim() || sending) return;
    const contact = selected.id;
    const text = draft;
    sending = true; error = ''; note = '';
    try {
      await request({kind:'send',contact,text,...(replying ? {reply_to:replying.msgId} : {})});
      if (drafts[contact] === text) drafts[contact] = '';
      replying = null;
      await refresh();
      await tick();
      list?.scrollTo({top:list.scrollHeight});
      compose?.focus();
    } catch (failure) { if (active) error = (failure as {code?:string})?.code === 'not_connected'
      ? 'Tor is still starting. Your message has not been queued; your draft is kept here. Try sending again when Najwa connects.' : messagingError(failure); }
    finally { sending = false; }
  }
  function key(event: KeyboardEvent) {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); void send(); }
  }
  function open(kind: typeof mode) {
    mode = kind; messageMenu=''; error = ''; note = ''; exported = ''; invitation = ''; qr=null; confirmDelete=false; limitWarning=false; limitConfirmed=false; rename=selected?.name ?? '';
    const seconds = selected?.timerSeconds ?? 0;
    timerChoice = timers.some(t => t.value === seconds) ? String(seconds) : 'custom';
    customSeconds = seconds || 30;
    note = ''; dialogOpen = true; dialog.showModal();
  }
  function timerLabel(seconds: number) { return timers.find(t => t.value === seconds)?.label ?? `${seconds} seconds`; }
  async function saveTimer(event: SubmitEvent) {
    event.preventDefault();
    if (!selected || !selected.ready || selected.blocked || selected.timerPending) return;
    const seconds = Number(timerChoice === 'custom' ? customSeconds : timerChoice);
    if (!Number.isInteger(seconds) || seconds < 0 || seconds > 4294967295 || (seconds > 0 && seconds < 30)
      || (timerChoice === 'custom' && seconds < 30)) {
      error = 'Choose a whole number of seconds from 30 to 4,294,967,295.'; return;
    }
    const contact = selected.id;
    await perform(async () => {
      await request({kind:'set_timer',contact,seconds});
      dialog.close();
      note = 'Timer saved locally. The encrypted update is queued for your contact. Existing messages keep their previous timer.';
    }, 'set_timer');
  }
  function leaveConversation() {
    resetHistory();
    selectedId=''; messages=[];transfers=[]; viewInitialized=false; newIncoming=0; messageMenu=''; replying=null; highlighted=''; revision++;
  }
  function closeMessageMenu(focus=false) {
    const id=messageMenu; messageMenu='';
    if(focus && id) document.getElementById('message-actions-'+id)?.focus();
  }
  async function toggleMessageMenu(id:string) {
    if(messageMenu===id) {closeMessageMenu(true);return;}
    messageMenu=id; await tick();
    const trigger=document.getElementById('message-actions-'+id), panel=document.getElementById('message-menu-'+id);
    if(!trigger || !panel || messageMenu!==id) return;
    const rect=trigger.getBoundingClientRect();
    menuPosition={left:Math.max(8,Math.min(rect.right-panel.offsetWidth,innerWidth-panel.offsetWidth-8)),top:rect.bottom+panel.offsetHeight+8<innerHeight ? rect.bottom+4 : Math.max(8,rect.top-panel.offsetHeight-4)};
    panel.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
  }
  function outsideMessageMenu(event:PointerEvent) {
    if(messageMenu && (!(event.target instanceof Element) || !event.target.closest('[data-message-actions]'))) closeMessageMenu();
  }
  function messageKeys(event:KeyboardEvent) {
    if(event.key==='Escape' && messageMenu) {event.preventDefault();closeMessageMenu(true);}
  }
  async function replyTo(message:Message) {
    closeMessageMenu();
    replyFromSearch=!!activeSearch;
    replying=visibleMessages.find(m=>m.id===message.id) ?? null;
    if (activeSearch) await clearSearch();
    await tick(); compose?.focus();
  }
  async function copyMessage(message:Message) {
    closeMessageMenu(true);
    try {await navigator.clipboard.writeText(message.attachment?.filename ?? message.text);if(active) note=message.attachment?'Filename copied.':'Message copied.';}
    catch {if(active) error='Could not copy. You can select the message text and copy it with your browser.';}
  }
  function showMessageInfo(message:Message) {infoMessageId=message.msgId;open('message_info');}
  async function jumpToMessage(id:string) {
    const message=messageById.get(id);
    if(!message) return;
    if (activeSearch && !searchResults.some(m=>m.msgId===id)) { await clearSearch(); }
    const element=list?.querySelector<HTMLElement>(`[data-message-id="${message.id}"]`);
    if(!element) return;
    element.scrollIntoView({block:'center',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
    element.focus({preventScroll:true}); highlighted=message.id;
    clearTimeout(highlightTimeout); highlightTimeout=setTimeout(()=>highlighted='',1800);
  }
  function chatScroll() {
    if(list && list.scrollHeight-list.scrollTop-list.clientHeight<60) newIncoming=0;
    closeMessageMenu();void acknowledge().catch(()=>{});
  }
  function latestMessages() {list?.scrollTo({top:list.scrollHeight,behavior:'instant'});newIncoming=0;}
  function cursor(page: Message[]): [number,string] | undefined {
    return page.length ? [page[0].timestamp,page[0].id] : undefined;
  }
  function comesBefore(a:Message,b:Message) {
    return a.timestamp<b.timestamp || a.timestamp===b.timestamp && BigInt(a.id)<BigInt(b.id);
  }
  function resetHistory() {
    historyLoaded=false;historyBefore=undefined;hasOlder=false;historyLoading=false;
    searchEpoch++;searchOpen=false;messageQuery='';activeSearch='';searchResults=[];
    searchBefore=undefined;moreSearchResults=false;searching=false;
  }
  async function loadOlder() {
    if(!selectedId || !historyBefore || historyLoading) return;
    const contact=selectedId, version=revision, before=historyBefore;
    historyLoading=true;error='';
    const height=list?.scrollHeight ?? 0, top=list?.scrollTop ?? 0;
    try {
      const page=checkedMessages(await request<Message[]>({kind:'messages',contact,before}));
      if(!active || version!==revision || contact!==selectedId)return;
      const known=new Set(messages.map(m=>m.id));
      messages=[...page.filter(m=>!known.has(m.id)),...messages];historyLoaded=true;
      historyBefore=cursor(page);hasOlder=page.length===200;
      await tick();if(list)list.scrollTop=top+list.scrollHeight-height;
      await acknowledge();
    } catch(failure) {if(active && version===revision)error=messagingError(failure);}
    finally {if(version===revision)historyLoading=false;}
  }
  async function openSearch() {searchOpen=true;await tick();searchField?.focus();}
  async function clearSearch() {
    searchEpoch++;searchOpen=false;messageQuery='';activeSearch='';searchResults=[];
    searchBefore=undefined;moreSearchResults=false;searching=false;
    await tick();list?.scrollTo({top:list.scrollHeight});
  }
  async function searchMessages(event?: SubmitEvent, older=false) {
    event?.preventDefault();
    const query=(older ? activeSearch : messageQuery).trim();
    if(!selectedId || !query || searching)return;
    const contact=selectedId,version=revision,epoch=++searchEpoch,before=older?searchBefore:undefined;
    searching=true;error='';
    if(!older){activeSearch=query;searchResults=[];}
    try {
      const page=checkedMessages(await request<Message[]>({kind:'messages',contact,query,...(before?{before}:{})}));
      if(!active || version!==revision || contact!==selectedId || epoch!==searchEpoch)return;
      const known=new Set(searchResults.map(m=>m.id));
      searchResults=older?[...page.filter(m=>!known.has(m.id)),...searchResults]:page;
      searchBefore=cursor(page);moreSearchResults=page.length===200;
      await tick();if(!older)list?.scrollTo({top:0});await acknowledge();
    } catch(failure) {if(active && version===revision && epoch===searchEpoch)error=messagingError(failure);}
    finally {if(epoch===searchEpoch)searching=false;}
  }
  function contactTime(timestamp:number) {
    const date=new Date(timestamp*1000),today=new Date();
    return new Intl.DateTimeFormat(undefined,date.toDateString()===today.toDateString()
      ? {hour:'2-digit',minute:'2-digit'} : {month:'short',day:'numeric'}).format(date);
  }
  async function addMailbox(event: SubmitEvent) {
    event.preventDefault();
    let address = onion.trim().toLowerCase();
    if (/^https?:\/\//.test(address)) {
      try { const url = new URL(address); if (url.pathname === '/' && !url.port && !url.search && !url.hash && !url.username && !url.password) address = url.hostname; } catch { /* Inline validation below. */ }
    }
    if (!/^[a-z2-7]{56}\.onion$/.test(address)) { error = 'Enter the complete 56-character .onion address from your mailbox operator.'; return; }
    await perform(async () => { await request({kind:'add_mailbox',onion:address}); onion = ''; note = 'Mailbox saved and prekeys published.'; }, 'add_mailbox');
  }
  async function copyInvitation() {
    try { await navigator.clipboard.writeText(exported); note = 'Invitation copied. Share it privately with your contact.'; }
    catch { invitationField?.focus(); invitationField?.select(); note = 'Link selected. Press Ctrl+C or Command+C to copy.'; }
  }
  async function manage(action:'block'|'unblock'|'delete'|'rename') {
    if(!selected) return;
    const contact=selected.id;
    await perform(async()=> {
      await request({kind:'manage_contact',contact,action,...(action==='rename'?{name:rename.trim()}:{})});
      if(action==='delete') { delete drafts[contact]; leaveConversation(); }
      dialog.close(); note=action==='delete'?'Contact and local conversation deleted.':action==='block'?'Contact blocked. Queued delivery is paused.':action==='unblock'?'Contact unblocked. Queued delivery resumes automatically.':'Contact name saved on this computer.';
    },'manage_contact');
  }
  function downloadBlob(blob:Blob,filename:string) {
    const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=filename; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  async function attach(event:Event) {
    const input=event.currentTarget as HTMLInputElement; const file=input.files?.[0]; input.value='';
    if(!file || !selected || attaching) return;
    if(!file.size || file.size>256*1024*1024) {error='Choose a nonempty file of up to 256 MB.';return;}
    if(selected.timerSeconds || selected.timerPending) {error='Turn off disappearing messages before sending a file in this preview.';return;}
    const contact=selected.id;uploadContact=contact; attaching=true; error=''; note='';
    uploadController=new AbortController();
    try { await invoke('attachment_upload',{session:identity.session,generation:identity.generation,contact,file,signal:uploadController.signal,onprogress:(phase:string,bytes:number,total:number)=>{if(active)uploadProgress=`${phase} · ${Math.round(bytes/total*100)}%`;}});
      if(active) { note='File saved in the encrypted queue. It sends automatically; your contact can be offline. Images are converted to WebP and file metadata is cleaned.'; await refresh(); }
    } catch(failure) { if(active) error=messagingError(failure); }
    finally {attaching=false;uploadProgress='';uploadController=undefined;}
  }
  async function cancelTransfer(id:string) {
    if(!selected)return;
    try {await invoke('attachment_cancel',{session:identity.session,generation:identity.generation,contact:selected.id,id});await refresh();}catch(failure){error=messagingError(failure);}
  }
  async function download(message:Message) {
    if(!selected || downloading) return;
    const version=revision; downloading=message.id; error='';
    try { note='Checking file integrity and preparing download…';const file=await invoke<{url:string;filename:string;metadataWarning?:boolean}>('attachment_download',{session:identity.session,generation:identity.generation,contact:selected.id,message:message.id});
      if(!active || version!==revision) return;
      if(!/^\/api\/download\/[a-f0-9]{64}$/.test(file.url))throw {code:'invalid_file'};
      const anchor=document.createElement('a');anchor.href=file.url;anchor.download=file.filename;anchor.click();note='Download started. Progress and resume are available in your browser’s downloads.';
      if(file.metadataWarning) error='Warning: this file may still contain hidden details (metadata) that Najwa normally removes, such as location, device or author. The sender’s app may not have cleaned it. Open it with care and clean it before passing it on.';
    } catch(failure) { if(active) error=messagingError(failure); } finally {downloading='';}
  }
  onMount(() => {
    void refresh();
    const polling = setInterval(() => void refresh(), 1000);
    const expiry = setInterval(() => {
      messages = messages.filter(m => m.expiresAt === null || m.expiresAt > Date.now());
      searchResults = searchResults.filter(m => m.expiresAt === null || m.expiresAt > Date.now());
      if (replying?.expiresAt != null && replying.expiresAt <= Date.now()) replying=null;
      void acknowledge().catch(() => {});
    },1000);
    return () => { active = false; revision++; uploadController?.abort();clearInterval(polling); clearInterval(expiry); clearTimeout(highlightTimeout);
      contacts = []; messages = [];transfers=[]; drafts = {}; replying=null; qr=null; name = ''; invitation = ''; exported = ''; dialog?.close(); };
  });
</script>

<svelte:window onpointerdown={outsideMessageMenu} onkeydown={messageKeys} onresize={()=>closeMessageMenu()}/>

{#snippet mailboxForm()}
  <form class="mailbox-form" onsubmit={addMailbox}>
    <label class="field-label" for="onion">Tor v3 mailbox</label>
    <p class="field-help" id="mailbox-help">Paste the address provided by your mailbox operator. No account or email is needed.</p>
    <input class="text-input" id="onion" aria-describedby="mailbox-help" bind:value={onion} maxlength={256} placeholder="Paste a mailbox .onion address" autocomplete="off" spellcheck="false" required />
    <div class="form-actions"><button class="primary" disabled={busy || network.connection !== 'connected' || !onion.trim()}><Plus size={17}/>Add mailbox</button><span class="field-help">{network.connection === 'connected' ? 'Registration happens through Tor.' : 'Waiting for Tor to connect…'}</span></div>
  </form>
{/snippet}

{#if section === 'settings'}
  <main class="page-view settings-page">
    <button class="back-link" onclick={() => navigate('chats')}><ArrowLeft size={17}/>Back to conversations</button>
    <div class="page-heading"><div><span class="eyebrow">MAKE YOURSELF AT HOME</span><h1>Settings</h1><p>Your mailboxes and message delivery, in one place.</p></div></div>
    <section class="settings-section"><h2>Mailboxes <span class="count">{network.mailboxes.length}/8</span></h2><p>A mailbox holds encrypted messages for you. Add independent operators for backup delivery. Your primary appears first in new invitations; all registered mailboxes are included.</p>
      <div class="mailbox-list">{#each mailboxRows as mailbox (mailbox.onion)}<div class="mailbox-row">
        <div class="mailbox-row-title"><b>{!mailbox.registered ? 'Mailbox setup' : mailbox.primary ? 'Primary mailbox' : 'Backup mailbox'}</b><span class:registered={mailbox.registered} class="mailbox-badge">{pendingOperation === 'add_mailbox' && onion.trim().includes(mailbox.onion) ? 'Registering…' : mailbox.registered ? 'Registered' : 'Setup incomplete'}</span></div>
        <p class="mailbox-host">{mailbox.onion}</p>
        {#if !mailbox.registered}<button class="text-button" disabled={busy || network.connection !== 'connected'} onclick={() => perform(async () => { await request({kind:'add_mailbox',onion:mailbox.onion}); note = 'Mailbox registration completed.'; }, 'add_mailbox')}>Retry registration</button>
        <button class="text-button remove-setup" disabled={busy} onclick={() => perform(async () => { await request({kind:'forget_mailbox',onion:mailbox.onion}); note = 'Incomplete mailbox setup removed.'; }, 'forget_mailbox')}>Remove incomplete setup</button>
        {:else if !mailbox.primary}<button class="text-button" disabled={busy} onclick={() => perform(async () => { await request({kind:'select_mailbox',onion:mailbox.onion}); note = 'Primary mailbox updated for new invitations.'; }, 'select_mailbox')}>Make primary</button>{/if}
      </div>{/each}</div>
      <p class="mailbox-state" role="status">{mailboxState}</p>
      {#if network.mailboxes.length < 8}{@render mailboxForm()}{/if}
    </section>
    <section class="settings-section"><h2>Message delivery</h2><p>Choose when the app sends. Your mailbox operator also controls server-side delays.</p>
      <div class="delivery-options" role="group" aria-label="Delivery preference">
        <button class:chosen={deliveryMode === 'responsive'} aria-pressed={deliveryMode === 'responsive'} disabled={busy} onclick={() => perform(async () => { await request({kind:'set_delivery_mode',mode:'responsive'}); note = 'Responsive delivery saved.'; }, 'set_delivery_mode')}><Lightning size={21}/><b>Responsive <span class="recommended">Default</span></b><span>Send without waiting for a random slot. Best for everyday conversations.</span></button>
        <button class:chosen={deliveryMode === 'privacy'} aria-pressed={deliveryMode === 'privacy'} disabled={busy} onclick={() => perform(async () => { await request({kind:'set_delivery_mode',mode:'privacy'}); note = 'Timing privacy saved. Messages may wait for a cover slot.'; }, 'set_delivery_mode')}><Clock size={21}/><b>Timing privacy</b><span>Wait for cover traffic slots to obscure send timing. Delivery takes longer.</span></button>
      </div>
      <p class="field-help">Both modes use Tor and encrypted messages. Responsive mode exposes more information about when you send.</p>
      {#if (network.pendingDeposits ?? 0) > 0}<p class="field-help" role="status">{network.pendingDeposits} queued {network.pendingDeposits === 1 ? 'item is' : 'items are'} waiting to reach a mailbox. Keep this app unlocked until sending finishes. Your contacts can be offline.</p>{/if}
    </section>
    <section class="settings-section"><h2>Connection</h2><p>Tor: {network.connection}. Cover traffic: {network.coverRunning ? 'running' : 'starting'}.</p><p>Tor connectivity alone does not confirm mailbox setup or message delivery.</p>
      {#if network.retryingMailboxes?.length}<div role="status"><h3>Retrying mailbox connections</h3><p>Temporary connection failures. Najwa retries automatically while unlocked; queued messages and contact requests are kept.</p>
        {#each network.retryingMailboxes as mailbox}<p class="mailbox-host">{mailbox}</p>{/each}
      </div>{/if}
      <button class="secondary" disabled={busy} onclick={() => perform(async () => { await request({kind:'reconnect'}); note = 'Connection requested.'; }, 'reconnect')}>Reconnect</button>
      <button class="secondary" disabled={busy || network.connection !== 'connected'} onclick={() => perform(async () => { await request({kind:'sync'}); note = 'Synchronization completed.'; }, 'sync')}>Synchronize now</button>
    </section>
    {@render localSettings?.()}
    <div class="inline-note"><ShieldCheck size={20}/><p>Message storage is encrypted locally. Locking clears decrypted views and keys; the cover schedule continues while this app is running.</p></div>
    {#if busy}<p role="status">{progress}</p>{/if}
    {#if error}<p class="messenger-error" role="alert">{error}</p>{/if}{#if note}<p role="status">{note}</p>{/if}
  </main>
{:else if section === 'contacts'}
  <ContactDirectory {contacts} {loading} {error} {note} onchat={openContactChat}
    onmanage={async contact=>{await choose(contact);open('manage');}}
    onaccept={()=>open('accept')} oninvite={()=>open('invite')}/>
{:else}
  <aside class="conversation-list" class:empty-start={!contacts.length} aria-label="Real contacts">
    <div class="list-heading"><h1>Conversations</h1><button class="icon-button" aria-label="Add contact invitation" onclick={() => open('accept')}><NotePencil size={23}/></button></div>
    <label class="search"><MagnifyingGlass size={18}/><input aria-label="Find a real contact" placeholder="Find a contact" bind:value={query} autocomplete="off"/></label>
    <div class="filters"><button class:chosen={!unreadOnly} onclick={() => unreadOnly = false}>All chats <span>{contacts.length}</span></button><button class:chosen={unreadOnly} onclick={() => unreadOnly = true}>Unread <span>{contacts.filter(c => c.unread > 0).length}</span></button></div>
    <div class="conversation-items">
      {#each filtered as contact (contact.id)}
        <button class="conversation" class:selected={selectedId === contact.id} aria-current={selectedId === contact.id ? 'true' : undefined} onclick={() => choose(contact)}>
          <span class="avatar sand">{contact.name.slice(0,1).toUpperCase()}</span>
          <span class="conversation-copy"><b><bdi>{contact.name}</bdi></b><span class="preview" dir="auto">{contact.blocked ? 'Blocked' : !contact.ready ? contactSetupStatus(contact).label : contact.repairStatus==='repairing' ? 'Repairing encrypted session…' : contact.preview ?? (contact.verified ? 'Verified identity' : 'Identity not verified')}</span></span>
          <span class="conversation-meta">{#if contact.lastMessageAt != null}<time datetime={new Date(contact.lastMessageAt*1000).toISOString()}>{contactTime(contact.lastMessageAt)}</time>{/if}{#if contact.unread}<span class="unread-count" aria-label={`${contact.unread} unread ${contact.unread===1?'message':'messages'}`}>{contact.unread>99?'99+':contact.unread}</span>{/if}</span>
        </button>
      {:else}<div class="empty-list"><ChatCircle size={26}/><b>{loading ? 'Loading conversations…' : query.trim() ? 'No matching contacts' : unreadOnly ? 'All caught up' : 'No contacts yet'}</b><p>{loading ? 'Opening your encrypted store.' : query.trim() ? 'Try another name.' : unreadOnly ? 'Your unread conversations will appear here.' : 'Start with an invitation.'}</p>{#if query.trim() || unreadOnly}<button class="text-button" onclick={() => {query = ''; unreadOnly = false;}}>Show all contacts</button>{/if}</div>{/each}
    </div>
    <button class="secondary full" onclick={() => open('invite')}>Create invitation</button>
    <div class="demo-note tor-connection" class:connected={network.enabled && network.connection === 'connected'}>
      {#if network.enabled && network.connection === 'connected'}<WifiHigh size={20} aria-hidden="true"/>{:else}<WifiSlash size={20} aria-hidden="true"/>{/if}
      <div><b>{mailboxState}</b><p>Tor: {network.connection}</p><p>{deliveryMode === 'privacy' ? 'Timing privacy' : 'Responsive delivery'}</p>{#if network.retryingMailboxes?.length}<p role="status">Temporary connection failures. Retrying automatically while Najwa is unlocked.</p>{/if}{#if busy}<p role="status">{progress}</p>{:else if !network.mailboxes.length}<button class="text-button" onclick={() => navigate('settings')}>Set up a mailbox</button>{/if}</div>
    </div>
  </aside>
  <main class="chat connected-chat" class:has-selection={!!selected} aria-label={selected ? `Conversation with ${selected.name}` : 'Choose a contact'}>
    {#if selected}
      <header class="chat-header"><button class="icon-button mobile-back" aria-label="Back to contacts" onclick={leaveConversation}><ArrowLeft size={21}/></button><span class="avatar sand">{selected.name.slice(0,1).toUpperCase()}</span><div class="chat-title"><h2><bdi>{selected.name}</bdi></h2><span>{#if selected.verified}<ShieldCheck size={14}/>{:else}<WarningCircle size={14}/>{/if}{selected.verified ? 'Identity verified' : 'Identity not verified'} · Timer: {timerLabel(selected.timerSeconds)}</span></div><div class="chat-actions"><button class="icon-button" aria-label="Search messages" title="Search messages" aria-expanded={searchOpen} onclick={openSearch}><MagnifyingGlass size={21}/></button><button class="secondary" disabled={!selected.ready || selected.blocked || selected.timerPending} onclick={() => open('timer')}>Disappearing messages</button><button class="secondary" onclick={() => open('verify')}>Safety number</button><button class="icon-button" aria-label="Contact details" title="Contact details" onclick={() => open('manage')}><DotsThree size={24}/></button></div></header>
      {#if network.connection !== 'connected'}<div class="chat-banner" role="status"><WifiSlash size={17}/><span>Reconnecting to Tor. Established conversations can queue messages locally; delivery resumes automatically.</span><button class="text-button" disabled={busy} onclick={() => perform(async () => {await request({kind:'reconnect'});}, 'reconnect')}>Reconnect</button></div>{/if}
      {#if selected.repairStatus}<div class="chat-banner" role="status"><Clock size={17}/><span>{selected.repairStatus==='repairing'?'Repairing the encrypted session. Najwa continues automatically when your contact returns.':'The encrypted session could not be repaired yet. Najwa will try to reconnect when messages arrive.'}</span></div>{/if}
      {#if !selected.ready}<div class="chat-banner" role="status"><Clock size={17}/><span><b>{contactSetupStatus(selected).label}.</b> {contactSetupStatus(selected).description}{#if selected.setupExpiresAt && ['queued','waiting'].includes(selected.setupState ?? '')} Introduction valid until {new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(selected.setupExpiresAt * 1000))}.{/if}</span></div>{/if}
      {#if selected.blocked}<div class="chat-banner" role="status"><span>This contact is blocked. Incoming messages are ignored and queued sends are paused.</span><button class="text-button" onclick={() => open('manage')}>Manage contact</button></div>{/if}
      {#if selected.timerPending}<p role="status">Timer update awaiting your contact. Sending will resume after acknowledgement.</p>{/if}
      {#if searchOpen}<form class="message-search" onsubmit={searchMessages}>
        <label for="message-search-input">Search this conversation</label><div>
          <input bind:this={searchField} id="message-search-input" class="text-input" bind:value={messageQuery} maxlength="128" placeholder="Words in a message" autocomplete="off" onkeydown={event=>{if(event.key==='Escape'){event.preventDefault();void clearSearch();}}}/>
          <button class="secondary" disabled={searching || !messageQuery.trim()}>Search</button>
          <button class="icon-button" type="button" aria-label="Close message search" onclick={clearSearch}><X size={20}/></button>
        </div></form>{/if}
      <div class="message-pane">
        <div class="messages" bind:this={list} onscroll={chatScroll}>
          {#if activeSearch}
            <div class="history-tools" role="status">{searching?'Searching…':`${searchResults.length} matching ${searchResults.length===1?'message':'messages'}`}. Disappearing messages are excluded.</div>
            {#if moreSearchResults}<button class="text-button history-tools" disabled={searching} onclick={()=>searchMessages(undefined,true)}>Load earlier matches</button>{/if}
          {:else if hasOlder}<button class="text-button history-tools" disabled={historyLoading} onclick={loadOlder}>{historyLoading?'Loading history…':'Load older messages'}</button>{/if}
          {#each visibleMessages as message (message.id)}
            <MessageBubble {message} original={message.replyTo ? messageById.get(message.replyTo) : undefined} contactName={selected.name}
              canReply={selected.ready && !selected.blocked} menuOpen={messageMenu===message.id} {menuPosition} highlighted={highlighted===message.id}
              downloading={!!downloading} onmenu={toggleMessageMenu} onreply={replyTo} oncopy={copyMessage} oninfo={showMessageInfo} onjump={jumpToMessage} ondownload={download}/>
          {:else}<div class="empty-chat"><ChatCircle size={40}/><h2>{activeSearch ? searching ? 'Searching messages…' : 'No matching messages' : 'A little space to talk.'}</h2><p>{activeSearch ? 'Try another word or return to your conversation.' : selected.ready ? 'Write your first message.' : 'You can come back later. Both people can connect at different times to finish setup.'}</p></div>{/each}
        </div>
        {#if newIncoming && !activeSearch}<button class="new-messages" onclick={latestMessages}><ArrowDown size={15}/>{newIncoming} new {newIncoming===1?'message':'messages'}</button>{/if}
      </div>
      <div class="composer-area">{#if replying}<div class="reply-preview"><ArrowBendUpLeft size={18}/><span>Replying to {replying.outgoing ? 'yourself' : selected.name}<b>{replying.text}</b></span><button class="icon-button" aria-label="Cancel reply" onclick={()=>replying=null}><X size={18}/></button></div>{/if}
        {#if fileSupported}
          {#if attaching && uploadContact===selectedId}<div class="transfer-progress" role="status"><span>{uploadProgress || 'Checking file…'}</span><button class="text-button" onclick={()=>uploadController?.abort()}>Pause upload</button></div>{/if}
          {#if transfers.length}<div class="transfer-list" aria-label="File transfers">{#each transfers as transfer (transfer.id)}<div class="transfer-row"><div><b dir="auto">{transfer.filename}</b><span>{(transfer.size/1024/1024).toFixed(1)} MiB · {transfer.phase==='uploading'?`${Math.round(transfer.uploaded/transfer.size*100)}% saved. Choose the same file to resume.`:transfer.phase==='preparing'?'Cleaning file before sending…':transfer.phase==='failed'?'This file could not be safely prepared.':'Preparing encrypted parts. Sending continues automatically.'}</span></div>{#if transfer.phase==='uploading'}<button class="text-button" disabled={attaching} onclick={()=>fileInput?.click()}>Resume upload</button>{/if}{#if transfer.phase==='uploading' || transfer.phase==='failed'}<button class="text-button" onclick={()=>cancelTransfer(transfer.id)} aria-label={'Remove upload '+transfer.filename}>Remove</button>{/if}</div>{/each}</div>{/if}
          <div class="attachment-tools"><label class="text-button attach-file" class:disabled={attaching || !selected.ready || selected.blocked || selected.timerPending || !!selected.timerSeconds}><Paperclip size={18}/>{attaching ? 'Uploading file…' : 'Attach file'}<input bind:this={fileInput} type="file" aria-label="Attach file" disabled={attaching || !selected.ready || selected.blocked || selected.timerPending || !!selected.timerSeconds} onchange={attach}/></label><span><strong>Maximum file size: 256 MB. Recommended: 10 MB or less. Larger files transfer very slowly.</strong>{selected.timerSeconds ? 'Files require the message timer off in this preview.' : 'Cleaned before sending · resumes after restart. For long transfers, select Keep unlocked above.'}</span></div>
        {/if}<form class="composer" onsubmit={send}><textarea bind:this={compose} aria-label="Write a message" placeholder="Write a message…" value={draft} oninput={e => drafts[selectedId] = e.currentTarget.value} onkeydown={key} maxlength={4000} rows="2" autocomplete="off" spellcheck="false" dir="auto" disabled={!selected.ready || selected.blocked || selected.timerPending}></textarea><button class="send-button" aria-label="Send message" disabled={sending || !selected.ready || selected.blocked || selected.timerPending || !draft.trim()}><PaperPlaneTilt size={23}/></button></form>
      <div class="composer-caption"><span class="composer-hint">Enter to send · Shift + Enter for a new line</span>{#if latestDelivery && !activeSearch}<span class="outgoing-confirmation" role="status" aria-label="Latest outgoing message status" title={latestDelivery.description}>Last send: <b>{latestDelivery.confirmation}</b></span>{:else}<span>{sending ? 'Saving message…' : selected.ready ? 'Encrypted conversation' : 'Contact setup pending'}</span>{/if}</div>
      {#if error}<p class="messenger-error" role="alert">{error}</p>{/if}{#if note}<p role="status">{note}</p>{/if}</div>
    {:else if !network.mailboxes.length}
      <section class="getting-started"><span class="eyebrow">WELCOME TO NAJWA</span><h1>A private place<br/>to keep in touch.</h1><p class="setup-intro">Connect a mailbox, invite someone, and start a conversation.</p>
        <ol class="setup-steps"><li class="current"><span>1</span><div><b>Connect your mailbox</b><p>Your operator provides the address. Najwa registers it for you.</p></div></li><li><span>2</span><div><b>Exchange an invitation</b><p>Share your link privately, or paste one you received.</p></div></li><li><span>3</span><div><b>Start talking</b><p>Messages stay encrypted between you and your contact.</p></div></li></ol>
        {@render mailboxForm()}
        {#if busy}<p class="setup-feedback" role="status">{progress}</p>{/if}{#if error}<p class="messenger-error" role="alert">{error}</p>{/if}
      </section>
    {:else if !contacts.length && !loading}
      <section class="getting-started"><span class="setup-ready"><Check size={18}/>{readyMailboxes.length ? 'Your mailbox is registered' : 'Finish mailbox registration'}</span><h1>Make your first<br/>connection.</h1><p class="setup-intro">Have an invitation? Paste it here. Or create your own link and share it with someone you trust.</p><div class="welcome-actions"><button class="primary" onclick={() => open('accept')}>Add a contact</button><button class="secondary" onclick={() => open('invite')}>Create an invitation</button></div><p class="field-help">Your display name is shared when you connect. You can compare safety numbers afterward.</p>{#if !readyMailboxes.length}<button class="text-button" onclick={() => navigate('settings')}>Finish setup in Settings</button>{/if}{#if busy}<p role="status">{progress}</p>{/if}{#if error}<p class="messenger-error" role="alert">{error}</p>{/if}</section>
    {:else}<div class="empty-chat"><ChatCircle size={40}/><h2>Your conversations</h2><p>Choose a contact to pick up where you left off.</p><button class="text-button" onclick={() => open('accept')}>Add another contact</button>{#if error}<p role="alert">{error}</p>{/if}</div>{/if}
  </main>
{/if}

<dialog bind:this={dialog} onclose={() => {dialogOpen = false; qr=null; exported=''; invitation='';}} aria-labelledby="connected-dialog-title">
  <h2 id="connected-dialog-title">{mode === 'message_info' ? 'Message info' : mode === 'manage' ? 'Contact details' : mode === 'timer' ? 'Disappearing messages' : mode === 'invite' ? 'Create a signed invitation' : mode === 'accept' ? 'Add a contact' : 'Compare safety numbers'}</h2>
  {#if mode === 'message_info'}
    {#if infoMessage}<dl class="message-info"><dt>Sent</dt><dd>{new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(infoMessage.timestamp*1000))}</dd>
      <dt>Status</dt><dd>{infoMessage.outgoing ? messageDelivery(infoMessage).label : 'Received'}</dd></dl>
      {#if infoMessage.outgoing}<p>{messageDelivery(infoMessage).description}</p>{/if}
      {#if infoMessage.expiresAt}<p>Disappears {new Intl.DateTimeFormat(undefined,{timeStyle:'medium'}).format(new Date(infoMessage.expiresAt))}.</p>{/if}
    {:else}<p>This message expired or is no longer available.</p>{/if}
  {:else if mode === 'manage' && selected}
    {#if confirmDelete}<div class="delete-confirm"><h3>Delete {selected.name}?</h3><p>This removes this contact, conversation history and queued messages from this computer. It also removes the conversation from the other person's Najwa when their app receives the notice. It cannot remove copies they made themselves. It cannot be undone.</p><p>To talk again, exchange a new invitation.</p><button class="danger-button" disabled={busy} onclick={()=>manage('delete')}>Delete contact and history</button><button class="secondary" disabled={busy} onclick={()=>confirmDelete=false}>Keep contact</button></div>
    {:else}<form onsubmit={e=>{e.preventDefault();void manage('rename');}}><label class="field-label" for="contact-name">Contact name on this computer</label><input class="text-input" id="contact-name" bind:value={rename} maxlength={128} required/><button class="secondary" disabled={busy || !rename.trim() || rename.trim()===selected.name}>Save name</button></form>
      <div class="contact-action"><h3>{selected.blocked ? 'Unblock contact' : 'Block contact'}</h3><p>{selected.blocked ? 'Allow messages again and resume queued delivery. Messages discarded while blocked cannot be recovered.' : 'Ignore new incoming messages and pause queued sends. History stays here. Messages already deposited or in flight cannot be recalled.'}</p><button class="secondary" disabled={busy} onclick={()=>manage(selected!.blocked?'unblock':'block')}>{selected.blocked?'Unblock contact':'Block contact'}</button></div>
      <div class="contact-action"><h3>Delete contact</h3><p>Permanently remove this device's contact and conversation history, including queued messages.</p><button class="danger-button" disabled={busy} onclick={()=>confirmDelete=true}>Delete contact…</button></div>
    {/if}
  {:else if mode === 'verify' && selected}
    <p>Compare this number in person or through a separate trusted channel.</p><p class="safety-number">{selected.safetyNumber}</p><p>{selected.verified ? 'Marked verified on this device.' : 'This identity is not verified yet.'}</p>
    <button class="primary" disabled={busy} onclick={() => perform(async () => { await request({kind:'verify',contact:selected!.id,safety:selected!.safetyNumber,verified:!selected!.verified}); dialog.close(); }, 'verify')}>{selected.verified ? 'Clear verification' : 'I compared the numbers'}</button>
  {:else if mode === 'timer' && selected}
    <p>This changes future messages. Sent messages count down after delivery; received messages count down when viewed. Existing messages keep their previous timer.</p>
    <p>Sending pauses until your contact acknowledges the encrypted timer update.</p>
    <form onsubmit={saveTimer}>
      <label class="field-label" for="timer-choice">Message timer</label>
      <select class="text-input" id="timer-choice" bind:value={timerChoice}>{#each timers as timer}<option value={String(timer.value)}>{timer.label}</option>{/each}<option value="custom">Custom seconds</option></select>
      {#if timerChoice === 'custom'}<label class="field-label" for="timer-seconds">Custom timer in seconds</label><input class="text-input" id="timer-seconds" type="number" min="30" max="4294967295" step="1" bind:value={customSeconds} required/>{/if}
      <div class="modal-actions"><button class="primary" disabled={busy || !selected.ready || selected.blocked || selected.timerPending}>Save timer</button></div>
    </form>
  {:else}
    <p>{mode === 'invite' ? 'Use a separate invitation for each contact. This link is valid for up to 48 hours from creation. Share it privately.' : 'Paste the Najwa invitation you received. You do not need to be online at the same time.'}</p>
    <p>Your display name is shared with the other person during contact setup.</p>
    <form onsubmit={e => { e.preventDefault(); void perform(async () => {
      if (mode === 'invite') { await createInvitation(); }
      else {
        try { selectedId = await request<string>({kind:'accept_invitation',invitation:invitation.trim(),name:name.trim(),...(limitConfirmed ? {confirmed:true} : {})}); }
        catch (failure) { if ((failure as {code?:string})?.code === 'contact_limit_confirm') { limitWarning = true; limitConfirmed = false; } throw failure; }
        revision++; dialog.close(); note = 'Contact request saved. The introduction sends in the background. You can use other conversations while waiting for a reply.';
      }
    }, mode === 'invite' ? 'invitation' : 'accept_invitation'); }}>
      <label class="field-label" for="shared-name">Your display name to share</label><input id="shared-name" class="text-input" bind:value={name} maxlength={128} autocomplete="off" required/>
      {#if mode === 'accept'}{#if dialogOpen}<QrScanner onscan={value=>{invitation=value;note='Invitation scanned. Enter your display name and choose Accept invitation.';}}/>{/if}<label class="field-label" for="invite">Signed invitation</label><textarea id="invite" class="text-input" bind:value={invitation} maxlength={4096} rows="4" autocomplete="off" spellcheck="false" required></textarea>
        {#if limitWarning}<label class="limit-confirm"><input type="checkbox" bind:checked={limitConfirmed}/>I understand. Add this contact anyway.</label>{/if}{/if}
      <div class="modal-actions"><button class="primary" disabled={busy || (mode === 'invite' && network.connection !== 'connected') || !readyMailboxes.length || !name.trim() || (mode === 'accept' && limitWarning && !limitConfirmed)}>{mode === 'invite' ? 'Generate invitation' : 'Accept invitation'}</button></div>
    </form>
    {#if exported}{#if qr}<div class="invitation-qr"><img src={'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(qr.qrSvg)} alt="Scan this QR code to add this Najwa contact"/><p>Valid until {new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(qr.expiresAt*1000))}</p><button class="secondary" onclick={()=>downloadBlob(new Blob([qr!.qrSvg],{type:'image/svg+xml'}),'Najwa-invitation.svg')}>Save QR image</button></div>{/if}<label class="field-label" for="exported">Invitation to share</label><textarea bind:this={invitationField} id="exported" class="text-input invitation-output" readonly value={exported} rows="4" onfocus={e => e.currentTarget.select()}></textarea><button class="secondary copy-invitation" onclick={copyInvitation}><Copy size={17}/>Copy invitation</button><p class="field-help">Includes {readyMailboxes.length} registered {readyMailboxes.length === 1 ? 'mailbox' : 'mailboxes'} for delivery.</p>{/if}
    {#if !readyMailboxes.length}<p>Finish mailbox setup in Settings first.</p><button class="text-button" onclick={() => {dialog.close(); navigate('settings');}}>Go to mailbox settings</button>{/if}
  {/if}
  {#if busy}<p role="status">{progress}</p>{/if}{#if error}<p class="messenger-error" role="alert">{error}</p>{/if}{#if note && dialogOpen}<p class="dialog-note" role="status">{note}</p>{/if}
  <div class="modal-actions"><button class="secondary" onclick={() => { dialog.close(); exported = ''; invitation = ''; }}>Close</button></div>
</dialog>

<style>
  .composer-caption {flex-wrap:wrap;line-height:1.5;}
  .composer-caption > .outgoing-confirmation {display:inline;overflow-wrap:anywhere;}
  .outgoing-confirmation b {font-weight:600;color:var(--ink);}
  @media(max-width:600px){.composer-caption > .composer-hint {display:none;}}
  .conversation-meta {display:flex;flex-direction:column;align-items:flex-end;gap:7px;flex-shrink:0;margin-left:auto;}
  .conversation-meta time {font-size:10px;color:var(--muted);white-space:nowrap;}
  .unread-count {display:grid;place-items:center;min-width:20px;height:20px;padding:0 5px;border-radius:10px;background:var(--accent);color:white;font-size:11px;font-weight:600;}
  .message-search {padding:10px 25px;border-bottom:1px solid var(--line);}
  .message-search label {display:block;font-size:12px;color:var(--muted);margin-bottom:6px;}
  .message-search>div {display:flex;gap:8px;align-items:center;}
  .message-search input {flex:1;min-width:0;}
  .history-tools {display:block;text-align:center;margin:0 auto 15px;font-size:12px;color:var(--muted);line-height:1.6;}

  dialog {max-height:calc(100dvh - 40px);overflow-y:auto;}
  .invitation-qr {text-align:center;margin:18px 0}.invitation-qr img{display:block;margin:auto;width:min(100%,350px);image-rendering:pixelated}.invitation-qr p{font-size:12px;color:var(--muted)}
  .contact-action{border-top:1px solid var(--line);margin-top:24px;padding-top:20px}.contact-action h3,.delete-confirm h3{font-size:15px}.contact-action p,.delete-confirm p{font-size:13px;line-height:1.7;color:var(--muted);margin:10px 0 14px}.danger-button{color:var(--warning);border:1px solid var(--warning);padding:10px 14px;border-radius:7px}.delete-confirm button{margin:6px 10px 6px 0}
  .message-pane {position:relative;display:flex;flex:1;min-height:0;}
  .message-pane .messages {padding-top:18px;padding-bottom:16px;}
  .new-messages {position:absolute;bottom:12px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:7px;padding:8px 13px;background:var(--accent);color:white;border-radius:18px;font-size:12px;box-shadow:0 3px 12px rgb(40 27 76 / 15%);white-space:nowrap;}
  .new-messages:active {transform:translateX(-50%) translateY(1px);}
  .message-info {display:grid;grid-template-columns:70px 1fr;gap:12px;font-size:13px;margin:20px 0;}.message-info dt{color:var(--muted);}.message-info dd{margin:0;}
  .reply-preview{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:7px;padding:10px 12px;background:var(--soft);font-size:11px;margin-bottom:10px;color:var(--accent);font-weight:600}.reply-preview span{flex:1;min-width:0}.reply-preview b{display:block;margin-top:3px;font-weight:400;font-size:12px;color:var(--ink);overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
  .attachment-tools{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:8px}.attachment-tools>span{font-size:11px;line-height:1.5;color:var(--muted)}.attachment-tools strong{display:block;font-size:12px;font-weight:600;color:var(--ink)}.attach-file{position:relative;display:flex;gap:6px;align-items:center;cursor:pointer}.attach-file input{position:absolute;inset:0;opacity:0;width:100%;cursor:pointer}.attach-file:focus-within{outline:2px solid var(--accent);outline-offset:3px}.attach-file.disabled{opacity:.5;cursor:default}
  .transfer-list{max-height:150px;overflow:auto;margin-bottom:10px}.transfer-row,.transfer-progress{display:flex;align-items:center;gap:12px;padding:7px 0;font-size:12px;border-bottom:1px solid var(--line);flex-wrap:wrap}.transfer-row>div{min-width:0;flex:1 1 180px}.transfer-row b,.transfer-row span{display:block;overflow-wrap:anywhere}.transfer-row span{font-size:11px;line-height:1.5;color:var(--muted);margin-top:3px}.transfer-progress{justify-content:space-between;color:var(--muted)}


  .back-link { display:flex; align-items:center; gap:7px; color:var(--muted); margin-bottom:24px; padding:0; font-size:13px; }
  .settings-page { padding-top:30px; }
  .settings-section > h2 { display:flex; align-items:center; gap:12px; margin-bottom:7px; }
  .count { font-size:12px; font-weight:500; color:var(--muted); font-variant-numeric:tabular-nums; }
  .mailbox-list { margin-top:20px; }
  .mailbox-row { padding:17px 0; border-bottom:1px solid var(--line); }
  .mailbox-row-title { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:6px; }
  .mailbox-badge { color:var(--muted); font-size:11px; background:var(--soft); padding:3px 8px; border-radius:4px; }
  .mailbox-badge.registered { color:var(--success); }
  .mailbox-state { margin-top:12px; font-size:12px; }
  .field-help { color:var(--muted); font-size:12px; line-height:1.65; }
  .mailbox-form .field-help { margin-bottom:10px; }
  .form-actions { display:flex; align-items:center; gap:14px; flex-wrap:wrap; margin-top:14px; }
  .form-actions .primary, .copy-invitation { display:inline-flex; align-items:center; gap:7px; }
  .form-actions .field-help { margin:0; }
  .text-button { color:var(--accent); font-size:12px; font-weight:600; padding:8px 0; }
  .remove-setup { margin-left:20px; color:var(--muted); }
  .delivery-options { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin:18px 0 12px; }
  .delivery-options > button { display:flex; align-items:flex-start; flex-direction:column; gap:8px; padding:18px; border:1px solid var(--line); border-radius:10px; text-align:left; }
  .delivery-options > button.chosen { border-color:var(--accent); background:var(--accent-soft); }
  .delivery-options > button > span { font-size:12px; color:var(--muted); line-height:1.65; }
  .delivery-options :global(svg) { color:var(--accent); }
  .recommended { font-size:10px; margin-left:6px; font-weight:500; color:var(--muted); }
  .getting-started { width:min(100%, 620px); margin:auto; padding:42px 44px; overflow-y:auto; }
  .getting-started h1 { font-size:38px; line-height:1.16; letter-spacing:-1.4px; margin:10px 0 18px; }
  .setup-intro { font-size:15px; line-height:1.7; color:var(--muted); max-width:40ch; }
  .setup-steps { list-style:none; margin:30px 0 24px; padding:0; display:grid; gap:20px; }
  .setup-steps li { display:flex; align-items:flex-start; gap:15px; }
  .setup-steps li > span { display:grid; place-items:center; border:1px solid var(--line); border-radius:9px; width:30px; height:30px; flex-shrink:0; font-size:12px; color:var(--muted); }
  .setup-steps li.current > span { color:var(--accent); background:var(--accent-soft); border-color:transparent; }
  .setup-steps b { font-size:13px; font-weight:600; }
  .setup-steps p { margin-top:2px; font-size:12px; line-height:1.6; color:var(--muted); }
  .setup-ready { display:flex; align-items:center; gap:7px; color:var(--success); font-size:12px; margin-bottom:23px; }
  .welcome-actions { display:flex; gap:10px; flex-wrap:wrap; margin:28px 0 16px; }
  .setup-feedback { font-size:12px; color:var(--muted); margin-top:16px; }
  .chat-actions { display:flex; gap:8px; }
  .mobile-back { display:none; }
  .chat-banner { display:flex; align-items:center; gap:10px; background:var(--soft); color:var(--muted); font-size:12px; padding:12px 25px; }
  .chat-banner > span { flex:1; }
  .invitation-output { font-size:12px; word-break:break-all; }
  .copy-invitation { margin:12px 0 8px; }
  .dialog-note { margin-top:15px; color:var(--success); font-size:12px; }
  .limit-confirm { display:flex; align-items:flex-start; gap:9px; margin-top:14px; font-size:13px; line-height:1.6; }
  .limit-confirm input { margin-top:3px; accent-color:var(--accent); }
  .mailbox-host { overflow-wrap:anywhere; font-family:monospace; font-size:13px; }
  .safety-number { font-family:monospace; font-size:20px; line-height:1.8; letter-spacing:2px; }
  .messenger-error { color:var(--warning); font-size:13px; line-height:1.6; }
  .settings-section > p { color:var(--muted); line-height:1.7; }
  .chat > .empty-chat { margin:auto; }
  .composer-area > p { font-size:12px; line-height:1.6; margin-top:10px; }
  @media (max-width:1120px) { .chat-header { flex-wrap:wrap; } .chat-actions { margin-left:auto; } }
  @media (max-width:900px) {
    .conversation-list:has(+ .has-selection), .conversation-list.empty-start { display:none; }
    .conversation-list:not(.empty-start) { width:100%; }
    .connected-chat:not(.has-selection) { display:none; }
    .empty-start + .connected-chat { display:flex; }
    .mobile-back { display:inline-flex; }
    .getting-started { padding:30px; }
    .getting-started h1 { font-size:32px; }
    .delivery-options { grid-template-columns:1fr; }
    .chat-actions { width:100%; justify-content:flex-end; }
  }
</style>
