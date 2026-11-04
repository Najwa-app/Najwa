<script lang="ts">
  import { onMount } from 'svelte';
  import { ChatCircle, Users, GearSix, LockSimple, ArrowLeft, Key, DownloadSimple, ShieldCheck } from 'phosphor-svelte';
  import Messenger from '../src/Messenger.svelte';
  import Preferences from './Preferences.svelte';
  import EraseProfile from './EraseProfile.svelte';
  import logo from '../src/assets/najwa-mark.png';
  import { identityError, type IdentityStatus } from '../src/identity';
  import { messagingStatus, unavailableNetwork, type NetworkStatus } from '../src/messaging';
  import { api, lockOnExit } from './bridge';
  type Status = IdentityStatus & {protection:'os-keystore'|'hardware';busy:boolean;softwareFallbackAvailable:boolean;softwareFallbackApproved:boolean;lockTimeoutSeconds?:number};
  let identity = $state<Status | null>(null);
  let network = $state<NetworkStatus>(unavailableNetwork);
  let section = $state<'chats'|'contacts'|'settings'|'account'>('chats');
  let screen = $state<'main'|'recover'|'password'|'kit'>('main');
  let password = $state(''); let confirmation = $state(''); let current = $state('');
  let words = $state(''); let revealed = $state('');
  let recoveryRecord = $state('');
  let acting = $state(false); let error = $state(''); let note = $state('');
  let closing = $state(false);
  let closed = $state(false);
  let erased = $state(false); let erasing = $state(false);
  let erasedMailboxes = $state<{deactivated:string[];unreachable:string[]}|null>(null);
  const lockMinutes = $derived((identity?.lockTimeoutSeconds ?? 300)/60);
  let downloaded = $state(false); let savedWords = $state(false);
  let wordCheck = $state(false); let kitVerified = $state(false);
  let challenge = $state<number[]>([]); let answers = $state<string[]>([]); let wordError = $state('');
  $effect(() => {
    void revealed;wordCheck=false;kitVerified=false;challenge=[];answers=[];wordError='';
    if(!revealed){downloaded=false;savedWords=false;}
  });
  let checking = false; let lastActivity = 0; let running = true;
  let connectionIssue = $state('');
  let keepUnlocked = $state(false);
  let approvalDialog = $state(false); let approvalChecked = $state(false);
  let approvalElement = $state<HTMLDialogElement>();
  const identityEpoch = $derived(`${identity?.session}:${identity?.generation}:${identity?.phase}`);
  const unlocked = $derived(identity?.phase === 'unlocked');
  const creating = $derived(identity?.phase === 'absent');
  const busy = $derived(acting || identity?.busy || identity?.phase === 'locking');
  $effect(() => { void identityEpoch; keepUnlocked = false; approvalDialog = false; approvalChecked = false; });
  $effect(() => { if (approvalDialog && approvalElement && !approvalElement.open) approvalElement.showModal(); });
  $effect(() => {
    if (!keepUnlocked || !unlocked) return;
    const interval = setInterval(activity,15_000);
    return () => clearInterval(interval);
  });
  function clearSecrets() { password = ''; confirmation = ''; current = ''; words = ''; revealed = ''; recoveryRecord = ''; }
  function erasedProfile(mailboxes?:{deactivated:string[];unreachable:string[]}) { if(mailboxes)erasedMailboxes=mailboxes;erased=true;closing=true;closed=true;clearSecrets();identity=null;network=unavailableNetwork;error='';note=''; }
  function preferencesChanged(value:IdentityStatus) {
    if(identity)identity={...identity,...value};
    if(value.phase!=='unlocked'){clearSecrets();network=unavailableNetwork;screen='main';note='Connection settings saved. Unlock to connect using them.';}
  }
  function failure(value:unknown) {
    const code = (value as {code?:string})?.code;
    if (code === 'weak_passphrase') {
      const hint = (value as {hint?:unknown}).hint;
      return 'This passphrase is too easy to guess. Try four or more unrelated words.' + (typeof hint === 'string' && hint.length <= 200 ? ` ${hint}` : '');
    }
    return ({service_unavailable:'The local service is unavailable. Start Najwa, then reload this page.',
      service_restarted:'Najwa restarted. Reconnecting to your locked profile…',
      launch_required:'Connect this browser once by opening Najwa on this computer or using the complete launch link.',
      keystore_unavailable:'Key storage is unavailable. Check your TPM or system keyring and try again. If hardware protection is unavailable, you can explicitly choose system key storage below.',
      software_approval_not_available:'Try hardware protection first. System storage needs your explicit approval after a hardware failure.',
      lock_failed:'Locking could not finish. Retry Lock now before leaving this computer.'} as Record<string,string>)[code ?? ''] ?? identityError(value);
  }
  async function refresh() {
    if (checking || acting || erasing || !running || closing) return;
    checking = true;
    try {
      const status = await api<Status>('/api/status');
      if (!running || acting) return;
      if(status.phase === 'erased') { erasedProfile(); return; }
      if (identity && identity.session !== status.session) { clearSecrets(); screen = 'main'; }
      if (identity?.session !== status.session || status.phase !== 'unlocked') { revealed = ''; network = unavailableNetwork; }
      identity = status;
      if (['service_unavailable','service_restarted','launch_required'].some(code => error === failure({code}))) error = '';
      connectionIssue = '';
      if (status.phase === 'unlocked' && !status.busy) network = await messagingStatus();
    } catch (value) {
      error = failure(value);
      const code = (value as {code?:string})?.code ?? '';
      if (['service_unavailable','service_restarted','launch_required'].includes(code)) {
        connectionIssue = code;
        identity = null; network = unavailableNetwork; clearSecrets();
      }
    }
    finally { checking = false; }
  }
  async function action(operation:Record<string,unknown>) {
    if (!identity || acting) return;
    acting = true; error = ''; note = '';
    const before = identity;
    try {
      const result = await api<{identity:Status;value: {words?:string;record?:string}|null}>('/api/identity',{
        session:before.session,generation:before.generation,operation
      });
      identity = result.identity;
      return result.value;
    } catch (value) { error = failure(value); }
    finally { acting = false; await refresh(); }
  }
  async function approveSoftwareStorage() {
    if (!approvalChecked) return;
    await action({kind:'approve_software_storage',confirmed:true});
    approvalDialog = false; approvalChecked = false; clearSecrets();
    if (!error) {
      if (!creating && identity?.recoveryAvailable) screen = 'recover';
      note = creating ? 'System storage approved for this identity. Enter your passphrase again to continue.' : 'System storage approved. If the hardware key is unavailable, use this identity’s recovery kit to restore access.';
    }
  }
  async function submit(event:SubmitEvent) {
    event.preventDefault();
    const kind = screen === 'recover' ? creating ? 'restore' : 'recover' : screen === 'password' ? 'change_password' : creating ? 'create' : 'unlock';
    if (kind === 'restore' && !recoveryRecord) { error = 'Choose your encrypted recovery file first.'; return; }
    const operation = kind === 'unlock' ? {kind,password} : kind === 'restore' ? {kind,record:recoveryRecord,words,password,confirmation} : kind === 'recover' ? {kind,words,password,confirmation}
      : kind === 'change_password' ? {kind,current,password,confirmation} : {kind,password,confirmation};
    clearSecrets();
    await action(operation);
    // Drop the final JS references as soon as the request completes.
    for (const key of ['password','confirmation','current','words']) if (key in operation) (operation as Record<string,unknown>)[key] = '';
    if (!error) {
      screen = identity?.recoveryPending ? 'kit' : 'main';
      if (kind === 'change_password') note = 'Passphrase updated. Your identity and conversations are unchanged.';
    }
  }
  async function importRecovery(event:Event) {
    recoveryRecord = ''; error = '';
    const file = (event.currentTarget as HTMLInputElement).files?.[0];
    if (!file) return;
    if (file.size !== 105) { error = 'Choose the 105-byte encrypted .recovery file from your kit.'; return; }
    const bytes = new Uint8Array(await file.arrayBuffer());
    recoveryRecord = btoa(String.fromCharCode(...bytes));
  }
  async function lock() {
    if (!identity) return;
    clearSecrets(); network = unavailableNetwork; screen = 'main';
    const before = identity;
    identity = {...identity,phase:'locking'};
    try { identity = await api<Status>('/api/lock',{session:before.session,generation:before.generation}); error = ''; }
    catch (value) { error = failure(value); }
    finally { await refresh(); }
  }
  async function quit() {
    if (!identity || closing) return;
    const before = identity;
    closing = true; clearSecrets(); network = unavailableNetwork;
    try { await api('/api/quit',{session:before.session,generation:before.generation}); closed = true; identity = null; error = ''; }
    catch (value) { closing = false; error = failure(value); await refresh(); }
  }
  async function reveal() {
    const value = await action({kind:'recovery_words'});
    if (value?.words) revealed = value.words;
  }
  async function download() {
    const value = await action({kind:'export_recovery'});
    if (!value?.record) return;
    const bytes = Uint8Array.from(atob(value.record),v => v.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));
    const link = document.createElement('a'); link.href = url; link.download = `najwa-${identity?.fingerprint?.slice(0,12)}.recovery`;
    link.click(); setTimeout(() => URL.revokeObjectURL(url),1000); downloaded = true;
  }
  async function finishKit() {
    if(!downloaded || !savedWords || !kitVerified) return;
    await action({kind:'acknowledge_recovery'});
    if (!error) { revealed = ''; screen = 'main'; note = 'Recovery kit saved.'; }
  }
  function startWordCheck() {
    if(!revealed || !downloaded || !savedWords) return;
    const indices=new Set<number>(),random=new Uint8Array(1);
    while(indices.size<3){crypto.getRandomValues(random);const index=random[0]&31;if(index<24)indices.add(index);}
    challenge=[...indices].sort((a,b)=>a-b);answers=['','',''];wordError='';wordCheck=true;kitVerified=false;
  }
  function checkWords(event:SubmitEvent) {
    event.preventDefault();const expected=revealed.trim().split(/\s+/);
    if(challenge.length!==3 || expected.length!==24 || challenge.some((index,i)=>answers[i]?.trim().toLowerCase()!==expected[index])) {
      wordError='These words do not match. Check your written copy, or review the words and try again.';return;
    }
    kitVerified=true;wordCheck=false;answers=[];wordError='';
  }
  async function replaceKit(event:SubmitEvent) {
    event.preventDefault(); const value = password; password = '';
    await action({kind:'replace_recovery',password:value});
    if (!error) { downloaded = false; savedWords = false; screen = 'kit'; }
  }
  function activity() {
    if (!identity || !unlocked || Date.now() - lastActivity < 30_000) return;
    lastActivity = Date.now();
    void api('/api/activity',{session:identity.session,generation:identity.generation}).catch(() => {});
  }
  function exit() {
    clearSecrets();
    if (identity && !closing) void lockOnExit(identity.session,identity.generation).catch(() => {});
  }
  onMount(() => {
    void refresh();
    const interval = setInterval(() => void refresh(),1500);
    return () => { running = false; clearInterval(interval); clearSecrets(); };
  });
</script>

<svelte:window onpointerdown={activity} onkeydown={activity} onpagehide={exit}/>
<div class="local-app">
  <header class="brandbar"><div class="brand"><img src={logo} alt=""/>Najwa</div><span class="local-label">On this computer</span>
    {#if unlocked}<label class="keep-unlocked" title="Keep unlocked while this page is open, for example during a long file transfer"><input type="checkbox" bind:checked={keepUnlocked}/>Keep unlocked</label><button class="secondary lock" onclick={lock}><LockSimple size={16}/>Lock</button>{/if}
    {#if identity && !closing}<button class="secondary" onclick={quit}>Quit Najwa</button>{/if}
  </header>
  {#if unlocked && keepUnlocked}<div class="notice" role="status">Automatic locking is paused for this tab. Use Lock or close the page when you leave.</div>{/if}
  {#if error}<div class="notice error" role="alert">{error}<button onclick={() => error = ''} aria-label="Dismiss error">×</button></div>{/if}
  {#if note}<div class="notice" role="status">{note}</div>{/if}
  {#if identity?.protection === 'os-keystore' && identity.softwareFallbackApproved}<div class="notice storage-status" role="status"><ShieldCheck size={17}/>Using system key storage — approved by you. This identity is not protected by a hardware key.</div>{/if}
  {#if identity?.softwareFallbackAvailable && !identity.softwareFallbackApproved && !busy && !closing}
    <div class="notice"><button class="secondary" onclick={() => {approvalChecked = false; approvalDialog = true;}}>Use system key storage instead…</button></div>
  {/if}
  {#if approvalDialog && identity && !closing}
    <dialog class="approval-dialog" bind:this={approvalElement} aria-labelledby="storage-title" onclose={() => {approvalDialog = false; approvalChecked = false;}}>
      <h2 id="storage-title">Use system key storage?</h2>
      <p>Your passphrase and your operating system’s key storage will protect this identity. It will not have TPM or Secure Enclave protection. Najwa will still try hardware first when creating a new key.</p>
      {#if !creating}<p>An existing hardware-protected identity still needs its recovery kit if its hardware key is unavailable. This choice cannot bypass or replace a missing key.</p>{/if}
      <label class="check"><input type="checkbox" bind:checked={approvalChecked}/>I understand and approve using system key storage for this identity.</label>
      <div class="approval-actions"><button class="secondary" onclick={() => {approvalDialog = false; approvalChecked = false;}}>Keep hardware protection</button><button class="primary" disabled={!approvalChecked || acting} onclick={approveSoftwareStorage}>Use system key storage</button></div>
    </dialog>
  {/if}
  {#if closing}
    <main class="gate"><div class="gate-content"><h1>{erased ? 'Local profile erased.' : closed ? 'Najwa is closed.' : 'Closing Najwa…'}</h1><p>{erased ? 'You can close this tab. Open Najwa again to create or restore an identity.' : closed ? 'You can close this tab. Open the installed app when you want to return.' : 'Locking your identity and stopping the local app.'}</p>{#if erased && erasedMailboxes?.deactivated.length}<p class="mailboxes">These mailboxes stopped accepting messages for this profile: {erasedMailboxes.deactivated.join(', ')}</p>{/if}{#if erased && erasedMailboxes?.unreachable.length}<p class="mailboxes">These mailboxes could not be reached. They keep accepting your contacts’ messages for this profile until 30 days pass without any: {erasedMailboxes.unreachable.join(', ')}</p>{/if}</div></main>
  {:else if !identity}
    <main class="gate"><div class="gate-content"><h1>{connectionIssue === 'launch_required' ? 'Connect this browser' : 'Opening Najwa…'}</h1><p>{connectionIssue === 'launch_required' ? 'After connecting once, this browser can return to your locked profile for up to 30 days. Your passphrase is still required.' : 'Your local service keeps your identity and conversations on this computer.'}</p><button class="secondary" onclick={() => location.reload()}>Reload</button></div></main>
  {:else if identity.phase === 'wiping'}
    <main class="gate"><div class="gate-content"><h1>{identity.busy?'Erasing this local profile…':'Finish local erasure'}</h1>{#if identity.busy}<p>Keep Najwa open until cleanup finishes.</p>{:else}<p>Local erasure was interrupted. Unlock and identity creation are blocked until cleanup finishes.</p><EraseProfile {identity} onerased={erasedProfile} onbusy={value=>erasing=value}/>{/if}</div></main>
  {:else if identity.phase === 'error'}
    <main class="gate"><div class="gate-content"><h1>Finish locking your identity</h1><p>Najwa could not confirm that all key handles were cleared.</p><button class="primary" onclick={lock}>Retry Lock now</button></div></main>
  {:else if busy}
    <main class="gate"><div class="gate-content"><div class="pulse"></div><h1>{identity.phase === 'locking' && !acting ? 'Locking…' : 'Opening your profile…'}</h1><p>Your passphrase protects the same identity each time you return. This can take a few seconds.</p><button class="secondary" onclick={lock}>Lock now</button></div></main>
  {:else if !unlocked || screen === 'recover' || screen === 'password'}
    <main class="gate"><div class="gate-content">
      {#if screen !== 'main'}<button class="back" onclick={() => {screen = 'main'; clearSecrets(); error = '';}}><ArrowLeft size={16}/>Back</button>{/if}
      <div class="gate-symbol"><Key size={28}/></div>
      <span class="eyebrow">YOUR PRIVATE SPACE</span>
      <h1>{screen === 'recover' ? creating ? 'Bring your identity back.' : 'Recover this identity' : screen === 'password' ? 'Change your passphrase' : creating ? 'Make yourself at home.' : 'Welcome back.'}</h1>
      <p>{screen === 'recover' ? creating ? 'Choose the encrypted file from your kit and enter its 24 words. This restores your identity. Conversation history stays in your original profile.' : 'Use the 24 words that match this profile’s recovery record. Your identity and stored conversations will be preserved.' : screen === 'password' ? 'Choose a new passphrase for this profile.' : creating ? 'Create one identity on this computer. You’ll return to the same account and conversations every time.' : 'Unlock your identity to return to your conversations.'}</p>
      <form onsubmit={submit}>
        {#if screen === 'recover'}
          {#if creating}<label for="recovery-file">Encrypted recovery file</label><input id="recovery-file" type="file" accept=".recovery,application/octet-stream" onchange={importRecovery} required/>{/if}
          <label for="words">Recovery words</label><textarea id="words" bind:value={words} rows="4" autocomplete="off" spellcheck="false" required maxlength="1024"></textarea>{/if}
        {#if screen === 'password'}<label for="current">Current passphrase</label><input id="current" type="password" bind:value={current} autocomplete="current-password" required maxlength="1024"/>{/if}
        <label for="password">{creating || screen !== 'main' ? 'New passphrase' : 'Passphrase'}</label>
        <input id="password" type="password" bind:value={password} autocomplete={creating || screen !== 'main' ? 'new-password' : 'current-password'} minlength={creating || screen !== 'main' ? 12 : 1} maxlength="1024" required/>
        {#if creating || screen !== 'main'}<small>Use at least 12 characters that are hard to guess. Four or more unrelated words work well.</small><label for="confirmation">Confirm passphrase</label><input id="confirmation" type="password" bind:value={confirmation} autocomplete="new-password" minlength="12" maxlength="1024" required/>{/if}
        <button class="primary wide" type="submit">{screen === 'recover' ? 'Recover identity' : screen === 'password' ? 'Update passphrase' : creating ? 'Create my identity' : 'Unlock Najwa'}</button>
      </form>
      {#if !creating && screen === 'main' && identity.recoveryAvailable}<button class="text-button" onclick={() => {screen = 'recover'; clearSecrets();}}>Forgot your passphrase?</button>{/if}
      {#if creating && screen === 'main'}<button class="text-button" onclick={() => {screen = 'recover'; clearSecrets();}}>I already have a recovery kit</button>{/if}
      <div class="footnote"><ShieldCheck size={17}/><span>Encrypted on this computer. Protected by your passphrase and {identity.protection === 'hardware' ? 'hardware key storage' : 'system key storage'}. Automatic locking can be changed in Settings after unlocking.</span></div>
      {#if !creating && screen==='main'}<details class="erase-locked"><summary>Remove this profile from this computer</summary><p>Use this if you want to start over. Erased conversations cannot be recovered.</p><EraseProfile {identity} onerased={erasedProfile} onbusy={value=>erasing=value}/></details>{/if}
    </div></main>
  {:else if screen === 'kit'}
    <main class="gate"><div class="gate-content kit"><span class="eyebrow">A WAY BACK IN</span><h1>Save your recovery kit.</h1><p>Keep both parts: your 24 words and the encrypted recovery file. Together they can restore this identity if you forget your passphrase. Keep them in separate safe places.</p>
      <div class="kit-step"><h2>1. Write down your 24 words</h2>{#if revealed && !wordCheck && !kitVerified}<ol class="words">{#each revealed.split(' ') as word}<li>{word}</li>{/each}</ol>{:else if !revealed}<button class="secondary" onclick={reveal}>Reveal recovery words</button>{:else}<p>{kitVerified ? "Recovery words checked." : "Your words are hidden while you check your written copy."}</p>{/if}</div>
      <div class="kit-step"><h2>2. Save the encrypted recovery file</h2><button class="secondary" onclick={download}><DownloadSimple size={17}/>{downloaded ? 'Download again' : 'Download recovery file'}</button></div>
      <label class="check"><input type="checkbox" bind:checked={savedWords}/>I saved the words somewhere safe.</label>
      {#if revealed && downloaded && savedWords && !kitVerified}
        {#if wordCheck}<form class="word-check" onsubmit={checkWords}>
          <h2>3. Check your written copy</h2><p>Enter these three words from the copy you saved.</p>
          {#each challenge as index,i}<label for={'recovery-check-'+index}>Word {index+1}</label><input id={'recovery-check-'+index} bind:value={answers[i]} autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="32" required/>{/each}
          {#if wordError}<p class="word-error" role="alert">{wordError}</p>{/if}
          <button class="primary" type="submit">Check words</button><button class="secondary" type="button" onclick={()=>{wordCheck=false;answers=[];wordError='';}}>Review recovery words</button>
        </form>{:else}<button class="secondary wide" onclick={startWordCheck}>Check my recovery words</button>{/if}
      {/if}
      {#if kitVerified}<p class="word-confirmed" role="status">Your three recovery words match.</p>{/if}
      <button class="primary wide" disabled={!downloaded || !savedWords || !revealed || !kitVerified} onclick={finishKit}>I’ve saved both — continue</button>
      <p class="footnote">Your profile and conversations remain on this computer. The recovery kit restores your identity; it does not back up conversation history.</p>
    </div></main>
  {:else}
    <div class="workspace"><nav class="rail" aria-label="Navigation">
      <button class:active={section === 'chats'} onclick={() => section = 'chats'}><ChatCircle size={22}/>Chats</button>
      <button class:active={section === 'contacts'} onclick={() => section = 'contacts'}><Users size={22}/>Contacts</button>
      <div class="rail-spacer"></div>
      <button class:active={section === 'settings'} onclick={() => section = 'settings'}><GearSix size={22}/>Settings</button>
      <button class:active={section === 'account'} onclick={() => section = 'account'}><Key size={22}/>Identity</button>
    </nav>
    {#if section === 'account'}
      <main class="page-view account"><span class="eyebrow">YOUR IDENTITY</span><h1>Always you.</h1><p>Your identity and encrypted conversations are saved on this computer.</p><code>{identity.fingerprint}</code>
        <section><h2>Passphrase</h2><p>Change how you unlock this local profile.</p><button class="secondary" onclick={() => {screen = 'password'; clearSecrets();}}>Change passphrase</button></section>
        <section><h2>Recovery kit</h2><p>{identity.recoveryPending ? 'Your recovery words are still available this session. Save the kit before locking.' : 'You can replace the kit after confirming your passphrase. Replacing it makes the previous words incompatible with this profile’s new recovery file. Old copies of a complete kit remain usable.'}</p>
          {#if identity.recoveryPending}<button class="secondary" onclick={() => screen = 'kit'}>Save recovery kit</button>{:else}<form onsubmit={replaceKit}><label for="kit-password">Confirm passphrase</label><input id="kit-password" type="password" bind:value={password} autocomplete="current-password" maxlength="1024" required/><button class="secondary" type="submit">Create replacement recovery kit</button></form>{/if}
        </section><section><h2>Local access</h2><p>Najwa locks after {lockMinutes} {lockMinutes===1?'minute':'minutes'} without activity and when this page closes. Change the timeout in Settings. For a long transfer, select Keep unlocked at the top of this page. This choice resets when you lock or restart Najwa. A browser tab may remain in your history; your passphrase is required to return.</p><button class="secondary" onclick={lock}><LockSimple size={16}/>Lock now</button></section>
        <section><h2>Erase this local profile</h2><p>Permanently remove this profile and its conversations from this computer. Downloaded files, exported recovery kits and other people’s copies are kept.</p><EraseProfile {identity} onerased={erasedProfile} onbusy={value=>erasing=value}/></section>
      </main>
    {:else}
      {#key `${identity.session}:${identity.generation}`}<Messenger {identity} {network} {section} navigate={value => section = value}>
        {#snippet localSettings()}{#if identity}<Preferences {identity} onchange={preferencesChanged}/>{/if}{/snippet}
      </Messenger>{/key}
    {/if}</div>
  {/if}
</div>

<style>
  .mailboxes{overflow-wrap:anywhere;}
  .erase-locked{margin-top:26px;font-size:12px;color:var(--muted);}.erase-locked summary{cursor:pointer;}.erase-locked p{margin:12px 0;line-height:1.6;}
  .word-check {margin:20px 0;padding-top:16px;border-top:1px solid var(--line);}.word-check h2{font-size:18px;}.word-check p{font-size:13px;line-height:1.6;margin-bottom:12px;}.word-check .secondary{margin-left:8px;}.word-error{color:var(--warning);}.word-confirmed{color:var(--success);font-size:13px;margin:12px 0;}

  .approval-dialog::backdrop { background:#11182780; }
  .approval-dialog { width:min(480px,calc(100% - 40px)); max-height:calc(100dvh - 40px); overflow:auto; border:0; padding:28px; border-radius:16px; background:var(--surface,#fff); color:var(--text,#1f2937); box-shadow:0 16px 64px #0003; }
  .approval-dialog h2 { margin:0 0 14px; } .approval-dialog p { line-height:1.55; }
  .approval-actions { display:flex; flex-wrap:wrap; gap:10px; margin-top:22px; } .storage-status { display:flex; align-items:center; gap:8px; }
  .local-app { height:100dvh; min-height:480px; display:flex; flex-direction:column; }
  .keep-unlocked {display:flex;align-items:center;gap:6px;margin:0;font-size:12px;white-space:nowrap;cursor:pointer;}
  @media(max-width:600px) { .brandbar {flex-wrap:wrap;min-height:64px;} .keep-unlocked {margin-left:auto;} }
  .lock { margin-left:4px; } .gate { flex:1; overflow:auto; padding:36px 24px 60px; display:flex; }
  .gate-content { width:100%; max-width:430px; margin:auto; } .gate-content.kit { max-width:600px; }
  .gate-symbol { width:56px; height:56px; display:grid; place-items:center; background:var(--accent-soft); color:var(--accent); border-radius:18px; margin-bottom:28px; }
  h1 { font-size:32px; letter-spacing:-1px; line-height:1.2; } .gate-content > p, .account > p { color:var(--muted); margin:14px 0 24px; }
  form { margin-top:25px; } label { display:block; font-size:13px; font-weight:600; margin:18px 0 8px; }
  input:not([type=checkbox]), textarea { width:100%; border:1px solid var(--input-line); background:var(--surface); border-radius:7px; padding:12px 14px; color:var(--ink); }
  small { display:block; color:var(--muted); font-size:12px; margin-top:8px; } .wide { width:100%; margin-top:24px; min-height:44px; font-size:14px; }
  .text-button { color:var(--accent); display:block; margin:18px auto; font-size:13px; padding:8px; }
  .footnote { display:flex; gap:10px; color:var(--muted); font-size:12px; line-height:1.7; margin-top:28px; }
  .notice { background:var(--accent-soft); padding:12px 24px; font-size:13px; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-shrink:0; }
  .notice.error { background:#fbefed; color:var(--warning); } .notice button { font-size:22px; padding:0 8px; }
  .back { display:flex; align-items:center; gap:6px; padding:8px 0; color:var(--muted); margin-bottom:16px; }
  .kit-step { border-top:1px solid var(--line); padding:22px 0; } .kit-step h2 { margin-bottom:14px; } .words { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px 28px; padding-left:28px; font-size:14px; margin:16px 0 0; } .words li::marker { color:var(--muted); font-size:11px; }
  .check { display:flex; align-items:center; gap:9px; font-weight:400; } .check input { width:17px; height:17px; accent-color:var(--accent); }
  .account { max-width:none; } .account section { max-width:640px; border-top:1px solid var(--line); margin-top:30px; padding-top:26px; } .account section p { margin:10px 0 16px; color:var(--muted); font-size:13px; } code { display:block; max-width:640px; overflow-wrap:anywhere; color:var(--muted); font-size:12px; } .account form { max-width:420px; } .account form button { margin-top:12px; }
  .pulse { width:32px; height:32px; border:3px solid var(--accent-soft); border-top-color:var(--accent); border-radius:50%; margin-bottom:24px; animation:spin 1s linear infinite; } @keyframes spin { to {transform:rotate(360deg);} } @media(prefers-reduced-motion:reduce) { .pulse { animation:none; } }
  @media(max-width:600px) { .brandbar { padding:8px 16px; gap:8px; height:auto; } .local-label { font-size:11px; } .gate { padding:28px 22px 40px; } h1 { font-size:28px; } .words { grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px 24px; } .account { padding:28px 22px; } .rail { width:68px; padding-left:4px; padding-right:4px; } }
</style>
