<script lang="ts">
  import { CaretDown, Check, Checks, Clock, WarningCircle, ArrowBendUpLeft, Copy, Info, Paperclip, DownloadSimple } from 'phosphor-svelte';
  import type { Message } from './messaging';
  import { messageDelivery } from './chatView';
  let { message, original, contactName, canReply, menuOpen, menuPosition, highlighted, downloading, onmenu, onreply, oncopy, oninfo, onjump, ondownload }: {
    message:Message; original?:Message; contactName:string; canReply:boolean; menuOpen:boolean;
    menuPosition:{top:number;left:number}; highlighted:boolean; downloading:boolean;
    onmenu:(id:string)=>void; onreply:(message:Message)=>void; oncopy:(message:Message)=>void;
    oninfo:(message:Message)=>void; onjump:(id:string)=>void; ondownload:(message:Message)=>void;
  } = $props();
  const delivery=$derived(messageDelivery(message));
  const author=$derived(original ? original.outgoing ? 'You' : contactName : 'Quoted message');
  const sent=$derived(new Intl.DateTimeFormat(undefined,{hour:'2-digit',minute:'2-digit'}).format(new Date(message.timestamp*1000)));
</script>

<article class="message" class:outgoing={message.outgoing} class:highlighted data-message-id={message.id} tabindex="-1">
  <div class="bubble">
    {#if message.replyTo}
      <button class="quoted-message" class:unavailable={!original} disabled={!original} aria-label={original ? `View original message from ${author}` : 'Original message unavailable'} onclick={()=>onjump(message.replyTo!)}>
        <ArrowBendUpLeft size={15}/><span><strong><bdi>{author}</bdi></strong><span class="quote-text" dir="auto">{original?.attachment?.filename ?? original?.text ?? 'Original message unavailable'}</span></span>
      </button>
    {/if}
    <div class="bubble-content">
      {#if message.attachment}
        <div class="file-card"><Paperclip size={21}/><div><b dir="auto">{message.attachment.filename}</b><span>{(message.attachment.size/1024).toFixed(1)} KiB · {message.attachment.supported ? message.outgoing && (message.attachment.depositedChunks ?? 0)<message.attachment.chunks ? `${message.attachment.depositedChunks ?? 0} of ${message.attachment.chunks} parts deposited` : message.attachment.complete ? message.outgoing ? 'File deposited' : 'File ready' : `${message.attachment.availableChunks} of ${message.attachment.chunks} parts received${message.attachment.failed ? ' · the rest did not arrive' : ''}` : 'Unsupported size or disappearing attachment in this preview'}</span></div><button class="download-file" aria-label={'Download '+message.attachment.filename} disabled={!message.attachment.complete || downloading} onclick={()=>ondownload(message)}><DownloadSimple size={20}/></button></div>
      {:else}<p class="message-text" dir="auto">{message.text}</p>{/if}
      <footer>
        {#if message.expiresAt}<span class="expiry" title="Disappearing message" aria-label="Disappearing message"><Clock size={12}/></span>{/if}
        <time datetime={new Date(message.timestamp*1000).toISOString()} title={new Date(message.timestamp*1000).toLocaleString()}>{sent}</time>
        {#if message.outgoing}<span class="delivery-status" class:read={delivery.read} class:failed={delivery.kind==='failed'} role="img" aria-label={delivery.label} title={delivery.description} data-status={message.attachment ? delivery.kind : message.status}>
          {#if delivery.kind==='double'}<Checks size={16}/>{:else if delivery.kind==='single'}<Check size={15}/>{:else if delivery.kind==='failed'}<WarningCircle size={15}/>{:else}<Clock size={13}/>{/if}
        </span>{/if}
      </footer>
    </div>
  </div>
  <div class="message-actions" data-message-actions>
    <button class="message-menu-toggle" id={'message-actions-'+message.id} aria-label="Message actions" aria-expanded={menuOpen} aria-controls={'message-menu-'+message.id} title="Message actions" onclick={()=>onmenu(message.id)}><CaretDown size={16}/></button>
    {#if menuOpen}<div class="message-menu" id={'message-menu-'+message.id} role="group" aria-label="Message actions" style:top={menuPosition.top+'px'} style:left={menuPosition.left+'px'}>
      <button disabled={!canReply} onclick={()=>onreply(message)}><ArrowBendUpLeft size={17}/>Reply</button>
      <button onclick={()=>oncopy(message)}><Copy size={17}/>{message.attachment?'Copy filename':'Copy text'}</button>
      <button onclick={()=>oninfo(message)}><Info size={17}/>Message info</button>
    </div>{/if}
  </div>
</article>

<style>
  .message {display:flex;flex-direction:row;align-items:flex-start;gap:3px;margin:0 0 6px;position:relative;scroll-margin-block:60px;outline:none;}
  .message.outgoing {justify-content:flex-end;align-items:flex-start;}
  .bubble {min-width:0;max-width:min(calc(100% - 35px),520px);padding:8px 10px 5px;background:var(--soft);border-radius:11px 11px 11px 3px;}
  .outgoing .bubble {background:var(--accent-soft);border-radius:11px 11px 3px 11px;}
  .bubble-content {display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:3px 12px;min-width:0;}
  .message .message-text {flex:1 1 auto;min-width:0;max-width:none;padding:0;background:none;border-radius:0;font-size:14px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;unicode-bidi:plaintext;}
  .message footer {display:inline-flex;align-items:center;justify-content:flex-end;gap:4px;margin-left:auto;padding:0;color:var(--muted);font-size:10px;line-height:16px;white-space:nowrap;}
  time {font-variant-numeric:tabular-nums;}.delivery-status,.expiry {display:inline-flex;align-items:center;}.delivery-status.read{color:#1682c4;}.delivery-status.failed{color:var(--warning);}
  .message-actions {align-self:flex-start;flex-shrink:0;padding-top:1px;}
  .message-menu-toggle {display:grid;place-items:center;width:27px;height:27px;padding:0;color:var(--muted);border-radius:6px;}
  .message-menu-toggle:hover,.message-menu-toggle[aria-expanded='true'] {background:var(--soft);color:var(--ink);}
  .message-menu {position:fixed;z-index:5;width:170px;padding:5px;border:1px solid var(--line);border-radius:9px;background:var(--surface);box-shadow:0 7px 24px rgb(35 28 56 / 12%);}
  .message-menu button {display:flex;align-items:center;gap:9px;width:100%;padding:9px 10px;border-radius:5px;text-align:left;font-size:12px;}
  .message-menu button:hover:not(:disabled) {background:var(--soft);}
  .quoted-message {display:flex;align-items:flex-start;gap:8px;width:100%;min-width:0;padding:8px 10px;margin:0 0 7px;background:rgb(255 255 255 / 78%);border:1px solid rgb(105 81 197 / 14%);border-left:3px solid var(--accent);border-radius:6px;text-align:start;}
  .quoted-message>span {min-width:0;flex:1;}.quoted-message :global(svg) {color:var(--accent);flex-shrink:0;margin-top:2px;}
  .quoted-message strong {display:block;font-size:11px;font-weight:650;color:var(--accent);margin-bottom:2px;}
  .quote-text {display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;line-clamp:2;overflow:hidden;font-size:12px;line-height:1.45;overflow-wrap:anywhere;color:var(--ink);white-space:pre-wrap;}
  .quoted-message.unavailable {opacity:1;color:var(--muted);}.quoted-message.unavailable .quote-text{color:var(--muted);}
  .highlighted .bubble,.message:focus-visible .bubble {box-shadow:0 0 0 2px var(--accent);}
  .file-card {display:flex;align-items:center;gap:10px;min-width:min(240px,100%);max-width:100%;padding:2px 0 4px;}
  .file-card>div{flex:1;min-width:0;}.file-card b{display:block;font-size:13px;font-weight:600;overflow-wrap:anywhere;}.file-card span{display:block;color:var(--muted);font-size:11px;line-height:1.5;margin-top:3px;}
  .download-file{display:grid;place-items:center;flex-shrink:0;width:28px;height:28px;padding:0;border-radius:5px;}
  @media(max-width:600px){.bubble{max-width:calc(100% - 32px);}.message .message-text{font-size:14px;}}
</style>
