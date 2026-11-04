<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import jsQR from 'jsqr';
  let { onscan }: {onscan:(value:string)=>void} = $props();
  let video = $state<HTMLVideoElement>();
  let stream: MediaStream | undefined;
  let running = $state(false);
  let starting = $state(false);
  let error = $state('');
  let epoch = 0;
  let timeout: ReturnType<typeof setTimeout>;
  function stop() { epoch++; clearTimeout(timeout); stream?.getTracks().forEach(track=>track.stop()); stream=undefined; running=false; starting=false; }
  function decoded(source:CanvasImageSource,width:number,height:number) {
    const scale=Math.min(1,2048/Math.max(width,height));
    const canvas=document.createElement('canvas'); canvas.width=Math.round(width*scale); canvas.height=Math.round(height*scale);
    const ctx=canvas.getContext('2d',{willReadFrequently:true}); if(!ctx || !canvas.width || !canvas.height) return '';
    ctx.drawImage(source,0,0,canvas.width,canvas.height);
    const pixels=ctx.getImageData(0,0,canvas.width,canvas.height);
    return jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:'attemptBoth'})?.data ?? '';
  }
  function accept(value:string) {
    if (!value.startsWith('NAJWA:') && !value.startsWith('najwa://contact?data=')) { error='This QR code is not a Najwa invitation.'; return false; }
    if (value.length>4096) { error='This invitation is too large.'; return false; }
    stop(); onscan(value); return true;
  }
  async function start() {
    stop(); const current=epoch; error=''; starting=true;
    try {
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('unavailable');
      const camera=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280}},audio:false});
      if(current!==epoch) { camera.getTracks().forEach(t=>t.stop()); return; }
      stream=camera; running=true; await tick();
      if(current!==epoch) return;
      if(!video) return;
      video.srcObject=camera; await video.play();
      const scan=()=> {
        if(current!==epoch || !running || !video) return;
        try { if(video.readyState>=2) { const value=decoded(video,video.videoWidth,video.videoHeight); if(value && accept(value)) return; } }
        catch { error='Could not read the camera. You can upload a QR image instead.'; stop(); return; }
        timeout=setTimeout(scan,180);
      }; scan();
    } catch { if(current===epoch) { stop(); error='Camera unavailable or permission denied. Allow camera access in your browser, or upload a QR image.'; } }
    finally { if(current===epoch) starting=false; }
  }
  async function image(event:Event) {
    const input=event.currentTarget as HTMLInputElement; const file=input.files?.[0]; input.value=''; if(!file) return;
    stop(); const current=epoch; error='';
    if(file.size>10*1024*1024 || !['image/png','image/jpeg','image/webp','image/svg+xml'].includes(file.type)) { error='Choose a PNG, JPEG, WebP or QR SVG image up to 10 MiB.'; return; }
    const url=URL.createObjectURL(file);
    try {
      const img=new Image(); img.src=url; await img.decode(); if(current!==epoch) return;
      if(img.naturalWidth*img.naturalHeight>32_000_000) throw new Error('image too large');
      const value=decoded(img,img.naturalWidth,img.naturalHeight);
      if(!value) error='No QR code found. Try a clear image containing the whole code.'; else accept(value);
    } catch { if(current===epoch) error='Could not read this image. Try a clear PNG or JPEG.'; }
    finally { URL.revokeObjectURL(url); }
  }
  onDestroy(stop);
</script>
<div class="qr-scanner">
  <div class="scanner-actions"><button type="button" class="secondary" disabled={starting} onclick={()=>running?stop():void start()}>{starting?'Opening camera…':running?'Stop camera':'Scan with camera'}</button><label class="secondary upload-qr">Upload QR image<input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml" onchange={image}/></label></div>
  {#if running}<video bind:this={video} muted playsinline aria-label="QR scanner camera"></video><p>Point the camera at a Najwa invitation.</p>{/if}
  {#if error}<p class="scan-error" role="alert">{error}</p>{/if}
</div>
<style>
 .scanner-actions{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.upload-qr{position:relative;display:inline-flex;align-items:center;cursor:pointer}.upload-qr input{position:absolute;inset:0;opacity:0;width:100%;cursor:pointer}.upload-qr:focus-within{outline:2px solid var(--accent);outline-offset:3px}video{display:block;width:100%;max-height:260px;object-fit:contain;background:#111;border-radius:8px}.qr-scanner p{font-size:12px;line-height:1.6;color:var(--muted)}.qr-scanner .scan-error{color:var(--warning)}
</style>
