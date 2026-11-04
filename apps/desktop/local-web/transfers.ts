import {api,connect} from './bridge';
const PART=1024*1024;
export interface Transfer {id:string;filename:string;size:number;uploaded:number;phase:'uploading'|'preparing'|'queued'|'failed';parts:number[];error:string|null}
interface Status {session:string;generation:number;phase:string;fingerprint:string|null}
export async function transferControl<T>(identity:Record<string,unknown>,action:Record<string,unknown>):Promise<T> {
  return api<T>('/api/transfers',{session:identity.session,generation:identity.generation,action});
}
export async function streamUpload(args:Record<string,unknown>):Promise<void> {
  const {file,contact,signal,onprogress}=args as {file:File;contact:string;signal:AbortSignal;onprogress?:(phase:string,bytes:number,total:number)=>void};
  if(!file.size || file.size>256*PART) throw {code:'file_too_large'};
  const check=()=>{if(signal?.aborted)throw {code:'cancelled'};};
  const first=await api<Status>('/api/status');
  if(first.session!==args.session || first.generation!==args.generation || first.phase!=='unlocked')throw {code:'stale_operation'};
  const current=async()=>{const id=await api<Status>('/api/status');if(id.phase!=='unlocked')throw {code:'locked'};if(id.fingerprint!==first.fingerprint)throw {code:'stale_operation'};return id;};
  const retry=async<T>(work:()=>Promise<T>):Promise<T>=>{
    let attempts=0;
    for(;;){check();try{return await work();}catch(error){
      const code=(error as {code?:string})?.code;
      if(!['service_unavailable','service_restarted','busy'].includes(code ?? ''))throw error;
      onprogress?.('Connection interrupted — retrying automatically',0,file.size);
      await new Promise<void>((resolve,reject)=>{const abort=()=>{clearTimeout(timer);reject({code:'cancelled'});};const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},Math.min(1000*2**attempts++,10000));signal?.addEventListener('abort',abort,{once:true});});
    }}
  };
  // A bounded per-part digest manifest commits to every byte of the selected
  // file. Resume cannot accidentally combine similarly named different files.
  const hashes:string[]=[];
  for(let offset=0;offset<file.size;offset+=PART){check();const bytes=await file.slice(offset,offset+PART).arrayBuffer();const digest=await crypto.subtle.digest('SHA-256',bytes);hashes.push(Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join(''));onprogress?.('Checking file',Math.min(offset+PART,file.size),file.size);}
  const transfer=await retry(async()=>transferControl<Transfer>(await current() as unknown as Record<string,unknown>,{kind:'begin',contact,manifest:{name:file.name,size:file.size,hashes}}));
  if(transfer.phase!=='uploading')return;
  const present=new Set(transfer.parts);let uploaded=transfer.uploaded;
  onprogress?.('Uploading to encrypted storage',uploaded,file.size);
  for(let part=0;part<hashes.length;part++){
    check();if(present.has(part))continue;
    const body=file.slice(part*PART,Math.min((part+1)*PART,file.size));
    await retry(async()=>{
      const id=await current();const bootstrap=await connect();
      let response:Response;
      try {response=await fetch(`/api/transfer-part/${transfer.id}/${part}`,{method:'POST',credentials:'omit',redirect:'error',cache:'no-store',signal,
        headers:{'X-Najwa-Session':bootstrap.token,'X-Najwa-Identity':id.session,'X-Najwa-Generation':String(id.generation),'Content-Type':'application/octet-stream'},body});}
      catch {check();throw {code:'service_unavailable'};}
      if(!response.ok) {if(response.status===403){await api('/api/status');throw {code:'service_restarted'};}throw {code:response.status===413?'file_too_large':'service_unavailable'};}
      const result=await response.json();if(result.error)throw result.error;
    });
    uploaded+=body.size;onprogress?.('Uploading to encrypted storage',uploaded,file.size);
  }
  await retry(async()=>transferControl(await current() as unknown as Record<string,unknown>,{kind:'finish',id:transfer.id}));
  onprogress?.('File saved — preparing secure transfer',file.size,file.size);
}
