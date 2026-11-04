// Only the local web build aliases the shared messenger to this adapter.
import {streamUpload,transferControl} from './transfers';
let connection: Promise<{token:string;session:string}> | undefined;
let connectionGrant = '';
export function connect() {
  const grant = location.hash.slice(1);
  const headers = /^[a-f0-9]{64}$/.test(grant) ? {'X-Najwa-Launch':grant} : undefined;
  if (connection && (!headers || grant === connectionGrant)) return connection;
  connectionGrant = headers ? grant : '';
  const attempt = fetch('/api/bootstrap', {cache:'no-store',credentials:'same-origin',redirect:'error',headers}).then(async response => {
    if (!response.ok) throw {code:response.status === 403 ? 'launch_required' : 'service_unavailable'};
    const value = await response.json();
    if (!/^[a-f0-9]{64}$/.test(value.token) || !/^[a-f0-9]{32}$/.test(value.session)) throw {code:'ipc_failed'};
    if (grant && location.hash.slice(1) === grant) history.replaceState(null,'',location.pathname+location.search);
    return value as {token:string;session:string};
  }).catch(error => {
    if (connection === attempt) connection = undefined;
    throw error?.code ? error : {code:'service_unavailable'};
  });
  connection = attempt;
  return attempt;
}
export async function api<T>(path:string, body?:unknown): Promise<T> {
  for (let retry = 0; retry < 2; retry++) {
    const attempt = connect();
    const bootstrap = await attempt;
    const response = await fetch(path, {
      method:body === undefined ? 'GET' : 'POST', cache:'no-store',credentials:'omit',redirect:'error',
      headers:{'X-Najwa-Session':bootstrap.token, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
      ...(body === undefined ? {} : {body:JSON.stringify(body)})
    }).catch(() => {
      if (connection === attempt) connection = undefined;
      throw {code:'service_unavailable'};
    });
    if (!response.ok) {
      if (connection === attempt) connection = undefined;
      // Only reads can resume automatically. Never replay a passphrase or mutation.
      if (response.status === 403 && body === undefined && retry === 0) continue;
      throw {code:response.status === 403 ? 'service_restarted' : 'service_unavailable'};
    }
    const result = await response.json();
    if (result.error) throw result.error;
    return result.ok as T;
  }
  throw {code:'service_restarted'};
}
export function invoke<T>(command:string, args:Record<string,unknown> = {}) {
  if (command === 'attachment_upload') return upload<T>(args);
  if (command === 'attachment_transfers') return transferControl<T>(args,{kind:'list',contact:args.contact});
  if (command === 'attachment_cancel') return transferControl<T>(args,{kind:'cancel',contact:args.contact,id:args.id});
  if (command === 'attachment_download') return transferControl<T>(args,{kind:'download',contact:args.contact,message:args.message});
  return api<T>('/api/invoke',{command,args});
}
async function upload<T>(args:Record<string,unknown>): Promise<T> {
  return streamUpload(args) as Promise<T>;
}
export async function lockOnExit(session:string, generation:number) {
  const bootstrap = await connect();
  await fetch('/api/lock',{method:'POST',credentials:'omit',redirect:'error',keepalive:true,
    headers:{'Content-Type':'application/json','X-Najwa-Session':bootstrap.token},body:JSON.stringify({session,generation})});
}
