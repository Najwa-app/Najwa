// Vite aliases only the isolated local-demo build to this adapter.
export interface Bootstrap {
  token: string; session: string; username: string; fingerprint: string;
}
let bootstrap: Promise<Bootstrap> | undefined;
export function connect(): Promise<Bootstrap> {
  return bootstrap ??= fetch('/api/bootstrap', { credentials:'omit', redirect:'error', cache:'no-store' }).then(async response => {
    if (!response.ok) throw { code:'ipc_failed' };
    return await response.json() as Bootstrap;
  });
}
export async function invoke<T>(command: string, args: Record<string,unknown> = {}): Promise<T> {
  const connection = await connect();
  const response = await fetch('/api/invoke', {
    method:'POST', credentials:'omit', redirect:'error', cache:'no-store',
    headers:{'Content-Type':'application/json','X-Najwa-Demo':connection.token},
    body:JSON.stringify({command,args})
  });
  if (!response.ok) throw { code:'ipc_failed' };
  const value = await response.json();
  if (value.error) throw {code:value.error};
  return value.ok as T;
}
