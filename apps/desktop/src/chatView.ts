import type { Message } from './messaging';

// The first page retains the store's normal sent-time order. During this open
// conversation, refresh existing rows in place and append new local arrivals.
// Row IDs are native 64-bit counters, so compare them without Number rounding.
export function liveMessagePage(previous: Message[], page: Message[], initialized: boolean): Message[] {
  const available = page.filter(m => m.expiresAt === null || m.expiresAt > Date.now());
  if (!initialized) return available;
  const current = new Map(available.map(m => [m.id, m]));
  const known = new Set(previous.map(m => m.id));
  const retained = previous.flatMap(m => current.has(m.id) ? [current.get(m.id)!] : []);
  const arrivals = available.filter(m => !known.has(m.id)).sort((a,b) => BigInt(a.id) < BigInt(b.id) ? -1 : BigInt(a.id) > BigInt(b.id) ? 1 : 0);
  return [...retained, ...arrivals];
}

export function messageDelivery(message: Message): {kind:'clock'|'single'|'double'|'failed';read:boolean;label:string;confirmation:string;description:string} {
  if (message.attachment) {
    const sent = message.attachment.depositedChunks ?? 0;
    return sent < message.attachment.chunks
      ? {kind:'clock',read:false,label:'File queued',confirmation:`File sending: ${sent} of ${message.attachment.chunks} parts deposited`,description:`${sent} of ${message.attachment.chunks} parts deposited. Keep Najwa unlocked until all parts reach the mailbox. Your contact can be offline.`}
      : {kind:'single',read:false,label:'File deposited',confirmation:'File deposited in mailbox',description:'All file parts are stored in the mailbox. Your contact can collect them later. This does not confirm that the file has been downloaded.'};
  }
  return ({
    queued:{kind:'clock',read:false,label:'Queued',confirmation:'Queued on this device',description:'Saved on this computer. Keep Najwa unlocked until the message reaches the mailbox. Your contact can be offline.'},
    retrying:{kind:'clock',read:false,label:'Retrying',confirmation:'Retrying mailbox deposit',description:'Saved on this computer. Temporary delivery failures retry automatically while Najwa is unlocked.'},
    deposited:{kind:'single',read:false,label:'Deposited',confirmation:'Deposited in mailbox',description:'Stored in the mailbox. Your contact can receive it later, even after you close Najwa.'},
    delivered:{kind:'double',read:false,label:'Delivered',confirmation:'Received by contact',description:'Your contact received this message.'},
    read:{kind:'double',read:true,label:'Read',confirmation:'Read by contact',description:'Your contact marked this message read.'},
    failed:{kind:'failed',read:false,label:'Not sent',confirmation:'Not sent',description:'Delivery could not be completed. Open the conversation status for details.'}
  } as const)[message.status];
}
