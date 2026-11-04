import { invoke } from 'najwa:bridge';
import type { IdentityStatus } from './identity';

export interface NetworkStatus {
  enabled: boolean; unlocked: boolean; connection: 'unavailable' | 'locked' | 'connecting' | 'connected' | 'offline';
  coverRunning: boolean; mailboxes: string[]; pausedMailboxes: string[];
  mailboxDetails?: { onion: string; registered: boolean; primary: boolean }[];
  deliveryMode?: 'responsive' | 'privacy';
  pendingDeposits?: number | null;
  retryingMailboxes?: string[];
}
export interface Contact {
  id: string; name: string; verified: boolean; blocked: boolean; unread: number; ready: boolean; safetyNumber: string;
  timerSeconds: number;
  timerPending: boolean;
  setupState?: 'queued' | 'waiting' | 'unconfirmed' | 'expired' | 'failed' | 'ready';
  setupExpiresAt?: number | null;
  preview?: string | null;
  lastMessageAt?: number | null;
  repairStatus?: 'repairing' | 'failed' | null;
}
export interface Message {
  // Native message timestamps are Unix seconds; expiry deadlines are Unix milliseconds.
  id: string; msgId: string; text: string; outgoing: boolean; timestamp: number;
  status: 'queued' | 'deposited' | 'delivered' | 'read' | 'retrying' | 'failed'; expiresAt: number | null;
  replyTo?: string | null;
  attachment?: {filename:string;size:number;chunks:number;availableChunks:number;depositedChunks?:number;complete:boolean;supported:boolean;failed?:boolean} | null;
}
export function contactSetupStatus(contact: Contact): {label:string;description:string} {
  return ({
    queued:{label:'Contact request queued',description:'Your introduction is saved on this computer. It sends in the background; keep Najwa unlocked until it reaches the mailbox. The other person can be offline.'},
    waiting:{label:'Contact request deposited',description:'Your introduction is deposited in the mailbox. You can close Najwa now. The other person can collect it later when they open and unlock their app; setup continues when you next return.'},
    unconfirmed:{label:'No reply yet',description:'The introduction’s collection window has ended. The other person may not have collected it. This contact remains unconfirmed; other conversations are available.'},
    expired:{label:'Contact request expired',description:'The introduction expired before delivery was confirmed. Setup retries have stopped for this contact; your other conversations are available.'},
    failed:{label:'Contact setup failed',description:'The introduction could not be sent. This contact remains unconfirmed; your other conversations are available.'},
    ready:{label:'Connected',description:'Your encrypted conversation is ready.'}
  } as Record<string,{label:string;description:string}>)[contact.ready ? 'ready' : contact.setupState ?? '']
    ?? {label:'Contact setup pending',description:'Setup continues when each person next opens and unlocks Najwa. You can use other conversations or return later.'};
}
export const unavailableNetwork: NetworkStatus = {
  enabled: false, unlocked: false, connection: 'unavailable', coverRunning: false, mailboxes: [], pausedMailboxes: []
};
// A saved mailbox address does not prove a live connection or successful delivery.
export function mailboxSummary(network: NetworkStatus): string {
  if (!network.mailboxes.length) return 'Mailbox setup needed';
  if (network.retryingMailboxes?.length) return 'Retrying mailbox connection';
  const incomplete = network.mailboxDetails?.filter(m => !m.registered).length ?? 0;
  if (incomplete) {
    const ready = network.mailboxes.length - incomplete;
    return ready ? `${ready} ${ready === 1 ? 'mailbox' : 'mailboxes'} configured · ${incomplete} setup incomplete` : 'Mailbox registration needed';
  }
  return 'Mailbox configured';
}
export async function messagingStatus(): Promise<NetworkStatus> {
  const value = await invoke<NetworkStatus>('messaging_status');
  if (!value || typeof value.enabled !== 'boolean' || typeof value.unlocked !== 'boolean'
    || typeof value.coverRunning !== 'boolean' || !Array.isArray(value.mailboxes)
    || !value.mailboxes.every(v => typeof v === 'string' && /^[a-z2-7]{56}\.onion$/.test(v))
    || !Array.isArray(value.pausedMailboxes)
    || !value.pausedMailboxes.every(v => typeof v === 'string' && /^[a-z2-7]{56}\.onion$/.test(v))
    || (value.retryingMailboxes !== undefined && (!Array.isArray(value.retryingMailboxes)
      || !value.retryingMailboxes.every(v => typeof v === 'string' && /^[a-z2-7]{56}\.onion$/.test(v))))
    || (value.deliveryMode !== undefined && !['responsive', 'privacy'].includes(value.deliveryMode))
    || (value.pendingDeposits !== undefined && value.pendingDeposits !== null
      && (!Number.isSafeInteger(value.pendingDeposits) || value.pendingDeposits < 0))
    || (value.mailboxDetails !== undefined && (!Array.isArray(value.mailboxDetails) || value.mailboxDetails.some(m => !m
      || !value.mailboxes.includes(m.onion) || typeof m.registered !== 'boolean' || typeof m.primary !== 'boolean')))
    || !['unavailable', 'locked', 'connecting', 'connected', 'offline'].includes(value.connection)) throw { code: 'ipc_failed' };
  return value;
}
type Operation = { kind: 'contacts' | 'sync' | 'reconnect' }
  | { kind: 'messages'; contact: string; before?: [number,string]; query?: string }
  | { kind: 'displayed'; contact: string; ids: string[] }
  | { kind: 'send'; contact: string; text: string; reply_to?: string }
  | { kind: 'manage_contact'; contact: string; action: 'block'|'unblock'|'delete'|'rename'; name?: string }
  | { kind: 'invitation_details'; invitation: string }
  | { kind: 'download_file'; contact:string; message:string }
  | { kind: 'set_timer'; contact: string; seconds: number }
  | { kind: 'add_mailbox'; onion: string }
  | { kind: 'select_mailbox'; onion: string }
  | { kind: 'forget_mailbox'; onion: string }
  | { kind: 'set_delivery_mode'; mode: 'responsive' | 'privacy' }
  | { kind: 'retry_mailbox'; onion: string }
  | { kind: 'invitation'; name: string }
  | { kind: 'accept_invitation'; invitation: string; name: string; confirmed?: boolean }
  | { kind: 'verify'; contact: string; safety: string; verified: boolean };
export async function messagingRequest<T>(identity: IdentityStatus, operation: Operation): Promise<T> {
  if (identity.phase !== 'unlocked') throw { code: 'locked' };
  // Background receive can own the native network guard when a user clicks.
  // Busy means admission was refused before setup started, so retry that same
  // intent briefly. Keep the original epoch even if the identity prop changes.
  const payload = { request: { session: identity.session, generation: identity.generation, operation } };
  const waitForNetwork = ['add_mailbox','invitation'].includes(operation.kind);
  const deadline = performance.now() + 60_000;
  for (;;) {
    try { return await invoke<T>('messaging_request', payload); }
    catch (failure) {
      if (!waitForNetwork || (failure as {code?:string})?.code !== 'busy' || performance.now() >= deadline) throw failure;
      await new Promise(resolve => setTimeout(resolve, 250));
    }
  }
}
export function checkedContacts(value: Contact[]): Contact[] {
  if (!Array.isArray(value) || value.some(c => !c || !/^[1-9][0-9]{0,18}$/.test(c.id)
    || typeof c.name !== 'string' || c.name.length > 128 || typeof c.verified !== 'boolean'
    || typeof c.blocked !== 'boolean' || typeof c.ready !== 'boolean' || !Number.isSafeInteger(c.unread)
    || c.unread < 0 || typeof c.timerPending !== 'boolean' || !Number.isInteger(c.timerSeconds) || c.timerSeconds < 0 || c.timerSeconds > 4294967295
    || (c.setupState !== undefined && !['queued','waiting','unconfirmed','expired','failed','ready'].includes(c.setupState))
    || (c.setupExpiresAt !== undefined && c.setupExpiresAt !== null && (!Number.isSafeInteger(c.setupExpiresAt) || c.setupExpiresAt < 0 || c.setupExpiresAt > 8640000000000))
    || (c.preview != null && (typeof c.preview !== 'string' || c.preview.length > 512))
    || (c.lastMessageAt != null && (!Number.isSafeInteger(c.lastMessageAt) || c.lastMessageAt < 0 || c.lastMessageAt > 8640000000000))
    || (c.repairStatus != null && !['repairing','failed'].includes(c.repairStatus))
    || (c.timerSeconds > 0 && c.timerSeconds < 30)
    || !/^[a-f0-9]{4}( [a-f0-9]{4}){7}$/.test(c.safetyNumber))) throw { code: 'ipc_failed' };
  return value;
}
export function checkedMessages(value: Message[]): Message[] {
  if (!Array.isArray(value) || value.length > 200 || value.some(m => !m || !/^[1-9][0-9]{0,18}$/.test(m.id)
    || !/^[a-f0-9]{32}$/.test(m.msgId) || typeof m.text !== 'string' || typeof m.outgoing !== 'boolean'
    || (m.replyTo != null && !/^[a-f0-9]{32}$/.test(m.replyTo))
    || (m.attachment != null && (typeof m.attachment.filename !== 'string' || m.attachment.filename.length > 255
      || !Number.isSafeInteger(m.attachment.size) || m.attachment.size < 0 || m.attachment.size > 268435456
      || !Number.isInteger(m.attachment.chunks) || m.attachment.chunks < 0
      || !Number.isInteger(m.attachment.availableChunks) || m.attachment.availableChunks < 0 || m.attachment.availableChunks > m.attachment.chunks
      || typeof m.attachment.complete !== 'boolean' || typeof m.attachment.supported !== 'boolean'
      || (m.attachment.failed != null && typeof m.attachment.failed !== 'boolean')))
    || !Number.isSafeInteger(m.timestamp) || m.timestamp < 0 || m.timestamp > 8640000000000
    || (m.expiresAt !== null && (!Number.isSafeInteger(m.expiresAt) || m.expiresAt < 0))
    || !['queued','deposited','delivered','read','retrying','failed'].includes(m.status))) throw { code: 'ipc_failed' };
  return value.reverse();
}
export function messagingError(error: unknown): string {
  const code = error && typeof error === 'object' ? (error as { code?: string }).code : '';
  return ({ busy: 'A network operation is running. It may take a few minutes over Tor.',
    contact_blocked:'This contact is blocked. Unblock them in Contact details to send again.', contact_missing:'This contact has been removed.',
    file_too_large:'Choose a nonempty file of up to 256 MB.', unsupported_file:'This file type could not be safely prepared. Try a supported image, PDF, document, audio or video file.',
    cancelled:'Upload paused. Choose the same file to resume saved parts.',
    file_timer_unsupported:'Turn off disappearing messages before sending a file in this preview.',
    file_preparing:'Wait for the queued file to finish preparing before turning on disappearing messages.',
    file_unavailable:'This file is still arriving or is no longer available. Najwa keeps receiving in the background.', invalid_file:'File integrity could not be confirmed. The download was refused.',
    qr_too_large:'This invitation is too large for a QR code. Share the invitation link instead.',
    invalid_timer: 'Choose Off or a whole number of seconds of at least 30.',
    timer_pending: 'Your contact has not acknowledged the timer update yet. Sending will resume when it arrives.',
    not_connected: 'Tor is not connected yet.', mailbox_required: 'Add your mailbox in Settings first.',
    invalid_mailbox: 'Enter a complete Tor v3 .onion hostname.', registration_failed: 'Mailbox registration failed. Retry uses the saved capability pair.',
    mailbox_limit: 'You can add up to eight mailboxes.', mailbox_unregistered: 'Finish registering this mailbox before making it primary.',
    mailbox_in_use: 'This mailbox is registered or has contact routes. Only incomplete, unused setup can be removed.',
    registration_transport: 'The registration request could not reach the mailbox through Tor. Retry when the mailbox is reachable.',
    registration_pow: 'Registration proof-of-work could not finish before its deadline. Retry to request a fresh challenge.',
    registration_limited: 'The mailbox deferred registration. Wait briefly, then retry with a fresh proof-of-work challenge.',
    registration_conflict: 'The mailbox rejected conflicting registration details. Retrying unchanged details will not resolve this.',
    registration_server: 'The mailbox server could not complete registration. Try again when the server is available.',
    registration_rejected: 'The mailbox rejected the registration request. Check that the address belongs to a Najwa mailbox, then retry.',
    invitation_expiring: 'This invitation expired or has too little time left after setup. Generate a fresh invitation.',
    mailbox_unavailable: 'This contact has no usable delivery route. Check the mailbox details in Settings.',
    mailbox_not_paused: 'This mailbox is no longer paused. Check synchronization before trying again.',
    contact_pending: 'This contact is not ready yet. Setup continues when the other person returns. You can use your other conversations.',
    invalid_invitation: 'This invitation is invalid, expired, or could not be accepted.',
    contact_limit_confirm: 'Adding many contacts in a short time can make you easier to identify. You added 10 or more in the last 24 hours.',
    contact_exists: 'This identity is already a contact.', self_contact: 'This invitation belongs to your own identity.',
    invalid_name: 'Enter a name of at most 128 UTF-8 bytes.', invalid_message: 'Enter a nonempty message of at most 16,000 UTF-8 bytes.',
    sync_failed: 'Synchronization failed. Stored messages remain available; queued work will retry.',
    timeout: 'The network operation timed out. Check synchronization before trying again.',
    stale_operation: 'The identity changed. This result was discarded.', locked: 'Unlock your identity to continue.',
    storage_unavailable: 'The encrypted message store could not be read or saved.', ipc_failed: 'The native messaging response could not be confirmed.'
  } as Record<string,string>)[code ?? ''] ?? 'The messaging operation failed. Check the connection and try again.';
}
