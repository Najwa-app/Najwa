export interface IdentityStatus {
  enabled: boolean;
  session: string;
  generation: number;
  phase: 'absent' | 'locked' | 'unlocked' | 'locking' | 'wiping' | 'erased' | 'error' | 'unavailable';
  hardware: 'required' | 'protected' | 'unavailable' | 'unverified';
  fingerprint: string | null;
  recoveryAvailable: boolean;
  recoveryPending: boolean;
  prekeyRefreshRequired: boolean;
  unavailableReason: string | null;
}
export function identityError(error: unknown): string {
  const failure = error && typeof error === 'object' ? error as { code?: string; retryAfterMs?: number } : {};
  if (failure.code === 'rate_limited') {
    const delay = typeof failure.retryAfterMs === 'number' && Number.isFinite(failure.retryAfterMs) ? Math.min(Math.max(failure.retryAfterMs, 0), 86_400_000) : 1000;
    return `Too many attempts. Wait ${Math.ceil(delay / 1000)} seconds before trying again.`;
  }
  const messages: Record<string, string> = {
    authentication_failed: 'Unable to unlock this identity.',
    locked_out: 'This profile is locked out. Use its recovery kit to restore access.',
    hardware_unavailable: 'The required hardware key is unavailable. No software fallback is allowed.',
    invalid_password: 'Use at least 12 characters for a new passphrase and enter an identical confirmation. Inputs are limited to 1024 UTF-8 bytes.',
    recovery_invalid: 'The recovery words could not unlock this profile’s encrypted recovery record.',
    recovery_missing: 'This profile has no readable encrypted recovery record.',
    stale_operation: 'The identity state changed. Check its current state and try again.',
    wipe_incomplete: 'Local erasure is incomplete. Unlock and creation are blocked. Retry Erase local profile to finish cleanup.',
    busy: 'Another native identity operation is still running.',
    storage_unavailable: 'The local profile could not be read or saved.',
    unavailable: 'Identity integration is unavailable in this build.',
    ipc_failed: 'The native identity state could not be confirmed.'
  };
  return messages[failure.code ?? ''] ?? 'The native operation failed. Check the current identity state.';
}
