/** Portable failures of a host key operation. */
export type KeyOutcome = 'cancelled' | 'presenceFailed' | 'unsupportedHere' | 'credentialMissing' | 'hardwareUnavailable';

/** Host key failure; protocol verification errors still come from the core. */
export class KeyProviderError extends Error {
  constructor(readonly outcome: KeyOutcome, message: string, options?: ErrorOptions) {
    super(message, options); this.name = 'KeyProviderError';
  }
}

/** Translate browser failures without relying on localized error messages. */
export function keyProviderError(error: unknown): KeyProviderError {
  if (error instanceof KeyProviderError) return error;
  const name = error instanceof Error ? error.name : '';
  const outcome: KeyOutcome = name === 'AbortError' ? 'cancelled'
    : name === 'NotAllowedError' || name === 'SecurityError' ? 'presenceFailed'
    : name === 'NotFoundError' ? 'credentialMissing'
    : name === 'NotSupportedError' ? 'unsupportedHere' : 'hardwareUnavailable';
  return new KeyProviderError(outcome, error instanceof Error ? error.message : 'Key operation failed', { cause: error });
}
