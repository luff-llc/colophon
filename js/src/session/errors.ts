/** Errors the session layer raises itself. Engine errors are the glue's `AccountFault` (see `wasm.ts`). */

export type StorageReason = 'unavailable' | 'invalidPath' | 'conflict' | 'limitExceeded';
/** A record store failure. `unavailable` is never read as "empty". */
export class StorageError extends Error {
  constructor(readonly reason: StorageReason, message: string, readonly path?: string, options?: ErrorOptions) {
    super(message, options); this.name = 'StorageError';
  }
  static unavailable(why: string, cause?: unknown): StorageError { return new StorageError('unavailable', why, undefined, { cause }); }
  static invalidPath(path: string): StorageError { return new StorageError('invalidPath', `Invalid record path: ${path}`, path); }
  /** Immutable bytes already exist at the path and differ. */
  static conflict(path: string): StorageError { return new StorageError('conflict', `Immutable record conflict: ${path}`, path); }
  static limitExceeded(): StorageError { return new StorageError('limitExceeded', 'Storage limit exceeded'); }
}

export type SessionErrorCode = 'notReady' | 'staleRevision' | 'destinationChanged' | 'invalidCommand' | 'noHome' | 'ownerRequired' | 'insecureHome' | 'cancelled';
const sessionMessages: Record<SessionErrorCode, string> = {
  notReady: 'The library is not ready. Restore access and retry.',
  staleRevision: 'The library changed while this action was open. Review the current values and try again.',
  destinationChanged: 'The selected library or member changed. Start this action again.',
  invalidCommand: 'This command is invalid.',
  noHome: 'This account has no home. Without one there is no witness of time or order for your changes; add a home before relying on it.',
  ownerRequired: "This step needs the account owner's key.",
  insecureHome: 'A home must be reached over HTTPS. This one is not, so it was not used.',
  cancelled: 'The operation was cancelled.',
};
export class SessionError extends Error {
  constructor(readonly code: SessionErrorCode, options?: ErrorOptions) { super(sessionMessages[code], options); this.name = 'SessionError'; }
}

export type HomeTransportReason = 'offline' | 'invalidRequest' | 'responseTooLarge' | 'insecureEndpoint' | 'redirected' | 'timeout';
/** A transport failure: the request did not produce an answer the engine may judge. */
export class HomeTransportError extends Error {
  constructor(readonly reason: HomeTransportReason, message: string, readonly limit?: number, options?: ErrorOptions) {
    super(message, options); this.name = 'HomeTransportError';
  }
}

/**
 * A home's door refused a provisioning request (`ColophonSession.provisionRequest`): `status` is the HTTP status and
 * `code` the `result` it gave when valid (for a refused grant call, the core's code, such as `refused:revoked` or
 * `refused:outOfScope`; 403 is final, never retried on another path). `retryAfterSeconds` is its `Retry-After`.
 */
export class ProvisionRefusal extends Error {
  constructor(readonly status: number, readonly code: string | undefined, readonly retryAfterSeconds?: number) {
    super(`the home refused to provision: ${status}${code ? ` ${code}` : ''}`); this.name = 'ProvisionRefusal';
  }
}

export type KeyOutcome = 'cancelled' | 'presenceFailed' | 'unsupportedHere' | 'credentialMissing' | 'hardwareUnavailable' | 'noKey' | 'missingChallenge';
/** A host key failure, classified at its origin. Protocol verification errors still come from the core. */
export class KeyCustodyError extends Error {
  constructor(readonly outcome: KeyOutcome, message: string, options?: ErrorOptions) { super(message, options); this.name = 'KeyCustodyError'; }
  /** Classifies a browser failure by its `name`, never by a localized message. */
  static from(error: unknown): KeyCustodyError | SessionError {
    if (error instanceof KeyCustodyError || error instanceof SessionError) return error;
    const name = error instanceof Error ? error.name : '';
    const outcome: KeyOutcome = name === 'AbortError' ? 'cancelled'
      : name === 'NotAllowedError' || name === 'SecurityError' ? 'presenceFailed'
      : name === 'NotFoundError' ? 'credentialMissing'
      : name === 'NotSupportedError' ? 'unsupportedHere' : 'hardwareUnavailable';
    return new KeyCustodyError(outcome, error instanceof Error ? error.message : 'Key operation failed', { cause: error });
  }
}

export type BlobErrorCode = 'unpublished' | 'missing' | 'inaccessible' | 'invalid' | 'tooLarge' | 'digestMismatch';
export class BlobError extends Error {
  constructor(readonly code: BlobErrorCode, message: string) { super(message); this.name = 'BlobError'; }
}

/** Throws `SessionError('cancelled')` when `signal` is aborted. */
export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new SessionError('cancelled', { cause: signal.reason });
}

/**
 * `promise`, or a `SessionError('cancelled')` as soon as `signal` is aborted, whichever comes first: something that
 * never settles (a prompt nobody answers, a transport that ignores its signal) cannot hold the caller. If the promise
 * settles after the abort, `dispose` receives its value (to wipe a secret nobody will use).
 */
export function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined, dispose?: (value: T) => void): Promise<T> {
  if (!signal) return promise;
  return new Promise<T>((resolve, reject) => {
    let done = false;
    const onAbort = () => { if (done) return; done = true; reject(new SessionError('cancelled', { cause: signal.reason })); };
    if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      value => { signal.removeEventListener('abort', onAbort); if (done) { try { dispose?.(value); } catch { /* best effort */ } return; } done = true; resolve(value); },
      error => { signal.removeEventListener('abort', onAbort); if (done) return; done = true; reject(error as Error); },
    );
  });
}
