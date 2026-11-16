/**
 * Secret bytes the SDK owns and overwrites with zeros on `close`. PRF outputs, ECDH results, epoch shares, the
 * device-held sealed-state key and action entropy live in one until the one export call that takes them.
 *
 * What it cannot reach: a copy the browser made before it handed the bytes over (WebCrypto's and WebAuthn's own
 * buffers), a copy the JavaScript engine made while moving the array, and the copy into the wasm heap (the Rust side
 * overwrites that one through its zero-on-free allocator, and the three secret records are wiped by the call that
 * consumes them). `toString` and `toJSON` are redacted.
 */
export class SecretBytes {
  #bytes: Uint8Array | null;
  private constructor(bytes: Uint8Array) { this.#bytes = bytes; }
  /** Takes ownership of `bytes` (no copy): the caller must not keep using its own reference. */
  static adopt(bytes: Uint8Array): SecretBytes { return new SecretBytes(bytes); }
  static random(count: number): SecretBytes { return new SecretBytes(crypto.getRandomValues(new Uint8Array(count))); }
  get size(): number { return this.#bytes?.length ?? 0; }
  get closed(): boolean { return this.#bytes === null; }
  /** Lends the bytes for one call. They must not escape `body`. */
  lend<R>(body: (bytes: Uint8Array) => R): R {
    if (!this.#bytes) throw new Error('secret already wiped');
    return body(this.#bytes);
  }
  /** Overwrites the bytes. Idempotent. */
  close(): void { this.#bytes?.fill(0); this.#bytes = null; }
  toString(): string { return 'SecretBytes(redacted)'; }
  toJSON(): string { return 'SecretBytes(redacted)'; }
}

/** Runs `body` with `count` bytes of fresh entropy, wiped afterwards (refusals included). `body` is synchronous. */
export function withEntropy<R>(count: number, body: (entropy: Uint8Array) => R): R {
  const bytes = crypto.getRandomValues(new Uint8Array(count));
  try { return body(bytes); } finally { bytes.fill(0); }
}

/** Closes every secret in `list` (idempotent); for a path that never reached the export call. */
export function closeAll(list: readonly { secret: SecretBytes }[]): void { for (const item of list) item.secret.close(); }

/**
 * Builds one answer per item, in order. If any item fails (a provider throws, a prompt is cancelled), every secret
 * built so far is wiped before the failure propagates.
 */
export async function collectSecrets<I, A extends { secret: SecretBytes }>(items: readonly I[], make: (item: I) => Promise<A>): Promise<A[]> {
  const out: A[] = [];
  try {
    for (const item of items) out.push(await make(item));
    return out;
  } catch (error) {
    closeAll(out);
    throw error;
  }
}
