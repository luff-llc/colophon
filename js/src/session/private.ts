import { SecretBytes } from './secrets.js';
import { StorageError } from './errors.js';

/**
 * Small private files of one device: the session journal and the engine's sealed saved state. Never synchronised,
 * never shared. `write` replaces a file atomically.
 */
export interface PrivateStore {
  read(name: string): Promise<Uint8Array | undefined>;
  write(name: string, bytes: Uint8Array): Promise<void>;
  remove(name: string): Promise<void>;
}

export class MemoryPrivateStore implements PrivateStore {
  private readonly files = new Map<string, Uint8Array>();
  async read(name: string): Promise<Uint8Array | undefined> { return this.files.get(name)?.slice(); }
  async write(name: string, bytes: Uint8Array): Promise<void> { this.files.set(name, bytes.slice()); }
  async remove(name: string): Promise<void> { this.files.delete(name); }
}

/**
 * Where the 32-byte device-held key that seals saved state lives (spec §17.2). A cache key, not an identity: losing it
 * makes the engine replay the history. It must never leave this device. In a browser: `WebCryptoDeviceSecrets`.
 */
export interface DeviceSecretStore {
  /** The key for `account`, created on first use. The caller closes the returned copy. */
  key(account: string): Promise<SecretBytes>;
  remove(account: string): Promise<void>;
}

/** A process-lifetime store for tests and previews. */
export class MemoryDeviceSecrets implements DeviceSecretStore {
  private readonly keys = new Map<string, Uint8Array>();
  async key(account: string): Promise<SecretBytes> {
    let key = this.keys.get(account);
    if (!key) { key = crypto.getRandomValues(new Uint8Array(32)); this.keys.set(account, key); }
    return SecretBytes.adopt(key.slice());
  }
  async remove(account: string): Promise<void> { this.keys.get(account)?.fill(0); this.keys.delete(account); }
}

const text = new TextEncoder();
const untext = new TextDecoder('utf-8', { fatal: true });

/** Small durable state: which account, whether the person left, what was shown. u64 values are decimal strings. */
export class SessionJournal {
  account: string | undefined;
  left = false;
  shownSeq = 0n;
  shownTransitions: string[] = [];
  /** Activations above `shownSeq` the person marked seen one by one. */
  seenActivations = new Set<bigint>();
  /** Homes that hold this host's delivery routes (true), or said they offer no registration (false). */
  routes = new Map<string, boolean>();
  /** The change of each transition this device signed, by digest, so a dead one can be signed again. */
  signedChanges = new Map<string, string>();
  /** Removal follow-ups the person answered, by activation seq. */
  answeredRemovals = new Set<bigint>();

  encode(): Uint8Array {
    return text.encode(JSON.stringify({
      account: this.account ?? null, left: this.left, shownSeq: this.shownSeq.toString(), shownTransitions: this.shownTransitions,
      seenActivations: [...this.seenActivations].map(String), routes: Object.fromEntries(this.routes),
      signedChanges: Object.fromEntries(this.signedChanges), answeredRemovals: [...this.answeredRemovals].map(String),
    }));
  }

  static decode(bytes: Uint8Array): SessionJournal {
    let m: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(untext.decode(bytes));
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
      m = parsed as Record<string, unknown>;
    } catch (error) {
      throw StorageError.unavailable('the session journal is not readable', error);
    }
    const strings = (v: unknown): string[] => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
    const seqs = (v: unknown): bigint[] => strings(v).filter(s => /^[0-9]{1,20}$/.test(s)).map(BigInt);
    const entries = (v: unknown): [string, unknown][] => typeof v === 'object' && v !== null && !Array.isArray(v) ? Object.entries(v) : [];
    const j = new SessionJournal();
    j.account = typeof m.account === 'string' ? m.account : undefined;
    j.left = m.left === true;
    j.shownSeq = typeof m.shownSeq === 'string' && /^[0-9]{1,20}$/.test(m.shownSeq) ? BigInt(m.shownSeq) : 0n;
    j.shownTransitions = strings(m.shownTransitions);
    j.seenActivations = new Set(seqs(m.seenActivations));
    j.routes = new Map(entries(m.routes).filter((e): e is [string, boolean] => typeof e[1] === 'boolean'));
    j.signedChanges = new Map(entries(m.signedChanges).filter((e): e is [string, string] => typeof e[1] === 'string'));
    j.answeredRemovals = new Set(seqs(m.answeredRemovals));
    return j;
  }
}

/** The sealed state an engine saves between sessions, as plain values. */
export interface SavedStateData { verifier: Uint8Array; checkpoint: Uint8Array; parts: { namespace: string; bytes: Uint8Array }[] }

/**
 * The engine's sealed saved state per account, in the private store. It is sealed under the device key by the core; a
 * file that fails its seal is ignored by the engine (the history replays), and a file this code cannot parse is
 * ignored here.
 */
export class SavedStateCache {
  constructor(private readonly store: PrivateStore) {}
  private name(account: string): string {
    if (!/^[0-9a-f]{64}$/.test(account)) throw new Error('an account ID is 64 hex');
    return `saved-${account}.bin`;
  }
  async load(account: string): Promise<SavedStateData | undefined> {
    try {
      const bytes = await this.store.read(this.name(account));
      return bytes ? decodeSaved(bytes) : undefined;
    } catch { return undefined; }
  }
  async save(account: string, state: SavedStateData): Promise<void> { await this.store.write(this.name(account), encodeSaved(state)); }
}

export function encodeSaved(s: SavedStateData): Uint8Array {
  const names = s.parts.map(p => text.encode(p.namespace));
  let size = 4 + 4 + s.verifier.length + 4 + s.checkpoint.length + 4;
  s.parts.forEach((p, i) => { size += 4 + names[i]!.length + 4 + p.bytes.length; });
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  const int = (n: number) => { view.setUint32(at, n); at += 4; };
  const field = (b: Uint8Array) => { int(b.length); out.set(b, at); at += b.length; };
  int(1); field(s.verifier); field(s.checkpoint); int(s.parts.length);
  s.parts.forEach((p, i) => { field(names[i]!); field(p.bytes); });
  return out;
}

export function decodeSaved(bytes: Uint8Array): SavedStateData | undefined {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const int = (): number => { if (at + 4 > bytes.length) throw new Error('short'); const n = view.getUint32(at); at += 4; return n; };
  const field = (): Uint8Array => { const n = int(); if (at + n > bytes.length) throw new Error('short'); const b = bytes.slice(at, at + n); at += n; return b; };
  if (int() !== 1) return undefined;
  const verifier = field(); const checkpoint = field();
  const count = int();
  if (count > 4096) throw new Error('too many parts');
  const parts: SavedStateData['parts'] = [];
  for (let i = 0; i < count; i++) { const namespace = untext.decode(field()); parts.push({ namespace, bytes: field() }); }
  return { verifier, checkpoint, parts };
}
