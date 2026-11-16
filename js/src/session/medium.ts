import { StorageError } from './errors.js';

/** A path the medium holds and its content-version token (none: no cheap version). */
export interface MediumEntry { path: string; version?: string }
/** Exact bytes to store at a path. */
export interface MediumWrite { path: string; bytes: Uint8Array }

/**
 * Where an account's records live: the host's record store of docs/bindings-05.md.
 *
 * Reads are **synchronous**: the engine's `JsSource` callbacks need the bytes at once, and a `Promise` returned to the
 * engine is a `Host` error. A browser medium therefore reads ahead (`IndexedDBMedium` keeps what it stores in memory);
 * a file medium reads the disk. `write` is asynchronous and all-or-none: every write of the batch is stored, in order,
 * or none is, across a failure or a kill at any point. A medium never calls into the engine.
 */
export interface RecordMedium {
  /** Every path held, with versions, in one batch. A listing that cannot be completed throws: an error is never an empty store. */
  listing(): MediumEntry[];
  /** The exact bytes at `path`. Missing or unreadable throws `StorageError('unavailable')`. */
  read(path: string): Uint8Array;
  /** A blob chunk's ciphertext; empty means "not held here" (the engine fetches it from a home). */
  readBlob(path: string): Uint8Array;
  /**
   * Stores every write, in order, or none. Exact duplicates are idempotent; different bytes at an existing path are
   * `StorageError('conflict')` except at a replaceable path (`state/`, `heads/`).
   */
  write(writes: readonly MediumWrite[]): Promise<void>;
  /** Wake-up hints when something changes (this medium's own writes included). A hint carries nothing: list again. */
  changes(listener: () => void): () => void;
  close?(): void;
}

const encoder = new TextEncoder();

export const RecordPaths = {
  /** The largest stored object (docs/bindings-05.md §5: a request or entry blob is 40 MiB). */
  maximumBytes: 40 * 1024 * 1024,
  /** A relative path of at most 512 bytes, in components that are neither empty nor hidden. */
  validate(path: string): void {
    const bytes = encoder.encode(path);
    if (bytes.length === 0 || bytes.length > 512 || bytes.includes(0) || bytes.includes(92) || bytes[0] === 47 || bytes[bytes.length - 1] === 47) {
      throw StorageError.invalidPath(path);
    }
    for (const part of path.split('/')) {
      if (part.length === 0 || encoder.encode(part).length > 255 || part.startsWith('.')) throw StorageError.invalidPath(path);
    }
  },
  /** Live slots and head marks are replaced by newer bytes; everything else is immutable. */
  isReplaceable(path: string): boolean { return path.startsWith('state/') || path.startsWith('heads/'); },
  isBlob(path: string): boolean { return path.startsWith('blobs/'); },
};

export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Checks a batch against what is held and returns the writes that change something. It throws before anything is
 * stored, so a medium that applies the result in one atomic step is all-or-none. A path written twice in one batch is
 * judged against the batch's own earlier write.
 */
export function planBatch(writes: readonly MediumWrite[], held: (path: string) => Uint8Array | undefined): MediumWrite[] {
  const staged = new Map<string, Uint8Array>();
  for (const write of writes) {
    RecordPaths.validate(write.path);
    if (write.bytes.length > RecordPaths.maximumBytes) throw StorageError.limitExceeded();
    const old = staged.get(write.path) ?? held(write.path);
    if (old && sameBytes(old, write.bytes)) continue;
    if (old && !RecordPaths.isReplaceable(write.path)) throw StorageError.conflict(write.path);
    staged.set(write.path, write.bytes.slice());
  }
  return [...staged].map(([path, bytes]) => ({ path, bytes }));
}

/** Listener bookkeeping shared by the media. */
export class ChangeHints {
  private readonly listeners = new Set<() => void>();
  add(listener: () => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  emit(): void { for (const listener of [...this.listeners]) { try { listener(); } catch { /* a listener's failure is its own */ } } }
}

/** An in-memory medium for tests and previews, with the all-or-none contract and fault injection. */
export class MemoryMedium implements RecordMedium {
  private readonly files = new Map<string, Uint8Array>();
  private readonly versions = new Map<string, number>();
  private generation = 0;
  private readonly hints = new ChangeHints();
  /** Test hook: the next `write` fails with this error, storing nothing. */
  failNextWrite: Error | undefined;

  constructor(files?: Iterable<readonly [string, Uint8Array]>) {
    for (const [path, bytes] of files ?? []) { this.files.set(path, bytes.slice()); this.versions.set(path, 0); }
  }
  snapshot(): Map<string, Uint8Array> { return new Map([...this.files].map(([p, b]) => [p, b.slice()])); }
  copy(filter?: (path: string) => boolean): MemoryMedium { return new MemoryMedium([...this.files].filter(([p]) => !filter || filter(p))); }
  /** Puts bytes without the immutability check (a test of an outside change). */
  put(path: string, bytes: Uint8Array): void {
    this.files.set(path, bytes.slice()); this.versions.set(path, ++this.generation);
    this.hints.emit();
  }
  listing(): MediumEntry[] { return [...this.files.keys()].sort().map(path => ({ path, version: String(this.versions.get(path) ?? 0) })); }
  read(path: string): Uint8Array {
    const bytes = this.files.get(path);
    if (!bytes) throw StorageError.unavailable(`Missing record: ${path}`);
    return bytes.slice();
  }
  readBlob(path: string): Uint8Array { return this.files.get(path)?.slice() ?? new Uint8Array(0); }
  async write(writes: readonly MediumWrite[]): Promise<void> {
    const fault = this.failNextWrite;
    if (fault) { this.failNextWrite = undefined; throw fault; }
    const plan = planBatch(writes, path => this.files.get(path));
    if (plan.length === 0) return;
    for (const write of plan) { this.files.set(write.path, write.bytes); this.versions.set(write.path, ++this.generation); }
    this.hints.emit();
  }
  changes(listener: () => void): () => void { return this.hints.add(listener); }
}
