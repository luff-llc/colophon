import { KeyCustodyError, StorageError } from './errors.js';
import { ChangeHints, planBatch, RecordPaths, sameBytes, type MediumEntry, type MediumWrite, type RecordMedium } from './medium.js';
import type { DeviceSecretStore, PrivateStore } from './private.js';
import { SecretBytes } from './secrets.js';

function openDatabase(factory: IDBFactory | undefined, name: string, stores: readonly string[]): Promise<IDBDatabase> {
  if (!factory) return Promise.reject(StorageError.unavailable('IndexedDB is not available here'));
  return new Promise<IDBDatabase>((resolve, reject) => {
    const open = factory.open(name, 1);
    open.onupgradeneeded = () => { for (const store of stores) if (!open.result.objectStoreNames.contains(store)) open.result.createObjectStore(store); };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(StorageError.unavailable(open.error?.message ?? 'IndexedDB failed to open', open.error));
    open.onblocked = () => reject(StorageError.unavailable('IndexedDB is blocked by another tab'));
  });
}

/** One request in its own transaction; resolves when the transaction has committed, never before. */
function transact<T>(db: IDBDatabase, store: string, mode: IDBTransactionMode, body: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(store, mode, { durability: mode === 'readwrite' ? 'strict' : 'default' });
    const request = body(tx.objectStore(store));
    tx.oncomplete = () => resolve(request.result);
    tx.onabort = () => reject(request.error ?? tx.error ?? new Error('IndexedDB transaction aborted'));
    tx.onerror = () => { /* onabort reports it after the rollback */ };
  });
}

interface Row { b: Uint8Array; v: number }

/**
 * The browser's record store: one IndexedDB object store, with everything it holds kept in memory so the engine's
 * synchronous reads are answered at once (docs/bindings-05.md §3a: a callback cannot wait for IndexedDB).
 *
 * `write` is one `readwrite` transaction with strict durability: IndexedDB commits all of it or none of it, across a
 * failure, a closed tab or a kill, and the in-memory copy changes only after the commit. Inside the transaction each
 * path is compared with what the database really holds, so a second tab cannot make this one replace an immutable
 * record. Other tabs on the same store are told through a `BroadcastChannel` and re-read what changed.
 *
 * Bound: the whole store is held in memory, blob chunks included. That suits a library of records and modest blobs; a
 * host with large media should fetch optional blobs on demand and not keep them (a store over OPFS synchronous handles
 * in a worker is the follow-up).
 */
export class IndexedDBMedium implements RecordMedium {
  private readonly mirror = new Map<string, Row>();
  private readonly hints = new ChangeHints();
  private readonly channel: BroadcastChannel | undefined;
  private closed = false;

  private constructor(private readonly db: IDBDatabase, readonly name: string) {
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel(`colophon-medium:${name}`);
      this.channel.onmessage = () => { void this.reload().catch(() => {}); };
    }
    db.onversionchange = () => this.close();
  }

  /** Opens (creating if needed) the store `name` and reads everything it holds. */
  static async open(name: string, factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedDBMedium> {
    const medium = new IndexedDBMedium(await openDatabase(factory, name, ['records', 'meta']), name);
    await medium.reload(false);
    return medium;
  }
  /** Deletes the store `name` and everything in it. */
  static destroy(name: string, factory: IDBFactory | undefined = globalThis.indexedDB): Promise<void> {
    if (!factory) return Promise.reject(StorageError.unavailable('IndexedDB is not available here'));
    return new Promise<void>((resolve, reject) => {
      const request = factory.deleteDatabase(name);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(StorageError.unavailable(request.error?.message ?? 'delete failed', request.error));
      request.onblocked = () => reject(StorageError.unavailable('IndexedDB is blocked by another tab'));
    });
  }

  /** Reads the database again (another tab wrote). The in-memory copy is replaced in one step. */
  async reload(announce = true): Promise<void> {
    if (this.closed) return;
    const next = await new Promise<Map<string, Row>>((resolve, reject) => {
      const tx = this.db.transaction('records', 'readonly');
      const store = tx.objectStore('records');
      const keys = store.getAllKeys(); const values = store.getAll();
      tx.oncomplete = () => {
        const map = new Map<string, Row>();
        keys.result.forEach((key, i) => { const row = values.result[i] as Row | undefined; if (typeof key === 'string' && row) map.set(key, row); });
        resolve(map);
      };
      tx.onabort = () => reject(StorageError.unavailable(tx.error?.message ?? 'IndexedDB read failed', tx.error));
    });
    let changed = next.size !== this.mirror.size;
    if (!changed) for (const [path, row] of next) { if (this.mirror.get(path)?.v !== row.v) { changed = true; break; } }
    this.mirror.clear();
    for (const [path, row] of next) this.mirror.set(path, row);
    if (changed && announce) this.hints.emit();
  }

  listing(): MediumEntry[] {
    this.requireOpen();
    return [...this.mirror].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([path, row]) => ({ path, version: String(row.v) }));
  }
  read(path: string): Uint8Array {
    this.requireOpen();
    const row = this.mirror.get(path);
    if (!row) throw StorageError.unavailable(`Missing record: ${path}`);
    return row.b.slice();
  }
  readBlob(path: string): Uint8Array {
    this.requireOpen();
    return this.mirror.get(path)?.b.slice() ?? new Uint8Array(0);
  }

  async write(writes: readonly MediumWrite[]): Promise<void> {
    this.requireOpen();
    const plan = planBatch(writes, path => this.mirror.get(path)?.b);
    if (plan.length === 0) return;
    const applied: [string, Row][] = [];
    let conflict: string | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = this.db.transaction(['records', 'meta'], 'readwrite', { durability: 'strict' });
        const records = tx.objectStore('records'); const meta = tx.objectStore('meta');
        const current = meta.get('generation');
        current.onsuccess = () => {
          let generation = typeof current.result === 'number' ? current.result : 0;
          for (const write of plan) {
            const existing = records.get(write.path);
            existing.onsuccess = () => {
              if (conflict !== undefined) return;
              const row = existing.result as Row | undefined;
              if (row && sameBytes(row.b, write.bytes)) { applied.push([write.path, row]); return; }
              if (row && !RecordPaths.isReplaceable(write.path)) { conflict = write.path; tx.abort(); return; }
              const next: Row = { b: write.bytes, v: ++generation };
              records.put(next, write.path);
              meta.put(generation, 'generation');
              applied.push([write.path, next]);
            };
          }
        };
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(conflict !== undefined ? StorageError.conflict(conflict)
          : tx.error?.name === 'QuotaExceededError' ? StorageError.limitExceeded()
          : StorageError.unavailable(tx.error?.message ?? 'IndexedDB write aborted', tx.error));
        tx.onerror = () => { /* onabort reports it after the rollback */ };
      });
    } catch (error) {
      // Nothing was stored. The database held something this copy did not know: read it again.
      if (conflict !== undefined) await this.reload().catch(() => {});
      throw error;
    }
    for (const [path, row] of applied) this.mirror.set(path, row);
    this.hints.emit();
    this.channel?.postMessage('changed');
  }

  changes(listener: () => void): () => void { return this.hints.add(listener); }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.channel?.close();
    this.db.close();
    this.mirror.clear();
  }
  private requireOpen(): void { if (this.closed) throw StorageError.unavailable('the record store is closed'); }
}

/** The private files of one device in IndexedDB (one object store). */
export class IndexedDBPrivateStore implements PrivateStore {
  private db: Promise<IDBDatabase> | undefined;
  constructor(readonly name: string, private readonly factory: IDBFactory | undefined = globalThis.indexedDB) {}
  private open(): Promise<IDBDatabase> { return this.db ??= openDatabase(this.factory, this.name, ['files']); }
  async read(name: string): Promise<Uint8Array | undefined> {
    const value: unknown = await transact(await this.open(), 'files', 'readonly', s => s.get(name));
    return value instanceof Uint8Array ? value : undefined;
  }
  async write(name: string, bytes: Uint8Array): Promise<void> { await transact(await this.open(), 'files', 'readwrite', s => s.put(bytes.slice(), name)); }
  async remove(name: string): Promise<void> { await transact(await this.open(), 'files', 'readwrite', s => s.delete(name)); }
  async close(): Promise<void> { if (this.db) { (await this.db).close(); this.db = undefined; } }
}

/** Two P-256 key pairs as the browser holds them. The private halves are non-extractable `CryptoKey`s. */
export interface StoredKeyPairs { signing: CryptoKeyPair; agreement: CryptoKeyPair }

/**
 * Keeps `CryptoKey` handles in IndexedDB by structured clone: the private keys are never exported and cannot be (they
 * are created non-extractable). Clearing the site's data loses them. `insert` is atomic: a second tab cannot replace
 * a key the first one made.
 */
export class WebCryptoKeyStore {
  private db: Promise<IDBDatabase> | undefined;
  constructor(readonly name = 'colophon-keys', private readonly factory: IDBFactory | undefined = globalThis.indexedDB) {}
  private open(): Promise<IDBDatabase> { return this.db ??= openDatabase(this.factory, this.name, ['keys']); }
  async read(id: string): Promise<StoredKeyPairs | undefined> {
    return await transact(await this.open(), 'keys', 'readonly', s => s.get(id)) as StoredKeyPairs | undefined;
  }
  /** Stores `keys` under `id` unless something is already there. False: something was. */
  async insert(id: string, keys: StoredKeyPairs): Promise<boolean> {
    try { await transact(await this.open(), 'keys', 'readwrite', s => s.add(keys, id)); return true; }
    catch (error) { if (error instanceof Error && error.name === 'ConstraintError') return false; throw error; }
  }
  async remove(id: string): Promise<void> { await transact(await this.open(), 'keys', 'readwrite', s => s.delete(id)); }
  async close(): Promise<void> { if (this.db) { (await this.db).close(); this.db = undefined; } }
}

/**
 * The device key that seals saved state, in a browser. Nothing readable is stored: IndexedDB holds one
 * non-extractable HMAC-SHA-256 key and a random salt per account, and the 32-byte key is `HMAC(key, salt)`, computed
 * when asked and wiped by the caller. `remove` deletes the salt, after which that key cannot be made again.
 */
export class WebCryptoDeviceSecrets implements DeviceSecretStore {
  private db: Promise<IDBDatabase> | undefined;
  constructor(readonly name = 'colophon-device', private readonly factory: IDBFactory | undefined = globalThis.indexedDB) {}
  private open(): Promise<IDBDatabase> { return this.db ??= openDatabase(this.factory, this.name, ['secrets']); }

  private async master(db: IDBDatabase): Promise<CryptoKey> {
    const held: unknown = await transact(db, 'secrets', 'readonly', s => s.get('master'));
    if (held instanceof CryptoKey) return held;
    const made = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    try { await transact(db, 'secrets', 'readwrite', s => s.add(made, 'master')); return made; }
    catch (error) {
      if (!(error instanceof Error) || error.name !== 'ConstraintError') throw error;
      const raced: unknown = await transact(db, 'secrets', 'readonly', s => s.get('master'));
      if (raced instanceof CryptoKey) return raced;
      throw new KeyCustodyError('hardwareUnavailable', 'the device key could not be stored');
    }
  }

  async key(account: string): Promise<SecretBytes> {
    const db = await this.open();
    const master = await this.master(db);
    const name = `salt:${account}`;
    let salt: unknown = await transact(db, 'secrets', 'readonly', s => s.get(name));
    if (!(salt instanceof Uint8Array) || salt.length !== 32) {
      const fresh = crypto.getRandomValues(new Uint8Array(32));
      try { await transact(db, 'secrets', 'readwrite', s => s.add(fresh, name)); salt = fresh; }
      catch (error) {
        if (!(error instanceof Error) || error.name !== 'ConstraintError') throw error;
        salt = await transact(db, 'secrets', 'readonly', s => s.get(name));
      }
    }
    if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new KeyCustodyError('hardwareUnavailable', 'the device key salt is unreadable');
    return SecretBytes.adopt(new Uint8Array(await crypto.subtle.sign('HMAC', master, salt.slice())));
  }
  async remove(account: string): Promise<void> { await transact(await this.open(), 'secrets', 'readwrite', s => s.delete(`salt:${account}`)); }
  async close(): Promise<void> { if (this.db) { (await this.db).close(); this.db = undefined; } }
}
