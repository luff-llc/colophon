import { WebCryptoKeys, type KeyProvider } from '../index.js';
import { KeyProviderError, keyProviderError } from './errors.js';

/** CryptoKeys are structured-cloned; private halves must remain non-extractable. */
export interface OwnerKeyPairs { signing: CryptoKeyPair; agreement: CryptoKeyPair }
/** Atomic insert prevents concurrent first opens from replacing an existing owner. */
export interface OwnerKeyStorage {
  read(id: string): Promise<OwnerKeyPairs | undefined>;
  insert(id: string, keys: OwnerKeyPairs): Promise<boolean>;
}

/** Browser/software custody, weaker than a hardware owner key. No user-presence guarantee. */
export class WebCryptoOwnerKey implements KeyProvider {
  readonly form = 'raw' as const;
  readonly custody = 'software/browser' as const;
  private constructor(private readonly keys: WebCryptoKeys) {}
  /** Open or atomically persist two independent non-extractable P-256 key pairs in IndexedDB. */
  static async openOrCreate(id: string, storage: OwnerKeyStorage = new IndexedDBOwnerKeyStorage()): Promise<WebCryptoOwnerKey> {
    if (!globalThis.crypto?.subtle) throw new KeyProviderError('unsupportedHere', 'WebCrypto unavailable');
    try {
      let pairs = await storage.read(id);
      if (!pairs) {
        const keys = await WebCryptoKeys.generate();
        pairs = await storage.insert(id, keys.keyPairs()) ? keys.keyPairs() : await storage.read(id);
      }
      if (!pairs) throw new KeyProviderError('credentialMissing', 'Stored owner key missing');
      const keys = await WebCryptoKeys.fromKeyPairs(pairs.signing, pairs.agreement);
      if (keys.signingPublicKey.every((byte, i) => byte === keys.agreementPublicKey[i])) throw new KeyProviderError('hardwareUnavailable', 'Owner keys must be separate');
      return new WebCryptoOwnerKey(keys);
    } catch (error) { throw keyProviderError(error); }
  }
  get signingPublicKey(): Uint8Array { return this.keys.signingPublicKey; }
  get agreementPublicKey(): Uint8Array { return this.keys.agreementPublicKey; }
  async sign(body: Uint8Array): Promise<Uint8Array> { try { return await this.keys.sign(body); } catch (error) { throw keyProviderError(error); } }
  async agree(peer: Uint8Array): Promise<Uint8Array> { try { return await this.keys.agree(peer); } catch (error) { throw keyProviderError(error); } }
}

/** IndexedDB storage for browser-scoped CryptoKey handles. Clearing site data loses these keys. */
export class IndexedDBOwnerKeyStorage implements OwnerKeyStorage {
  constructor(private readonly database = 'colophon-owner-keys', private readonly indexedDB: IDBFactory | undefined = globalThis.indexedDB) {}
  async read(id: string): Promise<OwnerKeyPairs | undefined> { return this.transaction('readonly', store => store.get(id)); }
  async insert(id: string, keys: OwnerKeyPairs): Promise<boolean> {
    try { await this.transaction('readwrite', store => store.add(keys, id)); return true; }
    catch (error) { if (error instanceof Error && error.name === 'ConstraintError') return false; throw error; }
  }
  private async transaction<T>(mode: IDBTransactionMode, request: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const factory = this.indexedDB;
    if (!factory) throw new KeyProviderError('unsupportedHere', 'IndexedDB unavailable');
    const database = await new Promise<IDBDatabase>((resolve, reject) => {
      let blocked = false;
      const open = factory.open(this.database, 1);
      open.onupgradeneeded = () => { open.result.createObjectStore('owners'); };
      open.onsuccess = () => { if (blocked) open.result.close(); else resolve(open.result); };
      open.onerror = () => reject(open.error);
      open.onblocked = () => { blocked = true; reject(new KeyProviderError('hardwareUnavailable', 'IndexedDB upgrade blocked')); };
    });
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = database.transaction('owners', mode);
        const operation = request(tx.objectStore('owners'));
        tx.oncomplete = () => resolve(operation.result);
        tx.onabort = () => reject(operation.error ?? tx.error ?? new KeyProviderError('hardwareUnavailable', 'IndexedDB transaction aborted'));
        tx.onerror = () => { /* onabort reports the request error after rollback. */ };
      });
    } finally { database.close(); }
  }
}
