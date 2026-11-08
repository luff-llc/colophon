/* Host persistence: records and non-extractable key handles, never the vault seed.
 * The v4 storage key deliberately does not reopen older authority records.
 */

import type { Records } from './core';

const DB = 'colophon-playground';
const STORE = 'kv';
const KEY = 'records-v4';
const DEVICE_KEYS = 'device-keys-v4';

/** Persisted host key handles. CryptoKeys structured-clone into IndexedDB with
 * private halves staying non-extractable; restore with WebCryptoKeys.fromKeyPairs. */
export interface StoredKeyPairs {
  signing: CryptoKeyPair;
  agreement: CryptoKeyPair;
}

function b64encode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** Snapshot exact signed record bytes. */
export async function saveRecords(records: Records): Promise<number> {
  const pairs: [string, string][] = [...records.entries()].map(([p, b]) => [p, b64encode(b)]);
  const db = await openDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(pairs, KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? new Error('Record storage aborted'));
    });
  } finally {
    db.close();
  }
  return pairs.length;
}

/** A device has distinct controller and member handles; the demo kit is separate. */
export interface StoredDeviceKeys {
  owner: StoredKeyPairs;
  member: StoredKeyPairs;
  recoveryKit?: StoredKeyPairs;
}

/** Store host key handles together, independently of signed library records. */
export async function saveKeys(keys: StoredDeviceKeys): Promise<void> {
  const db = await openDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(keys, DEVICE_KEYS);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? new Error('Key storage aborted'));
    });
  } finally {
    db.close();
  }
}

/** Load only 0.4 key handles; older libraries require a clean copy. */
export async function loadKeys(): Promise<StoredDeviceKeys | null> {
  const db = await openDB();
  try {
    return await new Promise<StoredDeviceKeys | null>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const rq = tx.objectStore(STORE).get(DEVICE_KEYS) as IDBRequest<StoredDeviceKeys | undefined>;
      rq.onsuccess = () => resolve(rq.result ?? null);
      rq.onerror = () => reject(rq.error);
    });
  } finally {
    db.close();
  }
}

/** Restore the last 0.4 record snapshot. */
export async function loadRecords(): Promise<Records | null> {
  const db = await openDB();
  try {
    const pairs = await new Promise<[string, string][] | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const rq = tx.objectStore(STORE).get(KEY) as IDBRequest<[string, string][] | undefined>;
      rq.onsuccess = () => resolve(rq.result);
      rq.onerror = () => reject(rq.error);
    });
    if (!pairs) return null;
    const records: Records = new Map();
    for (const [p, b] of pairs) records.set(p, b64decode(b));
    return records;
  } finally {
    db.close();
  }
}
