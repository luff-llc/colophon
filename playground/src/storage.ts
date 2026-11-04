/* IndexedDB persistence for the Recover verb. The in-memory Records map is
 * snapshotted after every mutation; Recover drops every Library object and
 * re-opens from these stored bytes with the tab's keys.
 */

import type { Records } from './core';

const DB = 'colophon-playground';
const STORE = 'kv';
const KEY = 'records-v1';

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

export async function saveRecords(records: Records): Promise<number> {
  const pairs: [string, string][] = [...records.entries()].map(([p, b]) => [p, b64encode(b)]);
  const db = await openDB();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(pairs, KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
  return pairs.length;
}

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
