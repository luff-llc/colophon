/**
 * Where a cell's persisted claim lives, fenced so that no save can overwrite a newer one, whichever client makes it.
 *
 * Every save carries a fence `{generation, seq}` (safe integers, compared in that order) and the fence its caller last
 * saw held. The store applies it as one linearizable compare-and-set across every client of the same underlying
 * storage: it writes only if the fence it holds is exactly the expected one and the new fence is greater. A host
 * instance takes its generation, when it opens and when it rebuilds its endpoint, by such a save (the claim it holds
 * under `{generation + 1, 0}`), and numbers its later saves within that generation. Two instances that read the same
 * held fence cannot both reserve the next generation: the first save changes the held fence, so the second's
 * comparison fails and it is `stale`. The held fence therefore never goes back and changes only by a save made from
 * exactly the previous one, so a save from an older instance or attempt that settles late finds a fence it did not
 * expect and changes nothing. The fence is stored with the claim, so it survives restarts.
 *
 * A store that reads, compares and writes in separate steps is incorrect: two clients can both read fence F, both
 * pass the comparison, and both write, so two hosts would believe they own the cell and a stale claim could be
 * written over a newer one. The comparison and the write must be one atomic step against every other client.
 */
import type { AtomicPrivateStore } from '../session/private.js';

/** A save's fencing value: two non-negative safe integers, compared by `generation`, then `seq`. */
export interface Fence { generation: number; seq: number }
/** A claim (the `Persist` effect's `persisted_json`, or none yet) with the fence it was saved under. */
export interface StoredClaim { claim: string | null; fence: Fence }

/**
 * The store contract. `load` returns what is held. `save(record, expected)` is a linearizable compare-and-set across
 * every client of the same storage: if the held fence equals `expected` (none: nothing is held) and `record.fence` is
 * greater, the record is written durably and it resolves `stored`; otherwise nothing is written and it resolves
 * `stale`. It rejects when the write failed (and then it may or may not have been written: the host reads again).
 */
export interface ClaimStore {
  load(): Promise<StoredClaim | undefined>;
  /** The held fence alone, read cheaply (a host asks every beat). */
  fence(): Promise<Fence | undefined>;
  save(record: StoredClaim, expected: Fence | undefined): Promise<'stored' | 'stale'>;
}

/** Whether `f` is a fence: two non-negative safe integers. */
export function isFence(f: unknown): f is Fence {
  const v = f as Partial<Fence> | null;
  return typeof v === 'object' && v !== null && Number.isSafeInteger(v.generation) && Number.isSafeInteger(v.seq)
    && (v.generation as number) >= 0 && (v.seq as number) >= 0;
}
function checked(f: Fence): Fence {
  if (!isFence(f)) throw new RangeError('a fence is two non-negative safe integers');
  return f;
}
/** Whether fence `a` comes after `b` (both checked). */
export function fenceAfter(a: Fence, b: Fence): boolean {
  checked(a); checked(b);
  return a.generation !== b.generation ? a.generation > b.generation : a.seq > b.seq;
}
const sameFence = (a: Fence | undefined, b: Fence | undefined): boolean => a === undefined || b === undefined ? a === b : a.generation === b.generation && a.seq === b.seq;

/** The compare-and-set every store applies: the record to write, or none. */
export function compareAndSet(held: StoredClaim | undefined, record: StoredClaim, expected: Fence | undefined): StoredClaim | undefined {
  checked(record.fence);
  if (expected !== undefined) checked(expected);
  if (record.claim !== null && typeof record.claim !== 'string') throw new TypeError('a claim is a string or null');
  if (!sameFence(held?.fence, expected)) return undefined;
  if (held && !fenceAfter(record.fence, held.fence)) return undefined;
  return { claim: record.claim, fence: { generation: record.fence.generation, seq: record.fence.seq } };
}

/**
 * A claim store in memory: every client that shares this object shares the record, and `save` compares and writes in
 * one synchronous step (tests, previews).
 */
export class MemoryClaimStore implements ClaimStore {
  private record: StoredClaim | undefined;
  async load(): Promise<StoredClaim | undefined> { return this.record && { claim: this.record.claim, fence: { ...this.record.fence } }; }
  async fence(): Promise<Fence | undefined> { return this.record && { ...this.record.fence }; }
  async save(record: StoredClaim, expected: Fence | undefined): Promise<'stored' | 'stale'> {
    const next = compareAndSet(this.record, record, expected);
    if (!next) return 'stale';
    this.record = next;
    return 'stored';
  }
}

/**
 * A record without a valid fence is refused, never read as unfenced: 0.6 has not been released, so no claim was ever
 * stored without one and there is nothing to migrate.
 */
const decode = (bytes: Uint8Array | undefined, name: string): StoredClaim | undefined => {
  if (!bytes) return undefined;
  const v = JSON.parse(new TextDecoder().decode(bytes)) as StoredClaim;
  if ((v.claim !== null && typeof v.claim !== 'string') || !isFence(v.fence)) throw new Error(`${name} is not a stored claim`);
  return v;
};

/**
 * A claim store in one record of an `AtomicPrivateStore` (`IndexedDBPrivateStore`, `MemoryPrivateStore`). A private
 * store without the atomic `update` is refused: there is no file-backed claim store yet.: `{claim, fence}` as JSON under `name`, saved through the store's `update`, so the comparison
 * and the write are one atomic step against every client of the same database or folder.
 */
export function privateClaimStore(store: AtomicPrivateStore, name: string): ClaimStore {
  // A store without an atomic update (the file-backed `FilePrivateStore`) would make the compare-and-set two steps.
  if (typeof (store as Partial<AtomicPrivateStore>).update !== 'function') {
    throw new TypeError('file-backed claim persistence is not available yet: this private store has no atomic update, so supply a ClaimStore (MemoryClaimStore, or privateClaimStore over IndexedDBPrivateStore)');
  }
  return {
    load: async () => decode(await store.read(name), name),
    // The record is one small file, so its fence is read with it.
    fence: async () => decode(await store.read(name), name)?.fence,
    save: async (record, expected) => {
      const wrote = await store.update(name, current => {
        const next = compareAndSet(decode(current, name), record, expected);
        return next ? new TextEncoder().encode(JSON.stringify(next)) : undefined;
      });
      return wrote ? 'stored' : 'stale';
    },
  };
}
