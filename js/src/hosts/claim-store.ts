/**
 * Where a cell's persisted claim lives, fenced so that a save can never overwrite a newer one.
 *
 * Every save carries a fence `{generation, seq}`, compared in that order. A host instance takes its generation from
 * what the store holds when it opens (one more than the held generation) and reserves it at once, by saving the claim
 * it loaded under `{generation, 0}`, before anything else; it then numbers its saves within that generation (and moves
 * to a new generation when it rebuilds its endpoint, after its last save has settled). A store refuses (`stale`) a save
 * whose fence is not greater than the one it holds, so the held fence never goes back. Because every instance's
 * generation is in the store before it saves a claim, each later instance starts above every earlier one, and a save
 * from an earlier instance (or an earlier attempt) that settles late is refused instead of replacing what a later one
 * stored. The fence is stored with the claim, so it survives restarts.
 *
 * The rule needs one live host per cell and store at a time: an instance whose reservation is refused does not open.
 */

/** A save's fencing value: compared by `generation`, then `seq`. */
export interface Fence { generation: number; seq: number }
/** A claim (the `Persist` effect's `persisted_json`, or none yet) with the fence it was saved under. */
export interface StoredClaim { claim: string | null; fence: Fence }

/**
 * The store contract. `load` returns what was last stored. `save` resolves only once the record is durable
 * (`stored`), or with `stale` when the store already holds a fence not lower than the record's (nothing is written);
 * it rejects when the write failed. The host never has two saves in flight for one cell.
 */
export interface ClaimStore {
  load(): Promise<StoredClaim | undefined>;
  save(record: StoredClaim): Promise<'stored' | 'stale'>;
}

/** Whether fence `a` comes after `b`. */
export function fenceAfter(a: Fence, b: Fence): boolean { return a.generation !== b.generation ? a.generation > b.generation : a.seq > b.seq; }

/**
 * A `ClaimStore` over any `read`/`write` of the whole record, with the fence check: reads and writes are serialised,
 * and a save is written only when its fence is greater than the one held. Subclass it, or use the two below.
 */
export class FencedClaimStore implements ClaimStore {
  private tail: Promise<unknown> = Promise.resolve();
  constructor(private readonly read: () => Promise<StoredClaim | undefined>, private readonly write: (record: StoredClaim) => Promise<void>) {}
  load(): Promise<StoredClaim | undefined> { return this.serial(() => this.read()); }
  save(record: StoredClaim): Promise<'stored' | 'stale'> {
    return this.serial(async () => {
      const held = await this.read();
      if (held && !fenceAfter(record.fence, held.fence)) return 'stale';
      await this.write({ claim: record.claim, fence: { ...record.fence } });
      return 'stored';
    });
  }
  private serial<T>(body: () => Promise<T>): Promise<T> {
    const run = this.tail.then(body, body);
    this.tail = run.catch(() => {});
    return run;
  }
}

/** A fenced claim store in memory (tests, previews). */
export class MemoryClaimStore extends FencedClaimStore {
  private record: StoredClaim | undefined;
  constructor() {
    super(async () => this.record && { claim: this.record.claim, fence: { ...this.record.fence } }, async record => { this.record = record; });
  }
}

/**
 * A fenced claim store in one file of a session's `PrivateStore` (`IndexedDBPrivateStore` in a browser,
 * `MemoryPrivateStore` in tests): `{claim, fence}` as JSON under `name`.
 */
export function privateClaimStore(store: { read(name: string): Promise<Uint8Array | undefined>; write(name: string, bytes: Uint8Array): Promise<void> }, name: string): ClaimStore {
  return new FencedClaimStore(
    async () => {
      const bytes = await store.read(name);
      if (!bytes) return undefined;
      const v = JSON.parse(new TextDecoder().decode(bytes)) as StoredClaim;
      if ((v.claim !== null && typeof v.claim !== 'string') || typeof v.fence?.generation !== 'number' || typeof v.fence.seq !== 'number') throw new Error(`${name} is not a stored claim`);
      return v;
    },
    record => store.write(name, new TextEncoder().encode(JSON.stringify(record))),
  );
}
