/**
 * A claim store in a directory, for Node and Bun: a lock-free compare-and-set built on the file system's atomic
 * no-replace primitive, the hard link. Not for browsers (use `privateClaimStore` over `IndexedDBPrivateStore`).
 *
 * Every saved claim is its own file, named by its fence (`claim-<generation>-<seq>.json`, both zero-padded to 16
 * digits so that names sort as fences do), written to a temporary file first and committed with
 * `link(temporary, name)`, which fails with EEXIST if that fence's file exists. No claim file is ever replaced.
 *
 * `save(record N, expected E)`:
 *   1. list the directory; if the highest fence present is not E, it is `stale`;
 *   2. link N's file; EEXIST is `stale`;
 *   3. list again; it is `stored` only if N is the highest fence present and no fence F with E < F < N exists;
 *      otherwise it removes its own file and is `stale`.
 *
 * At most one of two savers from the same E succeeds, in every interleaving. Each lists (step 3) after its own link
 * (step 2), so whichever of the two lists later sees the other's file, unless that file was already removed by its
 * owner, which removes it only after deciding to fail. A saver that sees the other's file F fails: if F > N, N is not
 * the highest; if E < F < N, F is an intermediate fence; F = N is impossible, since the second link of one name fails
 * with EEXIST. So both can fail (each sees the other), but both cannot succeed, and many savers from one E reduce to
 * pairs. Successful saves therefore form a chain: each succeeded from the highest fence present at its first listing
 * and, at its last listing, left its own fence highest with nothing between the two, so the next successful save
 * starts from it.
 *
 * A crash at any point leaves the old state or one complete new file: before the link, only an ignored temporary file
 * exists (removed once it is an hour old); after the link, the claim file is complete (it was written and synced
 * before it got its name), so it is either the new highest fence or a lower file that changes nothing. A saver that
 * crashed after deciding to fail but before removing its file can leave that file as the highest: a host that believed
 * its own save succeeded then sees a fence that is not its own at its next check and fails as superseded.
 *
 * Reading takes the highest fence file. A highest file that does not parse, or whose content names another fence,
 * is an error (fail closed): skipping it would lower the held fence. Lower files are removed after a successful save,
 * which never changes the highest. If the file system cannot hard-link, the store cannot be made.
 */
import * as fs from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { compareAndSet, fenceAfter, isFence, type ClaimStore, type Fence, type StoredClaim } from './claim-store.js';

/** Test hooks: called between the steps of a save, so a test can interleave savers or simulate a crash by throwing. */
export interface FileClaimStoreOptions {
  onStep?: (step: 'begin' | 'listed' | 'written' | 'linked' | 'checked', fence: Fence) => void | Promise<void>;
}

const PAD = 16;
const NAME = /^claim-(\d{16})-(\d{16})\.json$/;
const TEMPORARY_AGE_MS = 3_600_000;
const nameOf = (f: Fence): string => `claim-${String(f.generation).padStart(PAD, '0')}-${String(f.seq).padStart(PAD, '0')}.json`;
const fenceOf = (name: string): Fence | undefined => {
  const m = NAME.exec(name);
  if (!m) return undefined;
  const f = { generation: Number(m[1]), seq: Number(m[2]) };
  return isFence(f) ? f : undefined;
};
const errorCode = (error: unknown): string | undefined => (error as { code?: string } | null)?.code;

function writeDurably(path: string, bytes: Uint8Array): void {
  const fd = fs.openSync(path, 'wx', 0o600);
  try {
    let at = 0;
    while (at < bytes.length) at += fs.writeSync(fd, bytes, at, bytes.length - at);
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}
function syncDirectory(path: string): void {
  let fd: number;
  try { fd = fs.openSync(path, 'r'); } catch { return; }
  try { fs.fsyncSync(fd); } catch { /* not every file system syncs a directory */ } finally { fs.closeSync(fd); }
}

export class FileClaimStore implements ClaimStore {
  private readonly onStep: NonNullable<FileClaimStoreOptions['onStep']>;
  constructor(readonly directory: string, options: FileClaimStoreOptions = {}) {
    this.onStep = options.onStep ?? (() => {});
    fs.mkdirSync(directory, { recursive: true });
    // The commit is a hard link: a file system without them cannot hold a fenced claim.
    const probe = join(directory, `.probe-${randomUUID()}`);
    try {
      writeDurably(probe, new Uint8Array(0));
      fs.linkSync(probe, `${probe}.link`);
    } catch (error) {
      throw new Error(`FileClaimStore needs hard links, and ${directory} does not support them (${errorCode(error) ?? String(error)})`);
    } finally {
      fs.rmSync(probe, { force: true }); fs.rmSync(`${probe}.link`, { force: true });
    }
  }

  /** The claim fences present, highest first. */
  private fences(): Fence[] {
    const out: Fence[] = [];
    for (const entry of fs.readdirSync(this.directory, { withFileTypes: true })) {
      const f = entry.isFile() ? fenceOf(entry.name) : undefined;
      if (f) out.push(f);
    }
    return out.sort((a, b) => (fenceAfter(a, b) ? -1 : fenceAfter(b, a) ? 1 : 0));
  }
  async fence(): Promise<Fence | undefined> { return this.fences()[0]; }
  async load(): Promise<StoredClaim | undefined> {
    const top = this.fences()[0];
    if (!top) return undefined;
    const name = nameOf(top);
    let v: StoredClaim;
    try { v = JSON.parse(new TextDecoder().decode(fs.readFileSync(join(this.directory, name)))) as StoredClaim; } catch (error) {
      throw new Error(`the highest claim file ${name} cannot be read`, { cause: error });
    }
    if ((v.claim !== null && typeof v.claim !== 'string') || !isFence(v.fence) || v.fence.generation !== top.generation || v.fence.seq !== top.seq) {
      throw new Error(`the highest claim file ${name} is not the claim its name says`);
    }
    return v;
  }

  async save(record: StoredClaim, expected: Fence | undefined): Promise<'stored' | 'stale'> {
    await this.onStep('begin', record.fence);
    // The record's own checks (safe integers, a greater fence); the held claim's content is not needed for them.
    const held = this.fences()[0];
    if (!compareAndSet(held ? { claim: null, fence: held } : undefined, record, expected)) return 'stale';
    const n = record.fence;
    await this.onStep('listed', n);
    this.ageTemporaries();
    const temporary = join(this.directory, `.tmp-${randomUUID()}`);
    const target = join(this.directory, nameOf(n));
    writeDurably(temporary, new TextEncoder().encode(JSON.stringify({ claim: record.claim, fence: { generation: n.generation, seq: n.seq } })));
    try {
      await this.onStep('written', n);
      try { fs.linkSync(temporary, target); } catch (error) {
        if (errorCode(error) === 'EEXIST') return 'stale';
        throw error;
      }
    } finally {
      fs.rmSync(temporary, { force: true });
    }
    syncDirectory(this.directory);
    await this.onStep('linked', n);
    const present = this.fences();
    const top = present[0];
    const between = present.some(f => (expected === undefined || fenceAfter(f, expected)) && fenceAfter(n, f));
    if (!top || top.generation !== n.generation || top.seq !== n.seq || between) {
      fs.rmSync(target, { force: true });
      syncDirectory(this.directory);
      return 'stale';
    }
    await this.onStep('checked', n);
    // Lower files never change the highest: remove them.
    for (const f of present.slice(1)) fs.rmSync(join(this.directory, nameOf(f)), { force: true });
    return 'stored';
  }

  private ageTemporaries(): void {
    const now = Date.now();
    for (const entry of fs.readdirSync(this.directory, { withFileTypes: true })) {
      if (!entry.name.startsWith('.tmp-')) continue;
      const path = join(this.directory, entry.name);
      try { if (now - fs.lstatSync(path).mtimeMs > TEMPORARY_AGE_MS) fs.rmSync(path, { force: true }); } catch { /* gone */ }
    }
  }
}
