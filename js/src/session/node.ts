/**
 * File-backed storage for Node and Bun: tests, command-line tools and agents. Not for browsers (`indexeddb.ts`).
 */
import * as fs from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { StorageError } from './errors.js';
import { ChangeHints, planBatch, RecordPaths, type MediumEntry, type MediumWrite, type RecordMedium } from './medium.js';
import type { PrivateStore } from './private.js';

declare const process: { pid: number; kill(pid: number, signal: number): boolean };

/** Test hook: called at each point of a batch where a crash is interesting. Throwing (or killing the process) there simulates one. */
export type FileMediumStep = 'staged' | 'committed' | 'applied' | 'cleaned';
export interface FileMediumOptions { onStep?: (step: FileMediumStep, index?: number) => void }

interface BatchItem { path: string; file: string; sha256: string; size: number }

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

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
function sleep(ms: number): void { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

/**
 * A folder as the record store. Reads go to the disk. A `write` is published through a journal in
 * `.colophon.nosync/`: every file of the batch is staged and synchronised with a record of the batch, the staging
 * folder is renamed to `commit-…` (the commit point), and only then are the files renamed into place. A failure or a
 * kill before the commit point leaves nothing; after it, the next `listing`, `write` or open completes the batch
 * (a committed batch is never discarded: if it cannot be completed the store is `unavailable`, not partly written).
 * A lock file with its holder's token keeps two processes from publishing at once; a dead holder's lock is taken over
 * (see `locked`).
 */
export class FileMedium implements RecordMedium {
  private readonly journal: string;
  private readonly hints = new ChangeHints();
  private readonly onStep: (step: FileMediumStep, index?: number) => void;

  constructor(readonly root: string, options: FileMediumOptions = {}) {
    this.onStep = options.onStep ?? (() => {});
    this.journal = join(root, '.colophon.nosync');
    fs.mkdirSync(this.journal, { recursive: true });
    this.locked(() => this.recover());
  }

  listing(): MediumEntry[] {
    return this.locked(() => {
      this.recover();
      const out: MediumEntry[] = [];
      const walk = (directory: string, prefix: string): void => {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
          if (entry.name.startsWith('.')) continue;
          const full = join(directory, entry.name); const path = prefix + entry.name;
          if (entry.isSymbolicLink()) throw StorageError.unavailable(`a symbolic link in the record store: ${path}`);
          if (entry.isDirectory()) walk(full, path + '/');
          else if (entry.isFile()) { const s = fs.lstatSync(full); out.push({ path, version: `${s.size}:${s.mtimeMs}` }); }
        }
      };
      try { walk(this.root, ''); } catch (error) {
        throw error instanceof StorageError ? error : StorageError.unavailable('the record store could not be listed', error);
      }
      return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    });
  }

  read(path: string): Uint8Array {
    const bytes = this.held(path);
    if (!bytes) throw StorageError.unavailable(`Missing record: ${path}`);
    return bytes;
  }
  readBlob(path: string): Uint8Array { return this.held(path) ?? new Uint8Array(0); }

  /** The bytes at `path`, or nothing. A path that leaves the root through a symbolic link is refused. */
  private held(path: string): Uint8Array | undefined {
    RecordPaths.validate(path);
    this.settle();
    const full = join(this.root, path);
    if (!fs.existsSync(full)) return undefined;
    try {
      if (fs.realpathSync(full) !== join(fs.realpathSync(this.root), path)) throw StorageError.unavailable(`a symbolic link in the record store: ${path}`);
      const stat = fs.lstatSync(full);
      if (!stat.isFile()) throw StorageError.unavailable(`not a file: ${path}`);
      if (stat.size > RecordPaths.maximumBytes) throw StorageError.limitExceeded();
      return new Uint8Array(fs.readFileSync(full));
    } catch (error) {
      throw error instanceof StorageError ? error : StorageError.unavailable(`Unreadable record: ${path}`, error);
    }
  }

  async write(writes: readonly MediumWrite[]): Promise<void> {
    const wrote = this.locked(() => {
      this.recover();
      const plan = planBatch(writes, path => this.held(path));
      if (plan.length === 0) return false;
      const id = randomUUID();
      const stage = join(this.journal, `stage-${id}`);
      try {
        fs.mkdirSync(stage);
        const items: BatchItem[] = plan.map((write, n) => {
          const file = `${n}.bin`;
          writeDurably(join(stage, file), write.bytes);
          return { path: write.path, file, sha256: sha256(write.bytes), size: write.bytes.length };
        });
        writeDurably(join(stage, 'batch.json'), new TextEncoder().encode(JSON.stringify({ version: 1, items })));
        syncDirectory(stage);
        this.onStep('staged');
      } catch (error) {
        // Before the commit point: nothing is published, the staging folder goes.
        fs.rmSync(stage, { recursive: true, force: true });
        throw error instanceof StorageError ? error : StorageError.unavailable('the batch could not be staged', error);
      }
      const commit = join(this.journal, `commit-${id}`);
      try {
        // A holder that was displaced commits nothing.
        if (!this.holding()) throw new Error('the store\'s lock was lost');
        fs.renameSync(stage, commit);
      } catch (error) {
        fs.rmSync(stage, { recursive: true, force: true });
        throw StorageError.unavailable('the batch could not be committed', error);
      }
      syncDirectory(this.journal);
      // From here the batch is committed: a failure leaves the journal, and the next operation completes it.
      this.onStep('committed');
      this.apply(commit);
      return true;
    });
    if (wrote) this.hints.emit();
  }

  /**
   * A read never sees a batch half applied. While a batch is between its commit point and its last rename, its
   * `commit-…` folder exists: a reader that finds one takes the lock (so it waits for a writer that is still working, in
   * this process or another) and completes the batch before it reads. A reader that cannot get the lock fails as
   * `unavailable`; it is never handed part of a batch. Inside this medium's own locked section nothing is done.
   */
  private settle(): void {
    if (this.token !== undefined) return;
    let committed: boolean;
    try { committed = fs.readdirSync(this.journal, { withFileTypes: true }).some(entry => entry.name.startsWith('commit-')); }
    catch (error) { throw StorageError.unavailable('the record store\'s journal could not be read', error); }
    if (committed) this.locked(() => this.recover());
  }

  /** Completes every committed batch and discards every uncommitted one. */
  private recover(): void {
    for (const entry of fs.readdirSync(this.journal, { withFileTypes: true })) {
      if (entry.name.startsWith('commit-')) this.apply(join(this.journal, entry.name));
      else if (entry.name.startsWith('stage-') || entry.name.startsWith('dead-')) fs.rmSync(join(this.journal, entry.name), { recursive: true, force: true });
    }
  }

  /** Moves a committed batch's files into place. Never deletes the journal of a batch it could not complete. */
  private apply(commit: string): void {
    let items: BatchItem[];
    try {
      const parsed = JSON.parse(new TextDecoder().decode(fs.readFileSync(join(commit, 'batch.json')))) as { items: BatchItem[] };
      items = parsed.items;
      if (!Array.isArray(items)) throw new Error('no items');
    } catch (error) {
      throw StorageError.unavailable('a committed batch has an unreadable record; the store is not partly written, and needs repair', error);
    }
    const parents = new Set<string>();
    items.forEach((item, index) => {
      RecordPaths.validate(item.path);
      const staged = join(commit, item.file); const target = join(this.root, item.path);
      if (fs.existsSync(staged)) {
        fs.mkdirSync(dirname(target), { recursive: true });
        fs.renameSync(staged, target);
        parents.add(dirname(target));
      } else if (!fs.existsSync(target) || sha256(new Uint8Array(fs.readFileSync(target))) !== item.sha256) {
        // The staged file is gone and the target is not what the batch holds. A replaceable path may have been
        // replaced again by a later batch; anything else is damage, and the journal stays for repair.
        if (!RecordPaths.isReplaceable(item.path) || !fs.existsSync(target)) {
          throw StorageError.unavailable(`a committed batch cannot be completed at ${item.path}; its journal is kept`);
        }
      }
      this.onStep('applied', index);
    });
    for (const parent of parents) syncDirectory(parent);
    fs.rmSync(commit, { recursive: true, force: true });
    syncDirectory(this.journal);
    this.onStep('cleaned');
  }

  /**
   * Runs `body` holding the store's lock: the file `.colophon.nosync/lock`, created exclusively, holding this
   * holder's token (its process ID and a random part). A lock whose process is dead is taken over by renaming it away
   * and checking that what was moved is the dead holder's token; anything else is put back. There is no kernel lock
   * here (Node and Bun have none that is portable), so a live holder can still be displaced in the instant between
   * another process's check and its rename. That is why `holding()` is asked again just before a batch's commit point:
   * a displaced holder commits nothing.
   */
  private locked<T>(body: () => T): T {
    const lock = join(this.journal, 'lock');
    const token = `${process.pid}:${randomUUID()}`;
    const read = (path: string): string | undefined => { try { return new TextDecoder().decode(fs.readFileSync(path)); } catch { return undefined; } };
    for (let attempt = 0; ; attempt++) {
      try { writeDurably(lock, new TextEncoder().encode(token)); break; } catch { /* held, or being taken */ }
      const holder = read(lock);
      const pid = holder === undefined ? 0 : Number(holder.split(':')[0]);
      let alive = pid === process.pid;
      if (!alive && pid > 0) { try { process.kill(pid, 0); alive = true; } catch { alive = false; } }
      if (holder !== undefined && pid > 0 && !alive) {
        const grave = join(this.journal, `dead-${randomUUID()}`);
        try { fs.renameSync(lock, grave); } catch { continue; }
        if (read(grave) !== holder) {
          // Not the dead holder's: another process took the lock in between. Give it back unless a third already holds it.
          try { fs.linkSync(grave, lock); } catch { /* someone holds it; the displaced holder finds out in holding() */ }
        }
        fs.rmSync(grave, { force: true });
        continue;
      }
      if (attempt > 400) throw StorageError.unavailable('the record store is in use by another process');
      sleep(5);
    }
    this.token = token;
    try { return body(); } finally {
      this.token = undefined;
      if (read(lock) === token) fs.rmSync(lock, { force: true });
    }
  }
  private token: string | undefined;
  /** Whether this medium still holds the lock it took. */
  private holding(): boolean {
    try { return this.token !== undefined && new TextDecoder().decode(fs.readFileSync(join(this.journal, 'lock'))) === this.token; } catch { return false; }
  }

  changes(listener: () => void): () => void { return this.hints.add(listener); }
}

/** The private files of one device in a folder; each write is a synchronised sibling renamed into place. */
export class FilePrivateStore implements PrivateStore {
  constructor(readonly directory: string) { fs.mkdirSync(directory, { recursive: true }); }
  private path(name: string): string {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/.test(name)) throw StorageError.invalidPath(name);
    return join(this.directory, name);
  }
  async read(name: string): Promise<Uint8Array | undefined> {
    const path = this.path(name);
    if (!fs.existsSync(path)) return undefined;
    return new Uint8Array(fs.readFileSync(path));
  }
  async write(name: string, bytes: Uint8Array): Promise<void> {
    const path = this.path(name);
    const temporary = join(this.directory, `.${name}.${randomUUID()}.tmp`);
    try { writeDurably(temporary, bytes); fs.renameSync(temporary, path); }
    catch (error) { fs.rmSync(temporary, { force: true }); throw StorageError.unavailable(`could not store ${name}`, error); }
    syncDirectory(this.directory);
  }
  async remove(name: string): Promise<void> { fs.rmSync(this.path(name), { force: true }); }
}
