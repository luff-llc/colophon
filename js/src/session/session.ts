import { KeyCustodyError, HomeTransportError, SessionError, StorageError } from './errors.js';
import { keyDescriptorOf, type AsyncKeyProvider } from './keys.js';
import type { AccountMember, Home, SealedSeed } from './records.js';
import type { HomeIssue } from './transport.js';
import {
  emptyNotices, failureMessage, noDuties, phaseUsable, samePhase, SessionRefusal,
  type AccessRequest, type DomainCommand, type HomeFault, type HostDuties, type ObservedRevision, type SessionConfiguration, type SessionNotices,
  type SessionPhase, type SessionSnapshot, type SessionState, type Submission, type WriteReceipt,
} from './types.js';
import { glue, isAccountFault } from './wasm.js';
import { SessionWorker } from './worker.js';

const describe = (error: unknown): string => error instanceof Error ? error.message : String(error);
const sleep = (ms: number, signal: AbortSignal): Promise<void> => new Promise(resolve => {
  if (signal.aborted) { resolve(); return; }
  const timer = setTimeout(done, ms);
  function done(): void { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); }
  signal.addEventListener('abort', done, { once: true });
});

/**
 * The one object a web app holds over one Colophon 0.5 account: it opens the account's records, unlocks this device's
 * member, keeps the engine fresh as the store and the homes change, performs writes with observed revisions, and
 * surfaces what a person must see (pending changes, unseen activations, "this account has no home", update required).
 * Own exactly one per page and account, and call `init()` (the wasm module) before constructing it.
 *
 * Published state is `state`, an immutable value replaced on every change; `subscribe` is told when it is. What the
 * session decides: nothing about the account. Every verdict is the engine's. The twin of the Swift and Kotlin
 * `ColophonSession`, with the same names where JavaScript allows.
 */
export class ColophonSession {
  /** @internal */
  readonly worker: SessionWorker;
  readonly homesConfigured: boolean;
  private current: SessionState;
  private readonly listeners = new Set<(state: SessionState) => void>();
  private restoring: Promise<void> | undefined;
  private usable = false;
  private commandFailureRevision = 0;
  private retryCreate = false;
  private readonly submissions = new Map<string, Submission>();
  /** Aborted by `shutdown`: every loop and every pass in flight ends. */
  private readonly life = new AbortController();
  private syncLoop: AbortController | undefined;
  private dueTimer: ReturnType<typeof setInterval> | undefined;
  private unwatch: (() => void) | undefined;
  private batchTimer: ReturnType<typeof setTimeout> | undefined;
  private checkpointTimer: ReturnType<typeof setTimeout> | undefined;
  private syncTail: Promise<unknown> = Promise.resolve();
  private wakeSync: (() => void) | undefined;
  /** In-progress blob downloads by digest. @internal */
  readonly blobDownloads = new Map<string, { completed: number; total: number }>();

  constructor(configuration: SessionConfiguration) {
    this.worker = new SessionWorker(configuration);
    this.homesConfigured = (configuration.homes ?? []).length > 0;
    this.current = {
      phase: { kind: 'opening' }, revision: 0, namespaceRevisions: {}, members: [], requests: [], context: crypto.randomUUID(), notices: emptyNotices,
      homes: [], duties: noDuties, syncState: this.homesConfigured ? { kind: 'idle' } : { kind: 'disabled' }, homeFaults: [], homeIssues: [],
    };
  }

  /** Everything the session publishes. */
  get state(): SessionState { return this.current; }
  /** Calls `listener` after every change of `state`. Returns the function that stops it. */
  subscribe(listener: (state: SessionState) => void): () => void { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; }
  get phase(): SessionPhase { return this.current.phase; }
  get revision(): number { return this.current.revision; }
  get libraryId(): string | undefined { return this.current.libraryId; }
  get memberId(): string | undefined { return this.current.memberId; }
  get members(): AccountMember[] { return this.current.members; }
  get requests(): AccessRequest[] { return this.current.requests; }
  get notices(): SessionNotices { return this.current.notices; }
  get homes(): Home[] { return this.current.homes; }
  get duties(): HostDuties { return this.current.duties; }
  get homeFaults(): HomeFault[] { return this.current.homeFaults; }
  get homeIssues(): HomeIssue[] { return this.current.homeIssues; }
  get lastError(): string | undefined { return this.current.lastError; }
  get observedRevision(): ObservedRevision { return { context: this.current.context, revision: this.current.revision }; }
  get hasUsableContent(): boolean { return this.usable && phaseUsable(this.current.phase); }
  /** @internal */
  get context(): string { return this.current.context; }

  private set(change: Partial<SessionState>): void {
    this.current = { ...this.current, ...change };
    for (const listener of [...this.listeners]) { try { listener(this.current); } catch { /* a listener's failure is its own */ } }
  }

  /** Stops the background loops, aborts what is in flight and locks the engine. The session is unusable afterwards. */
  shutdown(): void {
    this.life.abort(new SessionError('cancelled'));
    this.stopSync();
    this.unwatch?.(); this.unwatch = undefined;
    clearTimeout(this.batchTimer); clearTimeout(this.checkpointTimer);
    this.worker.lock();
    this.usable = false;
  }

  private scheduleCheckpoint(): void {
    clearTimeout(this.checkpointTimer);
    this.checkpointTimer = setTimeout(() => { this.worker.saveCheckpoint().catch(error => { this.set({ lastError: describe(error) }); }); }, 1000);
  }
  /** Persist the sealed saved state now (it is otherwise saved one second after the last change). */
  async flushCheckpoint(): Promise<void> { clearTimeout(this.checkpointTimer); await this.worker.saveCheckpoint(); }

  /** A shared completion barrier: dependent startup work awaits this before using the session. */
  restore(): Promise<void> { return this.restoring ??= this.runRestore(); }
  private async runRestore(): Promise<void> {
    const lease = this.context;
    this.startWatching();
    try {
      const snapshot = await this.worker.restore();
      if (lease === this.context) this.apply(snapshot);
    } catch (error) { if (lease === this.context) this.fail(error); }
    this.startSyncLoop(); this.startDueLoop();
  }

  refresh(): Promise<void> { return this.refreshKeeping(false); }
  private async refreshKeeping(_preservingCommandFailure: boolean): Promise<void> {
    await this.restore();
    const lease = this.context;
    const failureRevision = this.commandFailureRevision;
    if (this.phase.kind === 'ready') this.set({ phase: { kind: 'refreshing' } });
    try {
      const snapshot = await this.worker.refresh();
      if (lease !== this.context) return;
      // A command that failed while this refresh was in flight keeps its phase.
      if (snapshot.phase.kind === 'ready' && failureRevision !== this.commandFailureRevision) return;
      this.apply(snapshot);
      this.startWatching();
    } catch (error) { if (lease === this.context && failureRevision === this.commandFailureRevision) this.fail(error); }
  }

  /**
   * Creates the account for this device: the owner controller, this device's member, and (spec §18) the configured
   * homes appointed at once, with the creation's own engine (a passkey owner is asked once).
   */
  async create(): Promise<void> {
    await this.restore();
    if (this.phase.kind !== 'noLibrary') return;
    this.retryCreate = true;
    this.set({ phase: { kind: 'creating' } });
    const lease = this.context;
    try {
      const snapshot = await this.worker.create(this.life.signal);
      if (lease !== this.context) return;
      this.apply(snapshot); this.retryCreate = false; this.startWatching(); this.startSyncLoop(); this.startDueLoop();
      if (this.homesConfigured) { try { this.apply(await this.worker.registerRoutes()); } catch { /* shown as an unregistered route */ } }
    } catch (error) {
      if (lease !== this.context) return;
      if (error instanceof SessionError && error.code === 'noHome') { this.retryCreate = false; this.set({ lastError: error.message, phase: { kind: 'noLibrary' } }); }
      else this.fail(error);
    }
  }
  /** Retries the lifecycle action that failed, an interrupted create included. */
  async retry(): Promise<void> {
    await this.refresh();
    if (this.retryCreate && this.phase.kind === 'noLibrary') await this.create();
  }

  /** One write, bound to the revision observed when the person began the action. */
  async perform(command: DomainCommand, observed: ObservedRevision): Promise<WriteReceipt> {
    await this.restore();
    if (observed.context !== this.context) throw new SessionError('destinationChanged');
    try {
      const { receipt, snapshot } = await this.worker.write(command, observed.revision, this.life.signal);
      if (observed.context !== this.context) throw new SessionError('destinationChanged');
      this.apply(snapshot);
      if (this.homesConfigured) this.requestSync();
      return receipt;
    } catch (error) {
      if (error instanceof SessionRefusal) {
        if (observed.context === this.context) { this.apply(error.snapshot); this.set({ lastError: error.error.message }); }
        throw error.error;
      }
      if (observed.context === this.context) this.handleCommandError(error);
      throw error;
    }
  }

  /** Approves a member's request with the owner controller. `termsJson` overrides the requested terms. */
  approve(request: AccessRequest, termsJson?: string): Promise<void> { return this.owner(signal => this.worker.approve(request, termsJson, signal)); }
  revoke(memberId: string): Promise<void> { return this.owner(signal => this.worker.revoke(memberId, signal)); }
  /** Leaves locally; does not revoke the member or delete the person's records. */
  async leave(): Promise<void> {
    await this.restore(); await this.worker.leave(); this.stopSync(); this.invalidateContext(); this.set({ phase: { kind: 'noLibrary' } });
  }
  /** A revoked identity needs fresh keys. */
  async rejoin(keys: AsyncKeyProvider): Promise<void> {
    await this.restore(); this.invalidateContext(); this.set({ phase: { kind: 'opening' } });
    const lease = this.context;
    try { const s = await this.worker.rejoin(keys); if (lease === this.context) { this.apply(s); this.startWatching(); this.startSyncLoop(); } }
    catch (error) { if (lease === this.context) this.fail(error); }
  }
  /** Takes a request that arrived out of band (a file, a code) and shows it for approval. */
  importRequest(data: Uint8Array): Promise<void> { return this.owner(() => this.worker.importRequest(data)); }
  /** This device's own signed membership request, to hand to an approver. */
  async exportRequest(): Promise<Uint8Array> { await this.restore(); return this.worker.exportRequest(); }

  /** A bounded core query (`query_json`), fenced against namespace and identity changes. Returns the value's JSON. */
  async query(namespace: string, name: string, argumentsJson = '{}'): Promise<string> {
    await this.restore();
    if (!this.hasUsableContent) throw new SessionError('notReady');
    try { return this.worker.query(namespace, name, argumentsJson); } catch (error) { this.handleCommandError(error); throw error; }
  }
  /** The namespace's fold as the engine reports it (`view_json`, `{"ok":...,"value":...}`), for screens and tests. */
  async view(namespace: string): Promise<string> {
    await this.restore();
    if (!this.hasUsableContent) throw new SessionError('notReady');
    return this.worker.view(namespace);
  }
  /** The verified history as the engine reports it (JSON). */
  async ledger(): Promise<string> { await this.restore(); return this.worker.ledger(); }

  // Adding a device, pending changes

  /** Adds a controller key (a second device's owner key, a passkey, a security key). The owner confirms. */
  async addController(key: AsyncKeyProvider, label: string, roles: glue.ControllerRole[] = [glue.ControllerRole.Approve], immediate = true): Promise<void> {
    const descriptor = await keyDescriptorOf(key);
    return this.owner(signal => this.worker.addController(descriptor, label, roles, immediate ? glue.AddMode.Immediate : glue.AddMode.Transition, key, signal));
  }
  /** The existing device's half of "add a device": seals the vault seed to the new device. */
  async transferSeed(pairing: glue.AccountPairing): Promise<SealedSeed> { await this.restore(); return this.worker.transferSeed(pairing, this.life.signal); }
  /** The new device's half: takes the sealed seed and builds this controller's own slot. */
  acceptSeedTransfer(key: glue.PairingTransferKey, pairing: glue.AccountPairing, sealed: SealedSeed, label: string): Promise<void> {
    return this.owner(signal => this.worker.acceptSeedTransfer(key, pairing, sealed, label, signal));
  }
  /** The removal follow-up (§17.5, `duties.removals`): revokes and removes in one action what a removed key admitted. */
  removeFollowUp(seq: bigint): Promise<void> { return this.owner(signal => this.worker.removeFollowUp(seq, signal)); }
  /** The person keeps what a removed key admitted; the card is not shown again. */
  keepFollowUp(seq: bigint): Promise<void> { return this.owner(() => this.worker.keepFollowUp(seq)); }
  /** One call to veto a pending transition (§17.5): signs, stores, and submits to every home until each receipted it or 300 s passed. */
  async veto(transition: string): Promise<void> {
    await this.owner(signal => this.worker.veto(transition, signal));
    await this.submitUntilReceipted(transition, 'veto');
  }
  /** Proposes a change to the account (spec §8.7: homes, keyring, policy) signed with the owner's keys, and submits it. Returns its digest. */
  proposeTransition(changeJson: string): Promise<string> { return this.submitted('transition', signal => this.worker.submitTransition(changeJson, signal)); }
  /** Signs a dead transition this device signed again and submits the new one. */
  resign(transition: string): Promise<string> { return this.submitted('transition', signal => this.worker.resign(transition, signal)); }
  /** Suspends `key` while `transition` is pending (§8.7), and submits it like a veto. */
  suspendKey(key: string, transition: string): Promise<string> { return this.submitted('suspend', signal => this.worker.suspend(key, transition, signal)); }
  private async submitted(kind: Submission['kind'], body: (signal: AbortSignal) => Promise<{ digest: string; snapshot: SessionSnapshot }>): Promise<string> {
    await this.restore();
    let digest: string;
    try { const done = await body(this.life.signal); this.apply(done.snapshot); digest = done.digest; }
    catch (error) { this.handleCommandError(error); throw error; }
    await this.submitUntilReceipted(digest, kind);
    return digest;
  }
  /** Records that the person saw one activation. A pending transition stays until it is vetoed, activates or is dead. */
  async acknowledgeActivation(seq: bigint): Promise<void> {
    try { this.apply(await this.worker.acknowledgeActivation(seq)); } catch (error) { this.set({ lastError: describe(error) }); }
  }
  /** How many homes hold a verified receipt for a transition, out of how many the account names. */
  receipts(object: string): { receipted: number; homes: number } { return this.worker.receipts(object); }

  private async owner(body: (signal: AbortSignal) => Promise<SessionSnapshot>): Promise<void> {
    await this.restore();
    const lease = this.context;
    try { const s = await body(this.life.signal); if (lease === this.context) this.apply(s); }
    catch (error) { if (lease === this.context) this.handleCommandError(error); throw error; }
  }

  /** §17.5 submission: exchanges with every home, repeated until each receipted `object` or `deadlineMs` passed. */
  async submitUntilReceipted(object: string, kind: Submission['kind'], deadlineMs = 300_000): Promise<void> {
    if (!this.homesConfigured || object === '') return;
    const end = performance.now() + deadlineMs;
    let wait = 500;
    let last: Submission = { object, kind, receipted: 0, homes: this.homes.length, finished: false };
    this.record(last);
    while (performance.now() < end && !this.life.signal.aborted) {
      await this.syncNow();
      try {
        const counts = this.worker.receipts(object);
        last = { object, kind, receipted: counts.receipted, homes: counts.homes, finished: false };
        this.record(last);
        if (counts.homes === 0 || counts.receipted >= counts.homes) break;
      } catch { /* not ready now: try again */ }
      await sleep(Math.min(wait, Math.max(0, end - performance.now())), this.life.signal);
      wait = Math.min(wait * 2, 15_000);
    }
    this.record({ ...last, finished: true });
  }
  private sortedSubmissions(): Submission[] { return [...this.submissions.values()].sort((a, b) => (a.object < b.object ? -1 : a.object > b.object ? 1 : 0)); }
  private record(s: Submission): void {
    this.submissions.set(s.object, s);
    this.set({ duties: { ...this.duties, submissions: this.sortedSubmissions() } });
  }

  // Lock

  /**
   * Hides the content and drops every secret the engine holds, at once: it does not wait for an operation in flight
   * or for a key prompt nobody answers (both end as `Locked` or `cancelled`). Call it when the page is hidden.
   */
  lock(): void {
    const snapshot = this.worker.lock();
    this.usable = false;
    this.apply(snapshot);
  }
  async unlock(): Promise<void> {
    const lease = this.context;
    try { const s = await this.worker.unlock(); if (lease === this.context) { this.apply(s); this.startWatching(); } }
    catch (error) { if (lease === this.context) this.fail(error); }
  }

  // Exchange with the homes

  /**
   * Runs one exchange with every home now and refreshes when something arrived. False when it failed. Passes never
   * overlap: callers queue. Aborting `signal` ends the pass in flight; the engine is left ready for the next one.
   */
  syncNow(signal?: AbortSignal): Promise<boolean> {
    if (!this.homesConfigured) return Promise.resolve(false);
    const run = this.syncTail.then(() => this.runSync(signal ? AbortSignal.any([signal, this.life.signal]) : this.life.signal));
    this.syncTail = run.catch(() => {});
    return run;
  }
  private async runSync(signal: AbortSignal): Promise<boolean> {
    await this.restore();
    if (signal.aborted) return false;
    this.set({ syncState: { kind: 'syncing' } });
    try {
      const result = await this.worker.exchange(signal);
      this.set({ homeFaults: result.faults, homeIssues: result.issues, lastSyncedMs: Date.now(), syncState: result.unauthorized ? { kind: 'unauthorized' } : { kind: 'idle' } });
      if (result.changed || this.phase.kind !== 'ready') await this.refreshKeeping(true);
      else { try { this.apply(await this.worker.currentSnapshot()); } catch { /* the next refresh shows it */ } }
      return !result.unauthorized;
    } catch (error) {
      if (error instanceof SessionError && error.code === 'cancelled') { this.set({ syncState: { kind: 'idle' } }); return false; }
      if (error instanceof HomeTransportError) { this.set({ syncState: { kind: 'offline', reason: error.message } }); return false; }
      this.set({ syncState: { kind: 'error', reason: describe(error) } });
      if (isAccountFault(error) && (error.kind === 'NewerFormat' || error.kind === 'Locked')) this.fail(error);
      return false;
    }
  }

  /** Wakes the background exchange loop (a local change, the network came back). */
  requestSync(): void { this.wakeSync?.(); }
  /** Stops the background exchange. Local storage and the session keep working. */
  stopSync(): void {
    this.syncLoop?.abort(); this.syncLoop = undefined;
    clearInterval(this.dueTimer); this.dueTimer = undefined;
  }
  private startSyncLoop(): void {
    if (!this.homesConfigured || this.syncLoop || this.life.signal.aborted) return;
    const loop = new AbortController();
    this.syncLoop = loop;
    const signal = AbortSignal.any([loop.signal, this.life.signal]);
    void (async () => {
      let failures = 0;
      while (!signal.aborted) {
        const ok = this.phase.kind === 'locked' ? true : await this.syncNow(signal);
        failures = ok ? 0 : failures + 1;
        // Success: poll after duties.pollIntervalMs or when a local change arrives. Failure: capped, jittered backoff.
        const wait = ok ? this.duties.pollIntervalMs : Math.min(60, 2 ** Math.max(0, failures - 1)) * (0.5 + Math.random() / 2) * 1000;
        const woken = new AbortController();
        this.wakeSync = () => woken.abort();
        await sleep(wait, AbortSignal.any([signal, woken.signal]));
      }
    })();
  }
  /** `record_due` on a schedule: transitions that came due are recorded without waiting for a pass. */
  private startDueLoop(): void {
    if (this.dueTimer !== undefined || this.life.signal.aborted) return;
    this.dueTimer = setInterval(() => {
      if (this.phase.kind !== 'ready') return;
      this.worker.recordDue().then(s => this.apply(s), () => {});
    }, 60_000);
    // A timer must not keep a Node or Bun process alive.
    (this.dueTimer as { unref?: () => void }).unref?.();
  }

  private startWatching(): void {
    if (this.unwatch || this.life.signal.aborted) return;
    this.unwatch = this.worker.storage.changes(() => this.externalChange());
  }
  /** One trailing batch coalesces bursts of store changes. */
  private externalChange(): void {
    if (this.batchTimer !== undefined) return;
    this.batchTimer = setTimeout(() => { this.batchTimer = undefined; void this.refreshKeeping(true); }, 75);
  }
  /** A deterministic barrier for hosts and tests. */
  async flushExternalChanges(): Promise<void> { clearTimeout(this.batchTimer); this.batchTimer = undefined; await this.refreshKeeping(true); }

  private apply(s: SessionSnapshot): void {
    if (s.revision < this.current.revision) return;
    if (this.homesConfigured && (s.revision !== this.current.revision || !samePhase(s.phase, this.current.phase))) this.requestSync();
    const lost = !phaseUsable(s.phase);
    this.set({
      phase: s.phase, revision: s.revision, namespaceRevisions: s.namespaceRevisions, libraryId: s.libraryId ?? this.current.libraryId,
      memberId: s.memberId ?? this.current.memberId, members: s.members, requests: s.requests, notices: s.notices, homes: s.homes,
      duties: { ...s.duties, submissions: this.sortedSubmissions() }, lastError: undefined,
    });
    this.usable = !lost;
    if (!lost) this.scheduleCheckpoint();
  }
  private invalidateContext(): void {
    this.usable = false;
    this.set({ context: crypto.randomUUID(), members: [], requests: [], libraryId: undefined, memberId: undefined, notices: emptyNotices });
  }
  private handleCommandError(error: unknown): void {
    if (isAccountFault(error) && error.kind === 'Denied') {
      // A refused command does not decide the phase: the engine's access check does, on the next refresh.
      this.set({ lastError: error.message });
      void this.refresh();
    } else if (isAccountFault(error) || error instanceof StorageError || error instanceof KeyCustodyError) {
      this.commandFailureRevision++; this.fail(error);
    } else this.set({ lastError: describe(error) });
  }
  private fail(error: unknown): void {
    this.set({ lastError: describe(error) });
    let phase: SessionPhase;
    if (isAccountFault(error)) {
      if (error.kind === 'NewerFormat') phase = { kind: 'updateRequired' };
      else if (error.kind === 'Denied') phase = error.reason === 'notReadable' || error.reason === 'unavailable' ? { kind: 'unavailable', reason: error.detail } : { kind: 'denied' };
      else if (error.kind === 'Host' || error.kind === 'Unavailable' || error.kind === 'Reentered' || error.kind === 'Integrity') { this.set({ phase: { kind: 'retry' } }); return; }
      else if (error.kind === 'Locked') phase = { kind: 'locked' };
      else phase = { kind: 'failed', failure: { kind: 'other', detail: error.message || error.code } };
    } else if (error instanceof KeyCustodyError) {
      // A cancelled prompt is not a broken key: the session stays where it was.
      if (error.outcome === 'cancelled') return;
      phase = { kind: 'failed', failure: { kind: 'keysUnavailable', detail: error.message } };
    } else if (error instanceof StorageError) {
      this.set({ phase: error.reason === 'unavailable' && error.message.includes('download pending') ? { kind: 'waitingForDownload' } : { kind: 'retry' } }); return;
    } else if (error instanceof SessionError && error.code === 'cancelled') {
      return;
    } else phase = { kind: 'failed', failure: { kind: 'other', detail: describe(error) } };
    this.set({ phase });
    this.usable = false;
  }
}

export { failureMessage };
