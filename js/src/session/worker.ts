import { HomeTransportError, raceAbort, SessionError, StorageError, throwIfAborted } from './errors.js';
import { ColophonEngine, listed, type Identity } from './engine.js';
import { descriptorView, KeyCustody, keyDescriptorOf, keyIdOf, toPrfAnswers, toSignatures, type AsyncKeyProvider } from './keys.js';
import type { MediumEntry, RecordMedium } from './medium.js';
import { SavedStateCache, SessionJournal, type SavedStateData } from './private.js';
import type {
  AccountDenial, AccountMember, CallNeed, Controller, Created, EpochAgreement, ExchangeStep, HistoryReport, Home, KeyDescriptor, Notices, Policy,
  PrfRequest, RemovalFollowUp, Report, RequestInfo, SealedSeed, SigningStep, SlotInfo, Standing, Status, Store, UnlockInput, Written, NamespaceRevision,
} from './records.js';
import { closeAll, withEntropy } from './secrets.js';
import { HomeLimits, type HomeAnswer, type HomeIssue, type HomeProblem, type HomeRequest } from './transport.js';
import {
  ConfiguredHome, emptyNotices, noDuties, noticesFrom, pairingCode, phaseUsable, samePhase, SessionRefusal,
  type AccessRequest, type DeadTransition, type DomainCommand, type HomeFault, type HostDuties, type RemovalCard, type RouteState,
  type SessionConfiguration, type SessionNotices, type SessionPhase, type SessionSnapshot, type WriteReceipt,
} from './types.js';
import { glue, isAccountFault, makeFault, plain } from './wasm.js';

const NOTHING = new Uint8Array(0);
const methodName = (m: glue.HttpMethod): 'GET' | 'POST' | 'PUT' => m === glue.HttpMethod.Get ? 'GET' : m === glue.HttpMethod.Post ? 'POST' : 'PUT';
const base = (text: string): string => text.endsWith('/') ? text.slice(0, -1) : text;
const trimSlashes = (text: string): string => text.replace(/^\/+|\/+$/g, '');
const keepEverything = (): glue.RevokeKeep => new glue.RevokeKeep(glue.KeepMode.Everything, [], []);

/** One operation at a time, in arrival order, across awaits. */
class Gate {
  private tail: Promise<void> = Promise.resolve();
  run<T>(body: () => Promise<T>): Promise<T> {
    const result = this.tail.then(body);
    this.tail = result.then(() => {}, () => {});
    return result;
  }
}

class HomeProblemError extends Error {
  constructor(readonly problem: HomeProblem) { super(problem.kind); this.name = 'HomeProblemError'; }
}

export interface ExchangeResult {
  passes: number; faults: HomeFault[]; issues: HomeIssue[]; changed: boolean; unauthorized: boolean;
  /** A pass that did not finish (the engine still waited after its one recovery): the exchange failed. */
  failed: boolean;
}

/**
 * Every engine call, key ceremony, store operation and HTTP request of a session. The gate serialises complete
 * operations across awaits, including a passkey prompt and the persistence of the stores a finish returned: the
 * engine is never ahead of the store when another operation reads it. A port of the Swift and Kotlin `SessionWorker`,
 * with the same names.
 *
 * Cancellation is by `AbortSignal` and is checked only between steps. What must not be cut in half has no check inside
 * it: a finish and the persistence of its stores, an exchange answer and its stores, `record_due` and its stores, and
 * the abort of a pass.
 */
export class SessionWorker {
  readonly homes: ConfiguredHome[];
  readonly libraryNamespaces: string[];
  readonly access: ('read' | 'write')[];
  private readonly gate = new Gate();
  private memberKeys: AsyncKeyProvider;
  private engine: ColophonEngine | undefined;
  private memberCustody: KeyCustody | undefined;
  accountId: string | undefined;
  memberId: string | undefined;
  private journal = new SessionJournal();
  private journalLoaded = false;
  private lockedFlag = false;
  private revision = 0;
  private lastRevisions: Record<string, bigint> = {};
  private lastPhase: SessionPhase = { kind: 'opening' };
  private readonly cache: SavedStateCache;
  /** Aborted by `lock`: every key ceremony in flight ends, so a prompt nobody answers never holds the session. */
  private ceremonies = new AbortController();
  /** Owner engines open right now (each lives for one owner operation), so `lock` locks them too. */
  private readonly openOwners = new Set<ColophonEngine>();
  /** Blob writers in use (each holds an epoch key), so `lock` frees them too. */
  private readonly openWriters = new Set<{ free(): void }>();
  /** The longest one exchange with one home may take (tests shorten it). */
  exchangeTimeMs: number;

  constructor(readonly configuration: SessionConfiguration) {
    this.homes = (configuration.homes ?? []).map(h => new ConfiguredHome(h));
    this.libraryNamespaces = configuration.libraryNamespaces ?? configuration.namespaces;
    this.access = configuration.access ?? ['read', 'write'];
    this.memberKeys = configuration.keys;
    this.cache = new SavedStateCache(configuration.privateStore);
    this.exchangeTimeMs = configuration.exchangeTimeMs ?? HomeLimits.exchangeTimeMs;
  }

  private get nowMs(): number { return (this.configuration.now ?? Date.now)(); }
  get storage(): RecordMedium { return this.configuration.medium; }
  private gated<T>(body: () => Promise<T>): Promise<T> { return this.gate.run(body); }
  /** The signal of an operation that may wait on a person: the caller's, and the session's lock. */
  private waiting(signal?: AbortSignal): AbortSignal { return signal ? AbortSignal.any([signal, this.ceremonies.signal]) : this.ceremonies.signal; }

  // Storage

  private async loadJournal(): Promise<void> {
    if (this.journalLoaded) return;
    const bytes = await this.configuration.privateStore.read('session.json');
    this.journal = bytes ? SessionJournal.decode(bytes) : new SessionJournal();
    this.journalLoaded = true;
  }
  private saveJournal(): Promise<void> { return this.configuration.privateStore.write('session.json', this.journal.encode()); }

  /** Persists the stores of one finished step, all or none. If the store refuses, the engine is ahead of it: discard it. */
  private async persist(stores: readonly Store[], on?: ColophonEngine): Promise<void> {
    if (stores.length === 0) return;
    try {
      await this.storage.write(stores.map(s => ({ path: s.path, bytes: s.bytes })));
    } catch (error) {
      if (on && on !== this.engine) on.discard(); else { this.engine?.discard(); this.engine = undefined; }
      throw error;
    }
  }
  /** Persists a finish's stores in the same step as the finish (`ColophonEngine.execute`). */
  private persistOn(on?: ColophonEngine): (written: Written) => Promise<void> { return written => this.persist(written.stores, on); }

  // Opening

  restore(): Promise<SessionSnapshot> { return this.gated(() => this.reconcile()); }
  refresh(): Promise<SessionSnapshot> { return this.gated(() => this.reconcile()); }

  /**
   * Locks at once, whatever holds the gate: the member engine and every open owner engine are locked (their keys and
   * opened plaintext overwritten) and every key ceremony in flight is aborted, without waiting for the operation in
   * flight, which then fails as `Locked` or `cancelled`. Synchronous: nothing can delay it.
   */
  lock(): SessionSnapshot {
    this.lockedFlag = true;
    const engine = this.engine;
    this.engine = undefined;
    engine?.lock();
    for (const owner of [...this.openOwners]) owner.lock();
    this.openOwners.clear();
    // A blob writer holds an epoch key: freed now, so it encrypts nothing more (`blobWriter` refuses a freed one).
    for (const writer of [...this.openWriters]) { try { writer.free(); } catch { /* already finished */ } }
    this.openWriters.clear();
    this.ceremonies.abort(new SessionError('cancelled'));
    this.ceremonies = new AbortController();
    return this.snapshot({ kind: 'locked' });
  }
  unlock(): Promise<SessionSnapshot> { return this.gated(() => { this.lockedFlag = false; return this.reconcile(); }); }
  /**
   * A blob writer the session can end. `use` runs one call on it and refuses (`Locked`) once the session was locked or
   * the writer released; `release` frees it.
   */
  blobWriter(writer: glue.AccountBlobWriter): { use<T>(body: (writer: glue.AccountBlobWriter) => T): T; release(): void } {
    if (this.lockedFlag) { try { writer.free(); } catch { /* freed */ } throw makeFault('Locked', 'locked', 'the session was locked'); }
    this.openWriters.add(writer);
    return {
      use: body => {
        if (!this.openWriters.has(writer)) throw makeFault('Locked', 'locked', 'the session was locked while a blob was being stored');
        return body(writer);
      },
      release: () => { if (this.openWriters.delete(writer)) { try { writer.free(); } catch { /* finished */ } } },
    };
  }
  private tracked(owner: ColophonEngine): ColophonEngine {
    if (this.lockedFlag) { owner.lock(); throw makeFault('Locked', 'locked', 'the session was locked'); }
    this.openOwners.add(owner);
    return owner;
  }
  private release(owner: ColophonEngine): void { owner.lock(); this.openOwners.delete(owner); }

  private async reconcile(signal?: AbortSignal): Promise<SessionSnapshot> {
    await this.loadJournal();
    if (this.journal.left) return this.snapshot({ kind: 'noLibrary' });
    if (this.lockedFlag) return this.snapshot({ kind: 'locked' });
    const entries = this.storage.listing();
    if (!entries.some(e => e.path.startsWith('authority/'))) {
      if (this.journal.account !== undefined) throw StorageError.unavailable('Selected library is unavailable');
      return this.snapshot({ kind: 'noLibrary' });
    }
    try {
      if (!this.engine) await this.openEngine(entries, signal); else await this.refreshEngine(entries, signal);
    } catch (error) {
      if (isAccountFault(error) && error.kind === 'NewerFormat') { this.engine?.discard(); this.engine = undefined; return this.snapshot({ kind: 'updateRequired' }); }
      if (isAccountFault(error) && error.kind === 'Integrity') { this.engine?.discard(); this.engine = undefined; }
      throw error;
    }
    return this.build();
  }

  private discoverAccount(entries: readonly MediumEntry[]): string {
    const medium = this.storage;
    const objects = (prefix: string): glue.ByteString[] => entries.filter(e => e.path.startsWith(prefix)).map(e => new glue.ByteString(medium.read(e.path)));
    const pending = [...objects('transitions/'), ...objects('vetoes/'), ...objects('receipts/')];
    const report = plain<HistoryReport>(glue.account_verify_history(new glue.AuthorityObjects(objects('authority/'), pending, objects('heads/'), objects('predecessor/')), BigInt(this.nowMs)));
    if (report.kind === glue.StatusKind.NewerFormat) throw makeFault('NewerFormat', report.code, report.detail ?? '');
    if (report.account === undefined) throw makeFault('Malformed', report.code, report.detail ?? "the library's history does not verify");
    return report.account;
  }

  private async openEngine(entries: readonly MediumEntry[], signal?: AbortSignal): Promise<void> {
    const account = this.journal.account ?? this.discoverAccount(entries);
    const keyId = await keyIdOf(this.memberKeys);
    this.memberId = keyId;
    this.memberCustody = await KeyCustody.of([this.memberKeys]);
    const saved = await this.cache.load(account);
    const key = await this.configuration.deviceSecrets.key(account);
    let opened: ColophonEngine;
    try {
      opened = ColophonEngine.open({ medium: this.storage, listing: this.storage.listing(), identity: { kind: 'member', id: keyId }, account,
        namespaces: this.libraryNamespaces, saved, deviceKey: key, nowMs: this.nowMs });
    } finally { key.close(); }
    if (this.lockedFlag) { opened.lock(); throw makeFault('Locked', 'locked', 'the session was locked while it opened'); }
    this.engine = opened; this.accountId = account;
    // A member that is not approved yet holds no keys; the records can still be read and the exchange can still bring
    // the approval in. A member opens its epoch shares in `unlockIfPossible`.
    if (plain<Standing>(opened.run(e => e.me())).kind !== glue.StandingKind.Member) plain(opened.run(e => e.load()));
    if (this.journal.account === undefined) { this.journal.account = account; await this.saveJournal(); }
    await this.unlockIfPossible(signal);
  }

  private async refreshEngine(entries: readonly MediumEntry[], signal?: AbortSignal): Promise<void> {
    const engine = this.engine;
    if (!engine) return;
    plain(engine.run(e => e.advance(BigInt(this.nowMs))));
    plain(engine.run(e => e.refresh(listed(entries))));
    for (const written of plain<Written[]>(engine.run(e => e.record_due()))) await this.persist(written.stores);
    await this.unlockIfPossible(signal);
  }

  /** A member opens its epoch shares with its own agreement key: at first, and whenever new epochs were sealed to it. */
  private async unlockIfPossible(signal?: AbortSignal): Promise<void> {
    const engine = this.engine; const custody = this.memberCustody;
    if (!engine || !custody) return;
    if (plain<Standing>(engine.run(e => e.me())).kind !== glue.StandingKind.Member) return;
    const agreements = plain<EpochAgreement[]>(engine.run(e => e.begin_unlock_epochs()));
    if (agreements.length === 0) return;
    engine.finishUnlockEpochs(await custody.answerEpochs(agreements, this.waiting(signal)));
  }

  saveCheckpoint(): Promise<void> {
    return this.gated(async () => {
      const engine = this.engine; const account = this.accountId;
      if (!engine || account === undefined || this.lastPhase.kind !== 'ready') return;
      plain(engine.run(e => e.verify_batch(128n)));
      const state = plain<SavedStateData>(engine.run(e => withEntropy(32, seed => e.save(seed))));
      await this.cache.save(account, state);
    });
  }

  // Snapshot

  private snapshot(phase: SessionPhase, more: Partial<Omit<SessionSnapshot, 'phase' | 'revision'>> = {}): SessionSnapshot {
    const revisions = more.namespaceRevisions ?? {};
    const sameRevisions = Object.keys(revisions).length === Object.keys(this.lastRevisions).length
      && Object.entries(revisions).every(([k, v]) => this.lastRevisions[k] === v);
    if (!samePhase(phase, this.lastPhase) || !sameRevisions) this.revision++;
    this.lastPhase = phase; this.lastRevisions = revisions;
    return { phase, revision: this.revision, namespaceRevisions: revisions, libraryId: this.accountId, memberId: this.memberId,
      members: more.members ?? [], requests: more.requests ?? [], notices: more.notices ?? emptyNotices, homes: more.homes ?? [], duties: more.duties ?? noDuties,
      setupPending: this.journal.setupPending };
  }

  private async build(): Promise<SessionSnapshot> {
    const engine = this.engine;
    if (!engine) return this.snapshot(this.lockedFlag ? { kind: 'locked' } : { kind: 'noLibrary' });
    const standing = plain<Standing>(engine.run(e => e.me()));
    const status = plain<Status>(engine.run(e => e.status()));
    if (status.kind === glue.StatusKind.NewerFormat) return this.snapshot({ kind: 'updateRequired' });
    const members = plain<AccountMember[]>(engine.run(e => e.members()));
    const requests = this.pendingRequests(members);
    const homes = plain<Home[]>(engine.run(e => e.homes()));
    let phase: SessionPhase;
    if (this.journal.setupPending) {
      // This device made the account and its first setup did not finish: nothing waits for an approval nobody can give.
      return this.snapshot({ kind: 'failed', failure: { kind: 'other', detail: 'Setting up this library was interrupted. Retry to finish it.' } }, { members, requests, homes });
    }
    if (standing.kind === glue.StandingKind.Unknown) {
      await this.ensureOwnRequest();
      return this.snapshot({ kind: 'waitingForApproval', code: pairingCode(this.memberId ?? '') }, { members, requests, homes });
    } else if (standing.kind === glue.StandingKind.Controller) {
      phase = { kind: 'failed', failure: { kind: 'other', detail: 'this identity is a controller, not a member' } };
    } else if (standing.member?.revokedAt !== undefined) {
      phase = { kind: 'denied' };
    } else {
      phase = { kind: 'ready' };
      for (const namespace of this.libraryNamespaces) {
        const denial = plain<AccountDenial | undefined>(engine.run(e => e.access(namespace)));
        if (!denial) continue;
        phase = denial.reason === glue.AccountDenialReason.NotReadable || denial.reason === glue.AccountDenialReason.Unavailable
          ? { kind: 'unavailable', reason: denial.detail } : { kind: 'denied' };
        break;
      }
    }
    const ready = phase.kind === 'ready';
    const revisions: Record<string, bigint> = {};
    if (ready) {
      for (const r of plain<NamespaceRevision[]>(engine.run(e => e.revisions()))) if (this.libraryNamespaces.includes(r.namespace)) revisions[r.namespace] = r.revision;
      revisions['colophon.authority'] = engine.run(e => e.head_seq());
    }
    const notices = await this.currentNotices();
    const duties = await this.hostDuties(notices, homes);
    return this.snapshot(phase, { members, requests, notices, namespaceRevisions: revisions, homes, duties });
  }

  private async ownerId(): Promise<string | undefined> { try { return await keyIdOf(this.configuration.ownerController); } catch { return undefined; } }
  private async localKeyIds(): Promise<string[]> {
    const ids: string[] = [];
    if (this.memberId !== undefined) ids.push(this.memberId);
    const owner = await this.ownerId();
    if (owner !== undefined) ids.push(owner);
    if (this.configuration.recoveryKeys) { try { ids.push(await keyIdOf(this.configuration.recoveryKeys)); } catch { /* not held now */ } }
    return ids;
  }
  private rawNotices(engine: ColophonEngine, keys: string[]): Notices {
    return plain<Notices>(engine.run(e => e.notices(this.journal.shownSeq, [...this.journal.shownTransitions], keys)));
  }

  private async currentNotices(): Promise<SessionNotices> {
    const engine = this.engine;
    if (!engine) return emptyNotices;
    const keys = await this.localKeyIds();
    const owner = await this.ownerId();
    const raw = this.rawNotices(engine, keys);
    // The member engine that reads the account is not a controller, so the engine reports nothing as vetoable to it.
    // The one-tap veto is the owner controller's: offered when the owner key is a controller with `control` or
    // `recover` and the deadline the engine computed has not passed.
    const controllers = plain<Controller[]>(engine.run(e => e.controllers()));
    const mine = controllers.find(c => c.id === owner);
    const ownerMayVeto = mine !== undefined && (mine.roles.includes(glue.ControllerRole.Control) || mine.roles.includes(glue.ControllerRole.Recover));
    const now = BigInt(this.nowMs);
    const pending = raw.pending.map(p => ({ ...p, vetoable: ownerMayVeto && p.fullSet !== true && p.vetoDeadlineMs !== undefined && now <= p.vetoDeadlineMs }));
    const activations = raw.activations.filter(a => !this.journal.seenActivations.has(a.seq));
    return noticesFrom({ ...raw, pending, activations });
  }

  /** Marks one activation seen, and nothing else (a pending transition is never dismissed by it). */
  acknowledgeActivation(seq: bigint): Promise<SessionSnapshot> {
    return this.gated(async () => {
      const engine = this.engine;
      if (!engine) return this.snapshot(this.lastPhase);
      await this.loadJournal();
      this.journal.seenActivations.add(seq);
      let floor = this.journal.shownSeq;
      const activations = this.rawNotices(engine, await this.localKeyIds()).activations.sort((a, b) => (a.seq < b.seq ? -1 : a.seq > b.seq ? 1 : 0));
      for (const activation of activations) {
        if (!this.journal.seenActivations.has(activation.seq)) break;
        if (activation.seq > floor) floor = activation.seq;
      }
      this.journal.shownSeq = floor;
      this.journal.seenActivations = new Set([...this.journal.seenActivations].filter(s => s > floor));
      await this.saveJournal();
      return this.build();
    });
  }

  // Host duties (§17.5)

  private async hostDuties(notices: SessionNotices, homes: Home[]): Promise<HostDuties> {
    const engine = this.engine;
    if (!engine) return noDuties;
    const controllers = plain<Controller[]>(engine.run(e => e.controllers()));
    const policy = plain<Policy>(engine.run(e => e.policy()));
    const quorum = Math.max(1, Number(policy.headQuorum));
    const now = BigInt(this.nowMs);
    const deadTransitions: DeadTransition[] = [];
    if (homes.length > 0) {
      for (const pending of notices.pending) {
        if (now <= pending.issuedMs + 300_000n) continue;
        const receipted = engine.run(e => e.receipted_by(pending.digest)).length;
        if (receipted < quorum) deadTransitions.push({ digest: pending.digest, receipted, quorum, canResign: this.journal.signedChanges.has(pending.digest) });
      }
    }
    const routes: RouteState[] = homes.map(home => {
      const configured = this.transportFor(home);
      const reaches = new Set((configured?.deliveryRoutes ?? []).map(r => r.reaches));
      const label = home.label;
      if (reaches.size < 2) return { home: home.id, label, registered: false,
        detail: 'This app has fewer than two ways to reach you about changes to your account (on different devices or services). Add a second one.' };
      if (this.journal.routes.get(home.id) === true) return { home: home.id, label, registered: true, detail: '' };
      return { home: home.id, label, registered: false,
        detail: this.journal.routes.get(home.id) === false || !configured?.configuration.registerRoutes
          ? `${label} does not offer notices yet, so it cannot tell you about a pending change. This app checks for them itself.`
          : `Your ways to be reached are not registered with ${label} yet.` };
    });
    const follow = plain<RemovalFollowUp[]>(engine.run(e => e.removal_follow_up())).filter(r => !this.journal.answeredRemovals.has(r.seq));
    let removals: RemovalCard[] = [];
    if (follow.length > 0) {
      const memberLabels = new Map(plain<AccountMember[]>(engine.run(e => e.members())).map(m => [m.id, m.label]));
      const labels = new Map(controllers.map(c => [c.id, c.label]));
      removals = follow.map(r => ({ seq: r.seq, removed: r.removed,
        members: r.members.map(id => ({ id, label: memberLabels.get(id) ?? id.slice(0, 8) })),
        controllers: r.controllers.map(id => ({ id, label: labels.get(id) ?? id.slice(0, 8) })) }));
    }
    const delay = Number(policy.recoveryDelay / 6n);
    return {
      soleDevice: controllers.filter(c => c.roles.includes(glue.ControllerRole.Control) && !c.suspended).length <= 1,
      routes, submissions: [], deadTransitions, removals,
      homeLabels: Object.fromEntries(homes.map(h => [h.id, h.label])),
      pollIntervalMs: notices.pending.length === 0 ? Math.max(60, delay) * 1000 : 15_000,
    };
  }

  /** Registers this host's delivery routes with every home that offers it and has not got them (§17.5). */
  registerRoutes(): Promise<SessionSnapshot> {
    return this.gated(async () => {
      const engine = this.engine; const account = this.accountId;
      if (!engine || account === undefined) return this.snapshot(this.lastPhase);
      await this.loadJournal();
      for (const home of plain<Home[]>(engine.run(e => e.homes()))) {
        if (this.journal.routes.get(home.id) === true) continue;
        const configured = this.transportFor(home);
        if (!configured || new Set(configured.deliveryRoutes.map(r => r.reaches)).size < 2) continue;
        const register = configured.configuration.registerRoutes;
        this.journal.routes.set(home.id, register ? await register(account, configured.deliveryRoutes) : false);
      }
      await this.saveJournal();
      return this.build();
    });
  }

  /** Signs a transition with the owner's keys, stores it, and keeps its change so a dead one can be signed again. */
  submitTransition(changeJson: string, signal?: AbortSignal): Promise<{ digest: string; snapshot: SessionSnapshot }> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      const digest = await this.withOwner(signal, async (owner, custody, ownerId, waiting) => {
        const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
        const written = await owner.execute(custody, e => e.begin_transition(changeJson, signers, glue.RuleKind.Control, NOTHING), this.persistOn(owner), waiting);
        return objectDigest(written.stores, 'transitions/') ?? '';
      });
      await this.loadJournal();
      if (digest !== '') { this.journal.signedChanges.set(digest, changeJson); await this.saveJournal(); }
      return { digest, snapshot: await this.reconcile(signal) };
    });
  }
  /** Signs the same change again (a dead transition this device signed). */
  async resign(digest: string, signal?: AbortSignal): Promise<{ digest: string; snapshot: SessionSnapshot }> {
    const change = await this.gated(async () => { await this.loadJournal(); return this.journal.signedChanges.get(digest); });
    if (change === undefined) throw new SessionError('invalidCommand');
    return this.submitTransition(change, signal);
  }
  /** Suspends `key` while `transition` is pending (§8.7), signed by the owner key. */
  suspend(key: string, transition: string, signal?: AbortSignal): Promise<{ digest: string; snapshot: SessionSnapshot }> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      const digest = await this.withOwner(signal, async (owner, custody, ownerId, waiting) => {
        const written = await owner.execute(custody, e => withEntropy(32, entropy => e.begin_suspend(key, transition, ownerId, entropy)), this.persistOn(owner), waiting);
        return objectDigest(written.stores, '') ?? '';
      });
      return { digest, snapshot: await this.reconcile(signal) };
    });
  }

  // Requests

  private requestPath(id: string): string { return `requests/${id}.json`; }
  private async ownRequestBytes(signal?: AbortSignal): Promise<Uint8Array> {
    const account = this.accountId;
    if (account === undefined || this.memberId === undefined) throw new SessionError('notReady');
    const keys = await this.memberKeys.publicKeys();
    const spec = new glue.RequestSpec(account, keys.signing, keys.agreement, this.configuration.memberLabel, this.configuration.memberKind ?? glue.AccountMemberKind.App,
      terms(this.configuration.namespaces, this.access), glue.account_format_date(BigInt(this.nowMs - 1000)), undefined, undefined, []);
    const request = glue.AccountRequest.prepare(spec);
    try {
      const step = plain<SigningStep>(request.step());
      const signature = await raceAbort(this.memberKeys.sign(step.body, this.waiting(signal)), this.waiting(signal));
      return plain<RequestInfo>(request.finish(new glue.Signature(signature, undefined, undefined))).raw;
    } finally { try { request.free(); } catch { /* consumed */ } }
  }
  private held(path: string): Uint8Array | undefined {
    try { return this.storage.read(path); } catch (error) { if (error instanceof StorageError) return undefined; throw error; }
  }
  private async ensureOwnRequest(): Promise<void> {
    const id = this.memberId;
    if (id === undefined || this.held(this.requestPath(id))) return;
    await this.storage.write([{ path: this.requestPath(id), bytes: await this.ownRequestBytes() }]);
  }
  exportRequest(): Promise<Uint8Array> {
    return this.gated(async () => {
      await this.loadJournal();
      if (!this.engine) await this.reconcile();
      const id = this.memberId;
      if (id === undefined) throw new SessionError('notReady');
      await this.ensureOwnRequest();
      return this.storage.read(this.requestPath(id));
    });
  }
  importRequest(data: Uint8Array): Promise<SessionSnapshot> {
    return this.gated(async () => {
      const info = plain<RequestInfo>(glue.account_request_info(data));
      await this.storage.write([{ path: this.requestPath(info.member), bytes: info.raw }]);
      return this.reconcile();
    });
  }
  private pendingRequests(members: readonly AccountMember[]): AccessRequest[] {
    const known = new Set(members.map(m => m.id));
    const out: AccessRequest[] = [];
    for (const entry of this.storage.listing()) {
      if (!entry.path.startsWith('requests/')) continue;
      let info: RequestInfo;
      try { info = plain<RequestInfo>(glue.account_request_info(this.storage.read(entry.path))); } catch { continue; }
      if (known.has(info.member) || info.member === this.memberId) continue;
      const records = requestedRecords(info.termsJson);
      out.push({ id: info.member, label: info.label, kind: info.kind, termsJson: info.termsJson, pairingCode: pairingCode(info.member), record: info.raw,
        namespaces: records.map(r => r.namespace), access: records.some(r => r.access === 'write') ? ['read', 'write'] : ['read'] });
    }
    return out;
  }

  // Owner operations

  private openOwnerEngine(account: string, ownerId: string, deviceKey: import('./secrets.js').SecretBytes): ColophonEngine {
    return ColophonEngine.open({ medium: this.storage, listing: this.storage.listing(), identity: { kind: 'controller', id: ownerId }, account,
      namespaces: this.libraryNamespaces, deviceKey, nowMs: this.nowMs });
  }

  /** Opens a controller engine for the owner, unlocks it by the owner's slot, runs `body`, locks it. */
  private async withOwner<T>(signal: AbortSignal | undefined, body: (owner: ColophonEngine, custody: KeyCustody, ownerId: string, waiting: AbortSignal) => Promise<T>): Promise<T> {
    const account = this.accountId;
    if (account === undefined) throw new SessionError('notReady');
    const waiting = this.waiting(signal);
    const custody = await this.ownerCustody();
    const ownerId = await keyIdOf(this.configuration.ownerController);
    const key = await this.configuration.deviceSecrets.key(account);
    let owner: ColophonEngine;
    try { owner = this.tracked(this.openOwnerEngine(account, ownerId, key)); } finally { key.close(); }
    try {
      if (!plain<Controller[]>(owner.run(e => e.controllers())).some(c => c.id === ownerId)) throw new SessionError('ownerRequired');
      await this.unlockOwner(owner, custody, ownerId, waiting);
      return await body(owner, custody, ownerId, waiting);
    } finally {
      this.release(owner);
    }
  }
  private async ownerCustody(): Promise<KeyCustody> {
    return KeyCustody.of([this.configuration.ownerController, ...(this.configuration.recoveryKeys ? [this.configuration.recoveryKeys] : [])]);
  }
  /** Opens the controller's own slot with the owner's key (a PRF ceremony for a passkey, a silent ECDH for a device key). */
  private async unlockOwner(owner: ColophonEngine, custody: KeyCustody, ownerId: string, waiting: AbortSignal): Promise<void> {
    const slots = plain<SlotInfo[]>(owner.run(e => e.slots()));
    const slot = slots.find(s => s.controllers.length === 1 && s.controllers[0]!.id === ownerId) ?? slots.find(s => s.controllers.some(c => c.id === ownerId));
    if (!slot) throw new SessionError('ownerRequired');
    const inputs = plain<UnlockInput[]>(owner.run(e => e.begin_unlock_slot(slot.index)));
    owner.finishUnlockSlot(slot.index, await custody.answerUnlock(inputs, waiting));
  }
  private signers(owner: ColophonEngine, ownerId: string, need: glue.SignerNeed): string[] {
    const chosen = owner.run(e => e.suggest_signers([ownerId], need));
    return chosen.length > 0 ? chosen : [ownerId];
  }
  /** One gated owner operation, followed by a fresh snapshot. */
  private ownerOperation(signal: AbortSignal | undefined, body: (owner: ColophonEngine, custody: KeyCustody, ownerId: string, waiting: AbortSignal) => Promise<void>): Promise<SessionSnapshot> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      await this.withOwner(signal, body);
      return this.reconcile(signal);
    });
  }

  approve(request: AccessRequest, termsJson?: string, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.ownerOperation(signal, async (owner, custody, ownerId, waiting) => {
      const signers = this.signers(owner, ownerId, glue.SignerNeed.Member);
      await owner.execute(custody, e => withEntropy(32, entropy => e.begin_approve(request.record, termsJson ?? request.termsJson, signers, entropy)), this.persistOn(owner), waiting);
    });
  }
  revoke(member: string, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.ownerOperation(signal, async (owner, custody, ownerId, waiting) => {
      const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
      await owner.execute(custody, e => withEntropy(32, entropy => e.begin_revoke(member, keepEverything(), signers, entropy)), this.persistOn(owner), waiting);
    });
  }
  /** The removal follow-up's one action (§17.5): revokes the members and removes the controllers a removed key admitted. */
  removeFollowUp(seq: bigint, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      await this.withOwner(signal, async (owner, custody, ownerId, waiting) => {
        const follow = plain<RemovalFollowUp[]>(owner.run(e => e.removal_follow_up())).find(r => r.seq === seq);
        if (!follow) return;
        for (const member of follow.members) {
          const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
          await owner.execute(custody, e => withEntropy(32, entropy => e.begin_revoke(member, keepEverything(), signers, entropy)), this.persistOn(owner), waiting);
        }
        if (follow.controllers.length > 0) {
          const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
          await owner.execute(custody, e => e.begin_remove_controller(follow.controllers, [], signers, glue.RuleKind.Control, false, NOTHING), this.persistOn(owner), waiting);
        }
      });
      await this.loadJournal();
      this.journal.answeredRemovals.add(seq); await this.saveJournal();
      return this.reconcile(signal);
    });
  }
  keepFollowUp(seq: bigint): Promise<SessionSnapshot> {
    return this.gated(async () => {
      await this.loadJournal();
      this.journal.answeredRemovals.add(seq); await this.saveJournal();
      return this.reconcile();
    });
  }
  /** Signs a veto of the pending transition with the keys this device holds and stores it; the next exchange submits it. */
  veto(transition: string, signal?: AbortSignal): Promise<{ digest: string; snapshot: SessionSnapshot }> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      // The veto is its own object (`vetoes/<digest>.json`): its digest, not the transition's, is what homes receipt.
      const digest = await this.withOwner(signal, async (owner, custody, ownerId, waiting) => {
        const signers = this.signers(owner, ownerId, glue.SignerNeed.Veto);
        const written = await owner.execute(custody, e => e.begin_veto(transition, signers, NOTHING), this.persistOn(owner), waiting);
        return objectDigest(written.stores, 'vetoes/') ?? '';
      });
      return { digest, snapshot: await this.reconcile(signal) };
    });
  }
  /** Adds a controller key (a second device, a passkey, a security key); the new key signs its own possession proof. */
  addController(key: KeyDescriptor, label: string, roles: glue.ControllerRole[], mode: glue.AddMode, possession: AsyncKeyProvider, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.ownerOperation(signal, async (owner, ownerCustody, ownerId, waiting) => {
      const custody = ownerCustody.merging(glue.account_key_id(key.signing), possession);
      const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
      const spec = () => new glue.ControllerSpec(descriptorView(key), label, [...roles], key.form === glue.SignForm.Webauthn, undefined, []);
      await owner.execute(custody, e => e.begin_add_controller(spec(), mode, signers, glue.RuleKind.Control, NOTHING), this.persistOn(owner), waiting);
    });
  }
  /** The existing device's half of seed transfer: seals the vault seed to the device that confirmed `pairing`. */
  transferSeed(pairing: glue.AccountPairing, signal?: AbortSignal): Promise<SealedSeed> {
    return this.gated(async () => {
      if (!this.engine) await this.reconcile(signal);
      return this.withOwner(signal, async owner => plain<SealedSeed>(owner.run(e => withEntropy(32, entropy => e.transfer_seed(pairing, entropy)))));
    });
  }
  /** The new device's half: takes the seed and builds this controller's own slot so it unlocks alone from now on. */
  acceptSeedTransfer(key: glue.PairingTransferKey, pairing: glue.AccountPairing, sealed: SealedSeed, label: string, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.gated(async () => {
      await this.loadJournal();
      let account = this.accountId ?? this.journal.account;
      if (account === undefined) { try { account = this.discoverAccount(this.storage.listing()); } catch { throw new SessionError('notReady'); } }
      this.accountId = account;
      const waiting = this.waiting(signal);
      const custody = await this.ownerCustody();
      const ownerId = await keyIdOf(this.configuration.ownerController);
      const deviceKey = await this.configuration.deviceSecrets.key(account);
      let owner: ColophonEngine;
      try { owner = this.tracked(this.openOwnerEngine(account, ownerId, deviceKey)); } finally { deviceKey.close(); }
      try {
        plain(owner.run(e => e.accept_seed_transfer(key, pairing, new glue.SealedSeed(sealed.enc.slice(), sealed.ciphertext.slice()))));
        plain(owner.run(e => e.load()));
        await owner.execute(custody, e => withEntropy(32, entropy => e.begin_add_slot(ownerId, new glue.SlotPlan([ownerId], label), entropy)), this.persistOn(owner), waiting);
      } finally {
        this.release(owner);
      }
      return this.reconcile(signal);
    });
  }

  // Create

/**
   * Creates the account. The genesis is stored first and the journal marks the setup as pending; appointing the homes
   * and approving this device follow. If one of those fails (a home that does not answer, a cancelled prompt, a closed
   * tab), the next `create` finishes the setup from where it stopped instead of leaving an account nobody can enter.
   */
  create(signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.gated(async () => {
      await this.loadJournal();
      if (this.lockedFlag) throw makeFault('Locked', 'locked', 'the session is locked');
      if (this.homes.length === 0 && !this.configuration.createWithoutHome) throw new SessionError('noHome');
      if (!this.homes.every(h => h.isAllowed)) throw new SessionError('insecureHome');
      const waiting = this.waiting(signal);
      if (this.journal.setupPending && this.journal.account !== undefined) {
        // Resume: the owner unlocks its slot as for any owner operation, and the remaining steps run.
        this.accountId = this.journal.account;
        await this.withOwner(signal, (owner, custody, ownerId) => this.finishSetup(owner, this.journal.account!, ownerId, custody, waiting));
        return this.reconcile(signal);
      }
      if (this.engine || this.journal.account !== undefined || this.storage.listing().some(e => e.path.startsWith('authority/'))) throw new SessionError('destinationChanged');
      this.journal.left = false;
      let custody = await this.ownerCustody();
      const ownerKey = await keyDescriptorOf(this.configuration.ownerController);
      const ownerId = glue.account_key_id(ownerKey.signing);
      const controllers: { key: KeyDescriptor; label: string; roles: glue.ControllerRole[] }[] =
        [{ key: ownerKey, label: 'Owner', roles: [glue.ControllerRole.Approve, glue.ControllerRole.Control, glue.ControllerRole.Recover] }];
      const slots: { id: string; label: string }[] = [{ id: ownerId, label: 'Owner' }];
      if (this.configuration.recoveryKeys) {
        const d = await keyDescriptorOf(this.configuration.recoveryKeys);
        controllers.push({ key: d, label: 'Recovery kit', roles: [glue.ControllerRole.Recover] });
        slots.push({ id: glue.account_key_id(d.signing), label: 'Recovery kit' });
      }
      for (const extra of this.configuration.additionalControllers ?? []) {
        const d = await keyDescriptorOf(extra.provider); const id = glue.account_key_id(d.signing);
        controllers.push({ key: d, label: extra.label, roles: extra.roles ?? [glue.ControllerRole.Approve, glue.ControllerRole.Control] });
        slots.push({ id, label: extra.label });
        custody = custody.merging(id, extra.provider);
      }
      const policy = JSON.parse(glue.account_default_policy()) as Record<string, unknown>;
      if (this.configuration.recoveryDelay !== undefined) policy.recoveryDelay = this.configuration.recoveryDelay;
      if (this.configuration.history !== undefined) policy.history = this.configuration.history;
      if (this.configuration.headQuorum !== undefined) policy.headQuorum = this.configuration.headQuorum;
      const params = new glue.CreateParams(this.configuration.memberLabel, [...this.libraryNamespaces].sort(),
        controllers.map(c => new glue.ControllerSpec(descriptorView(c.key), c.label, [...c.roles], c.key.form === glue.SignForm.Webauthn, undefined, [])),
        slots.map(s => new glue.SlotPlan([s.id], s.label)), undefined, undefined, undefined, false, JSON.stringify(policy), [ownerId], [ownerId]);
      const identity: Identity = { kind: 'controller', id: ownerId };
      const { creation, created } = await runCreation(params, identity, custody, this.nowMs, waiting);
      try {
        await this.storage.write(created.stores.map(s => ({ path: s.path, bytes: s.bytes })));
        this.journal.account = created.account; this.journal.setupPending = true; this.accountId = created.account;
        await this.saveJournal();
        // The creation's own engine: unlocked as the creation left it, so the owner is asked once at first run.
        const deviceKey = await this.configuration.deviceSecrets.key(created.account);
        let owner: ColophonEngine;
        try {
          owner = this.tracked(ColophonEngine.openCreated(creation, { medium: this.storage, listing: this.storage.listing(), identity, account: created.account,
            namespaces: this.libraryNamespaces, deviceKey, nowMs: this.nowMs }));
        } finally { deviceKey.close(); }
        try { await this.finishSetup(owner, created.account, ownerId, custody, waiting); } finally { this.release(owner); }
      } finally {
        try { creation.free(); } catch { /* consumed */ }
      }
      return this.reconcile(signal);
    });
  }

  /**
   * The first setup of an account this device made: the homes appointed in one transition recorded at once, and this
   * device's member approved. Every step looks at what the account already holds, so it can run again after a failure.
   */
  private async finishSetup(owner: ColophonEngine, account: string, ownerId: string, custody: KeyCustody, waiting: AbortSignal): Promise<void> {
    if (plain<Home[]>(owner.run(e => e.homes())).length === 0) {
      if (plain<unknown[]>(owner.run(e => e.pending())).length === 0) {
        const appoint: { request: string; terms: unknown }[] = [];
        for (const home of this.homes) {
          const makeRequest = home.configuration.request;
          if (!makeRequest) continue;
          const raw = await raceAbort(makeRequest(account), waiting);
          const info = plain<RequestInfo>(glue.account_request_info(raw));
          appoint.push({ request: base64(raw), terms: JSON.parse(info.termsJson) as unknown });
        }
        if (appoint.length > 0) {
          const change = JSON.stringify({ homes: { appoint } });
          const signers = this.signers(owner, ownerId, glue.SignerNeed.Control);
          await owner.execute(custody, e => e.begin_transition(change, signers, glue.RuleKind.Control, NOTHING), this.persistOn(owner), waiting);
        }
      }
      for (const due of plain<Written[]>(owner.run(e => e.record_due()))) await this.persist(due.stores, owner);
    }
    this.memberId = await keyIdOf(this.memberKeys);
    this.accountId = account;
    if (!plain<AccountMember[]>(owner.run(e => e.members())).some(m => m.id === this.memberId)) {
      const memberRaw = await this.ownRequestBytes(waiting);
      const memberTerms = terms(this.configuration.namespaces, this.access);
      const signers = this.signers(owner, ownerId, glue.SignerNeed.Member);
      await owner.execute(custody, e => withEntropy(32, entropy => e.begin_approve(memberRaw, memberTerms, signers, entropy)), this.persistOn(owner), waiting);
    }
    this.journal.setupPending = false;
    await this.saveJournal();
  }

  // Leave and rejoin

  leave(): Promise<void> {
    return this.gated(async () => {
      await this.loadJournal();
      this.engine?.lock(); this.engine = undefined;
      this.journal.left = true; await this.saveJournal();
    });
  }
  rejoin(keys: AsyncKeyProvider): Promise<SessionSnapshot> {
    return this.gated(async () => {
      await this.loadJournal();
      this.engine?.lock(); this.engine = undefined;
      this.memberKeys = keys; this.memberCustody = undefined;
      this.journal.left = false; await this.saveJournal();
      return this.reconcile();
    });
  }

  // Writes and queries

  write(command: DomainCommand, observed: number, signal?: AbortSignal): Promise<{ receipt: WriteReceipt; snapshot: SessionSnapshot }> {
    return this.gated(async () => {
      const fresh = await this.reconcile(signal);
      const engine = this.engine; const custody = this.memberCustody;
      if (fresh.phase.kind !== 'ready' || !engine || !custody) throw new SessionRefusal(fresh, new SessionError('notReady'));
      if (observed !== this.revision) throw new SessionRefusal(fresh, new SessionError('staleRevision'));
      if (!this.configuration.namespaces.includes(command.namespace) || !this.access.includes('write')) throw new SessionError('invalidCommand');
      if (!isJsonObject(command.payloadJson)) throw new SessionError('invalidCommand');
      const ceiling = command.kind === 'colophon.blobPublish' ? 1024 * 1024 : 256 * 1024;
      if (new TextEncoder().encode(command.payloadJson).length > ceiling) throw new SessionError('invalidCommand');
      const written = await engine.execute(custody, e => withEntropy(32, entropy => e.begin_write(command.namespace, command.kind, command.payloadJson, entropy)),
        this.persistOn(), this.waiting(signal));
      return { receipt: { kind: 'saved', operationId: operationId(written.stores) ?? '' }, snapshot: await this.build() };
    });
  }

  requireEngine(): ColophonEngine { if (!this.engine) throw new SessionError('notReady'); return this.engine; }
  query(namespace: string, name: string, argumentsJson: string): string { return queryResult(this.requireEngine().run(e => e.query_json(namespace, name, argumentsJson))); }
  /** The namespace's whole fold as the engine reports it (`view_json`), unchanged. */
  view(namespace: string): string { return this.requireEngine().run(e => e.view_json(namespace)); }
  ledger(): string { return this.requireEngine().run(e => e.ledger_json()); }
  persistStores(stores: readonly Store[]): Promise<void> { return this.persist(stores); }
  inGate<T>(body: () => Promise<T>): Promise<T> { return this.gated(body); }
  currentSnapshot(): Promise<SessionSnapshot> { return this.gated(() => this.build()); }

  // Exchange

  private transportFor(home: Home): ConfiguredHome | undefined {
    return this.homes.find(configured => home.endpoints.some(e => trimSlashes(e) === trimSlashes(configured.endpoint)));
  }

  /**
   * One exchange with every home. The network calls run outside the gate; each engine step and the persistence of its
   * stores run inside it, so an unpersisted answer is never visible to a refresh. A home is held to `HomeLimits`.
   *
   * However a pass with a home ends that is not `Done` (a transport failure, an engine error, a bound, the deadline,
   * `signal` aborted, the session locked), the request in flight is abandoned with `exchange_abort` before this
   * returns or throws, so the next pass never finds the engine waiting for an answer nobody will give.
   */
  /** Tests only: answers `exchange_next` for a home instead of the engine when it returns a step. */
  nextStepOverride?: (home: string) => ExchangeStep | undefined;

  async exchange(caller?: AbortSignal): Promise<ExchangeResult> {
    // Locking the session ends the pass in flight, as a cancelled caller does.
    const signal = this.waiting(caller);
    await this.gated(async () => { if (!this.engine) await this.reconcile(signal); });
    const result: ExchangeResult = { passes: 0, faults: [], issues: [], changed: false, unauthorized: false, failed: false };
    const engine = this.engine;
    if (!engine) return result;
    const homes = plain<Home[]>(engine.run(e => e.exchange_homes()));
    for (const home of homes) {
      throwIfAborted(signal);
      const configured = this.transportFor(home);
      if (!configured) continue;
      if (!configured.isAllowed) { result.issues.push({ home: home.id, problem: { kind: 'insecureEndpoint', url: configured.endpoint } }); continue; }
      const token = configured.configuration.bearerToken;
      if (token !== undefined) engine.run(e => e.exchange_set_bearer(home.id, token));
      // The pass starts from fresh local state.
      await this.gated(async () => {
        plain(engine.run(e => e.advance(BigInt(this.nowMs))));
        plain(engine.run(e => e.refresh(listed(this.storage.listing()))));
        await this.unlockIfPossible(signal);
      });
      const started = performance.now();
      const elapsed = (): number => performance.now() - started;
      const tooSlow = (): HomeProblem => ({ kind: 'tooSlow', seconds: Math.round(this.exchangeTimeMs / 1000) });
      let stopped: HomeProblem | undefined;
      let finished = false;
      try {
        let progress = true; let passIndex = 0; let recovered = false;
        // A pass can end before everything moved (the engine plans the next stage from what the home just said): run
        // passes until one moves nothing, at most HomeLimits.passes.
        homeLoop: while (progress && passIndex < HomeLimits.passes) {
          progress = false; passIndex++;
          for (let steps = 1; ; steps++) {
            throwIfAborted(signal);
            if (steps > HomeLimits.stepsPerPass) { stopped = { kind: 'tooManySteps', steps: HomeLimits.stepsPerPass }; break homeLoop; }
            if (elapsed() > this.exchangeTimeMs) { stopped = tooSlow(); break homeLoop; }
            const step = await this.gated(async () => this.nextStepOverride?.(home.id) ?? plain<ExchangeStep>(engine.run(e => e.exchange_next(home.id))));
            if (step.kind === glue.ExchangeStepKind.Done) break;
            if (step.kind === glue.ExchangeStepKind.Waiting) {
              // This loop answers every request it is given, so an outstanding one belongs to a pass that was
              // interrupted: abandon it and run the pass again, once. A second `Waiting` after that recovery means the pass
              // cannot finish: a failed exchange, never "done".
              await this.abortPass(engine, home.id);
              if (recovered) { stopped = { kind: 'stillWaiting' }; break homeLoop; }
              recovered = true; progress = true;
              break;
            }
            if (step.kind === glue.ExchangeStepKind.NeedCall) {
              if (!step.need) break;
              try { await this.provideCall(step.need, home, configured, signal); } catch (error) {
                if (error instanceof HomeProblemError) { stopped = error.problem; break homeLoop; }
                throw error;
              }
              continue;
            }
            const request = step.request;
            if (!request) break;
            // A request is for this home, except another home's public head (headQuorum above 1), which goes to the
            // transport configured for the home its URL names, with no credential.
            let target = configured;
            if (!request.url.startsWith(base(configured.endpoint) + '/')) {
              const other = this.homes.find(h => request.url === base(h.endpoint) + '/head');
              const publicHead = request.method === glue.HttpMethod.Get && !request.headers.some(h => h.name.toLowerCase() === 'authorization');
              if (!other || !other.isAllowed || !publicHead) { stopped = { kind: 'callNotBound', why: 'a request for another host than the configured home' }; break homeLoop; }
              target = other;
            }
            if (request.method !== glue.HttpMethod.Get) progress = true;
            // The exchange deadline covers the transport, whatever the transport does with its signal.
            const deadline = new AbortController();
            const timer = setTimeout(() => deadline.abort(), Math.max(1, this.exchangeTimeMs - elapsed()));
            const sending = AbortSignal.any([signal, deadline.signal]);
            const outgoing: HomeRequest = { method: methodName(request.method), url: request.url, headers: request.headers, body: request.body };
            let answer: HomeAnswer;
            try {
              answer = await raceAbort(target.transport.send(outgoing, sending), sending);
            } catch (error) {
              if (deadline.signal.aborted && !signal.aborted) { stopped = tooSlow(); break homeLoop; }
              if (error instanceof HomeTransportError) {
                if (error.reason === 'responseTooLarge') { stopped = { kind: 'responseTooLarge', limit: error.limit ?? 0 }; break homeLoop; }
                if (error.reason === 'insecureEndpoint') { stopped = { kind: 'insecureEndpoint', url: request.url }; break homeLoop; }
                if (error.reason === 'redirected') { stopped = { kind: 'redirected' }; break homeLoop; }
                if (error.reason === 'timeout') { stopped = tooSlow(); break homeLoop; }
              }
              throw error;
            } finally { clearTimeout(timer); }
            const limit = HomeLimits.responseBytes(request.url);
            if (answer.body.length > limit) { stopped = { kind: 'responseTooLarge', limit }; break homeLoop; }
            throwIfAborted(signal);
            // The answer and the persistence of its stores are one step: never abandoned half way.
            const report = await this.gated(async () => {
              const headers = answer.headers.slice(0, 256).map(h => new glue.Header(h.name, h.value));
              const r = plain<Report>(engine.run(e => e.exchange_answer(home.id, request.ticket, new glue.HttpAnswer(answer.status, headers, answer.body))));
              await this.persist(r.store);
              return r;
            });
            for (const fault of report.faults) {
              result.faults.push({ home: home.id, fault });
              if (fault.kind === glue.ExchangeFaultKind.Unauthorized) result.unauthorized = true;
            }
            if (report.store.length > 0 || report.changes.authorityToSeq !== report.changes.authorityFromSeq || report.changes.namespaces.length > 0) {
              result.changed = true; progress = true;
            }
          }
          result.passes++;
        }
        finished = stopped === undefined;
      } finally {
        // Every exit that is not a completed pass abandons the request in flight, a cancelled caller included.
        if (!finished) await this.abortPass(engine, home.id);
      }
      if (stopped) {
        result.issues.push({ home: home.id, problem: stopped });
        if (stopped.kind === 'stillWaiting') result.failed = true;
      }
    }
    return result;
  }

  /** Abandons the pass in flight with `home`. Never throws: a locked or discarded engine has nothing to abandon. */
  private async abortPass(engine: ColophonEngine, home: string): Promise<void> {
    try {
      await this.gated(async () => {
        if (engine.isLocked) return;
        await this.persist(plain<Report>(engine.run(e => e.exchange_abort(home))).store);
      });
    } catch { /* the engine is gone or the store refused: the next open starts clean */ }
  }

  /**
   * The call a `NeedCall` asked for, built by the engine for exactly the request it will send, signed by this device's
   * member key and judged by the core with the home's own rule before it is returned. A need for another home or
   * audience is not signed (`callNotBound`); a call the core's own check refuses is `callRefused`.
   */
  private async provideCall(need: CallNeed, home: Home, configured: ConfiguredHome, signal?: AbortSignal): Promise<void> {
    const engine = this.engine; const custody = this.memberCustody; const id = this.memberId;
    if (!engine || !custody || id === undefined) throw new SessionError('notReady');
    if (need.home !== home.id || base(need.audience) !== base(configured.endpoint) || need.url !== base(need.audience) + need.path) {
      throw new HomeProblemError({ kind: 'callNotBound', why: 'the engine asked a call for another home than the configured one' });
    }
    const signing = (await custody.provider(id).publicKeys()).signing;
    let written: Written;
    try {
      written = await this.gated(() => engine.execute(custody, e => withEntropy(32, entropy => e.exchange_begin_call(need.home, need.ticket, signing, entropy)), undefined, this.waiting(signal)));
    } catch (error) {
      if (isAccountFault(error) && (error.kind === 'Refused' || error.kind === 'Unavailable' || error.kind === 'Denied')) throw new HomeProblemError({ kind: 'callRefused', code: error.code });
      throw error;
    }
    const artifact = written.artifact;
    if (!artifact) throw makeFault('Internal', 'internal', 'a call returned no envelope');
    await this.gated(async () => engine.run(e => e.exchange_provide_call(need.home, need.ticket, artifact)));
  }

  /** Records transitions that came due (§8.7). A schedule calls it; refresh calls it too. */
  recordDue(): Promise<SessionSnapshot> {
    return this.gated(async () => {
      const engine = this.engine;
      if (!engine) return this.reconcile();
      plain(engine.run(e => e.advance(BigInt(this.nowMs))));
      for (const written of plain<Written[]>(engine.run(e => e.record_due()))) await this.persist(written.stores);
      return this.build();
    });
  }
  /** How many homes hold a verified receipt for `object`, and how many the account names. */
  receipts(object: string): { receipted: number; homes: number } {
    const engine = this.requireEngine();
    return { receipted: engine.run(e => e.receipted_by(object)).length, homes: plain<Home[]>(engine.run(e => e.exchange_homes())).length };
  }
  /** Whether the transition `digest` is still pending in what this device holds. */
  isPending(digest: string): boolean {
    return plain<{ digest: string }[]>(this.requireEngine().run(e => e.pending())).some(p => p.digest === digest);
  }
  /** Test hook. */
  engineForTests(): ColophonEngine | undefined { return this.engine; }
}

/** Drives `AccountCreation` through its stages with the host's key custody. Every PRF output is wiped on every path. */
async function runCreation(params: glue.CreateParams, identity: Identity, custody: KeyCustody, nowMs: number, signal: AbortSignal):
  Promise<{ creation: glue.AccountCreation; created: Created }> {
  const who = new glue.AccountIdentity(identity.kind === 'member' ? glue.AccountIdentityKind.Member : glue.AccountIdentityKind.Controller, identity.id);
  const creation = withEntropy(96, entropy => glue.AccountCreation.begin(params, who, BigInt(nowMs), entropy));
  try {
    const requests = plain<PrfRequest[]>(creation.prf_requests());
    if (requests.length > 0) {
      const answers = await custody.answer(requests, signal);
      try { creation.provide_prf(toPrfAnswers(answers)); } finally { closeAll(answers); }
    }
    for (let round = 0; round < 8; round++) {
      const signatures = await custody.sign(plain<SigningStep[]>(creation.steps()), signal);
      throwIfAborted(signal);
      if (creation.provide_signatures(toSignatures(signatures)) === glue.CreateStage.Done) return { creation, created: plain<Created>(creation.take_result()) };
    }
    throw makeFault('Internal', 'internal', 'the creation did not finish');
  } catch (error) {
    try { creation.free(); } catch { /* consumed */ }
    throw error;
  }
}

function base64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function isJsonObject(text: string): boolean {
  try { const v: unknown = JSON.parse(text); return typeof v === 'object' && v !== null && !Array.isArray(v); } catch { return false; }
}
function requestedRecords(termsJson: string): { namespace: string; access: string }[] {
  try {
    const parsed = JSON.parse(termsJson) as { records?: unknown };
    if (!Array.isArray(parsed.records)) return [];
    return parsed.records.flatMap((r: unknown) => typeof r === 'object' && r !== null && typeof (r as { namespace?: unknown }).namespace === 'string'
      ? [{ namespace: (r as { namespace: string }).namespace, access: typeof (r as { access?: unknown }).access === 'string' ? (r as { access: string }).access : 'read' }] : []);
  } catch { return []; }
}

/** A member's terms (§9.1): `{"records":[{"access","namespace"}...]}`, namespaces sorted. */
export function terms(namespaces: readonly string[], access: readonly ('read' | 'write')[], expires?: string, budget?: bigint): string {
  const records = [...namespaces].sort().map(namespace => `{"access":${JSON.stringify(access.includes('write') ? 'write' : 'read')},"namespace":${JSON.stringify(namespace)}}`);
  let out = '{';
  if (expires !== undefined) out += `"expires":${JSON.stringify(expires)},`;
  out += `"records":[${records.join(',')}]`;
  if (budget !== undefined) out += `,"writes":${budget.toString()}`;
  return out + '}';
}
/** The digest an object's store path names (`transitions/<digest>.json`). */
export function objectDigest(stores: readonly Store[], prefix: string): string | undefined {
  for (const s of stores) {
    if (prefix !== '' && !s.path.startsWith(prefix)) continue;
    const name = s.path.slice(s.path.lastIndexOf('/') + 1).replace(/\.json$/, '');
    if (/^[0-9a-fA-F]{64}$/.test(name)) return name;
  }
  return undefined;
}
/** `ops/<author>/<namespace>/<clock>-<id>.json`: the operation ID is the part after the clock. */
export function operationId(stores: readonly Store[]): string | undefined {
  for (const s of stores) {
    if (!s.path.startsWith('ops/')) continue;
    const name = s.path.slice(s.path.lastIndexOf('/') + 1).replace(/\.json$/, '');
    const dash = name.indexOf('-');
    if (dash >= 0) return name.slice(dash + 1);
  }
  return undefined;
}
const knownReasons = new Set(['notFound', 'deleted', 'notGranted', 'unavailable', 'invalidArgument', 'staleCursor', 'contentTooLarge']);
/**
 * The engine's `{"ok":true,"value":X}` outcome as the value's JSON text, or `{"ok":false,"reason":...}`. The value passes
 * through `JSON.parse`, so a `u64` above 2^53 inside it loses precision (a known gap of the `*_json` results,
 * docs/bindings-05.md §9); `view` returns the engine's text untouched.
 */
export function queryResult(text: string): string {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return text; }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return text;
  const o = parsed as { ok?: unknown; value?: unknown; reason?: unknown };
  if (o.ok === true && 'value' in o) return JSON.stringify(o.value);
  const reason = typeof o.reason === 'string' && knownReasons.has(o.reason) ? o.reason : 'unavailable';
  return JSON.stringify({ ok: false, reason });
}
