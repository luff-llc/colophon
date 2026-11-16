import { throwIfAborted } from './errors.js';
import { closeAll } from './secrets.js';
import { descriptorView, toEpochAnswers, toPrfAnswers, toSignatures, toUnlockSecrets, type HostEpochAnswer, type HostUnlockSecret, type KeyCustody } from './keys.js';
import type { MediumEntry, RecordMedium } from './medium.js';
import type { SavedStateData } from './private.js';
import type { AccountDenial, Changes, KeyDescriptor, PrfRequest, SigningStep, Written } from './records.js';
import { SecretBytes } from './secrets.js';
import { glue, makeFault, plain, type AccountAction, type AccountEngine } from './wasm.js';

export type Identity = { kind: 'member' | 'controller'; id: string };
const identityRecord = (i: Identity): glue.AccountIdentity =>
  new glue.AccountIdentity(i.kind === 'member' ? glue.AccountIdentityKind.Member : glue.AccountIdentityKind.Controller, i.id);
export const listed = (entries: readonly MediumEntry[]): glue.ListedPath[] => entries.map(e => new glue.ListedPath(e.path, e.version));
const savedRecord = (s: SavedStateData | undefined): glue.SavedState =>
  new glue.SavedState(s?.verifier.slice() ?? new Uint8Array(0), s?.checkpoint.slice() ?? new Uint8Array(0), (s?.parts ?? []).map(p => new glue.SavedPart(p.namespace, p.bytes.slice())));

/** The record source the engine reads through: the medium, nothing else. Synchronous, and it never calls the engine. */
const source = (medium: RecordMedium): unknown =>
  ({ read: (path: string) => medium.read(path), readBlob: (path: string) => medium.readBlob(path) });

const wire: Record<number, string> = {
  [glue.AccountDenialReason.NotGranted]: 'notGranted', [glue.AccountDenialReason.Revoked]: 'revoked', [glue.AccountDenialReason.Expired]: 'expired',
  [glue.AccountDenialReason.BudgetSpent]: 'budgetSpent', [glue.AccountDenialReason.NotReadable]: 'notReadable',
  [glue.AccountDenialReason.Unavailable]: 'unavailable', [glue.AccountDenialReason.Unknown]: 'unknown',
};
/** The §19 access reason as the protocol writes it. */
export const denialReason = (d: AccountDenial): string => d.reasonRaw ?? wire[d.reason] ?? 'unknown';

/**
 * One `AccountEngine` and its lifecycle. Every engine call is synchronous and JavaScript has one thread, so calls are
 * ordered by construction; what this adds is the rule of docs/bindings-05.md §3b: `lock` before the object is freed,
 * and a locked or discarded engine answers `Locked` instead of a dead wasm object's plain `Error`.
 */
export class ColophonEngine {
  private engine: AccountEngine | undefined;
  private constructor(readonly account: string, readonly identity: Identity, engine: AccountEngine) { this.engine = engine; }

  /** Opens the engine over `medium`. See `AccountEngine.open` for the arguments. The device key is lent for the call. */
  static open(options: { medium: RecordMedium; listing: readonly MediumEntry[]; identity: Identity; account: string; namespaces: string[];
    saved?: SavedStateData; deviceKey: SecretBytes; nowMs: number }): ColophonEngine {
    const engine = options.deviceKey.lend(key => glue.AccountEngine.open(source(options.medium), listed(options.listing), identityRecord(options.identity),
      options.account, [...options.namespaces], 0n, savedRecord(options.saved), key, BigInt(options.nowMs)));
    return new ColophonEngine(options.account, options.identity, engine);
  }
  /**
   * Opens the engine over the stores `creation.take_result()` returned (stored and listed by the host), unlocked as
   * the creation left it: the owner is asked once at first run. One shot.
   */
  static openCreated(creation: glue.AccountCreation, options: { medium: RecordMedium; listing: readonly MediumEntry[]; identity: Identity;
    account: string; namespaces: string[]; deviceKey: SecretBytes; nowMs: number }): ColophonEngine {
    const engine = options.deviceKey.lend(key => creation.open_engine(source(options.medium), listed(options.listing), [...options.namespaces], 0n, key, BigInt(options.nowMs)));
    return new ColophonEngine(options.account, options.identity, engine);
  }

  /** Runs `body` with the engine. A locked or discarded engine is `Locked`. */
  run<T>(body: (engine: AccountEngine) => T): T {
    if (!this.engine) throw makeFault('Locked', 'locked', 'this engine was locked or discarded; open a new one');
    return body(this.engine);
  }
  get isLocked(): boolean { return this.engine === undefined; }

  /** Overwrites the engine's keys and opened plaintext and frees it. Further calls are `Locked`. Never throws. */
  lock(): void {
    const engine = this.engine;
    if (!engine) return;
    this.engine = undefined;
    try { engine.lock(); } catch { /* an engine that cannot lock is freed all the same */ }
    try { engine.free(); } catch { /* already freed */ }
  }
  /** Drops the engine after a call that ended in `Integrity` (it is unusable). */
  discard(): void { this.lock(); }

  /** The secrets are wiped whether the call succeeds, refuses or the engine is locked. */
  finishUnlockSlot(index: bigint, secrets: HostUnlockSecret[]): Changes {
    try { return plain<Changes>(this.run(e => e.finish_unlock_slot(index, toUnlockSecrets(secrets)))); } finally { closeAll(secrets); }
  }
  finishUnlockEpochs(answers: HostEpochAnswer[]): Changes {
    try { return plain<Changes>(this.run(e => e.finish_unlock_epochs(toEpochAnswers(answers)))); } finally { closeAll(answers); }
  }

  /**
   * An action from `begin` to `Written`: prepare, answer PRF requests, sign every step, finish. The key ceremonies in
   * between are awaited outside any engine call, so a person's pause never holds the engine, and they end when
   * `signal` is aborted. A write refused for access reasons throws `Denied` (a value in the bindings). A failed finish
   * changes nothing and consumes the action. `then` runs with the finished stores before anything else may run: the
   * finish and the persistence of its stores are one step, which a cancelled caller cannot cut in half.
   */
  async execute(custody: KeyCustody, begin: (engine: AccountEngine) => AccountAction, then?: (written: Written) => Promise<void>, signal?: AbortSignal): Promise<Written> {
    throwIfAborted(signal);
    const action = this.run(begin);
    try {
      const denial = plain<AccountDenial | undefined>(action.denial());
      if (denial) throw makeFault('Denied', `denied:${denialReason(denial)}`, denial.detail, denialReason(denial));
      const requests = plain<PrfRequest[]>(action.prf_requests());
      if (requests.length > 0) {
        const answers = await custody.answer(requests, signal);
        try { this.run(e => e.provide_prf(action, toPrfAnswers(answers))); } finally { closeAll(answers); }
      }
      const signatures = await custody.sign(plain<SigningStep[]>(action.steps()), signal);
      throwIfAborted(signal);
      const written = plain<Written>(this.run(e => e.finish(action, toSignatures(signatures))));
      if (then) await then(written);
      return written;
    } finally {
      try { action.free(); } catch { /* consumed */ }
    }
  }
}

export { descriptorView };
export type { KeyDescriptor };
