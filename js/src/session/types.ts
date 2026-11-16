import type { SessionError } from './errors.js';
import type { AsyncKeyProvider } from './keys.js';
import type { RecordMedium } from './medium.js';
import type { DeviceSecretStore, PrivateStore } from './private.js';
import type { AccountMember, ExchangeFault, Home, Notices, Owed, Pending, SeenActivation } from './records.js';
import { FetchHomeTransport, HomeLimits, type HomeIssue, type HomeSyncState, type HomeTransport } from './transport.js';
import { glue } from './wasm.js';

/** Where the session stands. The engine decides every verdict; the session only chooses what to show. */
export type SessionPhase =
  | { kind: 'opening' } | { kind: 'noLibrary' } | { kind: 'creating' } | { kind: 'waitingForDownload' }
  | { kind: 'waitingForApproval'; code: string }
  /** A revoked member, or a grant that no longer allows reading. */
  | { kind: 'denied' }
  | { kind: 'unavailable'; reason: string }
  /** Authenticated content of a newer format than this client evaluates. Nothing is changed or lost. */
  | { kind: 'updateRequired' }
  | { kind: 'ready' }
  /** A refresh is in flight; previously verified content is still usable. */
  | { kind: 'refreshing' }
  | { kind: 'retry' }
  /** `lock` ran: content is hidden and no secret is held. */
  | { kind: 'locked' }
  | { kind: 'failed'; failure: SessionFailure };

export type SessionFailure = { kind: 'keysUnavailable'; detail: string } | { kind: 'other'; detail: string };
export function failureMessage(f: SessionFailure): string {
  return f.kind === 'keysUnavailable' ? `Your identity keys are unavailable. Unlock this device or restore key access, then retry. ${f.detail}` : f.detail;
}
export const phaseUsable = (p: SessionPhase): boolean => p.kind === 'ready' || p.kind === 'refreshing' || p.kind === 'waitingForDownload' || p.kind === 'retry';
export const samePhase = (a: SessionPhase, b: SessionPhase): boolean => JSON.stringify(a) === JSON.stringify(b);

/** A command is bound to the context and revision observed before the person's action began. */
export interface ObservedRevision { context: string; revision: number }

/** One write: the namespace, the record kind and the JSON object payload, passed to the engine as written. */
export interface DomainCommand { namespace: string; kind: string; payloadJson: string }

export type WriteReceipt =
  /** The signed record is durable in this device's store. Homes receive it on the next exchange. */
  | { kind: 'saved'; operationId: string }
  | { kind: 'queued' };

/** A delivery route a host registers with each home (§17.5: at least two, on different devices or services). */
export interface DeliveryRoute { kind: 'push' | 'email' | 'sms' | 'webhook' | 'other'; address: string; reaches: string }

/** A home the account names, as this host reaches it. */
export interface HomeConfiguration {
  /** The home's base URL, as the account names it (`Home.endpoints`). */
  endpoint: string;
  label?: string;
  /**
   * Asks the home service for its signed member request (§9.1) for a new account, to appoint it when this host creates
   * the account. The session calls it with the new account's ID. Absent: the home is not appointed here.
   */
  request?: (account: string) => Promise<Uint8Array>;
  /** Storage bearer token (access to the home's store only, never membership). */
  bearerToken?: string;
  /** Default: `FetchHomeTransport`. */
  transport?: HomeTransport;
  /** Testing option: allow a plain `http` endpoint on a loopback address. */
  allowsLoopbackHttp?: boolean;
  deliveryRoutes?: DeliveryRoute[];
  /** Registers routes with the home; false when it offers no registration. Absent: not offered. */
  registerRoutes?: (account: string, routes: DeliveryRoute[]) => Promise<boolean>;
}
/** A home configuration with its defaults filled in. */
export class ConfiguredHome {
  readonly endpoint: string; readonly label: string; readonly transport: HomeTransport; readonly allowsLoopbackHttp: boolean;
  readonly deliveryRoutes: DeliveryRoute[];
  constructor(readonly configuration: HomeConfiguration) {
    this.endpoint = configuration.endpoint; this.label = configuration.label ?? 'Home';
    this.allowsLoopbackHttp = configuration.allowsLoopbackHttp ?? false;
    this.transport = configuration.transport ?? new FetchHomeTransport({ allowingLoopbackHttp: this.allowsLoopbackHttp });
    this.deliveryRoutes = configuration.deliveryRoutes ?? [];
  }
  get isAllowed(): boolean { return HomeLimits.isAllowed(this.endpoint, this.allowsLoopbackHttp); }
}

/** Who may read an account's history at its homes (`policy.history`, spec §13.4). */
export type HistoryAccess = 'public' | 'members';

/** A further controller the account is created with (spec §18). It signs its own possession proof at creation. */
export interface AdditionalController { provider: AsyncKeyProvider; label: string; roles?: glue.ControllerRole[] }

/** The session's configuration: one per page (or process) and account. */
export interface SessionConfiguration {
  memberLabel: string;
  /** Default: `App`. */
  memberKind?: glue.AccountMemberKind;
  namespaces: string[];
  /** Default: read and write. */
  access?: ('read' | 'write')[];
  /** The namespaces the account is created with and the engine reads. Default: `namespaces`. */
  libraryNamespaces?: string[];
  /** The account's record store: `IndexedDBMedium` in a browser, `FileMedium` under Node or Bun, `MemoryMedium` in tests. */
  medium: RecordMedium;
  /** Private files for the session journal and the sealed saved state (never synchronised, never shared). */
  privateStore: PrivateStore;
  /** This app's content member key. Never reused as a controller. */
  keys: AsyncKeyProvider;
  /** The person's controller key (a passkey or an owner key): asked only for owner operations. */
  ownerController: AsyncKeyProvider;
  /** An optional recovery kit controller (`recover` only, with its own slot). */
  recoveryKeys?: AsyncKeyProvider;
  /** Spec §18: a host creates every account with at least one home and warns when there is none. */
  homes?: HomeConfiguration[];
  /** Explicit opt-out of §18 (tests). The account then reports `noHome`. */
  createWithoutHome?: boolean;
  additionalControllers?: AdditionalController[];
  /** Where the 32-byte device key that seals saved state is kept. */
  deviceSecrets: DeviceSecretStore;
  /** `policy.recoveryDelay` (seconds) of a new account. */
  recoveryDelay?: number;
  /** `policy.history` of a new account. */
  history?: HistoryAccess;
  /** `policy.headQuorum` of a new account. */
  headQuorum?: number;
  /** The clock in milliseconds, for tests. Everything the engine judges by time uses it. */
  now?: () => number;
  /** The longest one exchange with one home may take (default `HomeLimits.exchangeTimeMs`). */
  exchangeTimeMs?: number;
}

/** A member's request for access, as an approver sees it. */
export interface AccessRequest {
  /** The member's key ID. */
  id: string; label: string; kind: glue.AccountMemberKind; termsJson: string;
  /** A short code both devices derive from the key ID: compare it before approving. */
  pairingCode: string;
  /** The request exactly as signed. */
  record: Uint8Array;
  namespaces: string[];
  access: ('read' | 'write')[];
}
export function pairingCode(id: string): string { const head = id.slice(0, 8).toUpperCase(); return `${head.slice(0, 4)}-${head.slice(4, 8)}`; }

/** What a person may be shown about this account that is not content (§17.5, §18). */
export interface SessionNotices {
  /** Transitions still pending, with signers, first-seen seq, deadline and `vetoable`. */
  pending: Pending[];
  /** Activations no key on this device signed that the person has not seen. */
  unseenActivations: SeenActivation[];
  /** The account names no home: warn (spec §18). */
  noHome: boolean;
  owed: Owed[];
  controllersWithoutSlot: string[];
  vaultRetiring: boolean;
}
export const emptyNotices: SessionNotices = { pending: [], unseenActivations: [], noHome: false, owed: [], controllersWithoutSlot: [], vaultRetiring: false };
export const noticesFrom = (n: Notices): SessionNotices => ({ pending: n.pending, unseenActivations: n.activations, noHome: n.noHome, owed: n.owed, controllersWithoutSlot: n.controllersWithoutSlot, vaultRetiring: n.vaultRetiring });

export interface RouteState { home: string; label: string; registered: boolean; detail: string }
/** The outcome of submitting a transition, veto or `suspend` to every current home (§17.5). */
export interface Submission { object: string; kind: 'transition' | 'veto' | 'suspend'; receipted: number; homes: number; finished: boolean }
/** A transition fewer than `headQuorum` homes receipted within 300 s of its `issued`: dead (§17.5). */
export interface DeadTransition { digest: string; receipted: number; quorum: number; canResign: boolean }
/** The removal follow-up of one activation that removed controllers (§17.5), as the person is shown it. */
export interface RemovalCard { seq: bigint; removed: string[]; members: { id: string; label: string }[]; controllers: { id: string; label: string }[] }

/** What a host must do and say beyond the engine's notices (§17.5). */
export interface HostDuties {
  /** The account has one control key: a stolen sole device can't be vetoed. */
  soleDevice: boolean;
  routes: RouteState[];
  submissions: Submission[];
  deadTransitions: DeadTransition[];
  removals: RemovalCard[];
  homeLabels: Record<string, string>;
  /** How often the session polls the homes: `recoveryDelay` / 6, or 15 s while something is pending. */
  pollIntervalMs: number;
}
export const noDuties: HostDuties = { soleDevice: false, routes: [], submissions: [], deadTransitions: [], removals: [], homeLabels: {}, pollIntervalMs: 600_000 };

/** A fault a home raised that the engine did not follow, for the person (or the log) to see. */
export interface HomeFault { home: string; fault: ExchangeFault }

/** Everything the session publishes, as one immutable value. */
export interface SessionState {
  phase: SessionPhase;
  revision: number;
  namespaceRevisions: Record<string, bigint>;
  libraryId?: string;
  memberId?: string;
  members: AccountMember[];
  requests: AccessRequest[];
  lastError?: string;
  context: string;
  notices: SessionNotices;
  homes: Home[];
  duties: HostDuties;
  syncState: HomeSyncState;
  lastSyncedMs?: number;
  homeFaults: HomeFault[];
  homeIssues: HomeIssue[];
}

/** What the worker hands the facade after each operation. */
export interface SessionSnapshot {
  phase: SessionPhase; revision: number; namespaceRevisions: Record<string, bigint>; libraryId?: string; memberId?: string;
  members: AccountMember[]; requests: AccessRequest[]; notices: SessionNotices; homes: Home[]; duties: HostDuties;
}
/** A refusal that carries the fresh snapshot so the facade shows what the person must now see. */
export class SessionRefusal extends Error {
  constructor(readonly snapshot: SessionSnapshot, readonly error: SessionError) { super(error.message); this.name = 'SessionRefusal'; }
}
