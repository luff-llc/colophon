/**
 * The engine's records as plain values (see `plain` in `wasm.ts`): the names of docs/bindings-05.md §6 in camelCase.
 * Enums are the glue's numeric enums, re-exported from the package root.
 */
import type { glue } from './wasm.js';

export interface KeyDescriptor {
  form: glue.SignForm; signing: Uint8Array; agreement?: Uint8Array; rp?: string; credential?: Uint8Array;
  origins: string[]; authorityOrigins: string[];
}
export interface PublicKeys { signing: Uint8Array; agreement: Uint8Array }
export interface Store { path: string; bytes: Uint8Array }
export interface SigningStep {
  path: string; body: Uint8Array; signer: string; role: glue.StepRole; form: glue.SignForm; descriptor?: KeyDescriptor;
  signingKey: Uint8Array; challenge?: string; uv: boolean;
}
export interface PrfRequest { controller: string; rp: string; credential: Uint8Array; salt: Uint8Array; challenge: Uint8Array }
export interface UnlockInput { kind: glue.UnlockKind; controller: string; enc: Uint8Array; salt: Uint8Array }
export interface EpochAgreement { namespace: string; epoch: bigint; recipient: string; recipientPoint: Uint8Array; peer: Uint8Array }
export interface SlotController { id: string; label: string }
export interface SlotInfo { index: bigint; kind: glue.SlotKind; kindRaw?: string; label: string; controllers: SlotController[] }
export interface Status { seq: bigint; code: string; kind: glue.StatusKind; reason?: string; stopSeq?: bigint; detail?: string; rollback: boolean;
  /** Set when this reader is stopped for the account (§1 "A stop"): a verified state, not a fault. */
  stopped?: AccountStop }
/** Where a reader stopped: the raising activation's seq and the layout it names (none for an entry of a newer format). */
export interface AccountStop { seq: bigint; layout?: bigint }
export interface NamespaceRevision { namespace: string; revision: bigint }
export interface Changes {
  authorityFromSeq: bigint; authorityToSeq: bigint; namespaces: NamespaceRevision[]; membersAdded: string[]; membersRevoked: string[];
  vaultChanged: boolean; policyChanged: boolean; reorganized: boolean; pendingNow: string[]; status?: Status;
}
export interface Written { stores: Store[]; changes: Changes; artifact?: Uint8Array }
export interface Controller {
  id: string; label: string; roles: glue.ControllerRole[]; rolesRaw: string[]; key: KeyDescriptor; form: glue.SignForm; verification: boolean;
  holder?: string; hasSlot: boolean; provisional: boolean; suspended: boolean; addedSeq: bigint; addedBy: string[];
}
export interface AccountGrant { namespaces: string[]; access: glue.AccessKind[]; expires?: string; writeBudget?: bigint; import: boolean }
export interface AccountMember {
  id: string; label: string; kind: glue.AccountMemberKind; kindRaw?: string; grant?: AccountGrant; since: bigint; revokedAt?: bigint;
  writes: bigint; expiresMs?: bigint; provisional: boolean; home: boolean; session: bigint; grantedBy: string[];
}
export interface Standing { kind: glue.StandingKind; controller?: Controller; member?: AccountMember; unknownId?: string }
export interface Home { id: string; label: string; status: glue.HomeStatus; statusRaw?: string; endpoints: string[]; primary: boolean }
export interface Policy {
  threshold: bigint; recoverThreshold: bigint; addThreshold: bigint; countByHolders: boolean; callWindow: bigint; headMaxAge: bigint;
  headQuorum: bigint; linkMaxAge: bigint; memberRule: string; recoveryDelay: bigint; primaryHome?: string;
}
export interface Signer { id: string; label: string }
export interface Pending {
  digest: string; by: string; signers: Signer[]; issuedMs: bigint; anchorSeq: bigint; firstSeenSeq?: bigint; dueMs?: bigint;
  vetoDeadlineMs?: bigint; fullSet?: boolean; components: string[]; removes: string[]; adds: string[]; vetoes: string[]; vetoable: boolean;
}
export interface Receipted { home: string; receivedMs: bigint }
export interface SeenActivation { seq: bigint; transition: string; signers: string[]; components: string[]; receipted: Receipted[] }
export interface Owed { member: string; namespace: string; epoch: bigint; provisional: boolean }
export interface Notices {
  pending: Pending[]; activations: SeenActivation[]; owed: Owed[]; controllersWithoutSlot: string[]; vaultRetiring: boolean; noHome: boolean;
}
export interface AccountDenial { reason: glue.AccountDenialReason; reasonRaw?: string; detail: string }
export interface RemovalFollowUp { seq: bigint; anchorSeq: bigint; removed: string[]; members: string[]; controllers: string[] }
export interface Header { name: string; value: string }
export interface HttpRequest { ticket: bigint; home: string; method: glue.HttpMethod; url: string; headers: Header[]; body: Uint8Array }
export interface CallNeed { ticket: bigint; home: string; audience: string; purpose: string; method: glue.HttpMethod; url: string; path: string; bodySha256: string }
export interface ExchangeStep { kind: glue.ExchangeStepKind; request?: HttpRequest; need?: CallNeed }
export interface ExchangeFault {
  kind: glue.ExchangeFaultKind; home: string; path?: string; feed?: string; code?: string; what?: string; why?: string;
  purpose?: string; audience?: string; endpoints: string[]; status?: number;
}
export interface Report { store: Store[]; changes: Changes; faults: ExchangeFault[] }
export interface RequestInfo { raw: Uint8Array; member: string; label: string; kind: glue.AccountMemberKind; kindRaw?: string; termsJson: string }
export interface BlobAvailability { state: glue.BlobState; present: bigint; total: bigint; detail?: string }
export interface BlobChunk { path: string; bytes: Uint8Array }
export interface Created { account: string; stores: Store[] }
export interface HistoryReport { code: string; kind: glue.StatusKind; reason?: string; seq: bigint; detail?: string; rollback: boolean; account?: string }
export interface SealedSeed { enc: Uint8Array; ciphertext: Uint8Array }
export interface SavedPart { namespace: string; bytes: Uint8Array }
