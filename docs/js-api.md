# `@colophon/core` JavaScript API (contract)

The npm package in `js/` wraps `crates/colophon-wasm`. The playground and any web client use only
this surface. Names here are the contract between the core and the playground; the core may add to
it, but changes to these names are agreed first.

All binary values cross the boundary as `Uint8Array`; IDs are lowercase hex strings; dates are ISO
8601 strings. Host steps (signing, ECDH) are `async`, and the package drives the core's two-phase
calls, so callers just `await`.

```ts
export function init(): Promise<void>;                 // loads the wasm module once

// Keys: private keys never enter the core.
export interface KeyProvider {
  readonly signingPublicKey: Uint8Array;              // P-256, X9.63 uncompressed
  readonly agreementPublicKey: Uint8Array;            // P-256, X9.63 uncompressed
  sign(body: Uint8Array): Promise<Uint8Array>;        // ECDSA P-256 SHA-256, raw r||s (64 bytes)
  agree(peerPublicKey: Uint8Array): Promise<Uint8Array>; // ECDH shared secret (32 bytes)
}
export class WebCryptoKeys implements KeyProvider {   // non-extractable CryptoKeys
  static generate(): Promise<WebCryptoKeys>;
}

export type MemberKind = 'device' | 'app' | 'agent' | 'server';
export type Access = 'read' | 'write';

export interface Grant {
  namespaces: string[];
  access: Access[];
  expires?: string;
  writeBudget?: number;
}

export interface Member {
  id: string; label: string; kind: MemberKind;
  grant: Grant | null;          // null for the root
  since: number;                // authority sequence it was admitted at
  revokedAt: number | null;
  writes: number;               // admitted operations it authored
}

// A library's records, keyed by their storage path (spec §5.1). Hosts persist and sync them;
// any two clients holding the same records compute the same views.
export type Records = Map<string, Uint8Array>;

export interface AccessRequest {
  id: string; label: string; kind: MemberKind;
  namespaces: string[]; access: Access[];
  pairingCode: string;          // six digits both sides display
  record: Uint8Array;           // the signed request to hand to the root
}

export type Outcome<T> =
  | { ok: true; value: T }
  | { ok: false; reason: 'notGranted' | 'revoked' | 'expired' | 'budgetSpent' | 'notReadable' | 'unavailable'; detail: string };

export interface OperationView {
  id: string; kind: string; author: string; authorLabel: string;
  origin: 'person' | 'ai';      // from the author's member kind, never from the payload
  clock: number; created: string;
  payload: unknown;
}

export interface NamespaceView<State = unknown> {
  namespace: string;
  admitted: OperationView[];
  held: { id: string; author: string; reason: string }[];
  refused: { id: string; author: string; reason: string }[];
  state: State;                 // the domain fold: saved shelf, podcasts, notebooks
}

// One entry of the colophon page: the plain-language ledger of the library.
export interface LedgerEntry {
  sequence: number; at: string;
  actor: string; actorLabel: string;
  event: 'created' | 'requested' | 'granted' | 'revoked' | 'rekeyed' | 'wrote' | 'held' | 'refused';
  subject?: string;             // member or operation ID
  text: string;                 // e.g. "Llama on MacBook could read listening and write notes"
}

export class Library {
  static create(opts: { owner: KeyProvider; label: string; ownerLabel: string; namespaces: string[] }): Promise<Library>;
  static open(records: Records, me: KeyProvider): Promise<Library>;

  readonly id: string;
  readonly records: Records;    // a live view; hosts persist the deltas
  me(): Member;
  members(): Member[];
  ledger(): LedgerEntry[];

  // A prospective member asks. It runs on the member's side, before it has any access.
  static requestAccess(opts: { libraryID: string; keys: KeyProvider; label: string; kind: MemberKind;
                               namespaces: string[]; access: Access[] }): Promise<AccessRequest>;
  // The root approves or ends access. Ending access rotates every namespace the member could read.
  approve(request: Uint8Array, grant?: Partial<Grant>): Promise<Outcome<Member>>;
  revoke(memberID: string): Promise<Outcome<void>>;

  // Records arriving from elsewhere (another member, a relay).
  merge(records: Records): void;

  write(namespace: string, kind: string, payload: unknown): Promise<Outcome<OperationView>>;
  view<State = unknown>(namespace: string): Outcome<NamespaceView<State>>;

  // Agent tooling generated from the domain modules' operation and query specs.
  tools(): { name: string; description: string; inputSchema: unknown }[];
  call(tool: string, input: unknown): Promise<Outcome<unknown>>;
}
```

The `colophon` CLI and the MCP server use the same tool list, so an agent sees identical tools in a
browser, a terminal and an MCP client.
