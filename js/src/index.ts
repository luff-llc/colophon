/** Colophon 0.2: records and deterministic policy in Rust; private keys and I/O in the host. */
import wasmInit, { HostAction, WasmLibrary } from '../dist/wasm/colophon_wasm.js';

/** Initialize the web-target WASM once. Node reads the file URL; browsers use fetch. */
let initialization: Promise<void> | undefined;
export function init(): Promise<void> {
  initialization ??= (async () => {
    const url = new URL('./wasm/colophon_wasm_bg.wasm', import.meta.url);
    if (url.protocol === 'file:') {
      // A variable import keeps this package independent of @types/node and bundlers.
      const nodeFS = 'node:fs/promises';
      const fs: { readFile(path: URL): Promise<Uint8Array<ArrayBuffer>> } = await import(nodeFS);
      await wasmInit({ module_or_path: await fs.readFile(url) });
    } else {
      await wasmInit({ module_or_path: url });
    }
  })();
  return initialization;
}

export interface KeyProvider {
  readonly signingPublicKey: Uint8Array;
  readonly agreementPublicKey: Uint8Array;
  sign(body: Uint8Array): Promise<Uint8Array>;
  agree(peerPublicKey: Uint8Array): Promise<Uint8Array>;
}

/** Non-extractable P-256 private keys. Persist these CryptoKeys using host structured cloning. */
export class WebCryptoKeys implements KeyProvider {
  private constructor(
    private readonly signing: CryptoKeyPair,
    private readonly agreement: CryptoKeyPair,
    private readonly signingBytes: Uint8Array,
    private readonly agreementBytes: Uint8Array,
  ) {}
  get signingPublicKey(): Uint8Array { return this.signingBytes.slice(); }
  get agreementPublicKey(): Uint8Array { return this.agreementBytes.slice(); }
  static async generate(): Promise<WebCryptoKeys> {
    const signing = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const agreement = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    return WebCryptoKeys.fromKeyPairs(signing, agreement);
  }
  /** Restore host-persisted non-extractable CryptoKeys without exporting private material. */
  static async fromKeyPairs(signing: CryptoKeyPair, agreement: CryptoKeyPair): Promise<WebCryptoKeys> {
    for (const [pair, algorithm, usage] of [[signing, 'ECDSA', 'sign'], [agreement, 'ECDH', 'deriveBits']] as const) {
      for (const key of [pair.privateKey, pair.publicKey]) {
        if (key.algorithm.name !== algorithm || (key.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256') throw new Error('Expected P-256 keys');
      }
      if (pair.privateKey.type !== 'private' || pair.privateKey.extractable || !pair.privateKey.usages.includes(usage)) throw new Error('Expected a non-extractable private key');
      if (pair.publicKey.type !== 'public') throw new Error('Expected a public key');
    }
    const result = new WebCryptoKeys(signing, agreement,
      new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey)),
      new Uint8Array(await crypto.subtle.exportKey('raw', agreement.publicKey)));
    // Reject accidentally mismatched persisted public/private pairs before they can create records.
    const challenge = new Uint8Array(32);
    const signature = await result.sign(challenge);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, signing.publicKey, copy(signature), challenge)) throw new Error('Signing key pair mismatch');
    const peer = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const peerBytes = new Uint8Array(await crypto.subtle.exportKey('raw', peer.publicKey));
    const left = await result.agree(peerBytes);
    const right = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: agreement.publicKey }, peer.privateKey, 256));
    if (!equal(left, right)) throw new Error('Agreement key pair mismatch');
    return result;
  }
  /** Host storage handle: CryptoKey private halves remain non-extractable. */
  keyPairs(): { signing: CryptoKeyPair; agreement: CryptoKeyPair } {
    return { signing: { ...this.signing }, agreement: { ...this.agreement } };
  }
  async sign(body: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.signing.privateKey, copy(body)));
  }
  async agree(peerPublicKey: Uint8Array): Promise<Uint8Array> {
    const peer = await crypto.subtle.importKey('raw', copy(peerPublicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, this.agreement.privateKey, 256));
  }
}
function copy(value: Uint8Array): Uint8Array<ArrayBuffer> { return new Uint8Array(value); }
function equal(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function entropy(): Uint8Array { return crypto.getRandomValues(new Uint8Array(32)); }
function now(): string { return new Date().toISOString(); }
function json(value: unknown): string { const result = JSON.stringify(value); if (result === undefined) throw new Error('Expected JSON input'); return result; }

export type MemberKind = 'device' | 'app' | 'agent' | 'server';
export type Access = 'read' | 'write';
export interface Grant { namespaces: string[]; access: Access[]; expires?: string; writeBudget?: number }
export interface Member { id: string; label: string; kind: MemberKind; grant: Grant | null; since: number; revokedAt: number | null; writes: number }
export type Records = Map<string, Uint8Array>;
export interface AccessRequest { id: string; label: string; kind: MemberKind; namespaces: string[]; access: Access[]; pairingCode: string; record: Uint8Array }
export type Outcome<T> = { ok: true; value: T } | { ok: false; reason: 'notGranted' | 'revoked' | 'expired' | 'budgetSpent' | 'notReadable' | 'unavailable'; detail: string };
export interface OperationView { id: string; kind: string; author: string; authorLabel: string; origin: 'person' | 'ai'; clock: number; created: string; payload: unknown }
export interface NamespaceView<State = unknown> { namespace: string; admitted: OperationView[]; held: { id: string; author: string; reason: string }[]; refused: { id: string; author: string; reason: string }[]; state: State }
export interface LedgerEntry { sequence: number; at: string; actor: string; actorLabel: string; event: 'created' | 'requested' | 'granted' | 'revoked' | 'rekeyed' | 'wrote' | 'held' | 'refused'; subject?: string; text: string }
export interface Tool { name: string; description: string; inputSchema: unknown }

/** An in-memory library. Hosts persist and sync records; no storage backend is assumed. */
export class Library {
  readonly records: Records = new Map();
  /** Present on creation; persist independently from the owner's keys for recovery. */
  readonly recoveryKeys?: KeyProvider;
  private queue: Promise<unknown> = Promise.resolve();
  private unlockFailure: unknown;
  private constructor(private readonly core: WasmLibrary, private readonly keys: KeyProvider, recovery?: KeyProvider) { this.recoveryKeys = recovery; }

  static async create(opts: { owner: KeyProvider; label: string; ownerLabel: string; namespaces: string[]; recovery?: KeyProvider }): Promise<Library> {
    await init();
    const recovery = opts.recovery ?? await WebCryptoKeys.generate();
    const core = new WasmLibrary(opts.owner.signingPublicKey, opts.owner.agreementPublicKey);
    const lib = new Library(core, opts.owner, recovery);
    const action = core.begin_create(opts.label, opts.ownerLabel, json(opts.namespaces), recovery.signingPublicKey, recovery.agreementPublicKey, now(), entropy());
    await lib.execute(action);
    return lib;
  }
  static async open(records: Records, me: KeyProvider): Promise<Library> {
    await init();
    const lib = new Library(new WasmLibrary(me.signingPublicKey, me.agreementPublicKey), me);
    for (const [path, raw] of records) lib.core.import_record(path, raw);
    lib.core.merge(); lib.refreshRecords(); await lib.unlock();
    return lib;
  }
  static async requestAccess(opts: { libraryID: string; keys: KeyProvider; label: string; kind: MemberKind; namespaces: string[]; access: Access[] }): Promise<AccessRequest> {
    await init();
    const action = WasmLibrary.begin_request(opts.keys.signingPublicKey, opts.keys.agreementPublicKey, json({ libraryID: opts.libraryID, label: opts.label, kind: opts.kind, namespaces: opts.namespaces, access: opts.access, created: now() }));
    let consumed = false;
    try {
      for (let i = 0; i < action.count(); i++) action.sign(i, await opts.keys.sign(action.body(i)));
      consumed = true;
      const record = action.finish_request();
      return { ...JSON.parse(WasmLibrary.request_info(record, opts.libraryID)), record };
    } finally { if (!consumed) action.free(); }
  }
  get id(): string { return this.core.id(); }
  me(): Member { return JSON.parse(this.core.me()); }
  members(): Member[] { return JSON.parse(this.core.members()); }
  ledger(): LedgerEntry[] { return JSON.parse(this.core.ledger()); }

  approve(request: Uint8Array, grant?: Partial<Grant>): Promise<Outcome<Member>> {
    return this.serial(async () => {
      await this.unlock();
      const info: AccessRequest = JSON.parse(WasmLibrary.request_info(request, this.id));
      const narrowed: Grant = { ...grant, namespaces: grant?.namespaces ?? info.namespaces, access: grant?.access ?? info.access };
      const result = await this.execute(this.core.begin_approve(request, json(narrowed), now(), entropy()));
      if (!result.ok) return result;
      const member = this.members().find(m => m.id === info.id);
      if (!member) throw new Error('Approved member missing');
      return { ok: true, value: member };
    });
  }
  revoke(memberID: string): Promise<Outcome<void>> {
    return this.serial(async () => { await this.unlock(); const result = await this.execute(this.core.begin_revoke(memberID, now(), entropy())); return result.ok ? { ok: true, value: undefined } : result; });
  }
  /** Authority changes apply synchronously. New ECDH steps finish asynchronously; await ready() before view. */
  merge(records: Records): void {
    for (const [path, raw] of records) this.core.import_record(path, raw);
    this.core.merge(); this.refreshRecords();
    // Observe failures here to avoid an unhandled rejection; ready() reports them to the caller.
    void this.serial(async () => { try { await this.unlock(); } catch (error) { this.unlockFailure = error; } });
  }
  /** Await key opening after synchronous merge. Async write/approve/call also do this automatically. */
  async ready(): Promise<void> {
    await this.queue;
    if (this.unlockFailure !== undefined) { const error = this.unlockFailure; this.unlockFailure = undefined; throw error; }
    await this.unlock();
  }
  write(namespace: string, kind: string, payload: unknown): Promise<Outcome<OperationView>> {
    return this.serial(async () => { await this.unlock(); return this.executeWrite(this.core.begin_write(namespace, kind, json(payload), now(), entropy()), namespace); });
  }
  view<State = unknown>(namespace: string): Outcome<NamespaceView<State>> { return JSON.parse(this.core.view(namespace, now())); }
  tools(): Tool[] { return JSON.parse(this.core.tools(now())); }
  call(tool: string, input: unknown): Promise<Outcome<unknown>> {
    return this.serial(async () => {
      await this.unlock();
      const action = this.core.begin_call(tool, json(input), now(), entropy());
      const immediate: Outcome<unknown> | null = JSON.parse(action.settled());
      if (immediate !== null) { action.free(); return immediate; }
      const namespace = tool.split('__')[0];
      if (!namespace) { action.free(); throw new Error('Missing tool namespace'); }
      return this.executeWrite(action, namespace);
    });
  }
  /** Planned handover shares all epochs before transferring authority. */
  handover(root: KeyProvider, label: string): Promise<Outcome<void>> {
    return this.serial(async () => { await this.unlock(); const result = await this.execute(this.core.begin_handover(root.signingPublicKey, root.agreementPublicKey, label, now(), entropy())); return result.ok ? { ok: true, value: undefined } : result; });
  }
  /** Open with recoveryKeys first, then transfer authority and all data epochs to a fresh root. */
  recover(root: KeyProvider, label: string): Promise<Outcome<void>> {
    return this.serial(async () => { await this.unlock(); const result = await this.execute(this.core.begin_recover(root.signingPublicKey, root.agreementPublicKey, label, now(), entropy())); return result.ok ? { ok: true, value: undefined } : result; });
  }
  private serial<T>(work: () => Promise<T>): Promise<T> {
    const result = this.queue.then(work);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
  private async unlock(): Promise<void> {
    while (this.core.unlock_count() > 0) {
      const step = this.core.begin_unlock(0);
      let secret: Uint8Array | undefined;
      try { secret = await this.keys.agree(step.peer()); this.core.finish_unlock(step.namespace(), step.epoch(), secret); }
      finally { secret?.fill(0); step.free(); }
    }
  }
  private async execute(action: HostAction): Promise<Outcome<void>> {
    const immediate: Outcome<void> | null = JSON.parse(action.settled());
    if (immediate !== null) { action.free(); return immediate; }
    let consumed = false;
    try {
      for (let i = 0; i < action.count(); i++) {
        if (!equal(action.signing_key(i), this.keys.signingPublicKey)) throw new Error('Unexpected signing identity');
        action.sign(i, await this.keys.sign(action.body(i)));
      }
      consumed = true;
      this.core.commit(action); this.refreshRecords(); await this.unlock();
      return { ok: true, value: undefined };
    } finally { if (!consumed) action.free(); }
  }
  private async executeWrite(action: HostAction, namespace: string): Promise<Outcome<OperationView>> {
    const immediate: Outcome<OperationView> | null = JSON.parse(action.settled());
    if (immediate !== null) { action.free(); return immediate; }
    const path = action.path(0);
    const id = path.slice(path.lastIndexOf('-') + 1, -5);
    const result = await this.execute(action);
    if (!result.ok) return result;
    const view = this.view(namespace);
    if (!view.ok) return view;
    const operation = view.value.admitted.find(op => op.id === id);
    return operation ? { ok: true, value: operation } : { ok: false, reason: 'unavailable', detail: 'The signed operation is held or refused under the merged authority history' };
  }
  private refreshRecords(): void {
    for (let i = 0; i < this.core.record_count(); i++) this.records.set(this.core.record_path(i), this.core.record(i));
  }
}
