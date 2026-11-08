/** Colophon 0.4: records and deterministic policy in Rust; private keys and I/O in the host. */
import wasmInit, { HostAction, HostCombinedParts, WasmLibrary } from '../dist/wasm/colophon_wasm.js';

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

export type KeyForm = 'raw' | 'webauthn';
/** Protocol JSON bytes use standard base64. */
export type KeyDescriptor = { form: 'raw'; signing: string; agreement?: string } |
  { form: 'webauthn'; signing: string; rp: string; credential: string; origins?: string[] };
export interface Controller { key: KeyDescriptor; label: string; roles: ('approve' | 'control' | 'recover')[]; verification?: true }
export interface Sealed { enc: string; ciphertext: string }
export type Slot = { kind: 'sealed'; controllers: string[]; label: string; sealed: Sealed } |
  { kind: 'prf'; controllers: string[]; label: string; salt: string; box: string } |
  { kind: 'combined'; controllers: string[]; label: string; parts: ({ kind: 'sealed'; sealed: Sealed } | { kind: 'prf'; salt: string })[]; box: string };
export interface Keyring { controllers: Controller[]; threshold: number; recoverThreshold: number; vault: { signing: string; agreement: string }; slots: Slot[] }
export interface WebauthnResult { signature: Uint8Array; authenticatorData: Uint8Array; clientData: Uint8Array; prf?: Uint8Array }
export interface SlotOption { index: number; label: string; inputs: ({ kind: 'ecdh'; controller: string; enc: number[] } | { kind: 'prf'; controller: string; salt: number[] })[] }
export interface KeyProvider {
  readonly form?: KeyForm;
  /** get must be restricted to this provider's single credential. */
  assert?(challenge: string, prfSalt?: Uint8Array): Promise<WebauthnResult>;
  /** Existing-route PRF evaluation; missing output is an explicit failure. */
  prf?(salt: Uint8Array): Promise<Uint8Array | undefined>;
  readonly signingPublicKey: Uint8Array;
  readonly agreementPublicKey: Uint8Array;
  sign(body: Uint8Array): Promise<Uint8Array>;
  agree(peerPublicKey: Uint8Array): Promise<Uint8Array>;
}

/** Non-extractable P-256 private keys. Persist these CryptoKeys using host structured cloning. */
export class WebCryptoKeys implements KeyProvider {
  readonly form = 'raw' as const;
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
    let right: Uint8Array | undefined;
    try {
      right = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: agreement.publicKey }, peer.privateKey, 256));
      if (!equal(left, right)) throw new Error('Agreement key pair mismatch');
    } finally {
      left.fill(0);
      right?.fill(0);
    }
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
function equal(a: Uint8Array, b: Uint8Array): boolean {
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return difference === 0;
}
function entropy(): Uint8Array { return crypto.getRandomValues(new Uint8Array(32)); }
function now(): string { return new Date().toISOString(); }
function json(value: unknown): string { const result = JSON.stringify(value); if (result === undefined) throw new Error('Expected JSON input'); return result; }

export type MemberKind = 'device' | 'app' | 'agent' | 'server';
export type Access = 'read' | 'write';
export interface Grant { import?: true; namespaces: string[]; access: Access[]; expires?: string; writeBudget?: number }
export interface Member { id: string; label: string; kind: MemberKind; grant: Grant | null; since: number; revokedAt: number | null; writes: number }
export type Records = Map<string, Uint8Array>;
export interface AccessRequest { id: string; label: string; kind: MemberKind; namespaces: string[]; access: Access[]; pairingCode: string; record: Uint8Array }
export type Outcome<T> = { ok: true; value: T } | { ok: false; reason: 'notGranted' | 'revoked' | 'expired' | 'budgetSpent' | 'notReadable' | 'unavailable'; detail: string };
export interface OperationView { id: string; kind: string; author: string; authorLabel: string; origin: 'person' | 'ai'; clock: number; created: string; payload: unknown }
export interface NamespaceView<State = unknown> { namespace: string; admitted: OperationView[]; held: { id: string; author: string; reason: string }[]; refused: { id: string; author: string; reason: string }[]; state: State }
export interface LedgerEntry { sequence: number; at: string; actor: string; actorLabel: string; event: 'created' | 'requested' | 'granted' | 'revoked' | 'rekeyed' | 'wrote' | 'held' | 'refused'; subject?: string; namespace?: string; kind?: string; origin?: 'person' | 'ai'; text: string }
export interface Tool { name: string; description: string; inputSchema: unknown }

/** An in-memory library. Hosts persist and sync records; no storage backend is assumed. */
export class Library {
  readonly records: Records = new Map();
  private controllers: KeyProvider[] = [];
  private queue: Promise<unknown> = Promise.resolve();
  private unlockFailure: unknown;
  private constructor(private readonly core: WasmLibrary, private readonly keys: KeyProvider) {}

  static async create(opts: { owner: KeyProvider; controller: KeyProvider; label: string; ownerLabel: string; namespaces: string[] }): Promise<Library> {
    await init();
    const controller = opts.controller;
    const core = new WasmLibrary(opts.owner.signingPublicKey, opts.owner.agreementPublicKey);
    const lib = new Library(core, opts.owner);
    lib.controllers = [controller];
    const first = core.begin_create(opts.label, opts.ownerLabel, json(opts.namespaces), controller.signingPublicKey, controller.agreementPublicKey, entropy(), now(), entropy());
    await lib.signAction(first, [opts.owner, controller]);
    const final = first.advance_create();
    await lib.signAction(final, [controller]);
    core.commit(final); lib.refreshRecords();
    core.select_controller(await controllerID(controller.signingPublicKey));
    await lib.unlockVault([controller]);
    await lib.unlock();
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
  /** Make controller providers available for authority signatures. */
  setControllers(providers: KeyProvider[]): void { this.controllers = [...providers]; }
  selectController(id: string): void { this.core.select_controller(id); }
  keyring(): Keyring { return JSON.parse(this.core.keyring()); }
  static async parseRegistration(attestationObject: Uint8Array, rp: string): Promise<KeyDescriptor> {
    await init(); return JSON.parse(WasmLibrary.parse_registration(attestationObject, rp));
  }
  /** Open one complete route; every PRF byte is the platform's results.first. */
  async unlockVault(providers: KeyProvider[] = this.controllers): Promise<void> {
    const available = new Map<string, KeyProvider>();
    for (const provider of providers) available.set(await controllerID(provider.signingPublicKey), provider);
    const options: SlotOption[] = JSON.parse(this.core.begin_unlock_slots());
    for (const option of options) {
      if (!option.inputs.every(input => available.has(input.controller))) continue;
      const secrets: { kind: string; bytes: number[] }[] = [];
      try {
        for (const input of option.inputs) {
          const provider = available.get(input.controller);
          if (!provider) throw new Error('Missing controller');
          const output = input.kind === 'ecdh' ? await provider.agree(new Uint8Array(input.enc)) : await provider.prf?.(new Uint8Array(input.salt));
          if (!output) throw new Error('WebAuthn PRF unsupported or missing results.first');
          secrets.push({ kind: input.kind, bytes: Array.from(output) }); output.fill(0);
        }
        this.core.finish_unlock_slot(option.index, json(secrets)); return;
      } finally { for (const secret of secrets) secret.bytes.fill(0); }
    }
    throw new Error('No available vault route');
  }
  prepareAuthority(action: unknown, by: string, signers: string[]): HostAction {
    return this.core.prepare_authority(json(action), by, json(signers), now());
  }
  finishAuthority(action: HostAction): Promise<Outcome<void>> { return this.serial(() => this.execute(action)); }
  buildSealedSlot(controller: Controller, label: string, newSeed?: Uint8Array): Slot {
    return JSON.parse(this.core.build_sealed_slot(json(controller), label, newSeed ?? new Uint8Array(), entropy()));
  }
  async buildPasskeySlot(key: KeyDescriptor, provider: KeyProvider, label: string, newSeed?: Uint8Array): Promise<Slot> {
    const action = this.core.begin_prf_slot(json(key), entropy());
    let consumed = false;
    let result: WebauthnResult | undefined;
    try {
      result = await provider.assert?.(action.challenge(), action.salt());
      if (!result?.prf) throw new Error('WebAuthn assertion or PRF unsupported');
      consumed = true;
      return JSON.parse(this.core.finish_prf_slot(action, result.signature, result.authenticatorData, result.clientData, result.prf, label, newSeed ?? new Uint8Array(), entropy()));
    } finally { result?.prf?.fill(0); if (!consumed) action.free(); }
  }
  /** Build a combined route, verifying every get assertion and reopening every part. */
  async buildCombinedSlot(parts: { controller: Controller; provider: KeyProvider }[], label: string, newSeed?: Uint8Array): Promise<Slot> {
    const builder = new HostCombinedParts();
    const outputs: (Uint8Array | undefined)[] = [];
    let builderConsumed = false;
    let pending: ReturnType<WasmLibrary['begin_combined_slot']> | undefined;
    const secrets: { kind: string; bytes: number[] }[] = [];
    try {
      for (const part of parts) {
        if (part.controller.key.form === 'raw') { builder.sealed(json(part.controller)); outputs.push(undefined); }
        else {
          const ceremony = this.core.begin_prf_slot(json(part.controller.key), entropy());
          let consumed = false;
          try {
            const result = await part.provider.assert?.(ceremony.challenge(), ceremony.salt());
            if (!result?.prf) throw new Error('WebAuthn assertion or PRF unsupported');
            outputs.push(result.prf);
            consumed = true;
            builder.prf(json(part.controller), ceremony, result.signature, result.authenticatorData, result.clientData, result.prf);
          } finally { if (!consumed) ceremony.free(); }
        }
      }
      builderConsumed = true;
      pending = this.core.begin_combined_slot(builder, label, newSeed ?? new Uint8Array(), entropy());
      for (let i = 0; i < parts.length; i++) {
        const input = (JSON.parse(pending.inputs()) as SlotOption['inputs'])[i];
        const part = parts[i];
        if (!input || !part) throw new Error('Missing combined part');
        const output = input.kind === 'prf' ? outputs[i] : await part.provider.agree(new Uint8Array(input.enc));
        if (!output) throw new Error('Missing combined secret');
        secrets.push({ kind: input.kind, bytes: Array.from(output) });
        if (input.kind === 'ecdh') output.fill(0);
      }
      const completed = pending; pending = undefined;
      return JSON.parse(this.core.finish_combined_slot(completed, json(secrets)));
    } finally {
      for (const output of outputs) output?.fill(0);
      for (const secret of secrets) secret.bytes.fill(0);
      pending?.free(); if (!builderConsumed) builder.free();
    }
  }
  /** Candidate controllers and forms; finishing verifies the complete quorum. */
  eligibleSigners(action: unknown): Controller[] { return JSON.parse(this.core.eligible_signers(json(action))); }
  static async vaultPublic(seed: Uint8Array): Promise<{ signing: string; agreement: string }> { await init(); return JSON.parse(WasmLibrary.vault_public(seed)); }
  static async webauthnPRFInput(salt: Uint8Array): Promise<Uint8Array> { await init(); return WasmLibrary.webauthn_prf_input(salt); }
  addController(controller: Controller, slot: Slot | undefined, signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_add_controller(json(controller), json(slot ?? null), json(signers), now())));
  }
  recoveryAdd(controller: Controller, slot: Slot | undefined, signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_recovery_add(json(controller), json(slot ?? null), json(signers), now())));
  }
  addPasskey(controller: Controller, slot: Slot, signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_add_passkey(json(controller), json(slot), json(signers), now())));
  }
  removeController(id: string, newSeed: Uint8Array, slots: Slot[], signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_remove_controller(id, newSeed, json(slots), json(signers), now(), entropy())));
  }
  replaceKeyring(keyring: Keyring, newSeed: Uint8Array | undefined, signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_keyring(json(keyring), newSeed ?? new Uint8Array(), json(signers), now(), entropy())));
  }
  importGrant(request: Uint8Array, grant: Grant, signers: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_import_grant(request, json(grant), json(signers), now(), entropy())));
  }
  rekey(namespaces: string[]): Promise<Outcome<void>> {
    return this.serial(() => this.execute(this.core.begin_rekey(json(namespaces), now(), entropy())));
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
      await this.signAction(action, [this.keys, ...this.controllers]);
      consumed = true;
      this.core.commit(action); this.refreshRecords(); await this.unlock();
      return { ok: true, value: undefined };
    } finally { if (!consumed) action.free(); }
  }
  private async signAction(action: HostAction, providers: KeyProvider[]): Promise<void> {
    for (let i = 0; i < action.count(); i++) {
      const descriptor: KeyDescriptor = JSON.parse(action.descriptor(i));
      const provider = providers.find(p => equal(p.signingPublicKey, action.signing_key(i)) && (p.form ?? 'raw') === descriptor.form);
      if (!provider) throw new Error('Unexpected signing identity or form');
      const challenge = action.challenge(i);
      if (challenge) {
        const result = await provider.assert?.(challenge);
        if (!result) throw new Error('WebAuthn assertion unsupported');
        action.assert(i, result.signature, result.authenticatorData, result.clientData);
      } else action.sign(i, await provider.sign(action.body(i)));
    }
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

/** Controller key ID, shared with the core's first 16 SHA-256 bytes. */
export async function controllerID(signing: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', copy(signing))).slice(0, 16), b => b.toString(16).padStart(2, '0')).join('');
}
export { HostAction };
