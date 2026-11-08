/** Device sessions keep controller authority separate from member authorship. */
import * as core from './core';

/** Host-owned device keys; external controller providers may use hardware or PRF. */
export interface DeviceKeys {
  /** Controller authority provider, independent of member authorship. */
  readonly owner: core.KeyProvider;
  /** Per-app member identity used to open epochs and sign content. */
  readonly member: core.KeyProvider;
}

/** Creation inputs, including an optional independent recovery-kit controller. */
export interface SessionOptions extends DeviceKeys {
  label: string;
  memberLabel: string;
  namespaces: string[];
  recoveryKit?: core.KeyProvider;
  recoveryLabel?: string;
  importedFrom?: string;
  importExpires?: string;
}

/** A member replica with a separate owner provider for authority actions. */
export class DeviceSession {
  /** Verified member replica and its signed records. */
  readonly library: core.Library;
  /** Host providers; the vault seed is held only by the core session. */
  readonly keys: DeviceKeys;

  private constructor(library: core.Library, keys: DeviceKeys) {
    this.library = library;
    this.keys = keys;
  }

  /** Create through the core's two signing rounds, including member grant and layout 2. */
  static async create(options: SessionOptions): Promise<DeviceSession> {
    if ((options.owner.form ?? 'raw') !== 'raw') {
      throw new Error('Creation requires a raw device controller. Open existing libraries with an external controller provider.');
    }
    if (options.recoveryKit && (options.recoveryKit.form ?? 'raw') !== 'raw') {
      throw new Error('A recovery kit requires separate raw signing and agreement keys.');
    }
    await core.init();
    const wasm = new core.WasmLibrary(options.member.signingPublicKey, options.member.agreementPublicKey);
    const vaultSeed = crypto.getRandomValues(new Uint8Array(32));
    const entropy = crypto.getRandomValues(new Uint8Array(32));
    let action: core.HostAction | undefined;
    try {
      action = wasm.begin_create_with(JSON.stringify({
        label: options.label,
        ownerLabel: options.memberLabel,
        namespaces: options.namespaces,
        recoveryLabel: options.recoveryLabel,
        importedFrom: options.importedFrom,
        importExpires: options.importExpires,
      }), options.owner.signingPublicKey, options.owner.agreementPublicKey, vaultSeed,
      options.recoveryKit?.signingPublicKey, options.recoveryKit?.agreementPublicKey,
      new Date().toISOString(), entropy);
      // Only the owner and member sign creation. The kit supplies public keys only.
      await signCreation(action, [options.owner, options.member]);
      const first = action;
      action = undefined; // advance_create consumes the first round, including on error.
      action = first.advance_create();
      await signCreation(action, [options.owner]);
      const final = action;
      action = undefined;
      wasm.commit(final);
      const records: core.Records = new Map();
      for (let i = 0; i < wasm.record_count(); i++) records.set(wasm.record_path(i), wasm.record(i));
      const session = await DeviceSession.open(records, { owner: options.owner, member: options.member });
      await session.library.unlockVault([options.owner]);
      return session;
    } finally {
      action?.free();
      wasm.free();
      vaultSeed.fill(0);
      entropy.fill(0);
    }
  }

  /** Open member epochs; authority operations unlock a controller slot when needed. */
  static async open(records: core.Records, keys: DeviceKeys): Promise<DeviceSession> {
    const library = await core.Library.open(records, keys.member);
    library.setControllers([keys.owner]);
    library.selectController(await core.controllerID(keys.owner.signingPublicKey));
    return new DeviceSession(library, keys);
  }

  /** Unlock the owner's sealed or provider-backed PRF route before granting access. */
  async approve(request: Uint8Array, grant?: Partial<core.Grant>): Promise<core.Outcome<core.Member>> {
    await this.library.unlockVault([this.keys.owner]);
    return this.library.approve(request, grant);
  }

  /** Unlock the vault before revocation seals replacement epochs. */
  async revoke(memberID: string): Promise<core.Outcome<void>> {
    await this.library.unlockVault([this.keys.owner]);
    return this.library.revoke(memberID);
  }

  /** Restore using only a kit, records and fresh device keys, preserving the prior keyring. */
  static async restore(options: DeviceKeys & {
    records: core.Records;
    recoveryKit: core.KeyProvider;
    memberLabel: string;
  }): Promise<DeviceSession> {
    // The kit is a controller, never the replica's member identity.
    const library = await core.Library.open(options.records, options.member);
    const kitID = await core.controllerID(options.recoveryKit.signingPublicKey);
    const keyring = library.keyring();
    if (!keyring.controllers.some(c => c.roles.includes('recover')) || keyring.recoverThreshold === 0) {
      throw new Error('This keyring has no recovery rule.');
    }
    library.setControllers([options.recoveryKit]);
    await library.unlockVault([options.recoveryKit]);
    const controller: core.Controller = {
      key: rawDescriptor(options.owner),
      label: `${options.memberLabel}'s device controller`,
      roles: keyring.recoverThreshold < keyring.threshold ? ['approve'] : ['approve', 'control'],
    };
    const slot = library.buildSealedSlot(controller, controller.label);
    requireSuccess(await library.recoveryAdd(controller, slot, [kitID]));

    library.setControllers([options.owner]);
    library.selectController(await core.controllerID(options.owner.signingPublicKey));
    await library.unlockVault([options.owner]);
    const request = await core.Library.requestAccess({
      libraryID: library.id,
      keys: options.member,
      label: options.memberLabel,
      kind: 'device',
      namespaces: libraryNamespaces(library),
      access: ['read', 'write'],
    });
    requireSuccess(await library.approve(request.record));
    return new DeviceSession(library, { owner: options.owner, member: options.member });
  }
}

async function signCreation(action: core.HostAction, providers: core.KeyProvider[]): Promise<void> {
  for (let i = 0; i < action.count(); i++) {
    const signing = action.signing_key(i);
    const provider = providers.find(candidate => {
      const publicKey = candidate.signingPublicKey;
      return publicKey.length === signing.length && publicKey.every((byte, index) => byte === signing[index]);
    });
    if (!provider) throw new Error('Unexpected creation signer');
    action.sign(i, await provider.sign(action.body(i)));
  }
}

function requireSuccess<T>(outcome: core.Outcome<T>): T {
  if (!outcome.ok) throw new Error(outcome.detail);
  return outcome.value;
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function rawDescriptor(provider: core.KeyProvider): core.KeyDescriptor {
  if ((provider.form ?? 'raw') !== 'raw') {
    throw new Error('The demo restores a raw device controller; supply a raw signing and agreement provider.');
  }
  return { form: 'raw', signing: base64(provider.signingPublicKey), agreement: base64(provider.agreementPublicKey) };
}

function libraryNamespaces(library: core.Library): string[] {
  const genesis = library.records.get('authority/00000001.json');
  if (!genesis) throw new Error('Missing verified genesis record');
  // These bytes have already passed the core's strict parsing and signature checks.
  const envelope = JSON.parse(new TextDecoder().decode(genesis)) as { body: string };
  const body = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(envelope.body), c => c.charCodeAt(0)))) as { namespaces: string[] };
  return [...body.namespaces];
}
