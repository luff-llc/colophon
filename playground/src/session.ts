/** Device sessions keep controller authority separate from member authorship. */
import * as core from './core';

/** Host-owned device keys; external controller providers may use hardware or PRF. */
export interface DeviceKeys {
  /** Controller authority provider, independent of member authorship. */
  readonly owner: core.KeyProvider;
  /** Per-app member identity used to open epochs and sign content. */
  readonly member: core.KeyProvider;
}

/** Creation inputs. Recovery kits require a genesis-capable core creation API. */
export interface SessionOptions extends DeviceKeys {
  label: string;
  memberLabel: string;
  namespaces: string[];
  recoveryKit?: core.KeyProvider;
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
    if (options.recoveryKit) {
      throw new Error('The core creation API cannot include a recovery-kit controller and slot in genesis.');
    }
    if ((options.owner.form ?? 'raw') !== 'raw') {
      throw new Error('The core creation API requires a raw device controller. Open existing libraries with an external controller provider.');
    }
    const library = await core.Library.create({
      owner: options.member,
      controller: options.owner,
      label: options.label,
      ownerLabel: options.memberLabel,
      namespaces: options.namespaces,
    });
    return new DeviceSession(library, { owner: options.owner, member: options.member });
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
