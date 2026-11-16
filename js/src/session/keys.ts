import { KeyCustodyError, raceAbort, throwIfAborted } from './errors.js';
import type { StoredKeyPairs, WebCryptoKeyStore } from './indexeddb.js';
import type { EpochAgreement, KeyDescriptor, PrfRequest, PublicKeys, SigningStep, UnlockInput } from './records.js';
import { collectSecrets, SecretBytes } from './secrets.js';
import { glue } from './wasm.js';

/**
 * A WebAuthn get result: the signed bytes exactly as the authenticator returned them, and the PRF output
 * (`results.first`) when a salt was evaluated.
 */
export interface KeyAssertion { signature: Uint8Array; authenticatorData: Uint8Array; clientData: Uint8Array; prf?: SecretBytes }

/**
 * A key the host holds. Raw signatures are `r || s`; WebAuthn assertions keep DER and the original signed bytes.
 * Public points are X9.63 uncompressed; ECDH returns the 32-byte x coordinate. The twin of the Swift and Kotlin
 * `AsyncKeyProvider`. Every method that may wait on a person takes a `signal` and must stop when it is aborted: the
 * session aborts it when it is locked, so a prompt nobody answers never holds the session.
 */
export interface AsyncKeyProvider {
  /** Raw ES256 or WebAuthn assertions. Default: raw. */
  readonly form?: glue.SignForm;
  publicKeys(): Promise<PublicKeys>;
  sign(body: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
  /** Raw 32-byte ECDH with this provider's agreement key. */
  sharedSecret(peer: Uint8Array, signal?: AbortSignal): Promise<SecretBytes>;
  /** The key as the protocol writes it (spec §3.1). Default: the raw descriptor of `publicKeys`. */
  keyDescriptor?(): Promise<KeyDescriptor>;
  /** A WebAuthn get restricted to this credential over `challenge` (base64url), evaluating `prfSalt` when given. */
  assert?(challenge: string, prfSalt?: Uint8Array, signal?: AbortSignal): Promise<KeyAssertion>;
  /** The PRF output of an existing route for `salt`. Absent: unsupported (never a fallback secret). */
  prf?(salt: Uint8Array, signal?: AbortSignal): Promise<SecretBytes>;
}

export async function keyDescriptorOf(provider: AsyncKeyProvider): Promise<KeyDescriptor> {
  if (provider.keyDescriptor) return provider.keyDescriptor();
  const keys = await provider.publicKeys();
  return { form: glue.SignForm.Raw, signing: keys.signing, agreement: keys.agreement.length > 0 ? keys.agreement : undefined, origins: [], authorityOrigins: [] };
}
/** A fresh glue record for one call (a record passed to a call is consumed by it). */
export function descriptorView(d: KeyDescriptor): glue.KeyDescriptorView {
  return new glue.KeyDescriptorView(d.form, d.signing.slice(), d.agreement?.slice(), d.rp, d.credential?.slice(), [...d.origins], [...d.authorityOrigins]);
}
export async function keyIdOf(provider: AsyncKeyProvider): Promise<string> {
  return glue.account_key_id((await provider.publicKeys()).signing);
}

const P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const P256DH = { name: 'ECDH', namedCurve: 'P-256' } as const;
const owned = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

/**
 * Two P-256 keys held by WebCrypto with **non-extractable** private halves: a device's member key, or an owner key in
 * software custody. `generate` keeps them for the life of the page (tests, previews); `openOrCreate` keeps the
 * `CryptoKey` handles in IndexedDB so the same device key is there next time. No accessor exports a private scalar,
 * and the browser refuses to.
 *
 * This is software custody in the browser's profile: it proves nothing about a person being present, and script
 * running on this origin can use the keys while the page is open. A person's controller should be a passkey.
 */
export class WebCryptoKeyProvider implements AsyncKeyProvider {
  readonly form = glue.SignForm.Raw;
  private constructor(private readonly pairs: StoredKeyPairs, private readonly signing: Uint8Array, private readonly agreement: Uint8Array) {}

  static async generate(): Promise<WebCryptoKeyProvider> {
    return WebCryptoKeyProvider.from({
      signing: await crypto.subtle.generateKey(P256, false, ['sign', 'verify']),
      agreement: await crypto.subtle.generateKey(P256DH, false, ['deriveBits']),
    });
  }
  /** The keys stored under `id`, made and stored on first use. Two tabs racing end with the same keys. */
  static async openOrCreate(id: string, store: WebCryptoKeyStore): Promise<WebCryptoKeyProvider> {
    let pairs = await store.read(id);
    if (!pairs) {
      const made = await WebCryptoKeyProvider.generate();
      pairs = await store.insert(id, made.pairs) ? made.pairs : await store.read(id);
    }
    if (!pairs) throw new KeyCustodyError('credentialMissing', 'the stored device key is missing');
    return WebCryptoKeyProvider.from(pairs);
  }
  /** Wraps existing `CryptoKey`s after checking they are P-256, non-extractable and usable. */
  static async from(pairs: StoredKeyPairs): Promise<WebCryptoKeyProvider> {
    for (const [pair, algorithm, usage] of [[pairs.signing, 'ECDSA', 'sign'], [pairs.agreement, 'ECDH', 'deriveBits']] as const) {
      const priv = pair?.privateKey; const pub = pair?.publicKey;
      if (!(priv instanceof CryptoKey) || !(pub instanceof CryptoKey)) throw new KeyCustodyError('credentialMissing', 'expected CryptoKey pairs');
      for (const key of [priv, pub]) {
        if (key.algorithm.name !== algorithm || (key.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256') throw new KeyCustodyError('unsupportedHere', 'expected P-256 keys');
      }
      if (priv.type !== 'private' || priv.extractable || !priv.usages.includes(usage)) throw new KeyCustodyError('unsupportedHere', 'expected a non-extractable private key');
    }
    return new WebCryptoKeyProvider(pairs,
      new Uint8Array(await crypto.subtle.exportKey('raw', pairs.signing.publicKey)),
      new Uint8Array(await crypto.subtle.exportKey('raw', pairs.agreement.publicKey)));
  }

  async publicKeys(): Promise<PublicKeys> { return { signing: this.signing.slice(), agreement: this.agreement.slice() }; }
  async sign(body: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
    throwIfAborted(signal);
    try { return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.pairs.signing.privateKey, owned(body))); }
    catch (error) { throw KeyCustodyError.from(error); }
  }
  async sharedSecret(peer: Uint8Array, signal?: AbortSignal): Promise<SecretBytes> {
    throwIfAborted(signal);
    try {
      const point = await crypto.subtle.importKey('raw', owned(peer), P256DH, false, []);
      // The ArrayBuffer WebCrypto returns is adopted, not copied, so closing the secret wipes it.
      return SecretBytes.adopt(new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: point }, this.pairs.agreement.privateKey, 256)));
    } catch (error) { throw KeyCustodyError.from(error); }
  }
  toString(): string { return 'WebCryptoKeyProvider'; }
}

/** The host's answers, their secrets held as `SecretBytes` until the one export call that takes them. */
export interface HostPrfAnswer { authenticatorData: Uint8Array; clientData: Uint8Array; signature: Uint8Array; secret: SecretBytes }
export interface HostUnlockSecret { kind: glue.UnlockKind; secret: SecretBytes }
export interface HostEpochAnswer { namespace: string; epoch: bigint; secret: SecretBytes }
export interface HostSignature { signature: Uint8Array; authenticatorData?: Uint8Array; clientData?: Uint8Array }

const base64url = (bytes: Uint8Array): string => {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * The host's key custody for one engine operation: the providers it holds, by key ID. The engine never calls a key
 * provider: it returns exact bodies to sign, PRF requests, unlock inputs and epoch agreements, and this type answers
 * them, so raw keys and passkeys are driven the same way. A provider's failure arrives as `KeyCustodyError`.
 */
export class KeyCustody {
  constructor(readonly providers: ReadonlyMap<string, AsyncKeyProvider>) {}
  static async of(list: readonly AsyncKeyProvider[]): Promise<KeyCustody> {
    const map = new Map<string, AsyncKeyProvider>();
    for (const provider of list) map.set(await keyIdOf(provider), provider);
    return new KeyCustody(map);
  }
  provider(id: string): AsyncKeyProvider {
    const found = this.providers.get(id);
    if (!found) throw new KeyCustodyError('noKey', `This device does not hold the key ${id}.`);
    return found;
  }
  holds(id: string): boolean { return this.providers.has(id); }
  merging(id: string, provider: AsyncKeyProvider): KeyCustody { return new KeyCustody(new Map([...this.providers, [id, provider]])); }

  /** One signature per step, in order: raw `r||s`, or the WebAuthn assertion for the step's challenge. */
  async sign(steps: readonly SigningStep[], signal?: AbortSignal): Promise<HostSignature[]> {
    const out: HostSignature[] = [];
    for (const step of steps) {
      throwIfAborted(signal);
      const provider = this.provider(step.signer);
      try {
        if (step.form === glue.SignForm.Raw) out.push({ signature: await raceAbort(provider.sign(step.body, signal), signal) });
        else if (step.form === glue.SignForm.Webauthn) {
          if (step.challenge === undefined) throw new KeyCustodyError('missingChallenge', 'A WebAuthn step carried no challenge.');
          if (!provider.assert) throw new KeyCustodyError('unsupportedHere', 'This key cannot perform the requested ceremony.');
          const result = await raceAbort(provider.assert(step.challenge, undefined, signal), signal, late => late.prf?.close());
          result.prf?.close();
          out.push({ signature: result.signature, authenticatorData: result.authenticatorData, clientData: result.clientData });
        } else throw new KeyCustodyError('unsupportedHere', 'This key has a signing form this client does not know.');
      } catch (error) { throw KeyCustodyError.from(error); }
    }
    return out;
  }

  /** One assertion per request, evaluating the request's salt: `results.first` is the PRF output. No fallback. */
  answer(requests: readonly PrfRequest[], signal?: AbortSignal): Promise<HostPrfAnswer[]> {
    return collectSecrets(requests, async request => {
      throwIfAborted(signal);
      const provider = this.provider(request.controller);
      if (!provider.assert) throw new KeyCustodyError('unsupportedHere', 'This key cannot perform the requested ceremony.');
      let result: KeyAssertion;
      try { result = await raceAbort(provider.assert(base64url(request.challenge), request.salt, signal), signal, late => late.prf?.close()); } catch (error) { throw KeyCustodyError.from(error); }
      if (!result.prf || result.prf.size !== 32) { result.prf?.close(); throw new KeyCustodyError('unsupportedHere', 'The passkey returned no PRF output.'); }
      return { authenticatorData: result.authenticatorData, clientData: result.clientData, signature: result.signature, secret: result.prf };
    });
  }

  /** The raw results of a slot's routes, in input order: ECDH against `enc`, or the PRF of `salt`. */
  answerUnlock(inputs: readonly UnlockInput[], signal?: AbortSignal): Promise<HostUnlockSecret[]> {
    return collectSecrets(inputs, async input => {
      throwIfAborted(signal);
      const provider = this.provider(input.controller);
      try {
        if (input.kind === glue.UnlockKind.Ecdh) return { kind: input.kind, secret: await raceAbort(provider.sharedSecret(input.enc, signal), signal, late => late.close()) };
        if (!provider.prf) throw new KeyCustodyError('unsupportedHere', 'This key cannot perform the requested ceremony.');
        const prf = await raceAbort(provider.prf(input.salt, signal), signal, late => late.close());
        if (prf.size !== 32) { prf.close(); throw new KeyCustodyError('unsupportedHere', 'The passkey returned no PRF output.'); }
        return { kind: input.kind, secret: prf };
      } catch (error) { throw KeyCustodyError.from(error); }
    });
  }

  /** The ECDH results a member's host performs to open its epoch shares. */
  answerEpochs(agreements: readonly EpochAgreement[], signal?: AbortSignal): Promise<HostEpochAnswer[]> {
    return collectSecrets(agreements, async a => {
      throwIfAborted(signal);
      try { return { namespace: a.namespace, epoch: a.epoch, secret: await raceAbort(this.provider(a.recipient).sharedSecret(a.peer, signal), signal, late => late.close()) }; }
      catch (error) { throw KeyCustodyError.from(error); }
    });
  }
}

/** Fresh glue records for one call; the SDK's own copies of the secrets are wiped by the caller right after it. */
export const toSignatures = (list: readonly HostSignature[]): glue.Signature[] =>
  list.map(s => new glue.Signature(s.signature.slice(), s.authenticatorData?.slice(), s.clientData?.slice()));
export const toPrfAnswers = (list: readonly HostPrfAnswer[]): glue.PrfAnswer[] =>
  list.map(a => a.secret.lend(out => new glue.PrfAnswer(a.authenticatorData.slice(), a.clientData.slice(), a.signature.slice(), out)));
export const toUnlockSecrets = (list: readonly HostUnlockSecret[]): glue.UnlockSecret[] =>
  list.map(a => a.secret.lend(secret => new glue.UnlockSecret(a.kind, secret)));
export const toEpochAnswers = (list: readonly HostEpochAnswer[]): glue.EpochAnswer[] =>
  list.map(a => a.secret.lend(shared => new glue.EpochAnswer(a.namespace, a.epoch, shared)));
