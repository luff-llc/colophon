import { Library, type KeyDescriptor, type KeyProvider, type WebauthnResult } from '../index.js';
import { KeyProviderError, keyProviderError } from './errors.js';

/** Injectable browser ceremony boundary, also usable by tests. */
export interface CredentialClient {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
}
type PasskeyDescriptor = Extract<KeyDescriptor, { form: 'webauthn' }>;
type PRFOutputs = { prf?: { results?: { first?: ArrayBuffer } } };

/** WebAuthn controller. Every PRF evaluation uses get restricted to one credential. */
export class PasskeyProvider implements KeyProvider {
  readonly form = 'webauthn' as const;
  private readonly key: PasskeyDescriptor;
  constructor(key: PasskeyDescriptor, private readonly credentials?: CredentialClient) {
    this.key = structuredClone(key);
  }
  /** Protocol descriptor; registration public-key parsing is performed by WASM. */
  descriptor(): PasskeyDescriptor { return structuredClone(this.key); }
  get signingPublicKey(): Uint8Array { return decode(this.key.signing); }
  get agreementPublicKey(): Uint8Array { return new Uint8Array(); }

  /** Register ES256 with UV. Registration extension outputs are never used for slots. */
  static async register(options: { rp: PublicKeyCredentialRpEntity & { id: string }; user: PublicKeyCredentialUserEntity; challenge?: Uint8Array }, credentials?: CredentialClient): Promise<PasskeyProvider> {
    let credential: PublicKeyCredential;
    try {
      const result = await client(credentials).create({ publicKey: {
        rp: options.rp, user: options.user, challenge: new Uint8Array(options.challenge ?? randomChallenge()),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none',
        authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
        extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
      } });
      if (!result) throw new KeyProviderError('cancelled', 'Registration cancelled');
      credential = publicKey(result);
    } catch (error) { throw keyProviderError(error); }
    const response = credential.response as AuthenticatorAttestationResponse;
    const key = await Library.parseRegistration(new Uint8Array(response.attestationObject), options.rp.id);
    if (key.form !== 'webauthn' || !same(decode(key.credential), new Uint8Array(credential.rawId))) {
      throw new KeyProviderError('credentialMissing', 'Registration credential does not match attestation');
    }
    return new PasskeyProvider(key, credentials);
  }

  /** The challenge is the core's unpadded base64url SHA-256(body), passed unchanged. */
  async assert(challenge: string, prfSalt?: Uint8Array): Promise<WebauthnResult> {
    if (prfSalt && prfSalt.length !== 32) throw new KeyProviderError('unsupportedHere', 'PRF salt must be 32 bytes');
    try {
      const result = await client(this.credentials).get({ publicKey: {
        challenge: decode(challenge), rpId: this.key.rp, userVerification: 'required',
        allowCredentials: [{ type: 'public-key', id: decode(this.key.credential) }],
        ...(prfSalt ? { extensions: { prf: { eval: { first: new Uint8Array(prfSalt) } } } as AuthenticationExtensionsClientInputs } : {}),
      } });
      if (!result) throw new KeyProviderError('credentialMissing', 'Credential missing');
      const credential = publicKey(result);
      if (!same(new Uint8Array(credential.rawId), decode(this.key.credential))) throw new KeyProviderError('credentialMissing', 'Unexpected credential');
      const response = credential.response as AuthenticatorAssertionResponse;
      const first = (credential.getClientExtensionResults() as PRFOutputs).prf?.results?.first;
      if (prfSalt && (!first || first.byteLength !== 32)) throw new KeyProviderError('unsupportedHere', 'WebAuthn PRF missing results.first');
      return {
        signature: new Uint8Array(response.signature).slice(), authenticatorData: new Uint8Array(response.authenticatorData).slice(),
        clientData: new Uint8Array(response.clientDataJSON).slice(), ...(prfSalt && first ? { prf: new Uint8Array(first).slice() } : {}),
      };
    } catch (error) { throw keyProviderError(error); }
  }
  /** Existing-slot opening still performs a fresh get ceremony. */
  async prf(salt: Uint8Array): Promise<Uint8Array> {
    const result = await this.assert(encodeURL(randomChallenge()), salt);
    if (!result.prf) throw new KeyProviderError('unsupportedHere', 'WebAuthn PRF missing results.first');
    return result.prf;
  }
  async sign(_body: Uint8Array): Promise<Uint8Array> { throw new KeyProviderError('unsupportedHere', 'Passkeys require an assertion'); }
  async agree(_peer: Uint8Array): Promise<Uint8Array> { throw new KeyProviderError('unsupportedHere', 'Passkeys do not provide ECDH'); }
}
function client(injected?: CredentialClient): CredentialClient {
  const result = injected ?? globalThis.navigator?.credentials;
  if (!result) throw new KeyProviderError('unsupportedHere', 'WebAuthn unavailable');
  return result;
}
function publicKey(value: Credential): PublicKeyCredential {
  if (value.type !== 'public-key') throw new KeyProviderError('credentialMissing', 'Expected public-key credential');
  return value as PublicKeyCredential;
}
function randomChallenge(): Uint8Array<ArrayBuffer> {
  if (!globalThis.crypto?.getRandomValues) throw new KeyProviderError('unsupportedHere', 'Secure randomness unavailable');
  return crypto.getRandomValues(new Uint8Array(32));
}
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, i) => byte === b[i]); }
function decode(value: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
function encodeURL(value: Uint8Array): string { return btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
