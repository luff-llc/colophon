import { KeyCustodyError } from './errors.js';
import type { AsyncKeyProvider, KeyAssertion } from './keys.js';
import type { KeyDescriptor, PublicKeys } from './records.js';
import { SecretBytes } from './secrets.js';
import { glue } from './wasm.js';

/** The browser's ceremony boundary (`navigator.credentials`), injectable. */
export interface CredentialClient {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
}
type PrfOutputs = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } } };

export interface PasskeyRegistration {
  /** The relying party ID (a registrable domain the page's origin belongs to). */
  rpId: string;
  rpName: string;
  /** The account ID when the account exists (spec §17.4: `user.id` is its UTF-8 bytes), else nothing (32 random bytes). */
  account?: string;
  userName: string;
  userDisplayName?: string;
  /** Origins that may make account-authority assertions with this key. Default: this page's origin. */
  authorityOrigins?: string[];
  /** Origins that may make any assertion with this key. Default: `authorityOrigins`. Every authority origin must be among them. */
  origins?: string[];
  challenge?: Uint8Array;
  signal?: AbortSignal;
}

const owned = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);
const fromBase64 = (value: string): Uint8Array => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

function client(injected?: CredentialClient): CredentialClient {
  const found = injected ?? (globalThis.navigator?.credentials as CredentialClient | undefined);
  if (!found) throw new KeyCustodyError('unsupportedHere', 'WebAuthn is not available here');
  return found;
}
function publicKeyCredential(value: Credential | null, missing: string): PublicKeyCredential {
  if (!value) throw new KeyCustodyError('cancelled', missing);
  if (value.type !== 'public-key') throw new KeyCustodyError('credentialMissing', 'Expected a public-key credential');
  return value as PublicKeyCredential;
}

/**
 * A person's passkey as a controller key: WebAuthn ES256 with user verification, and the PRF extension for the vault
 * slot. Every ceremony is a `get` restricted to this one credential. A passkey that returns no PRF output where one is
 * needed fails (`unsupportedHere`): there is no software fallback and no stand-in secret. The private key never
 * leaves the authenticator; this object holds only the public descriptor.
 */
export class PasskeyProvider implements AsyncKeyProvider {
  readonly form = glue.SignForm.Webauthn;
  private readonly descriptor: KeyDescriptor;
  constructor(descriptor: KeyDescriptor, private readonly credentials?: CredentialClient) {
    if (descriptor.form !== glue.SignForm.Webauthn || !descriptor.rp || !descriptor.credential) throw new KeyCustodyError('unsupportedHere', 'not a WebAuthn key descriptor');
    this.descriptor = { ...descriptor, signing: descriptor.signing.slice(), credential: descriptor.credential.slice(), origins: [...descriptor.origins], authorityOrigins: [...descriptor.authorityOrigins] };
  }

  /** The WebAuthn `user.id` to register with (spec §17.4): the UTF-8 account ID when it exists, else 32 random bytes. */
  static userId(account?: string): Uint8Array {
    return account !== undefined ? new TextEncoder().encode(account) : crypto.getRandomValues(new Uint8Array(32));
  }

  /**
   * Registers an ES256 credential with user verification and the PRF extension, and returns the provider over the
   * descriptor the core parsed from the attestation (never a registration PRF output). Fails when the authenticator
   * says it has no PRF.
   */
  static async register(options: PasskeyRegistration, credentials?: CredentialClient): Promise<PasskeyProvider> {
    const authorityOrigins = [...(options.authorityOrigins ?? (globalThis.location ? [globalThis.location.origin] : []))].sort();
    const origins = [...new Set([...(options.origins ?? []), ...authorityOrigins])].sort();
    if (authorityOrigins.length === 0) throw new KeyCustodyError('unsupportedHere', 'a passkey controller needs at least one authority origin');
    let credential: PublicKeyCredential;
    try {
      credential = publicKeyCredential(await client(credentials).create({
        signal: options.signal,
        publicKey: {
          rp: { id: options.rpId, name: options.rpName },
          user: { id: owned(PasskeyProvider.userId(options.account)), name: options.userName, displayName: options.userDisplayName ?? options.userName },
          challenge: owned(options.challenge ?? crypto.getRandomValues(new Uint8Array(32))),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none',
          authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
          extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
        },
      }), 'Registration was cancelled');
    } catch (error) { throw KeyCustodyError.from(error); }
    const extensions = credential.getClientExtensionResults() as PrfOutputs;
    if (extensions.prf?.enabled === false) throw new KeyCustodyError('unsupportedHere', 'This passkey does not support the PRF extension, which the vault needs.');
    const response = credential.response as AuthenticatorAttestationResponse;
    // The core checks the RP binding and extracts the key; nothing here trusts the attestation.
    const parsed = JSON.parse(glue.WasmLibrary.parse_registration(new Uint8Array(response.attestationObject), options.rpId)) as { form?: string; signing?: string; credential?: string; rp?: string };
    if (parsed.form !== 'webauthn' || typeof parsed.signing !== 'string' || typeof parsed.credential !== 'string') throw new KeyCustodyError('credentialMissing', 'The registration is not a WebAuthn ES256 credential');
    const id = fromBase64(parsed.credential);
    if (!same(id, new Uint8Array(credential.rawId))) throw new KeyCustodyError('credentialMissing', 'The registered credential does not match its attestation');
    return new PasskeyProvider({ form: glue.SignForm.Webauthn, signing: fromBase64(parsed.signing), rp: options.rpId, credential: id, origins, authorityOrigins }, credentials);
  }

  async keyDescriptor(): Promise<KeyDescriptor> {
    const d = this.descriptor;
    return { ...d, signing: d.signing.slice(), credential: d.credential!.slice(), origins: [...d.origins], authorityOrigins: [...d.authorityOrigins] };
  }
  async publicKeys(): Promise<PublicKeys> { return { signing: this.descriptor.signing.slice(), agreement: new Uint8Array(0) }; }

  /** The challenge is the core's unpadded base64url value, passed unchanged. */
  async assert(challenge: string, prfSalt?: Uint8Array, signal?: AbortSignal): Promise<KeyAssertion> {
    if (prfSalt && prfSalt.length !== 32) throw new KeyCustodyError('unsupportedHere', 'A PRF salt is 32 bytes');
    try {
      const credential = publicKeyCredential(await client(this.credentials).get({
        signal,
        publicKey: {
          challenge: owned(fromBase64(challenge)), rpId: this.descriptor.rp, userVerification: 'required',
          allowCredentials: [{ type: 'public-key', id: owned(this.descriptor.credential!) }],
          ...(prfSalt ? { extensions: { prf: { eval: { first: owned(prfSalt) } } } as AuthenticationExtensionsClientInputs } : {}),
        },
      }), 'The passkey prompt was cancelled');
      // The PRF output is taken first, into memory this SDK wipes: the browser's own buffer is adopted, and every
      // failure below wipes it. A missing output is a failure, never a fallback.
      const first = (credential.getClientExtensionResults() as PrfOutputs).prf?.results?.first;
      const output = first === undefined ? undefined : first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
      let prf: SecretBytes | undefined;
      try {
        if (!same(new Uint8Array(credential.rawId), this.descriptor.credential!)) throw new KeyCustodyError('credentialMissing', 'Another credential answered');
        if (prfSalt) {
          if (!output || output.length !== 32) throw new KeyCustodyError('unsupportedHere', 'The passkey returned no PRF output');
          prf = SecretBytes.adopt(output);
        } else output?.fill(0);
      } catch (error) { output?.fill(0); throw error; }
      const response = credential.response as AuthenticatorAssertionResponse;
      return { signature: new Uint8Array(response.signature).slice(), authenticatorData: new Uint8Array(response.authenticatorData).slice(), clientData: new Uint8Array(response.clientDataJSON).slice(), prf };
    } catch (error) { throw KeyCustodyError.from(error); }
  }

  /** Opening an existing slot is a fresh get ceremony evaluating the slot's exact salt. */
  async prf(salt: Uint8Array, signal?: AbortSignal): Promise<SecretBytes> {
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    let text = '';
    for (const b of challenge) text += String.fromCharCode(b);
    const result = await this.assert(btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), salt, signal);
    if (!result.prf) throw new KeyCustodyError('unsupportedHere', 'The passkey returned no PRF output');
    return result.prf;
  }
  async sign(): Promise<Uint8Array> { throw new KeyCustodyError('unsupportedHere', 'A passkey signs by assertion'); }
  async sharedSecret(): Promise<SecretBytes> { throw new KeyCustodyError('unsupportedHere', 'A passkey has no agreement key'); }
}
