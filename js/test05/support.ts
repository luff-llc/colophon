// Shared by the Bun run and the browser run: nothing here touches Node, Bun or the DOM.
import {
  ColophonSession, FetchHomeTransport, glue, MemoryDeviceSecrets, MemoryMedium, MemoryPrivateStore, plain, WebCryptoKeyProvider,
  type AdditionalController, type AsyncKeyProvider, type DeviceSecretStore, type HistoryAccess, type HomeConfiguration, type HomeTransport,
  type AccessRequest, type PrivateStore, type RecordMedium, type RequestInfo, type SigningStep, type WriteReceipt,
} from '../src/session/index.js';

export function assert(condition: unknown, message: string | (() => string)): asserts condition {
  if (!condition) throw new Error(`assertion failed: ${typeof message === 'function' ? message() : message}`);
}
export function equal<T>(actual: T, expected: T, message: string): void {
  assert(actual === expected, () => `${message}: expected ${String(expected)}, got ${String(actual)}`);
}
export const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
export const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

/** One device of a test account: a session over its own medium, with WebCrypto keys and private state in memory. */
export class Device {
  readonly session: ColophonSession;
  private constructor(readonly medium: RecordMedium, readonly member: AsyncKeyProvider, readonly owner: AsyncKeyProvider, session: ColophonSession) { this.session = session; }
  static async make(options: {
    medium?: RecordMedium; member?: AsyncKeyProvider; owner?: AsyncKeyProvider; homes?: HomeConfiguration[]; createWithoutHome?: boolean;
    additional?: AdditionalController[]; namespaces?: string[]; libraryNamespaces?: string[]; history?: HistoryAccess; headQuorum?: number; secrets?: DeviceSecretStore;
    privateStore?: PrivateStore; exchangeTimeMs?: number;
  } = {}): Promise<Device> {
    const medium = options.medium ?? new MemoryMedium();
    const member = options.member ?? await WebCryptoKeyProvider.generate();
    const owner = options.owner ?? await WebCryptoKeyProvider.generate();
    const session = new ColophonSession({
      memberLabel: 'Test device', namespaces: options.namespaces ?? ['notes'], libraryNamespaces: options.libraryNamespaces, medium, privateStore: options.privateStore ?? new MemoryPrivateStore(),
      keys: member, ownerController: owner, homes: options.homes ?? [], createWithoutHome: options.createWithoutHome ?? (options.homes === undefined),
      additionalControllers: options.additional ?? [], deviceSecrets: options.secrets ?? new MemoryDeviceSecrets(), history: options.history,
      headQuorum: options.headQuorum, exchangeTimeMs: options.exchangeTimeMs,
    });
    return new Device(medium, member, owner, session);
  }
  close(): void { this.session.shutdown(); }
  describe(): string {
    const s = this.session.state;
    return `phase ${JSON.stringify(s.phase)} error ${s.lastError ?? '-'} issues ${JSON.stringify(s.homeIssues)} faults ${JSON.stringify(s.homeFaults.map(f => [glue.ExchangeFaultKind[f.fault.kind], f.fault.status, f.fault.code, f.fault.what, f.fault.why]))} sync ${JSON.stringify(s.syncState)}`;
  }
}

/** The number of admitted records in a namespace's fold (`view_json`). */
export async function admitted(session: ColophonSession, namespace = 'notes'): Promise<number> {
  const v = JSON.parse(await session.view(namespace)) as { ok?: boolean; value?: { admitted?: unknown[] } };
  assert(v.ok === true, () => `view refused: ${JSON.stringify(v)}`);
  assert(Array.isArray(v.value?.admitted), 'no admitted list');
  return v.value.admitted.length;
}
/** A note, written as the Rust journey writes it. */
export function note(session: ColophonSession, id: string): Promise<WriteReceipt> {
  return session.perform({ namespace: 'notes', kind: 'note.put', payloadJson: JSON.stringify({ id, text: id }) }, session.observedRevision);
}

/** Where the relays run: a Bun process spawns them; a browser asks the test server to. */
export interface RelayHost {
  freePort(): Promise<number>;
  /** Starts `bun relay/server.js --test-clock` on `port` for `account` at `base`, with the home key `jwk`. */
  start(spec: { port: number; account: string; base: string; jwk: JsonWebKey; peers: { base: string; port: number }[] }): Promise<void>;
  /** The URL that reaches the relay's slot (`/v1/libraries/home`) on `port` from this runtime. */
  local(port: number): string;
  /** Sets the relay's test clock to now. */
  touchClock(port: number): Promise<void>;
  stopAll(): Promise<void>;
}

const b64url = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * The real relay as a home. Its key is a P-256 key this test made (extractable, so the relay can be given it as a
 * private JWK: a test key, never an account key); the home's signed member request is made with the same key.
 */
export class RelayHome {
  private started = false;
  private constructor(readonly host: RelayHost, readonly base: string, readonly port: number, private readonly signing: CryptoKeyPair, private readonly point: Uint8Array, private readonly agreement: Uint8Array) {}
  static async make(host: RelayHost, base: string): Promise<RelayHome> {
    const signing = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const agreement = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return new RelayHome(host, base, await host.freePort(), signing,
      new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey)), new Uint8Array(await crypto.subtle.exportKey('raw', agreement.publicKey)));
  }
  get id(): string { return glue.account_key_id(this.point); }
  async start(account: string, peers: RelayHome[]): Promise<void> {
    if (this.started) return;
    const jwk = await crypto.subtle.exportKey('jwk', this.signing.privateKey);
    await this.host.start({ port: this.port, account, base: this.base, jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }, peers: peers.map(p => ({ base: p.base, port: p.port })) });
    this.started = true;
  }
  /** The home's signed member request (§9.1) naming `account`, as a home service answers it. */
  async memberRequest(account: string): Promise<Uint8Array> {
    const spec = new glue.RequestSpec(account, this.point, this.agreement, 'Relay home', glue.AccountMemberKind.Server, '{"serves":["home"]}',
      glue.account_format_date(BigInt(Date.now() - 5000)), undefined, undefined, [`${this.base}/`]);
    const request = glue.AccountRequest.prepare(spec);
    const step = plain<SigningStep>(request.step());
    const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.signing.privateKey, new Uint8Array(step.body)));
    const info = plain<RequestInfo>(request.finish(new glue.Signature(signature, undefined, undefined)));
    request.free();
    return info.raw;
  }
  /**
   * The session's transport to this relay: the account's `https://` name goes to the process on loopback (plain `http`
   * allowed for loopback only, by the SDK's testing option) through the SDK's own `FetchHomeTransport`, and the
   * relay's clock is set to now first. `refusals` collects the `result` of every 403.
   */
  transport(refusals?: string[]): HomeTransport {
    const inner = new FetchHomeTransport({ allowingLoopbackHttp: true });
    return {
      send: async (request, signal) => {
        await this.host.touchClock(this.port);
        assert(request.url.startsWith(this.base), `a request for another host: ${request.url}`);
        const answer = await inner.send({ ...request, url: this.host.local(this.port) + request.url.slice(this.base.length) }, signal);
        if (answer.status === 403 && refusals) {
          let result = '-';
          try { result = (JSON.parse(new TextDecoder().decode(answer.body)) as { result?: string }).result ?? '-'; } catch { /* not JSON */ }
          refusals.push(result);
        }
        return answer;
      },
    };
  }
}
export { b64url };

// Pairing before approval (§7.3, §9.1)

/**
 * The six-digit code between a joining device and an approving one, each through its own session, with the messages passed
 * between them as an app would carry them: the request with the commitment, the nonce, the reveal. Both screens' digits
 * are compared and both devices confirm. Returns the request the approving device approves and its confirmed pairing.
 */
export async function pairByCode(joining: ColophonSession, approving: ColophonSession): Promise<{ request: AccessRequest; pairing: glue.AccountPairing }> {
  const raw = await joining.exportRequest();
  const j = await joining.beginJoinPairing();
  const start = await approving.beginApproval(j.commitment());
  const reveal = j.receive_nonce(start.nonce);
  assert(reveal !== undefined, 'a code-path joiner reveals');
  const code = await approving.approvalCode(start.pairing, reveal.e, reveal.nb);
  equal(code, j.digits(), 'both screens show the same six digits');
  assert(/^\d{6}$/.test(code), 'six digits');
  j.confirm(); start.pairing.confirm();
  const info = plain<RequestInfo>(glue.account_request_info(raw));
  const request: AccessRequest = { id: info.member, label: info.label, kind: info.kind, termsJson: info.termsJson, record: info.raw, namespaces: [], access: [] };
  return { request, pairing: start.pairing };
}

/** Pairs by the code and approves. */
export async function approveByCode(joining: ColophonSession, approving: ColophonSession, termsJson?: string): Promise<void> {
  const { request, pairing } = await pairByCode(joining, approving);
  await approving.approve(request, pairing, termsJson);
}

/** The scan path: the approving device scans the joining device's request (its canonical envelope) and approves it. */
export async function approveByScan(joining: ColophonSession, approving: ColophonSession, termsJson?: string): Promise<void> {
  const scanned = await approving.scanRequest(await joining.exportRequest());
  await approving.approve(scanned.request, scanned.pairing, termsJson);
}
