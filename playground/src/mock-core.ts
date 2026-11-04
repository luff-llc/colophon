/* ============================================================================
 * MOCK CORE — PREVIEW IMPLEMENTATION, NOT THE REAL @colophon/core.
 * ----------------------------------------------------------------------------
 * This file implements the docs/js-api.md contract with believable behaviour
 * so the playground can be built while the real Rust/WASM core lands:
 *
 *  - Real WebCrypto keys: P-256 ECDSA signing + P-256 ECDH agreement,
 *    non-extractable private keys, raw r||s signatures, ECDH-wrapped epoch
 *    keys, AES-256-GCM sealed operations. Nothing here is faked crypto.
 *  - Real signed records in memory (canonical JSON bodies, verified bytes).
 *  - Grants enforced on every read/write/tool call; revocation refuses later
 *    writes while keeping earlier notes; AI origin derived from member kind.
 *
 * What it does NOT do: persist anything itself, speak to a network, implement
 * the full 0.1/0.2 spec (no handover, keyring, blobs, caveats beyond the
 * js-api Grant). Hosts persist `library.records` and re-open with
 * `Library.open()` — exactly like the real package.
 *
 * The UI must treat this as a preview: core.ts exposes IS_MOCK_CORE so the
 * page can show a "preview core" badge while this file backs it.
 * ========================================================================== */

export async function init(): Promise<void> {
  // The real package loads the WASM module here. The mock has no module.
}

/* ------------------------------------------------------------------ */
/* Types: exact names from docs/js-api.md                             */
/* ------------------------------------------------------------------ */

export interface KeyProvider {
  readonly signingPublicKey: Uint8Array; // P-256, X9.63 uncompressed
  readonly agreementPublicKey: Uint8Array; // P-256, X9.63 uncompressed
  sign(body: Uint8Array): Promise<Uint8Array>; // ECDSA P-256 SHA-256, raw r||s
  agree(peerPublicKey: Uint8Array): Promise<Uint8Array>; // ECDH secret (32B)
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
  id: string;
  label: string;
  kind: MemberKind;
  grant: Grant | null; // null for the root
  since: number; // authority sequence it was admitted at
  revokedAt: number | null;
  writes: number; // admitted operations it authored
}

export type Records = Map<string, Uint8Array>;

export interface AccessRequest {
  id: string;
  label: string;
  kind: MemberKind;
  namespaces: string[];
  access: Access[];
  pairingCode: string; // six digits both sides display
  record: Uint8Array; // the signed request to hand to the root
}

export type Outcome<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      reason: 'notGranted' | 'revoked' | 'expired' | 'budgetSpent' | 'notReadable' | 'unavailable';
      detail: string;
    };

export interface OperationView {
  id: string;
  kind: string;
  author: string;
  authorLabel: string;
  origin: 'person' | 'ai'; // from the author's member kind, never the payload
  clock: number;
  created: string;
  payload: unknown;
}

export interface NamespaceView<State = unknown> {
  namespace: string;
  admitted: OperationView[];
  held: { id: string; author: string; reason: string }[];
  refused: { id: string; author: string; reason: string }[];
  state: State; // the domain fold
}

export interface LedgerEntry {
  sequence: number;
  at: string;
  actor: string;
  actorLabel: string;
  event: 'created' | 'requested' | 'granted' | 'revoked' | 'rekeyed' | 'wrote' | 'held' | 'refused';
  subject?: string; // member or operation ID
  text: string;
}

/** Present only on the mock. Lets the UI badge itself honestly. */
export const IS_MOCK_CORE = true;

/* ------------------------------------------------------------------ */
/* Byte helpers                                                       */
/* ------------------------------------------------------------------ */

const te = new TextEncoder();
const td = new TextDecoder();

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toB64(bytes: Uint8Array): string {
  let bin = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === 'string' ? te.encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)));
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function randomHex(nBytes: number): string {
  return toHex(randomBytes(nBytes));
}

/** Canonical JSON: sorted keys, slashes unescaped (spec §2). */
function canonicalJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(',')}}`;
}

/* ------------------------- ECDSA DER <-> raw ------------------------- */

function derToRaw(der: Uint8Array): Uint8Array {
  // 0x30 len 0x02 rlen r 0x02 slen s
  let o = 2;
  if (der[0] !== 0x30) throw new Error('bad DER');
  if ((der[o] ?? 0) & 0x80) o += ((der[o] ?? 0) & 0x7f) + 1;
  else o += 1;
  if (der[o] !== 0x02) throw new Error('bad DER');
  const rLen = der[o + 1] ?? 0;
  let r = der.slice(o + 2, o + 2 + rLen);
  o = o + 2 + rLen;
  if (der[o] !== 0x02) throw new Error('bad DER');
  const sLen = der[o + 1] ?? 0;
  let s = der.slice(o + 2, o + 2 + sLen);
  while (r.length > 32) r = r.slice(1);
  while (s.length > 32) s = s.slice(1);
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

function rawToDer(raw: Uint8Array): Uint8Array {
  const half = (h: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < h.length - 1 && h[i] === 0) i++;
    let v = h.slice(i);
    if ((v[0] ?? 0) & 0x80) {
      const w = new Uint8Array(v.length + 1);
      w.set(v, 1);
      v = w;
    }
    const out = new Uint8Array(v.length + 2);
    out[0] = 0x02;
    out[1] = v.length;
    out.set(v, 2);
    return out;
  };
  const r = half(raw.slice(0, 32));
  const s = half(raw.slice(32, 64));
  const out = new Uint8Array(r.length + s.length + 2);
  out[0] = 0x30;
  out[1] = r.length + s.length;
  out.set(r, 2);
  out.set(s, 2 + r.length);
  return out;
}

async function importSigningKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );
}

async function importAgreementKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

/** Browsers return DER from ECDSA sign; Node 24+ returns raw r||s. Accept both. */
function toRawSignature(out: Uint8Array): Uint8Array {
  if (out.length === 64 && out[0] !== 0x30) return out;
  return derToRaw(out);
}

async function verifyRaw(pubRaw: Uint8Array, body: Uint8Array, sigRaw: Uint8Array): Promise<boolean> {
  try {
    const key = await importSigningKey(pubRaw);
    const alg = { name: 'ECDSA', hash: 'SHA-256' };
    if (await crypto.subtle.verify(alg, key, rawToDer(sigRaw) as BufferSource, body as BufferSource)) {
      return true;
    }
    // Second chance for runtimes that verify raw directly (Node 24+);
    // browsers just answer false here.
    return await crypto.subtle
      .verify(alg, key, sigRaw as BufferSource, body as BufferSource)
      .catch(() => false);
  } catch {
    return false;
  }
}

/* ------------------------- sealing (spec §4) ------------------------- */

const SEALED_KEY_INFO = te.encode('colophon/sealed-key/1');

async function aesSeal(keyBytes: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ]);
  const nonce = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce as BufferSource }, key, plaintext as BufferSource),
  );
  const out = new Uint8Array(12 + ct.length);
  out.set(nonce, 0);
  out.set(ct, 12);
  return out;
}

async function aesOpen(keyBytes: Uint8Array, sealed: Uint8Array): Promise<Uint8Array | null> {
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, 'AES-GCM', false, [
      'decrypt',
    ]);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sealed.slice(0, 12) as BufferSource },
      key,
      sealed.slice(12) as BufferSource,
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/** Wrap an epoch key to one recipient (ephemeral ECDH + HKDF + AES-GCM). */
async function wrapEpochKey(
  epochKey: Uint8Array,
  recipientAgreement: Uint8Array,
  recipientSigning: Uint8Array,
): Promise<{ ephemeral: Uint8Array; box: Uint8Array }> {
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const peer = await importAgreementKey(recipientAgreement);
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peer },
      (ephemeral as CryptoKeyPair).privateKey,
      256,
    ),
  );
  const wrap = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: recipientSigning as BufferSource,
        info: SEALED_KEY_INFO as BufferSource,
      },
      await crypto.subtle.importKey('raw', shared as BufferSource, 'HKDF', false, ['deriveBits']),
      256,
    ),
  );
  const box = await aesSeal(wrap, epochKey);
  const ephemeralRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', (ephemeral as CryptoKeyPair).publicKey),
  );
  return { ephemeral: ephemeralRaw, box };
}

/* ------------------------------------------------------------------ */
/* Keys                                                             */
/* ------------------------------------------------------------------ */

export class WebCryptoKeys implements KeyProvider {
  readonly signingPublicKey: Uint8Array;
  readonly agreementPublicKey: Uint8Array;
  private readonly signingPrivate: CryptoKey;
  private readonly agreementPrivate: CryptoKey;

  private constructor(
    signingPublicKey: Uint8Array,
    agreementPublicKey: Uint8Array,
    signingPrivate: CryptoKey,
    agreementPrivate: CryptoKey,
  ) {
    this.signingPublicKey = signingPublicKey;
    this.agreementPublicKey = agreementPublicKey;
    this.signingPrivate = signingPrivate;
    this.agreementPrivate = agreementPrivate;
  }

  static async generate(): Promise<WebCryptoKeys> {
    const signing = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    const agreement = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )) as CryptoKeyPair;
    // Public halves are exportable; the private keys stay non-extractable in
    // the tab. WebCrypto 'raw' export of a P-256 public key is X9.63 (65 B).
    const signingPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey));
    const agreementPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', agreement.publicKey),
    );
    return new WebCryptoKeys(signingPublicKey, agreementPublicKey, signing.privateKey, agreement.privateKey);
  }

  async sign(body: Uint8Array): Promise<Uint8Array> {
    const out = new Uint8Array(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        this.signingPrivate,
        body as BufferSource,
      ),
    );
    return toRawSignature(out);
  }

  async agree(peerPublicKey: Uint8Array): Promise<Uint8Array> {
    const peer = await importAgreementKey(peerPublicKey);
    return new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, this.agreementPrivate, 256),
    );
  }
}

/** Key-derived ID: first 32 hex chars of SHA-256 of the signing key bytes. */
export async function memberIDFor(keys: Pick<KeyProvider, 'signingPublicKey'>): Promise<string> {
  return (await sha256Hex(keys.signingPublicKey)).slice(0, 32);
}

/** Six-digit pairing code, spec §7.2: SHA-256(libraryID || signing bytes). */
export async function pairingCodeFor(libraryID: string, signingPublicKey: Uint8Array): Promise<string> {
  const pre = new Uint8Array(te.encode(libraryID).length + signingPublicKey.length);
  pre.set(te.encode(libraryID), 0);
  pre.set(signingPublicKey, te.encode(libraryID).length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', pre));
  const n =
    ((digest[0] ?? 0) * 2 ** 24 + (digest[1] ?? 0) * 2 ** 16 + (digest[2] ?? 0) * 2 ** 8 + (digest[3] ?? 0)) >>>
    0;
  return String(n % 1000000).padStart(6, '0');
}

/* ------------------------------------------------------------------ */
/* Records                                                            */
/* ------------------------------------------------------------------ */

interface SignedRecordBody {
  body: string; // base64 of the exact inner JSON bytes
  signature: string; // base64 raw r||s
}

async function signRecord(inner: unknown, keys: KeyProvider): Promise<{ path: string; bytes: Uint8Array; body: Uint8Array }> {
  const body = te.encode(canonicalJson(inner));
  const sig = await keys.sign(body);
  const rec: SignedRecordBody = { body: toB64(body), signature: toB64(sig) };
  return { path: '', bytes: te.encode(canonicalJson(rec)), body };
}

interface ParsedRecord {
  bodyBytes: Uint8Array;
  body: Record<string, unknown>;
  signature: Uint8Array;
}

function parseRecord(bytes: Uint8Array): ParsedRecord | null {
  try {
    const rec = JSON.parse(td.decode(bytes)) as SignedRecordBody;
    const bodyBytes = fromB64(rec.body);
    return { bodyBytes, body: JSON.parse(td.decode(bodyBytes)) as Record<string, unknown>, signature: fromB64(rec.signature) };
  } catch {
    return null;
  }
}

function authorityPath(seq: number): string {
  return `authority/${String(seq).padStart(8, '0')}.json`;
}

function opPath(author: string, clock: number, opID: string): string {
  return `ops/${author}/${String(clock).padStart(12, '0')}-${opID}.json`;
}

/* ------------------------------------------------------------------ */
/* Derived state (rebuilt from records)                               */
/* ------------------------------------------------------------------ */

interface MemberInternal extends Member {
  signingPub: Uint8Array;
  agreementPub: Uint8Array;
  heldNamespaces: string[]; // every namespace the member could read (for rekey)
}

interface AuthorityEntry {
  seq: number;
  issued: string;
  kind: string;
  body: Record<string, unknown>;
  bodyDigest: string;
}

interface OpInternal {
  path: string;
  id: string;
  kind: string;
  author: string;
  namespace: string;
  epoch: number;
  clock: number;
  authority: number;
  created: string;
  payload: unknown;
  status: 'admitted' | 'held' | 'refused';
  reason: string;
}

interface Derived {
  libraryID: string;
  label: string;
  ownerLabel: string;
  namespaces: string[];
  rootID: string;
  rootSigning: Uint8Array;
  members: Map<string, MemberInternal>;
  entries: AuthorityEntry[];
  latestSeq: number;
  epochs: Map<string, number>; // namespace -> current epoch
  /** Sealed epoch keys: `${memberID}/${namespace}/${epoch}` -> box. */
  sealedKeys: Map<string, { ephemeral: Uint8Array; box: Uint8Array }>;
  ops: OpInternal[];
  ledger: LedgerEntry[];
}

/** Per-record-map shared slot: libraries over the same Records see one view. */
interface SharedSlot {
  derived: Derived | null;
  plaintext: Map<string, unknown>; // opID -> opened plaintext payload
  opMeta: Map<string, { kind: string; clock: number; created: string }>;
  keys: Map<string, Map<string, Map<number, Uint8Array>>>; // member -> ns -> epoch -> key
}

const slots = new WeakMap<Records, SharedSlot>();

function slotFor(records: Records): SharedSlot {
  let s = slots.get(records);
  if (!s) {
    s = { derived: null, plaintext: new Map(), opMeta: new Map(), keys: new Map() };
    slots.set(records, s);
  }
  return s;
}

function memberKeys(slot: SharedSlot, memberID: string): Map<string, Map<number, Uint8Array>> {
  let m = slot.keys.get(memberID);
  if (!m) {
    m = new Map();
    slot.keys.set(memberID, m);
  }
  return m;
}

/* ------------------------- domain folds ------------------------- */

export interface ListeningState {
  shows: { id: string; title: string; feed: string }[];
  episodes: {
    id: string;
    showId: string;
    showTitle: string;
    title: string;
    published: string;
    durationSec: number;
    excerpt: string;
    hasTranscript: boolean;
    transcript: string;
  }[];
}

export interface NotesState {
  notebooks: {
    id: string;
    title: string;
    archived: boolean;
    cells: {
      id: string;
      opId: string;
      title: string;
      text: string;
      origin: 'person' | 'ai';
      author: string;
      authorLabel: string;
      created: string;
    }[];
  }[];
}

export interface ReadingState {
  items: { id: string; url: string; title: string; saved: string; revision: string }[];
}

function emptyListening(): ListeningState {
  return { shows: [], episodes: [] };
}
function emptyNotes(): NotesState {
  return { notebooks: [] };
}
function emptyReading(): ReadingState {
  return { items: [] };
}

function foldListening(ops: OpInternal[], slot: SharedSlot): ListeningState {
  const state = emptyListening();
  const transcripts = new Map<string, string>();
  for (const op of ops) {
    const p = (slot.plaintext.get(op.id) ?? op.payload) as Record<string, unknown>;
    if (op.kind === 'show.follow' && typeof p['showId'] === 'string') {
      const id = p['showId'] as string;
      const existing = state.shows.find((s) => s.id === id);
      if (existing) {
        existing.title = String(p['title'] ?? existing.title);
        existing.feed = String(p['feed'] ?? existing.feed);
      } else {
        state.shows.push({ id, title: String(p['title'] ?? 'Untitled show'), feed: String(p['feed'] ?? '') });
      }
    } else if (op.kind === 'episode.add' && typeof p['episodeId'] === 'string') {
      const showId = String(p['showId'] ?? '');
      let show = state.shows.find((s) => s.id === showId);
      if (!show && showId) {
        // A reference arriving before its show (cross-author order) opens a
        // shell; the later show.follow fills in the title.
        show = { id: showId, title: 'Unknown show', feed: '' };
        state.shows.push(show);
      }
      state.episodes.push({
        id: p['episodeId'] as string,
        showId,
        showTitle: show?.title ?? 'Unknown show',
        title: String(p['title'] ?? 'Untitled episode'),
        published: String(p['published'] ?? ''),
        durationSec: Number(p['durationSec'] ?? 0),
        excerpt: '',
        hasTranscript: false,
        transcript: '',
      });
    } else if (op.kind === 'episode.transcript' && typeof p['episodeId'] === 'string') {
      transcripts.set(p['episodeId'] as string, String(p['text'] ?? ''));
    }
    // Unknown kinds are skipped, unknown fields kept (spec §9).
  }
  for (const ep of state.episodes) {
    const t = transcripts.get(ep.id);
    if (t) {
      ep.transcript = t;
      ep.hasTranscript = true;
      ep.excerpt = t.length > 220 ? `${t.slice(0, 220)}…` : t;
    }
    const s = state.shows.find((sh) => sh.id === ep.showId);
    if (s) ep.showTitle = s.title;
  }
  return state;
}

function foldNotes(
  ops: OpInternal[],
  slot: SharedSlot,
  members: Map<string, MemberInternal>,
): NotesState {
  const state = emptyNotes();
  for (const op of ops) {
    const p = (slot.plaintext.get(op.id) ?? op.payload) as Record<string, unknown>;
    if (op.kind === 'notebook.create' && typeof p['notebookId'] === 'string') {
      const id = p['notebookId'] as string;
      const existing = state.notebooks.find((n) => n.id === id);
      if (existing) existing.title = String(p['title'] ?? existing.title);
      else {
        state.notebooks.push({ id, title: String(p['title'] ?? 'Notebook'), archived: false, cells: [] });
      }
    } else if (op.kind === 'cell.put' && typeof p['notebookId'] === 'string') {
      const id = p['notebookId'] as string;
      let nb = state.notebooks.find((n) => n.id === id);
      if (!nb) {
        // A note arriving before its notebook (cross-author order) opens a
        // shell; the later notebook.create fills in the title.
        nb = { id, title: 'Untitled notebook', archived: false, cells: [] };
        state.notebooks.push(nb);
      }
      const m = members.get(op.author);
      const cellId = typeof p['cellId'] === 'string' ? (p['cellId'] as string) : op.id;
      const existing = nb.cells.findIndex((c) => c.id === cellId);
      const cell = {
        id: cellId,
        opId: op.id,
        title: String(p['title'] ?? ''),
        text: String(p['text'] ?? ''),
        origin: (m?.kind === 'agent' ? 'ai' : 'person') as 'person' | 'ai',
        author: op.author,
        authorLabel: m?.label ?? 'Someone',
        created: op.created,
      };
      if (existing >= 0) nb.cells[existing] = cell;
      else nb.cells.push(cell);
    }
  }
  return state;
}

function foldReading(ops: OpInternal[], slot: SharedSlot): ReadingState {
  const state = emptyReading();
  for (const op of ops) {
    const p = (slot.plaintext.get(op.id) ?? op.payload) as Record<string, unknown>;
    if (op.kind === 'capture.link' && typeof p['itemId'] === 'string') {
      state.items.push({
        id: p['itemId'] as string,
        url: String(p['url'] ?? ''),
        title: String(p['title'] ?? 'Untitled'),
        saved: op.created,
        revision: op.id,
      });
    }
  }
  return state;
}

/* ------------------------- ledger sentences ------------------------- */

function scopeWords(g: Grant): string {
  const canRead = g.access.includes('read');
  const canWrite = g.access.includes('write');
  if (canRead && canWrite) return `read and write ${g.namespaces.join(', ')}`;
  if (canRead) return `read ${g.namespaces.join(', ')}`;
  if (canWrite) return `write ${g.namespaces.join(', ')}`;
  return 'nothing';
}

/* ------------------------------------------------------------------ */
/* Small readers for parsed JSON                                    */
/* ------------------------------------------------------------------ */

function getStr(o: Record<string, unknown>, k: string): string | null {
  const v = o[k];
  return typeof v === 'string' ? v : null;
}
function getNum(o: Record<string, unknown>, k: string): number | null {
  const v = o[k];
  return typeof v === 'number' ? v : null;
}
function getStrArr(o: Record<string, unknown>, k: string): string[] | null {
  const v = o[k];
  return Array.isArray(v) && v.every((e) => typeof e === 'string') ? (v as string[]) : null;
}

function shortTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' }).format(d);
}

function kindWord(kind: string): string {
  if (kind === 'cell.put') return 'a note';
  if (kind === 'capture.link') return 'a link';
  if (kind === 'notebook.create') return 'a notebook';
  if (kind.startsWith('episode.')) return 'an episode update';
  if (kind.startsWith('show.')) return 'a show update';
  return 'an update';
}

function kindNoun(kind: MemberKind): string {
  if (kind === 'agent') return 'AI agent';
  if (kind === 'server') return 'server';
  if (kind === 'app') return 'app';
  return 'device';
}

/* ------------------------------------------------------------------ */
/* Agent tool definitions (stand-ins for generated operation specs)   */
/* ------------------------------------------------------------------ */

interface ToolDef {
  name: string;
  description: string;
  inputSchema: unknown;
  namespace: string;
  access: Access;
}

const TOOL_DEFS: ToolDef[] = [
  {
    name: 'listening_list_episodes',
    description: 'List the podcast episodes saved in listening, newest first.',
    inputSchema: {
      type: 'object',
      properties: { show: { type: 'string', description: 'Only episodes of this show ID.' } },
    },
    namespace: 'listening',
    access: 'read',
  },
  {
    name: 'listening_get_transcript',
    description: 'Read the saved transcript excerpt of one episode, with citation details.',
    inputSchema: {
      type: 'object',
      properties: { episode: { type: 'string', description: 'The episode ID.' } },
      required: ['episode'],
    },
    namespace: 'listening',
    access: 'read',
  },
  {
    name: 'notes_list',
    description: 'List notebooks and their notes.',
    inputSchema: { type: 'object', properties: {} },
    namespace: 'notes',
    access: 'read',
  },
  {
    name: 'notes_write',
    description: 'Write a note into the first notebook. The note is signed and marked as written by AI.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'Short title for the note.' },
        text: { type: 'string', description: 'The note text.' },
      },
      required: ['text'],
    },
    namespace: 'notes',
    access: 'write',
  },
  {
    name: 'reading_list',
    description: 'List saved links in reading.',
    inputSchema: { type: 'object', properties: {} },
    namespace: 'reading',
    access: 'read',
  },
];

/* ------------------------------------------------------------------ */
/* Library (mock)                                                   */
/* ------------------------------------------------------------------ */

function publicMember(m: MemberInternal): Member {
  return {
    id: m.id,
    label: m.label,
    kind: m.kind,
    grant: m.grant ? { ...m.grant, namespaces: [...m.grant.namespaces], access: [...m.grant.access] } : null,
    since: m.since,
    revokedAt: m.revokedAt,
    writes: m.writes,
  };
}

export class Library {
  readonly records: Records;
  private readonly meKeys: KeyProvider;
  private readonly meID: string;

  private constructor(records: Records, meKeys: KeyProvider, meID: string) {
    this.records = records; // live view; the host persists the deltas
    this.meKeys = meKeys;
    this.meID = meID;
  }

  static async create(opts: {
    owner: KeyProvider;
    label: string;
    ownerLabel: string;
    namespaces: string[];
  }): Promise<Library> {
    const records: Records = new Map();
    const rootID = await memberIDFor(opts.owner);
    const issued = new Date().toISOString();
    const genesis = {
      seq: 1,
      issued,
      kind: 'genesis',
      by: 'root',
      label: opts.label,
      ownerLabel: opts.ownerLabel,
      namespaces: [...opts.namespaces],
      root: {
        signing: toB64(opts.owner.signingPublicKey),
        agreement: toB64(opts.owner.agreementPublicKey),
      },
    };
    const g = await signRecord(genesis, opts.owner);
    records.set(authorityPath(1), g.bytes);
    let prevDigest = await sha256Hex(g.body);
    let seq = 1;
    // Epoch 1 of every namespace, sealed to the root.
    for (const ns of opts.namespaces) {
      seq++;
      const key = randomBytes(32);
      const wrapped = await wrapEpochKey(key, opts.owner.agreementPublicKey, opts.owner.signingPublicKey);
      const entry = {
        seq,
        previous: prevDigest,
        issued: new Date().toISOString(),
        kind: 'shareKey',
        by: 'root',
        memberID: rootID,
        namespace: ns,
        epoch: 1,
        key: { ephemeral: toB64(wrapped.ephemeral), box: toB64(wrapped.box) },
      };
      const r = await signRecord(entry, opts.owner);
      records.set(authorityPath(seq), r.bytes);
      prevDigest = await sha256Hex(r.body);
    }
    const lib = new Library(records, opts.owner, rootID);
    await lib.refresh();
    return lib;
  }

  static async open(records: Records, me: KeyProvider): Promise<Library> {
    const lib = new Library(records, me, await memberIDFor(me));
    await lib.refresh();
    const d = slotFor(records).derived;
    if (!d) throw new Error('Not a library: no genesis record in these records.');
    return lib;
  }

  static async requestAccess(opts: {
    libraryID: string;
    keys: KeyProvider;
    label: string;
    kind: MemberKind;
    namespaces: string[];
    access: Access[];
  }): Promise<AccessRequest> {
    const id = await memberIDFor(opts.keys);
    const body = {
      member: id,
      label: opts.label,
      kind: opts.kind,
      namespaces: [...opts.namespaces],
      access: [...opts.access],
      created: new Date().toISOString(),
      signing: toB64(opts.keys.signingPublicKey),
      agreement: toB64(opts.keys.agreementPublicKey),
    };
    const rec = await signRecord(body, opts.keys);
    return {
      id,
      label: opts.label,
      kind: opts.kind,
      namespaces: [...opts.namespaces],
      access: [...opts.access],
      pairingCode: await pairingCodeFor(opts.libraryID, opts.keys.signingPublicKey),
      record: rec.bytes,
    };
  }

  get id(): string {
    const d = slotFor(this.records).derived;
    if (!d) throw new Error('Library has no derived state yet.');
    return d.libraryID;
  }

  me(): Member {
    const d = this.derived();
    const m = d.members.get(this.meID);
    if (!m) throw new Error('This tab holds no membership in this library.');
    return publicMember(m);
  }

  members(): Member[] {
    return [...this.derived().members.values()].map(publicMember);
  }

  ledger(): LedgerEntry[] {
    return [...this.derived().ledger];
  }

  async approve(request: Uint8Array, grant?: Partial<Grant>): Promise<Outcome<Member>> {
    await this.refresh();
    const d = this.derived();
    if (this.meID !== d.rootID) {
      return { ok: false, reason: 'notGranted', detail: 'Only the library owner can approve access.' };
    }
    const parsed = parseRecord(request);
    const b = parsed?.body;
    const signingB64 = b ? getStr(b, 'signing') : null;
    const agreementB64 = b ? getStr(b, 'agreement') : null;
    const memberID = b ? getStr(b, 'member') : null;
    const label = b ? getStr(b, 'label') : null;
    const kind = b ? getStr(b, 'kind') : null;
    const reqNs = b ? getStrArr(b, 'namespaces') : null;
    const reqAccess = b ? getStrArr(b, 'access') : null;
    if (!parsed || !signingB64 || !agreementB64 || !memberID || !label || !kind || !reqNs || !reqAccess) {
      return { ok: false, reason: 'unavailable', detail: 'That request is damaged and cannot be read.' };
    }
    const signingPub = fromB64(signingB64);
    if (!(await verifyRaw(signingPub, parsed.bodyBytes, parsed.signature))) {
      return { ok: false, reason: 'unavailable', detail: 'That request has a bad signature.' };
    }
    if ((await sha256Hex(signingPub)).slice(0, 32) !== memberID) {
      return { ok: false, reason: 'unavailable', detail: 'That request names a member its key does not match.' };
    }
    const existing = d.members.get(memberID);
    if (existing && existing.revokedAt === null) {
      return { ok: false, reason: 'unavailable', detail: `${existing.label} is already a member.` };
    }
    if (existing) {
      return { ok: false, reason: 'unavailable', detail: `${existing.label} was revoked and cannot rejoin this way.` };
    }
    // The grant narrows the request; it can never widen it.
    const namespaces = (grant?.namespaces ?? reqNs).filter((n) => reqNs.includes(n));
    const access = (grant?.access ?? (reqAccess as Access[])).filter((a) =>
      (reqAccess as string[]).includes(a),
    ) as Access[];
    if (namespaces.length === 0 || access.length === 0) {
      return { ok: false, reason: 'unavailable', detail: 'A grant must keep at least one namespace and one access.' };
    }
    let seq = d.latestSeq;
    let prevDigest = d.entries.length > 0 ? (d.entries[d.entries.length - 1]?.bodyDigest ?? '') : '';
    const memberBody: Record<string, unknown> = {
      seq: seq + 1,
      previous: prevDigest,
      issued: new Date().toISOString(),
      kind: 'member',
      by: 'root',
      member: memberID,
      memberKind: kind,
      label,
      namespaces,
      access,
      signing: signingB64,
      agreement: agreementB64,
    };
    if (grant?.expires !== undefined) memberBody['expires'] = grant.expires;
    if (grant?.writeBudget !== undefined) memberBody['writeBudget'] = grant.writeBudget;
    seq++;
    const mr = await signRecord(memberBody, this.meKeys);
    this.records.set(authorityPath(seq), mr.bytes);
    prevDigest = await sha256Hex(mr.body);
    // Share the current epoch of each granted namespace with the new member.
    const agreementPub = fromB64(agreementB64);
    for (const ns of namespaces) {
      const epoch = d.epochs.get(ns) ?? 1;
      const key = memberKeys(slotFor(this.records), this.meID).get(ns)?.get(epoch);
      if (!key) continue;
      seq++;
      const wrapped = await wrapEpochKey(key, agreementPub, signingPub);
      const entry = {
        seq,
        previous: prevDigest,
        issued: new Date().toISOString(),
        kind: 'shareKey',
        by: 'root',
        memberID,
        namespace: ns,
        epoch,
        key: { ephemeral: toB64(wrapped.ephemeral), box: toB64(wrapped.box) },
      };
      const r = await signRecord(entry, this.meKeys);
      this.records.set(authorityPath(seq), r.bytes);
      prevDigest = await sha256Hex(r.body);
    }
    // The request has been decided; keep it filed for the record.
    this.records.set(`requests/${memberID}.json`, request);
    await this.refresh();
    const m = this.derived().members.get(memberID);
    if (!m) return { ok: false, reason: 'unavailable', detail: 'Approval did not take.' };
    return { ok: true, value: publicMember(m) };
  }

  async revoke(memberID: string): Promise<Outcome<void>> {
    await this.refresh();
    const d = this.derived();
    if (this.meID !== d.rootID) {
      return { ok: false, reason: 'notGranted', detail: 'Only the library owner can end access.' };
    }
    const m = d.members.get(memberID);
    if (!m) return { ok: false, reason: 'unavailable', detail: 'No such member.' };
    if (m.id === d.rootID) {
      return { ok: false, reason: 'unavailable', detail: 'The owner cannot be removed this way.' };
    }
    if (m.revokedAt !== null) {
      return { ok: false, reason: 'unavailable', detail: `${m.label}'s access already ended.` };
    }
    let seq = d.latestSeq;
    let prevDigest = d.entries.length > 0 ? (d.entries[d.entries.length - 1]?.bodyDigest ?? '') : '';
    const kept = d.ops.filter((o) => o.author === memberID && o.status === 'admitted').map((o) => o.id);
    seq++;
    const revokeBody = {
      seq,
      previous: prevDigest,
      issued: new Date().toISOString(),
      kind: 'revoke',
      by: 'root',
      memberID,
      kept,
    };
    const rr = await signRecord(revokeBody, this.meKeys);
    this.records.set(authorityPath(seq), rr.bytes);
    prevDigest = await sha256Hex(rr.body);
    // Rotate every namespace the member could read: a new epoch sealed to the
    // root and the remaining members, never to the revoked one.
    for (const ns of m.heldNamespaces) {
      const epoch = (d.epochs.get(ns) ?? 1) + 1;
      const key = randomBytes(32);
      const holders = [...d.members.values()].filter(
        (c) => c.id !== memberID && c.revokedAt === null && (c.id === d.rootID || (c.grant?.namespaces.includes(ns) ?? false)),
      );
      for (const h of holders) {
        seq++;
        const wrapped = await wrapEpochKey(key, h.agreementPub, h.signingPub);
        const entry = {
          seq,
          previous: prevDigest,
          issued: new Date().toISOString(),
          kind: 'shareKey',
          by: 'root',
          memberID: h.id,
          namespace: ns,
          epoch,
          key: { ephemeral: toB64(wrapped.ephemeral), box: toB64(wrapped.box) },
        };
        const r = await signRecord(entry, this.meKeys);
        this.records.set(authorityPath(seq), r.bytes);
        prevDigest = await sha256Hex(r.body);
      }
    }
    await this.refresh();
    return { ok: true, value: undefined };
  }

  /** Mock-only helper: file an access request and refresh, so Knock ledgers. */
  async noteRequest(request: Uint8Array): Promise<void> {
    const parsed = parseRecord(request);
    const id = parsed?.body ? getStr(parsed.body, 'member') : null;
    if (parsed && id) this.records.set(`requests/${id}.json`, request);
    await this.refresh();
  }

  merge(records: Records): void {
    for (const [p, b] of records) {
      if (!this.records.has(p)) this.records.set(p, b);
    }
    void this.refresh();
  }

  async write(namespace: string, kind: string, payload: unknown): Promise<Outcome<OperationView>> {
    await this.refresh();
    const d = this.derived();
    const gate = this.checkAccess(d, namespace, 'write');
    if (!gate.ok) return gate as Outcome<OperationView>;
    const me = d.members.get(this.meID);
    if (me?.grant?.writeBudget !== undefined && me.writes >= me.grant.writeBudget) {
      return {
        ok: false,
        reason: 'budgetSpent',
        detail: `${me.label} used all ${me.grant.writeBudget} of its writes.`,
      };
    }
    const epoch = d.epochs.get(namespace);
    const key = epoch !== undefined ? memberKeys(slotFor(this.records), this.meID).get(namespace)?.get(epoch) : undefined;
    if (epoch === undefined || !key) {
      return { ok: false, reason: 'notReadable', detail: `This tab holds no key for ${namespace}.` };
    }
    const clock = d.ops.filter((o) => o.author === this.meID && o.namespace === namespace).reduce((m, o) => Math.max(m, o.clock), 0) + 1;
    const opID = randomHex(8);
    const created = new Date().toISOString();
    const plaintext = te.encode(canonicalJson({ id: opID, kind, v: 1, clock, authority: d.latestSeq, created, payload }));
    const sealed = await aesSeal(key, plaintext);
    const header = { author: this.meID, namespace, epoch, sealed: toB64(sealed) };
    const rec = await signRecord(header, this.meKeys);
    const path = opPath(this.meID, clock, opID);
    this.records.set(path, rec.bytes);
    await this.refresh();
    const op = this.derived().ops.find((o) => o.id === opID);
    if (!op || op.status !== 'admitted') {
      return { ok: false, reason: 'unavailable', detail: `The write was recorded but not admitted (${op?.reason ?? 'unknown'}).` };
    }
    return { ok: true, value: this.toView(op) };
  }

  view<State = unknown>(namespace: string): Outcome<NamespaceView<State>> {
    const d = this.derived();
    const gate = this.checkAccess(d, namespace, 'read');
    if (!gate.ok) return gate as Outcome<NamespaceView<State>>;
    const admitted = d.ops
      .filter((o) => o.namespace === namespace && o.status === 'admitted')
      .map((o) => this.toView(o));
    const held = d.ops
      .filter((o) => o.namespace === namespace && o.status === 'held')
      .map((o) => ({ id: o.id, author: o.author, reason: o.reason }));
    const refused = d.ops
      .filter((o) => o.namespace === namespace && o.status === 'refused')
      .map((o) => ({ id: o.id, author: o.author, reason: o.reason }));
    const slot = slotFor(this.records);
    const ordered = d.ops.filter((o) => o.namespace === namespace && o.status === 'admitted');
    let state: unknown = { admitted: admitted.length };
    if (namespace === 'listening') state = foldListening(ordered, slot);
    else if (namespace === 'notes') state = foldNotes(ordered, slot, d.members);
    else if (namespace === 'reading') state = foldReading(ordered, slot);
    else if (this.meID !== d.rootID) {
      return { ok: false, reason: 'notGranted', detail: `No grant covers ${namespace}.` };
    }
    return { ok: true, value: { namespace, admitted, held, refused, state: state as State } };
  }

  tools(): { name: string; description: string; inputSchema: unknown }[] {
    return TOOL_DEFS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
  }

  async call(tool: string, input: unknown): Promise<Outcome<unknown>> {
    await this.refresh();
    const d = this.derived();
    const def = TOOL_DEFS.find((t) => t.name === tool);
    if (!def) return { ok: false, reason: 'unavailable', detail: `No such tool: ${tool}.` };
    const gate = this.checkAccess(d, def.namespace, def.access);
    if (!gate.ok) return gate;
    const args = (typeof input === 'object' && input !== null ? input : {}) as Record<string, unknown>;
    if (tool === 'listening_list_episodes') {
      const v = this.view<ListeningState>('listening');
      if (!v.ok) return v as Outcome<unknown>;
      const show = typeof args['show'] === 'string' ? (args['show'] as string) : null;
      const eps = v.value.state.episodes
        .filter((e) => !show || e.showId === show)
        .map((e) => ({
          id: e.id,
          show: e.showTitle,
          title: e.title,
          published: e.published,
          durationSec: e.durationSec,
          hasTranscript: e.hasTranscript,
        }));
      return { ok: true, value: { episodes: eps } };
    }
    if (tool === 'listening_get_transcript') {
      const v = this.view<ListeningState>('listening');
      if (!v.ok) return v as Outcome<unknown>;
      const ep = v.value.state.episodes.find((e) => e.id === args['episode']);
      if (!ep || !ep.hasTranscript) {
        return { ok: false, reason: 'unavailable', detail: 'No saved transcript for that episode.' };
      }
      return {
        ok: true,
        value: {
          episode: { id: ep.id, show: ep.showTitle, title: ep.title, published: ep.published },
          text: ep.transcript,
          citation: `${ep.showTitle} — “${ep.title}” (${ep.published})`,
        },
      };
    }
    if (tool === 'notes_list') {
      const v = this.view<NotesState>('notes');
      if (!v.ok) return v as Outcome<unknown>;
      return {
        ok: true,
        value: {
          notebooks: v.value.state.notebooks.map((n) => ({
            id: n.id,
            title: n.title,
            notes: n.cells.map((c) => ({ id: c.id, title: c.title, origin: c.origin, author: c.authorLabel })),
          })),
        },
      };
    }
    if (tool === 'notes_write') {
      const text = typeof args['text'] === 'string' ? args['text'].trim() : '';
      if (!text) return { ok: false, reason: 'unavailable', detail: 'A note needs some text.' };
      const v = this.view<NotesState>('notes');
      if (!v.ok) return v as Outcome<unknown>;
      const nb = v.value.state.notebooks.find((n) => !n.archived) ?? v.value.state.notebooks[0];
      if (!nb) return { ok: false, reason: 'unavailable', detail: 'There is no notebook to write in.' };
      const title = typeof args['title'] === 'string' ? (args['title'] as string) : '';
      const w = await this.write('notes', 'cell.put', { notebookId: nb.id, cellId: randomHex(8), title, text });
      if (!w.ok) return w as Outcome<unknown>;
      return { ok: true, value: { note: w.value } };
    }
    if (tool === 'reading_list') {
      const v = this.view<ReadingState>('reading');
      if (!v.ok) return v as Outcome<unknown>;
      return {
        ok: true,
        value: {
          items: v.value.state.items.map((i) => ({ id: i.id, title: i.title, url: i.url, saved: i.saved })),
        },
      };
    }
    return { ok: false, reason: 'unavailable', detail: `No such tool: ${tool}.` };
  }

  /**
   * Mock-only inspection for the "show the record" toggle: the stored bytes
   * of one operation plus a fresh signature verification against the author's
   * key from the authority history.
   */
  async operationRecord(opID: string): Promise<{
    path: string;
    record: string;
    header: string;
    sealedBytes: number;
    author: string;
    authorLabel: string;
    origin: 'person' | 'ai';
    verified: boolean;
  } | null> {
    await this.refresh();
    const d = this.derived();
    const op = d.ops.find((o) => o.id === opID);
    const bytes = op ? this.records.get(op.path) : undefined;
    if (!op || !bytes) return null;
    const parsed = parseRecord(bytes);
    const m = d.members.get(op.author);
    const verified = parsed ? await verifyRaw(m?.signingPub ?? new Uint8Array(), parsed.bodyBytes, parsed.signature) : false;
    const sealedB64 = parsed?.body ? getStr(parsed.body, 'sealed') : null;
    return {
      path: op.path,
      record: td.decode(bytes),
      header: parsed ? td.decode(parsed.bodyBytes) : '',
      sealedBytes: sealedB64 ? fromB64(sealedB64).length : 0,
      author: op.author,
      authorLabel: m?.label ?? 'Someone',
      origin: m?.kind === 'agent' ? 'ai' : 'person',
      verified: verified && !!m,
    };
  }

  /* ------------------------- internals ------------------------- */

  private derived(): Derived {
    const d = slotFor(this.records).derived;
    if (!d) throw new Error('Library has no derived state yet.');
    return d;
  }

  private toView(op: OpInternal): OperationView {
    const d = this.derived();
    const m = d.members.get(op.author);
    const slot = slotFor(this.records);
    return {
      id: op.id,
      kind: op.kind,
      author: op.author,
      authorLabel: m?.label ?? 'Someone',
      origin: m?.kind === 'agent' ? 'ai' : 'person',
      clock: op.clock,
      created: op.created,
      payload: slot.plaintext.get(op.id) ?? op.payload,
    };
  }

  /** Grant gate for `me` on one namespace. Root passes; members are checked. */
  private checkAccess(d: Derived, namespace: string, access: Access): Outcome<null> {
    const me = d.members.get(this.meID);
    if (!me) {
      return { ok: false, reason: 'unavailable', detail: 'This tab holds no membership in this library.' };
    }
    if (me.id === d.rootID) return { ok: true, value: null };
    const g = me.grant;
    if (!g || !g.namespaces.includes(namespace)) {
      return { ok: false, reason: 'notGranted', detail: `${me.label} was never granted ${namespace}.` };
    }
    if (me.revokedAt !== null) {
      const notes = d.ops.filter((o) => o.author === me.id && o.status === 'admitted' && o.kind === 'cell.put').length;
      const kept = me.kind === 'agent' && notes > 0 ? ` Its ${notes} note${notes === 1 ? '' : 's'} stay${notes === 1 ? 's' : ''}, marked as written by AI.` : ' Its earlier work stays.';
      return { ok: false, reason: 'revoked', detail: `Access ended. ${me.label}'s access ended.${kept}` };
    }
    if (g.expires && new Date(g.expires).getTime() < Date.now()) {
      return { ok: false, reason: 'expired', detail: `${me.label}'s grant expired.` };
    }
    if (access === 'write' && !g.access.includes('write')) {
      return { ok: false, reason: 'notGranted', detail: `${me.label} can read ${namespace} but not write it.` };
    }
    return { ok: true, value: null };
  }

  /** Rebuild everything from the records. Mutations await this before resolving. */
  private async refresh(): Promise<void> {
    const slot = slotFor(this.records);
    const authPaths = [...this.records.keys()].filter((p) => p.startsWith('authority/')).sort();
    if (authPaths.length === 0 || !this.records.get(authorityPath(1))) {
      slot.derived = null;
      return;
    }
    // Walk the authority history in order, verifying every entry.
    const entries: AuthorityEntry[] = [];
    const members = new Map<string, MemberInternal>();
    const epochs = new Map<string, number>();
    const sealedKeys = new Map<string, { ephemeral: Uint8Array; box: Uint8Array }>();
    const ledger: LedgerEntry[] = [];
    let label = '';
    let ownerLabel = '';
    let namespaces: string[] = [];
    let libraryID = '';
    let rootID = '';
    let rootSigning: Uint8Array = new Uint8Array();
    let rootAgreement: Uint8Array = new Uint8Array();
    let prevDigest = '';
    let seq = 0;
    let latestSeq = 0;
    const rekeyedSeen = new Set<string>();

    for (const p of authPaths) {
      const bytes = this.records.get(p);
      if (!bytes) continue;
      const parsed = parseRecord(bytes);
      if (!parsed) break; // stop at the first failure (spec §6)
      seq++;
      const b = parsed.body;
      if (getNum(b, 'seq') !== seq) break;
      const digest = await sha256Hex(parsed.bodyBytes);
      if (seq === 1) {
        if (getStr(b, 'kind') !== 'genesis') break;
        const root = b['root'] as Record<string, unknown> | undefined;
        const rs = typeof root?.['signing'] === 'string' ? (root['signing'] as string) : null;
        const ra = typeof root?.['agreement'] === 'string' ? (root['agreement'] as string) : null;
        const ns = getStrArr(b, 'namespaces');
        if (!rs || !ra || !ns) break;
        rootSigning = fromB64(rs);
        rootAgreement = fromB64(ra);
        if (!(await verifyRaw(rootSigning, parsed.bodyBytes, parsed.signature))) break;
        libraryID = digest.slice(0, 32);
        rootID = (await sha256Hex(rootSigning)).slice(0, 32);
        label = getStr(b, 'label') ?? 'My library';
        ownerLabel = getStr(b, 'ownerLabel') ?? 'You';
        namespaces = [...ns];
        members.set(rootID, {
          id: rootID, label: ownerLabel, kind: 'device', grant: null,
          since: 1, revokedAt: null, writes: 0,
          signingPub: rootSigning, agreementPub: rootAgreement, heldNamespaces: [...ns],
        });
        ledger.push({
          sequence: 1, at: getStr(b, 'issued') ?? '', actor: rootID, actorLabel: ownerLabel,
          event: 'created', text: `This library belongs to ${ownerLabel}. It lives in this browser tab.`,
        });
      } else {
        if (getStr(b, 'previous') !== prevDigest) break;
        if (!(await verifyRaw(rootSigning, parsed.bodyBytes, parsed.signature))) break;
        const kind = getStr(b, 'kind');
        const issued = getStr(b, 'issued') ?? '';
        if (kind === 'member') {
          const mid = getStr(b, 'member');
          const mlabel = getStr(b, 'label');
          const mkind = getStr(b, 'memberKind');
          const mns = getStrArr(b, 'namespaces');
          const maccess = getStrArr(b, 'access');
          const msign = getStr(b, 'signing');
          const magree = getStr(b, 'agreement');
          if (!mid || !mlabel || !mns || !maccess || !msign || !magree) continue;
          const g: Grant = { namespaces: [...mns], access: [...(maccess as Access[])] };
          const exp = getStr(b, 'expires');
          const wb = getNum(b, 'writeBudget');
          if (exp !== null) g.expires = exp;
          if (wb !== null) g.writeBudget = wb;
          const memberKind: MemberKind =
            mkind === 'device' || mkind === 'app' || mkind === 'agent' || mkind === 'server' ? mkind : 'app';
          members.set(mid, {
            id: mid, label: mlabel, kind: memberKind, grant: g,
            since: seq, revokedAt: null, writes: 0,
            signingPub: fromB64(msign), agreementPub: fromB64(magree), heldNamespaces: [...mns],
          });
          let text = `${mlabel} can ${scopeWords(g)}.`;
          if (g.expires) text += ` Until ${shortTime(g.expires)}.`;
          if (g.writeBudget !== undefined) text += ` Up to ${g.writeBudget} writes.`;
          ledger.push({
            sequence: seq, at: issued, actor: rootID, actorLabel: ownerLabel,
            event: 'granted', subject: mid, text,
          });
        } else if (kind === 'revoke') {
          const mid = getStr(b, 'memberID');
          if (!mid) continue;
          const m = members.get(mid);
          if (m) m.revokedAt = seq;
          // Text is finished after ops are folded (it counts kept notes).
          ledger.push({
            sequence: seq, at: issued, actor: rootID, actorLabel: ownerLabel,
            event: 'revoked', subject: mid, text: '',
          });
        } else if (kind === 'shareKey') {
          const mid = getStr(b, 'memberID');
          const ns = getStr(b, 'namespace');
          const epoch = getNum(b, 'epoch');
          const key = b['key'] as Record<string, unknown> | undefined;
          const eph = typeof key?.['ephemeral'] === 'string' ? (key['ephemeral'] as string) : null;
          const box = typeof key?.['box'] === 'string' ? (key['box'] as string) : null;
          if (!mid || !ns || epoch === null || !eph || !box) continue;
          sealedKeys.set(`${mid}/${ns}/${epoch}`, { ephemeral: fromB64(eph), box: fromB64(box) });
          epochs.set(ns, Math.max(epochs.get(ns) ?? 0, epoch));
          const rk = `${ns}/${epoch}`;
          if (epoch > 1 && !rekeyedSeen.has(rk)) {
            rekeyedSeen.add(rk);
            ledger.push({
              sequence: seq, at: issued, actor: rootID, actorLabel: ownerLabel,
              event: 'rekeyed', text: `New keys for ${ns}. Anything written after needs them.`,
            });
          }
        }
      }
      entries.push({ seq, issued: getStr(b, 'issued') ?? '', kind: getStr(b, 'kind') ?? '', body: b, bodyDigest: digest });
      prevDigest = digest;
      latestSeq = seq;
    }

    // Unseal my epoch keys (ECDH with my agreement key, like the real core).
    const myCache = memberKeys(slot, this.meID);
    const mySigning = this.meKeys.signingPublicKey;
    for (const [k, v] of sealedKeys) {
      const [mid, ns, epochStr] = k.split('/');
      if (mid !== this.meID || !ns || !epochStr) continue;
      const epoch = Number(epochStr);
      let perNs = myCache.get(ns);
      if (!perNs) {
        perNs = new Map();
        myCache.set(ns, perNs);
      }
      if (perNs.has(epoch)) continue;
      try {
        const shared = await this.meKeys.agree(v.ephemeral);
        const hkdfKey = await crypto.subtle.importKey('raw', shared as BufferSource, 'HKDF', false, ['deriveBits']);
        const wrap = new Uint8Array(
          await crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: mySigning as BufferSource, info: SEALED_KEY_INFO as BufferSource },
            hkdfKey,
            256,
          ),
        );
        const opened = await aesOpen(wrap, v.box);
        if (opened) perNs.set(epoch, opened);
      } catch {
        // A key that does not open is simply not held.
      }
    }

    // Read operations: verify, admit, open.
    const opPaths = [...this.records.keys()].filter((p) => p.startsWith('ops/')).sort();
    const ops: OpInternal[] = [];
    for (const p of opPaths) {
      const bytes = this.records.get(p);
      if (!bytes) continue;
      const parsed = parseRecord(bytes);
      const h = parsed?.body;
      const author = h ? getStr(h, 'author') : null;
      const ns = h ? getStr(h, 'namespace') : null;
      const epoch = h ? getNum(h, 'epoch') : null;
      const sealedB64 = h ? getStr(h, 'sealed') : null;
      if (!parsed || !author || !ns || epoch === null || !sealedB64) continue;
      const m = members.get(author);
      const verified = m ? await verifyRaw(m.signingPub, parsed.bodyBytes, parsed.signature) : false;
      if (!verified || !m) {
        ops.push({ path: p, id: p, kind: '?', author, namespace: ns, epoch, clock: 0, authority: 0, created: '', payload: null, status: 'refused', reason: 'bad signature' });
        continue;
      }
      // Open the sealed plaintext with any cached epoch key (ops are
      // immutable, so one opening fills the shared cache for every reader).
      let plain: Record<string, unknown> | null = null;
      const sealed = fromB64(sealedB64);
      for (const [, perMember] of slot.keys) {
        const key = perMember.get(ns)?.get(epoch);
        if (!key) continue;
        const opened = await aesOpen(key, sealed);
        if (opened) {
          try {
            plain = JSON.parse(td.decode(opened)) as Record<string, unknown>;
          } catch {
            plain = null;
          }
          break;
        }
      }
      // Admission (spec §8.3, simplified for the mock's closed caveat set).
      const created = typeof plain?.['created'] === 'string' ? (plain['created'] as string) : '';
      const opAuthority = typeof plain?.['authority'] === 'number' ? (plain['authority'] as number) : 0;
      const clock = typeof plain?.['clock'] === 'number' ? (plain['clock'] as number) : 0;
      const opID = typeof plain?.['id'] === 'string' ? (plain['id'] as string) : p;
      const opKind = typeof plain?.['kind'] === 'string' ? (plain['kind'] as string) : '?';
      const payload = plain?.['payload'] ?? null;
      let status: OpInternal['status'] = 'admitted';
      let reason = '';
      const g = m.grant;
      if (opAuthority > latestSeq) {
        status = 'held';
        reason = 'the verifier is behind';
      } else if (m.id !== rootID && (!g || !g.namespaces.includes(ns))) {
        status = 'refused';
        reason = `no grant for ${ns}`;
      } else if (m.id !== rootID && g && !g.access.includes('write')) {
        status = 'refused';
        reason = 'read-only grant';
      } else if (m.id !== rootID && g?.expires && new Date(created).getTime() > new Date(g.expires).getTime()) {
        status = 'refused';
        reason = 'grant expired';
      } else if (m.revokedAt !== null && opAuthority >= m.revokedAt) {
        status = 'refused';
        reason = 'access ended';
      }
      if (status === 'admitted' && plain) {
        slot.plaintext.set(opID, payload);
        slot.opMeta.set(opID, { kind: opKind, clock, created });
      }
      ops.push({ path: p, id: opID, kind: opKind, author, namespace: ns, epoch, clock, authority: opAuthority, created, payload, status, reason });
    }
    // Write budgets, evaluated in agreed order over admitted ops.
    const spent = new Map<string, number>();
    const agreed = [...ops].sort(
      (a, b) => a.clock - b.clock || (a.author < b.author ? -1 : 1) || (a.id < b.id ? -1 : 1),
    );
    for (const o of agreed) {
      if (o.status !== 'admitted') continue;
      const m = members.get(o.author);
      const budget = m?.grant?.writeBudget;
      if (m && m.id !== rootID && budget !== undefined) {
        const n = (spent.get(m.id) ?? 0) + 1;
        spent.set(m.id, n);
        if (n > budget) {
          o.status = 'refused';
          o.reason = 'write budget spent';
          continue;
        }
      }
      if (m) m.writes++;
    }

    // Access requests on file (Knock) ledger as 'requested'.
    const reqPaths = [...this.records.keys()].filter((p) => p.startsWith('requests/')).sort();
    for (const p of reqPaths) {
      const bytes = this.records.get(p);
      if (!bytes) continue;
      const parsed = parseRecord(bytes);
      const b = parsed?.body;
      const mid = b ? getStr(b, 'member') : null;
      const rlabel = b ? getStr(b, 'label') : null;
      const rkind = b ? getStr(b, 'kind') : null;
      const rns = b ? getStrArr(b, 'namespaces') : null;
      const racc = b ? getStrArr(b, 'access') : null;
      const rsign = b ? getStr(b, 'signing') : null;
      if (!parsed || !mid || !rlabel || !rkind || !rns || !racc || !rsign) continue;
      if (!b) continue;
      if (!(await verifyRaw(fromB64(rsign), parsed.bodyBytes, parsed.signature))) continue;
      if (members.has(mid)) continue; // decided requests leave the waiting list
      const g: Grant = { namespaces: [...rns], access: [...(racc as Access[])] };
      ledger.push({
        sequence: latestSeq,
        at: getStr(b, 'created') ?? '',
        actor: mid,
        actorLabel: rlabel,
        event: 'requested',
        subject: mid,
        text: `${rlabel} asked to join (${kindNoun(rkind as MemberKind)}). “${scopeWords(g)}.”`,
      });
    }

    // Writes ledger, in agreed order.
    for (const o of agreed) {
      if (o.status !== 'admitted') continue;
      const m = members.get(o.author);
      ledger.push({
        sequence: o.authority,
        at: o.created,
        actor: o.author,
        actorLabel: m?.label ?? 'Someone',
        event: 'wrote',
        subject: o.id,
        text: `${m?.label ?? 'Someone'} wrote ${kindWord(o.kind)} in ${o.namespace}.`,
      });
    }

    // Finish 'revoked' sentences now that kept notes are counted.
    for (const e of ledger) {
      if (e.event !== 'revoked' || e.text) continue;
      const m = e.subject ? members.get(e.subject) : undefined;
      const label = m?.label ?? 'A member';
      const notes = ops.filter((o) => o.author === e.subject && o.status === 'admitted' && o.kind === 'cell.put').length;
      e.text =
        m?.kind === 'agent'
          ? `${label}'s access ended. Its ${notes} note${notes === 1 ? '' : 's'} stay${notes === 1 ? 's' : ''}, marked as written by AI.`
          : `${label}'s access ended. Its earlier work stays.`;
    }

    slot.derived = {
      libraryID, label, ownerLabel, namespaces, rootID, rootSigning,
      members, entries, latestSeq, epochs, sealedKeys, ops, ledger,
    };
  }
}
