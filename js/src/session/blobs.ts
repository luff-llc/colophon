import { BlobError, SessionError } from './errors.js';
import type { BlobAvailability, BlobChunk, Home } from './records.js';
import { withEntropy } from './secrets.js';
import type { ColophonSession } from './session.js';
import type { WriteReceipt } from './types.js';
import { glue, isAccountFault, plain } from './wasm.js';

/** A published blob. */
export interface ColophonBlob { namespace: string; digest: string; size: number; mediaType: string; receipt: WriteReceipt }

/** How much of a blob this device holds. */
export type BlobAvailabilityState =
  | { kind: 'available' }
  | { kind: 'missing'; presentChunks: number; totalChunks: number }
  | { kind: 'downloading'; completedChunks: number; totalChunks: number }
  | { kind: 'inaccessible'; reason: string }
  /** No manifest for this digest is published in the namespace. */
  | { kind: 'unpublished' };

interface ManifestInfo { digest: string; size: number; mediaType: string; chunks: number }
const CHUNK = 64 * 1024;
const hex = (bytes: Uint8Array): string => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const ready = (session: ColophonSession): boolean => session.phase.kind === 'ready' || session.phase.kind === 'refreshing';

function parseManifest(text: string): ManifestInfo | undefined {
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { return undefined; }
  const obj = parsed as { ok?: unknown; value?: Record<string, unknown> };
  if (obj?.ok !== true || typeof obj.value !== 'object' || obj.value === null) return undefined;
  let value = obj.value;
  if (typeof value.manifest === 'object' && value.manifest !== null) value = value.manifest as Record<string, unknown>;
  const descriptor = (typeof value.descriptor === 'object' && value.descriptor !== null ? value.descriptor : value) as Record<string, unknown>;
  if (typeof descriptor.digest !== 'string' || typeof descriptor.size !== 'number' || !Array.isArray(value.chunks)) return undefined;
  return { digest: descriptor.digest, size: descriptor.size, mediaType: typeof descriptor.mediaType === 'string' ? descriptor.mediaType : 'application/octet-stream', chunks: value.chunks.length };
}
function manifestOf(session: ColophonSession, namespace: string, digest: string): ManifestInfo {
  const info = parseManifest(session.worker.requireEngine().run(e => e.blob_manifest_json(namespace, digest)));
  if (!info) throw new BlobError('unpublished', 'No blob with this digest is published.');
  return info;
}
function availability(session: ColophonSession, namespace: string, digest: string): BlobAvailabilityState {
  let manifest: ManifestInfo;
  try { manifest = manifestOf(session, namespace, digest); } catch { return { kind: 'unpublished' }; }
  const a = plain<BlobAvailability>(session.worker.requireEngine().run(e => e.blob_availability(namespace, digest)));
  if (a.state === glue.BlobState.Complete) return { kind: 'available' };
  if (a.state === glue.BlobState.Partial) return { kind: 'missing', presentChunks: Number(a.present), totalChunks: Number(a.total) };
  if (a.state === glue.BlobState.Missing) return { kind: 'missing', presentChunks: 0, totalChunks: manifest.chunks };
  return { kind: 'inaccessible', reason: a.detail ?? 'not readable' };
}

/**
 * Encrypts and stores `data` in 64 KiB chunks under the namespace epoch key, then publishes a signed
 * `colophon.blobPublish` manifest with one reference. Identical content already published is not stored again; a
 * reference is added instead. `required` asks every device to download it. Chunks are stored before the manifest is
 * published; only `begin_blob` and the publish take the session's gate.
 */
export async function putBlob(session: ColophonSession, data: Uint8Array, options: { namespace: string; mediaType: string; reference: string; required?: boolean }): Promise<ColophonBlob> {
  await session.restore();
  if (!ready(session)) throw new SessionError('notReady');
  const lease = session.context;
  const { namespace, mediaType, reference } = options; const required = options.required ?? false;
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data))));
  if (lease !== session.context) throw new SessionError('destinationChanged');
  const worker = session.worker;
  const existing = await worker.inGate(async () => {
    try { return parseManifest(worker.requireEngine().run(e => e.blob_manifest_json(namespace, digest))); } catch (error) { if (isAccountFault(error)) return undefined; throw error; }
  });
  let payload: string; let kind: string; let size = data.length; let type = mediaType;
  if (existing) {
    kind = 'colophon.blobReference'; size = existing.size; type = existing.mediaType;
    payload = JSON.stringify({ reference, required, digest, retain: true });
  } else {
    // The writer holds an epoch key. The session tracks it: `lock` frees it at once, and every use after that is refused.
    const writer = await worker.inGate(async () => worker.blobWriter(worker.requireEngine().run(e => withEntropy(32, entropy => e.begin_blob(namespace, mediaType, entropy)))));
    let manifestText: string;
    try {
      for (let at = 0; at < data.length; at += CHUNK) {
        const sealed = plain<BlobChunk>(writer.use(w => w.push(data.subarray(at, Math.min(data.length, at + CHUNK)))));
        await worker.storage.write([{ path: sealed.path, bytes: sealed.bytes }]);
        if (lease !== session.context) throw new SessionError('destinationChanged');
      }
      manifestText = writer.use(w => w.finish());
    } finally { writer.release(); }
    kind = 'colophon.blobPublish';
    // The signed manifest is embedded byte for byte: no numeric re-encoding.
    payload = `{"reference":${JSON.stringify(reference)},"required":${required ? 'true' : 'false'},"manifest":${manifestText}}`;
  }
  if (lease !== session.context) throw new SessionError('destinationChanged');
  const receipt = await session.perform({ namespace, kind, payloadJson: payload }, session.observedRevision);
  return { namespace, digest, size, mediaType: type, receipt };
}

/** Adds (`retain`) or removes a live reference. */
export function setBlobReference(session: ColophonSession, blob: ColophonBlob, reference: string, retain: boolean, required?: boolean): Promise<WriteReceipt> {
  const payload: Record<string, unknown> = { digest: blob.digest, reference, retain };
  if (required !== undefined) payload.required = required;
  return session.perform({ namespace: blob.namespace, kind: 'colophon.blobReference', payloadJson: JSON.stringify(payload) }, session.observedRevision);
}

/** Checks local presence without downloading or decrypting anything. */
export async function blobAvailability(session: ColophonSession, namespace: string, digest: string): Promise<BlobAvailabilityState> {
  await session.restore();
  const downloading = session.blobDownloads.get(digest);
  if (downloading) return { kind: 'downloading', completedChunks: downloading.completed, totalChunks: downloading.total };
  if (!ready(session)) return { kind: 'inaccessible', reason: 'The library is not ready' };
  try { return availability(session, namespace, digest); } catch (error) { return { kind: 'inaccessible', reason: error instanceof Error ? error.message : 'not readable' }; }
}

/**
 * Complete verified plaintext; missing chunks are fetched from the homes first. Each chunk is authenticated by the
 * engine and the whole content is checked against its digest before it is returned.
 */
export async function blobData(session: ColophonSession, namespace: string, digest: string, maximumBytes = 16 * 1024 * 1024): Promise<Uint8Array> {
  await session.restore();
  if (!ready(session)) throw new SessionError('notReady');
  const lease = session.context;
  const manifest = manifestOf(session, namespace, digest);
  if (manifest.size > maximumBytes) throw new BlobError('tooLarge', 'The blob is larger than the caller allows.');
  if (availability(session, namespace, digest).kind === 'missing') await fetchBlob(session, namespace, digest);
  if (lease !== session.context) throw new SessionError('destinationChanged');
  const out = new Uint8Array(manifest.size);
  let at = 0;
  for (let index = 0; index < manifest.chunks; index++) {
    let plaintext: Uint8Array;
    try { plaintext = session.worker.requireEngine().run(e => e.blob_chunk(namespace, digest, BigInt(index))); } catch (error) {
      if (isAccountFault(error)) {
        if (error.kind === 'Unavailable') throw new BlobError('missing', error.detail);
        if (error.kind === 'Denied') throw new BlobError('inaccessible', error.detail);
        if (error.kind === 'Malformed' || error.kind === 'BadSignature') throw new BlobError('invalid', error.detail);
      }
      throw error;
    }
    if (at + plaintext.length > out.length) throw new BlobError('digestMismatch', "The blob's content does not match its digest.");
    out.set(plaintext, at); at += plaintext.length;
  }
  if (at !== manifest.size || hex(new Uint8Array(await crypto.subtle.digest('SHA-256', out))) !== manifest.digest) {
    throw new BlobError('digestMismatch', "The blob's content does not match its digest.");
  }
  return out;
}

/** Downloads every missing chunk (ciphertext only) from the homes so later reads work offline. */
export async function prefetchBlob(session: ColophonSession, namespace: string, digest: string): Promise<void> {
  await session.restore();
  if (!ready(session)) throw new SessionError('notReady');
  await fetchBlob(session, namespace, digest);
}

/** Fetches every blob marked `required` that is not complete here (one exchange pulls them). */
export async function downloadRequiredBlobs(session: ColophonSession): Promise<void> {
  await session.restore();
  if (session.phase.kind !== 'ready' || !session.homesConfigured) return;
  for (const namespace of session.worker.configuration.namespaces) {
    let missing: string[] = [];
    try { missing = session.worker.requireEngine().run(e => e.required_blob_fetches(namespace)); } catch { /* not readable now */ }
    if (missing.length > 0) { await session.syncNow(); return; }
  }
}

async function fetchBlob(session: ColophonSession, namespace: string, digest: string): Promise<void> {
  const manifest = manifestOf(session, namespace, digest);
  session.blobDownloads.set(digest, { completed: 0, total: manifest.chunks });
  try {
    if (!session.homesConfigured) throw new BlobError('missing', 'No home is configured to fetch it from.');
    const engine = session.worker.requireEngine();
    for (const home of plain<Home[]>(engine.run(e => e.exchange_homes()))) engine.run(e => e.exchange_want_blob(home.id, namespace, digest));
    await session.syncNow();
    if (availability(session, namespace, digest).kind === 'available') return;
    throw new BlobError('missing', 'No home holds every chunk yet.');
  } finally {
    session.blobDownloads.delete(digest);
  }
}
