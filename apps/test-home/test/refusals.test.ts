// The local home service refuses what a web page or a rebinding name could send, and a readable key file.
// Run: swift build --package-path apps/test-home && bun test apps/test-home/test
import { afterAll, beforeAll, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const binary = join(import.meta.dir, '..', '.build', 'debug', 'colophon-test-home');
const port = 18_000 + Math.floor(Math.random() * 1000);
const dirs: string[] = [];
let child: ReturnType<typeof Bun.spawn> | undefined;
let token = '';

async function start(data: string, p: number): Promise<{ proc: ReturnType<typeof Bun.spawn>; line: string; err: string }> {
  const proc = Bun.spawn([binary, '--data', data, '--port', String(p), '--relay-port', String(p + 1)], { stdout: 'pipe', stderr: 'pipe' });
  const reader = proc.stdout.getReader();
  const first = await Promise.race([reader.read(), proc.exited.then(() => ({ value: undefined }))]);
  const line = first.value ? new TextDecoder().decode(first.value) : '';
  const err = line ? '' : await new Response(proc.stderr).text();
  return { proc, line, err };
}

beforeAll(async () => {
  const data = mkdtempSync(join(tmpdir(), 'colophon-test-home-'));
  dirs.push(data);
  const started = await start(data, port);
  child = started.proc;
  token = JSON.parse(started.line).token;
});
afterAll(() => { child?.kill(); for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const url = `http://127.0.0.1:${port}/status`;
const provision = `http://127.0.0.1:${port}/provision`;
const body = JSON.stringify({ slot: 'trefuse', base: 'https://home.test/v1/libraries/trefuse', account: 'a'.repeat(64) });

test('a token is printed and required', async () => {
  expect(token).toMatch(/^[0-9a-f]{64}$/);
  expect((await fetch(url)).status).toBe(401);
  expect((await fetch(url, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);
  expect((await fetch(url, { headers: { authorization: `Bearer ${token}` } })).status).toBe(200);
});

test('a request from a web page (any Origin) is refused', async () => {
  const r = await fetch(provision, { method: 'POST', body, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', origin: 'https://evil.example' } });
  expect(r.status).toBe(403);
});

test('a CORS-simple text/plain POST is refused', async () => {
  const r = await fetch(provision, { method: 'POST', body, headers: { authorization: `Bearer ${token}`, 'content-type': 'text/plain' } });
  expect(r.status).toBe(415);
});

test('another Host (DNS rebinding) is refused', async () => {
  const r = await fetch(url, { headers: { authorization: `Bearer ${token}`, host: 'rebind.example:' + port } });
  expect(r.status).toBe(403);
});

test('a group- or world-readable key file is refused at start-up, and a loose data directory is made private', async () => {
  const data = mkdtempSync(join(tmpdir(), 'colophon-test-home-'));
  dirs.push(data);
  chmodSync(data, 0o755);
  writeFileSync(join(data, 'home-key.jwk'), '{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"AAAA"}');
  chmodSync(join(data, 'home-key.jwk'), 0o644);
  const started = await start(data, port + 10);
  expect(started.line).toBe('');
  expect(await started.proc.exited).not.toBe(0);
  expect(started.err).toContain('readable by others');
  const mode = (await Bun.file(data).stat()).mode & 0o777;
  expect(mode).toBe(0o700);
});
