// Runs test05/browser/main.ts in a real browser engine: headless Chrome, driven over the DevTools protocol with
// nothing but Bun (no npm dependency). It bundles the page with Bun's own bundler, serves it on loopback with the
// wasm module, starts relays when the page asks, proxies the page's requests to them (same origin), gives the page a
// virtual WebAuthn authenticator with user verification and PRF, and exits non-zero unless every test passed.
//
// Usage: bun test05/run-browser.ts            (needs COLOPHON_HOME_WASM and js/dist/wasm, as scripts/test-js.sh makes)
// Chrome: COLOPHON_CHROME, or the usual install locations.
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BunRelayHost } from './relay-bun.ts';

const here = import.meta.dir;
const work = mkdtempSync(join(tmpdir(), 'colophon-js-browser-'));
const relays = new BunRelayHost();
BunRelayHost.module();

function chrome(): string {
  const candidates = [process.env.COLOPHON_CHROME, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
  const found = candidates.find(c => c !== undefined && existsSync(c));
  if (!found) throw new Error('browser prerequisite missing: Chrome or Chromium (set COLOPHON_CHROME)');
  return found;
}

const built = await Bun.build({ entrypoints: [join(here, 'browser/main.ts')], outdir: join(work, 'site'), target: 'browser', format: 'esm', naming: 'main.js' });
if (!built.success) { console.error(built.logs.join('\n')); process.exit(1); }
const wasm = new Uint8Array(readFileSync(join(here, '../dist/wasm/colophon_wasm_bg.wasm')));
const page = '<!doctype html><meta charset="utf-8"><title>Colophon 0.5 JS session: browser run</title><script type="module" src="/main.js"></script>';

let redirectTargetHits = 0;
let setAuthenticator: (prf: boolean) => Promise<void> = async () => {};
const json = (value: unknown, status = 200): Response => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
// The core takes only `https://<host>` (no port) as a web origin, and WebAuthn needs a secure context. So the page is
// served over TLS with a certificate made for this run (thrown away with the run), and Chrome is told that
// https://colophon-js.test (port 443) is this server and that this run ignores certificate errors.
const HOST = 'colophon-js.test';
const made = Bun.spawnSync(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', join(work, 'key.pem'),
  '-out', join(work, 'cert.pem'), '-days', '2', '-subj', `/CN=${HOST}`, '-addext', `subjectAltName=DNS:${HOST}`], { stdout: 'ignore', stderr: 'pipe' });
if (made.exitCode !== 0) { console.error(`browser prerequisite missing: openssl could not make the run's certificate: ${made.stderr.toString()}`); process.exit(1); }
const server = Bun.serve({
  port: 0, hostname: '127.0.0.1', idleTimeout: 120, tls: { key: Bun.file(join(work, 'key.pem')), cert: Bun.file(join(work, 'cert.pem')) },
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/') return new Response(page, { headers: { 'content-type': 'text/html' } });
    if (url.pathname === '/main.js') return new Response(Bun.file(join(work, 'site/main.js')), { headers: { 'content-type': 'text/javascript' } });
    if (url.pathname === '/colophon_wasm_bg.wasm') return new Response(wasm, { headers: { 'content-type': 'application/wasm' } });
    if (url.pathname === '/redirect/head') return new Response(null, { status: 302, headers: { location: '/redirect-target' } });
    if (url.pathname === '/redirect-target') { redirectTargetHits++; return new Response('followed'); }
    if (url.pathname.startsWith('/control/')) {
      const body = await request.json().catch(() => ({})) as Record<string, unknown>;
      try {
        switch (url.pathname.slice('/control/'.length)) {
          case 'port': return json({ port: await relays.freePort() });
          case 'start': await relays.start(body as Parameters<BunRelayHost['start']>[0]); return json({});
          case 'stop': await relays.stopAll(); return json({});
          case 'authenticator': await setAuthenticator(body.prf === true); return json({});
          case 'redirect-target-hits': return json({ hits: redirectTargetHits });
        }
      } catch (error) { return json({ error: String(error) }, 500); }
      return json({ error: 'unknown control' }, 404);
    }
    const proxied = /^\/relay\/([0-9]{1,5})(\/.*)?$/.exec(url.pathname);
    if (proxied) {
      const port = Number(proxied[1]);
      await relays.touchClock(port);
      const headers = new Headers(request.headers);
      for (const name of ['host', 'origin', 'referer', 'connection', 'accept-encoding']) headers.delete(name);
      const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer();
      const answer = await fetch(`${relays.local(port)}${proxied[2] ?? ''}${url.search}`, { method: request.method, headers, body, redirect: 'manual' });
      const out = new Headers(answer.headers);
      out.delete('content-encoding'); out.delete('content-length');
      return new Response(await answer.arrayBuffer(), { status: answer.status, headers: out });
    }
    return new Response('not found', { status: 404 });
  },
});
const origin = `https://${HOST}`;

const profile = join(work, 'profile');
const browser = Bun.spawn([chrome(), '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
  '--disable-gpu', `--host-resolver-rules=MAP ${HOST}:443 127.0.0.1:${server.port}`, '--ignore-certificate-errors', '--disable-extensions', '--disable-background-networking', 'about:blank'], { stdout: 'ignore', stderr: 'ignore', stdin: 'ignore' });
let exitCode = 1;
try {
  let devtools = '';
  for (let n = 0; n < 200 && devtools === ''; n++) {
    await Bun.sleep(50);
    try { devtools = readFileSync(join(profile, 'DevToolsActivePort'), 'utf8').split('\n')[0]!.trim(); } catch { /* not yet */ }
  }
  if (devtools === '') throw new Error('Chrome did not open its DevTools port');
  const target = await (await fetch(`http://127.0.0.1:${devtools}/json/new?about:blank`, { method: 'PUT' })).json() as { webSocketDebuggerUrl: string };
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise<void>((resolve, reject) => { socket.onopen = () => resolve(); socket.onerror = () => reject(new Error('DevTools socket failed')); });
  let next = 1;
  const waiting = new Map<number, { resolve(v: Record<string, unknown>): void; reject(e: Error): void }>();
  socket.onmessage = event => {
    const message = JSON.parse(String(event.data)) as { id?: number; result?: Record<string, unknown>; error?: { message: string }; method?: string; params?: { type?: string; args?: { value?: unknown; description?: string }[]; exceptionDetails?: { text?: string; exception?: { description?: string } } } };
    if (message.id !== undefined) {
      const pending = waiting.get(message.id); waiting.delete(message.id);
      if (message.error) pending?.reject(new Error(message.error.message)); else pending?.resolve(message.result ?? {});
    } else if (message.method === 'Runtime.consoleAPICalled') {
      console.log(`  [page] ${(message.params?.args ?? []).map(a => a.value ?? a.description ?? '').join(' ')}`);
    } else if (message.method === 'Runtime.exceptionThrown') {
      console.log(`  [page exception] ${message.params?.exceptionDetails?.exception?.description ?? message.params?.exceptionDetails?.text ?? ''}`);
    }
  };
  const send = (method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    const id = next++; waiting.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
  });
  await send('Runtime.enable'); await send('Page.enable'); await send('WebAuthn.enable');
  let authenticator: string | undefined;
  setAuthenticator = async prf => {
    if (authenticator !== undefined) await send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticator });
    const added = await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: prf } });
    authenticator = added.authenticatorId as string;
  };
  await setAuthenticator(true);
  const version: Record<string, unknown> = await send('Browser.getVersion').catch(() => ({}));
  console.log(`browser: ${String(version.product ?? 'unknown')} at ${origin}`);
  await send('Page.navigate', { url: `${origin}/` });
  const deadline = Date.now() + 15 * 60_000;
  let report: { done: boolean; failures: string[]; lines: string[] } | undefined;
  while (Date.now() < deadline) {
    await Bun.sleep(500);
    const evaluated = await send('Runtime.evaluate', { expression: 'JSON.stringify(globalThis.__colophon ?? null)', returnByValue: true });
    const value = (evaluated.result as { value?: string } | undefined)?.value;
    report = value ? JSON.parse(value) as typeof report : undefined;
    if (report?.done) break;
  }
  if (!report?.done) throw new Error('the page did not finish in time');
  const passed = report.lines.filter(l => l.startsWith('PASS ')).length;
  console.log(`browser run: ${passed} passed, ${report.failures.length} failed`);
  exitCode = report.failures.length === 0 && passed > 0 ? 0 : 1;
  socket.close();
} catch (error) {
  console.error(`browser run failed: ${error instanceof Error ? error.message : String(error)}`);
} finally {
  browser.kill();
  await browser.exited;
  await relays.stopAll();
  await server.stop(true);
  rmSync(work, { recursive: true, force: true });
}
process.exit(exitCode);
