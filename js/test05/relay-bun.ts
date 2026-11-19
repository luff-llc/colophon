// The Bun side of the relays: spawns `bun relay/server.js --test-clock` on loopback with a temporary data directory.
// Missing Bun or the home module fails the run (it never passes by skipping). Every relay is killed by `stopAll`, and
// by an exit hook if the process dies first; its data directory names `colophon-js-relay` so `scripts/test-js.sh` can
// check that none is left behind.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RelayHost } from './support.ts';

export const repository = new URL('../..', import.meta.url).pathname.replace(/\/$/, '');

interface Running { process: ReturnType<typeof Bun.spawn>; clock: string; directory: string }

export class BunRelayHost implements RelayHost {
  private readonly running = new Map<number, Running>();
  private readonly onExit = (): void => { for (const r of this.running.values()) { try { r.process.kill('SIGKILL'); } catch { /* gone */ } } };
  constructor() { process.on('exit', this.onExit); }

  static module(): string {
    const path = process.env.COLOPHON_HOME_WASM;
    if (!path) throw new Error('relay prerequisite missing: COLOPHON_HOME_WASM is not set (run scripts/test-js.sh)');
    return path;
  }
  async freePort(): Promise<number> {
    const server = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: () => new Response('') });
    const port = server.port;
    await server.stop(true);
    if (port === undefined) throw new Error('no free port');
    return port;
  }
  async start(spec: { port: number; account: string; base: string; jwk: JsonWebKey; peers: { base: string; port: number }[] }): Promise<void> {
    const directory = mkdtempSync(join(tmpdir(), `colophon-js-relay-${process.pid}-`));
    const clock = join(directory, 'clock');
    writeFileSync(clock, String(Date.now()));
    const config = join(directory, 'config.json');
    writeFileSync(config, JSON.stringify({ resolve: Object.fromEntries(spec.peers.map(p => [p.base, `http://127.0.0.1:${p.port}/v1/libraries/home`])) }));
    const child = Bun.spawn([process.execPath, join(repository, 'relay/server.js'), '--test-clock', '--config', config], {
      env: { ...process.env, COLOPHON_RELAY_PORT: String(spec.port), COLOPHON_RELAY_DATA: join(directory, 'data'),
        COLOPHON_RELAY_HOME_SLOTS: `home=${spec.account}@${spec.base}`, COLOPHON_HOME_KEY: JSON.stringify(spec.jwk),
        COLOPHON_HOME_WASM: BunRelayHost.module(), COLOPHON_RELAY_CLOCK_FILE: clock, COLOPHON_RELAY_TICK_MS: '50' },
      stdout: 'pipe', stderr: 'ignore', stdin: 'ignore',
    });
    this.running.set(spec.port, { process: child, clock, directory });
    // The first stdout line is machine-readable: {"listening":{...}}. Keep draining so the relay never blocks on a full pipe.
    const reader = child.stdout.getReader();
    const first = await reader.read();
    const line = new TextDecoder().decode(first.value ?? new Uint8Array());
    if (!line.includes('"listening"')) { await this.stop(spec.port); throw new Error(`the relay did not start: ${line}`); }
    void (async () => { try { for (;;) { if ((await reader.read()).done) break; } } catch { /* closed */ } })();
  }
  local(port: number): string { return `http://127.0.0.1:${port}/v1/libraries/home`; }
  async touchClock(port: number): Promise<void> {
    const running = this.running.get(port);
    if (running) writeFileSync(running.clock, String(Date.now()));
  }
  private async stop(port: number): Promise<void> {
    const running = this.running.get(port);
    if (!running) return;
    this.running.delete(port);
    running.process.kill();
    const killer = setTimeout(() => { try { running.process.kill('SIGKILL'); } catch { /* gone */ } }, 5000);
    await running.process.exited;
    clearTimeout(killer);
    rmSync(running.directory, { recursive: true, force: true });
  }
  async stopAll(): Promise<void> {
    for (const port of [...this.running.keys()]) await this.stop(port);
    process.off('exit', this.onExit);
  }
}
