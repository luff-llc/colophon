import { afterAll, beforeAll, test } from 'bun:test';
import { init } from '../src/session/index.js';
import { journey, journeys } from './journey.ts';
import { BunRelayHost } from './relay-bun.ts';

const host = new BunRelayHost();
beforeAll(async () => { BunRelayHost.module(); await init(); });
afterAll(async () => { await host.stopAll(); });

for (const [name, history, homes] of journeys) {
  test(name, async () => { await journey(host, history, homes, line => console.log(line)); }, 600_000);
}
