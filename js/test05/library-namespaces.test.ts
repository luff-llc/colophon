// A session whose `libraryNamespaces` (what the account declares at genesis) is wider than its own `namespaces` (what its
// member is granted) is ready after `create()`: readiness and published revisions follow the member's own namespaces.
// Before 0.5.0's final commit it came out denied. Each case runs without a home and with the real relay as its home.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { init, type HomeConfiguration } from '../src/session/index.js';
import { Device, RelayHome } from './support.ts';
import { BunRelayHost } from './relay-bun.ts';

const host = new BunRelayHost();
beforeAll(async () => { await init(); });
afterAll(async () => { await host.stopAll(); });

const all = ['listening.podcasts', 'notes', 'reading.books', 'reading.saved'];
const cases: [string, string[], string[]][] = [
  ['one own namespace of all four', ['listening.podcasts'], all],
  ['a member narrower than the library', ['reading.saved'], ['reading.saved', 'notes']],
  ['equal lists', ['notes', 'reading.saved'], ['notes', 'reading.saved']],
];

describe('a library wider than its member', () => {
  for (const [name, namespaces, library] of cases) {
    for (const withHome of [false, true]) {
      test(`${name} is ready after create (${withHome ? 'with a home' : 'no home'})`, async () => {
        let homes: HomeConfiguration[] | undefined;
        if (withHome) {
          const relay = await RelayHome.make(host, `https://home.test/v1/accounts/library-${crypto.randomUUID().slice(0, 8)}`);
          homes = [{ endpoint: `${relay.base}/`, transport: relay.transport(), request: async account => { await relay.start(account, []); return relay.memberRequest(account); } }];
        }
        const device = await Device.make({ homes, namespaces, libraryNamespaces: library });
        try {
          await device.session.create();
          if (device.session.state.phase.kind !== 'ready') throw new Error(device.describe());
          expect(device.session.members.some(m => JSON.stringify(m.grant?.namespaces) === JSON.stringify([...namespaces].sort()))).toBe(true);
          const published = Object.keys(device.session.state.namespaceRevisions).filter(n => n !== 'colophon.authority');
          expect(published.every(n => namespaces.includes(n))).toBe(true);
        } finally { device.close(); }
      }, 120_000);
    }
  }
});
