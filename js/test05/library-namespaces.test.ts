// A session whose `libraryNamespaces` (what the account declares at genesis) is wider than its own `namespaces` (what its
// member is granted) is ready after `create()`: readiness and published revisions follow the member's own namespaces.
// Before 0.5.0's final commit it came out denied. Each case runs without a home and with the real relay as its home.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { init, type HomeConfiguration } from '../src/session/index.js';
import { admitted, approveByScan, Device, note, RelayHome } from './support.ts';
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

// The owner's engine sees every namespace of the account, whatever the app's own libraryNamespaces: a revoke made from an
// app whose library is narrower keeps what the revoked member wrote in the other namespaces. Before 0.5.0's final commit
// the owner engine was scoped to the app's library, and the revoked member's notes were dropped.
test('a revoke from a narrower app keeps what the member wrote elsewhere', async () => {
  const all = ['notes', 'reading.saved'];
  const writer = await Device.make({ namespaces: ['notes'], libraryNamespaces: all });
  const saved = await Device.make({ medium: writer.medium, owner: writer.owner, namespaces: ['reading.saved'], createWithoutHome: true });
  const reader = await Device.make({ medium: writer.medium, owner: writer.owner, namespaces: ['notes'], libraryNamespaces: all, createWithoutHome: true });
  try {
    await writer.session.create();
    await note(writer.session, 'kept');
    await saved.session.restore(); await approveByScan(saved.session, writer.session); await saved.session.refresh();
    if (saved.session.state.phase.kind !== 'ready') throw new Error(saved.describe());
    await reader.session.restore(); await approveByScan(reader.session, writer.session); await reader.session.refresh();
    if (reader.session.state.phase.kind !== 'ready') throw new Error(reader.describe());
    expect(await admitted(reader.session)).toBe(1);
    await saved.session.revoke(writer.session.memberId!);
    await reader.session.refresh();
    if (reader.session.state.phase.kind !== 'ready') throw new Error(reader.describe());
    expect(await admitted(reader.session)).toBe(1);
  } finally { reader.close(); saved.close(); writer.close(); }
}, 120_000);
