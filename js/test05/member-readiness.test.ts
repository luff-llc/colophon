import { beforeAll, expect, test } from 'bun:test';
import { init } from '../src/session/index.js';
import { ColophonEngine } from '../src/session/engine.js';
import { SecretBytes } from '../src/session/secrets.js';
import { plain } from '../src/session/wasm.js';
import type { AccountMember, AccountDenial } from '../src/session/records.js';
import { glue } from '../src/session/wasm.js';
import { memberReadiness } from '../src/session/worker.js';
import { approveByScan, Device } from './support.ts';

beforeAll(async () => { await init(); });

for (const namespaces of [[], ['notes']]) for (const libraryNamespaces of [[], ['reading.saved']]) {
  test(`expiry is checked for grant ${namespaces} outside library ${libraryNamespaces}`, async () => {
    let now = 1_800_000_000_000;
    const first = await Device.make({ namespaces: ['notes'], libraryNamespaces: ['notes', 'reading.saved'], now: () => now });
    const services = [{ audience: 'urn:test', purposes: ['read'] }];
    const second = await Device.make({ medium: first.medium, namespaces, libraryNamespaces, services, now: () => now });
    try {
      await first.session.create();
      await second.session.restore();
      const expires = new Date(now + 3_600_000).toISOString().replace('.000Z', 'Z');
      await approveByScan(second.session, first.session, JSON.stringify({
        ...(namespaces.length ? { records: namespaces.map(namespace => ({ namespace, access: 'write' })) } : {}),
        services, expires,
      }));
      now += 3_600_000;
      await second.session.refresh();
      expect(second.session.phase.kind).toBe('ready'); // The core's expiry bound is inclusive.
      now++;
      await second.session.refresh();
      expect(second.session.phase.kind).toBe('denied');
      expect(second.session.state.namespaceRevisions).toEqual({});
    } finally { second.close(); first.close(); }
  });
}

test('provisional and revoked members are denied even with no namespace checks; missing epoch keys remain unavailable', async () => {
  const device = await Device.make();
  try {
    await device.session.create();
    const member = device.session.state.members.find(m => m.id === device.session.memberId)!;
    expect(member).not.toBeUndefined();
    for (const namespaces of [[], ['notes']]) {
      for (const denied of [{ ...member, grant: { ...member.grant!, namespaces: [] }, provisional: true },
        { ...member, grant: { ...member.grant!, namespaces: [] }, revokedAt: 1n }]) {
        let calls = 0;
        const result = memberReadiness(denied, 0n, namespaces, () => { calls++; return undefined; });
        expect(result).toEqual({ phase: { kind: 'denied' }, readable: [] });
        expect(calls).toBe(0);
      }
    }
    for (const reason of [glue.AccountDenialReason.Unavailable, glue.AccountDenialReason.NotReadable]) {
      const checked: string[] = [];
      const result = memberReadiness(member, 0n, ['notes'], namespace => {
        checked.push(namespace);
        return { reason, detail: 'epoch key not held' };
      });
      expect(checked).toEqual(['notes']);
      expect(result).toEqual({ phase: { kind: 'unavailable', reason: 'epoch key not held' }, readable: [] });
    }
  } finally { device.close(); }
});

test('a real member engine without unlocked epoch keys is unavailable', async () => {
  const device = await Device.make();
  const key = SecretBytes.random(32);
  let engine: ColophonEngine | undefined;
  try {
    await device.session.create();
    engine = ColophonEngine.open({ medium: device.medium, listing: await device.medium.listing(),
      identity: { kind: 'member', id: device.session.memberId! }, account: device.session.libraryId!,
      namespaces: ['notes'], deviceKey: key, nowMs: Date.now() });
    const member = plain<AccountMember>(engine.run(e => e.me().member));
    const denial = plain<AccountDenial | undefined>(engine.run(e => e.access('notes')));
    expect(denial?.reason).toBe(glue.AccountDenialReason.NotReadable);
    const result = memberReadiness(member, BigInt(Date.now()), ['notes'], () => denial);
    expect(result.phase.kind).toBe('unavailable');
    expect(result.readable).toEqual([]);
  } finally { engine?.lock(); key.close(); device.close(); }
});
