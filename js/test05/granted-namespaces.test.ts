// Folded into 0.5.0 from the fix-051 branch.
import { beforeAll, describe, expect, test } from 'bun:test';
import { init, type MemoryMedium } from '../src/session/index.js';
import { approveByScan, Device, equal, note } from './support.ts';

beforeAll(async () => { await init(); });

// A session whose library declares more namespaces than its own member was granted (`libraryNamespaces` wider than
// `namespaces`). The session is `denied` only when its member lost access it was granted, never because the library
// declares namespaces this member never had (docs/js-session.md, Phases).
describe('a member of a wider library', () => {
  const published = (device: Device): string[] => Object.keys(device.session.state.namespaceRevisions).filter(n => n !== 'colophon.authority').sort();

  test('is ready after creation, and publishes only what it may read', async () => {
    const cases: [string[], string[]][] = [
      [['listening.podcasts'], ['listening.podcasts', 'reading.saved', 'notes', 'reading.books']],
      [['reading.saved'], ['reading.saved', 'notes']],
      [['reading.saved', 'notes'], ['reading.saved', 'notes']],
    ];
    for (const [namespaces, libraryNamespaces] of cases) {
      const device = await Device.make({ namespaces, libraryNamespaces });
      await device.session.create();
      equal(device.session.phase.kind, 'ready', `${namespaces} of ${libraryNamespaces}: ${device.describe()}`);
      expect(published(device)).toEqual([...namespaces].sort());
      device.close();
    }
  });

  test('that is later revoked is denied', async () => {
    const libraryNamespaces = ['reading.saved', 'notes'];
    const first = await Device.make({ namespaces: ['reading.saved'], libraryNamespaces });
    await first.session.create();
    expect(first.session.phase.kind).toBe('ready');
    const second = await Device.make({ medium: first.medium, namespaces: ['notes'], libraryNamespaces });
    await second.session.restore();
    await approveByScan(second.session, first.session);
    await second.session.refresh();
    equal(second.session.phase.kind, 'ready', second.describe());
    expect(published(second)).toEqual(['notes']);
    await first.session.revoke(second.session.memberId!);
    await second.session.refresh();
    equal(second.session.phase.kind, 'denied', second.describe());
    expect(Object.keys(second.session.state.namespaceRevisions)).toEqual([]);
    second.close(); first.close();
  });

  // The approver narrows the terms: the device asks for two namespaces of the library and is granted one.
  test('approved for fewer namespaces than it asked is ready, publishes only those, and is refused a write to the others', async () => {
    const libraryNamespaces = ['reading.saved', 'notes', 'reading.books'];
    const first = await Device.make({ namespaces: ['reading.books'], libraryNamespaces });
    await first.session.create();
    expect(first.session.phase.kind).toBe('ready');
    const second = await Device.make({ medium: first.medium, namespaces: ['reading.saved', 'notes'], libraryNamespaces });
    await second.session.restore();
    await approveByScan(second.session, first.session, '{"records":[{"namespace":"reading.saved","access":"write"}]}');
    await second.session.refresh();
    equal(second.session.phase.kind, 'ready', second.describe());
    expect(published(second)).toEqual(['reading.saved']);
    const before = (first.medium as MemoryMedium).listing().length;
    await expect(note(second.session, 'x')).rejects.toMatchObject({ kind: 'Denied', reason: 'notGranted' });
    expect((first.medium as MemoryMedium).listing().length).toBe(before);
    equal(second.session.phase.kind, 'ready', second.describe());
    second.close(); first.close();
  });

  // Driven by the injected clock, no sleeping.
  test('whose grant has expired is denied', async () => {
    const libraryNamespaces = ['reading.saved', 'notes'];
    let now = Date.now();
    const first = await Device.make({ namespaces: ['reading.saved'], libraryNamespaces, now: () => now });
    await first.session.create();
    expect(first.session.phase.kind).toBe('ready');
    const second = await Device.make({ medium: first.medium, namespaces: ['notes'], libraryNamespaces, now: () => now });
    await second.session.restore();
    const expires = new Date(Math.floor((now + 3_600_000) / 1000) * 1000).toISOString().replace('.000Z', 'Z');
    await approveByScan(second.session, first.session, `{"records":[{"namespace":"notes","access":"write"}],"expires":"${expires}"}`);
    await second.session.refresh();
    equal(second.session.phase.kind, 'ready', second.describe());
    expect(published(second)).toEqual(['notes']);
    now += 7_200_000;
    await second.session.refresh();
    equal(second.session.phase.kind, 'denied', second.describe());
    expect(Object.keys(second.session.state.namespaceRevisions)).toEqual([]);
    second.close(); first.close();
  });
});
