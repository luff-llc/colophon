// A revoked member has no epoch shares to unlock, but its engine must still load before notices and the exchange: a cold
// reopen of a revoked member is denied, not failed. The Swift and Kotlin sessions had this; the JS session did not
// before 0.5.0's final commit.
import { beforeAll, expect, test } from 'bun:test';
import { init, MemoryDeviceSecrets, MemoryPrivateStore, WebCryptoKeyProvider } from '../src/session/index.js';
import { approveByScan, Device } from './support.ts';

beforeAll(async () => { await init(); });

test('a revoked member reopens cold as denied', async () => {
  const first = await Device.make();
  const member = await WebCryptoKeyProvider.generate();
  const privateStore = new MemoryPrivateStore();
  const secrets = new MemoryDeviceSecrets();
  const open = () => Device.make({ medium: first.medium, member, privateStore, secrets, createWithoutHome: true });
  const joined = await open();
  try {
    await first.session.create();
    await joined.session.restore();
    await approveByScan(joined.session, first.session);
    await joined.session.refresh();
    if (joined.session.state.phase.kind !== 'ready') throw new Error(joined.describe());
    await first.session.revoke(joined.session.memberId!);
    joined.close();
    const reopened = await open();
    try {
      await reopened.session.restore();
      await reopened.session.refresh();
      expect(reopened.session.state.phase).toEqual({ kind: 'denied' });
      expect(reopened.session.state.lastError).toBeUndefined();
    } finally { reopened.close(); }
  } finally { joined.close(); first.close(); }
}, 120_000);
