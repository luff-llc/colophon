/**
 * Two devices of one person, each running a JavaScript `ColophonSession`, syncing through the REAL relay as their home
 * (`relay/server.js` on Bun with the Rust home module), which requires a signed call for everything spec §13.4 and §14
 * say needs one. No simulated home. The same journey runs through the Rust exports
 * (`crates/colophon-ffi/tests/v05_relay_journey.rs`), the Swift session and the Kotlin session.
 *
 * The journey: an owner creates an account with the home (the relay is started for the new account ID when the session
 * asks the home for its request); a second device holding a copy of the history from before its approval asks, is
 * approved, learns its approval through the home and syncs; both write and read, with a required and an optional
 * blob; a third device is approved then revoked, reads nothing new and is refused with exactly `refused:revoked`; a
 * pending change proposed on the first device is shown on the second (which holds a control key) and vetoed there.
 */
import {
  blobAvailability, blobData, glue, MemoryMedium, prefetchBlob, putBlob, SessionError, WebCryptoKeyProvider,
  type HistoryAccess, type HomeConfiguration,
} from '../src/session/index.js';
import { admitted, approveByCode, approveByScan, assert, Device, equal, note, RelayHome, sameBytes, sleep, type RelayHost } from './support.js';

export const authorityOnly = (medium: MemoryMedium): MemoryMedium => medium.copy(path => path.startsWith('authority/'));
const callRefused = (device: Device): string[] => device.session.homeIssues.flatMap(i => i.problem.kind === 'callRefused' ? [i.problem.code] : []);

/** Sync until the session says nothing is wrong (a home records entries and forwards heads on its own schedule). */
export async function settle(device: Device, tries = 40): Promise<boolean> {
  for (let n = 0; n < tries; n++) {
    const ok = await device.session.syncNow();
    if (ok && device.session.homeIssues.length === 0 && device.session.homeFaults.length === 0) return true;
    await sleep(150);
  }
  return false;
}

/**
 * A device that asked learns its approval through the home. The home signs a new head on its own tick (50 ms here), so
 * a pass that runs before it may find the approval not yet covered: then the device's own check of the call it would
 * need says `refused:revoked` (it is not a member at what it holds) and nothing is sent. Any other issue or fault
 * fails. Returns the number of passes it took.
 */
export async function untilApproved(device: Device, tries = 20): Promise<number> {
  for (let n = 1; n <= tries; n++) {
    await device.session.syncNow();
    await device.session.refresh();
    if (device.session.phase.kind === 'ready') return n;
    assert(device.session.homeFaults.length === 0 && device.session.homeIssues.every(i => i.problem.kind === 'callRefused' && i.problem.code === 'refused:revoked'),
      () => `only the device's own check may hold it back: ${device.describe()}`);
    await sleep(100);
  }
  throw new Error(`the device did not learn its approval through the home: ${device.describe()}`);
}

export async function journey(host: RelayHost, history: HistoryAccess, homeCount: number, log: (line: string) => void = () => {}): Promise<void> {
  const tag = `${history}-${homeCount}-${crypto.randomUUID().slice(0, 8)}`;
  const relays: RelayHome[] = [];
  for (let n = 0; n < homeCount; n++) relays.push(await RelayHome.make(host, `https://home-${n}.test/v1/accounts/js-${tag}`));
  const creating: HomeConfiguration[] = relays.map(relay => ({
    endpoint: `${relay.base}/`, label: `Relay ${relay.port}`, transport: relay.transport(),
    request: async account => { await relay.start(account, relays.filter(r => r !== relay)); return relay.memberRequest(account); },
  }));
  const joining = (refusals?: string[]): HomeConfiguration[] => relays.map(relay => ({ endpoint: `${relay.base}/`, transport: relay.transport(refusals) }));
  const devices: Device[] = [];
  try {
    const phoneOwner = await WebCryptoKeyProvider.generate();
    const first = await Device.make({ homes: creating, additional: [{ provider: phoneOwner, label: 'Phone owner key' }], history, headQuorum: homeCount });
    devices.push(first);
    await first.session.create();
    first.session.stopSync();
    equal(first.session.phase.kind, 'ready', `the first device is ready: ${first.describe()}`);
    equal(first.session.homes.length, homeCount, 'the homes are appointed at creation');
    await note(first.session, 'a');
    const required = Uint8Array.from({ length: 90_000 }, (_, i) => (i * 7) & 0xff);
    const optional = Uint8Array.from({ length: 20_000 }, (_, i) => (i * 13) & 0xff);
    const a = await putBlob(first.session, required, { namespace: 'notes', mediaType: 'text/plain', reference: 'a', required: true });
    const b = await putBlob(first.session, optional, { namespace: 'notes', mediaType: 'text/plain', reference: 'b', required: false });
    assert(await settle(first), () => `the first upload and the records reach the home: ${first.describe()}`);

    // The second device: a copy of the history from before its approval; it asks and is approved.
    const second = await Device.make({ medium: authorityOnly(first.medium as MemoryMedium), owner: phoneOwner, homes: joining() });
    devices.push(second);
    await second.session.restore();
    second.session.stopSync();
    equal(second.session.phase.kind, 'waitingForApproval', `the second device waits: ${second.describe()}`);
    // The two devices pair by the six-digit code (§7.3) and the owner approves what that pairing confirmed.
    await approveByCode(second.session, first.session);
    assert(await settle(first), () => first.describe());
    const secondPasses = await untilApproved(second);
    equal(second.session.phase.kind, 'ready', `the phone learnt its approval through the home: ${second.describe()}`);
    assert(await settle(second), () => second.describe());
    equal(await admitted(second.session), 3, 'the second device reads the note and the two blob publications');
    equal((await blobAvailability(second.session, 'notes', a.digest)).kind, 'available', 'a required blob comes with the sync');
    assert(sameBytes(required, await blobData(second.session, 'notes', a.digest)), 'the required blob reads back');
    equal((await blobAvailability(second.session, 'notes', b.digest)).kind, 'missing', 'an optional blob is not downloaded before it is asked for');
    await prefetchBlob(second.session, 'notes', b.digest);
    equal((await blobAvailability(second.session, 'notes', b.digest)).kind, 'available', 'fetched when asked');
    assert(sameBytes(optional, await blobData(second.session, 'notes', b.digest)), 'the optional blob reads back');
    await note(second.session, 'b');
    assert(await settle(second), () => second.describe());
    assert(await settle(first), () => first.describe());
    equal(await admitted(first.session), 4, 'the first device reads what the second wrote');

    // A third device is approved, then revoked: it reads nothing new and the home refuses it.
    const thirdRefusals: string[] = [];
    const third = await Device.make({ medium: authorityOnly(first.medium as MemoryMedium), homes: joining(thirdRefusals) });
    devices.push(third);
    await third.session.restore();
    third.session.stopSync();
    // The owner scans the third device's request from its screen (the scan path, §9.1).
    await approveByScan(third.session, first.session);
    assert(await settle(first), () => first.describe());
    const thirdPasses = await untilApproved(third);
    equal(third.session.phase.kind, 'ready', third.describe());
    assert(await settle(third), () => third.describe());
    equal(await admitted(third.session), 4, 'the third device reads everything');
    const thirdId = third.session.memberId;
    assert(thirdId !== undefined, 'the third device has a member ID');
    await first.session.revoke(thirdId);
    await note(first.session, 'c');
    assert(await settle(first), () => first.describe());
    thirdRefusals.length = 0;
    await third.session.syncNow();
    // Under `members` the home refuses its call with `refused:revoked` (the home holds the revocation, the device
    // cannot fetch it); under `public` it may fetch the revocation without a call, and then its own check refuses with
    // the same code and sends nothing. Any other refusal fails the test.
    const byHome = third.session.homeFaults.some(f => f.fault.kind === glue.ExchangeFaultKind.Unauthorized);
    const byItself = callRefused(third).includes('refused:revoked');
    assert(byHome || byItself, () => `the revoked device is refused: ${third.describe()} home said ${thirdRefusals.join(',')}`);
    if (byHome) assert(thirdRefusals.length > 0 && thirdRefusals.every(c => c === 'refused:revoked'), () => `the home refuses it as exactly refused:revoked: ${thirdRefusals.join(',')}`);
    if (history === 'members') assert(byHome, () => `the home refuses the revoked device: ${third.describe()}`);
    assert(callRefused(third).every(c => c === 'refused:revoked'), () => third.describe());
    log(`journey ${history}/${homeCount}: approvals learnt in ${secondPasses} and ${thirdPasses} passes; revoked device refused by home=${byHome} by itself=${byItself}, home results [${thirdRefusals.join(',')}]`);
    await third.session.refresh();
    // A device that holds its own revocation is `denied` and serves no read; one the home refused before it could
    // fetch the revocation still reads only what it had.
    if (byItself) equal(third.session.phase.kind, 'denied', third.describe());
    if (third.session.phase.kind === 'denied') {
      let served = true;
      try { await admitted(third.session); } catch (error) { served = !(error instanceof SessionError && error.code === 'notReady'); }
      assert(!served, 'a denied session served a read');
    } else {
      assert(await admitted(third.session) <= 4, () => `the revoked device reads nothing new: ${third.describe()}`);
    }

    // A pending change proposed on the first device is shown on the second and vetoed there: a policy change (a longer
    // recovery delay), a transition with a veto window, signed by the first device's owner.
    const proposing = first.session.proposeTransition('{"policy":{"recoveryDelay":7200}}');
    const digest = await proposing;
    assert(await settle(first), () => first.describe());
    assert(await settle(second), () => second.describe());
    const shown = second.session.notices.pending.find(p => p.digest === digest);
    assert(shown, () => `the second device shows the pending change: ${second.describe()}`);
    assert(shown.vetoable, "the phone's owner key may veto it");
    await second.session.veto(digest);
    // The veto was submitted as its own object, by its own digest, and every home receipted that.
    const vetoed = second.session.duties.submissions.find(s => s.kind === 'veto');
    assert(vetoed && vetoed.object !== digest && /^[0-9a-f]{64}$/.test(vetoed.object), () => `the veto is submitted by its own digest: ${JSON.stringify(second.session.duties.submissions)}`);
    // Done when every home receipted it, or when a home recorded the veto (then the others have nothing left to receipt).
    assert(vetoed.finished && vetoed.homes === homeCount && vetoed.receipted >= 1, () => `a home receipted the veto: ${JSON.stringify(vetoed)}`);
    assert(vetoed.receipted === homeCount || !second.session.notices.pending.some(p => p.digest === digest), () => `the veto is receipted everywhere or recorded: ${JSON.stringify(vetoed)}`);
    assert(await settle(second), () => second.describe());
    let gone = false;
    for (let n = 0; n < 60 && !gone; n++) {
      await first.session.syncNow();
      gone = !first.session.notices.pending.some(p => p.digest === digest);
      if (!gone) await sleep(150);
    }
    assert(gone, () => `the home recorded the veto and the first device no longer shows the change: ${first.describe()}`);
  } finally {
    for (const device of devices) device.close();
  }
}

export const journeys: [string, HistoryAccess, number][] = [
  ['two devices and a real home with the history for members', 'members', 1],
  ['two devices and a real home with a public history', 'public', 1],
  ['two devices and two real homes at quorum two', 'members', 2],
];
