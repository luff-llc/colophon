// The 0.6 session conformance vectors replayed from JavaScript through the conformance wasm module
// (`colophon-conformance-wasm`, built by scripts/build-conformance.sh into js/.conformance/), as
// `crates/colophon-conformance/tests/support/vectors.rs` replays them in Rust. The module is test-only: the npm package
// neither includes nor imports it (checked below).
import { beforeAll, describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as c from '../.conformance/colophon_conformance.js';

const root = new URL('../..', import.meta.url).pathname;
const dir = join(root, 'conformance/0.6-sessions');
const read = (path: string): any => JSON.parse(readFileSync(path, 'utf8'));
const unhex = (t: string): Uint8Array => Uint8Array.from(t.match(/../g) ?? [], b => parseInt(b, 16));
const unb64 = (t: string): Uint8Array => Uint8Array.from(atob(t), ch => ch.charCodeAt(0));
const utf8 = (t: string): Uint8Array => new TextEncoder().encode(t);
const text = (b: Uint8Array): string => new TextDecoder().decode(b);
/** The code of a conformance error (`"<code>: <detail>"`). */
const codeOf = (error: unknown): string => String(error instanceof Error ? error.message : error).split(': ')[0] as string;
function thrown(run: () => unknown): string {
  try { run(); } catch (error) { return codeOf(error); }
  throw new Error('expected a refusal');
}

beforeAll(async () => {
  await c.default({ module_or_path: readFileSync(new URL('../.conformance/colophon_conformance_bg.wasm', import.meta.url)) });
});

/** Every machine transcript: one machine per member, each step's outputs compared in order, restarts from `persisted_json`. */
function replayMachines(): number {
  const names = readdirSync(dir).filter(n => n.endsWith('.json')).sort();
  let replayed = 0;
  for (const file of names) {
    const v = read(join(dir, file));
    if (v.format !== 'colophon/session-vectors/6') continue;
    const policy = JSON.stringify(v.policy); const fixes = JSON.stringify(v.fixes);
    const machines = new Map<string, c.ConformanceMachine>(); const canWrite = new Map<string, boolean>();
    for (const m of v.members) {
      machines.set(m.id, new c.ConformanceMachine(m.id, m.canWrite, policy, m.persisted === null ? undefined : JSON.stringify(m.persisted), fixes,
        m.freshSeed === null ? undefined : unhex(m.freshSeed)));
      canWrite.set(m.id, m.canWrite);
    }
    v.steps.forEach((step: any, k: number) => {
      const member: string = step.member;
      if (step.restart !== undefined) {
        const persisted = machines.get(member)!.persisted_json();
        machines.get(member)!.free();
        machines.set(member, new c.ConformanceMachine(member, canWrite.get(member)!, policy, persisted, fixes, undefined));
        return;
      }
      const got = JSON.parse(machines.get(member)!.handle(JSON.stringify(step.input), BigInt(step.at)));
      expect({ file, k, got }).toEqual({ file, k, got: step.outputs });
    });
    for (const f of v.final) {
      const m = machines.get(f.member)!;
      expect(m.digest()).toBe(f.digest);
      expect(JSON.parse(m.view_json())).toEqual(f.view);
    }
    for (const m of machines.values()) m.free();
    replayed++;
  }
  return replayed;
}

/** `offset.json`'s single samples (integers read losslessly: offsets saturate to the signed 64-bit range). */
function replayOffsets(): number {
  const raw = readFileSync(join(dir, 'offset.json'), 'utf8').replace(/(-?\d{16,})/g, '"$1"');
  const cases = JSON.parse(raw).cases as Record<string, string | number>[];
  for (const k of cases) {
    const n = (name: string): bigint => BigInt(k[name] as string | number);
    const s = c.session_clock_sample(n('now'), n('t'), n('echo'), n('hold'));
    expect([s.rtt, s.offset, s.error]).toEqual([n('rtt'), n('offset'), n('error')]);
    s.free();
  }
  return cases.length;
}

const members = (list: any[], ns: string): c.ConformanceMember[] => list.map(m => new c.ConformanceMember(unb64(m.signing), BigInt(m.session), undefined,
  [new c.ConformanceRecordEntry(ns, m.access === 'write' ? c.ConformanceAccess.Write : c.ConformanceAccess.Read)]));
function held(rx: c.ConformanceReceiver): [string, string, bigint | undefined][] {
  return rx.keys().map(k => { const r: [string, string, bigint | undefined] = [k.member, k.key, rx.window_high(k.member, k.key)]; k.free(); return r; });
}

/** The wire file: positive frames, scenarios and negative frames. Returns [frames, steps, negative]. */
function replayWire(): [number, number, number] {
  const v = read(join(dir, 'wire/vectors.json'));
  const { account, namespace: ns, cell, receiver: me, maxPayload } = v;
  const clock = BigInt(v.clockMs); const max = BigInt(maxPayload);
  const epochs = (): c.ConformanceEpochs => new c.ConformanceEpochs(ns, v.epochs.map((e: any) => new c.ConformanceEpochKey(BigInt(e.epoch), unhex(e.key))));
  const table = epochs();
  expect(table.current_epoch()).toBe(1n);
  const view = new c.ConformanceView(account, members(v.members, ns));

  // The session key and the exact delegation body; a changed signature refused, the real one installed.
  const sk = v.sessionKey;
  const tx = new c.ConformanceSender(account, ns, cell, sk.member, unhex(sk.privateKey));
  expect(tx.key_id()).toBe(sk.id);
  const body = tx.delegation_body(0n, clock, clock + 86_400_000n);
  expect(text(body)).toBe(v.delegation.body);
  const signature = unb64(v.delegation.signature);
  const forged = signature.slice(); forged[5]! ^= 1;
  expect(thrown(() => tx.install(body, forged, view, clock))).toBe('session:delegation');
  tx.install(body, signature, view, clock);

  const rx = new c.ConformanceReceiver(account, ns, cell, me);
  for (const f of v.frames) {
    const r = rx.open(utf8(f.frame), view, table, clock, max);
    const o = r.opened;
    expect({ name: f.name, dropped: r.dropped?.reason }).toEqual({ name: f.name, dropped: undefined });
    expect(text(o!.plaintext)).toBe(f.plaintext);
    expect([o!.writer, o!.n, o!.to, o!.epoch]).toEqual([f.writer, BigInt(f.n), f.to ?? undefined, 1n]);
  }

  let steps = 0;
  for (const sc of v.scenarios) {
    const rx2 = new c.ConformanceReceiver(account, ns, cell, sc.receiver ?? me);
    let current = new c.ConformanceView(account, members(v.views.default, ns));
    sc.steps.forEach((step: any, k: number) => {
      steps++;
      const ex = step.expect; const what = `${sc.name} step ${k}`;
      if (step.setView !== undefined) {
        current = new c.ConformanceView(account, members(v.views[step.setView], ns));
        const gone = rx2.set_account(current, clock);
        expect({ what, members: gone.members, keys: gone.keys.map(x => [x.member, x.key]) }).toEqual({ what, members: ex.forgottenMembers, keys: ex.closedKeys });
        return;
      }
      const at = step.clockMs !== undefined ? BigInt(step.clockMs) : clock;
      const before = held(rx2);
      const r = rx2.open(utf8(step.open), current, table, at, max);
      if (ex.drop === undefined || ex.drop === null) {
        expect({ what, dropped: r.dropped?.reason }).toEqual({ what, dropped: undefined });
        if (ex.writer !== undefined && ex.writer !== null) expect(r.opened!.writer).toBe(ex.writer);
      } else {
        expect({ what, reason: r.dropped?.reason }).toEqual({ what, reason: ex.drop });
        expect(r.opened).toBeUndefined();
        expect(held(rx2)).toEqual(before);
        if (ex.helloTo !== undefined) expect(r.dropped!.hello_to ?? null).toBe(ex.helloTo);
      }
    });
  }

  for (const n of v.negative) {
    const rx3 = new c.ConformanceReceiver(account, ns, cell, me);
    const at = n.clockMs !== undefined ? BigInt(n.clockMs) : clock;
    const maxp = n.maxPayload !== undefined ? BigInt(n.maxPayload) : max;
    for (const a of n.accept) expect(rx3.open(utf8(a), view, table, clock, max).opened).toBeDefined();
    const before = held(rx3);
    const r = rx3.open(utf8(n.frame), view, table, at, maxp);
    if (n.drop === null || n.drop === undefined) {
      expect({ name: n.name, opened: r.opened !== undefined, dropped: r.dropped?.reason }).toEqual({ name: n.name, opened: true, dropped: undefined });
    } else {
      expect({ name: n.name, reason: r.dropped?.reason }).toEqual({ name: n.name, reason: n.drop });
      expect(held(rx3)).toEqual(before);
    }
  }
  return [v.frames.length, steps, v.negative.length];
}

describe('0.6 session conformance from JavaScript', () => {
  test('every machine transcript, the offset cases and the wire file replay', () => {
    const machines = replayMachines();
    const offsets = replayOffsets();
    const [frames, steps, negative] = replayWire();
    console.log(`conformance: ${machines} machine transcripts, ${offsets} offset cases, wire ${frames} frames / ${steps} scenario steps / ${negative} negative frames`);
    expect(machines).toBeGreaterThanOrEqual(25);
    expect(offsets).toBeGreaterThan(0);
    expect(frames > 0 && steps > 0 && negative > 0).toBe(true);
  });

  test('session inputs are decoded strictly', () => {
    const policy = c.session_default_policy();
    const m = new c.ConformanceMachine('a', true, policy, undefined, undefined, undefined);
    for (const bad of ['{"input":"wave"}', '{"input":"tick","extra":1}', '{"input":"app","command":{"command":"jump"}}', '{"input":"app","command":{"command":"join"}}', 'not json']) {
      expect(thrown(() => m.handle(bad, 0n))).toBe('malformed');
    }
    expect(thrown(() => new c.ConformanceMachine('a', true, JSON.stringify({ ...JSON.parse(policy), surprise: true }), undefined, undefined, undefined))).toBe('malformed');
    expect(thrown(() => new c.ConformanceMachine('a', true, policy, '{"claim":{"term":0,"rank":0,"holder":"a"},"released":false}', undefined, undefined))).toBe('malformed');
    expect(thrown(() => new c.ConformanceMachine('a', true, policy, undefined, undefined, new Uint8Array(15)))).toBe('bound');
    expect(thrown(() => new c.ConformanceEpochs('listening.podcasts', [new c.ConformanceEpochKey(1n, new Uint8Array(31))]))).toBe('bound');
  });

  test('the shipped package neither includes nor imports the conformance module', () => {
    const pkg = read(join(root, 'js/package.json'));
    expect(pkg.files).toEqual(['dist']);
    expect(JSON.stringify(pkg.dependencies ?? {})).not.toContain('conformance');
    const sources: string[] = [];
    const walk = (d: string): void => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else sources.push(p); } };
    walk(join(root, 'js/src'));
    for (const s of sources) expect({ s, mentions: /conformance/i.test(readFileSync(s, 'utf8')) }).toEqual({ s, mentions: false });
  });
});
