// The idle cost of home slots: CPU per wall-clock minute while nobody is connected, and the home
// module calls the scheduler makes. Not a test (`bun test` does not run it); see
// scripts/bench-home-idle.sh, which builds the slot it copies.
//
//   bun relay/test/bench-idle.js --wasm <module> --fixture <dir> [--slots 1,8,50] [--seconds 60]
//                                [--warm 10] [--offset-ms 0] [--tick-ms 2000]
//   bun relay/test/bench-idle.js --micro --wasm <module>[,<module>…] --fixture <dir> [--runs 40]
//
// `--fixture` is a directory holding `home/` (a home slot) and `meta.json` ({account, base,
// homeKey, now}). Each of the N slots is a copy of it at its own base. The relay's clock is the
// fixture's `now` plus `--offset-ms` plus the wall time elapsed. `--micro` times single module
// calls over the fixture's state instead (one line per module).
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRelay } from '../relay.js';
import { HomeModule } from '../home.js';

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const fixture = opt('fixture');
const wasmFiles = (opt('wasm') ?? '').split(',').filter(Boolean);
if (!fixture || !wasmFiles.length) {
  console.error('usage: bun relay/test/bench-idle.js --wasm <module> --fixture <dir> [--slots 1,8,50] [--seconds 60]');
  process.exit(2);
}
const meta = JSON.parse(await readFile(path.join(fixture, 'meta.json'), 'utf8'));
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const round = (x, n = 2) => Number(x.toFixed(n));

/** A module whose calls are counted and timed, by op. */
async function counted(file) {
  const wasm = await HomeModule.load(file);
  const call = wasm.call.bind(wasm);
  wasm.stats = new Map();
  wasm.call = (request) => {
    const start = performance.now();
    try { return call(request); } finally {
      const s = wasm.stats.get(request.op) ?? { n: 0, ms: 0 };
      s.n += 1; s.ms += performance.now() - start;
      wasm.stats.set(request.op, s);
    }
  };
  return wasm;
}

async function micro() {
  const state = JSON.parse(await readFile(path.join(fixture, 'home/home-state.json'), 'utf8'));
  const runs = Number(opt('runs', '40'));
  const now = meta.now + Number(opt('offset-ms', '0'));
  console.log(JSON.stringify({ stateBytes: state.length }));
  for (const file of wasmFiles) {
    const wasm = await HomeModule.load(file);
    const out = { module: path.basename(file) };
    for (const op of ['status', 'record_due', 'head_request']) {
      wasm.call({ op, state, now }); // warm (instantiation, first allocation)
      const start = performance.now();
      for (let i = 0; i < runs; i++) wasm.call({ op, state, now: now + i });
      out[`${op}Ms`] = round((performance.now() - start) / runs);
    }
    console.log(JSON.stringify(out));
  }
}

async function idle(slots) {
  const wasm = await counted(wasmFiles[0]);
  const dataDir = await mkdtemp(path.join(tmpdir(), 'colophon-bench-idle-'));
  const libraries = {};
  for (let k = 0; k < slots; k++) {
    await cp(path.join(fixture, 'home'), path.join(dataDir, `s${k}`), { recursive: true });
    libraries[`s${k}`] = { home: true, base: `https://home-${k}.example`, account: meta.account };
  }
  const t0 = Date.now();
  const offset = Number(opt('offset-ms', '0'));
  const clock = () => meta.now + offset + (Date.now() - t0);
  const relay = await createRelay({
    dataDir, libraries, tickMs: Number(opt('tick-ms', '2000')), clock,
    home: { wasm, key: meta.homeKey }, limits: { requestsPerMinute: 0 },
  });
  try {
    await sleep(Number(opt('warm', '10')) * 1000);
    wasm.stats.clear();
    const cpu = process.cpuUsage();
    const wall = performance.now();
    await sleep(Number(opt('seconds', '60')) * 1000);
    const used = process.cpuUsage(cpu);
    const minutes = (performance.now() - wall) / 60_000;
    const calls = {};
    for (const [op, s] of [...wasm.stats].sort()) calls[op] = { perMin: round(s.n / minutes, 1), meanMs: round(s.ms / s.n) };
    console.log(JSON.stringify({
      module: path.basename(wasmFiles[0]), slots,
      cpuSecondsPerMinute: round((used.user + used.system) / 1e6 / minutes, 3),
      calls,
    }));
  } finally {
    await relay.close();
    await rm(dataDir, { recursive: true, force: true });
  }
}

if (args.includes('--micro')) await micro();
else for (const n of (opt('slots', '1,8,50')).split(',').map(Number)) await idle(n);
