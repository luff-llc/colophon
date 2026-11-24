// The module's cost per authenticated request on a slot with over a hundred history entries: one
// record GET (`access`) and one record PUT (`access`, then `check_record`), as the relay sends
// them. Not a test (`bun test` does not run it). The input is written by the ignored Rust test
// `write_request_bench_input` (crates/colophon-home-wasm/tests/v05_home_module.rs):
//
//   COLOPHON_REQUEST_BENCH=<file> cargo test -p colophon-home-wasm --test v05_home_module \
//     write_request_bench_input -- --ignored
//   bun relay/test/bench-request.js --input <file> --wasm <module>[,<module>…] [--runs 50] [--rows 2000]
//
// `--rows` gives the caller's principal that many retained replay rows: a module is sent them
// as `signerRows` and, when it takes them, as the two counts the relay now sends.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { HomeModule } from '../home.js';

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
};
const input = opt('input');
const wasmFiles = (opt('wasm') ?? '').split(',').filter(Boolean);
if (!input || !wasmFiles.length) {
  console.error('usage: bun relay/test/bench-request.js --input <file> --wasm <module>[,<module>…] [--runs 50] [--rows 2000]');
  process.exit(2);
}
const bench = JSON.parse(await readFile(input, 'utf8'));
const runs = Number(opt('runs', '50'));
const rows = Number(opt('rows', '0'));
const round = (x, n = 2) => Number(x.toFixed(n));
console.log(JSON.stringify({ entries: bench.entries, stateBytes: bench.stateBytes, rows }));

const signerRows = Array.from({ length: rows }, (_, i) => ({ key: `row-${i}`, at: bench.get.now - i * 1_000 }));
const counted = { signerLive: rows, signerOldest: rows ? bench.get.now - (rows - 1) * 1_000 : null };
for (const file of wasmFiles) {
  const wasm = await HomeModule.load(file);
  const out = { module: path.basename(file) };
  for (const [name, share] of [['rows', { signerRows }], ['counts', counted]]) {
    const time = (requests) => {
      for (const r of requests) wasm.call(r); // warm
      const start = performance.now();
      for (let i = 0; i < runs; i++) for (const r of requests) {
        const a = wasm.call(r);
        if (a.allowed !== true) throw new Error(`${r.op} refused: ${JSON.stringify(a)}`);
      }
      return round((performance.now() - start) / runs);
    };
    out[`get_${name}_ms`] = time([{ ...bench.get, ...share }]);
    out[`put_${name}_ms`] = time([{ ...bench.put, ...share }, bench.check]);
  }
  console.log(JSON.stringify(out));
}
