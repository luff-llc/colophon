import {readFile, writeFile, mkdir} from "node:fs/promises";
import {join} from "node:path";
import {cases, compiledModule, operationsFromText, runCase, probeMetering} from "./js-host.mjs";

const [wasmPath, out, meteredPath] = process.argv.slice(2);
if (!wasmPath || !out) throw new Error("usage: bun hosts/bun.mjs path/to/module.wasm path/to/out [metered.wasm]");
await mkdir(out, {recursive: true});
const bytes = await readFile(wasmPath);
const compiled = await compiledModule(bytes);
const operations = operationsFromText(await readFile(join(out, "operations.jsonl"), "utf8"));
for (const n of cases) {
  const [state, query] = await Promise.all([
    readFile(join(out, `expected-${n}.json`)),
    readFile(join(out, `expected-query-${n}.json`))
  ]);
  const result = await runCase(compiled, operations, n, state, query);
  result.host = "bun";
  result.host_version = Bun.version;
  result.rss_snapshot_bytes = process.memoryUsage().rss; // instant reading, NOT process peak
  delete result.peak_rss_bytes;
  await writeFile(join(out, `bun-${n}.json`), JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify(result));
  if (!result.byte_equal) process.exitCode = 1;
}
if (meteredPath) {
  const meter = await compiledModule(await readFile(meteredPath));
  const result = await probeMetering(meter, operations[0]);
  await writeFile(join(out, "bun-meter.json"), JSON.stringify(result, null, 2) + "\n");
  console.log("meter:", JSON.stringify(result));
  if (!result.passed) process.exitCode = 1;
}
