// A real Chromium page, not the Node WebAssembly engine.
// Start python3 -m http.server 8765 at the repository root before running.
import {chromium} from "playwright";
import {mkdir, writeFile} from "node:fs/promises";
import {join} from "node:path";
import {cases} from "./js-host.mjs";

const [base, out, meterPath] = process.argv.slice(2);
if (!base || !out) throw new Error("usage: node hosts/browser-runner.mjs http://localhost:8765 out [metered-path]");
const origin = base.replace(/\/$/, "");
const prefix = "/spikes/module-abi/";
const absolute = (path) => origin + prefix + path;
await mkdir(out, {recursive: true});
const browser = await chromium.launch({headless: true, args: ["--no-sandbox"]});
try {
  const page = await browser.newPage();
  await page.goto(absolute("hosts/browser.html"));
  await page.waitForFunction(() => typeof window.moduleSpikeRun === "function");
  for (const n of cases) {
    const result = await page.evaluate((x) => window.moduleSpikeRun(x), {
      wasmURL: absolute("target/wasm32-unknown-unknown/release/colophon_module_abi_spike.wasm"),
      opsURL: absolute("out/operations.jsonl"), count: n,
      expectedURL: absolute(`out/expected-${n}.json`),
      expectedQueryURL: absolute(`out/expected-query-${n}.json`)
    });
    await writeFile(join(out, `browser-${n}.json`), JSON.stringify(result, null, 2) + "\n");
    console.log(JSON.stringify(result));
    if (!result.byte_equal) process.exitCode = 1;
  }
  if (meterPath) {
    const result = await page.evaluate(x => window.moduleSpikeMeter(x), {
      wasmURL: absolute(meterPath),
      opsURL: absolute("out/operations.jsonl")
    });
    await writeFile(join(out, "browser-meter.json"), JSON.stringify(result, null, 2)+"\n");
    console.log("meter:", JSON.stringify(result));
    if (!result.passed) process.exitCode = 1;
  }
} finally {
  await browser.close();
}
