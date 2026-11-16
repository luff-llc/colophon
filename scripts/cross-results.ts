// Fail closed on empty selections and count the results emitted by each runner.
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
const [kind, path] = process.argv.slice(2);
try {
  let count = 0;
  if (kind === "swift") {
    const log = await readFile(path, "utf8");
    const summaries = [...log.matchAll(/Test run with (\d+) tests?(?: in \d+ suites?)? passed/g)];
    if (/Test run with \d+ tests?(?: in \d+ suites?)? failed/.test(log)) throw new Error("Swift tests failed");
    count = Number(summaries.at(-1)?.[1] ?? 0);
  } else if (kind === "bun") {
    const log = await readFile(path, "utf8");
    if (!/\b0 fail\b/.test(log)) throw new Error("Bun tests failed or have no summary");
    count = Number([...log.matchAll(/\b(\d+) pass\b/g)].at(-1)?.[1] ?? 0);
  } else if (kind === "kotlin") {
    const files = (await readdir(path)).filter(f => /^TEST-.*\.xml$/.test(f));
    for (const file of files) {
      const xml = await readFile(join(path, file), "utf8");
      const suite = xml.match(/<testsuite\b[^>]*>/)?.[0] ?? "";
      const n = (key: string) => Number(suite.match(new RegExp(`\\b${key}="(\\d+)"`))?.[1] ?? NaN);
      if (n("failures") !== 0 || n("errors") !== 0) throw new Error(`${file} failed`);
      count += n("tests") - n("skipped");
    }
  } else throw new Error(`unknown runner ${kind}`);
  if (!Number.isSafeInteger(count) || count <= 0) throw new Error(`${kind}: no passed tests (empty filter or missing results)`);
  console.log(count);
} catch (e) { console.error(String(e)); process.exit(1); }
