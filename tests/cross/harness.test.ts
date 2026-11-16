import { expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { World, settle } from "./device";

// Run actual helpers in disposable trees: no real framework or crate is changed.
test("Apple provenance changes for edited crates and Cargo.lock, and refuses a missing stamp", async () => {
  const root = await mkdtemp(join(tmpdir(), "colophon-provenance-"));
  async function run(...args: string[]) {
    const p = Bun.spawn(["bash", "scripts/apple-provenance.sh", root, ...args], { stdout: "pipe", stderr: "pipe" });
    return { code: await p.exited, out: await new Response(p.stdout).text() };
  }
  try {
    await mkdir(join(root, "crates/a"), { recursive: true });
    await writeFile(join(root, "crates/a/lib.rs"), "one");
    await writeFile(join(root, "Cargo.lock"), "lock one");
    await writeFile(join(root, "Cargo.toml"), "workspace");
    const first = await run("hash"); expect(first.code).toBe(0);
    expect((await run("check")).code).toBe(1);
    await mkdir(join(root, "sdk/apple/ColophonFFI.xcframework"), { recursive: true });
    expect((await run("check")).code).toBe(1);
    await writeFile(join(root, "sdk/apple/ColophonFFI.source-hash"), first.out);
    expect((await run("check")).code).toBe(0);
    await writeFile(join(root, "crates/a/lib.rs"), "two");
    expect((await run("check")).code).toBe(1);
    const second = await run("hash"); expect(second.out).not.toBe(first.out);
    await writeFile(join(root, "sdk/apple/ColophonFFI.source-hash"), second.out);
    expect((await run("check")).code).toBe(0);
    await writeFile(join(root, "Cargo.lock"), "lock two");
    expect((await run("check")).code).toBe(1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("a zero-match Swift filter is a failure, and result counts come from output", async () => {
  const root = await mkdtemp(join(tmpdir(), "colophon-results-"));
  async function count(log: string) {
    const file = join(root, "swift.log"); await writeFile(file, log);
    const p = Bun.spawn([process.execPath, "scripts/cross-results.ts", "swift", file], { stdout: "pipe", stderr: "pipe" });
    return { code: await p.exited, out: await new Response(p.stdout).text() };
  }
  try {
    expect((await count("warning: No matching test cases were run\n")).code).toBe(1);
    expect((await count("Test run with 0 tests passed after 0.1 seconds.\n")).code).toBe(1);
    expect(await count('✔ Test a() passed after 0.1 seconds.\n✔ Test b() passed after 0.1 seconds.\n✔ Test run with 2 tests in 1 suite passed after 0.1 seconds.\n')).toEqual({ code: 0, out: "2\n" });
    expect((await count("Test run with 2 tests failed after 0.1 seconds.\n")).code).toBe(1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("settle refuses lastError even when phase, issues and faults look healthy", async () => {
  const device = { platform: "swift", call: async () => ({ phase: "ready", issues: [], faults: [], error: "sync lost data" }) };
  await expect(settle(device as any)).rejects.toThrow("sync lost data");
});

test("driver key files are private even with a permissive parent umask", async () => {
  for (const platform of ["swift", "kotlin"] as const) {
    const world = await new World("members", 1).init();
    try {
      const d = world.device(platform, platform); await d.start(); await d.call("create");
      await d.call("checkpoint");
      const privateDir = join(d.root, "private");
      let secrets = 0;
      for await (const file of new Bun.Glob("**/*").scan({ cwd: privateDir, onlyFiles: true })) {
        if (!/member-|owner-|device-secret-/.test(file)) continue;
        if (file.startsWith("device-secret-")) secrets++;
        expect((await stat(join(privateDir, file))).mode & 0o777, `${platform}/${file}`).toBe(0o600);
      }
      expect(secrets).toBe(1);
      expect((await stat(join(d.root, ".."))).mode & 0o777).toBe(0o700);
      expect((await stat(join(d.root, "..", "key-0.json"))).mode & 0o777).toBe(0o600);
    } finally { await world.close(); }
  }
}, 60_000);

for (const signal of ["SIGINT", "SIGTERM"] as const) test(`${signal} cleans the owned drivers, relay and run directory`, async () => {
  const child = Bun.spawn([process.execPath, "tests/cross/signal-fixture.ts"], { stdout: "pipe", stderr: "inherit" });
  let root = "";
  try {
    for await (const line of (child.stdout as ReadableStream<Uint8Array>).pipeThrough(new TextDecoderStream())) {
      const state = JSON.parse(line.trim());
      if (state.ready) { root = join(state.root, ".."); break; }
    }
    expect(root).not.toBe("");
    child.kill(signal);
    expect(await child.exited).toBe(signal === "SIGTERM" ? 143 : 130);
    expect(await Bun.file(join(root, "key-0.json")).exists()).toBe(false);
    await expect(stat(root)).rejects.toThrow("ENOENT");
  } finally { if (child.exitCode === null) { child.kill(); await child.exited; } if (root) await rm(root, { recursive: true, force: true }); }
}, 60_000);
