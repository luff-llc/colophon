import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Subprocess } from "bun";

// Own process handles, never PID searches: even exceptional process exit can only kill our children.
const activeWorlds = new Set<World>();
let stopping = false;
for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143]] as const) process.on(signal, () => {
  if (stopping) return;
  stopping = true;
  const deadline = setTimeout(() => process.exit(code), 10_000);
  void Promise.allSettled([...activeWorlds].map(w => w.close())).then(() => {
    clearTimeout(deadline); process.exit(code);
  });
});
process.on("exit", () => { for (const world of activeWorlds) world.killOwned(); });

export const repo = resolve(import.meta.dir, "../..");
export type Platform = "swift" | "kotlin";
export type Home = { base: string; local: string; secret: string; signing: string; agreement: string };
export const b64 = (b: Uint8Array | string) => Buffer.from(b).toString("base64");
export const unb64 = (s: string) => Buffer.from(s, "base64");
export const delay = (ms: number) => new Promise(r => setTimeout(r, ms));

async function* lines(stream: ReadableStream<Uint8Array>) {
  let held = "";
  const decoder = new TextDecoder();
  for await (const chunk of stream) {
    held += decoder.decode(chunk, { stream: true });
    let end: number;
    while ((end = held.indexOf("\n")) >= 0) {
      yield held.slice(0, end); held = held.slice(end + 1);
    }
  }
  if (held) throw new Error("unterminated JSON line");
}
async function within<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label}: timeout after ${ms} ms`)), ms);
    })]);
  } finally { clearTimeout(timer!); }
}

/** One real SDK process. Exactly one command at a time; provisioning and remote possession signing are nested events. */
export class Device {
  private child?: Subprocess<"pipe", "pipe", "pipe">;
  private pending?: { resolve: (v: any) => void; reject: (e: Error) => void };
  private output?: Promise<void>;
  private errors?: Promise<void>;
  private stderr = "";
  private config?: Record<string, unknown>;
  signer?: Device;
  constructor(readonly platform: Platform, readonly root: string, private world: World) {}
  async start(extra?: unknown, more: Record<string, unknown> = {}) {
    const swift = process.env.COLOPHON_CROSS_SWIFT;
    const target = process.env.CARGO_TARGET_DIR;
    if (!swift || !target) throw new Error("run scripts/test-cross.sh (driver and native library required)");
    const classpath = (await readFile(join(repo, "sdk/kotlin/build/cross-device-classpath.txt"), "utf8")).trim();
    const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, "bin/java") : "java";
    const cmd = this.platform === "swift" ? [swift] : [java, `-Djna.library.path=${target}/release`, "-cp", classpath, "com.luff.colophon.session.CrossDeviceKt"];
    // A normal permissive umask makes the native drivers prove their own key-file permissions.
    this.child = Bun.spawn(["bash", "-c", 'umask 022; exec "$@"', "cross-device", ...cmd], { cwd: repo, stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    this.stderr = "";
    this.errors = (async () => {
      for await (const chunk of this.child!.stderr) this.stderr = (this.stderr + Buffer.from(chunk).toString()).slice(-12000);
    })();
    this.output = (async () => {
      try {
        for await (const line of lines(this.child!.stdout)) {
          const value = JSON.parse(line);
          if (value.event) {
            let reply: unknown;
            try {
              if (value.event === "provision") { await this.world.provision(value.account); reply = {}; }
              else if (value.event === "sign" && this.signer) reply = { signature: await this.signer.call("sign", { body: value.body }) };
              else throw new Error(`unknown driver event: ${value.event}`);
            } catch (e) { reply = { error: String(e) }; }
            await this.send(reply);
          } else {
            const pending = this.pending; this.pending = undefined;
            if (!pending) throw new Error(`unsolicited response: ${line}`);
            if (value.ok) pending.resolve(value.value);
            else pending.reject(new Error(`${this.platform}: ${value.error}`));
          }
        }
        if (this.pending) throw new Error("driver closed stdout");
      } catch (e) {
        this.pending?.reject(new Error(`${this.platform}: ${e}\n${this.stderr}`)); this.pending = undefined;
      }
    })();
    this.config = { op: "init", root: this.root, homes: this.world.homes, history: this.world.history, ...(extra ? { extra } : {}), ...more };
    return this.call("init", this.config);
  }
  private async send(value: unknown) {
    this.child!.stdin.write(JSON.stringify(value) + "\n"); await this.child!.stdin.flush();
  }
  async call(op: string, args: Record<string, unknown> = {}): Promise<any> {
    if (this.pending) throw new Error("concurrent commands on one device");
    const response = new Promise<any>((resolve, reject) => { this.pending = { resolve, reject }; });
    await this.send({ ...args, op });
    return within(response, 60_000, `${this.platform} ${op}`).catch(e => {
      throw new Error(`${e}\nstderr: ${this.stderr}`);
    });
  }
  killOwned() { this.child?.kill(9); }
  async close() {
    if (!this.child) return;
    const child = this.child; child.stdin.end();
    try { await within(child.exited, 5000, "driver exit"); }
    catch { child.kill(9); await child.exited; }
    await this.output; await this.errors; this.child = undefined;
  }
  async reopen() {
    await this.close();
    await this.start();
    return this.call("restore");
  }
}

/** Bun owns the real relays. It never decides protocol outcomes or synthesizes authority. */
export class World {
  homes: Home[] = [];
  devices: Device[] = [];
  private relays: Subprocess[] = [];
  private drains: Promise<unknown>[] = [];
  private account?: string;
  private provisioning?: Promise<void>;
  private root = "";
  private closing?: Promise<void>;
  /** `grant`: the first relay's door provisions by a grant (gate "grant", relay/README.md) for the account's slot as its
   *  operator slot, with this audience and slot prefix. */
  constructor(readonly history: "members" | "public", readonly count: number, readonly grant?: { audience: string; prefix: string }) {}
  /** The first relay's door (`POST /v1/provision`) on loopback. */
  get door(): string { return this.homes[0]!.local.replace(/\/v1\/libraries\/home$/, "/v1/provision"); }
  async init() {
    this.root = await mkdtemp(join(process.env.COLOPHON_CROSS_RUN_DIR ?? tmpdir(), `colophon-cross-relay-${process.env.COLOPHON_CROSS_TAG ?? process.pid}-`));
    activeWorlds.add(this);
    for (let n = 0; n < this.count; n++) {
      const server = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response() });
      const port = server.port!; await server.stop(true);
      const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
      const jwk = await crypto.subtle.exportKey("jwk", key.privateKey);
      const point = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey));
      const agreement = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      this.homes.push({ base: `https://cross-home-${n}.test/v1/accounts/cross`, local: `http://127.0.0.1:${port}/v1/libraries/home`,
        secret: b64(Buffer.from(jwk.d!, "base64url")), signing: b64(point), agreement: b64(new Uint8Array(await crypto.subtle.exportKey("raw", agreement.publicKey))) });
      await writeFile(join(this.root, `key-${n}.json`), JSON.stringify(jwk), { mode: 0o600 });
    }
    return this;
  }
  device(platform: Platform, name: string) {
    const device = new Device(platform, join(this.root, name), this); this.devices.push(device); return device;
  }
  async provision(account: string) {
    if (this.account && this.account !== account) throw new Error("relay reused for another account");
    this.account = account;
    this.provisioning ??= this.startRelays(account);
    await this.provisioning;
  }
  private async startRelays(account: string) {
    for (const [n, home] of this.homes.entries()) {
      const config = join(this.root, `config-${n}.json`);
      const provision = this.grant && n === 0
        ? { provision: { enabled: true, prefix: this.grant.prefix, gate: ["grant"], operator: { account, slot: "home" }, audience: this.grant.audience } } : {};
      await writeFile(config, JSON.stringify({ resolve: Object.fromEntries(this.homes.filter(h => h !== home).map(h => [h.base, h.local])),
        limits: { requestsPerMinute: 100_000 }, ...provision }));
      const child = Bun.spawn([process.execPath, join(repo, "relay/server.js"), "--config", config], { cwd: repo,
        env: { ...process.env, COLOPHON_RELAY_PORT: new URL(home.local).port, COLOPHON_RELAY_DATA: join(this.root, `home-${n}`),
          COLOPHON_RELAY_HOME_SLOTS: `home=${account}@${home.base}`, COLOPHON_HOME_KEY_FILE: join(this.root, `key-${n}.json`),
          COLOPHON_RELAY_TICK_MS: "50", COLOPHON_RELAY_OPEN: "", COLOPHON_RELAY_TOKENS: "" }, stdout: "pipe", stderr: "pipe" });
      this.relays.push(child);
      const reader = lines(child.stdout as ReadableStream<Uint8Array>);
      let stderr = "";
      this.drains.push((async () => { for await (const b of child.stderr as ReadableStream<Uint8Array>) stderr = (stderr + Buffer.from(b).toString()).slice(-12000); })());
      const line = await within(reader.next(), 15_000, "relay startup");
      if (line.done || !JSON.parse(line.value).listening) throw new Error(`relay failed to start: ${stderr}`);
      this.drains.push((async () => { for await (const _ of reader) { /* drain relay logs */ } })());
    }
  }
  killOwned() {
    for (const device of this.devices) device.killOwned();
    for (const relay of this.relays) relay.kill(9);
    if (this.root) rmSync(this.root, { recursive: true, force: true });
  }
  close(): Promise<void> { return this.closing ??= this.closeAll(); }
  private async closeAll() {
    try { await Promise.all(this.devices.map(device => device.close())); }
    finally {
      try {
        for (const relay of this.relays) relay.kill();
        for (const relay of this.relays) {
          try { await within(relay.exited, 5000, "relay exit"); }
          catch { relay.kill(9); await relay.exited; }
        }
        await Promise.all(this.drains);
      } finally {
        await rm(this.root, { recursive: true, force: true });
        activeWorlds.delete(this);
      }
    }
  }
}

export async function settle(device: Device, ready = true) {
  let state: any;
  for (let n = 1; n <= 50; n++) {
    state = await device.call("sync");
    if (state.error) throw new Error(`${device.platform} sync lastError: ${state.error}`);
    if ((!ready || state.phase === "ready") && !state.issues.length && !state.faults.length) return { ...state, passes: n };
    await delay(100);
  }
  throw new Error(`${device.platform} did not settle: ${JSON.stringify(state)}`);
}
