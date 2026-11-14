// Node smoke test over the wasm-bindgen 0.5 exports. NOT RUN in the fix round that added it: the
// installed wasm-bindgen CLI (0.2.127) refuses the crate's 0.2.130 schema. It runs as soon as the
// CLI matches (see ../README.md). Usage: node smoke.mjs <dir with colophon_wasm.js (--target nodejs)>
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
const require = createRequire(import.meta.url);
const w = require(process.argv[2] + "/colophon_wasm.js");
let failures = 0;
const check = (ok, what) => { console.log((ok ? "PASS " : "FAIL ") + what); if (!ok) failures++; };
const fresh = (n) => webcrypto.getRandomValues(new Uint8Array(n));
const b64 = (u8) => Buffer.from(u8).toString("base64");
async function p256() {
  const k = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const d = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  return { sign: k, agree: d,
    signing: new Uint8Array(await webcrypto.subtle.exportKey("raw", k.publicKey)),
    agreement: new Uint8Array(await webcrypto.subtle.exportKey("raw", d.publicKey)) };
}
const toRaw = (der) => der; // WebCrypto returns r||s (P1363) already.

// A typed error is a real Error with kind, code and detail.
try { w.account_key_id(new Uint8Array(1000)); check(false, "oversized point refused"); }
catch (e) { check(e instanceof Error && e.kind === "Bound" && e.code === "bound", "a bound error is an Error with kind and code"); }

const mac = await p256();
const id = w.account_key_id(mac.signing);
const controller = JSON.stringify({ key: { form: "raw", signing: b64(mac.signing), agreement: b64(mac.agreement) }, label: "Mac", roles: ["approve", "control"] });
const params = new w.CreateParams("JS smoke", ["notes"], [controller], [new w.SlotPlan([id], "Mac")], undefined, undefined, undefined, false, "", [id], [id]);
const now = BigInt(Date.now());
const creation = w.AccountCreation.begin(params, `controller:${id}`, now, fresh(96));
const signAll = async (steps) => Promise.all(steps.map(async (s) =>
  new w.Signature(new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mac.sign.privateKey, s.body)), undefined, undefined)));
while (creation.provide_signatures(await signAll(creation.steps())) !== w.CreateStage.Done) {}
const created = creation.take_result();
check(created.account.length === 64, "account id");

const files = new Map(created.stores.map((s) => [s.path, s.bytes]));
class Source {
  read(path) { const b = files.get(path); if (!b) throw new Error("missing " + path); return b; }
  readBlob(path) { return files.get(path) ?? new Uint8Array(0); }
}
const listing = [...files.keys()].sort().map((p) => new w.ListedPath(p, ""));
const empty = new w.SavedState(new Uint8Array(0), new Uint8Array(0), []);
const engine = w.AccountEngine.open(new Source(), listing, `controller:${id}`, created.account, [], 0n, empty, fresh(32), now);
check(engine.open_info().mode === w.OpenMode.Cold, "engine over a JS source");
try {
  w.AccountEngine.open({ read() { throw new Error("boom"); }, readBlob() { return new Uint8Array(0); } }, listing, `controller:${id}`, created.account, [], 0n, empty, fresh(32), now);
  check(false, "throwing source refused");
} catch (e) { check(e instanceof Error && e.kind === "Host" && e.detail.includes("boom"), "a JS source that throws arrives as Host with its message"); }
console.log(failures === 0 ? "ALL PASS" : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
