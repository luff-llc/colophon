// Node smoke test over the wasm-bindgen 0.5 exports. NOT RUN (in the fix round that added it, nor in
// B2): the installed wasm-bindgen CLI (0.2.127) refuses the crate's 0.2.130 schema, so the glue cannot
// be generated here. It runs as soon as the CLI matches (see ../README.md).
// Usage: node smoke.mjs <dir with colophon_wasm.js (--target nodejs)>
//
// A web record passed BY VALUE to a call is consumed by it (the JS object is dead afterwards), so every
// call below builds its own `ListedPath[]` and `SavedState` (`listing()`, `empty()`), never reuses one.
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
const controller = () => new w.ControllerSpec(
  new w.KeyDescriptorView(w.SignForm.Raw, mac.signing, mac.agreement, undefined, undefined, [], []),
  "Mac", [w.ControllerRole.Approve, w.ControllerRole.Control], false, undefined, []);
const who = () => new w.AccountIdentity(w.AccountIdentityKind.Controller, id);
const params = new w.CreateParams("JS smoke", ["notes"], [controller()], [new w.SlotPlan([id], "Mac")], undefined, undefined, undefined, false, "", [id], [id]);
const now = BigInt(Date.now());
const creation = w.AccountCreation.begin(params, who(), now, fresh(96));
const signAll = async (steps) => Promise.all(steps.map(async (s) =>
  new w.Signature(new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, mac.sign.privateKey, s.body)), undefined, undefined)));
for (;;) { // the signatures list is consumed by each call: build it per round
  if (creation.provide_signatures(await signAll(creation.steps())) === w.CreateStage.Done) break;
}
const created = creation.take_result();
check(created.account.length === 64, "account id");

const files = new Map(created.stores.map((s) => [s.path, s.bytes]));
// The host source: SYNCHRONOUS, returns a Uint8Array (a Promise, undefined or an Array is a Host error).
class Source {
  read(path) { const b = files.get(path); if (!b) throw new Error("missing " + path); return b; }
  readBlob(path) { return files.get(path) ?? new Uint8Array(0); }
}
const listing = () => [...files.keys()].sort().map((p) => new w.ListedPath(p, undefined));
const empty = () => new w.SavedState(new Uint8Array(0), new Uint8Array(0), []);
const open = (src, who_ = who()) => w.AccountEngine.open(src, listing(), who_, created.account, [], 0n, empty(), fresh(32), now);
const engine = open(new Source());
check(engine.open_info().mode === w.OpenMode.Cold, "engine over a JS source");
check(engine.identity().kind === w.AccountIdentityKind.Controller && engine.identity().id === id, "the identity is a record");

// An unlock from the host's ECDH result, then begin_* and finish, then a replay refused as Consumed.
const slot = engine.slots()[0];
check(slot.kind === w.SlotKind.Sealed, "the slot kind is an enum");
const inputs = engine.begin_unlock_slot(slot.index);
const peer = await webcrypto.subtle.importKey("raw", inputs[0].enc, { name: "ECDH", namedCurve: "P-256" }, false, []);
const shared = new Uint8Array(await webcrypto.subtle.deriveBits({ name: "ECDH", public: peer }, mac.agree.privateKey, 256));
engine.finish_unlock_slot(slot.index, [new w.UnlockSecret(w.UnlockKind.Ecdh, shared)]);
check(engine.is_unlocked(), "unlocked from the host's ECDH result");
const action = engine.begin_rekey(["notes"], [id], fresh(32));
check(action.kind() === w.ActionKind.Rekey, "the action's kind is an enum");
const sigs = await signAll(action.steps());
engine.finish(action, sigs);
try { engine.finish(action, await signAll([])); check(false, "replay refused"); }
catch (e) { check(e.kind === "Consumed", "a replay is refused as Consumed (the action is passed by reference; the first finish used it up)"); }

// A callback that does not return a Uint8Array is a Host error that names the callback.
for (const [what, bad] of [["a Promise", Promise.resolve(new Uint8Array(1))], ["undefined", undefined], ["an Array", [1, 2]]]) {
  try {
    open({ read() { return bad; }, readBlob() { return new Uint8Array(0); } });
    check(false, `${what} from read refused`);
  } catch (e) { check(e.kind === "Host" && e.detail.includes("JsSource.read"), `${what} returned by read is a Host error naming JsSource.read`); }
}
try {
  open({ read() { throw new Error("boom"); }, readBlob() { return new Uint8Array(0); } });
  check(false, "throwing source refused");
} catch (e) { check(e instanceof Error && e.kind === "Host" && e.detail.includes("boom"), "a JS source that throws arrives as Host with its message"); }

// lock, then a typed Locked refusal, with `reason` on the error as on the native one.
engine.lock();
try { engine.save(fresh(32)); check(false, "a locked engine saves"); }
catch (e) { check(e.kind === "Locked" && e.code === "locked", "a locked engine refuses with kind Locked"); }
engine.free(); // free every object you are done with: the finalizer's timing is not yours to rely on
console.log(failures === 0 ? "ALL PASS" : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
