// Node and Bun smoke test over the wasm-bindgen 0.5 exports. It needs the glue generated with the
// wasm-bindgen CLI that matches the crate (0.2.130): see ../README.md for the exact commands and the
// tool's location. Usage: node smoke.mjs <dir with colophon_wasm.js (--target nodejs)>
//
// A web record passed BY VALUE to a call is consumed by it (the JS object is dead afterwards), so every
// call below builds its own `ListedPath[]` and `SavedState` (`listing()`, `empty()`), never reuses one.
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
const require = createRequire(import.meta.url);
// Capture the wasm instance's memory (the glue keeps it private) so the smoke can look at the heap.
let wasmMemory;
const RealInstance = WebAssembly.Instance;
WebAssembly.Instance = class extends RealInstance {
  constructor(module, imports) { super(module, imports); wasmMemory = this.exports.memory; }
};
const w = require(process.argv[2] + "/colophon_wasm.js");
WebAssembly.Instance = RealInstance;
const heapHits = (needle) => {
  const heap = Buffer.from(wasmMemory.buffer);
  let n = 0, at = heap.indexOf(needle);
  while (at !== -1) { n++; at = heap.indexOf(needle, at + 1); }
  return n;
};
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
check(engine.status().stopped === undefined, "a status that is not stopped has no stop");

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

// A caught AccountFault is a real Error with kind, code, detail and reason: a wrong ECDH answer
// is Refused with reason vaultLocked.
{
  const e2 = open(new Source());
  e2.begin_unlock_slot(0n);
  try { e2.finish_unlock_slot(0n, [new w.UnlockSecret(w.UnlockKind.Ecdh, fresh(32))]); check(false, "a wrong answer opens nothing"); }
  catch (e) {
    check(e instanceof Error && e.name === "AccountFault" && e.kind === "Refused" && e.code === "refused:vaultLocked"
      && e.reason === "vaultLocked" && typeof e.detail === "string" && e.message === e.detail,
      "an AccountFault is a real Error with kind, code, detail and reason");
  }
  try { w.account_key_id(new Uint8Array(1000)); } catch (e) { check(e.reason === undefined, "reason is undefined when the error has none"); }
  e2.free();
}
// How numbers cross: u64 and i64 are bigint and exact above 2^53; u32 is a number. A Number where a
// bigint is expected is a plain TypeError from wasm-bindgen (not an AccountFault); a negative bigint
// for a u64 wraps (wasm-bindgen's own conversion: a documented gap).
{
  const big = 9007199254740993n; // 2^53 + 1
  check(new w.NamespaceRevision("n", big).revision === big, "a u64 above 2^53 crosses exactly");
  check(new w.Receipted("h", -big).received_ms === -big, "an i64 below -2^53 crosses exactly");
  check(new w.NamespaceRevision("n", 18446744073709551615n).revision === 18446744073709551615n, "u64::MAX crosses exactly");
  try { new w.NamespaceRevision("n", 5); check(false, "a Number for a u64 is refused"); }
  catch (e) { check(e instanceof TypeError && e.kind === undefined, "a Number where a bigint is expected is a plain TypeError"); }
  check(new w.NamespaceRevision("n", -1n).revision === 18446744073709551615n, "a negative bigint for a u64 wraps (documented gap)");
}
// The zero-on-free allocator on the wasm heap: a live secret is in the heap; once freed it is zeroed.
// (The probe is the TAIL of a 64-byte secret: the system allocator writes its free-list links over the
// first bytes of a freed chunk, so only the tail shows what a plain free leaves behind. Built with
// `--no-default-features --features web05` the same program reports the tail still there.)
{
  const secret = fresh(64);
  const probe = Buffer.from(secret.slice(32));
  const live = new w.UnlockSecret(w.UnlockKind.Ecdh, secret);
  const before = heapHits(probe);
  live.free();
  const after = heapHits(probe);
  const allocatorOn = process.env.COLOPHON_ALLOCATOR_OFF !== "1";
  check(before >= 1 && (allocatorOn ? after === 0 : after >= 1),
    `a secret is in the wasm heap while held (${before}) and ${allocatorOn ? "zero" : "still there (allocator off)"} once freed (${after})`);
}
// lock, then a typed Locked refusal, with `reason` on the error as on the native one.
engine.lock();
try { engine.save(fresh(32)); check(false, "a locked engine saves"); }
catch (e) { check(e.kind === "Locked" && e.code === "locked", "a locked engine refuses with kind Locked"); }
engine.free(); // free every object you are done with: the finalizer's timing is not yours to rely on
console.log(failures === 0 ? "ALL PASS" : `${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
