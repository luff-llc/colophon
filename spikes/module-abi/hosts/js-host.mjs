// Import-free WebAssembly host shared verbatim by Bun and a real browser.
// ABI glue deliberately does not canonicalize or modify the guest's JSON bytes.
const encoder = new TextEncoder();
const MAX = 16 * 1024 * 1024;
export const cases = [1, 1000, 10000];
export function firstDifference(expected, actual) {
  for (let i = 0; i < Math.min(expected.length, actual.length); i++) {
    if (expected[i] !== actual[i]) return {offset: i, expectedByte: expected[i], actualByte: actual[i]};
  }
  return expected.length === actual.length ? null : {
    offset: Math.min(expected.length, actual.length),
    expectedLength: expected.length, actualLength: actual.length
  };
}
export function operationsFromText(text) {
  return text.trimEnd().split("\n").map(line => encoder.encode(line));
}
export async function compiledModule(bytes) {
  const begun = performance.now();
  const module = await WebAssembly.compile(bytes);
  const compileMs = performance.now() - begun;
  const imports = WebAssembly.Module.imports(module);
  if (imports.length) throw new Error("module imports are forbidden: " + JSON.stringify(imports));
  return {module, compileMs};
}
export function guest(instance) {
  const x = instance.exports;
  for (const name of ["memory", "alloc", "release", "initial", "apply", "query"]) {
    if (!x[name]) throw new Error("Missing guest export " + name);
  }
  function unpack(raw) {
    if (typeof raw !== "bigint" || raw === 0n) throw new Error("Guest returned null/error pointer");
    const ptr = Number(raw & 0xffffffffn);
    const len = Number(raw >> 32n);
    if (len > MAX || len < 1 || ptr + len > x.memory.buffer.byteLength) {
      throw new Error("Guest result out of bounds: " + ptr + "/" + len);
    }
    const result = Uint8Array.from(new Uint8Array(x.memory.buffer, ptr, len));
    x.release(ptr, len);
    return result;
  }
  function call(fn, args = []) {
    const parts = [];
    try {
      for (const bytes of args) {
        if (bytes.length > MAX) throw new Error("Host input exceeds 16 MiB");
        const ptr = x.alloc(bytes.length) >>> 0;
        if (!ptr || ptr + bytes.length > x.memory.buffer.byteLength) throw new Error("Guest allocation failed");
        new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
        parts.push([ptr, bytes.length]);
      }
      return unpack(fn(...parts.flat()));
    } finally {
      for (const [ptr, len] of parts) x.release(ptr, len);
    }
  }
  return {
    x,
    initial: () => unpack(x.initial()),
    apply: (state, op) => call(x.apply, [state, op]),
    query: (state, name, args) => call(x.query, [state, encoder.encode(name), encoder.encode(args)]),
  };
}
export async function runCase(compiled, operations, count, expected, expectedQuery) {
  const before = performance.now();
  const instance = await WebAssembly.instantiate(compiled.module, {});
  const instantiateMs = performance.now() - before;
  const g = guest(instance);
  let state = g.initial();
  const started = performance.now();
  let peakLinearMemoryBytes = g.x.memory.buffer.byteLength;
  for (let i = 0; i < count; i++) {
    state = g.apply(state, operations[i]);
    if ((i & 127) === 0) peakLinearMemoryBytes = Math.max(peakLinearMemoryBytes, g.x.memory.buffer.byteLength);
  }
  const applyMs = performance.now() - started;
  peakLinearMemoryBytes = Math.max(peakLinearMemoryBytes, g.x.memory.buffer.byteLength);
  const query = g.query(state, "noteCounts", "{}");
  const stateDiff = firstDifference(expected, state);
  const queryDiff = firstDifference(expectedQuery, query);
  return {
    host: "javascript-webassembly",
    operations: count, compile_ms: compiled.compileMs,
    instantiate_ms: instantiateMs, apply_ms: applyMs, ms_per_op: applyMs/count,
    state_bytes: state.length, peak_linear_memory_bytes: peakLinearMemoryBytes,
    rss_snapshot_bytes: null, state_first_difference: stateDiff, query_first_difference: queryDiff,
    byte_equal: stateDiff === null && queryDiff === null
  };
}
// The rewritten module charges one unit at each function and loop entry.
// This precisely measures *that* instrumenter's threshold, not CPU instructions.
export async function probeMetering(compiled, operation) {
  async function tryBudget(budget) {
    const instance = await WebAssembly.instantiate(compiled.module, {});
    const x = instance.exports, g = guest(instance);
    if (!x.fuel_reset || !x.fuel_left) throw new Error("Not an instrumented module");
    x.fuel_reset(1000000000n);
    const state = g.initial();
    const statePtr = x.alloc(state.length) >>> 0;
    const opPtr = x.alloc(operation.length) >>> 0;
    new Uint8Array(x.memory.buffer, statePtr, state.length).set(state);
    new Uint8Array(x.memory.buffer, opPtr, operation.length).set(operation);
    x.fuel_reset(BigInt(budget));
    try {
      const raw = x.apply(statePtr, state.length, opPtr, operation.length);
      if (raw === 0n) throw new Error("Guest refused operation");
      const left = Number(x.fuel_left());
      return {ok: true, left};
    } catch (error) {
      return {ok: false, left: Number(x.fuel_left()), error: String(error)};
    }
    // On a trap the instance is discarded; no unsafe attempt to resume it.
  }
  let high = 1;
  let highResult = await tryBudget(high);
  while (!highResult.ok && high < 1_000_000_000) {
    high *= 2;
    highResult = await tryBudget(high);
  }
  if (!highResult.ok) return {passed: false, budget_ceiling: high, error: highResult.error};
  let low = 0;
  while (high - low > 1) {
    const mid = Math.floor((high + low)/2);
    if ((await tryBudget(mid)).ok) high = mid;
    else low = mid;
  }
  const succeeds = await tryBudget(high);
  const fails = await tryBudget(high-1);
  return {
    passed: succeeds.ok && !fails.ok, min_success_budget: high,
    failed_budget: high-1, remaining_at_success: succeeds.left,
    remaining_at_failure: fails.left, failure: fails.error,
    charges_for_apply: high - succeeds.left
  };
}
