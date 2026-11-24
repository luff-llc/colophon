// What `GET /healthz` checks beyond the relay answering at all. The process that runs the relay
// registers its own checks (the container entry point: its lock's heartbeat). Each check is a
// function returning `{ ok }` (and anything else it wants to say); one that throws is failing.

const checks = new Map();

/** Add a check by name. Returns a function that removes it. */
export function addHealthCheck(name, check) {
  checks.set(name, check);
  return () => { if (checks.get(name) === check) checks.delete(name); };
}

/** The names of the checks that fail now (none: healthy). */
export function failingChecks() {
  const failing = [];
  for (const [name, check] of checks) {
    let ok = false;
    try { ok = check()?.ok === true; } catch { ok = false; }
    if (!ok) failing.push(name);
  }
  return failing;
}

/** Each check's own answer, by name, for an operator's view. */
export function healthChecks() {
  const out = {};
  for (const [name, check] of checks) {
    try { out[name] = check() ?? { ok: false }; } catch (error) { out[name] = { ok: false, error: error.message }; }
  }
  return out;
}
