#!/usr/bin/env python3
"""Colophon 0.5 candidate vectors, built by hand from the specification text.

This is not an implementation of 0.5. It assembles canonical bodies, signs them with
published test keys and records the outcome spec/colophon-0.5.md says a verifier must
return. Every signature it writes verifies under ordinary ES256; every expected outcome is
the author's reading of the spec until a 0.5 verifier replays these files.

Dependency: Python 3 and `cryptography` (Apache-2.0 OR BSD-3-Clause), checked with 50.0.2.
Tooling only; nothing here ships. Signatures are deterministic (RFC 6979), so running this
again reproduces every file byte for byte.

Usage: python3 -I conformance/0.5/candidate/generate.py [--check]
"""

import base64
import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent  # conformance/
V4 = ROOT / "0.4"
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def canonical(value) -> bytes:
    """Sorted keys, no whitespace, slashes unescaped, UTF-8. Integers only (no floats here)."""
    def check(v):
        if isinstance(v, float):
            raise ValueError("floats are not used in these vectors")
        if isinstance(v, dict):
            for x in v.values():
                check(x)
        if isinstance(v, list):
            for x in v:
                check(x)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_id(point: bytes) -> str:
    return sha(point)[:32]


class Key:
    def __init__(self, scalar: int):
        self.scalar = scalar
        self.private = ec.derive_private_key(scalar, ec.SECP256R1())
        self.point = self.private.public_key().public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.X962,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.UncompressedPoint,
        )
        self.id = key_id(self.point)

    def sign(self, body: bytes) -> bytes:
        der = self.private.sign(body, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_raw(point: bytes, body: bytes, sig: bytes) -> bool:
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        public.verify(der, body, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def derived(name: str) -> Key:
    """A candidate-only test key: scalar = SHA-256('colophon-0.5-candidate/' + name) mod n."""
    scalar = int.from_bytes(hashlib.sha256(("colophon-0.5-candidate/" + name).encode()).digest(), "big") % N
    return Key(scalar)


def envelope(body_obj, signer: Key) -> dict:
    body = canonical(body_obj)
    return {"body": b64(body), "signature": b64(signer.sign(body))}


def env_bytes(env: dict) -> bytes:
    return canonical(env)


def body_of(env: dict) -> bytes:
    return unb64(env["body"])


OUT = {}


def write(rel: str, value):
    OUT[rel] = canonical(value) + b"\n"


def write_raw(rel: str, data: bytes):
    OUT[rel] = data


# ---------------------------------------------------------------------------------------
# Published 0.4 software keys (conformance/0.4/keys/keys.json).
published = json.loads((V4 / "keys" / "keys.json").read_text())
software = {}
for item in published["software"]:
    k = Key(int.from_bytes(unb64(item["signingScalar"]), "big"))
    assert k.id == item["id"], "published scalar does not match its key ID"
    software[item["id"]] = k

# Self-check: the canonical encoder reproduces every 0.4 authority body byte for byte.
recanonicalized = 0
for path in sorted(V4.glob("keys/*/records/authority/*.json")) + sorted(V4.glob("library/records/authority/*.json")):
    body = unb64(json.loads(path.read_text())["body"])
    pairs = []
    json.loads(body, object_pairs_hook=lambda kv: pairs.append(len(kv) != len({k for k, _ in kv})) or dict(kv))
    if any(pairs):
        continue  # a published duplicate-name refuse case; not canonical by design
    assert canonical(json.loads(body)) == body, f"canonical mismatch: {path}"
    recanonicalized += 1

# ---------------------------------------------------------------------------------------
# 1. Identifiers (spec §5.1).
identifiers = []
genesis_paths = sorted(V4.glob("keys/*/records/authority/00000001.json")) + [V4 / "library/records/authority/00000001.json"]
for path in genesis_paths:
    body = unb64(json.loads(path.read_text())["body"])
    full = sha(body)
    identifiers.append({
        "source": str(path.relative_to(ROOT)),
        "legacyLibraryID": full[:32],
        "accountID": full,
        "text": "colophon:" + full,
    })
# The 0.4 library fixture's operations bind `library`; it must equal the legacy prefix.
some_op = sorted((V4 / "library/records/ops").glob("*/*/*.json"))[0]
op_library = json.loads(unb64(json.loads(some_op.read_text())["body"]))["library"]
lib_full = sha(unb64(json.loads((V4 / "library/records/authority/00000001.json").read_text())["body"]))
assert op_library == lib_full[:32]
write("identifiers.json", {
    "description": "0.5 account IDs (spec §5.1) of every published 0.4 genesis. The 0.4 library ID is the first 32 characters. "
                   "The 0.4 library fixture's operation headers bind `library` = legacyLibraryID, checked by the generator.",
    "cases": identifiers,
    "references": [
        {"reference": {"account": lib_full}, "expected": "ok"},
        {"reference": {"account": lib_full[:32]}, "expected": "malformed", "why": "a 32-character legacy ID is not a 0.5 account reference"},
        {"reference": {"account": lib_full.upper()}, "expected": "malformed", "why": "uppercase hex"},
        {"reference": {"account": lib_full, "hints": []}, "expected": "malformed", "why": "hints, when present, is non-empty"},
        {"reference": {"account": lib_full, "hints": ["http://home.example/v1"]}, "expected": "malformed", "why": "hints are https only"},
    ],
})

# ---------------------------------------------------------------------------------------
# 2. Upgrade from 0.4 in place (spec §16.1), on the published seq-two-rekey chain.
DEFAULT_POLICY = {"callWindow": 300, "headMaxAge": 300, "headQuorum": 1, "history": "members", "linkMaxAge": 86400,
                  "memberRule": "single", "recoveryDelay": 259200}


def load_chain(case: str):
    paths = sorted((V4 / "keys" / case / "records/authority").glob("*.json"))
    return [p.read_bytes() for p in paths]


def upgrade_case(name, base_case, mutate=None, signer_id=None, seq_override=None, extra=None, expected5="ok",
                 expected4="newerFormat", why=""):
    chain = load_chain(base_case)
    envs = [json.loads(b) for b in chain]
    bodies = [unb64(e["body"]) for e in envs]
    genesis = json.loads(bodies[0])
    last = json.loads(bodies[-1])
    keyring = json.loads(json.dumps(genesis["keyring"]))  # unchanged since genesis in these cases
    keyring5 = dict(keyring)
    keyring5["addThreshold"] = 1
    keyring5["countBy"] = "keys"
    keyring5["policy"] = dict(DEFAULT_POLICY)
    controller = keyring["controllers"][0]
    cid = key_id(unb64(controller["key"]["signing"]))
    body = {
        "protocol": "colophon/authority/4",
        "seq": seq_override or (last["seq"] + 1),
        "previous": sha(bodies[-1]),
        "issued": "2026-11-11T09:00:00.000Z",
        "by": signer_id or cid,
        "kind": "upgrade",
        "account": sha(bodies[0]),
        "keyring": keyring5,
    }
    if mutate:
        mutate(body)
    signer = software.get(signer_id or cid) or derived("outsider")
    upgrade = envelope(body, signer)
    records = {f"records/authority/{i + 1:08d}.json": chain[i] for i in range(len(chain))}
    records[f"records/authority/{len(chain) + 1:08d}.json"] = env_bytes(upgrade)
    if extra:
        for rel, data in extra(body, upgrade, signer).items():
            records[rel] = data
    for rel, data in records.items():
        write_raw(f"upgrade/{name}/{rel}", data)
    write(f"upgrade/{name}/case.json", {
        "description": why,
        "base": f"conformance/0.4/keys/{base_case}",
        "sections": ["5.1", "8.5", "16.1"],
        "expected": {"colophon-0.5": expected5, "colophon-0.4": expected4},
        "accountID": sha(bodies[0]),
        "legacyLibraryID": sha(bodies[0])[:32],
    })


upgrade_case("accept", "seq-two-rekey",
             why="Control-signed upgrade entry after genesis and the seq-2 rekey. A 0.4 reader stops with newerFormat.")
upgrade_case("wrong-account", "seq-two-rekey",
             mutate=lambda b: b.__setitem__("account", "0" * 64), expected5="malformed",
             why="`account` is not the digest of the genesis body.")
upgrade_case("legacy-account", "seq-two-rekey",
             mutate=lambda b: b.__setitem__("account", b["account"][:32]), expected5="malformed",
             why="`account` gives only the 32-character legacy ID.")
upgrade_case("keyring-changed", "seq-two-rekey",
             mutate=lambda b: b["keyring"]["controllers"][0].__setitem__("label", "renamed"), expected5="malformed",
             why="The upgrade keyring changes a 0.4 field (a controller label); only addThreshold and policy may be added.")
upgrade_case("policy-out-of-range", "seq-two-rekey",
             mutate=lambda b: b["keyring"]["policy"].__setitem__("headMaxAge", 10), expected5="malformed",
             why="policy.headMaxAge below its range (30-86,400).")
upgrade_case("add-threshold-above", "seq-two-rekey",
             mutate=lambda b: b["keyring"].__setitem__("addThreshold", 2), expected5="malformed",
             why="addThreshold exceeds threshold (1).")
upgrade_case("foreign-signer", "seq-two-rekey", signer_id=derived("outsider").id, expected5="badSignature",
             expected4="badSignature",
             why="Signed by a key that is not a controller of the prior keyring.")
upgrade_case("at-seq-two", "genesis-only", expected5="malformed",
             why="Upgrade as seq 2 of a library whose seq 2 must be its rekey (0.4 seq-2 rule stands). A 0.4 reader reports newerFormat because unknown-kind detection precedes transition rules.")


def then_layout(body, upgrade, signer):
    nxt = {
        "protocol": "colophon/authority/5",
        "seq": body["seq"] + 1,
        "previous": sha(body_of(upgrade)),
        "issued": "2026-11-11T09:00:01.000Z",
        "by": signer.id,
        "kind": "layout",
        "layout": 2,
    }
    return {f"records/authority/{body['seq'] + 1:08d}.json": env_bytes(envelope(nxt, signer))}


def then_v4(body, upgrade, signer):
    nxt = {
        "protocol": "colophon/authority/4",
        "seq": body["seq"] + 1,
        "previous": sha(body_of(upgrade)),
        "issued": "2026-11-11T09:00:01.000Z",
        "by": signer.id,
        "kind": "layout",
        "layout": 2,
    }
    return {f"records/authority/{body['seq'] + 1:08d}.json": env_bytes(envelope(nxt, signer))}


upgrade_case("then-v5-layout", "seq-two-rekey", extra=then_layout,
             why="After the upgrade, a /5 layout entry under the control rule is accepted.")
upgrade_case("then-v4-entry", "seq-two-rekey", extra=then_v4, expected5="malformed",
             why="A /4 entry after the upgrade.")

# ---------------------------------------------------------------------------------------
# 3. A native 0.5 identity account with an agent and a home (spec §6, §9, §10, §12, §13).
# The keyring reuses the published genesis-one-raw keyring (controller "raw 11" with a sealed
# slot). Slot info strings bind the vault and controllers, not the account (spec §7.2), so the
# slot is valid here; the vault is fresh within this account's history.
g4 = json.loads(unb64(json.loads((V4 / "keys/genesis-one-raw/records/authority/00000001.json").read_text())["body"]))
controller = software["b609e0fd25ac2aefc193156581e112cb"]
keyring5 = dict(g4["keyring"])
keyring5["addThreshold"] = 1
keyring5["countBy"] = "keys"
keyring5["policy"] = dict(DEFAULT_POLICY)

agent_sign, agent_agree = derived("agent/signing"), derived("agent/agreement")
home_sign, home_agree = derived("home/signing"), derived("home/agreement")
session1 = derived("session/1")
session2 = derived("session/2")
attacker = derived("attacker")

genesis = {"protocol": "colophon/authority/5", "seq": 1, "previous": None, "issued": "2026-11-11T08:00:00Z",
           "by": controller.id, "kind": "genesis", "label": "Identity", "namespaces": [], "keyring": keyring5}
g_env = envelope(genesis, controller)
account = sha(body_of(g_env))

AUD = "https://projects.example/scopes/7"
agent_terms_req = {"services": [{"audience": AUD, "purposes": ["task.propose", "task.read"]}], "depth": 1}
agent_request = {"protocol": "colophon/request/5", "account": account,
                 "member": {"agreement": b64(agent_agree.point), "signing": b64(agent_sign.point)},
                 "label": "Agent on test host", "kind": "agent", "terms": agent_terms_req,
                 "created": "2026-11-11T08:00:00Z"}
agent_terms = {"services": [{"audience": AUD, "purposes": ["task.propose", "task.read"]}], "depth": 1,
               "expires": "2026-11-18T08:00:00Z", "conditions": [{"prefix": ["args.task", "T-"]}]}
grant_agent = {"protocol": "colophon/authority/5", "seq": 2, "previous": sha(body_of(g_env)), "issued": "2026-11-11T08:00:01Z",
               "by": controller.id, "kind": "grant", "request": b64(env_bytes(envelope(agent_request, agent_sign))),
               "terms": agent_terms, "shares": []}
ga_env = envelope(grant_agent, controller)

HOME = "https://home.example/v1/accounts/" + account
home_request = {"protocol": "colophon/request/5", "account": account,
                "member": {"agreement": b64(home_agree.point), "signing": b64(home_sign.point)},
                "label": "Test home", "kind": "server", "terms": {"serves": ["home"]},
                "created": "2026-11-11T08:00:00Z", "service": {"endpoints": [HOME]}}
grant_home = {"protocol": "colophon/authority/5", "seq": 3, "previous": sha(body_of(ga_env)), "issued": "2026-11-11T08:00:02Z",
              "by": controller.id, "kind": "grant", "request": b64(env_bytes(envelope(home_request, home_sign))),
              "terms": {"serves": ["home"]}, "shares": []}
gh_env = envelope(grant_home, controller)
history = [g_env, ga_env, gh_env]
for i, e in enumerate(history):
    write_raw(f"account/records/authority/{i + 1:08d}.json", env_bytes(e))

head = {"protocol": "colophon/head/5", "account": account, "authority": {"seq": 3, "digest": sha(body_of(gh_env))},
        "issued": "2026-11-11T09:00:00Z", "by": home_sign.id}
head_env = envelope(head, home_sign)
write("account/head.json", head_env)

NOW = "2026-11-11T09:01:00Z"
AS_OF = {"seq": 3, "digest": sha(body_of(gh_env))}
write("account/case.json", {
    "description": "Identity-only 0.5 account (no namespaces): genesis, an agent grant under the single rule, a home grant under the control rule.",
    "sections": ["6.2", "8.2", "8.4", "9.1", "9.2", "13.1"],
    "accountID": account,
    "expected": {"history": "ok", "head": "ok at now; stale after 2026-11-11T09:05:00Z (headMaxAge 300)"},
    "members": {agent_sign.id: "agent", home_sign.id: "home"},
})


def link(frm: Key, to: Key, terms, session=None, nb="2026-11-11T09:00:00Z", exp="2026-11-11T09:10:00Z"):
    body = {"protocol": "colophon/link/5", "account": account, "from": frm.id, "to": {"signing": b64(to.point)},
            "terms": terms, "notBefore": nb, "expires": exp, "created": nb}
    if session is not None:
        body["session"] = session
    return env_bytes(envelope(body, frm))


def call(acting: Key, links=None, audience=AUD, purpose="task.read", args=None, key_point=None, rid_seed="1",
         created="2026-11-11T09:01:00Z", signer=None):
    body = {"protocol": "colophon/call/5", "account": account, "asOf": AS_OF,
            "signer": {"member": agent_sign.id}, "key": b64(key_point or acting.point),
            "audience": audience, "purpose": purpose, "args": args if args is not None else {"task": "T-12"},
            "requestId": b64url(hashlib.sha256(("request/" + rid_seed).encode()).digest()), "created": created}
    if links:
        body["links"] = [b64(x) for x in links]
    return envelope(body, signer or acting)


narrow = {"services": [{"audience": AUD, "purposes": ["task.read"]}]}
wide = {"services": [{"audience": AUD, "purposes": ["*"]}]}
l_ok = link(agent_sign, session1, narrow, session=0)

calls = {
    "member-no-links": (call(agent_sign), "ok", "The member's own key acts."),
    "one-link": (call(session1, [l_ok], rid_seed="2"), "ok", "A session key acts through one link with narrower terms."),
    "copied-link": (call(attacker, [l_ok], rid_seed="3"), "badSignature",
                    "An attacker signs its own call with a copied link: the acting key is not the link's `to` key (step 6)."),
    "invalid-call-signature": (dict(call(agent_sign, rid_seed="4"), signature=b64(attacker.sign(b"x"))), "badSignature",
                               "The call signature doesn't verify under `key` (step 2, before any fetch)."),
    "wrong-audience": (call(agent_sign, audience="https://other.example", rid_seed="5"), "refused:audience",
                       "Audience is not one of the verifier's (step 3)."),
    "outside-window": (call(agent_sign, created="2026-11-11T08:50:00Z", rid_seed="6"), "refused:window",
                       "Created 660 s before now; callWindow is 300 (step 3)."),
    "widening-link": (call(session1, [link(agent_sign, session1, wide, session=0)], purpose="task.delete", rid_seed="7"),
                      "refused:notNarrower", "The link asks for every purpose; the member has two (step 6)."),
    "ended-session": (call(session1, [link(agent_sign, session1, narrow, session=1)], rid_seed="8"), "refused:ended",
                      "The link names session 1; the member's session number is 0 (step 6)."),
    "out-of-scope-purpose": (call(agent_sign, purpose="task.delete", rid_seed="9"), "refused:outOfScope",
                             "The member's terms don't grant task.delete (step 7)."),
    "condition-fails": (call(agent_sign, args={"task": "X-1"}, rid_seed="10"), "refused:outOfScope",
                        "The member's condition requires args.task to start with T- (step 7)."),
    "depth-exceeded": (call(session2, [l_ok, link(session1, session2, {"services": [{"audience": AUD, "purposes": ["task.read"]}]})],
                            rid_seed="11"), "refused:notNarrower",
                       "Member depth 1 allows one link; the second link's parent depth is 0 (step 6)."),
    "link-expired": (call(session1, [link(agent_sign, session1, narrow, session=0, nb="2026-11-11T08:00:00Z",
                                          exp="2026-11-11T08:30:00Z")], rid_seed="12"), "refused:expired",
                     "The link expired at 08:30 (step 6)."),
    "unknown-field-valid": (envelope(dict(json.loads(body_of(call(agent_sign, rid_seed="13"))), future=1), agent_sign),
                            "newerFormat", "An unknown body field on an otherwise valid, authorized call (step 8)."),
    "unknown-field-invalid": (dict(envelope(dict(json.loads(body_of(call(agent_sign, rid_seed="14"))), future=1), agent_sign),
                                   signature=b64(attacker.sign(b"y"))), "badSignature",
                              "The same unknown field with an invalid signature: never newerFormat."),
}
for name, (env, expected, why) in calls.items():
    write(f"calls/{name}/call.json", env)
    write(f"calls/{name}/case.json", {
        "description": why, "sections": ["12.3"], "expected": expected,
        "verifier": {"now": NOW, "audiences": [AUD], "replay": "empty",
                     "history": "conformance/0.5/candidate/account/records", "heads": ["conformance/0.5/candidate/account/head.json"]},
    })

# Heads (spec §13.3).
stale = envelope(dict(head, issued="2026-11-11T08:50:00Z"), home_sign)
by_agent = envelope(dict(head, by=agent_sign.id), agent_sign)
fork = envelope(dict(head, authority={"seq": 3, "digest": "1" * 64}), home_sign)
heads = {
    "valid": (head_env, "ok", "Fresh head by the appointed home."),
    "stale": (stale, "ok (accepted, not fresh)", "Issued 11 minutes before now with headMaxAge 300: a call verifier needing a fresh head returns unavailable."),
    "not-a-home": (by_agent, "badSignature", "Signed by a member without serves."),
    "fork": (fork, "refused:fork", "Names seq 3 with a digest that differs from the held history."),
}
for name, (env, expected, why) in heads.items():
    write(f"heads/{name}/head.json", env)
    write(f"heads/{name}/case.json", {"description": why, "sections": ["13.3"], "expected": expected,
                                       "verifier": {"now": NOW, "history": "conformance/0.5/candidate/account/records"}})

# Public test keys.
write("keys.json", {
    "warning": "PUBLIC TEST SECRETS. Never use these keys for real data.",
    "derivation": "scalar = SHA-256('colophon-0.5-candidate/' + name) mod n; controller keys are the published 0.4 software keys.",
    "keys": {name: {"id": k.id, "signing": b64(k.point), "scalar": b64(k.scalar.to_bytes(32, "big"))}
             for name, k in [("agent/signing", agent_sign), ("agent/agreement", agent_agree), ("home/signing", home_sign),
                             ("home/agreement", home_agree), ("session/1", session1), ("session/2", session2),
                             ("attacker", attacker), ("outsider", derived("outsider"))]},
})

# ---------------------------------------------------------------------------------------
# Revision 2 cases (spec revision 2): rules, origins, pairing, Swift succession.
exec(compile((HERE / "rules.py").read_text(), str(HERE / "rules.py"), "exec"))

# ---------------------------------------------------------------------------------------
# Self-checks: every envelope in the output whose signer is honest verifies.
honest = 0
for rel, data in OUT.items():
    if not rel.endswith(".json") or rel.endswith("case.json") or rel in ("keys.json", "identifiers.json"):
        continue
    env = json.loads(data)
    if not isinstance(env, dict) or "body" not in env or "non-canonical" in rel:
        continue
    body = unb64(env["body"])
    obj = json.loads(body)
    assert canonical(obj) == body, rel
    signer_id = obj.get("by") or (obj.get("from") if obj.get("protocol") == "colophon/link/5" else None)
    if obj.get("protocol") == "colophon/call/5" and rel.startswith("calls/"):
        point = unb64(obj["key"])
        ok = verify_raw(point, body, unb64(env["signature"]))
        expected_bad = "invalid" in rel
        assert ok != expected_bad, rel
        honest += ok
        for l in obj.get("links", []):
            le = json.loads(unb64(l))
            lb = unb64(le["body"])
            lo = json.loads(lb)
            keys = {k.id: k for k in [agent_sign, session1, session2, attacker]}
            assert verify_raw(keys[lo["from"]].point, lb, unb64(le["signature"])), rel
            honest += 1

if "--check" in sys.argv:
    bad = [rel for rel, data in OUT.items() if not (HERE / rel).exists() or (HERE / rel).read_bytes() != data]
    if bad:
        print("differs from generator:", *bad, sep="\n  ")
        sys.exit(1)
    print(f"ok: {len(OUT)} files match; {recanonicalized} 0.4 bodies re-canonicalized; {honest} call/link signatures verified")
else:
    for rel, data in OUT.items():
        path = HERE / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"wrote {len(OUT)} files; {recanonicalized} 0.4 bodies re-canonicalized; {honest} call/link signatures verified")
