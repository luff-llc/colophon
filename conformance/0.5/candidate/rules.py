# Revision 4 candidate vectors. Executed by generate.py in its namespace (helpers, published keys).
# Every expected outcome is the author's reading of spec/colophon-0.5.md revision 2; none has been
# replayed by a 0.5 implementation. Swift-format histories are also replayed by the Swift verifier
# (see README).

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SW = {item["id"]: item for item in published["software"]}
IDS = [item["id"] for item in published["software"]]
A, B, K1, K2, NK, MK = (software[i] for i in IDS)  # A has the published sealed slot (genesis-one-raw)
AGREE = {i: unb64(SW[i]["public"]["agreement"]) for i in IDS}
SLOT_A = g4["keyring"]["slots"][0]
VAULT_A = g4["keyring"]["vault"]
POLICY = dict(DEFAULT_POLICY)
T0 = "2026-11-11T08:00:00Z"


def ts(seconds: int) -> str:
    """T0 + seconds as a 0.5 date."""
    import datetime
    base = datetime.datetime(2026, 11, 11, 8, 0, 0, tzinfo=datetime.timezone.utc)
    return (base + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_desc(k: Key) -> dict:
    d = {"form": "raw", "signing": b64(k.point)}
    if k.id in AGREE:
        d["agreement"] = b64(AGREE[k.id])
    return d


def ctrl(k, roles, label=None, **extra) -> dict:
    c = {"key": raw_desc(k) if isinstance(k, Key) else k.descriptor(), "label": label or ("key " + k.id[:6]),
         "roles": sorted(roles)}
    c.update(extra)
    return c


def cid(c) -> str:
    return key_id(unb64(c["key"]["signing"]))


def keyring(ctrls, threshold=1, rt=0, add=1, count="keys", policy=None, slots=None):
    return {"controllers": sorted(ctrls, key=cid), "threshold": threshold, "recoverThreshold": rt, "addThreshold": add,
            "countBy": count, "policy": dict(policy or POLICY), "vault": VAULT_A,
            "slots": slots if slots is not None else [SLOT_A]}


class Authenticator:
    """Synthetic WebAuthn authenticator: authenticatorData = SHA-256(rp) || flags || counter."""

    def __init__(self, name, rp, **desc_extra):
        self.k = derived("webauthn/" + name)
        self.rp = rp
        self.credential = hashlib.sha256(name.encode()).digest()[:16]
        self.extra = desc_extra
        self.id = self.k.id
        self.point = self.k.point

    def descriptor(self):
        d = {"form": "webauthn", "signing": b64(self.point), "rp": self.rp, "credential": b64(self.credential)}
        d.update(self.extra)
        return d

    def sign(self, body: bytes, origin: str, flags=0x05):
        client = json.dumps({"type": "webauthn.get", "challenge": b64url(hashlib.sha256(body).digest()),
                             "origin": origin, "crossOrigin": False}, separators=(",", ":")).encode()
        auth = hashlib.sha256(self.rp.encode()).digest() + bytes([flags]) + (7).to_bytes(4, "big")
        msg = auth + hashlib.sha256(client).digest()
        der = self.k.private.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        return der, {"authenticatorData": b64(auth), "clientData": b64(client)}


def sig_item(signer, body, origin=None):
    if isinstance(signer, Authenticator):
        der, assertion = signer.sign(body, origin or "https://" + signer.rp)
        return {"signer": signer.id, "signature": b64(der), "assertion": assertion}
    return {"signer": signer.id, "signature": b64(signer.sign(body))}


def seal(body_obj, primary, cos=(), adds=(), handover=(), origin=None, body_bytes=None):
    body = body_bytes if body_bytes is not None else canonical(body_obj)
    p = sig_item(primary, body, origin)
    env = {"body": b64(body), "signature": p["signature"]}
    if "assertion" in p:
        env["assertion"] = p["assertion"]
    for name, group in (("cosignatures", cos), ("additions", adds), ("handover", handover)):
        if group:
            env[name] = sorted((sig_item(s, body, origin) for s in group), key=lambda x: x["signer"])
    return env


class Chain:
    def __init__(self):
        self.envs = []

    @property
    def last(self):
        return body_of(self.envs[-1]) if self.envs else None

    def add(self, kind, by, issued, signer, cos=(), adds=(), handover=(), origin=None, protocol="colophon/authority/5",
            **fields):
        body = {"protocol": protocol, "seq": len(self.envs) + 1, "previous": sha(self.last) if self.envs else None,
                "issued": issued, "by": by.id, "kind": kind}
        body.update(fields)
        env = seal(body, signer, cos, adds, handover, origin)
        self.envs.append(env)
        return env

    def copy(self):
        c = Chain()
        c.envs = list(self.envs)
        return c


def write_case(name, chain, expected, description, sections, extra=None, verifier=None, branches=None):
    for i, env in enumerate(chain.envs):
        write(f"rules/{name}/records/authority/{i + 1:08d}.json", env)
    for rel, value in (extra or {}).items():
        write(f"rules/{name}/{rel}", value)
    for label, envs in (branches or {}).items():
        for seq, env in envs:
            write(f"rules/{name}/branch-{label}/authority/{seq:08d}.json", env)
    write(f"rules/{name}/case.json", {"description": description, "sections": sections, "expected": expected,
                                       "verifier": verifier or {"now": "2026-11-20T00:00:00Z"}})


def genesis(chain, kr, signers, adds=(), label="Account", namespaces=(), predecessor=None, handover=(), origin=None):
    primary, *cos = signers
    fields = {"label": label, "namespaces": list(namespaces), "keyring": kr}
    if predecessor:
        fields["predecessor"] = predecessor
    return chain.add("genesis", primary, T0, primary, cos, adds, handover, origin, **fields)


def change(kr, **delta):
    new = json.loads(json.dumps(kr))
    for k, v in delta.items():
        if k == "policy":
            new["policy"].update(v)
        else:
            new[k] = v
    new["controllers"] = sorted(new["controllers"], key=cid)
    return new


def ok_at(seq):
    return {"result": "ok", "seq": seq}


def bad(result, seq):
    return {"result": result, "seq": seq}


HOME_K, HOME_A = derived("r2/home/signing"), derived("r2/home/agreement")
AGENT_K, AGENT_A = derived("r2/agent/signing"), derived("r2/agent/agreement")


def request(account, member, agree, kind, terms, label="Member", service=None):
    body = {"protocol": "colophon/request/5", "account": account,
            "member": {"agreement": b64(agree.point), "signing": b64(member.point)},
            "label": label, "kind": kind, "terms": terms, "created": T0}
    if service:
        body["service"] = service
    return b64(env_bytes(envelope(body, member)))


def account_id(chain):
    return sha(body_of(chain.envs[0]))


def grant_home(chain, by, issued, signer, cos=()):
    acct = account_id(chain)
    req = request(acct, HOME_K, HOME_A, "server", {"serves": ["home"]}, "Home",
                  {"endpoints": ["https://home.example/v1/accounts/" + acct]})
    return chain.add("grant", by, issued, signer, cos, request=req, terms={"serves": ["home"]}, shares=[])


def grant_agent(chain, by, issued, signer, key=AGENT_K, agree=AGENT_A, expires="2026-11-18T08:00:00Z"):
    acct = account_id(chain)
    terms = {"services": [{"audience": AUD, "purposes": ["task.read"]}], "expires": expires}
    req = request(acct, key, agree, "agent", {"services": [{"audience": AUD, "purposes": ["task.read"]}]}, "Agent")
    return chain.add("grant", by, issued, signer, request=req, terms=terms, shares=[])


def receipt(chain, seq, received):
    body = {"protocol": "colophon/receipt/5", "account": account_id(chain),
            "entry": {"seq": seq, "digest": sha(body_of(chain.envs[seq - 1]))}, "received": received, "by": HOME_K.id}
    return envelope(body, HOME_K)



kr_t1 = keyring([ctrl(A, ["approve", "control"], "Device")], threshold=1)

# Authority origins (§4.3) with a synthetic passkey.
P_open = Authenticator("passkey-open", "id.example")
P_pin = Authenticator("passkey-pinned", "id.example", authorityOrigins=["https://keys.id.example"])
for name, auth, origin, expected, why in [
    ("origin-exact-rp", P_open, "https://id.example", ok_at(1), "No pin: the bare rp origin may sign authority."),
    ("origin-subdomain-unpinned", P_open, "https://keys.id.example", bad("badSignature", 1),
     "No pin: a subdomain may not sign authority."),
    ("origin-subdomain-pinned", P_pin, "https://keys.id.example", ok_at(1), "Pinned subdomain signs authority."),
    ("origin-bare-not-pinned", P_pin, "https://id.example", bad("badSignature", 1), "Pinned elsewhere: the bare rp may not."),
]:
    kr_p = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(auth, ["approve", "control"], "Passkey", verification=True)])
    c = Chain(); genesis(c, kr_p, [auth], adds=[A], origin=origin)
    write_case(name, c, expected, why, ["4.3"])

# Calls against the revision-1 account: replay, evaluation point (§12.3, §12.4).
replay_ver = {"now": NOW, "audiences": [AUD], "history": "conformance/0.5/candidate/account/records",
              "heads": ["conformance/0.5/candidate/account/head.json"],
              "replay": ["conformance/0.5/candidate/calls/member-no-links/call.json"]}
write("rules/replay-identical/call.json", call(agent_sign))
write("rules/replay-identical/case.json", {"description": "The same call body again.", "sections": ["12.3", "12.4"],
                                           "expected": {"call": "refused:replay"}, "verifier": replay_ver})
write("rules/replay-conflict/call.json", call(agent_sign, args={"task": "T-13"}))
write("rules/replay-conflict/case.json", {"description": "Same key and requestId, different body.", "sections": ["12.3", "12.4"],
                                          "expected": {"call": "refused:conflict"}, "verifier": replay_ver})

beyond = Chain(); beyond.envs = list(history)
rev = beyond.add("revoke", controller, "2026-11-11T09:00:30Z", controller, member=agent_sign.id, kept=[], heads=[], epochs=[])
write("rules/removal-after-heads/records/authority/00000004.json", rev)
write("rules/removal-after-heads/call.json", call(agent_sign, rid_seed="r4"))
write("rules/removal-after-heads/case.json", {
    "description": "The verifier holds a revoke at seq 4 that no head covers yet; removals apply at once.",
    "sections": ["12.3"], "expected": {"call": "refused:revoked"},
    "verifier": {"now": NOW, "audiences": [AUD], "history": ["conformance/0.5/candidate/account/records",
                                                              "conformance/0.5/candidate/rules/removal-after-heads/records"],
                 "heads": ["conformance/0.5/candidate/account/head.json"]}})

# Heads: equivocation evidence, rollback (§13.3).
fake = envelope(dict(head, authority={"seq": 3, "digest": "2" * 64}), home_sign)
pair = sorted([head_env, fake], key=lambda e: sha(body_of(e)))
write("rules/equivocation/evidence.json", {"protocol": "colophon/equivocation/5", "account": account,
                                           "heads": [b64(env_bytes(e)) for e in pair]})
write("rules/equivocation/case.json", {"description": "Two heads by one home at seq 3 with different digests.",
                                       "sections": ["13.3"], "expected": {"evidence": "ok", "home": "not counted"}})
old_head = envelope(dict(head, authority={"seq": 2, "digest": sha(body_of(ga_env))}, issued="2026-11-11T09:00:30Z"), home_sign)
write("rules/rollback/head.json", old_head)
write("rules/rollback/case.json", {"description": "A fresh head over seq 2 after the verifier accepted seq 3.",
                                   "sections": ["13.3"], "expected": {"head": "refused:rollback"},
                                   "verifier": {"now": NOW, "highWater": {"seq": 3, "digest": sha(body_of(gh_env))}}})

# Canonical encodings (§2.1, §2.2).
c = Chain(); genesis(c, kr_t1, [A])
g_obj = json.loads(body_of(c.envs[0]))
unsorted = json.dumps(dict(reversed(list(g_obj.items()))), separators=(",", ":")).encode()  # keys in reverse order
assert unsorted != body_of(c.envs[0])
write("rules/non-canonical-json/records/authority/00000001.json", seal(None, A, body_bytes=unsorted))
write("rules/non-canonical-json/case.json", {"description": "Genesis body with keys not in sorted order.",
                                             "sections": ["2.1"], "expected": bad("malformed", 1)})
g_obj2 = json.loads(body_of(c.envs[0]))
spelled = g_obj2["keyring"]["controllers"][0]["key"]["signing"]
# A 65-byte value ends in one padding character; flip a padding bit in the last data character.
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
last = spelled[-2]
g_obj2["keyring"]["controllers"][0]["key"]["signing"] = spelled[:-2] + alphabet[alphabet.index(last) ^ 1] + "="
assert base64.b64decode(g_obj2["keyring"]["controllers"][0]["key"]["signing"]) == base64.b64decode(spelled)
write("rules/non-canonical-base64/records/authority/00000001.json", seal(g_obj2, A))
write("rules/non-canonical-base64/case.json", {"description": "A key spelled with a non-zero padding bit (decodes to the same bytes).",
                                               "sections": ["2.2"], "expected": bad("malformed", 1)})
c = Chain(); genesis(c, kr_t1, [A])
bad_date = Chain(); bad_date.envs = list(c.envs)
grant_agent(bad_date, A, ts(60), A, expires="2026-02-30T00:00:00Z")
write_case("invalid-expires-date", bad_date, bad("malformed", 2), "terms.expires on February 30.", ["2.2", "10.1"])

# ---------------------------------------------------------------------------------------------
# Pairing (§7.3).
acct_p = "0" * 63 + "1"
E = derived("pair/E")
nB = hashlib.sha256(b"pair/nB").digest()
nA = hashlib.sha256(b"pair/nA").digest()
C = hashlib.sha256(b"colophon/pair/5" + acct_p.encode() + E.point + nB).hexdigest()
code = int.from_bytes(hashlib.sha256(b"colophon/pair-code/5" + acct_p.encode() + E.point + nA + nB).digest()[:4], "big") % 1000000
E2 = derived("pair/E-substitute")
write("pairing/pairing.json", {
    "description": "Commit-then-reveal pairing (§7.3). Hex for bytes.",
    "account": acct_p, "E": E.point.hex(), "nB": nB.hex(), "nA": nA.hex(),
    "commitment": C, "code": f"{code:06d}",
    "refuse": [{"case": "reveal with another key", "E": E2.point.hex(), "nB": nB.hex(), "expected": "abort: commitment mismatch"},
               {"case": "reveal with another nB", "E": E.point.hex(), "nB": hashlib.sha256(b"x").hexdigest(),
                "expected": "abort: commitment mismatch"}],
})

# Swift keyring predecessors (§15.1, §16.3), replayed by the Swift verifier too.
SWIFT_T = "2026-11-01T08:00:00Z"
root_s, root_a = derived("swift/root/signing"), derived("swift/root/agreement")
rec_s, rec_a = derived("swift/recovery/signing"), derived("swift/recovery/agreement")
vault_s, vault_a = derived("swift/vault/signing"), derived("swift/vault/agreement")


def pid(sign: Key, agree: Key):
    return {"agreement": b64(agree.point), "signing": b64(sign.point)}


def swift_sealed(seed: bytes, recipient_sign: bytes, recipient_agree: bytes, eph_name: str):
    eph = derived(eph_name).private
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), recipient_agree)
    shared = eph.exchange(ec.ECDH(), peer)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=recipient_sign, info=b"colophon/sealed-key/1").derive(shared)
    nonce = hashlib.sha256(eph_name.encode()).digest()[:12]
    box = nonce + AESGCM(key).encrypt(nonce, seed, None)
    eph_point = derived(eph_name).point
    return {"box": b64(box), "ephemeral": b64(eph_point)}


def swift_ctrl(k: Key, roles, label):
    return {"key": b64(k.point), "kind": "p256", "label": label, "roles": roles}


def swift_record(body_obj, primary: Key, cos=()):
    body = canonical(body_obj)
    rec = {"body": b64(body), "signature": b64(primary.sign(body))}
    if cos:
        rec["cosignatures"] = [{"signer": k.id, "signature": b64(k.sign(body))} for k in cos]
    return rec


def swift_library(two_keys=False, adopt=True):
    g = {"by": "root", "issued": SWIFT_T, "kind": "genesis", "label": "Library", "recovery": pid(rec_s, rec_a),
         "root": pid(root_s, root_a), "seq": 1}
    recs = [swift_record(g, root_s)]
    if not adopt:
        return recs, None
    ctrls = [swift_ctrl(A, ["approve", "control"], "Mac"), swift_ctrl(K1, ["recover"], "Kit")]
    if two_keys:
        ctrls = [swift_ctrl(A, ["approve", "control"], "Mac"), swift_ctrl(B, ["approve", "control"], "iPhone"),
                 swift_ctrl(K1, ["recover"], "Key 1"), swift_ctrl(K2, ["recover"], "Key 2")]
    seed = hashlib.sha256(b"swift/vault-seed").digest()
    slot = {"controller": A.id, "kind": "sealed", "label": "Mac", "recipient": {"agreement": b64(AGREE[A.id]), "signing": b64(A.point)},
            "sealed": swift_sealed(seed, A.point, AGREE[A.id], "swift/slot-eph")}
    k = {"by": "root", "controllers": ctrls, "issued": "2026-11-01T08:01:00Z", "kind": "keyring",
         "previous": sha(unb64(recs[0]["body"])), "seq": 2, "slots": [slot], "threshold": 2 if two_keys else 1,
         "vault": pid(vault_s, vault_a)}
    if two_keys:
        k["recoverThreshold"] = 2
    recs.append(swift_record(k, root_s))
    return recs, k


def swift_freeze(recs, successor, signer, cos=(), root=False, seq=None, issued="2026-11-11T08:05:00Z"):
    seq = seq or len(recs) + 1
    f = {"by": "root" if root else "controller", "issued": issued, "kind": "layout", "layout": 3,
         "previous": sha(unb64(recs[seq - 2]["body"])), "seq": seq, "successor": successor}
    if not root:
        f["signer"] = signer.id
    return swift_record(f, signer, cos)


def new_genesis(pred_recs, head_seq, two_keys=False, handover=(), label="Library", rt=1):
    lib_id = sha(unb64(pred_recs[0]["body"]))[:32]
    ctrls = [ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")]
    if two_keys:
        ctrls = [ctrl(A, ["approve", "control"], "Mac"), ctrl(B, ["approve", "control"], "iPhone"),
                 ctrl(K1, ["recover"], "Key 1"), ctrl(K2, ["recover"], "Key 2")]
    kr_new = keyring(ctrls, threshold=1, rt=rt)
    pred = {"format": "colophon/swift-keyring/2", "account": lib_id,
            "head": {"seq": head_seq, "digest": sha(unb64(pred_recs[head_seq - 1]["body"]))}}
    g = Chain()
    adds = [] if pred_recs is not None else []
    genesis(g, kr_new, [A], label=label, predecessor=pred, handover=handover)
    return g


def write_swift(name, recs, g5, expected, why, extra_recs=None):
    for i, r in enumerate(recs):
        write(f"succession/{name}/predecessor/authority/{i + 1:08d}.json", r)
    for rel, r in (extra_recs or {}).items():
        write(f"succession/{name}/{rel}", r)
    if g5 is not None:
        write(f"succession/{name}/genesis.json", g5.envs[0])
    write(f"succession/{name}/case.json", {"description": why, "sections": ["15.1", "16.3"], "expected": expected})



N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

SP = Authenticator("swift-passkey", "id.example")
SY = Authenticator("swift-security-key", "id.example")


def swift_webauthn_ctrl(a, roles, label):
    return {"credential": b64(a.credential), "key": b64(a.point), "kind": "webauthn", "label": label,
            "roles": roles, "rpID": a.rp, "verification": True}


def swift_signed(body_obj, primary, cos=()):
    body = canonical(body_obj)

    def item(k):
        if isinstance(k, Authenticator):
            der, assertion = k.sign(body, "https://" + k.rp)
            return b64(der), assertion
        return b64(k.sign(body)), None
    sig, asr = item(primary)
    rec = {"body": b64(body), "signature": sig}
    if asr:
        rec["assertion"] = asr
    if cos:
        rec["cosignatures"] = []
        for k in cos:
            s2, a2 = item(k)
            c2 = {"signer": k.id, "signature": s2}
            if a2:
                c2["assertion"] = a2
            rec["cosignatures"].append(c2)
    return rec


def swift_webauthn_library(recover_add=False):
    recs, _ = swift_library(adopt=False)
    ctrls = [swift_ctrl(A, ["approve", "control"], "Mac"), swift_webauthn_ctrl(SP, ["approve", "recover"], "Passkey"),
             swift_webauthn_ctrl(SY, ["approve", "control"], "Security key")]
    seed = hashlib.sha256(b"swift/vault-seed").digest()
    slot = {"controller": A.id, "kind": "sealed", "label": "Mac",
            "recipient": {"agreement": b64(AGREE[A.id]), "signing": b64(A.point)},
            "sealed": swift_sealed(seed, A.point, AGREE[A.id], "swift/slot-eph")}
    k = {"by": "root", "controllers": ctrls, "issued": "2026-11-01T08:01:00Z", "kind": "keyring",
         "previous": sha(unb64(recs[0]["body"])), "seq": 2, "slots": [slot], "threshold": 1, "vault": pid(vault_s, vault_a)}
    recs.append(swift_record(k, root_s))
    if recover_add:
        k3 = {"by": "controller", "controllers": ctrls + [swift_ctrl(MK, ["approve", "control"], "Thief")],
              "issued": "2026-11-02T08:00:00Z", "kind": "keyring", "previous": sha(unb64(recs[1]["body"])), "seq": 3,
              "signer": SP.id, "slots": [slot], "threshold": 1, "vault": pid(vault_s, vault_a)}
        recs.append(swift_signed(k3, SP))
    return recs


def swift_freeze_signed(recs, successor, signer, issued="2026-11-11T08:05:00Z"):
    f = {"by": "controller", "issued": issued, "kind": "layout", "layout": 3, "previous": sha(unb64(recs[-1]["body"])),
         "seq": len(recs) + 1, "signer": signer.id, "successor": successor}
    return swift_signed(f, signer)


def genesis_from(recs, ctrls, rt, handover=(), adds=(), label="Library"):
    pred = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs[0]["body"]))[:32],
            "head": {"seq": len(recs), "digest": sha(unb64(recs[-1]["body"]))}}
    g = Chain(); genesis(g, keyring(ctrls, threshold=1, rt=rt), [A], adds=adds, label=label, predecessor=pred,
                         handover=handover, origin="https://id.example")
    return g


# A malleated envelope: s → n − s over the same body (§2.2, §8.6).
m = Chain(); genesis(m, kr_t1, [A])
env = dict(m.envs[0]); sig = unb64(env["signature"])
s_val = int.from_bytes(sig[32:], "big"); env["signature"] = b64(sig[:32] + (N - s_val).to_bytes(32, "big"))
assert verify_raw(A.point, body_of(env), unb64(env["signature"]))
write("rules/malleated-envelope/original.json", m.envs[0]); write("rules/malleated-envelope/malleated.json", env)
write("rules/malleated-envelope/case.json", {"description": "The same body with s replaced by n − s. Both verify; they are one entry.",
                                             "sections": ["2.2", "8.6", "14"], "expected": {"equal": True, "home": "200, keeps the first"}})


exec(compile((HERE / "rules_v8.py").read_text(), str(HERE / "rules_v8.py"), "exec"))
