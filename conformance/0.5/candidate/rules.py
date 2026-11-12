# Revision 2 candidate vectors. Executed by generate.py in its namespace (helpers, published keys).
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


# ---------------------------------------------------------------------------------------------
# Recovery-set rule (§8.4).
base_rs = [ctrl(A, ["approve", "control"], "Device"), ctrl(K1, ["recover"], "Key 1"), ctrl(K2, ["recover"], "Key 2")]
kr_rt2 = keyring(base_rs, threshold=1, rt=2)
kr_rt1 = keyring(base_rs, threshold=1, rt=1)
S8 = ["8.4"]

c = Chain(); genesis(c, kr_rt2, [A], adds=[K1, K2])
c1 = c.copy(); c1.add("keyring", A, ts(60), A, keyring=change(kr_rt2, recoverThreshold=1))
write_case("rs-lower-control-only", c1, bad("badSignature", 2),
           "Lowering recoverThreshold 2→1 with the control key alone: the recovery-set rule needs 2 recover signers.", S8)
c2 = c.copy(); c2.add("keyring", A, ts(60), A, cos=[K1, K2], keyring=change(kr_rt2, recoverThreshold=1))
write_case("rs-lower-with-recover", c2, ok_at(2), "The same change also signed by both recover keys.", S8)

kr_one = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(K1, ["recover"], "Key 1")], threshold=1, rt=1)
c = Chain(); genesis(c, kr_one, [A], adds=[K1])
added = change(kr_one, controllers=kr_one["controllers"] + [ctrl(K2, ["recover"], "Key 2")])
c1 = c.copy(); c1.add("keyring", A, ts(60), A, adds=[K2], keyring=added)
write_case("rs-add-recover-control-only", c1, bad("badSignature", 2),
           "Adding a recover controller needs the prior recovery quorum (K1).", S8)
c2 = c.copy(); c2.add("keyring", A, ts(60), A, cos=[K1], adds=[K2], keyring=added)
write_case("rs-add-recover-with-recover", c2, ok_at(2), "Adding a recover controller, signed by A and K1, with K2's possession proof.", S8)

c = Chain(); genesis(c, kr_rt1, [A], adds=[K1, K2])
removed = change(kr_rt1, controllers=[x for x in kr_rt1["controllers"] if cid(x) != K2.id])
c1 = c.copy(); c1.add("keyring", A, ts(60), A, keyring=removed)
write_case("rs-remove-recover-control-only", c1, bad("badSignature", 2),
           "Removing a recover controller (never named by a slot, so no rotation) with the control key alone.", S8)
c2 = c.copy(); c2.add("keyring", A, ts(60), A, cos=[K1], keyring=removed)
write_case("rs-remove-recover-with-recover", c2, ok_at(2), "The same removal also signed by K1.", S8)

# ---------------------------------------------------------------------------------------------
# Add rule and possession (§8.4, §17.3).
kr_t2 = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(B, ["approve", "control"], "Laptop")], threshold=2)
c = Chain(); genesis(c, kr_t2, [A, B])


def with_added(kr, c_new):
    return change(kr, controllers=kr["controllers"] + [c_new])


prov = ctrl(NK, ["approve"], "New passkey", until=ts(60 + 7 * 86400))
c1 = c.copy(); c1.add("keyring", A, ts(60), A, adds=[NK], keyring=with_added(kr_t2, prov))
write_case("add-provisional", c1, ok_at(2),
           "threshold 2, addThreshold 1: one control key adds a provisional approve-only key with `until`, no slot.", S8)
c1b = c1.copy()
acct_t2 = account_id(c1b)
req = request(acct_t2, AGENT_K, AGENT_A, "agent", {"services": [{"audience": AUD, "purposes": ["task.read"]}]})
c1b.add("grant", NK, ts(120), NK, request=req, terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]}, shares=[])
write_case("provisional-before-until", c1b, ok_at(3), "The provisional key approves a grant before its `until`.", ["6.1", "8.4"])
c1c = c1.copy()
c1c.add("grant", NK, ts(60 + 8 * 86400), NK, request=req, terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]},
        shares=[])
write_case("provisional-after-until", c1c, bad("badSignature", 3), "The same grant issued after `until`.", ["6.1", "8.4"])
c2 = c.copy(); c2.add("keyring", A, ts(60), A, adds=[NK],
                      keyring=with_added(kr_t2, ctrl(NK, ["approve", "control"], "New passkey", until=ts(86400))))
write_case("add-provisional-with-control", c2, bad("badSignature", 2), "A provisional addition may hold only approve.", S8)
c3 = c.copy(); c3.add("keyring", A, ts(60), A, adds=[NK], keyring=with_added(kr_t2, ctrl(NK, ["approve"], "New passkey")))
write_case("add-provisional-no-until", c3, bad("badSignature", 2), "Below threshold, an addition without `until`.", S8)
c4 = c.copy(); c4.add("keyring", A, ts(60), A, adds=[NK],
                      keyring=with_added(kr_t2, ctrl(NK, ["approve"], "New passkey", until=ts(60 + 31 * 86400))))
write_case("add-provisional-until-too-long", c4, bad("badSignature", 2), "`until` more than 30 days after `issued`.", S8)

kr_t1 = keyring([ctrl(A, ["approve", "control"], "Device")], threshold=1)
c = Chain(); genesis(c, kr_t1, [A])
full = with_added(kr_t1, ctrl(NK, ["approve", "control"], "Passkey on a new platform"))
c1 = c.copy(); c1.add("keyring", A, ts(60), A, adds=[NK], keyring=full)
write_case("add-one-approval", c1, ok_at(2), "threshold 1: one existing key adds a full controller (one approval).", ["8.4", "17.3"])
c2 = c.copy(); c2.add("keyring", A, ts(60), A, keyring=full)
write_case("add-missing-possession", c2, bad("badSignature", 2), "The added key did not sign `additions`.", ["4.1", "8.4"])
c3 = c.copy(); env = c3.add("keyring", A, ts(60), A, adds=[MK], keyring=full)
write_case("add-wrong-possession", c3, bad("badSignature", 2), "`additions` signed by a key that is not the one added.", ["4.1", "8.4"])
c4 = c.copy(); c4.add("keyring", A, "2026-11-11T07:59:59Z", A, adds=[NK], keyring=full)
write_case("issued-backwards", c4, bad("malformed", 2), "`issued` earlier than the preceding entry's.", ["8.1"])

# Re-adding a removed controller (no slot ever named it).
kr_n = with_added(kr_t1, ctrl(NK, ["approve"], "Tablet"))
c = Chain(); genesis(c, kr_n, [A], adds=[NK])
c.add("keyring", A, ts(60), A, keyring=kr_t1)
c.add("keyring", A, ts(120), A, adds=[NK], keyring=kr_n)
write_case("readd-removed-controller", c, ok_at(3), "Remove a never-slotted controller (no rotation), then add it back.", ["3.3", "8.3"])

# Principals across time.
c = Chain(); genesis(c, kr_t1, [A]); grant_agent(c, A, ts(60), A)
agent_as_ctrl = with_added(kr_t1, ctrl(AGENT_K, ["approve"], "Agent"))
c.add("keyring", A, ts(120), A, adds=[AGENT_K], keyring=agent_as_ctrl)
write_case("member-key-as-controller", c, bad("malformed", 3), "A member's key made a controller.", ["3.3", "9.7"])
c = Chain(); genesis(c, kr_n, [A], adds=[NK]); c.add("keyring", A, ts(60), A, keyring=kr_t1)
grant_agent(c, A, ts(120), A, key=NK, agree=derived("r2/nk-agreement"))
write_case("former-controller-as-member", c, bad("malformed", 3), "A grant to a key that was a controller.", ["3.3"])

# A sign-only controller signs no authority entry.
kr_s = with_added(kr_t1, ctrl(MK, ["sign"], "Staging passkey", audiences=["https://projects.staging.example"]))
c = Chain(); genesis(c, kr_s, [A], adds=[MK]); grant_agent(c, MK, ts(60), MK)
write_case("sign-controller-authority", c, bad("badSignature", 2), "A `sign` controller signs a grant.", ["6.1", "8.4"])

# Holders (§6.2).
kr_h = keyring([ctrl(A, ["approve", "control"], "Founder 1 phone", holder="founder-1"),
                ctrl(B, ["approve", "control"], "Founder 1 laptop", holder="founder-1"),
                ctrl(MK, ["approve", "control"], "Founder 2 phone", holder="founder-2")], threshold=2, count="holders")
c = Chain(); genesis(c, kr_h, [A, MK], adds=[B])
c1 = c.copy(); c1.add("keyring", A, ts(60), A, cos=[B], keyring=change(kr_h, policy={"headMaxAge": 600}))
write_case("holders-one-holder", c1, bad("badSignature", 2), "countBy holders: two keys of one holder are one signer.", ["6.2"])
c2 = c.copy(); c2.add("keyring", A, ts(60), A, cos=[MK], keyring=change(kr_h, policy={"headMaxAge": 600}))
write_case("holders-two-holders", c2, ok_at(2), "Two holders meet threshold 2.", ["6.2"])

# Recovery, receipt, delay and cancel (§8.4, §13.5). Threshold 2 so cancel is distinguishable.
kr_r = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(B, ["approve", "control"], "Laptop"),
                ctrl(K1, ["approve", "recover"], "Security key")], threshold=2, rt=1)
c = Chain(); genesis(c, kr_r, [A, B], adds=[K1]); grant_home(c, A, ts(60), A, cos=[B])
rec_kr = with_added(kr_r, ctrl(NK, ["approve"], "Recovered phone"))
issued_rec = ts(3600)
received = ts(3602)
crec = c.copy(); crec.add("keyring", K1, issued_rec, K1, adds=[NK], keyring=rec_kr)
rcpt = {"records/authority/00000003.receipt.json": receipt(crec, 3, received)}
write_case("recovery-with-receipt", crec, ok_at(3), "Recovery rule (approve-only addition since recoverThreshold < threshold), with a home receipt.",
           ["8.4", "13.5"], extra=rcpt)
write_case("recovery-without-receipt", crec, {"result": "held", "seq": 3, "why": "unavailable: receipt"},
           "The same recovery entry in an account with a home, without a receipt.", ["8.4"])
req2 = request(account_id(crec), AGENT_K, AGENT_A, "agent", {"services": [{"audience": AUD, "purposes": ["task.read"]}]})
early = crec.copy(); early.add("grant", NK, ts(7200), NK, request=req2,
                               terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]}, shares=[])
write_case("delayed-signer-early", early, bad("badSignature", 4),
           "The recovery-added key signs a grant one hour later; it is delayed for 72 h after the receipt.", ["8.4"], extra=rcpt)
late = crec.copy(); late.add("grant", NK, ts(3602 + 259200 + 60), NK, request=req2,
                             terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]}, shares=[])
write_case("delayed-signer-after", late, ok_at(4), "The same grant issued after the delay.", ["8.4"], extra=rcpt)
cancel = crec.copy(); cancel.add("keyring", A, ts(7200), A, keyring=kr_r)
write_case("cancel-during-delay", cancel, ok_at(4), "One pre-existing control key removes the still-delayed recovery-added key.",
           ["8.4"], extra=rcpt)
cancel2 = crec.copy(); cancel2.add("keyring", A, ts(3602 + 259200 + 60), A, keyring=kr_r)
write_case("cancel-after-delay", cancel2, bad("badSignature", 4),
           "After the delay the cancel rule no longer applies, and one key is below threshold 2.", ["8.4"], extra=rcpt)

c = Chain(); genesis(c, keyring([ctrl(A, ["approve", "control"], "Device")], policy=dict(POLICY, recoveryDelay=0)), [A])
grant_home(c, A, ts(60), A)
write_case("delay-zero-with-home", c, bad("malformed", 2), "Appointing a home while recoveryDelay is 0.", ["6.3"])

# Successor is terminal and needs the recovery quorum (§15.2).
c = Chain(); genesis(c, kr_one, [A], adds=[K1])
s_ok = c.copy(); s_ok.add("successor", A, ts(60), A, cos=[K1], account="ab" * 32)
write_case("successor", s_ok, ok_at(2), "Successor under control and recovery-set rules.", ["8.4", "15.2"])
s_bad = c.copy(); s_bad.add("successor", A, ts(60), A, account="ab" * 32)
write_case("successor-without-recovery", s_bad, bad("badSignature", 2), "Successor with the control key alone.", ["8.4"])
s_after = s_ok.copy(); s_after.add("layout", A, ts(120), A, layout=2)
write_case("entry-after-successor", s_after, {"result": "refused:fork", "seq": 3}, "An entry after a successor.", ["15.2"])

# Forks and resolve (§8.6).
c = Chain(); genesis(c, kr_one, [A], adds=[K1])
fa = c.copy(); fa.add("keyring", A, ts(60), A, keyring=change(kr_one, policy={"headMaxAge": 600}))
fb = c.copy(); fb.add("keyring", A, ts(61), A, keyring=change(kr_one, policy={"headMaxAge": 900}))
write_case("fork", fa, {"result": "refused:fork", "seq": 2}, "Two valid entries at seq 2.", ["8.6"],
           branches={"b": [(2, fb.envs[1])]})
fr = fa.copy(); fr.add("resolve", A, ts(120), A, cos=[K1], discarded={"seq": 2, "digest": sha(body_of(fb.envs[1]))})
write_case("fork-resolved", fr, ok_at(3), "Branch a resolves the fork under control and recovery-set rules.", ["8.6"],
           branches={"b": [(2, fb.envs[1])]})
fr2 = fa.copy(); fr2.add("resolve", A, ts(120), A, discarded={"seq": 2, "digest": sha(body_of(fb.envs[1]))})
write_case("resolve-without-recovery", fr2, {"result": "refused:fork", "seq": 2, "why": "resolve at 3 is badSignature"},
           "A resolve without the recovery quorum doesn't settle the fork.", ["8.6"], branches={"b": [(2, fb.envs[1])]})

# ---------------------------------------------------------------------------------------------
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

# Controller calls (§12.3 step 5): account with the pinned passkey and a home.
kr_p = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(P_pin, ["approve", "control"], "Passkey", verification=True),
                ctrl(K1, ["recover"], "Kit")], rt=1)
cc = Chain(); genesis(cc, kr_p, [A], adds=[K1, P_pin], origin="https://keys.id.example")
grant_home(cc, A, ts(60), A)
acct_cc = account_id(cc)
head_cc = envelope({"protocol": "colophon/head/5", "account": acct_cc,
                    "authority": {"seq": 2, "digest": sha(body_of(cc.envs[1]))}, "issued": "2026-11-11T09:00:00Z",
                    "by": HOME_K.id}, HOME_K)


def ctrl_call(signer, origin, purpose="sign-in", rid="c1"):
    body = {"protocol": "colophon/call/5", "account": acct_cc, "asOf": {"seq": 2, "digest": sha(body_of(cc.envs[1]))},
            "signer": {"controller": signer.id}, "key": b64(signer.point), "audience": "https://service.example",
            "purpose": purpose, "args": {"nonce": "n-" + rid},
            "requestId": b64url(hashlib.sha256(("ctrl/" + rid).encode()).digest()), "created": "2026-11-11T09:01:00Z"}
    return seal(body, signer, origin=origin)


ver_cc = {"now": "2026-11-11T09:01:00Z", "audiences": ["https://service.example"],
          "callOrigins": {"id.example": ["https://sign.id.example"]}, "controllerPurposes": ["sign-in"]}
for name, env, expected, why in [
    ("controller-call", ctrl_call(P_pin, "https://sign.id.example"), "ok", "Passkey call from the configured call origin."),
    ("controller-call-wrong-origin", ctrl_call(P_pin, "https://keys.id.example", rid="c2"), "refused:origin",
     "The same call from the authority origin, which this verifier doesn't list as a call origin."),
    ("controller-call-recover-only", ctrl_call(K1, None, rid="c3"), "refused:outOfScope", "A recover-only controller calls."),
]:
    write_case(name, cc, {"call": expected}, why, ["12.3"], extra={"call.json": env, "head.json": head_cc}, verifier=ver_cc)

# ---------------------------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------------------------
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


recs, _ = swift_library()
g5 = new_genesis(recs, 2)
acct5 = account_id(g5)
frozen = recs + [swift_freeze(recs, acct5, A)]
write_swift("swift-keyring", frozen, g5, {"genesis": "ok", "succession": "verified",
                                          "swiftReader": "unsupportedStorageLayout(3) at seq 3; seq 1-2 accept"},
            "Swift keyring library frozen by its control key; the 0.5 genesis reuses its keys (no possession proofs needed).")
write_swift("swift-stale-head", frozen, new_genesis(recs, 1), {"genesis": "ok", "succession": "unverified"},
            "The genesis names seq 1 as head; the final entry is not at head + 1 and names another account.")
extra = swift_freeze(frozen, acct5, A, seq=4, issued="2026-11-11T08:06:00Z")
extra_obj = json.loads(unb64(extra["body"])); extra_obj["previous"] = sha(unb64(frozen[2]["body"]))
write_swift("swift-entry-after-final", frozen + [swift_record(extra_obj, A)], g5,
            {"genesis": "ok", "succession": "refused:fork"}, "A further entry after the freezing entry.")
other = new_genesis(recs, 2, label="Other")
rival = swift_freeze(recs, account_id(other), A, issued="2026-11-11T08:05:30Z")
write_swift("swift-two-successors", frozen, g5, {"genesis": "ok", "succession": "refused:fork"},
            "Two freezing entries at seq 3 naming different accounts.",
            extra_recs={"rival/authority/00000003.json": rival, "rival-genesis.json": other.envs[0]})

recs2, _ = swift_library(two_keys=True)
g_short = new_genesis(recs2, 2, two_keys=True)
fz = recs2 + [swift_freeze(recs2, account_id(g_short), A, cos=[B])]
write_swift("swift-two-keys-lowered-without-recover", fz, g_short, {"genesis": "ok", "succession": "unverified"},
            "Predecessor recoverThreshold 2, new keyring 1, no recover signers in handover.")
g_hand = Chain()
pred2 = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs2[0]["body"]))[:32],
         "head": {"seq": 2, "digest": sha(unb64(recs2[1]["body"]))}}
kr2 = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(B, ["approve", "control"], "iPhone"),
               ctrl(K1, ["recover"], "Key 1"), ctrl(K2, ["recover"], "Key 2")], threshold=1, rt=1)
genesis(g_hand, kr2, [A], predecessor=pred2, handover=[K1, K2])
fz2 = recs2 + [swift_freeze(recs2, account_id(g_hand), A, cos=[B])]
write_swift("swift-two-keys-lowered-with-recover", fz2, g_hand, {"genesis": "ok", "succession": "verified"},
            "The same with both recover keys in handover.")

recs3, _ = swift_library(adopt=False)
g_root = Chain()
pred3 = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs3[0]["body"]))[:32],
         "head": {"seq": 1, "digest": sha(unb64(recs3[0]["body"]))}}
genesis(g_root, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
        predecessor=pred3, handover=[rec_s])
fr3 = recs3 + [swift_freeze(recs3, account_id(g_root), root_s, root=True)]
write_swift("swift-root-library", fr3, g_root, {"genesis": "ok", "succession": "verified"},
            "A root library frozen by its root; handover carries the recovery identity.")
g_root2 = Chain()
genesis(g_root2, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
        predecessor=pred3, label="No recovery")
fr4 = recs3 + [swift_freeze(recs3, account_id(g_root2), root_s, root=True)]
write_swift("swift-root-library-without-recovery", fr4, g_root2, {"genesis": "ok", "succession": "unverified"},
            "Root library, handover without the recovery identity.")

write("succession/keys.json", {"warning": "PUBLIC TEST SECRETS.",
                               "swift": {n: {"id": k.id, "scalar": b64(k.scalar.to_bytes(32, "big"))}
                                         for n, k in [("root/signing", root_s), ("recovery/signing", rec_s),
                                                      ("vault/signing", vault_s)]}})
