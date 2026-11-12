# Revision 3 candidate vectors. Executed by generate.py after rules.py, in the same namespace.
# Expected outcomes are the author's reading of spec revision 3; none has been replayed by a 0.5
# implementation. Swift-format histories are also replayed by the Swift verifier (README).

HOME2_K, HOME2_A = derived("r3/home2/signing"), derived("r3/home2/agreement")


def grant_home_k(chain, home_k, home_a, by, issued, signer, cos=(), label="Home"):
    acct = account_id(chain)
    req = request(acct, home_k, home_a, "server", {"serves": ["home"]}, label,
                  {"endpoints": [f"https://{label.lower().replace(' ', '')}.example/v1/accounts/" + acct]})
    return chain.add("grant", by, issued, signer, cos, request=req, terms={"serves": ["home"]}, shares=[])


def head_for(chain, seq, home, issued="2026-11-20T00:00:00Z"):
    return envelope({"protocol": "colophon/head/5", "account": account_id(chain),
                     "authority": {"seq": seq, "digest": sha(body_of(chain.envs[seq - 1]))}, "issued": issued,
                     "by": home.id}, home)


def receipt_by(chain, seq, home, received):
    body = {"protocol": "colophon/receipt/5", "account": account_id(chain),
            "entry": {"seq": seq, "digest": sha(body_of(chain.envs[seq - 1]))}, "received": received, "by": home.id}
    return {f"records/authority/{seq:08d}.{home.id}.receipt.json": envelope(body, home)}


def ctrl_call_on(chain, signer, rid, purpose="sign-in", origin=None, created="2026-11-20T00:00:30Z"):
    seq = len(chain.envs)
    body = {"protocol": "colophon/call/5", "account": account_id(chain),
            "asOf": {"seq": seq, "digest": sha(body_of(chain.envs[-1]))},
            "signer": {"controller": signer.id}, "key": b64(signer.point), "audience": "https://service.example",
            "purpose": purpose, "args": {"nonce": rid},
            "requestId": b64url(hashlib.sha256(("r3/" + rid).encode()).digest()), "created": created}
    return seal(body, signer, origin=origin)


CALL_VER = {"now": "2026-11-20T00:01:00Z", "audiences": ["https://service.example"], "controllerPurposes": ["sign-in"]}

# ---------------------------------------------------------------------------------------------
# Control rule counts the larger of old and new threshold (§8.4).
kr_ab = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(B, ["approve", "control"], "Laptop")], threshold=1)
c = Chain(); genesis(c, kr_ab, [A], adds=[B])
c1 = c.copy(); c1.add("keyring", A, ts(60), A, keyring=change(kr_ab, threshold=2))
write_case("control-raise-threshold-one-signer", c1, bad("badSignature", 2),
           "Raising threshold 1→2 needs two signers (the larger of old and new).", ["8.4"])
c2 = c.copy(); c2.add("keyring", A, ts(60), A, cos=[B], keyring=change(kr_ab, threshold=2))
write_case("control-raise-threshold-two-signers", c2, ok_at(2), "The same change signed by both.", ["8.4"])
c3 = c2.copy(); c3.add("keyring", A, ts(120), A, keyring=kr_ab)
write_case("control-lower-threshold-one-signer", c3, bad("badSignature", 3), "Lowering 2→1 with one signer.", ["8.4"])

# ---------------------------------------------------------------------------------------------
# Every recovery-set trigger, without and with recover signers (§6.3, §8.4).
kr_rs = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(K1, ["recover"], "Key 1"),
                 ctrl(K2, ["recover"], "Key 2")], threshold=1, rt=1)
base = Chain(); genesis(base, kr_rs, [A], adds=[K1, K2])


def k2_with(**fields):
    ctrls = []
    for x in kr_rs["controllers"]:
        x = json.loads(json.dumps(x))
        if cid(x) == K2.id:
            x.update(fields)
        ctrls.append(x)
    return change(kr_rs, controllers=ctrls)


k2_agree_changed = k2_with(key={"form": "raw", "signing": b64(K2.point), "agreement": b64(derived("r3/k2-agree").point)})
triggers = [
    ("demote-recover", k2_with(roles=["approve"]), [], "Removing `recover` from a recover key."),
    ("raise-recover-threshold", change(kr_rs, recoverThreshold=2), [], "Raising recoverThreshold 1→2."),
    ("change-recovery-delay", change(kr_rs, policy={"recoveryDelay": 86400}), [], "Changing recoveryDelay."),
    ("change-head-quorum", change(kr_rs, policy={"headQuorum": 1, "headMaxAge": 300}), None, None),
    ("raise-head-max-age", change(kr_rs, policy={"headMaxAge": 3600}), [], "Raising headMaxAge."),
    ("raise-call-window", change(kr_rs, policy={"callWindow": 600}), [], "Raising callWindow."),
    ("raise-link-max-age", change(kr_rs, policy={"linkMaxAge": 172800}), [], "Raising linkMaxAge."),
    ("history-public", change(kr_rs, policy={"history": "public"}), [], "history members→public."),
    ("recover-key-descriptor", k2_agree_changed, [], "Changing a recover key's agreement point (never slotted, no rotation)."),
    ("recover-key-holder", k2_with(holder="someone-else"), [K2], "Giving a recover key a holder (with its own signature)."),
]
for name, kr_new, adds, why in triggers:
    if why is None:
        continue
    t1 = base.copy(); t1.add("keyring", A, ts(60), A, adds=adds, keyring=kr_new)
    write_case(f"rs-{name}-control-only", t1, bad("badSignature", 2), why + " Control key alone.", ["6.3", "8.4"])
    t2 = base.copy(); t2.add("keyring", A, ts(60), A, cos=[K1], adds=adds, keyring=kr_new)
    write_case(f"rs-{name}-with-recover", t2, ok_at(2), why + " Also signed by K1.", ["6.3", "8.4"])
lower_ok = base.copy(); lower_ok.add("keyring", A, ts(60), A, keyring=change(kr_rs, policy={"headMaxAge": 120}))
write_case("lower-head-max-age-control-only", lower_ok, ok_at(2), "Lowering headMaxAge needs only the control rule.", ["6.3"])
h1 = base.copy(); grant_home_k(h1, HOME_K, HOME_A, A, ts(60), A)
write_case("rs-appoint-home-control-only", h1, bad("badSignature", 2), "Appointing a home with the control key alone.", ["6.3", "8.4"])
h2 = base.copy(); grant_home_k(h2, HOME_K, HOME_A, A, ts(60), A, cos=[K1])
write_case("rs-appoint-home-with-recover", h2, ok_at(2), "Appointing a home with K1 too.", ["6.3", "8.4"])
lab = base.copy(); lab.add("keyring", A, ts(60), A, cos=[K1], keyring=k2_with(holder="someone-else"))
write_case("holder-without-key-signature", lab, bad("badSignature", 2),
           "Labelling K2 with a holder without K2's own signature.", ["6.1", "8.4"])

# ---------------------------------------------------------------------------------------------
# A recovery account with two homes, headQuorum 2 (§8.4, §13.5).
kr_2h = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(K1, ["recover"], "Key 1"),
                 ctrl(K2, ["recover"], "Key 2")], threshold=1, rt=1)
acc = Chain(); genesis(acc, kr_2h, [A], adds=[K1, K2])
grant_home_k(acc, HOME_K, HOME_A, A, ts(60), A, cos=[K1], label="Home one")
grant_home_k(acc, HOME2_K, HOME2_A, A, ts(120), A, cos=[K1], label="Home two")
acc.add("keyring", A, ts(180), A, cos=[K1], keyring=change(kr_2h, policy={"headQuorum": 2}))
kr_2h_q2 = change(kr_2h, policy={"headQuorum": 2})
rec_issued = ts(3600)
rec = acc.copy(); rec.add("keyring", K1, rec_issued, K1, adds=[NK],
                          keyring=change(kr_2h_q2, controllers=kr_2h_q2["controllers"] + [ctrl(NK, ["approve", "control"], "Recovered phone")]))
r_h1 = receipt_by(rec, 5, HOME_K, ts(3601))
r_h2 = receipt_by(rec, 5, HOME2_K, ts(3700))
write_case("receipts-quorum", rec, {"result": "ok", "seq": 5, "activation": ts(3700 + 259200)},
           "Two receipts (headQuorum 2): activation runs from the later one.", ["8.4", "13.5"], extra={**r_h1, **r_h2})
write_case("receipts-one-of-two", rec, {"result": "held", "seq": 5, "why": "unavailable: 1 of 2 receipts"},
           "Only one of the two receipts.", ["8.4", "13.5"], extra=r_h1)
write_case("receipt-late", rec, {"result": "held", "seq": 5, "why": "receipt by home two is malformed (received > issued + 300 s)"},
           "A receipt 301 s after issued.", ["13.5"], extra={**r_h1, **receipt_by(rec, 5, HOME2_K, ts(3901))})
write_case("receipt-early", rec, {"result": "held", "seq": 5, "why": "receipt by home two is malformed (received < issued)"},
           "A receipt that predates issued.", ["13.5"], extra={**r_h1, **receipt_by(rec, 5, HOME2_K, ts(3599))})
write_case("receipt-non-home", rec, {"result": "held", "seq": 5, "why": "receipt by a non-home is malformed"},
           "A receipt signed by a key that is not a home.", ["13.5"], extra={**r_h1, **receipt_by(rec, 5, MK, ts(3610))})
full = acc.copy(); full.add("keyring", K1, rec_issued, K1, cos=[K2], adds=[NK],
                            keyring=change(kr_2h_q2, controllers=kr_2h_q2["controllers"] + [ctrl(NK, ["approve", "control"], "Recovered phone")]))
write_case("full-recovery-no-receipts", full, {"result": "ok", "seq": 5, "activation": rec_issued},
           "Every recover controller signs: no receipt and no delay (the way out when homes are gone).", ["8.4"])

# Calls by a delayed controller (§12.3 step 5).
write_case("call-by-delayed", rec, {"call": "refused:revoked"}, "The recovery-added key calls during its delay.", ["12.3"],
           extra={**r_h1, **r_h2, "call.json": ctrl_call_on(rec, NK, "delayed"),
                  "heads/one.json": head_for(rec, 5, HOME_K), "heads/two.json": head_for(rec, 5, HOME2_K)},
           verifier=CALL_VER)

# Attempt 2 and counter-recovery (§8.4).
cancel1 = rec.copy(); cancel1.add("keyring", A, ts(7200), A, keyring=kr_2h_q2)
att2_kr = change(kr_2h_q2, controllers=kr_2h_q2["controllers"] + [ctrl(MK, ["approve", "control"], "Second try")])
att2 = cancel1.copy(); att2.add("keyring", K1, ts(10800), K1, adds=[MK], keyring=att2_kr, attempt=2)
att_rcpt = {**r_h1, **r_h2, **receipt_by(att2, 7, HOME_K, ts(10801)), **receipt_by(att2, 7, HOME2_K, ts(10802))}
write_case("attempt-2", att2, {"result": "ok", "seq": 7, "activation": ts(10802 + 2 * 259200)},
           "After a cancel, K1 tries again with attempt 2: delayed twice as long.", ["8.4"], extra=att_rcpt)
solo = att2.copy(); solo.add("keyring", A, ts(14400), A, keyring=kr_2h_q2)
write_case("attempt-2-solo-cancel", solo, bad("badSignature", 8), "One control key can't cancel attempt 2.", ["8.4"], extra=att_rcpt)
counter = att2.copy(); counter.add("keyring", A, ts(14400), A, cos=[K2], keyring=kr_2h_q2)
write_case("attempt-2-counter-recovery", counter, ok_at(8), "A control key plus K2 (not a signer of attempt 2) cancels it.",
           ["8.4"], extra=att_rcpt)
not_cancel = att2.copy(); not_cancel.add("keyring", A, ts(14400), A,
                                         keyring=change(kr_2h_q2, controllers=[dict(x, label="Renamed") if cid(x) == A.id else x
                                                                                for x in kr_2h_q2["controllers"]]))
write_case("remove-delayed-by-control-rule", not_cancel, bad("badSignature", 8),
           "Removing the delayed key while also renaming A: not a cancel, and no other rule removes a delayed key.",
           ["8.4"], extra=att_rcpt)

# ---------------------------------------------------------------------------------------------
# Provisional controllers (§6.1).
kr_t2 = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(B, ["approve", "control"], "Laptop")], threshold=2)
p = Chain(); genesis(p, kr_t2, [A, B])
grant_home_k(p, HOME_K, HOME_A, A, ts(30), A, cos=[B])
prov_until = ts(60 + 7 * 86400)
p.add("keyring", A, ts(60), A, adds=[NK], keyring=change(kr_t2, controllers=kr_t2["controllers"] +
                                                           [ctrl(NK, ["approve"], "New passkey", until=prov_until)]))
kr_p1 = json.loads(body_of(p.envs[-1]))["keyring"]
heads_p = {"heads/one.json": head_for(p, 3, HOME_K)}
write_case("call-by-provisional", p, {"call": "ok"}, "The provisional key calls before `until`.", ["6.1", "12.3"],
           extra={**heads_p, "call.json": ctrl_call_on(p, NK, "prov-1")}, verifier=CALL_VER)
late_ver = dict(CALL_VER, now=ts(60 + 8 * 86400))
write_case("call-by-provisional-after-until", p, {"call": "refused:revoked"}, "The same call after `until`.", ["6.1", "12.3"],
           extra={"heads/one.json": head_for(p, 3, HOME_K, issued=ts(60 + 8 * 86400 - 30)),
                  "call.json": ctrl_call_on(p, NK, "prov-2", created=ts(60 + 8 * 86400 - 10))}, verifier=late_ver)
second = p.copy(); second.add("keyring", A, ts(120), A, adds=[MK],
                              keyring=change(kr_p1, controllers=kr_p1["controllers"] + [ctrl(MK, ["approve"], "Another", until=prov_until)]))
write_case("second-provisional", second, bad("malformed", 4), "A second provisional controller while one exists.", ["6.1"])
req_rec = request(account_id(p), AGENT_K, AGENT_A, "agent", {"records": [{"namespace": "notes", "access": "read"}]})
rg = p.copy(); rg.add("grant", NK, ts(120), NK, request=req_rec, terms={"records": [{"namespace": "notes", "access": "read"}]}, shares=[])
write_case("provisional-records-grant", rg, bad("badSignature", 4), "A provisional key grants `records`.", ["6.1"])
pb = Chain(); pb.envs = p.envs[:2]
pb.add("keyring", B, ts(60), B, adds=[NK], keyring=change(kr_t2, controllers=kr_t2["controllers"] +
                                                            [ctrl(NK, ["approve"], "New passkey", until=prov_until)]))
kr_pb = json.loads(body_of(pb.envs[-1]))["keyring"]
pb.add("keyring", A, ts(120), A, cos=[B],
       keyring=change(kr_pb, controllers=[x for x in kr_pb["controllers"] if cid(x) != B.id], threshold=1))
req_svc = request(account_id(p), AGENT_K, AGENT_A, "agent", {"services": [{"audience": AUD, "purposes": ["task.read"]}]})
pb.add("grant", NK, ts(180), NK, request=req_svc, terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]}, shares=[])
write_case("provisional-sponsor-removed", pb, bad("badSignature", 5),
           "B sponsored the provisional key; after B is removed (never slotted, so no rotation), the key's grant doesn't count.",
           ["6.1"])

# ---------------------------------------------------------------------------------------------
# Equivocation by a removed key (§8.6 rule 1), with a home head covering the honest branch.
kr_an = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(NK, ["approve"], "Tablet")], threshold=1)
e = Chain(); genesis(e, kr_an, [A], adds=[NK]); grant_home_k(e, HOME_K, HOME_A, A, ts(30), A)
e.add("keyring", A, ts(60), A, keyring=change(kr_an, controllers=[x for x in kr_an["controllers"] if cid(x) != NK.id]))
e.add("keyring", A, ts(90), A, keyring=change(json.loads(body_of(e.envs[-1]))["keyring"], policy={"headMaxAge": 120}))
rival = Chain(); rival.envs = e.envs[:2]
req_r = request(account_id(e), AGENT_K, AGENT_A, "agent", {"services": [{"audience": AUD, "purposes": ["task.read"]}]})
rival.add("grant", NK, ts(61), NK, request=req_r, terms={"services": [{"audience": AUD, "purposes": ["task.read"]}]}, shares=[])
write_case("removed-key-equivocation", e, {"result": "ok", "seq": 4, "evidence": sha(body_of(rival.envs[2]))},
           "The removed key signs a valid rival at seq 3, which no home covers: evidence, not a fork.", ["8.6"],
           extra={"heads/one.json": head_for(e, 4, HOME_K)}, branches={"rival": [(3, rival.envs[2])]})

# A vouched fork: each branch covered by a different home (§8.6 rule 3).
vf = Chain(); genesis(vf, kr_one, [A], adds=[K1])
grant_home_k(vf, HOME_K, HOME_A, A, ts(30), A, cos=[K1], label="Home one")
grant_home_k(vf, HOME2_K, HOME2_A, A, ts(40), A, cos=[K1], label="Home two")
kr_v = json.loads(body_of(vf.envs[0]))["keyring"]
va = vf.copy(); va.add("keyring", A, ts(60), A, keyring=change(kr_v, policy={"headMaxAge": 120}))
vb = vf.copy(); vb.add("keyring", A, ts(61), A, keyring=change(kr_v, policy={"headMaxAge": 60}))
vheads = {"heads/one.json": head_for(va, 4, HOME_K), "heads/two.json": head_for(vb, 4, HOME2_K)}
write_case("vouched-fork", va, {"result": "refused:fork", "seq": 4}, "Two homes vouch for different entries at seq 4.",
           ["8.6"], extra=vheads, branches={"b": [(4, vb.envs[3])]})
vr = va.copy(); vr.add("resolve", A, ts(120), A, cos=[K1], discarded={"seq": 4, "digest": sha(body_of(vb.envs[3]))})
write_case("vouched-fork-resolved", vr, ok_at(5), "Resolve under control and recovery-set rules.", ["8.6"], extra=vheads,
           branches={"b": [(4, vb.envs[3])]})
vr2 = va.copy(); vr2.add("resolve", A, ts(120), A, discarded={"seq": 4, "digest": sha(body_of(vb.envs[3]))})
write_case("vouched-resolve-without-recovery", vr2, {"result": "refused:fork", "seq": 4, "why": "resolve at 5 is badSignature"},
           "Resolve without the recovery quorum.", ["8.6"], extra=vheads, branches={"b": [(4, vb.envs[3])]})

# A malleated envelope: s → n − s over the same body (§2.2, §8.6).
m = Chain(); genesis(m, kr_t1, [A])
env = dict(m.envs[0]); sig = unb64(env["signature"])
s_val = int.from_bytes(sig[32:], "big"); env["signature"] = b64(sig[:32] + (N - s_val).to_bytes(32, "big"))
assert verify_raw(A.point, body_of(env), unb64(env["signature"]))
write("rules/malleated-envelope/original.json", m.envs[0]); write("rules/malleated-envelope/malleated.json", env)
write("rules/malleated-envelope/case.json", {"description": "The same body with s replaced by n − s. Both verify; they are one entry.",
                                             "sections": ["2.2", "8.6", "14"], "expected": {"equal": True, "home": "200, keeps the first"}})

# ---------------------------------------------------------------------------------------------
# Swift predecessors with WebAuthn controllers, a recovery-added freeze, and rotateRecovery.
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


wr = swift_webauthn_library()
same = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "recover"], "Passkey", verification=True),
        ctrl(SY, ["approve", "control"], "Security key", verification=True)]
g_same = genesis_from(wr, same, 1)
write_swift("swift-webauthn", wr + [swift_freeze_signed(wr, account_id(g_same), SY)], g_same,
            {"genesis": "ok", "succession": "verified"},
            "Swift library with a passkey (approve, recover) and a security key (approve, control), as the shipped app makes "
            "them. The security key signs F with WebAuthn; the genesis keeps the same roles.")
swap = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "control"], "Passkey", verification=True),
        ctrl(SY, ["approve", "recover"], "Security key", verification=True)]
g_swap = genesis_from(wr, swap, 1, label="Swapped")
write_swift("swift-webauthn-role-swap-without-consent", wr + [swift_freeze_signed(wr, account_id(g_swap), SY)], g_swap,
            {"genesis": "ok", "succession": "unverified"},
            "The genesis swaps which key recovers, with no handover by the old recover key (§15.1 rule 4).")
g_swap2 = genesis_from(wr, swap, 1, handover=[SP], label="Swapped with consent")
write_swift("swift-webauthn-role-swap-with-consent", wr + [swift_freeze_signed(wr, account_id(g_swap2), SY)], g_swap2,
            {"genesis": "ok", "succession": "verified"}, "The same swap with the old passkey's handover signature.")

ra = swift_webauthn_library(recover_add=True)
g_ra = genesis_from(ra, same + [ctrl(MK, ["approve", "control"], "Thief")], 1, label="Recovered")
refusal = envelope({"protocol": "colophon/refusal/5", "predecessor": sha(unb64(ra[0]["body"]))[:32],
                    "successor": account_id(g_ra), "issued": "2026-11-11T09:00:00Z", "by": A.id}, A)
write_swift("swift-recovery-added-freeze", ra + [swift_freeze_signed(ra, account_id(g_ra), MK)], g_ra,
            {"genesis": "ok", "succession": "pending until the successor's activation; unverified with refusal.json"},
            "The passkey's Swift recovery path adds a control key, which signs F at once (§15.1 rule 6).",
            extra_recs={"refusal.json": refusal})

# rotateRecovery in a root library (§15.1 rule 5).
recsR, _ = swift_library(adopt=False)
rec2_s, rec2_a = derived("swift/recovery2/signing"), derived("swift/recovery2/agreement")
rot = {"by": "root", "issued": "2026-11-05T08:00:00Z", "kind": "rotateRecovery", "previous": sha(unb64(recsR[0]["body"])),
       "recovery": pid(rec2_s, rec2_a), "seq": 2}
recsR.append(swift_record(rot, root_s))
predR = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recsR[0]["body"]))[:32],
         "head": {"seq": 2, "digest": sha(unb64(recsR[1]["body"]))}}
gR1 = Chain(); genesis(gR1, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                       predecessor=predR, handover=[rec2_s], label="Current recovery only")
write_swift("swift-rotate-recovery-current-only", recsR + [swift_freeze(recsR, account_id(gR1), root_s, root=True)], gR1,
            {"genesis": "ok", "succession": "unverified"},
            "Root rotated recovery; handover carries the root (as F) and the new recovery identity only.")
gR2 = Chain(); genesis(gR2, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                       predecessor=predR, handover=[rec2_s, rec_s, root_s], label="All identities")
write_swift("swift-rotate-recovery-all", recsR + [swift_freeze(recsR, account_id(gR2), root_s, root=True)], gR2,
            {"genesis": "ok", "succession": "verified"},
            "The same with the genesis recovery identity and the root also in handover.")
