# Revision 4: pending transitions with veto (spec §8.4, §8.7), executed by rules.py in the
# generate.py namespace. Every expected outcome is the author's reading of the spec; none has
# been replayed by a 0.5 implementation.

D = 259200  # recoveryDelay default, seconds
H1K, H1A = derived("r4/home1/signing"), derived("r4/home1/agreement")
H2K, H2A = derived("r4/home2/signing"), derived("r4/home2/agreement")
P = derived("r4/passkey")      # a third owner control key in some scenarios
NEW = derived("r4/new-device")  # a key added by recovery


def anchor(chain):
    return {"seq": len(chain.envs), "digest": sha(body_of(chain.envs[-1]))}


def transition(chain, change, signers, issued, adds=(), origin=None, account=None):
    primary, *cos = signers
    body = {"protocol": "colophon/transition/5", "account": account or account_id(chain), "anchor": anchor(chain),
            "issued": issued, "by": primary.id, "change": change}
    return seal(body, primary, cos, adds, origin=origin)


def receipt_of(acct, env, home, received):
    return envelope({"protocol": "colophon/receipt/5", "account": acct, "object": sha(body_of(env)),
                     "received": received, "by": home.id}, home)


def veto_of(acct, t_env, signers, issued):
    primary, *cos = signers
    return seal({"protocol": "colophon/veto/5", "account": acct, "transition": sha(body_of(t_env)), "issued": issued,
                 "by": primary.id}, primary, cos)


def activate(chain, t_env, receipts, by, issued, **extra):
    return chain.add("activate", by, issued, by, transition=b64(env_bytes(t_env)),
                     receipts=[b64(env_bytes(r)) for r in receipts], **extra)


def record_veto(chain, t_env, v_env, receipts, by, issued):
    return chain.add("vetoed", by, issued, by, transition=b64(env_bytes(t_env)), veto=b64(env_bytes(v_env)),
                     receipts=[b64(env_bytes(r)) for r in receipts])


def home_appointment(acct, home_k, home_a, label):
    req = request(acct, home_k, home_a, "server", {"serves": ["home"]}, label,
                  {"endpoints": [f"https://{label.lower().replace(' ', '')}.example/v1/accounts/{acct}"]})
    return {"request": req, "terms": {"serves": ["home"]}}


def files(prefix, objs):
    return {f"{prefix}/{name}.json": env for name, env in objs.items()}


def case(name, chain, expected, why, sections, objs=None, verifier=None, branches=None):
    write_case(name, chain, expected, why, sections, extra=files("objects", objs or {}), verifier=verifier,
               branches=branches)


# ---------------------------------------------------------------------------------------------
# The base account: device key A (slot), passkey B, security keys K1 and K2 (recover only),
# threshold 1, recoverThreshold 1, one home H1 appointed at seq 2. With no home yet, the
# appointment transition is due when issued (§8.7 "No home").
kr4 = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(B, ["approve", "control"], "Passkey"),
               ctrl(K1, ["recover"], "Security key 1"), ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
base = Chain(); genesis(base, kr4, [A], adds=[B, K1, K2])
acct4 = account_id(base)
t_home = transition(base, {"homes": {"appoint": [home_appointment(acct4, H1K, H1A, "Home one")]}}, [A, K1], ts(60))
activate(base, t_home, [], A, ts(60))
R0 = 3600  # proposals start one hour in


def proposal(change, signers, at=R0, adds=(), chain=None):
    return transition(chain or base, change, signers, ts(at), adds=adds)


def due(received):
    return received + D


# 1. A plain pending removal, received, waits D, activates.
t1 = proposal({"keyring": {"remove": [B.id]}}, [A])
r1 = receipt_of(acct4, t1, H1K, ts(R0 + 1))
c = base.copy(); activate(c, t1, [r1], H1K, ts(due(R0 + 1) + 60))
case("t-remove-after-delay", c, ok_at(3), "Remove the lost passkey: pending, received, activated after D.", ["8.7"],
     {"transition": t1, "receipt": r1})
c = base.copy(); activate(c, t1, [r1], H1K, ts(due(R0 + 1) - 60))
case("t-activate-early", c, {"result": "held", "seq": 3, "why": "transition not yet due"},
     "The same activation one minute before the due time.", ["8.5", "8.7"], {"transition": t1, "receipt": r1})
c = base.copy(); activate(c, t1, [r1], H1K, ts(due(R0 + 1) + 8 * 86400))
case("t-activate-expired", c, bad("malformed", 3), "Appended eight days after due: void.", ["8.7"],
     {"transition": t1, "receipt": r1})
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr4, controllers=[x for x in kr4["controllers"] if cid(x) != B.id]))
case("i-removal-as-immediate", c, bad("malformed", 3), "A removal written as an immediate keyring entry.", ["8.4"])

# 2. Veto in time, late veto, veto by too few keys, veto by the removal's target.
v1 = veto_of(acct4, t1, [B], ts(R0 + 600))
rv1 = receipt_of(acct4, v1, H1K, ts(R0 + 601))
c = base.copy(); record_veto(c, t1, v1, [r1, rv1], H1K, ts(R0 + 700))
case("t-vetoed-by-target", c, ok_at(3), "The passkey vetoes its own removal: a key the transition removes counts.", ["8.7"],
     {"transition": t1, "veto": v1})
c2 = c.copy(); activate(c2, t1, [r1], H1K, ts(due(R0 + 1) + 60))
case("t-activate-after-veto", c2, bad("malformed", 4), "Activating a vetoed transition.", ["8.7"])
v_late = veto_of(acct4, t1, [B], ts(due(R0 + 1) + 10))
rv_late = receipt_of(acct4, v_late, H1K, ts(due(R0 + 1) + 11))
c = base.copy(); activate(c, t1, [r1], H1K, ts(due(R0 + 1) + 60))
case("t-late-veto", c, ok_at(3), "A veto received after the due time doesn't count.", ["8.7"],
     {"transition": t1, "veto": v_late, "veto-receipt": rv_late})
t2 = proposal({"keyring": {"remove": [K2.id]}}, [A, K1])
r2 = receipt_of(acct4, t2, H1K, ts(R0 + 2))
v2 = veto_of(acct4, t2, [B], ts(R0 + 600))
c = base.copy(); record_veto(c, t2, v2, [r2, receipt_of(acct4, v2, H1K, ts(R0 + 601))], H1K, ts(R0 + 700))
case("t-veto-too-few", c, bad("malformed", 3), "A two-signer transition vetoed by one key: the veto is invalid.", ["8.7"],
     {"transition": t2, "veto": v2})

# 3. Escalation: after a veto, the vetoed key can't propose alone; with one more signer it can.
vetoed_chain = base.copy(); record_veto(vetoed_chain, t1, v1, [r1, rv1], H1K, ts(R0 + 700))
t_again = proposal({"keyring": {"remove": [B.id]}}, [A], at=R0 + 800, chain=vetoed_chain)
c = vetoed_chain.copy(); activate(c, t_again, [receipt_of(acct4, t_again, H1K, ts(R0 + 801))], H1K, ts(due(R0 + 801) + 60))
case("t-escalation-alone", c, bad("badSignature", 4), "A was vetoed once (v=1): its next transition needs two signers.",
     ["8.7"])
t_two = proposal({"keyring": {"remove": [B.id]}}, [A, K1], at=R0 + 800, chain=vetoed_chain)
r_two = receipt_of(acct4, t_two, H1K, ts(R0 + 801))
c = vetoed_chain.copy(); activate(c, t_two, [r_two], H1K, ts(due(R0 + 801) + 60))
case("t-escalation-two", c, ok_at(4), "The same with A and K1: accepted.", ["8.7"], {"transition": t_two, "receipt": r_two})
v_one = veto_of(acct4, t_two, [B], ts(R0 + 900))
c = vetoed_chain.copy(); record_veto(c, t_two, v_one, [r_two, receipt_of(acct4, v_one, H1K, ts(R0 + 901))], H1K, ts(R0 + 1000))
case("t-escalation-veto-too-few", c, bad("malformed", 4), "B alone can't veto a two-signer transition.", ["8.7"])

# 4. Full set: every control holder signs (two keys): due at once, no veto.
t_full = proposal({"keyring": {"remove": [B.id]}}, [A, B])
c = base.copy(); activate(c, t_full, [], A, ts(R0))
case("t-full-set", c, ok_at(3), "A and B (every control holder) remove B: immediate.", ["8.7"], {"transition": t_full})
kr_one = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(K1, ["recover"], "Security key 1")], threshold=1, rt=1)
solo = Chain(); genesis(solo, kr_one, [A], adds=[K1]); acct_solo = account_id(solo)
activate(solo, transition(solo, {"homes": {"appoint": [home_appointment(acct_solo, H1K, H1A, "Home one")]}}, [A, K1], ts(60)),
         [], A, ts(60))
t_solo = transition(solo, {"policy": {"headMaxAge": 600}}, [A], ts(R0))
c = solo.copy(); activate(c, t_solo, [], A, ts(R0))
case("t-full-set-one-key", c, {"result": "held", "seq": 3, "why": "a full set of one key is not immediate"},
     "One control key signs: still needs receipts and the delay.", ["8.7"], {"transition": t_solo})

# 5. Recovery-set consent.
k2_demoted = [dict(json.loads(json.dumps(x)), roles=["approve"]) if cid(x) == K2.id else x for x in kr4["controllers"]]
t_dem = proposal({"keyring": {"update": [x for x in k2_demoted if cid(x) == K2.id]}}, [A])
c = base.copy(); activate(c, t_dem, [receipt_of(acct4, t_dem, H1K, ts(R0 + 1))], H1K, ts(due(R0 + 1) + 60))
case("t-demote-recover-no-consent", c, bad("badSignature", 3), "Demoting K2 without a recover signer.", ["8.4"])
t_dem2 = proposal({"keyring": {"update": [x for x in k2_demoted if cid(x) == K2.id]}}, [A, K1])
c = base.copy(); activate(c, t_dem2, [receipt_of(acct4, t_dem2, H1K, ts(R0 + 1))], H1K, ts(due(R0 + 1) + 60))
case("t-demote-recover-with-consent", c, ok_at(3), "The same with K1.", ["8.4"])
t_thr = proposal({"keyring": {"threshold": 2}}, [A, B])
c = base.copy(); activate(c, t_thr, [receipt_of(acct4, t_thr, H1K, ts(R0 + 1))], H1K, ts(due(R0 + 1) + 60))
case("t-raise-threshold-no-consent", c, bad("badSignature", 3),
     "Raising threshold needs recovery-set consent (otherwise a thief locks out recovery).", ["8.4"])

# 6. Void at activation: a signer removed first; a delta that breaks §6.
t_rm_b = proposal({"keyring": {"remove": [B.id]}}, [A])
t_by_b = proposal({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "B's friend")]}}, [B], at=R0 + 10, adds=[NEW])
c = base.copy()
activate(c, t_rm_b, [receipt_of(acct4, t_rm_b, H1K, ts(R0 + 1))], H1K, ts(due(R0 + 1) + 60))
activate(c, t_by_b, [receipt_of(acct4, t_by_b, H1K, ts(R0 + 11))], H1K, ts(due(R0 + 11) + 60))
case("t-signer-removed-first", c, bad("malformed", 4), "B's own transition is void once B is removed.", ["8.7"])
t_all = proposal({"keyring": {"remove": [A.id, B.id]}}, [A, B])
c = base.copy(); activate(c, t_all, [], A, ts(R0))
case("t-breaks-keyring", c, bad("malformed", 3), "Removing every control key: the result breaks §6.2.", ["8.7"])

# 7. Ordering at one seq (§8.6 rule 1).
c = base.copy(); record_veto(c, t1, v1, [r1, rv1], H1K, ts(R0 + 700))
alt = base.copy(); activate(alt, t1, [r1], H1K, ts(due(R0 + 1) + 60))
case("t-vetoed-beats-activate", c, ok_at(3), "vetoed and activate for one transition at seq 3: the veto was in time.",
     ["8.6"], branches={"activate": [(3, alt.envs[2])]})
ordinary = base.copy(); grant_agent(ordinary, A, ts(due(R0 + 1) + 30), A)
c = base.copy(); activate(c, t1, [r1], H1K, ts(due(R0 + 1) + 60))
case("t-activate-beats-ordinary", c, ok_at(3), "A due activation and an ordinary grant at seq 3: the activation stands.",
     ["8.6"], branches={"ordinary": [(3, ordinary.envs[2])]})

# 8. Immediate classification and headroom (§6.2, §8.4).
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=[NEW],
                       keyring=change(kr4, controllers=kr4["controllers"] + [ctrl(NEW, ["approve"], "Tablet")]))
case("i-add-approve", c, ok_at(3), "Adding an approve-only key is immediate.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=[NEW],
                       keyring=change(kr4, controllers=kr4["controllers"] + [ctrl(NEW, ["approve", "control"], "Tablet")]))
case("i-add-control-immediate", c, bad("malformed", 3), "Adding a control key as an immediate entry.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr4, policy={"headMaxAge": 120}))
case("i-lower-head-max-age", c, ok_at(3), "Lowering headMaxAge (tightening) is immediate.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr4, policy={"headMaxAge": 3600}))
case("i-raise-head-max-age", c, bad("malformed", 3), "Raising headMaxAge as an immediate entry.", ["8.4"])
fillers = [derived(f"r4/filler/{i}") for i in range(53)]
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=fillers[:52],
                       keyring=change(kr4, controllers=kr4["controllers"] + [ctrl(k, ["approve"], f"Filler {i}") for i, k in enumerate(fillers[:52])]))
case("i-headroom-56", c, ok_at(3), "Immediate additions up to 56 controllers.", ["6.2"])
kr56 = json.loads(body_of(c.envs[-1]))["keyring"]
c.add("keyring", A, ts(R0 + 60), A, adds=[fillers[52]],
      keyring=change(kr56, controllers=kr56["controllers"] + [ctrl(fillers[52], ["approve"], "Filler 52")]))
case("i-headroom-57", c, bad("malformed", 4), "A 57th controller by an immediate entry.", ["6.2"])

# 9. Calls by keys whose change is pending (§12.3).
head4 = lambda chain: envelope({"protocol": "colophon/head/5", "account": account_id(chain),
                                "authority": {"seq": len(chain.envs), "digest": sha(body_of(chain.envs[-1]))},
                                "issued": ts(R0 + 1000), "by": H1K.id}, H1K)


def call_on(chain, signer, rid):
    body = {"protocol": "colophon/call/5", "account": account_id(chain), "asOf": anchor(chain),
            "signer": {"controller": signer.id}, "key": b64(signer.point), "audience": "https://service.example",
            "purpose": "sign-in", "args": {"nonce": rid},
            "requestId": b64url(hashlib.sha256(("r4/" + rid).encode()).digest()), "created": ts(R0 + 1010)}
    return seal(body, signer)


ver4 = {"now": ts(R0 + 1020), "audiences": ["https://service.example"], "controllerPurposes": ["sign-in"]}
t_add_new = proposal({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")]}}, [K1], adds=[NEW])
case("call-by-pending-addition", base, {"call": "refused:revoked"}, "NEW's addition is pending: it isn't a controller yet.",
     ["8.7", "12.3"], {"transition": t_add_new, "receipt": receipt_of(acct4, t_add_new, H1K, ts(R0 + 1)),
                       "call": call_on(base, NEW, "pending-add"), "head": head4(base)}, verifier=ver4)
case("call-by-pending-removal", base, {"call": "ok"}, "B's removal is pending: B keeps working until activation.",
     ["8.7", "12.3"], {"transition": t1, "receipt": r1, "call": call_on(base, B, "pending-rm"), "head": head4(base)},
     verifier=ver4)

# 10. Controller calls with a WebAuthn passkey and call origins (§4.3, §12.3).
kr_p = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(P_pin, ["approve", "control"], "Passkey", verification=True),
                ctrl(K1, ["recover"], "Kit")], rt=1)
cc = Chain(); genesis(cc, kr_p, [A], adds=[K1, P_pin], origin="https://keys.id.example"); acct_cc = account_id(cc)
activate(cc, transition(cc, {"homes": {"appoint": [home_appointment(acct_cc, H1K, H1A, "Home one")]}}, [A, K1], ts(60)), [], A, ts(60))
ver_cc = {"now": ts(R0 + 1020), "audiences": ["https://service.example"],
          "callOrigins": {"id.example": ["https://sign.id.example"]}, "controllerPurposes": ["sign-in"]}


def ctrl_call(signer, origin, rid):
    body = {"protocol": "colophon/call/5", "account": acct_cc, "asOf": anchor(cc), "signer": {"controller": signer.id},
            "key": b64(signer.point), "audience": "https://service.example", "purpose": "sign-in", "args": {"nonce": rid},
            "requestId": b64url(hashlib.sha256(("ctrl/" + rid).encode()).digest()), "created": ts(R0 + 1010)}
    return seal(body, signer, origin=origin)


for name, env, expected, why in [
    ("controller-call", ctrl_call(P_pin, "https://sign.id.example", "c1"), "ok", "Passkey call from the call origin."),
    ("controller-call-wrong-origin", ctrl_call(P_pin, "https://keys.id.example", "c2"), "refused:origin",
     "The same call from the authority origin."),
    ("controller-call-recover-only", ctrl_call(K1, None, "c3"), "refused:outOfScope", "A recover-only key calls."),
]:
    case(name, cc, {"call": expected}, why, ["12.3"], {"call": env, "head": head4(cc)}, verifier=ver_cc)

# ---------------------------------------------------------------------------------------------
# 11. The who-wins rows (§8.7) as event sequences. "events" lists objects in order with the
# outcome each one should get.


def scenario(name, chain, events, final, why):
    objs = {f"{i + 1:02d}-{label}": env for i, (label, env, _) in enumerate(events)}
    write_case(name, chain, {"events": [{"object": f"{i + 1:02d}-{label}", "outcome": out}
                                        for i, (label, _, out) in enumerate(events)], "final": final},
               why, ["8.7"], extra=files("events", objs))


# Thief holds B (one control key).
s = base.copy()
ta = proposal({"keyring": {"remove": [A.id]}}, [B], at=R0)
va = veto_of(acct4, ta, [K1], ts(R0 + 300))
record_veto(s, ta, va, [receipt_of(acct4, ta, H1K, ts(R0 + 1)), receipt_of(acct4, va, H1K, ts(R0 + 301))], H1K, ts(R0 + 400))
ta2 = proposal({"keyring": {"remove": [A.id]}}, [B], at=R0 + 500, chain=s)
tb = proposal({"keyring": {"remove": [B.id]}}, [A], at=R0 + 600, chain=s)
vb = veto_of(acct4, tb, [B], ts(R0 + 700))
record_veto(s, tb, vb, [receipt_of(acct4, tb, H1K, ts(R0 + 601)), receipt_of(acct4, vb, H1K, ts(R0 + 701))], H1K, ts(R0 + 800))
tb2 = proposal({"keyring": {"remove": [B.id]}}, [A, K1], at=R0 + 900, chain=s)
vb2 = veto_of(acct4, tb2, [B], ts(R0 + 1000))
rb2 = receipt_of(acct4, tb2, H1K, ts(R0 + 901))
activate(s, tb2, [rb2], H1K, ts(due(R0 + 901) + 60))
scenario("row-thief-one-control-key", s, [
    ("thief-removes-owner", ta, "vetoed by K1 (seq 3)"),
    ("veto-K1", va, "valid"),
    ("thief-again-alone", ta2, "refused: v(B)=1 needs 2 signers"),
    ("owner-removes-thief", tb, "vetoed by B (seq 4)"),
    ("veto-by-thief", vb, "valid"),
    ("owner-again-with-K1", tb2, f"activates at seq 5 after D ({ts(due(R0 + 901))})"),
    ("thief-veto-alone", vb2, "invalid: two-signer transition needs two vetoers"),
], {"controllers": sorted([A.id, K1.id, K2.id])}, "Thief with one control key: owner wins after D (plus minutes).")

# Thief holds K1 (one recovery key).
s = base.copy()
tr = proposal({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "Thief phone")], "remove": [A.id, B.id]}}, [K1], adds=[NEW])
vr = veto_of(acct4, tr, [A], ts(R0 + 300))
record_veto(s, tr, vr, [receipt_of(acct4, tr, H1K, ts(R0 + 1)), receipt_of(acct4, vr, H1K, ts(R0 + 301))], H1K, ts(R0 + 400))
tr2 = proposal({"keyring": {"remove": [A.id]}}, [K1], at=R0 + 500, chain=s)
to = proposal({"keyring": {"remove": [K1.id]}}, [A, K2], at=R0 + 600, chain=s)
ro = receipt_of(acct4, to, H1K, ts(R0 + 601))
activate(s, to, [ro], H1K, ts(due(R0 + 601) + 60))
scenario("row-thief-one-recovery-key", s, [
    ("thief-recovery", tr, "vetoed by A"), ("veto-A", vr, "valid"),
    ("thief-again-alone", tr2, "refused: v(K1)=1"),
    ("owner-removes-K1", to, "activates after D"),
], {"controllers": sorted([A.id, B.id, K2.id])}, "Thief with one recovery key: owner wins after D.")

# Owner has both recovery keys and no device: full recovery set, at once.
s = base.copy()
tf = proposal({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")], "remove": [A.id, B.id]}}, [K1, K2], adds=[NEW])
activate(s, tf, [], K1, ts(R0))
scenario("row-both-recovery-keys-no-device", s, [("full-recovery", tf, "activates at once (full recovery set, two keys)")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "Both security keys together: back in at once.")
scenario("row-burglar-both-recovery-keys", s, [("burglar-full-recovery", tf, "activates at once: the burglar wins")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "The same bytes signed by a burglar holding both keys.")

# Honest mistake: recovery started, phone found.
s = base.copy()
th = proposal({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")], "remove": [A.id]}}, [K1], adds=[NEW])
vh = veto_of(acct4, th, [A], ts(R0 + 3600))
record_veto(s, th, vh, [receipt_of(acct4, th, H1K, ts(R0 + 1)), receipt_of(acct4, vh, H1K, ts(R0 + 3601))], H1K, ts(R0 + 3700))
scenario("row-honest-mistake", s, [("recovery", th, "vetoed"), ("found-phone-veto", vh, "valid")],
         {"controllers": sorted([A.id, B.id, K1.id, K2.id])}, "The found phone vetoes; nothing changes.")

# Thief holds one control and one recovery key (B, K1); the owner holds A, P and K2.
kr5 = keyring([ctrl(A, ["approve", "control"], "Device"), ctrl(P, ["approve", "control"], "Passkey"),
               ctrl(B, ["approve", "control"], "Laptop"), ctrl(K1, ["recover"], "Security key 1"),
               ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
s = Chain(); genesis(s, kr5, [A], adds=[P, B, K1, K2]); acct5 = account_id(s)
activate(s, transition(s, {"homes": {"appoint": [home_appointment(acct5, H1K, H1A, "Home one")]}}, [A, K1], ts(60)), [], A, ts(60))
tx = transition(s, {"keyring": {"remove": [A.id, P.id, K2.id]}}, [B, K1], ts(R0))
vx = veto_of(acct5, tx, [A, K2], ts(R0 + 300))
record_veto(s, tx, vx, [receipt_of(acct5, tx, H1K, ts(R0 + 1)), receipt_of(acct5, vx, H1K, ts(R0 + 301))], H1K, ts(R0 + 400))
tx2 = transition(s, {"keyring": {"remove": [A.id, P.id, K2.id]}}, [B, K1], ts(R0 + 500))
vx2 = veto_of(acct5, tx2, [P, K2], ts(R0 + 600))
record_veto(s, tx2, vx2, [receipt_of(acct5, tx2, H1K, ts(R0 + 501)), receipt_of(acct5, vx2, H1K, ts(R0 + 601))], H1K, ts(R0 + 700))
tx3 = transition(s, {"keyring": {"remove": [A.id]}}, [B, K1], ts(R0 + 800))
toy = transition(s, {"keyring": {"remove": [B.id, K1.id]}}, [A, P, K2], ts(R0 + 900))
vy = veto_of(acct5, toy, [B, K1], ts(R0 + 1000))
ry = receipt_of(acct5, toy, H1K, ts(R0 + 901))
activate(s, toy, [ry], H1K, ts(due(R0 + 901) + 60))
scenario("row-thief-control-and-recovery", s, [
    ("thief-proposes", tx, "vetoed by A and K2"), ("owner-veto-1", vx, "valid (two vetoers for two signers)"),
    ("thief-again", tx2, "valid: v=1 needs 2 signers, has 2; vetoed by P and K2"), ("owner-veto-2", vx2, "valid"),
    ("thief-third", tx3, "refused: v(B)=v(K1)=2 needs 3 signers"),
    ("owner-removes-thief", toy, "three signers; activates after D"),
    ("thief-veto", vy, "invalid: three-signer transition needs three vetoers"),
], {"controllers": sorted([A.id, P.id, K2.id])}, "Thief with two keys against an owner with three: owner wins after D.")

# Two homes, the thief's home hostile: the owner's veto at the other home beats the activation.
kr6 = kr4
s = Chain(); genesis(s, kr6, [A], adds=[B, K1, K2], label="Two homes"); acct6 = account_id(s)
activate(s, transition(s, {"homes": {"appoint": [home_appointment(acct6, H1K, H1A, "Home one"),
                                                   home_appointment(acct6, H2K, H2A, "Home two")]}}, [A, K1], ts(60)), [], A, ts(60))
tt = transition(s, {"keyring": {"remove": [A.id]}}, [B], ts(R0))
r_hostile = receipt_of(acct6, tt, H1K, ts(R0 + 1))
vt = veto_of(acct6, tt, [K1], ts(R0 + 300))
rv_h2 = receipt_of(acct6, vt, H2K, ts(R0 + 301))
hostile = s.copy(); activate(hostile, tt, [r_hostile], H1K, ts(due(R0 + 1) + 60))
honest = s.copy(); record_veto(honest, tt, vt, [receipt_of(acct6, tt, H2K, ts(R0 + 2)), rv_h2], H2K, ts(R0 + 400))
case("row-hostile-home-second-home", honest, ok_at(3),
     "Home one (hostile) activates the thief's removal of A and hides the veto; home two records the veto: vetoed stands.",
     ["8.6", "8.7"], {"transition": tt, "veto": vt}, branches={"hostile": [(3, hostile.envs[2])]})

# Equivocation by a removed key (§8.6 rule 2).
e = base.copy(); activate(e, t_full, [], A, ts(R0))
rival = base.copy(); grant_agent(rival, B, ts(R0 + 1), B)
heads_e = envelope({"protocol": "colophon/head/5", "account": acct4, "authority": anchor(e), "issued": ts(R0 + 60),
                    "by": H1K.id}, H1K)
case("removed-key-equivocation", e, {"result": "ok", "seq": 3, "evidence": sha(body_of(rival.envs[2]))},
     "B signs a rival at seq 3 that no home covers: evidence, not a fork.", ["8.6"], {"head": heads_e},
     branches={"rival": [(3, rival.envs[2])]})

# ---------------------------------------------------------------------------------------------
# 12. Swift succession as a pending transition (§15.1, §16.2, §16.3).
SH, SHA_ = derived("r4/successor-home/signing"), derived("r4/successor-home/agreement")
SR0 = 7200


def successor_with_home(g):
    acct = account_id(g)
    known = {k.id: k for k in (A, B, K1, K2, MK, NK, SP, SY)}
    ctrls = json.loads(body_of(g.envs[0]))["keyring"]["controllers"]
    rec = [known[cid(x)] for x in ctrls if "recover" in x["roles"]][:1]
    activate(g, transition(g, {"homes": {"appoint": [home_appointment(acct, SH, SHA_, "Successor home")]}},
                           [A] + rec, ts(SR0 - 60), origin="https://id.example"), [], A, ts(SR0 - 60))
    return receipt_of(acct, g.envs[0], SH, ts(SR0))


def swift_case(name, recs, g, f_issued_offset, expected, why, extra=None, signer=A, freeze=None):
    rg = successor_with_home(g)
    f = (freeze or swift_freeze_signed)(recs, account_id(g), signer, issued=ts(SR0 + f_issued_offset))
    objs = {"genesis-receipt.json": rg}
    objs.update(extra or {})
    write_swift(name, recs + [f], g, expected, why, extra_recs={**{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g.envs)}, **objs})


AFTER, BEFORE = D + 120, D - 600
recs, _ = swift_library()
g = new_genesis(recs, 2, handover=[A]); swift_case("swift-keyring", recs, g, AFTER, {"succession": "verified"},
                                                   "Keyring library: handover by the control key; F written after the window.")
g = new_genesis(recs, 2, handover=[A], label="Too early")
swift_case("swift-freeze-before-window", recs, g, BEFORE, {"succession": "unverified"}, "F written before the veto window ends.")
g = new_genesis(recs, 2, handover=[A], label="Vetoed")
v_old = envelope({"protocol": "colophon/veto/5", "account": account_id(g), "transition": sha(body_of(g.envs[0])),
                  "issued": ts(SR0 + 600), "by": K1.id}, K1)
swift_case("swift-succession-vetoed", recs, g, AFTER, {"succession": "unverified"},
           "The old library's recovery key (not a handover signer) vetoes within the window.",
           extra={"veto.json": v_old, "veto-receipt.json": receipt_of(account_id(g), v_old, SH, ts(SR0 + 601))})
g = new_genesis(recs, 1, handover=[A], label="Stale head")
swift_case("swift-stale-head", recs, g, AFTER, {"succession": "unverified"}, "The genesis names seq 1; F is at seq 3.")


def freeze_root(recs_, successor, signer, issued):
    return swift_freeze(recs_, successor, signer, root=True, issued=issued)


recs3, _ = swift_library(adopt=False)
pred3 = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs3[0]["body"]))[:32],
         "head": {"seq": 1, "digest": sha(unb64(recs3[0]["body"]))}}
for name, hand, exp, why in [
    ("swift-root-library", [root_s, rec_s], "verified", "Root library: the current root and recovery identity sign handover."),
    ("swift-root-library-root-only", [root_s], "unverified", "Root library with the root alone."),
]:
    gr = Chain(); genesis(gr, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A],
                          adds=[K1], predecessor=pred3, handover=hand, label=name)
    swift_case(name, recs3, gr, AFTER, {"succession": exp}, why,
               freeze=lambda r_, s_, k_, issued: freeze_root(r_, s_, root_s, issued))

recsR, _ = swift_library(adopt=False)
rec2_s, rec2_a = derived("swift/recovery2/signing"), derived("swift/recovery2/agreement")
recsR.append(swift_record({"by": "root", "issued": "2026-11-05T08:00:00Z", "kind": "rotateRecovery",
                           "previous": sha(unb64(recsR[0]["body"])), "recovery": pid(rec2_s, rec2_a), "seq": 2}, root_s))
predR = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recsR[0]["body"]))[:32],
         "head": {"seq": 2, "digest": sha(unb64(recsR[1]["body"]))}}
gR = Chain(); genesis(gR, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                      predecessor=predR, handover=[root_s, rec2_s], label="After rotateRecovery")
swift_case("swift-rotate-recovery", recsR, gR, AFTER, {"succession": "verified"},
           "After rotateRecovery the app holds the root and the new kit only: those two suffice.",
           freeze=lambda r_, s_, k_, issued: freeze_root(r_, s_, root_s, issued))

wr = swift_webauthn_library()
same = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "recover"], "Passkey", verification=True),
        ctrl(SY, ["approve", "control"], "Security key", verification=True)]
g = genesis_from(wr, same, 1, handover=[A]); swift_case("swift-webauthn", wr, g, AFTER, {"succession": "verified"},
                                                       "Passkey and security key as the shipped app makes them; F signed by WebAuthn.",
                                                       signer=SY)
swap = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "control"], "Passkey", verification=True),
        ctrl(SY, ["approve", "recover"], "Security key", verification=True)]
g = genesis_from(wr, swap, 1, handover=[A], label="Swap"); swift_case("swift-webauthn-role-swap-without-consent", wr, g, AFTER,
                                                                      {"succession": "unverified"},
                                                                      "Recover set changed without the old recover key.", signer=SY)
g = genesis_from(wr, swap, 1, handover=[A, SP], label="Swap with consent")
swift_case("swift-webauthn-role-swap-with-consent", wr, g, AFTER, {"succession": "verified"}, "The same with SP's signature.", signer=SY)
ra = swift_webauthn_library(recover_add=True)
g = genesis_from(ra, same + [ctrl(MK, ["approve", "control"], "Thief")], 1, handover=[MK], label="Recovery-added")
v_ra = envelope({"protocol": "colophon/veto/5", "account": account_id(g), "transition": sha(body_of(g.envs[0])),
                 "issued": ts(SR0 + 600), "by": A.id}, A)
swift_case("swift-recovery-added-freeze-vetoed", ra, g, AFTER, {"succession": "unverified"},
           "A passkey's Swift recovery path added MK, which signs handover and F; the old device key vetoes in the window.",
           extra={"veto.json": v_ra, "veto-receipt.json": receipt_of(account_id(g), v_ra, SH, ts(SR0 + 601))}, signer=MK)
recs2, _ = swift_library(two_keys=True)
pred2 = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs2[0]["body"]))[:32],
         "head": {"seq": 2, "digest": sha(unb64(recs2[1]["body"]))}}
for name, hand, exp in [("swift-two-keys-lowered-without-recover", [A, B], "unverified"),
                        ("swift-two-keys-lowered-with-recover", [A, B, K1, K2], "verified")]:
    g2 = Chain(); genesis(g2, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(B, ["approve", "control"], "iPhone"),
                                       ctrl(K1, ["recover"], "Key 1"), ctrl(K2, ["recover"], "Key 2")], threshold=1, rt=1),
                          [A], predecessor=pred2, handover=hand, label=name)
    swift_case(name, recs2, g2, AFTER, {"succession": exp}, "Two Keys library; the genesis lowers recoverThreshold 2→1.",
               freeze=lambda r_, s_, k_, issued: swift_freeze(r_, s_, A, cos=[B], issued=issued))
g = new_genesis(recs, 2, handover=[A], label="After final")
rg_af = successor_with_home(g)
f_af = swift_freeze_signed(recs, account_id(g), A, issued=ts(SR0 + AFTER))
extra_obj = json.loads(unb64(f_af["body"])); extra_obj.update(seq=4, previous=sha(unb64(f_af["body"])), issued=ts(SR0 + AFTER + 60))
write_swift("swift-entry-after-final", recs + [f_af, swift_record(extra_obj, A)], g,
            {"succession": "verified", "evidence": "entry 4 is malformed evidence"},
            "An entry after F: malformed evidence, the succession stands.",
            extra_recs={"genesis-receipt.json": rg_af, **{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g.envs)}})

write("rules/keys-r4.json", {"warning": "PUBLIC TEST SECRETS. Never use these keys for real data.",
                             "keys": {n: {"id": k.id, "signing": b64(k.point), "scalar": b64(k.scalar.to_bytes(32, "big"))}
                                      for n, k in [("home1", H1K), ("home2", H2K), ("successor-home", SH), ("passkey", P),
                                                   ("new-device", NEW)] + [(f"filler/{i}", f) for i, f in enumerate(fillers)]}})
