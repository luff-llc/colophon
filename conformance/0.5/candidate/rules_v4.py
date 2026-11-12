# Revision 5: pending transitions with veto (spec §8.4, §8.6, §8.7, §13, §15), executed by rules.py
# in the generate.py namespace. Every expected outcome is the author's reading of the spec; none
# has been replayed by a 0.5 implementation.

import datetime

D = 259200  # recoveryDelay default, seconds
H1K, H1A = derived("r4/home1/signing"), derived("r4/home1/agreement")
H2K, H2A = derived("r4/home2/signing"), derived("r4/home2/agreement")
P = derived("r4/passkey")
NEW = derived("r4/new-device")
T_BASE = datetime.datetime(2026, 11, 11, 8, 0, 0, tzinfo=datetime.timezone.utc)


def secs(date: str) -> int:
    return int((datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc) - T_BASE).total_seconds())


def anchor(chain):
    return {"seq": len(chain.envs), "digest": sha(body_of(chain.envs[-1]))}


def transition(chain, change, signers, issued, adds=(), origin=None, signers_field=None):
    primary, *cos = signers
    body = {"protocol": "colophon/transition/5", "account": account_id(chain), "anchor": anchor(chain), "issued": issued,
            "by": primary.id, "signers": signers_field or sorted(k.id for k in signers), "change": change}
    return seal(body, primary, cos, adds, origin=origin)


def receipt_of(acct, env, home, received):
    return envelope({"protocol": "colophon/receipt/5", "account": acct, "object": sha(body_of(env)), "received": received,
                     "by": home.id}, home)


def veto_of(acct, t_env, signers, issued, origin=None, flags=0x05):
    primary, *cos = signers
    body = {"protocol": "colophon/veto/5", "account": acct, "transition": sha(body_of(t_env)), "issued": issued,
            "by": primary.id, "signers": sorted(k.id for k in signers)}
    if isinstance(primary, Authenticator) and flags != 0x05:
        b = canonical(body)
        der, asr = primary.sign(b, origin or "https://" + primary.rp, flags=flags)
        return {"body": b64(b), "signature": b64(der), "assertion": asr}
    return seal(body, primary, cos, origin=origin)


def received_of(r):
    return secs(json.loads(body_of(r))["received"])


def due_of(t_env, receipts, delay=D):
    if not receipts:
        return secs(json.loads(body_of(t_env))["issued"])
    return min(received_of(r) for r in receipts) + delay  # headQuorum 1 in these cases


def append_unsigned(chain, kind, by_id, issued, **fields):
    body = {"protocol": "colophon/authority/5", "seq": len(chain.envs) + 1, "previous": sha(chain.last),
            "issued": issued, "by": by_id, "kind": kind}
    body.update(fields)
    env = {"body": b64(canonical(body))}
    chain.envs.append(env)
    return env


def prev_issued(chain):
    return secs(json.loads(chain.last)["issued"])


def activate(chain, t_env, receipts, delay=D):
    """Determined body: by = transition's by, issued = max(due, previous issued), receipts sorted by home ID."""
    t = json.loads(body_of(t_env))
    issued = ts(max(due_of(t_env, receipts, delay), prev_issued(chain)))
    rs = sorted(receipts, key=lambda r: json.loads(body_of(r))["by"])
    return append_unsigned(chain, "activate", t["by"], issued, transition=b64(env_bytes(t_env)),
                           receipts=[b64(env_bytes(r)) for r in rs])


def record_veto(chain, t_env, v_env, receipts):
    v = json.loads(body_of(v_env))
    issued = ts(max(max(received_of(r) for r in receipts), prev_issued(chain)))
    rs = sorted(receipts, key=lambda r: json.loads(body_of(r))["by"])
    return append_unsigned(chain, "vetoed", v["by"], issued, transition=b64(env_bytes(t_env)), veto=b64(env_bytes(v_env)),
                           receipts=[b64(env_bytes(r)) for r in rs])


def home_appointment(acct, home_k, home_a, label):
    req = request(acct, home_k, home_a, "server", {"serves": ["home"]}, label,
                  {"endpoints": [f"https://{label.lower().replace(' ', '')}.example/v1/accounts/{acct}"]})
    return {"request": req, "terms": {"serves": ["home"]}}


def files(prefix, objs):
    return {f"{prefix}/{name}.json": env for name, env in objs.items()}


def case(name, chain, expected, why, sections, objs=None, verifier=None, branches=None):
    write_case(name, chain, expected, why, sections, extra=files("objects", objs or {}), verifier=verifier,
               branches=branches)


VER = lambda at: {"now": ts(at)}

# ---------------------------------------------------------------------------------------------
# Base account (reference person): Mac device key A (slot), phone key Ph, passkey B, security
# keys K1 and K2 (recover only), threshold 1, recoverThreshold 1, homes H1 and H2 at quorum 1.
Ph = derived("r5/phone")
kr5 = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(Ph, ["approve", "control"], "Phone"),
               ctrl(B, ["approve", "control"], "Passkey"), ctrl(K1, ["recover"], "Security key 1"),
               ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
base = Chain(); genesis(base, kr5, [A], adds=[Ph, B, K1, K2]); acct = account_id(base)
t_homes = transition(base, {"homes": {"appoint": [home_appointment(acct, H1K, H1A, "Home one"),
                                                  home_appointment(acct, H2K, H2A, "Home two")]}}, [A, K1], ts(60))
activate(base, t_homes, [])  # no home before it: due when issued
R0 = 3600


def prop(change, signers, at=R0, chain=None, **kw):
    return transition(chain or base, change, signers, ts(at), **kw)


def rec(t_env, home=None, at=R0 + 1):
    return receipt_of(acct, t_env, home or H1K, ts(at))


# 1. Delay, determined activation, early (held by clock), expired (by home clock).
t1 = prop({"keyring": {"remove": [B.id]}}, [A]); r1 = rec(t1)
c = base.copy(); activate(c, t1, [r1])
case("t-remove-after-delay", c, ok_at(3), "Pending removal, received, activated at its due time (determined bytes).",
     ["8.7"], {"transition": t1, "receipt": r1}, VER(R0 + 1 + D + 60))
case("t-activate-early", c, {"result": "held", "seq": 3}, "The same entry while the verifier's clock is before the due time.",
     ["8.5", "8.7"], {"transition": t1, "receipt": r1}, VER(R0 + 1 + D - 60))
case("t-activate-expired", c, {"home": "refuses to store (more than 7 days after due by its clock)"},
     "A home asked to store the activation 8 days after due.", ["8.7", "13.1"], {"transition": t1, "receipt": r1},
     {"now": ts(R0 + 1 + D + 8 * 86400), "role": "home"})
c2 = base.copy(); activate(c2, t1, [r1])
assert env_bytes(c.envs[-1]) == env_bytes(c2.envs[-1])
write("rules/t-activate-identical-bytes/case.json", {"description": "Two homes build the activation independently: identical bytes.",
                                                     "sections": ["8.7"], "expected": {"identical": True}})
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, controllers=[x for x in kr5["controllers"] if cid(x) != B.id]))
case("i-removal-as-immediate", c, bad("malformed", 3), "A removal written as an immediate entry.", ["8.4"])

# 2. Evaluation point (§8.7): anchor before the first home; receipt by a revoked home.
pre = Chain(); pre.envs = base.envs[:1]
t_pre = transition(pre, {"keyring": {"remove": [K1.id, K2.id]}}, [A], ts(R0))
c = base.copy(); activate(c, t_pre, [])
case("t-anchor-before-first-home", c, bad("badSignature", 3),
     "Anchored at seq 1 (no home), activated after homes exist: it needs consent, receipts and the delay.",
     ["8.7"], {"transition": t_pre})
t_rv = prop({"homes": {"revoke": [H2K.id]}}, [A, K1]); c = base.copy(); activate(c, t_rv, [rec(t_rv)])
t_by2 = prop({"keyring": {"remove": [B.id]}}, [A], at=R0 + 1 + D + 120, chain=c)
c3 = c.copy(); activate(c3, t_by2, [receipt_of(acct, t_by2, H2K, ts(R0 + 1 + D + 121))])
case("t-receipt-by-revoked-home", c3, {"result": "held", "seq": 4, "why": "H2 isn't a current home before the activate"},
     "Receipted only by the revoked home.", ["8.7", "13.5"])

# 3. signers field, vetoes.
t_bad = prop({"keyring": {"remove": [B.id]}}, [A], signers_field=sorted([A.id, K1.id]))
case("t-signers-mismatch", base, {"transition": "malformed"}, "`signers` names K1, who didn't sign.", ["8.7"], {"transition": t_bad})
v1 = veto_of(acct, t1, [B], ts(R0 + 600)); rv1 = rec(v1, at=R0 + 601)
c = base.copy(); record_veto(c, t1, v1, [rv1])
case("t-vetoed-by-target", c, ok_at(3), "The passkey vetoes its own removal.", ["8.7"], {"transition": t1, "veto": v1})
t2 = prop({"keyring": {"remove": [K2.id]}}, [A, K1])
v2 = veto_of(acct, t2, [B], ts(R0 + 600))
c = base.copy(); record_veto(c, t2, v2, [rec(v2, at=R0 + 601)])
case("t-veto-too-few", c, bad("malformed", 3), "A two-signer transition vetoed by one key.", ["8.7"], {"transition": t2, "veto": v2})
v_late = veto_of(acct, t1, [B], ts(R0 + 1 + D + 10))
c = base.copy(); activate(c, t1, [r1])
case("t-late-veto", c, ok_at(3), "A veto received after the due time doesn't count.", ["8.7"],
     {"transition": t1, "veto": v_late, "veto-receipt": rec(v_late, at=R0 + 1 + D + 11)}, VER(R0 + 1 + D + 60))

# 4. Ordering at one seq (§8.6 rule 1).
y_before = base.copy(); grant_agent(y_before, A, ts(R0 + 120), A)
x_after = y_before.copy(); activate(x_after, t1, [r1])
case("t-activate-after-covered-entry", x_after, ok_at(4),
     "An ordinary entry issued before the due time keeps its seq; the activation follows it.", ["8.6"],
     {"transition": t1, "receipt": r1})
c = base.copy(); record_veto(c, t1, v1, [rv1]); alt = base.copy(); activate(alt, t1, [r1])
case("t-vetoed-beats-activate", c, ok_at(3), "vetoed and activate of one transition at seq 3: the veto stands.", ["8.6"],
     branches={"activate": [(3, alt.envs[2])]})

# 5. Escalation and the full set.
vetoed_A = base.copy(); record_veto(vetoed_A, t1, v1, [rv1])
t_alone = prop({"keyring": {"remove": [B.id]}}, [A], at=R0 + 800, chain=vetoed_A)
c = vetoed_A.copy(); activate(c, t_alone, [rec(t_alone, at=R0 + 801)])
case("t-escalation-alone", c, bad("badSignature", 4), "v(A)=1: A alone can't propose.", ["8.7"])
t_two = prop({"keyring": {"remove": [B.id]}}, [A, K1], at=R0 + 800, chain=vetoed_A)
c = vetoed_A.copy(); activate(c, t_two, [rec(t_two, at=R0 + 801)])
case("t-escalation-two", c, ok_at(4), "A with K1: accepted; this compliant activation resets v(A) and v(K1).", ["8.7"])
t_full = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New laptop")]}}, [A, Ph, B], adds=[NEW])
c = base.copy(); activate(c, t_full, [])
case("t-full-set-b", c, ok_at(3), "Every control key signs a control-only change (b): immediate.", ["8.7"], {"transition": t_full})
t_full_consent = prop({"policy": {"recoveryDelay": 86400}}, [A, Ph, B, K1])
c = base.copy(); activate(c, t_full_consent, [])
case("t-full-set-b-missing-recover", c, {"result": "held", "seq": 3, "why": "needs consent: K2 didn't sign, so not a full set"},
     "A consent change signed by every control key and one of two recover keys.", ["8.7"], {"transition": t_full_consent})
t_phone = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "Thief laptop")]}}, [Ph, B], adds=[NEW])
c = base.copy(); activate(c, t_phone, [])
case("t-full-set-needs-every-control-key", c, {"result": "held", "seq": 3, "why": "A (Mac) didn't sign"},
     "The phone's two keys are not every control key while the Mac key exists.", ["8.7"], {"transition": t_phone})

# 6. Consent, immediate classification, void cases.
k2d = [dict(json.loads(json.dumps(x)), roles=["approve"]) for x in kr5["controllers"] if cid(x) == K2.id]
for name, signers, exp in [("t-demote-recover-no-consent", [A], bad("badSignature", 3)),
                           ("t-demote-recover-with-consent", [A, K1], ok_at(3))]:
    t = prop({"keyring": {"update": k2d}}, signers); c = base.copy(); activate(c, t, [rec(t)])
    case(name, c, exp, "Demoting K2.", ["8.4"])
t = prop({"keyring": {"threshold": 2}}, [A, Ph]); c = base.copy(); activate(c, t, [rec(t)])
case("t-raise-threshold-no-consent", c, bad("badSignature", 3), "Raising threshold without a recover signer.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, controllers=[dict(x, label="Mike's iPhone") if cid(x) == B.id else x
                                                                                 for x in kr5["controllers"]]))
case("i-relabel-other", c, ok_at(3), "Relabelling another key is immediate; hosts show key IDs beside labels.", ["6.1", "8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, policy={"memberRule": "control"}))
case("i-tighten-policy", c, ok_at(3), "Tightening memberRule is immediate.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, policy={"headMaxAge": 3600}))
case("i-loosen-policy", c, bad("malformed", 3), "Raising headMaxAge as an immediate entry.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=[NEW], keyring=change(kr5, controllers=kr5["controllers"] + [ctrl(NEW, ["approve"], "Tablet")]))
case("i-add-approve", c, ok_at(3), "An approve-only key is added immediately.", ["8.4"])
t_mig = prop({"migration": {"predecessor": {"format": "colophon/authority/5", "account": "ab" * 32,
                                             "final": {"seq": 2, "digest": "cd" * 32}}, "namespaces": [],
                            "controllers": [], "members": []}}, [A, K1])
c = base.copy(); activate(c, t_mig, [rec(t_mig)])
case("t-migration-without-predecessor", c, bad("malformed", 3), "A migration without a predecessor.", ["8.4", "15.4"])
t_noop = prop({"keyring": {"remove": [NEW.id]}}, [A]); c = base.copy(); activate(c, t_noop, [rec(t_noop)])
case("t-noop-void", c, bad("malformed", 3), "A transition that changes nothing is void.", ["8.7"])
t_cf = prop({"keyring": {"add": [ctrl(B, ["approve"], "Passkey")]}}, [A]); c = base.copy(); activate(c, t_cf, [rec(t_cf)])
case("t-add-present-different-roles", c, bad("malformed", 3), "Adding a present key with different roles voids.", ["8.7"])
t_all = prop({"keyring": {"remove": [A.id, Ph.id, B.id]}}, [A, Ph, B]); c = base.copy(); activate(c, t_all, [])
case("t-breaks-keyring", c, bad("malformed", 3), "Removing every control key breaks §6.2.", ["8.7"])

# 7. Suspension.
t_s = prop({"keyring": {"remove": [A.id]}}, [Ph, B]); r_s = rec(t_s)
c = base.copy(); c.add("suspend", Ph, ts(R0 + 60), Ph, key=A.id, transition=sha(body_of(t_s)))
case("t-suspend", c, ok_at(3), "A signer of a pending removal suspends its target.", ["8.7"], {"transition": t_s, "receipt": r_s})
c2 = c.copy(); grant_agent(c2, A, ts(R0 + 120), A)
case("t-suspended-immediate-entry", c2, bad("badSignature", 4), "The suspended key signs a grant.", ["8.7"],
     {"transition": t_s, "receipt": r_s})
c = base.copy(); c.add("suspend", Ph, ts(R0 + 60), Ph, key=A.id, transition="ee" * 32)
case("t-suspend-without-transition", c, bad("malformed", 3), "A suspension citing no pending removal.", ["8.7"])
v_s = veto_of(acct, t_s, [A, K1], ts(R0 + 300))
c = base.copy(); c.add("suspend", Ph, ts(R0 + 60), Ph, key=A.id, transition=sha(body_of(t_s)))
record_veto(c, t_s, v_s, [rec(v_s, at=R0 + 301)])
case("t-suspension-ends-with-veto", c, ok_at(4), "A (suspended) and K1 veto the removal: the suspension ends.", ["8.7"],
     {"transition": t_s, "veto": v_s})

# 8. Rate limit at the primary home (§13.1).
c = base.copy()
for i in range(65):
    grant_agent(c, A, ts(R0 + i), A, key=derived(f"r5/rate/{i}"), agree=derived(f"r5/rate/{i}/agreement"))
write_case("i-rate-limit", c, {"home": "accepts seq 3-66 and refuses seq 67 (65th immediate entry by A in 24 h)"},
           "One signer's immediate entries over a day.", ["13.1"])

# 9. Calls.
head5 = lambda chain, home=H1K: envelope({"protocol": "colophon/head/5", "account": account_id(chain), "authority": anchor(chain),
                                         "issued": ts(R0 + 1000), "by": home.id}, home)


def call_on(chain, signer, rid, purpose="sign-in", audience="https://service.example"):
    body = {"protocol": "colophon/call/5", "account": account_id(chain), "asOf": anchor(chain),
            "signer": {"controller": signer.id}, "key": b64(signer.point), "audience": audience, "purpose": purpose,
            "args": {"nonce": rid}, "requestId": b64url(hashlib.sha256(("r5/" + rid).encode()).digest()), "created": ts(R0 + 1010)}
    return seal(body, signer)


ver = {"now": ts(R0 + 1020), "audiences": ["https://service.example"], "controllerPurposes": ["sign-in"]}
t_add = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")]}}, [K1], adds=[NEW])
case("call-by-pending-addition", base, {"call": "refused:revoked"}, "NEW's addition is pending.", ["8.7", "12.3"],
     {"transition": t_add, "receipt": rec(t_add), "call": call_on(base, NEW, "a"), "head": head5(base)}, ver)
case("call-by-pending-removal", base, {"call": "ok"}, "B's removal is pending: B works until activation.", ["8.7", "12.3"],
     {"transition": t1, "receipt": r1, "call": call_on(base, B, "b"), "head": head5(base)}, ver)
cs = base.copy(); cs.add("suspend", Ph, ts(R0 + 60), Ph, key=A.id, transition=sha(body_of(t_s)))
case("call-by-suspended", cs, {"call": "refused:revoked"}, "A is suspended.", ["8.7", "12.3"],
     {"transition": t_s, "receipt": r_s, "call": call_on(cs, A, "c"), "head": head5(cs)}, ver)
home_ep = f"https://homeone.example/v1/accounts/{acct}"
ver_h = {"now": ts(R0 + 1020), "audiences": [home_ep], "role": "home"}
case("call-recover-history-read", base, {"call": "ok"}, "A recover-only key reads the history.", ["12.3", "13.4"],
     {"call": call_on(base, K1, "d", purpose="colophon.history.read", audience=home_ep), "head": head5(base)}, ver_h)

# 10. Veto signatures by a WebAuthn key.
kr_p = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(P_pin, ["approve", "control"], "Passkey", verification=True),
                ctrl(K1, ["recover"], "Key")], rt=1)
cc = Chain(); genesis(cc, kr_p, [A], adds=[K1, P_pin], origin="https://keys.id.example"); acct_cc = account_id(cc)
activate(cc, transition(cc, {"homes": {"appoint": [home_appointment(acct_cc, H1K, H1A, "Home one")]}}, [A, K1], ts(60)), [])
t_cc = transition(cc, {"keyring": {"remove": [K1.id]}}, [A, K1], ts(R0))
for name, origin, flags, exp in [("veto-webauthn-ok", "https://keys.id.example", 0x05, "valid signature"),
                                 ("veto-webauthn-no-uv", "https://keys.id.example", 0x01, "invalid: no UV"),
                                 ("veto-webauthn-call-origin", "https://sign.id.example", 0x05, "invalid: not an authority origin")]:
    v = veto_of(acct_cc, t_cc, [P_pin], ts(R0 + 300), origin=origin, flags=flags)
    write(f"rules/{name}/veto.json", v); write(f"rules/{name}/transition.json", t_cc)
    write(f"rules/{name}/case.json", {"description": "Checks only the veto's signature rule (§4.3, §8.7).",
                                      "sections": ["4.3", "8.7"], "expected": {"vetoSignature": exp}})

# ---------------------------------------------------------------------------------------------
# 11. Rows of changes §H as event sequences.


def scenario(name, chain, events, final, why):
    objs = {f"{i + 1:02d}-{label}": env for i, (label, env, _) in enumerate(events)}
    write_case(name, chain, {"events": [{"object": f"{i + 1:02d}-{label}", "outcome": out}
                                        for i, (label, _, out) in enumerate(events)], "final": final},
               why, ["8.7", "changes §H"], extra=files("events", objs))


s = base.copy()
ta = prop({"keyring": {"remove": [Ph.id, B.id]}}, [A]); va = veto_of(acct, ta, [Ph], ts(R0 + 300))
record_veto(s, ta, va, [rec(va, at=R0 + 301)])
ta2 = prop({"keyring": {"remove": [Ph.id]}}, [A], at=R0 + 500, chain=s)
to = prop({"keyring": {"remove": [A.id]}}, [Ph, B], at=R0 + 600, chain=s); ro = rec(to, at=R0 + 601)
s.add("suspend", Ph, ts(R0 + 650), Ph, key=A.id, transition=sha(body_of(to)))
vbad = veto_of(acct, to, [A], ts(R0 + 700))
activate(s, to, [ro])
scenario("row-2-thief-has-mac-key", s, [("thief-proposes", ta, "vetoed by Ph"), ("veto", va, "valid"),
                                        ("thief-again-alone", ta2, "refused: v(A)=1"),
                                        ("owner-removes-A", to, "activates after D; A suspended meanwhile"),
                                        ("thief-veto", vbad, "invalid: one vetoer against two signers")],
         {"controllers": sorted([Ph.id, B.id, K1.id, K2.id])}, "Owner wins after D.")

s = base.copy()
tt = prop({"keyring": {"remove": [Ph.id]}}, [A]); s.add("suspend", A, ts(R0 + 60), A, key=Ph.id, transition=sha(body_of(tt)))
vt = veto_of(acct, tt, [Ph], ts(R0 + 120)); record_veto(s, tt, vt, [rec(vt, at=R0 + 121)])
scenario("row-3-thief-suspends-first", s, [("thief-proposes-and-suspends", tt, "vetoed by Ph itself"), ("veto", vt, "valid")],
         {"controllers": sorted([A.id, Ph.id, B.id, K1.id, K2.id]), "suspended": []},
         "Ph vetoes its own removal; the suspension ends; A can't propose alone again.")

s = base.copy()
tx = prop({"keyring": {"remove": [A.id]}}, [Ph, B]); vx = veto_of(acct, tx, [A, K1], ts(R0 + 300)); record_veto(s, tx, vx, [rec(vx, at=R0 + 301)])
tx2 = prop({"keyring": {"remove": [A.id]}}, [Ph, B], at=R0 + 400, chain=s); vx2 = veto_of(acct, tx2, [A, K2], ts(R0 + 500))
record_veto(s, tx2, vx2, [rec(vx2, at=R0 + 501)])
tx3 = prop({"keyring": {"remove": [A.id]}}, [Ph, B], at=R0 + 600, chain=s)
toy = prop({"keyring": {"remove": [Ph.id, B.id]}}, [A, K1, K2], at=R0 + 700, chain=s)
activate(s, toy, [rec(toy, at=R0 + 701)])
scenario("row-4-thief-has-phone", s, [("thief-1", tx, "vetoed"), ("veto-1", vx, "valid"), ("thief-2", tx2, "vetoed"),
                                      ("veto-2", vx2, "valid"), ("thief-3", tx3, "refused: needs three units"),
                                      ("owner-removes-phone", toy, "three units; activates after D")],
         {"controllers": sorted([A.id, K1.id, K2.id])}, "Owner wins after D.")

s = base.copy()
tf = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")], "remove": [A.id, Ph.id, B.id]}}, [K1, K2], adds=[NEW])
activate(s, tf, [])
read = call_on(base, K1, "row9", purpose="colophon.history.read", audience=home_ep)
scenario("row-9-both-recovery-keys-no-device", s, [("read-history", read, "ok (recover may read)"),
                                                   ("full-recovery", tf, "full recovery set (a): immediate")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "Back in at once.")
scenario("row-10-burglar-both-recovery-keys", s, [("burglar-full-recovery", tf, "immediate: the burglar wins")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "The same bytes by a burglar.")

kr4k = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(B, ["approve", "control"], "Passkey"),
                ctrl(K1, ["recover"], "Security key 1"), ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
s = Chain(); genesis(s, kr4k, [A], adds=[B, K1, K2], label="Four keys"); a4 = account_id(s)
activate(s, transition(s, {"homes": {"appoint": [home_appointment(a4, H1K, H1A, "Home one")]}}, [A, K1], ts(60)), [])
e1 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0))
ve1 = veto_of(a4, e1, [B, K2], ts(R0 + 300)); record_veto(s, e1, ve1, [receipt_of(a4, ve1, H1K, ts(R0 + 301))])
e2 = transition(s, {"keyring": {"remove": [A.id, K1.id]}}, [B, K2], ts(R0 + 400))
ve2 = veto_of(a4, e2, [A, K1], ts(R0 + 500)); record_veto(s, e2, ve2, [receipt_of(a4, ve2, H1K, ts(R0 + 501))])
e3 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0 + 600))
ve3 = veto_of(a4, e3, [B, K2], ts(R0 + 700)); record_veto(s, e3, ve3, [receipt_of(a4, ve3, H1K, ts(R0 + 701))])
e4 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0 + 800))
scenario("row-8-equal-units-stall", s, [("thief", e1, "vetoed"), ("owner-veto", ve1, "valid"),
                                        ("owner", e2, "vetoed"), ("thief-veto", ve2, "valid"),
                                        ("thief-again", e3, "valid (v=1, two units), vetoed"), ("owner-veto-2", ve3, "valid"),
                                        ("thief-third", e4, "refused: v=2 needs three units")],
         {"controllers": sorted([A.id, B.id, K1.id, K2.id]), "state": "stall"}, "One control plus one recovery key each: stall.")

s = base.copy()
th = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")], "remove": [Ph.id]}}, [K1], adds=[NEW])
vh = veto_of(acct, th, [Ph], ts(R0 + 3600)); record_veto(s, th, vh, [rec(vh, at=R0 + 3601)])
scenario("row-11-honest-mistake", s, [("recovery", th, "vetoed"), ("found-phone", vh, "valid")],
         {"controllers": sorted([A.id, Ph.id, B.id, K1.id, K2.id])}, "Nothing changes.")

s = base.copy(); r_h2 = rec(t1, home=H2K); activate(s, t1, [r_h2])
case("row-12-one-home-down", s, {"result": "ok", "seq": 3, "finality": "provisional until H1's head covers seq 3"},
     "H1 is down: H2's receipt makes the removal due; it applies at once and is final when H1 returns.",
     ["8.7", "changes §H"], {"transition": t1, "receipt": r_h2, "head-H2": head5(s, H2K)}, VER(R0 + 1 + D + 60))

tb = prop({"keyring": {"remove": [Ph.id, B.id]}}, [A], at=R0 - 600)
rb = receipt_of(acct, tb, H1K, ts(R0 - 599))
hostile = base.copy(); activate(hostile, tb, [rb], delay=0)
case("row-13-backdating-home", base, {"honestHome": "refuses: never receipted it and first saw it now",
                                      "verifiersFollowingH1": "apply the removal once due", "elsewhere": "vouched fork"},
     "At quorum 1 a hostile home and one key are not safe.", ["13.1", "changes §H"],
     {"transition": tb, "receipt": rb}, branches={"hostile": [(3, hostile.envs[2])]})

# ---------------------------------------------------------------------------------------------
# 12. Swift succession (§15.1, §13.5).
SH, SHA_ = derived("r4/successor-home/signing"), derived("r4/successor-home/agreement")
SR0 = 7200
AFTER, BEFORE = D + 120, D - 600


def successor_with_home(g, receipt_delay=60):
    a = account_id(g)
    known = {k.id: k for k in (A, B, K1, K2, MK, NK, SP, SY, root_s, rec_s)}
    ctrls = json.loads(body_of(g.envs[0]))["keyring"]["controllers"]
    extra = [known[cid(x)] for x in ctrls if "recover" in x["roles"] and cid(x) in known][:1]
    activate(g, transition(g, {"homes": {"appoint": [home_appointment(a, SH, SHA_, "Successor home")]}},
                           [A] + extra, ts(SR0 - 60), origin="https://id.example"), [])
    return receipt_of(a, g.envs[0], SH, ts(SR0 - 60 + receipt_delay))


def swift_case(name, recs, g, f_at, expected, why, signer=A, freeze=None, receipt_delay=60, vetoes=()):
    rg = successor_with_home(g, receipt_delay)
    for v_env, v_rec in vetoes:
        record_veto(g, g.envs[0], v_env, [v_rec])
    f = (freeze or swift_freeze_signed)(recs, account_id(g), signer, issued=ts(SR0 + f_at))
    write_swift(name, recs + [f], g, expected, why,
                extra_recs={"genesis-receipt.json": rg, **{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g.envs)}})


def gveto(g, key, at=SR0 + 600):
    v = envelope({"protocol": "colophon/veto/5", "account": account_id(g), "transition": sha(body_of(g.envs[0])),
                  "issued": ts(at), "by": key.id, "signers": [key.id]}, key)
    return v, receipt_of(account_id(g), v, SH, ts(at + 1))


recs, _ = swift_library()
g = new_genesis(recs, 2, handover=[A]); swift_case("swift-keyring", recs, g, AFTER, {"succession": "verified"},
                                                   "Receipt 60 s after the appointing entry; F after the window.")
g = new_genesis(recs, 2, handover=[A], label="Late receipt")
swift_case("swift-late-genesis-receipt", recs, g, AFTER, {"succession": "unverified"},
           "The receipt is 400 s after the appointing entry: malformed, so never due.", receipt_delay=400)
g = new_genesis(recs, 2, handover=[A], label="Too early")
swift_case("swift-freeze-before-window", recs, g, BEFORE, {"succession": "unverified"}, "F written before the window ends.")
g = new_genesis(recs, 2, handover=[A], label="Vetoed")
swift_case("swift-succession-vetoed", recs, g, AFTER, {"succession": "unverified"},
           "K1 (current at head) vetoes; the successor home records it as `vetoed`.", vetoes=[gveto(g, K1)])

kX, kY = derived("swift/x"), derived("swift/y")
recsXY, _ = swift_library()
k2b = json.loads(unb64(recsXY[1]["body"]))
ctrls_xy = k2b["controllers"] + [swift_ctrl(kX, ["approve", "control"], "X"), swift_ctrl(kY, ["approve", "control"], "Y")]
k3 = {k: v for k, v in k2b.items() if k != "recoverThreshold"}
k3.update(by="controller", controllers=ctrls_xy, issued="2026-11-02T08:00:00Z", previous=sha(unb64(recsXY[1]["body"])), seq=3, signer=A.id)
recsXY.append(swift_record(k3, A))
k4 = dict(k3, controllers=[c_ for c_ in ctrls_xy if c_["key"] != b64(kX.point)], issued="2026-11-03T08:00:00Z",
          previous=sha(unb64(recsXY[2]["body"])), seq=4)
recsXY.append(swift_record(k4, A))
k5 = dict(k4, controllers=[c_ for c_ in k4["controllers"] if c_["key"] != b64(kY.point)], issued="2026-11-04T08:00:00Z",
          previous=sha(unb64(recsXY[3]["body"])), seq=5)
recsXY.append(swift_record(k5, A))
g = new_genesis(recsXY, 5, handover=[A], label="X vetoes")
swift_case("swift-veto-by-key-removed-earlier", recsXY, g, AFTER, {"succession": "verified"},
           "X was removed at seq 4, before the last removal at seq 5: X's veto is invalid.", vetoes=[gveto(g, kX)])
g = new_genesis(recsXY, 5, handover=[A], label="Y vetoes")
swift_case("swift-veto-by-last-removed", recsXY, g, AFTER, {"succession": "unverified"},
           "Y was current immediately before the last removal: Y may veto.", vetoes=[gveto(g, kY)])

recs3, _ = swift_library(adopt=False)
pred3 = {"format": "colophon/swift-keyring/2", "account": sha(unb64(recs3[0]["body"]))[:32],
         "head": {"seq": 1, "digest": sha(unb64(recs3[0]["body"]))}}
froot = lambda r_, s_, k_, issued: swift_freeze(r_, s_, root_s, root=True, issued=issued)
gr = Chain(); genesis(gr, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                      predecessor=pred3, handover=[root_s], label="Root only")
swift_case("swift-root-library", recs3, gr, AFTER, {"succession": "verified"}, "Root library: the root alone signs handover.", freeze=froot)
gr2 = Chain(); genesis(gr2, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                       predecessor=pred3, handover=[root_s], label="Kit vetoes")
swift_case("swift-root-library-kit-vetoes", recs3, gr2, AFTER, {"succession": "unverified"},
           "The current recovery kit vetoes the root's hand-over.", vetoes=[gveto(gr2, rec_s)], freeze=froot)

wr = swift_webauthn_library()
same = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "recover"], "Passkey", verification=True),
        ctrl(SY, ["approve", "control"], "Security key", verification=True)]
g = genesis_from(wr, same, 1, handover=[A]); swift_case("swift-webauthn", wr, g, AFTER, {"succession": "verified"},
                                                       "Shipped-app keys; F signed by WebAuthn.", signer=SY)
swap = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "control"], "Passkey", verification=True),
        ctrl(SY, ["approve", "recover"], "Security key", verification=True)]
g = genesis_from(wr, swap, 1, handover=[A], label="Swap"); swift_case("swift-webauthn-role-swap-without-consent", wr, g, AFTER,
                                                                      {"succession": "unverified"}, "Recover set changed without SP.", signer=SY)
g = genesis_from(wr, swap, 1, handover=[A, SP], label="Swap with consent")
swift_case("swift-webauthn-role-swap-with-consent", wr, g, AFTER, {"succession": "verified"}, "With SP.", signer=SY)

g_thief = new_genesis(recs, 2, handover=[A], label="Thief")
f_thief = swift_freeze_signed(recs, account_id(g_thief), A, issued=ts(SR0 + 60))
g_owner = new_genesis(recs + [f_thief], 3, handover=[A], label="Owner after premature freeze")
rg = successor_with_home(g_owner)
f2 = dict(json.loads(unb64(f_thief["body"])), layout=4, previous=sha(unb64(f_thief["body"])), seq=4,
          issued=ts(SR0 + AFTER), successor=account_id(g_owner))
write_swift("swift-premature-freeze-then-owner", recs + [f_thief, swift_record(f2, A)], g_owner,
            {"succession": "verified", "firstFreeze": "its succession was never due, so it doesn't end the predecessor"},
            "A thief's premature freeze at seq 3, then the owner's verified attempt with a layout-4 freeze at seq 4.",
            extra_recs={"genesis-receipt.json": rg, **{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g_owner.envs)},
                        "thief-genesis.json": g_thief.envs[0]})

g = new_genesis(recs, 2, handover=[A], label="After final")
rg = successor_with_home(g)
f_af = swift_freeze_signed(recs, account_id(g), A, issued=ts(SR0 + AFTER))
xo = dict(json.loads(unb64(f_af["body"])), seq=4, previous=sha(unb64(f_af["body"])), issued=ts(SR0 + AFTER + 60), layout=4)
write_swift("swift-entry-after-final", recs + [f_af, swift_record(xo, A)], g,
            {"succession": "verified", "evidence": "entry 4 is malformed evidence"}, "An entry after a verified F.",
            extra_recs={"genesis-receipt.json": rg, **{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g.envs)}})

write("rules/keys-r4.json", {"warning": "PUBLIC TEST SECRETS. Never use these keys for real data.",
                             "keys": {n: {"id": k.id, "signing": b64(k.point), "scalar": b64(k.scalar.to_bytes(32, "big"))}
                                      for n, k in [("home1", H1K), ("home2", H2K), ("successor-home", SH), ("passkey", P),
                                                   ("new-device", NEW), ("phone", Ph), ("swift-x", kX), ("swift-y", kY)]
                                      + [(f"rate/{i}", derived(f"r5/rate/{i}")) for i in range(65)]}})
