# Revision 6: pending transitions with veto (spec §8.4, §8.6, §8.7, §13, §15), executed by rules.py
# in the generate.py namespace. Every expected outcome is the author's reading of the spec; none
# has been replayed by a 0.5 implementation. New-vault slots and `previousVault` seals are
# structurally valid synthetic bytes: verifiers can't open them (§8.3), and these vectors don't.

import datetime

D = 259200  # recoveryDelay default, seconds
W = 300     # receipt window, seconds
H1K, H1A = derived("r4/home1/signing"), derived("r4/home1/agreement")
H2K, H2A = derived("r4/home2/signing"), derived("r4/home2/agreement")
P = derived("r4/passkey")
NEW = derived("r4/new-device")
APPR = derived("r6/approve-only")
X = derived("r6/thief-x")
T_BASE = datetime.datetime(2026, 11, 11, 8, 0, 0, tzinfo=datetime.timezone.utc)
Ph = derived("r5/phone")
AGREE[Ph.id] = derived("r5/phone/agreement").point  # Ph can hold a sealed slot in a new vault


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


def field(env, name):
    return json.loads(body_of(env))[name]


def received_of(r):
    return secs(field(r, "received"))


def t_issued(t_env):
    return secs(field(t_env, "issued"))


def due_of(t_env, receipts, delay=D):
    """§8.7: issued + 300 s + delay; with no receipts (no home, or a full set), issued."""
    return t_issued(t_env) + W + delay if receipts else t_issued(t_env)


def choose(receipts, quorum=1):
    """§8.7 'Choosing receipts': lowest home IDs, per home the lowest body digest, sorted by home."""
    best = {}
    for r in receipts:
        h = field(r, "by")
        if h not in best or sha(body_of(r)) < sha(body_of(best[h])):
            best[h] = r
    return [best[h] for h in sorted(best)][:quorum]


def append_unsigned(chain, kind, by_id, issued, **fields):
    body = {"protocol": "colophon/authority/5", "seq": len(chain.envs) + 1, "previous": sha(chain.last),
            "issued": issued, "by": by_id, "kind": kind}
    body.update(fields)
    env = {"body": b64(canonical(body))}
    chain.envs.append(env)
    return env


def prev_issued(chain):
    return secs(json.loads(chain.last)["issued"])


def emb(env):
    return b64(env_bytes(env))


def activate(chain, t_env, receipts, delay=D):
    """Determined body: by = transition's by, issued = max(due, previous issued), chosen receipts."""
    rs = choose(receipts)
    issued = ts(max(due_of(t_env, rs, delay), prev_issued(chain)))
    return append_unsigned(chain, "activate", field(t_env, "by"), issued, transition=emb(t_env), receipts=[emb(r) for r in rs])


def record_veto(chain, t_env, t_receipts, v_env, receipts):
    rs, trs = choose(receipts), choose(t_receipts)
    issued = ts(max(max(received_of(r) for r in rs), prev_issued(chain)))
    return append_unsigned(chain, "vetoed", field(v_env, "by"), issued, transition=emb(t_env),
                           transitionReceipts=[emb(r) for r in trs], veto=emb(v_env), receipts=[emb(r) for r in rs])


def suspend(chain, signer, key, t_env, receipts, at):
    return chain.add("suspend", signer, ts(at), signer, key=key.id, transition=emb(t_env), receipts=[emb(r) for r in choose(receipts)])


def new_vault(name):
    return {"agreement": b64(derived(f"r6/{name}/vault/agreement").point), "signing": b64(derived(f"r6/{name}/vault/signing").point)}


def synth48(label):
    return hashlib.sha256(label.encode()).digest() + hashlib.sha256((label + "/2").encode()).digest()[:16]


def sealed_slot(name, k, label):
    return {"kind": "sealed", "controllers": [k.id], "label": label,
            "sealed": {"enc": b64(derived(f"r6/{name}/slot/{k.id}/enc").point), "ciphertext": b64(synth48(f"r6/{name}/slot/{k.id}"))}}


def vault_change(name, slot_keys, previous=True):
    comp = {"vault": new_vault(name), "slots": [sealed_slot(name, k, l) for k, l in slot_keys]}
    if previous:
        comp["previousVault"] = {"enc": b64(derived(f"r6/{name}/previous/enc").point), "ciphertext": b64(synth48(f"r6/{name}/previous"))}
    return comp


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
# Base account (reference person): Mac device key A (the only slot), phone key Ph, passkey B,
# security keys K1 and K2 (recover only, no slots), thresholds 1, homes H1 and H2 at quorum 1.
kr5 = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(Ph, ["approve", "control"], "Phone"),
               ctrl(B, ["approve", "control"], "Passkey"), ctrl(K1, ["recover"], "Security key 1"),
               ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
base = Chain(); genesis(base, kr5, [A], adds=[Ph, B, K1, K2]); acct = account_id(base)
t_homes = transition(base, {"homes": {"appoint": [home_appointment(acct, H1K, H1A, "Home one"),
                                                  home_appointment(acct, H2K, H2A, "Home two")]}}, [A, K1], ts(60))
activate(base, t_homes, [])  # no home before it: due when issued, final at once
R0 = 3600
DUE0 = R0 + W + D            # due time of a transition issued at R0
DL0 = R0 + D                 # its veto deadline


def prop(change, signers, at=R0, chain=None, **kw):
    return transition(chain or base, change, signers, ts(at), **kw)


def rec(t_env, home=None, at=R0 + 1):
    return receipt_of(acct, t_env, home or H1K, ts(at))


head5 = lambda chain, home=H1K, at=R0 + 1000, seq=None: envelope(
    {"protocol": "colophon/head/5", "account": account_id(chain),
     "authority": {"seq": seq or len(chain.envs), "digest": sha(body_of(chain.envs[(seq or len(chain.envs)) - 1]))},
     "issued": ts(at), "by": home.id}, home)

# 1. Due time, determined activation, early, expired, identical and differing bytes.
t1 = prop({"keyring": {"remove": [B.id]}}, [A]); r1 = rec(t1); r1b = rec(t1, home=H2K, at=R0 + 2)
c = base.copy(); activate(c, t1, [r1])
case("t-remove-after-delay", c, ok_at(3), "Pending removal, receipted, activated at issued + 300 s + D (determined bytes).",
     ["8.7"], {"transition": t1, "receipt": r1}, VER(DUE0 + 60))
case("t-activate-early", c, {"result": "held", "seq": 3}, "The same entry while the verifier's clock is before the due time.",
     ["8.5", "8.7"], {"transition": t1, "receipt": r1}, VER(DUE0 - 60))
cx = base.copy(); grant_agent(cx, A, ts(DUE0 + 8 * 86400), A); activate(cx, t1, [r1])
case("t-activate-expired", cx, bad("malformed", 4), "Its determined issued would be 8 days after the due time.",
     ["8.7"], {"transition": t1, "receipt": r1}, VER(DUE0 + 9 * 86400))
c1 = base.copy(); activate(c1, t1, [r1, r1b]); c2 = base.copy(); activate(c2, t1, [r1b, r1])
assert env_bytes(c1.envs[-1]) == env_bytes(c2.envs[-1])
write("rules/t-activate-identical-bytes/home-1.json", c1.envs[-1])
write("rules/t-activate-identical-bytes/home-2.json", c2.envs[-1])
write("rules/t-activate-identical-bytes/case.json", {"description": "Two homes holding both receipts build the activation independently.",
                                                     "sections": ["8.7"], "expected": {"identical": True}})
c3 = base.copy(); activate(c3, t1, [r1b])
lo, hi = sorted([c.envs[-1], c3.envs[-1]], key=lambda e: sha(body_of(e)))
case("t-activate-differing-receipts", base, {"standsAtSeq3": sha(body_of(lo)), "other": "rebuilt or dropped; effects identical"},
     "Each home held only its own receipt: two activations of one transition at seq 3. The lower body digest stands.",
     ["8.6", "8.7"], {"transition": t1}, VER(DUE0 + 60), branches={"low": [(3, lo)], "high": [(3, hi)]})
c = base.copy(); activate(c, t1, [r1]); activate(c, t1, [r1])
case("t-activate-reappended", c, bad("malformed", 4), "The same activation appended again later.", ["8.7"], verifier=VER(DUE0 + 60))
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, controllers=[x for x in kr5["controllers"] if cid(x) != B.id]))
case("i-removal-as-immediate", c, bad("malformed", 3), "A removal written as an immediate entry.", ["8.4"])

# 2. Evaluation point (§8.7).
pre = Chain(); pre.envs = base.envs[:1]
t_pre = transition(pre, {"keyring": {"remove": [B.id]}}, [A], ts(R0))
c = base.copy(); activate(c, t_pre, [])
case("t-anchor-before-first-home", c, bad("malformed", 3),
     "A control-only removal anchored at seq 1 (no home then) with no receipts: before the activate the account has homes, "
     "so it needs receipts (would be ok if judged at the anchor).", ["8.7"], {"transition": t_pre})
t_rv = prop({"homes": {"revoke": [H2K.id]}}, [A, K1]); c = base.copy(); activate(c, t_rv, [rec(t_rv)])
t_by2 = prop({"keyring": {"remove": [B.id]}}, [A], at=DUE0 + 120, chain=c)
c3 = c.copy(); activate(c3, t_by2, [receipt_of(acct, t_by2, H2K, ts(DUE0 + 121))])
case("t-receipt-by-revoked-home", c3, bad("malformed", 4), "Receipted only by a home revoked before it: it can never be due.",
     ["8.5", "8.7", "13.5"], verifier=VER(DUE0 + 120 + W + D + 60))
side = base.copy(); grant_agent(side, A, ts(R0 - 100), A)
t_off = prop({"keyring": {"remove": [B.id]}}, [A], chain=side)
main = base.copy(); grant_agent(main, Ph, ts(R0 - 50), Ph, key=derived("r6/agent2"), agree=derived("r6/agent2/agreement"))
activate(main, t_off, [rec(t_off)])
case("t-anchor-off-branch", main, bad("malformed", 4), "Anchored on a seq-3 entry this branch doesn't have.", ["8.7"],
     {"transition": t_off}, VER(DUE0 + 60))
t_early = prop({"keyring": {"remove": [B.id]}}, [A], at=30)
case("t-issued-before-anchor", base, {"transition": "malformed"}, "issued is earlier than the anchor's.", ["8.7"], {"transition": t_early})

# 3. signers, vetoes.
t_bad = prop({"keyring": {"remove": [B.id]}}, [A], signers_field=sorted([A.id, K1.id]))
case("t-signers-mismatch", base, {"transition": "malformed"}, "`signers` names K1, who didn't sign.", ["8.7"], {"transition": t_bad})
v1 = veto_of(acct, t1, [B], ts(R0 + 600)); rv1 = rec(v1, at=R0 + 601)
c = base.copy(); record_veto(c, t1, [r1], v1, [rv1])
case("t-vetoed-by-target", c, ok_at(3), "The passkey vetoes its own removal; the entry carries both receipt sets.", ["8.7"])
c = base.copy(); record_veto(c, t1, [r1], v1, [rv1]); record_veto(c, t1, [r1], v1, [rv1])
case("t-vetoed-duplicate", c, bad("malformed", 4), "The same vetoed entry appended again: once only.", ["8.7"])
t2 = prop({"keyring": {"remove": [K2.id]}}, [A, K1])
v2 = veto_of(acct, t2, [B], ts(R0 + 600))
c = base.copy(); record_veto(c, t2, [rec(t2)], v2, [rec(v2, at=R0 + 601)])
case("t-veto-too-few", c, bad("malformed", 3), "A two-signer transition vetoed by one key.", ["8.7"])
v2s = veto_of(acct, t2, [K1, B], ts(R0 + 600))
c = base.copy(); record_veto(c, t2, [rec(t2)], v2s, [rec(v2s, at=R0 + 601)])
case("t-veto-shares-a-unit", c, bad("malformed", 3), "K1 signed the transition and its veto: vetoing units must be disjoint.", ["8.7"])
ca = base.copy(); ca.add("keyring", A, ts(R0 - 100), A, adds=[APPR], keyring=change(kr5, controllers=kr5["controllers"] + [ctrl(APPR, ["approve"], "Tablet")]))
t_a = prop({"keyring": {"remove": [B.id]}}, [A], chain=ca); v_a = veto_of(acct, t_a, [APPR], ts(R0 + 600))
c = ca.copy(); record_veto(c, t_a, [rec(t_a)], v_a, [rec(v_a, at=R0 + 601)])
case("t-veto-by-approve-only", c, bad("malformed", 4), "An approve-only key can't veto.", ["8.7"])
v_late = veto_of(acct, t1, [B], ts(DL0 + 10))
c = base.copy(); activate(c, t1, [r1])
case("t-late-veto", c, ok_at(3), "A veto received after the deadline (and before the due time) doesn't count.", ["8.7"],
     {"transition": t1, "veto": v_late, "veto-receipt": rec(v_late, at=DL0 + 11)}, VER(DUE0 + 60))
c = base.copy(); record_veto(c, t1, [r1], v_late, [rec(v_late, at=DL0 + 11)])
case("t-vetoed-after-deadline", c, bad("malformed", 3), "Recording that late veto: its receipt is after the veto deadline.", ["8.7"],
     verifier=VER(DUE0 + 60))

# 4. Ordering at one seq (§8.6 rule 1), finality.
y_before = base.copy(); grant_agent(y_before, A, ts(R0 + 120), A)
x_after = y_before.copy(); activate(x_after, t1, [r1])
case("t-activate-after-covered-entry", x_after, ok_at(4),
     "An ordinary entry issued before the due time keeps its seq; the activation follows it.", ["8.6"],
     {"transition": t1, "receipt": r1}, VER(DUE0 + 60))
c = base.copy(); record_veto(c, t1, [r1], v1, [rv1]); alt = base.copy(); activate(alt, t1, [r1])
case("t-vetoed-beats-activate", c, ok_at(3), "vetoed and a provisional activate of one transition at seq 3: the veto stands.",
     ["8.6"], branches={"activate": [(3, alt.envs[2])]})
fin = base.copy(); activate(fin, t1, [r1])
v_hid = veto_of(acct, t1, [B], ts(R0 + 600)); rv_hid = receipt_of(acct, v_hid, H2K, ts(R0 + 601))
vb = base.copy(); record_veto(vb, t1, [r1], v_hid, [rv_hid])
case("t-vetoed-after-final", fin, {"result": "ok", "seq": 3, "finality": "final",
                                   "vetoed": "changes nothing; equivocation evidence against H2, which receipted the veto and covered the activate"},
     "Heads of both homes cover the activation; later a vetoed for it appears.", ["8.6", "8.7", "13.3"],
     {"head-H1": head5(fin, H1K, DUE0 + 100), "head-H2": head5(fin, H2K, DUE0 + 100), "veto": v_hid, "veto-receipt": rv_hid},
     VER(DUE0 + 200), branches={"vetoed": [(3, vb.envs[2])]})
t_addc = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")]}}, [A], adds=[NEW])
pa = base.copy(); activate(pa, t_addc, [rec(t_addc)]); grant_agent(pa, NEW, ts(DUE0 + 100), NEW)
case("t-provisional-addition-signs", pa, bad("badSignature", 4),
     "NEW was added by an activation H2's head doesn't cover yet: until final, NEW signs nothing.", ["8.7"],
     {"head-H1": head5(pa, H1K, DUE0 + 150, seq=3), "head-H2": head5(base, H2K, DUE0 + 150)}, VER(DUE0 + 200))

# 5. Escalation and the full set.
vetoed_A = base.copy(); record_veto(vetoed_A, t1, [r1], v1, [rv1])
t_alone = prop({"keyring": {"remove": [B.id]}}, [A], at=R0 + 800, chain=vetoed_A)
c = vetoed_A.copy(); activate(c, t_alone, [rec(t_alone, at=R0 + 801)])
case("t-escalation-alone", c, bad("badSignature", 4), "v(A)=1: A alone can't propose.", ["8.7"], verifier=VER(R0 + 800 + W + D + 60))
t_two = prop({"keyring": {"remove": [B.id]}}, [A, K1], at=R0 + 800, chain=vetoed_A)
c = vetoed_A.copy(); activate(c, t_two, [rec(t_two, at=R0 + 801)])
case("t-escalation-two", c, ok_at(4), "A with K1: accepted; this compliant activation resets v(A) and v(K1).", ["8.7"],
     verifier=VER(R0 + 800 + W + D + 60))
t_full = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New laptop")]}}, [A, Ph, B], adds=[NEW])
c = base.copy(); activate(c, t_full, [])
case("t-full-set-b", c, ok_at(3), "Every control key signs a control-only change (b): due when issued, no receipts.", ["8.7"],
     {"transition": t_full})
t_full_consent = prop({"policy": {"recoveryDelay": 86400}}, [A, Ph, B, K1])
c = base.copy(); activate(c, t_full_consent, [])
case("t-full-set-b-missing-recover", c, bad("malformed", 3),
     "A consent change signed by every control key and one of two recover keys is not a full set, so `receipts: []` is invalid.",
     ["8.5", "8.7"], {"transition": t_full_consent})
t_phone = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "Thief laptop")]}}, [Ph, B], adds=[NEW])
c = base.copy(); activate(c, t_phone, [])
case("t-full-set-needs-every-control-key", c, bad("malformed", 3), "The phone's two keys are not every control key while the Mac key exists.",
     ["8.7"], {"transition": t_phone})

# 6. Consent, composites, keep, vault changes, immediate classification, void cases.
k2d = [dict(json.loads(json.dumps(x)), roles=["approve"]) for x in kr5["controllers"] if cid(x) == K2.id]
for name, signers, exp in [("t-demote-recover-no-consent", [A], bad("badSignature", 3)),
                           ("t-demote-recover-with-consent", [A, K1], ok_at(3))]:
    t = prop({"keyring": {"update": k2d}}, signers); c = base.copy(); activate(c, t, [rec(t)])
    case(name, c, exp, "Demoting K2.", ["8.4"], verifier=VER(DUE0 + 60))
t = prop({"keyring": {"threshold": 2}}, [A, Ph]); c = base.copy(); activate(c, t, [rec(t)])
case("t-raise-threshold-no-consent", c, bad("badSignature", 3), "Raising threshold without a recover signer.", ["8.4"], verifier=VER(DUE0 + 60))
t = prop({"keyring": {"remove": [Ph.id]}, "policy": {"callWindow": 600}}, [K1]); c = base.copy(); activate(c, t, [rec(t)])
case("t-composite-mixed-rules", c, bad("badSignature", 3),
     "K1 meets the recovery rule for the removal, but raising callWindow allows only the control rule: one rule must serve all components.",
     ["8.7"], verifier=VER(DUE0 + 60))
t = prop({"keyring": {"keep": [Ph.id, B.id]}}, [A, K1]); c = base.copy(); activate(c, t, [rec(t)])
case("t-keep-needs-recovery-rule", c, bad("badSignature", 3), "`keep` needs the recovery rule.", ["8.4", "8.7"], verifier=VER(DUE0 + 60))
t_vc = prop({"keyring": {"remove": [Ph.id]}, "vault": vault_change("vc", [(A, "Mac")])}, [A])
c = base.copy(); activate(c, t_vc, [rec(t_vc)])
case("t-vault-change-previous", c, ok_at(3),
     "A voluntary vault change with a removal: determined unsigned activate; previousVault reaches the old vault. No namespaces, so no rekey follows.",
     ["8.3", "8.7"], {"transition": t_vc}, VER(DUE0 + 60))
t_nv = prop({"keyring": {"remove": [A.id]}}, [Ph, B]); c = base.copy(); activate(c, t_nv, [rec(t_nv)])
case("t-removal-slotted-without-vault", c, bad("malformed", 3), "Removing the slotted Mac key without changing the vault is void.",
     ["8.3", "8.7"], verifier=VER(DUE0 + 60))
keep_c = base.copy()
t_tx = prop({"keyring": {"add": [ctrl(X, ["approve", "control"], "Thief X")]}}, [A, Ph, B], at=R0 + 100, adds=[X])
t_keep = prop({"keyring": {"keep": [], "add": [ctrl(NEW, ["approve", "control"], "New phone")]},
               "vault": vault_change("keep", [(K1, "Security key 1")], previous=False)}, [K1, K2], at=R0 + 200, adds=[NEW])
activate(keep_c, t_tx, []); activate(keep_c, t_keep, [])
case("t-keep-removes-unknown-key", keep_c, {"result": "ok", "seq": 4, "controllers": sorted([NEW.id, K1.id, K2.id])},
     "A thief with every control key adds X at once (seq 3) after the owner read the history; the owner's full recovery set, "
     "anchored at seq 2, keeps no non-recover key, so X goes too.", ["8.7", "changes §H"], {"thief": t_tx, "owner": t_keep})
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, controllers=[dict(x, label="Mike's iPhone") if cid(x) == B.id else x
                                                                                 for x in kr5["controllers"]]))
case("i-relabel-other", c, ok_at(3), "Relabelling another key is immediate; hosts show key IDs beside labels.", ["6.1", "8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, policy={"memberRule": "control"}))
case("i-tighten-policy", c, ok_at(3), "Tightening memberRule is immediate.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, policy={"headMaxAge": 3600}))
case("i-loosen-policy", c, bad("malformed", 3), "Raising headMaxAge as an immediate entry.", ["8.4"])
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=[NEW], keyring=change(kr5, controllers=kr5["controllers"] + [ctrl(NEW, ["approve"], "Tablet")]))
case("i-add-approve", c, ok_at(3), "An approve-only key is added immediately.", ["8.4"])
five = [derived(f"r6/five/{i}") for i in range(5)]
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=five,
                       keyring=change(kr5, controllers=kr5["controllers"] + [ctrl(k, ["approve"], f"Tablet {i}") for i, k in enumerate(five)]))
case("i-add-five-approve", c, bad("malformed", 3), "An immediate keyring entry adds at most four controllers.", ["8.4"])
t_mig = prop({"migration": {"predecessor": {"format": "colophon/authority/5", "account": "ab" * 32,
                                             "final": {"seq": 2, "digest": "cd" * 32}}, "namespaces": [],
                            "controllers": [], "members": []}}, [A, K1])
c = base.copy(); activate(c, t_mig, [rec(t_mig)])
case("t-migration-without-predecessor", c, bad("malformed", 3), "A migration without a predecessor.", ["8.4", "15.4"], verifier=VER(DUE0 + 60))
t_noop = prop({"keyring": {"remove": [NEW.id]}}, [A]); c = base.copy(); activate(c, t_noop, [rec(t_noop)])
case("t-noop-void", c, bad("malformed", 3), "A transition that changes nothing is void.", ["8.7"], verifier=VER(DUE0 + 60))
t_cf = prop({"keyring": {"add": [ctrl(B, ["approve"], "Passkey")]}}, [A]); c = base.copy(); activate(c, t_cf, [rec(t_cf)])
case("t-add-present-different-roles", c, bad("malformed", 3), "Adding a present key with different roles voids.", ["8.7"], verifier=VER(DUE0 + 60))
t_all = prop({"keyring": {"remove": [A.id, Ph.id, B.id]}, "vault": vault_change("all", [(K1, "Key")], previous=False)}, [A, Ph, B])
c = base.copy(); activate(c, t_all, [])
case("t-breaks-keyring", c, bad("malformed", 3), "Removing every control key breaks §6.2.", ["8.7"])
c = base.copy(); c.add("keyring", A, ts(R0), A, keyring=change(kr5, policy={"rate": {"account": {"bytes": 16777216, "entries": 256},
                                                                                     "signer": {"bytes": 4194304, "entries": 128}}}))
case("i-raise-rate", c, bad("malformed", 3), "Raising the rate limit as an immediate entry.", ["6.3", "8.4"])

# 7. Suspension (the removal of the slotted Mac key carries its vault change, so it isn't void).
t_s = prop({"keyring": {"remove": [A.id]}, "vault": vault_change("s", [(Ph, "Phone")], previous=False)}, [Ph, B]); r_s = rec(t_s)
c = base.copy(); suspend(c, Ph, A, t_s, [r_s], R0 + 60)
case("t-suspend", c, ok_at(3), "A signer of a pending removal suspends its target; the entry carries the transition and receipt.", ["8.7"])
c2 = c.copy(); grant_agent(c2, A, ts(R0 + 120), A)
case("t-suspended-immediate-entry", c2, bad("badSignature", 4), "The suspended key signs a grant.", ["8.7"])
c = base.copy(); suspend(c, Ph, A, t_nv, [rec(t_nv)], R0 + 60)
case("t-suspend-void-transition", c, bad("malformed", 3), "A suspension citing a removal of the slotted Mac key with no vault change.", ["8.7"])
c = base.copy(); suspend(c, K1, A, t_s, [r_s], R0 + 60)
case("t-suspend-by-non-signer", c, bad("badSignature", 3), "K1 didn't sign the transition.", ["8.4", "8.7"])
t_s2 = prop({"keyring": {"remove": [B.id]}}, [Ph], at=R0 + 30)
c = base.copy(); suspend(c, Ph, A, t_s, [r_s], R0 + 60); suspend(c, Ph, B, t_s2, [rec(t_s2, at=R0 + 31)], R0 + 90)
case("t-suspend-second-by-unit", c, bad("malformed", 4), "Ph already has a suspension outstanding.", ["8.7"])
v_s = veto_of(acct, t_s, [A, K1], ts(R0 + 300))
c = base.copy(); suspend(c, Ph, A, t_s, [r_s], R0 + 60); record_veto(c, t_s, [r_s], v_s, [rec(v_s, at=R0 + 301)])
c3 = c.copy(); grant_agent(c3, A, ts(R0 + 400), A)
case("t-suspension-ends-with-veto", c3, ok_at(5), "A (suspended) and K1 veto the removal; the suspension ends and A grants again.", ["8.7"])
c = base.copy(); suspend(c, Ph, A, t_s, [r_s], R0 + 60)
grant_agent(c, Ph, ts(DUE0 + 8 * 86400), Ph); grant_agent(c, A, ts(DUE0 + 8 * 86400 + 60), A, key=derived("r6/agent3"), agree=derived("r6/agent3/agreement"))
case("t-suspension-ends-at-expiry", c, ok_at(5), "No activate came within 7 days of the due time; entry 4 ends the suspension.", ["8.7"],
     verifier=VER(DUE0 + 9 * 86400))

# 8. Rate limit, checked by every verifier (§13.1).
c = base.copy()
for i in range(65):
    grant_agent(c, A, ts(R0 + i), A, key=derived(f"r5/rate/{i}"), agree=derived(f"r5/rate/{i}/agreement"))
write_case("i-rate-limit", c, bad("malformed", 67), "The 65th immediate entry by A within 24 hours.", ["13.1"])
plant = [derived(f"r6/plant/{i}") for i in range(4)]
c = base.copy(); c.add("keyring", A, ts(R0), A, adds=plant,
                       keyring=change(kr5, controllers=kr5["controllers"] + [ctrl(k, ["approve"], f"Planted {i}") for i, k in enumerate(plant)]))
for i in range(59):
    grant_agent(c, A, ts(R0 + 1 + i), A, key=derived(f"r6/pa/{i}"), agree=derived(f"r6/pa/{i}/agreement"))
for i in range(5):
    grant_agent(c, plant[0], ts(R0 + 100 + i), plant[0], key=derived(f"r6/pb/{i}"), agree=derived(f"r6/pb/{i}/agreement"))
write_case("i-rate-planted-keys", c, bad("malformed", 67),
           "Entries by a key A planted count against A: the addition, 59 grants by A, then the planted key's 5th grant is A's 65th.", ["13.1"])
kr_rate = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(Ph, ["approve", "control"], "Phone"),
                   ctrl(B, ["approve", "control"], "Passkey")], policy=dict(POLICY, rate={"account": {"bytes": 16777216, "entries": 64},
                                                                                         "signer": {"bytes": 4194304, "entries": 64}}))
c = Chain(); genesis(c, kr_rate, [A], adds=[Ph, B], label="Rate")
for i in range(32):
    grant_agent(c, A, ts(60 + i), A, key=derived(f"r6/ra/{i}"), agree=derived(f"r6/ra/{i}/agreement"))
for i in range(32):
    grant_agent(c, Ph, ts(120 + i), Ph, key=derived(f"r6/rb/{i}"), agree=derived(f"r6/rb/{i}/agreement"))
c.add("revoke", A, ts(200), A, member=derived("r6/ra/0").id, kept=[], heads=[], epochs=[])
grant_agent(c, B, ts(210), B, key=derived("r6/rc"), agree=derived("r6/rc/agreement"))
write_case("i-rate-revoke-outside-account-limit", c, {"result": "malformed", "seq": 67, "ok": "seq 66, the revoke, counts toward A only"},
           "Account limit 64: after 64 grants a revoke is still accepted; the next grant is refused.", ["13.1"])

# 9. Calls.


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
cs = base.copy(); suspend(cs, Ph, A, t_s, [r_s], R0 + 60)
case("call-by-suspended", cs, {"call": "refused:revoked"}, "A is suspended.", ["8.7", "12.3"],
     {"call": call_on(cs, A, "c"), "head": head5(cs)}, ver)
home_ep = f"https://homeone.example/v1/accounts/{acct}"
ver_h = {"now": ts(R0 + 1020), "audiences": [home_ep], "role": "home"}
case("call-recover-history-read", base, {"call": "ok"}, "A recover-only key reads the history; a home accepts the purpose without configuration.",
     ["12.3", "13.4"], {"call": call_on(base, K1, "d", purpose="colophon.history.read", audience=home_ep), "head": head5(base)}, ver_h)
case("call-suspended-history-read", cs, {"call": "ok"}, "The suspended key can still read the history, to see what to veto.",
     ["8.7", "12.3", "13.4"], {"call": call_on(cs, A, "e", purpose="colophon.history.read", audience=home_ep), "head": head5(cs)}, ver_h)
ver_p = dict(ver, now=ts(DUE0 + 200))


def call_late(chain, signer, rid):
    body = json.loads(body_of(call_on(chain, signer, rid))); body["created"] = ts(DUE0 + 190)
    return seal(body, signer)


pa2 = base.copy(); activate(pa2, t_addc, [rec(t_addc)])
case("call-by-provisional-addition", pa2, {"call": "refused:revoked"},
     "NEW's addition activated, but H2's head doesn't cover it: provisional, so NEW can't call.", ["8.7", "12.3"],
     {"call": call_late(pa2, NEW, "f"), "head-H1": head5(pa2, H1K, DUE0 + 150), "head-H2": head5(base, H2K, DUE0 + 150)}, ver_p)

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
ta = prop({"keyring": {"remove": [Ph.id, B.id]}}, [A]); ra = rec(ta); va = veto_of(acct, ta, [Ph], ts(R0 + 300))
record_veto(s, ta, [ra], va, [rec(va, at=R0 + 301)])
ta2 = prop({"keyring": {"remove": [Ph.id]}}, [A], at=R0 + 500, chain=s)
to = prop({"keyring": {"remove": [A.id]}, "vault": vault_change("row2", [(Ph, "Phone")], previous=False)}, [Ph, B], at=R0 + 600, chain=s)
ro = rec(to, at=R0 + 601)
suspend(s, Ph, A, to, [ro], R0 + 650)
vbad = veto_of(acct, to, [A], ts(R0 + 700))
activate(s, to, [ro])
scenario("row-2-thief-has-mac-key", s, [("thief-proposes", ta, "vetoed by Ph"), ("veto", va, "valid"),
                                        ("thief-again-alone", ta2, "refused: v(A)=1"),
                                        ("owner-removes-A-with-vault-change", to, "activates after D + 300 s; A suspended meanwhile"),
                                        ("thief-veto", vbad, "invalid: one vetoer against two signers")],
         {"controllers": sorted([Ph.id, B.id, K1.id, K2.id])}, "Owner wins after the delay; the vault rotates away from the Mac.")

s = base.copy()
tt = prop({"keyring": {"remove": [Ph.id]}}, [A]); rt_ = rec(tt); suspend(s, A, Ph, tt, [rt_], R0 + 60)
vt = veto_of(acct, tt, [Ph], ts(R0 + 120)); record_veto(s, tt, [rt_], vt, [rec(vt, at=R0 + 121)])
scenario("row-3-thief-suspends-first", s, [("thief-proposes-and-suspends", tt, "vetoed by Ph itself"), ("veto", vt, "valid")],
         {"controllers": sorted([A.id, Ph.id, B.id, K1.id, K2.id]), "suspended": []},
         "Ph vetoes its own removal; the suspension ends; A can't propose alone again.")

s = base.copy()
tx = prop({"keyring": {"remove": [A.id]}, "vault": vault_change("row4", [(Ph, "Phone")], previous=False)}, [Ph, B])
toy = prop({"keyring": {"keep": [A.id]}}, [K1, K2], at=R0 + 100)
activate(s, toy, [])
scenario("row-4-thief-has-phone", s, [("thief-proposes", tx, "pending; void once its signers are removed"),
                                      ("owner-full-recovery-keep-A", toy, "full recovery set (a): immediate, final when both homes cover it")],
         {"controllers": sorted([A.id, K1.id, K2.id])}, "Owner wins at once with both security keys.")

kr4k = keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(B, ["approve", "control"], "Passkey"),
                ctrl(K1, ["recover"], "Security key 1"), ctrl(K2, ["recover"], "Security key 2")], threshold=1, rt=1)
s = Chain(); genesis(s, kr4k, [A], adds=[B, K1, K2], label="Four keys"); a4 = account_id(s)
activate(s, transition(s, {"homes": {"appoint": [home_appointment(a4, H1K, H1A, "Home one")]}}, [A, K1], ts(60)), [])
r4 = lambda env, at: receipt_of(a4, env, H1K, ts(at))
e1 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0))
ve1 = veto_of(a4, e1, [B, K2], ts(R0 + 300)); record_veto(s, e1, [r4(e1, R0 + 1)], ve1, [r4(ve1, R0 + 301)])
e2 = transition(s, {"keyring": {"remove": [A.id, K1.id]}, "vault": vault_change("row8", [(B, "Passkey")], previous=False)}, [B, K2], ts(R0 + 400))
ve2 = veto_of(a4, e2, [A, K1], ts(R0 + 500)); record_veto(s, e2, [r4(e2, R0 + 401)], ve2, [r4(ve2, R0 + 501)])
e3 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0 + 600))
ve3 = veto_of(a4, e3, [B, K2], ts(R0 + 700)); record_veto(s, e3, [r4(e3, R0 + 601)], ve3, [r4(ve3, R0 + 701)])
e4 = transition(s, {"keyring": {"remove": [B.id, K2.id]}}, [A, K1], ts(R0 + 800))
scenario("row-8-equal-units-stall", s, [("thief", e1, "vetoed"), ("owner-veto", ve1, "valid"),
                                        ("owner", e2, "vetoed"), ("thief-veto", ve2, "valid"),
                                        ("thief-again", e3, "valid (v=1, two units), vetoed"), ("owner-veto-2", ve3, "valid"),
                                        ("thief-third", e4, "refused: v=2 needs three units")],
         {"controllers": sorted([A.id, B.id, K1.id, K2.id]), "state": "stall"}, "One control plus one recovery key each: stall.")

s = base.copy()
tf = prop({"keyring": {"keep": [], "add": [ctrl(NEW, ["approve", "control"], "New phone")]},
           "vault": vault_change("row9", [(K1, "Security key 1")], previous=False)}, [K1, K2], adds=[NEW])
activate(s, tf, [])
read = call_on(base, K1, "row9", purpose="colophon.history.read", audience=home_ep)
scenario("row-9-both-recovery-keys-no-device", s, [("read-history", read, "ok (recover may read)"),
                                                   ("full-recovery", tf, "full recovery set (a): immediate; new vault, old data unreachable without a recovery-key slot")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "Back in at once.")
scenario("row-10-burglar-both-recovery-keys", s, [("burglar-full-recovery", tf, "immediate: the burglar wins")],
         {"controllers": sorted([NEW.id, K1.id, K2.id])}, "The same bytes by a burglar.")

s = base.copy()
th = prop({"keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")], "remove": [Ph.id]}}, [K1], adds=[NEW])
vh = veto_of(acct, th, [Ph], ts(R0 + 3600)); record_veto(s, th, [rec(th)], vh, [rec(vh, at=R0 + 3601)])
scenario("row-11-honest-mistake", s, [("recovery", th, "vetoed"), ("found-phone", vh, "valid")],
         {"controllers": sorted([A.id, Ph.id, B.id, K1.id, K2.id])}, "Nothing changes.")

s = base.copy(); r_h2 = rec(t1, home=H2K); activate(s, t1, [r_h2])
case("row-12-one-home-down", s, {"result": "ok", "seq": 3, "finality": "provisional until H1's head covers seq 3"},
     "H1 is down: H2's receipt makes the removal due; it applies at once and is final when H1 returns.",
     ["8.7", "changes §H"], {"transition": t1, "receipt": r_h2, "head-H2": head5(s, H2K, DUE0 + 100)}, VER(DUE0 + 200))
t_gone = prop({"homes": {"revoke": [H1K.id]}, "keyring": {"add": [ctrl(NEW, ["approve", "control"], "New phone")]}}, [K1, K2], adds=[NEW])
s = base.copy(); activate(s, t_gone, [])
case("row-12-gone-home-full-set", s, {"result": "ok", "seq": 3, "finality": "final once H2 covers it (H1 is revoked by it)"},
     "H1 is gone for good: both security keys revoke it and add a key in one full-set transition.",
     ["8.7", "changes §H"], {"transition": t_gone, "head-H2": head5(s, H2K, R0 + 100)}, VER(R0 + 200))

tb = prop({"keyring": {"remove": [Ph.id, B.id]}}, [A])
rb = receipt_of(acct, tb, H1K, ts(R0 + 1))
hostile = base.copy(); activate(hostile, tb, [rb])
honest = base.copy(); grant_agent(honest, Ph, ts(5 * 86400), Ph)
case("row-13-backdating-home", honest, {"honestHome": "refuses for ever: it never saw the transition within 300 s of its issued",
                                        "verifiersWithBothHeads": "vouched fork (refused:fork) until the owner's resolve",
                                        "verifiersFollowingOnlyH1": "apply the removal"},
     "At quorum 1 a hostile home and one key cause a fork; the activation's bytes are the determined ones.", ["13.1", "changes §H"],
     {"transition": tb, "receipt": rb, "head-H1": head5(hostile, H1K, 5 * 86400 + 60), "head-H2": head5(honest, H2K, 5 * 86400 + 60)},
     VER(5 * 86400 + 120), branches={"hostile": [(3, hostile.envs[2])]})

s = base.copy()
t17 = prop({"keyring": {"remove": [A.id, K2.id]}, "vault": vault_change("row17", [(Ph, "Phone")], previous=False)}, [Ph, B, K1])
r17 = rec(t17); v17 = veto_of(acct, t17, [A, K2], ts(R0 + 600))
activate(s, t17, [r17])
scenario("row-17-phone-and-one-security-key", s, [("thief-proposes", t17, "three units, consent from K1"),
                                                  ("owner-veto", v17, "invalid: two units against three"),
                                                  ("activate", s.envs[-1], "ok after D + 300 s: the thief wins")],
         {"controllers": sorted([Ph.id, B.id, K1.id])}, "Losing row: more keys than the owner holds.")

# ---------------------------------------------------------------------------------------------
# 12. Swift succession (§15.1, §13.5).
SH, SHA_ = derived("r4/successor-home/signing"), derived("r4/successor-home/agreement")
SR0 = 7200
AFTER, BEFORE = D + 600, D - 600   # F at SR0 + AFTER is after the due time (window end SR0 + 240, plus D)


def successor_with_home(g, receipt_delay=60):
    a = account_id(g)
    known = {k.id: k for k in (A, B, K1, K2, MK, NK, SP, SY, root_s, rec_s)}
    ctrls = json.loads(body_of(g.envs[0]))["keyring"]["controllers"]
    extra = [known[cid(x)] for x in ctrls if "recover" in x["roles"] and cid(x) in known][:1]
    activate(g, transition(g, {"homes": {"appoint": [home_appointment(a, SH, SHA_, "Successor home")]}},
                           [A] + extra, ts(SR0 - 60), origin="https://id.example"), [])
    return receipt_of(a, g.envs[0], SH, ts(SR0 - 60 + receipt_delay))


def record_succession_veto(g, v_env, v_rec, g_rec):
    issued = ts(max(received_of(v_rec), prev_issued(g)))
    return append_unsigned(g, "successionVetoed", field(v_env, "by"), issued, veto=emb(v_env), receipts=[emb(v_rec)],
                           genesisReceipts=[emb(g_rec)])


def swift_case(name, recs, g, f_at, expected, why, signer=A, freeze=None, receipt_delay=60, vetoes=()):
    rg = successor_with_home(g, receipt_delay)
    for v_env, v_rec in vetoes:
        record_succession_veto(g, v_env, v_rec, rg)
    f = (freeze or swift_freeze_signed)(recs, account_id(g), signer, issued=ts(SR0 + f_at))
    write_swift(name, recs + [f], g, expected, why,
                extra_recs={"genesis-receipt.json": rg, **{f"successor/authority/{i + 1:08d}.json": e for i, e in enumerate(g.envs)}})


def gveto(g, key, at=SR0 + 600):
    v = envelope({"protocol": "colophon/veto/5", "account": account_id(g), "transition": sha(body_of(g.envs[0])),
                  "issued": ts(at), "by": key.id, "signers": [key.id]}, key)
    return v, receipt_of(account_id(g), v, SH, ts(at + 1))


recs, _ = swift_library()
g = new_genesis(recs, 2, handover=[A]); swift_case("swift-keyring", recs, g, AFTER, {"succession": "verified"},
                                                   "Receipt 60 s into the succession window; F after the due time.")
g = new_genesis(recs, 2, handover=[A], label="Late receipt")
swift_case("swift-late-genesis-receipt", recs, g, AFTER, {"succession": "unverified"},
           "The receipt is 400 s after the appointing entry, outside the succession window: never due.", receipt_delay=400)
g = new_genesis(recs, 2, handover=[A], label="Too early")
swift_case("swift-freeze-before-window", recs, g, BEFORE, {"succession": "unverified"}, "F written before the due time.")
g = new_genesis(recs, 2, handover=[A], label="Vetoed")
swift_case("swift-succession-vetoed", recs, g, AFTER, {"succession": "unverified", "seq3": "successionVetoed ok"},
           "K1 (current at head) vetoes; the successor home records a successionVetoed entry.", vetoes=[gveto(g, K1)])

kX, kY = derived("swift/x"), derived("swift/y")


def xy_library(t3, t4, t5):
    rs, _ = swift_library()
    k2b = json.loads(unb64(rs[1]["body"]))
    ctrls_xy = k2b["controllers"] + [swift_ctrl(kX, ["approve", "control"], "X"), swift_ctrl(kY, ["approve", "control"], "Y")]
    k3 = {k: v for k, v in k2b.items() if k != "recoverThreshold"}
    k3.update(by="controller", controllers=ctrls_xy, issued=t3, previous=sha(unb64(rs[1]["body"])), seq=3, signer=A.id)
    rs.append(swift_record(k3, A))
    k4 = dict(k3, controllers=[c_ for c_ in ctrls_xy if c_["key"] != b64(kX.point)], issued=t4, previous=sha(unb64(rs[2]["body"])), seq=4)
    rs.append(swift_record(k4, A))
    k5 = dict(k4, controllers=[c_ for c_ in k4["controllers"] if c_["key"] != b64(kY.point)], issued=t5,
              previous=sha(unb64(rs[3]["body"])), seq=5)
    rs.append(swift_record(k5, A))
    return rs


recsXY = xy_library("2026-11-02T08:00:00Z", "2026-11-03T08:00:00Z", "2026-11-04T08:00:00Z")
g = new_genesis(recsXY, 5, handover=[A], label="X vetoes")
swift_case("swift-veto-by-key-removed-earlier", recsXY, g, AFTER, {"succession": "verified", "seq3": "successionVetoed malformed"},
           "X was removed at seq 4, before the last removal and more than the delay before the genesis: X's veto is invalid.",
           vetoes=[gveto(g, kX)])
g = new_genesis(recsXY, 5, handover=[A], label="Y vetoes")
swift_case("swift-veto-by-last-removed", recsXY, g, AFTER, {"succession": "unverified"},
           "Y was current immediately before the last removal: Y may veto.", vetoes=[gveto(g, kY)])
recsW = xy_library("2026-11-02T08:00:00Z", "2026-11-09T09:00:00Z", "2026-11-09T10:00:00Z")
g = new_genesis(recsW, 5, handover=[A], label="X vetoes within delay")
swift_case("swift-veto-by-key-removed-within-delay", recsW, g, AFTER, {"succession": "unverified"},
           "X was removed two replacements back, but was current within the successor's delay before the genesis: X may veto.",
           vetoes=[gveto(g, kX)])

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
gr3 = Chain(); genesis(gr3, keyring([ctrl(A, ["approve", "control"], "Mac"), ctrl(K1, ["recover"], "Kit")], rt=1), [A], adds=[K1],
                       predecessor=pred3, handover=[root_s, rec_s], label="Handover with kit")
swift_case("swift-handover-extra-key-raises-veto", recs3, gr3, AFTER, {"succession": "verified", "seq3": "successionVetoed malformed"},
           "handover carries the root and the kit: one key's veto is too few.", vetoes=[gveto(gr3, rec_s)], freeze=froot)

wr = swift_webauthn_library()
same = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "recover"], "Passkey", verification=True),
        ctrl(SY, ["approve", "control"], "Security key", verification=True)]
g = genesis_from(wr, same, 1, handover=[A]); swift_case("swift-webauthn", wr, g, AFTER, {"succession": "verified"},
                                                       "Shipped-app keys with their roles carried over; F signed by WebAuthn.", signer=SY)
swap = [ctrl(A, ["approve", "control"], "Mac"), ctrl(SP, ["approve", "control"], "Passkey", verification=True),
        ctrl(SY, ["approve", "recover"], "Security key", verification=True)]
g = genesis_from(wr, swap, 1, handover=[A], label="Swap"); swift_case("swift-webauthn-role-swap-without-consent", wr, g, AFTER,
                                                                      {"succession": "unverified"}, "Recover set changed without SP.", signer=SY)
g = genesis_from(wr, swap, 1, handover=[A, SP], label="Swap with consent")
swift_case("swift-webauthn-role-swap-with-consent", wr, g, AFTER, {"succession": "verified"},
           "A format test: the reference tool carries roles over, but a genesis may change them with consent.", signer=SY)

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
                                                   ("new-device", NEW), ("phone", Ph), ("phone/agreement", derived("r5/phone/agreement")),
                                                   ("approve-only", APPR), ("thief-x", X), ("swift-x", kX), ("swift-y", kY)]
                                      + [(f"rate/{i}", derived(f"r5/rate/{i}")) for i in range(65)]
                                      + [(f"plant/{i}", k) for i, k in enumerate(plant)]
                                      + [(f"five/{i}", k) for i, k in enumerate(five)]}})
