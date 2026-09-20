# SPDX-License-Identifier: MIT
"""Cross-document bundle validator tests (N2) for scripts/bundle_lint.py."""
import copy
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")
reconstruct = bl.reconstruct  # M4: decode artefacts
ev_mod = _load("evidence_lint", "evidence_lint.py")  # CF-5: show LINT-EP-06 does NOT catch it


def _bundle(manifest="bundle.scoped.manifest.json"):
    m = reconstruct(json.loads((ROOT / "samples" / manifest).read_text(encoding="utf-8")))
    base = ROOT / "samples"

    def _rc(x):
        return reconstruct(json.loads((base / x).read_text()))
    return [
        m["entity_uid"],
        _rc(m["med"]),
        _rc(m["org"]),
        [_rc(x) for x in m["members"]],
        [_rc(x) for x in m["evidence"]],
    ]


@pytest.mark.parametrize("manifest", ["bundle.scoped.manifest.json",
                                      "bundle.default.manifest.json"])
def test_positive_bundles_are_coherent(manifest):
    """The shipped positive demo bundles must have zero cross-document violations."""
    assert bl.violations(bl.check_bundle(*_bundle(manifest))) == []


def test_device_class_warning_is_not_a_violation():
    """V5: LINT-BND-W1 is a warning — it must not make a bundle fail. A bundle
    whose only finding is the device-class warning still exits 0; the shipped
    bundles emit no warning at all."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle())
    org["acceptance_policy"]["ops"] = "device-class:hsm"
    # keep the F7 digest binding consistent with the mutated ORG, so the
    # device-class warning is the ONLY finding (LINT-BND-10 would otherwise
    # rightly flag the in-memory edit).
    payload = {k: v for k, v in org.items() if k != "doc_cose_b64"}
    hex_ = bl.hashlib.sha256(bl.dcbor(payload)).hexdigest()
    for evd in evidence:
        evd["acceptance_policy_ref"]["doc_digest"]["hex"] = hex_
    # NOT violations(): this test is ABOUT the warning, so it must see it. The
    # R4 sweep that wrapped every call hid exactly what is asserted here.
    issues = bl.check_bundle(entity, med, org, members, evidence)
    rules = [r for r, _ in issues]
    assert bl.violations(issues) == [], "a warning must not make a bundle fail"
    assert "LINT-BND-W1" in rules
    # R5-02: THREE verdicts now, so the partition is stated as a partition.
    # This fixture supplies no policy history, so it also reports LINT-BND-I1 —
    # which is deliberately NOT a violation and deliberately NOT a pass. The
    # old assertion said "nothing here is anything but a W rule"; keeping it
    # would have forced the incompleteness back into the warning class, which
    # is the defect R5-02 is about.
    assert bl.incomplete_of(issues), \
        "a bundle with no chain must report the maximality gap"
    leftover = [r for r in rules
                if not bl.is_warning(r) and not bl.is_incomplete(r)]
    assert leftover == [], leftover
    for manifest in ("bundle.scoped.manifest.json", "bundle.default.manifest.json"):
        assert [r for r, _ in bl.violations(bl.check_bundle(*_bundle(manifest)))
                if r.startswith("LINT-BND-W")] == []


def _org_digest(org):
    payload = {k: v for k, v in org.items() if k != "doc_cose_b64"}
    return bl.hashlib.sha256(bl.dcbor(payload)).hexdigest()


def test_grade_commitment_reveal_verifies_end_to_end():
    """X0: the shipped default bundle names the demo reveal fixture, so
    LINT-BND-11 runs the FULL verification (recompute + declared-class check)
    — and passes. Asserted explicitly, not just via the positive-bundle test."""
    m = reconstruct(json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text(encoding="utf-8")))
    assert m.get("grade_reveals") == "grade-reveal.demo.json"
    assert bl.violations(bl.lint_bundle(m, str(ROOT / "samples"))) == []


def test_reveal_with_undeclared_class_fails():
    """X0 negative: a commitment honestly computed over a class NOT declared
    availability-grade fails the declared-class check."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.default.manifest.json"))
    avail = [e for e in evidence if e.get("delivery_grade") == "availability"][0]
    salt = "64656d6f2d67726164652d73616c7421"
    avail["grade_commitment"] = bl.compute_grade_commitment(salt, "invoice", _org_digest(org))
    reveals = {avail["message_id"]: {"salt": salt, "content_class": "invoice"}}
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence, reveals=reveals))]
    assert "LINT-BND-11" in rules


def test_reveal_with_tampered_salt_fails():
    """X0 negative: a reveal whose salt does not reproduce the sealed
    commitment fails the recompute check."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.default.manifest.json"))
    avail = [e for e in evidence if e.get("delivery_grade") == "availability"][0]
    reveals = {avail["message_id"]: {"salt": "00" * 16, "content_class": "regulatory-filing"}}
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence, reveals=reveals))]
    assert "LINT-BND-11" in rules


def test_bnd13_message_id_collision_across_recipients():
    """S4 (TS clause 6 INTF-4): message_id is globally unique per issuing
    environment — the same message_id reused for a different recipient is a
    collision across the evidence set (LINT-BND-13)."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.default.manifest.json"))
    se = next(e for e in evidence if e.get("type") == "SE-v1")
    clash = copy.deepcopy(se)
    clash["recipient_uid"] = "EU-DE-EOID-7K3D9W0Q2M5FW0"  # same message_id, different recipient
    evidence.append(clash)
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence))]
    assert "LINT-BND-13" in rules


def test_bnd14_system_identity_must_resolve_to_a_system_member():
    """A1 (Annex R): evidence with auth_context.identity=system must name an
    acting MID that, where it is a member of this entity, is an active
    member_type=system member; naming a person member is LINT-BND-14."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.default.manifest.json"))
    person = next(m for m in members if m.get("member_type") != "system")  # an FR person
    de = next(e for e in evidence if e.get("type") == "DE-v1")
    de["auth_context"] = {"identity": "system", "mid": person["mid"],
                          "method": de.get("recipient_auth_method", "wallet-eid-high"),
                          "loa": "very-high"}
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence))]
    assert "LINT-BND-14" in rules


def test_bnd15_agent_se_mandate_must_match_and_be_valid():
    """A2 (Annex R): an agent-sent SE's mandate_ref must be the acting member's
    standing mandate (issuer+id) and in validity at sent_at — a mismatched
    mandate is LINT-BND-15."""
    base = ROOT / "samples"
    agent = reconstruct(json.loads((base / "sample-BW-MEMBER-agent.json").read_text()))
    se = reconstruct(json.loads((base / "sample-SE-agent.json").read_text()))
    entity = agent["uid"]
    se["mandate_ref"] = {"issuer": agent["mandate_ref"]["issuer"], "id": "urn:mandate:forged"}
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [agent], [se]))]
    assert "LINT-BND-15" in rules
    # sanity: the unmutated pair does not trip LINT-BND-15
    se2 = reconstruct(json.loads((base / "sample-SE-agent.json").read_text()))
    rules2 = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [agent], [se2]))]
    assert "LINT-BND-15" not in rules2


def test_bnd16_human_acceptance_scope_not_satisfiable_by_agents():
    """A3 (Annex R): a human_acceptance scope excludes system members from its
    eligible set; an all-agent eligible set is unsatisfiable (LINT-BND-16)."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.scoped.manifest.json"))
    sc = org["scope_map"]["scopes"][0]
    sc["human_acceptance"] = True
    # make every holder of the scope's role a system member
    for m in members:
        if any(r in (m.get("roles") or []) for r in sc.get("roles", [])):
            m["member_type"] = "system"
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence))]
    assert "LINT-BND-16" in rules


def test_bnd18_agent_ack_does_not_satisfy_human_acceptance_scope():
    """A8 (Annex R / §8.3): a system member may verify (S3) but its acknowledgement
    does not satisfy a human_acceptance scope's acceptance (S4) — LINT-BND-18."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.scoped.manifest.json"))
    # the scoped chain lives in the finance scope (F-08): gate THAT scope
    finance = next(s for s in org["scope_map"]["scopes"] if s["scope_id"] == "finance")
    finance["human_acceptance"] = True
    de = next(e for e in evidence if e.get("type") == "DE-v1")  # scope_ref=finance, has s3_attestation
    acker = de["s3_attestation"]["mid"]
    for m in members:
        if m["mid"] == acker:
            m["member_type"] = "system"
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence))]
    assert "LINT-BND-18" in rules


def test_bnd19_relay_b2_reason_maps_to_sender_nde_reason():
    """Finding 7 (twentieth review): a B.2 RelayRejection and the sender NDE for
    the same message must agree on the reason per the TS clause 4.1 mapping —
    policy-violation -> policy-block. A mismatch fires LINT-BND-19."""
    base = ROOT / "samples"
    relay = reconstruct(json.loads((base / "sample-RELAY-b2.json").read_text()))  # reason=policy-violation
    nde = reconstruct(json.loads((base / "sample-NDE.json").read_text()))
    mid = relay["message_id"]
    nde["message_id"] = mid
    # correct mapping: policy-violation -> policy-block
    nde["reason"] = "policy-block"
    good = [r for r, _ in bl.violations(bl.check_bundle("EU-DE-EOID-7K3D9W0Q2M5FW0", {}, {}, [], [relay, nde]))]
    assert "LINT-BND-19" not in good
    # wrong mapping: the typed rejection collapsed to a generic reason
    nde["reason"] = "recipient-unreachable"
    bad = [r for r, _ in bl.violations(bl.check_bundle("EU-DE-EOID-7K3D9W0Q2M5FW0", {}, {}, [], [relay, nde]))]
    assert "LINT-BND-19" in bad


def test_bnd20_ep_hop_seal_digest_is_recomputed_against_the_referenced_object():
    """CF-5 (twenty-first review): LINT-EP-06 can only check that the hex is
    well-formed — ANY 64-hex string survives it, so the digest could point at
    nothing. Where the referenced B.x object is in the SAME bundle, LINT-BND-20
    recomputes and binds it: SHA-256 over the DECODED COSE bytes of the seal.

    The negative is the whole point of the finding: an EP built under the OTHER
    defensible reading (SHA-256 over the base64 TEXT) is structurally perfect and
    passes every shape check — and is now rejected."""
    import base64
    import hashlib
    base = ROOT / "samples"
    ep = reconstruct(json.loads((base / "sample-EP-federated.json").read_text()))
    b1 = reconstruct(json.loads((base / "sample-RELAY-b1.json").read_text()))
    entity = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
    # the published pair binds: the digest recomputes
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [], [ep, b1]))]
    assert "LINT-BND-20" not in rules
    # ...and the base64-TEXT reading of the same seal is caught
    wrong = copy.deepcopy(ep)
    hop = next(h for h in wrong["rdp_chain"] if "evidence" in h)
    hop["evidence"]["seal_digest"]["hex"] = hashlib.sha256(
        b1["seal"]["cose_b64"].encode()).hexdigest()
    rules2 = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [], [wrong, b1]))]
    assert "LINT-BND-20" in rules2
    # sanity: that wrong digest is still perfectly well-formed 64-hex, so the
    # single-object linter (LINT-EP-06) does NOT catch it — only the binding does.
    assert len(hop["evidence"]["seal_digest"]["hex"]) == 64
    assert "LINT-EP-06" not in [r for r, _ in ev_mod.lint(wrong)]


def test_bnd22_outcomes_temporally_coherent_with_expires_at():
    """Finding R1 (twenty-fourth review): the SE carries an authenticated absolute
    deadline `expires_at` (= sent_at + ttl, the ttl being envelope-only and
    otherwise unverifiable). An `expired` NDE must not be premature, and a
    non-availability DE must not post-date expires_at."""
    base = ROOT / "samples"
    se = reconstruct(json.loads((base / "sample-SE.json").read_text()))
    de = reconstruct(json.loads((base / "sample-DE.json").read_text()))
    nde = reconstruct(json.loads((base / "sample-NDE.json").read_text()))
    entity = "EU-FR-PSBID-ZYWVTSRQPNM8M4"

    def bnd22(ev):
        return [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [], ev)) if r == "LINT-BND-22"]

    assert bnd22([se, de]) == []  # honest DE within the deadline
    # a premature `expired` NDE — observed before the message actually expired
    early = copy.deepcopy(nde)
    early.update(message_id=se["message_id"], reason="expired",
                 event="C.5-AcceptanceRejectionExpiry", observed_at="2026-04-05T00:00:00Z")
    assert bnd22([se, early])
    # a verification/acceptance DE delivered AFTER the deadline
    late = copy.deepcopy(de)
    late["delivered_at"] = "2026-04-08T00:00:00Z"
    assert bnd22([se, late])
    # X-21: the availability exemption is REMOVED — delivered_at is the EVENT
    # time and bounds EVERY grade; an availability DE past expires_at fails too.
    avail = copy.deepcopy(de)
    avail.update(delivered_at="2026-04-08T00:00:00Z", delivery_grade="availability")
    assert bnd22([se, avail])


def test_bnd21_wallet_confirmation_verifies_against_the_published_anchor():
    """Finding D (twenty-second review): a wallet-signed recipient confirmation
    MUST verify against the confirming device's PUBLISHED confirmation_key anchor,
    resolved per (mid, device_id) from BW-MEMBER — the reference-verifier check at
    lint time. The negative IS the point: an RDP-minted confirmation under a
    foreign/global key (finding F) does NOT verify against the member's own key."""
    import base64
    import hashlib
    from nacl.signing import SigningKey
    base = ROOT / "samples"
    de = reconstruct(json.loads((base / "sample-DE-walletsig.json").read_text()))
    fr = reconstruct(json.loads((base / "sample-BW-MEMBER-fr.json").read_text()))
    # X-05 (2.3): the walletsig DE's quorum entries are wallet-signed too, so
    # the second acker's member doc must be in the bundle for a clean baseline.
    fr2 = reconstruct(json.loads((base / "sample-BW-MEMBER-fr2.json").read_text()))
    entity = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
    did = de["s3_attestation"]["device_id"]

    def bnd21(members, evidence):
        return [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, members, evidence))
                if r == "LINT-BND-21"]

    # the published pair verifies — clean
    assert bnd21([fr, fr2], [de]) == []
    # a FOREIGN anchor (the published key is not the signer's) fails — exactly the
    # finding-F case: an RDP minting a confirmation under a key that is not the
    # member's own is now caught
    foreign = base64.b64encode(
        SigningKey(hashlib.sha256(b"not-this-member").digest()).verify_key.encode()).decode()
    fr_bad = copy.deepcopy(fr)
    next(d for d in fr_bad["devices"] if d["device_id"] == did)["confirmation_key"]["public_key_b64"] = foreign
    assert bnd21([fr_bad, fr2], [de])
    # wallet-signed but no device_id -> unresolvable per (mid, device_id)
    de_nodid = copy.deepcopy(de)
    de_nodid["s3_attestation"].pop("device_id")
    assert bnd21([fr, fr2], [de_nodid])
    # the member/device is not published at all -> nowhere to resolve the anchor
    assert bnd21([], [de])


def test_bnd15_mandate_reveal_verifies_and_catches_overreach():
    """A1 (nineteenth review): with a mandate-reveal fixture, LINT-BND-15 runs
    the full commitment verification — an in-scope reveal passes; an out-of-scope
    reveal (agent overreach) fires."""
    base = ROOT / "samples"
    agent = reconstruct(json.loads((base / "sample-BW-MEMBER-agent.json").read_text()))
    se = reconstruct(json.loads((base / "sample-SE-agent.json").read_text()))
    entity = agent["uid"]
    rev = reconstruct(json.loads((base / "mandate-reveal.demo.json").read_text()))
    mr = {r["message_id"]: r for r in rev["reveals"]}
    # in-scope reveal (content_class 'invoice' is in the mandate scope): clean
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [agent], [se], mandate_reveals=mr))]
    assert "LINT-BND-15" not in rules
    # overreach: a commitment honestly computed over a class NOT in the mandate
    # scope, then revealed — recompute matches, but the class is out of scope.
    salt = mr[se["message_id"]]["salt"]
    od = se["acceptance_policy_ref"]["doc_digest"]["hex"]
    se2 = reconstruct(json.loads((base / "sample-SE-agent.json").read_text()))
    se2["mandate_ref"]["mandate_commitment"] = bl.compute_mandate_commitment(
        salt, se2["mandate_ref"]["id"], "legal-notice", od)
    bad = {se2["message_id"]: {"salt": salt, "content_class": "legal-notice"}}
    rules2 = [r for r, _ in bl.violations(bl.check_bundle(entity, {}, {}, [agent], [se2], mandate_reveals=bad))]
    assert "LINT-BND-15" in rules2


def test_bnd17_records_scope_needs_a_staffed_records_leaf():
    """F16 (§8.3a): a recoverability=records scope's records_role must be staffed
    by an active member; an unstaffed records_role is LINT-BND-17."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle("bundle.scoped.manifest.json"))
    members = [m for m in members if "records" not in (m.get("roles") or [])]  # drop the records leaf
    rules = [r for r, _ in bl.violations(bl.check_bundle(entity, med, org, members, evidence))]
    assert "LINT-BND-17" in rules


def test_negative_manifest_fails_with_expected_rules():
    """P5: the intentionally incoherent bundle is asserted here and NEVER run
    in the green path — it must fail with exactly the documented rule ids. With
    a single member, quorum:2 is unsatisfiable (LINT-BND-08) AND the scoped DE's
    second acker is off-roster (LINT-BND-12, S2) — both are correct."""
    m = reconstruct(json.loads((ROOT / "samples" / "bundle.negative.manifest.json").read_text(encoding="utf-8")))
    # violations(): LINT-BND-W2 (maximality unproven) is a stated warning, and
    # this test enumerates the VIOLATIONS the negative fixture must produce.
    issues = bl.violations(bl.lint_bundle(m, str(ROOT / "samples")))
    rules = {r for r, _ in issues}
    assert rules == {"LINT-BND-08", "LINT-BND-12", "LINT-BND-17"}, \
        f"expected LINT-BND-08 + LINT-BND-12 + LINT-BND-17, got {sorted(rules)}"


# (id, expected_rule, mutation(entity, med, org, members, evidence))
BND_NEGATIVE_CASES = [
    ("bnd-01-capability-mismatch", "LINT-BND-01",
     lambda e, med, org, mem, ev: med["mls"].update(scopes_supported=False)),
    ("bnd-02-scope-role-no-member", "LINT-BND-02",
     lambda e, med, org, mem, ev: mem[0]["roles"].remove("legal")),
    ("bnd-03-no-receive-capability", "LINT-BND-03",
     lambda e, med, org, mem, ev: [d.update(capabilities=["sign"]) for d in mem[0]["devices"]]),
    ("bnd-04-evidence-policy-mismatch", "LINT-BND-04",
     lambda e, med, org, mem, ev: ev[0]["acceptance_policy_ref"].update(policy_version="9999-99-99.9")),
    ("bnd-05-scope-ref-unresolved", "LINT-BND-05",
     lambda e, med, org, mem, ev: ev[0]["scope_ref"].update(scope_id="ghost-scope")),
    # F6 (PoC feedback): the implicit default scope is fixed at version "1" (§8.3a).
    ("bnd-05-default-scope-wrong-version", "LINT-BND-05",
     lambda e, med, org, mem, ev: ev[0].update(scope_ref={"scope_id": "default",
                                                          "version": "2"})),
    ("bnd-06-uid-mismatch", "LINT-BND-06",
     lambda e, med, org, mem, ev: med.update(uid="EU-DE-EOID-7K3D9W0Q2M5FW0")),
    # P4 (ninth review): acceptance-policy satisfiability, umbrella §8.3 —
    # counting unit = distinct active member, never the device.
    ("bnd-07-quorum-zero", "LINT-BND-07",
     lambda e, med, org, mem, ev: org["acceptance_policy"].update(finance="quorum:0")),
    ("bnd-07-malformed-policy", "LINT-BND-07",
     lambda e, med, org, mem, ev: org["acceptance_policy"].update(legal="sometimes")),
    ("bnd-08-quorum-unsatisfiable", "LINT-BND-08",
     # quorum:2 with a single remaining member — one member's several
     # ack-capable devices still count ONCE.
     lambda e, med, org, mem, ev: mem.pop(1)),
    ("bnd-08-any-one-unsatisfiable", "LINT-BND-08",
     lambda e, med, org, mem, ev: mem[1]["roles"].remove("invoices")),
    ("bnd-09-all-empty-eligible-set", "LINT-BND-09",
     # nobody holds 'legal' any more: 'all' over an empty set is ambiguous.
     lambda e, med, org, mem, ev: mem[0]["roles"].remove("legal")),
    ("bnd-09-all-member-not-ack-capable", "LINT-BND-09",
     lambda e, med, org, mem, ev: [d.update(capabilities=["receive"])
                                   for d in mem[0]["devices"]]),
    # F7 (PoC feedback): doc_digest binds evidence to the published ORG content
    # — the raw-sha256 of the ORG's deterministic-CBOR body (§8.3, reseal-stable).
    ("bnd-10-doc-digest-mismatch", "LINT-BND-10",
     lambda e, med, org, mem, ev: ev[0]["acceptance_policy_ref"]["doc_digest"].update(
         hex="ab" * 32)),
    # V0 (thirteenth review, §8.3b): availability is never implicit — the
    # scoped demo ORG declares no availability-grade class.
    ("bnd-11-availability-not-declared", "LINT-BND-11",
     lambda e, med, org, mem, ev: ev[0].update(delivery_grade="availability")),
    # V5 (thirteenth review, §8.3): device-class outside advanced profiles is a
    # WARNING (non-fatal, LINT-BND-W1) — asserted via the same harness; main()
    # excludes W-rules from the exit code (test below).
    ("bnd-w1-device-class-warning", "LINT-BND-W1",
     lambda e, med, org, mem, ev: org["acceptance_policy"].update(
         ops="device-class:hsm")),
    # S2 (fifteenth review, TS clause 6 INTF-2): a recipient confirmation whose
    # mid is not an active, ack-capable member of the recipient entity does not
    # satisfy any acceptance policy.
    ("bnd-12-confirmation-off-roster", "LINT-BND-12",
     lambda e, med, org, mem, ev: next(x["s3_attestation"] for x in ev
                                       if x.get("s3_attestation")).update(mid="ZZZZZZZZT")),
]


@pytest.mark.parametrize("case", BND_NEGATIVE_CASES, ids=[c[0] for c in BND_NEGATIVE_CASES])
def test_bundle_lint_rejects(case):
    _id, rule, fn = case
    entity, med, org, members, evidence = copy.deepcopy(_bundle())
    fn(entity, med, org, members, evidence)
    # NOT violations(): this table drives both violation cases and the W1
    # warning case, so it must see every issue the linter reports. Wrapping it
    # would hide the one row that is about a warning — the same mistake as the
    # blanket sweep that hid test_device_class_warning_is_not_a_violation.
    rules = [r for r, _ in bl.check_bundle(entity, med, org, members, evidence)]
    assert rule in rules, f"{_id}: expected {rule}, got {rules}"
