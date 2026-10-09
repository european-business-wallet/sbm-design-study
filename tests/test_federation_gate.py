# SPDX-License-Identifier: MIT
"""Batch A / A5 — the federation admission GATE.

A1 published the register, A2 sealed one, A3 published the descriptor and A4
wrote the rule. None of them made a verifier ask the question. This file drives
the two rules that do, and the third verdict that reports the question
unanswered:

  LINT-TRUST-06  every provider a bundle names was admitted AT THE INSTANT OF
                 ITS OWN ACT. The provider set is DERIVED from the evidence
                 Schemas, not hand-written — R8-05 found six occurrences where
                 a hand-written list named three.

  LINT-TRUST-07  a descriptor's seal key is one the register pins to that
                 participant, and the register admits the participant at the
                 descriptor's own `asserted_at`.

  LINT-BND-I6    the register was not supplied. Nothing is wrong with the
                 evidence; the material to decide admission was not given, so
                 the verification is INCOMPLETE (exit 3) and not a pass.

The register is a SECOND input, never a replacement: `LINT-TRUST-01..05` and
the `--trust-store` slice are unchanged, and the last test here says so.
"""
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_lint as bl  # noqa: E402
import lint_cli as lc  # noqa: E402

SHIPPED = ["bundle.default.manifest.json", "bundle.scoped.manifest.json",
           "bundle.federated.manifest.json", "bundle.walletsig.manifest.json"]


def _run(manifest, *flags):
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "bundle_lint.py"),
         "--trust-store", str(ROOT / "samples" / "trust-store.demo.json"),
         *flags, str(ROOT / "samples" / manifest)],
        capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def _fa_seal(record, *, seed="federation-authority-demo",
             kid="federation-authority"):
    """Seal ONE membership record exactly as the Federation Authority does
    (`regen_samples._emit_register`): COSE_Sign1 over the dCBOR record minus
    {signature, timestamp}, then the demo QTS over the seal. Acting as the FA
    is legitimate here only because the FA key is DEMO material; it is how a
    test states "this register is genuine, and says X" rather than "this
    register was edited to say X" — which after R10-01 is refused on sight."""
    import base64
    import mock_rdp as mock
    body = {k: v for k, v in record.items() if k not in ("signature", "timestamp")}
    sig = base64.b64encode(mock.cose_sign(mock._dcbor(body), kid=kid,
                                          seed=seed)).decode("ascii")
    return dict(body, signature=sig,
                timestamp=mock._qts_over_cose(base64.b64decode(sig),
                                              body["asserted_at"])["token_b64"])


def _anchor():
    return lc.federation_authority_anchors(
        lc.load_trust_store(str(ROOT / "samples" / "trust-store.demo.json")))


# ---------------------------------------------------------------------------
# The input
# ---------------------------------------------------------------------------

def test_the_register_is_a_declared_retained_material_input():
    assert "federation_register" in bl.RETAINED_MATERIAL_INPUTS


@pytest.mark.parametrize("manifest", SHIPPED)
def test_every_shipped_manifest_supplies_the_register(manifest):
    """The positive case must be proven by the sample bar itself. It must also
    be proven by a fixture that CARRIES the input: the parametrised absence
    probe in test_release_probes skips an input the default fixture does not
    have, and a skipping probe looks exactly like a passing one."""
    m = json.loads((ROOT / "samples" / manifest).read_text())
    assert m.get("federation_register") == "federation.stage1.demo.json"


@pytest.mark.parametrize("manifest", SHIPPED)
def test_the_shipped_bundles_report_no_admission_finding(manifest):
    code, out = _run(manifest, "--allow-incomplete")
    assert "LINT-TRUST-06" not in out, out
    assert "LINT-BND-I6" not in out, out
    assert code == 0, out


def test_a_malformed_register_raises_rather_than_admitting_nobody(tmp_path):
    """Fail closed. A register that resolved to an empty one would report every
    provider unknown to the federation and LOOK like a fail-closed run while
    having no input at all."""
    bad = tmp_path / "register.json"
    bad.write_text('{"records": [{"role": "rdp"}]}')
    with pytest.raises(ValueError, match="participant_id"):
        lc.load_federation_register(str(bad))


# ---------------------------------------------------------------------------
# LINT-BND-I6 — the register was not supplied
# ---------------------------------------------------------------------------

def test_a_bundle_with_no_register_is_INCOMPLETE_and_not_a_pass():
    code, out = _run("bundle.no-register.manifest.json")
    assert "LINT-BND-I6" in out, out
    assert "[OK  ]" not in out
    assert code == 3, out


def test_the_gap_is_a_gap_and_the_finding_is_a_finding():
    """One rule id may not carry two verdicts. `is_incomplete` classifies by
    the `LINT-BND-I` prefix, so a row emitting LINT-TRUST-06 on ABSENCE would
    report a violation where the design calls for INCOMPLETE — and teaching
    the classifier to recognise LINT-TRUST-06 would make a genuine `suspended`
    finding report INCOMPLETE too. That is behaviour selected by a rule
    identifier, the defect R8-06 closed."""
    assert bl.is_incomplete("LINT-BND-I6")
    assert not bl.is_incomplete("LINT-TRUST-06")
    row = next(p for p in json.loads(
        (ROOT / "docs" / "required-properties.json").read_text())["properties"]
        if p["id"] == "federation-admission")
    assert row["gap_rule"] == "LINT-BND-I6"
    assert row["strategy"] == "report_gap"
    assert row["when"] == {"kind": "always"}
    assert "federation-admission" in json.loads(
        (ROOT / "docs" / "required-properties.json").read_text())["mandatory"]


# ---------------------------------------------------------------------------
# LINT-TRUST-06 — admitted at the instant of the act
# ---------------------------------------------------------------------------

def test_an_act_inside_a_suspension_window_is_a_violation():
    """The evidence is byte-identical to the positive run. The only thing that
    changed is the register, so the finding can only be the admission state."""
    code, out = _run("bundle.suspended.manifest.json")
    assert "LINT-TRUST-06" in out and "'suspended'" in out, out
    assert "2026-04-04T10:15:00Z" in out, "the ACT's instant is not reported"
    assert code == 1, out


def test_the_provider_set_is_derived_from_the_schemas():
    """Not hand-written. R8-05: the round-7 gate looked only at top-level
    `rdp_id` and reported three occurrences where there were six."""
    fields = bl._provider_id_fields()
    assert {"rdp_id", "sending_rdp_id", "receiving_rdp_id"} <= fields
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert "rdp_identity_inventory" in src


def test_every_provider_is_paired_with_its_own_act_instant():
    """An EP composes acts by several providers at several instants. Resolving
    them all against one instant — the EP's, or the verifier's — would ask the
    wrong question about every entry but one."""
    ep = json.loads(
        (ROOT / "samples" / "sample-EP-federated.json").read_text())["projection"]
    acts = {where: (pid, at) for pid, at, where in bl._provider_acts(ep)}
    assert acts["rdp_chain[0].rdp_id"][1] != acts["rdp_chain[1].rdp_id"][1], \
        "both chain entries resolved to one instant"
    for where, (_pid, at) in acts.items():
        assert at, f"{where} carries no act instant"
    # The nested SE is dated by its own `sent_at`, not by the EP.
    assert acts["se.rdp_id"][1] == ep["se"]["sent_at"]


def test_a_provider_this_verifier_cannot_date_is_a_violation_not_a_skip():
    """The one failure mode a hand-written type→instant map has is silence."""
    ev = {"type": "XX-v1", "rdp_id": "urn:sbm:rdp:mockeu-001"}
    out = bl.check_bundle(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", {}, {}, [], [ev],
        federation_register=json.loads(
            (ROOT / "samples" / "federation.stage1.demo.json").read_text()),
        fa_anchors=_anchor())
    assert any(r == "LINT-TRUST-06" and "no act instant" in m for r, m in out), out


def test_the_act_instant_map_covers_every_evidence_schema():
    """A new evidence type cannot arrive without either an entry in the map or
    a deliberate exclusion — the map is knowledge, but its COVERAGE is derived."""
    declared = set()
    for p in sorted((ROOT / "schemas").glob("evidence-*.json")):
        d = json.loads(p.read_text())
        t = (d.get("properties", {}).get("type") or {}).get("const")
        if t:
            declared.add(t)
    missing = declared - set(bl.ACT_INSTANT) - bl.ACT_INSTANT_COMPOSED
    assert not missing, (
        f"evidence type(s) {sorted(missing)} carry no act instant in "
        "bundle_lint.ACT_INSTANT and are not declared composed")


# ---------------------------------------------------------------------------
# LINT-TRUST-07 — the descriptor seal key the register pins
# ---------------------------------------------------------------------------

STORE = json.loads((ROOT / "samples" / "trust-store.demo.json").read_text())
REGISTER = json.loads(
    (ROOT / "samples" / "federation.stage1.demo.json").read_text())
DESCRIPTOR = json.loads(
    (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())


def _need(mod):
    try:
        __import__(mod)
    except Exception:
        pytest.skip(f"{mod} not installed", allow_module_level=True)


_need("cbor2")
_need("nacl")


def _discovery_lint():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "discovery_lint_a5", ROOT / "scripts" / "discovery_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_shipped_descriptor_is_authorised_by_the_register():
    issues = _discovery_lint().lint(
        DESCRIPTOR, trust_store=lc.load_trust_store(
            str(ROOT / "samples" / "trust-store.demo.json")),
        federation_register=REGISTER)
    assert [i for i in issues if i[0] == "LINT-TRUST-07"] == [], issues


def test_a_descriptor_sealed_by_an_unpinned_key_fails():
    """The work order's closure criterion. A key the federation never pinned to
    this participant cannot speak for it — `LINT-TRUST-05` one level up."""
    import copy
    import mock_rdp as mock
    body = copy.deepcopy(DESCRIPTOR["projection"])
    rogue = "mockeu-001-rogue"
    body["kid"] = rogue
    sealed = mock.discovery_artifact(body, kid=rogue, seed=f"{rogue}-demo")
    store = copy.deepcopy(STORE)
    # The rogue key IS in the store — otherwise LINT-TRUST-01 fires first and
    # the probe would prove only that an unknown signer is rejected.
    store["entries"][rogue] = {
        "role": "discovery-publisher",
        "identities": ["urn:sbm:rdp:mockeu-001"],
        "pubkey_b64": mock.demo_public_key_b64(f"{rogue}-demo"),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-06-30T23:59:59Z"}
    # `load_trust_store` returns the parsed document itself, so an in-memory
    # store is the same thing it would have loaded from disk.
    issues = _discovery_lint().lint(
        sealed, trust_store=store, federation_register=REGISTER)
    assert any(r == "LINT-TRUST-07" and "not an authorized seal key" in m
               for r, m in issues), issues


def test_a_descriptor_whose_participant_is_not_admitted_fails():
    """An excluded provider stops being resolved (§13.1). Reporting only the
    key would be a gate measuring part of its own surface."""
    import copy
    reg = copy.deepcopy(REGISTER)
    i = next(n for n, r in enumerate(reg["records"])
             if r["participant_id"] == "urn:sbm:rdp:mockeu-001")
    rec = dict(reg["records"][i], status="excluded",
               status_history=[{"status": "excluded",
                                "from": "2026-01-01T00:00:00Z"}])
    # R10-01: the exclusion is SEALED by the Federation Authority. This test
    # used to edit a signed register and expect the edit to be honoured —
    # which is the attack, not the control.
    reg["records"][i] = _fa_seal(rec)
    issues = _discovery_lint().lint(
        DESCRIPTOR, trust_store=lc.load_trust_store(
            str(ROOT / "samples" / "trust-store.demo.json")),
        federation_register=reg)
    assert any(r == "LINT-TRUST-07" and "excluded" in m for r, m in issues), issues


def test_a_participant_with_no_record_is_rejected_fail_closed():
    issues = _discovery_lint().lint(
        DESCRIPTOR, trust_store=lc.load_trust_store(
            str(ROOT / "samples" / "trust-store.demo.json")),
        federation_register={"records": []})
    assert any(r == "LINT-TRUST-07" and "no membership record" in m
               for r, m in issues), issues


# ---------------------------------------------------------------------------
# The register is a SECOND input, not a replacement
# ---------------------------------------------------------------------------

def test_the_trust_store_slice_is_not_relaxed():
    """A5 adds a gate; it removes none. `LINT-TRUST-01..05` keep their owners
    and the demo store keeps its job — after this batch it stands in for the
    Trusted List ONLY, and the register stands for admission."""
    cat = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text())
    owners = {r["id"]: r["owner_fn"] for r in cat["rules"]}
    assert owners["LINT-TRUST-01"] == "check_trust"
    assert owners["LINT-TRUST-02"] == "check_trust"
    assert owners["LINT-TRUST-03"] == "check_trust"
    assert owners["LINT-TRUST-04"] == "_relay_peer_trust"
    assert owners["LINT-TRUST-05"] == "check_directory_pin"
    assert owners["LINT-TRUST-06"] == "check_bundle"
    assert owners["LINT-TRUST-07"] == "check_register_pin"


# ---------------------------------------------------------------------------
# R10-01 — the register is authenticated AT INGRESS, on the consuming path
#
# Batch A's closure verified `_verify_record` in test_federation_stage1.py — a
# fixture helper — and never the path that CONSUMES a register. That path
# checked the container's shape and read every status and pinned key as
# written. These tests drive the two consumers themselves: descriptor pinning
# (discovery_lint, LINT-TRUST-07) and bundle admission (bundle_lint's CLI,
# LINT-TRUST-06). A test of the verifying instrument is not a test of the
# verifier that consumes it — that distinction is the whole finding.
# ---------------------------------------------------------------------------

import base64 as _b64  # noqa: E402
import copy as _copy  # noqa: E402
import hashlib as _hl  # noqa: E402

PID = "urn:sbm:rdp:mockeu-001"


def _record(reg):
    return next(n for n, r in enumerate(reg["records"])
                if r["participant_id"] == PID)


def _attacker():
    """A key the Federation Authority never pinned, and a descriptor for
    mockeu-001 sealed with it. The key IS in the store, so LINT-TRUST-01
    cannot mask the result: the only thing standing between this descriptor
    and acceptance is whether the register was believed."""
    import mock_rdp as mock
    kid = "mockeu-001-attacker"
    pub = mock.demo_public_key_b64(f"{kid}-demo")
    body = _copy.deepcopy(DESCRIPTOR["projection"]); body["kid"] = kid
    store = _copy.deepcopy(STORE)
    store["entries"][kid] = {"role": "discovery-publisher", "identities": [PID],
                             "pubkey_b64": pub, "not_before": "2026-01-01T00:00:00Z",
                             "not_after": "2027-06-30T23:59:59Z"}
    pin = {"kid": kid, "spki_sha256": _hl.sha256(_b64.b64decode(pub)).hexdigest(),
           "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-06-30T23:59:59Z"}
    return mock.discovery_artifact(body, kid=kid, seed=f"{kid}-demo"), store, pin


def _mutate(kind):
    reg = _copy.deepcopy(REGISTER); i = _record(reg); rec = reg["records"][i]
    if kind == "unsigned":
        rec.pop("signature"); rec.pop("timestamp")
    elif kind == "wrong-authority":
        # Sealed by the DESIGN authority: §13.1 keeps the roles distinct.
        reg["records"][i] = _fa_seal(rec, seed="design-authority-demo",
                                     kid="design-authority")
    elif kind == "signature-tampered":
        raw = bytearray(_b64.b64decode(rec["signature"])); raw[-1] ^= 0x01
        rec["signature"] = _b64.b64encode(bytes(raw)).decode()
    elif kind == "payload-divergent":
        # THE KEY-SUBSTITUTION ATTACK: a field changed, the FA's signature
        # left in place — now stale over a body it never signed.
        rec["authorized_seal_keys"] = [_attacker()[2]]
    elif kind == "timestamp-over-another-seal":
        other = reg["records"][(i + 1) % len(reg["records"])]
        rec["timestamp"] = other["timestamp"]
    elif kind == "schema-invalid":
        reg["records"][i] = _fa_seal(dict(rec, unexpected_field="x"))
    elif kind == "overlapping-history":
        reg["records"][i] = _fa_seal(dict(rec, status="excluded", status_history=[
            {"status": "admitted", "from": "2026-01-01T00:00:00Z",
             "until": "2026-12-01T00:00:00Z"},
            {"status": "excluded", "from": "2026-03-01T00:00:00Z"}]))
    elif kind == "summary-inconsistent":
        reg["records"][i] = _fa_seal(dict(rec, status="suspended"))
    elif kind == "duplicate-participant":
        reg["records"].append(_copy.deepcopy(rec))
    return reg


MUTATIONS = ["unsigned", "wrong-authority", "signature-tampered",
             "payload-divergent", "timestamp-over-another-seal",
             "schema-invalid", "overlapping-history", "summary-inconsistent",
             "duplicate-participant"]


def test_the_genuine_register_authenticates():
    """The control. Every refusal below means something only if this holds."""
    reg, issues = lc.authenticate_register(REGISTER, _anchor())
    assert issues == [] and isinstance(reg, lc.AuthenticatedRegister)


@pytest.mark.parametrize("kind", MUTATIONS)
def test_descriptor_pinning_refuses_an_unauthenticated_register(kind):
    """Consumer 1: discovery_lint. The genuine descriptor, a mutated register.
    Schema, history and summary cases are RE-SEALED by the FA, so they prove
    the refusal is about the content and not about a broken seal."""
    issues = _discovery_lint().lint(DESCRIPTOR, verify_demo=True,
                                    trust_store=STORE,
                                    federation_register=_mutate(kind))
    assert "LINT-TRUST-08" in {r for r, _ in issues}, (kind, issues)


def _bundle_with(register):
    """Consumer 2: bundle_lint's CLI, with a probe register beside the default
    manifest — the path `make lint` takes, not a function under it."""
    reg_p = ROOT / "samples" / "federation.__probe.json"
    man_p = ROOT / "samples" / "bundle.__probe.manifest.json"
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    m["federation_register"] = reg_p.name
    reg_p.write_text(json.dumps(register)); man_p.write_text(json.dumps(m))
    try:
        return _run(man_p.name)
    finally:
        reg_p.unlink(); man_p.unlink()


@pytest.mark.parametrize("kind", MUTATIONS)
def test_bundle_admission_refuses_an_unauthenticated_register(kind):
    code, out = _bundle_with(_mutate(kind))
    assert "LINT-TRUST-08" in out, (kind, out)
    assert code == 1, (kind, code, out)


def test_the_key_substitution_attack_is_refused_end_to_end():
    """R10-01 in its strongest form, which the review's probe did not reach:
    the attacker's own key installed in the register under the Federation
    Authority's STALE signature, and a descriptor sealed with it. Before
    R10-01 this returned zero findings."""
    forged, store, _pin = _attacker()
    issues = _discovery_lint().lint(forged, trust_store=store,
                                    federation_register=_mutate("payload-divergent"))
    rules = {r for r, _ in issues}
    assert "LINT-TRUST-08" in rules, issues
    assert rules, "an attacker's descriptor was accepted"


def test_a_register_with_no_configured_anchor_is_not_consulted():
    """No anchor, no authentication, no admission. The bundle path reports the
    property unestablished (INCOMPLETE); the descriptor path reports a register
    it could not consult rather than ignoring it in silence."""
    out = bl.check_bundle("EU-FR-PSBID-ZYWVTSRQPNM8M4", {}, {}, [], [],
                          federation_register=REGISTER, fa_anchors=None)
    assert any(r == "LINT-BND-I6" and "no Federation Authority anchor" in m
               for r, m in out), out
    issues = _discovery_lint().lint(DESCRIPTOR, federation_register=REGISTER)
    assert any(r == "LINT-TRUST-08" for r, _ in issues), issues


def test_the_authority_can_rotate_its_key():
    """R10-02, "authority bootstrap/update behaviour". B1 refused a store with
    two Federation Authority entries as ambiguous — which made rotation
    impossible, since an authority rolling its key over has two valid keys for
    a while and records sealed under each. Nothing is chosen between: each
    record names its signer in its own `kid`, and each key speaks only inside
    its own window at the record's `asserted_at`."""
    import mock_rdp as mock
    store = _copy.deepcopy(STORE)
    store["entries"]["federation-authority"]["not_after"] = "2026-06-30T23:59:59Z"
    store["entries"]["federation-authority-2"] = {
        "role": "federation-authority",
        "pubkey_b64": mock.demo_public_key_b64("federation-authority-2-demo"),
        "not_before": "2026-06-01T00:00:00Z", "not_after": "2027-06-30T23:59:59Z"}
    anchors = lc.federation_authority_anchors(store)
    assert sorted(anchors) == ["federation-authority", "federation-authority-2"]
    reg = _copy.deepcopy(REGISTER)
    old_key = lambda r: _fa_seal(dict(r, asserted_at="2026-05-01T00:00:00Z"))
    new_key = lambda r: _fa_seal(r, seed="federation-authority-2-demo",
                                 kid="federation-authority-2")
    reg["records"] = [old_key(reg["records"][0])] + \
                     [new_key(r) for r in reg["records"][1:]]
    got, issues = lc.authenticate_register(reg, anchors)
    assert issues == [] and got is not None, issues
    # A retired key does not keep speaking: sealed by the OLD key, asserted
    # after that key's window closed.
    reg["records"][0] = _fa_seal(dict(reg["records"][0], asserted_at="2026-09-01T00:00:00Z"))
    got, issues = lc.authenticate_register(reg, anchors)
    assert got is None and any("retired key" in m for _, m in issues), issues


def test_the_anchor_is_configuration():
    """An empty or role-less store configures no anchor; the design authority
    is never one."""
    assert lc.federation_authority_anchors({"entries": {}}) == {}
    assert "design-authority" not in lc.federation_authority_anchors(STORE)


def test_pinning_refuses_a_register_that_skipped_authentication():
    """The type is the guard: `check_register_pin` refuses anything that did
    not come out of `authenticate_register`, so a future caller cannot forget
    the step by reaching for the pin check directly."""
    with pytest.raises(TypeError, match="AuthenticatedRegister"):
        lc.check_register_pin(DESCRIPTOR["projection"], "", STORE, REGISTER)


# ---------------------------------------------------------------------------
# R10-02 / R10-X1 — an assertion speaks up to its own `asserted_at`
#
# Signing a register (R10-01) proves WHO asserted the history. It does not
# prove the history includes the status change relevant to the act. The
# review's case: a genuine, old `admitted` record replayed against an act
# that followed a later suspension it had never heard of. Driven through
# `check_bundle`, the consumer, with genuinely FA-sealed registers.
# ---------------------------------------------------------------------------

EARLY, LATE = "2026-02-15T10:00:00Z", "2026-04-04T10:15:00Z"


def _acts(*instants):
    return [{"type": "SE-v1", "rdp_id": PID, "sent_at": at} for at in instants]


def _register_where_001(history, asserted_at):
    reg = _copy.deepcopy(REGISTER); i = _record(reg)
    reg["records"][i] = _fa_seal(dict(reg["records"][i],
                                      status=history[-1]["status"],
                                      status_history=history,
                                      asserted_at=asserted_at))
    return reg


# The OLD genuine record: admitted, asserted 1 March.
OLD = _register_where_001([{"status": "admitted", "from": "2026-01-01T00:00:00Z"}],
                          "2026-03-01T00:00:00Z")
# The LATER genuine record: suspended from 15 March, asserted 1 June.
NEW = _register_where_001([
    {"status": "admitted", "from": "2026-01-01T00:00:00Z", "until": "2026-03-15T00:00:00Z"},
    {"status": "suspended", "from": "2026-03-15T00:00:00Z"}], "2026-06-01T00:00:00Z")


def _admission(register, evidence):
    out = bl.check_bundle("EU-FR-PSBID-ZYWVTSRQPNM8M4", {}, {}, [], evidence,
                          federation_register=register, fa_anchors=_anchor())
    return [(r, m) for r, m in out if r in ("LINT-TRUST-06", "LINT-TRUST-08")
            or (r == "LINT-BND-I6")]


def test_an_old_record_cannot_admit_an_act_after_it_was_asserted():
    """THE case. Holding only the old record, the act after the suspension is
    not `admitted`: it is unestablished (INCOMPLETE), because the record was
    asserted before the act and cannot speak for it."""
    got = _admission(OLD, _acts(LATE))
    assert [r for r, _ in got] == ["LINT-BND-I6"], got
    # The REASON, not an identifier. This asserted that the message carried the
    # round identifier `R10-X1`, which an implementer reading the diagnostic has
    # no way to resolve — so the identifier was removed from the message and this
    # now holds the message to the thing it has to explain: that the record was
    # asserted before the act and therefore cannot speak for it.
    assert "NOT ESTABLISHED" in got[0][1], got[0][1]
    assert "cannot speak for a later instant" in got[0][1], got[0][1]


def test_the_later_record_reports_the_suspension_as_a_violation():
    got = _admission(NEW, _acts(LATE))
    assert any(r == "LINT-TRUST-06" and "'suspended'" in m for r, m in got), got


def test_a_historical_positive_survives_a_later_suspension():
    """Admission AT THE ACT: an act on 15 February was admitted, and the
    suspension from 15 March does not reach back and unmake it."""
    assert _admission(NEW, _acts(EARLY)) == []


def test_missing_coverage_does_not_turn_earlier_valid_acts_into_failures():
    """The review's second clause. With the old record, the early act is still
    covered and still admitted; only the late act is unestablished — no
    violation for either."""
    got = _admission(OLD, _acts(EARLY, LATE))
    assert [r for r, _ in got] == ["LINT-BND-I6"], got
    assert LATE in got[0][1] and EARLY not in got[0][1]


def test_the_2036_act_is_not_admitted_by_a_2026_assertion():
    """The review's first probe: the unchanged shipped register answered
    `admitted` for an act in 2036."""
    got = _admission(REGISTER, _acts("2036-01-01T00:00:00Z"))
    assert [r for r, _ in got] == ["LINT-BND-I6"], got


# ---------------------------------------------------------------------------
# R10-X5 / D10-01 — the EP composer is admitted AT COMPOSITION
#
# A package records other providers' acts, each at its own instant, and is
# itself an act: its composer seals it at the instant its timestamp attests.
# The demo timestamp carried no time, so that instant was unobtainable and the
# composer went unchecked. The review's test: the composer suspended between
# the last relay hop and the sealing.
# ---------------------------------------------------------------------------

def _ep_stamped_at(gen_time):
    """sample-EP-federated, timestamped at `gen_time`. The same package: the
    timestamp is a SIBLING of the seal, and its imprint is SHA-256 of the seal,
    which does not change — only the instant the TSA attests does."""
    import cbor2
    import mock_rdp as mock
    art = json.loads((ROOT / "samples" / "sample-EP-federated.json").read_text())
    cose, _qts = cbor2.loads(_b64.b64decode(art["sm_artifact_b64"]))
    stamped = mock._dcbor([cose, mock._qts_over_cose(cose, gen_time)])
    return lc.reconstruct({"sm_artifact_b64": _b64.b64encode(stamped).decode(),
                           "projection": art["projection"]})


# The composer (se.rdp_id) admitted until 10:30, then suspended. Every act the
# package RECORDS — SE 10:15, CE 10:15:30, the relay hop 10:16:23 — precedes it.
COMPOSER_SUSPENDED = _register_where_001([
    {"status": "admitted", "from": "2026-01-01T00:00:00Z", "until": "2026-04-04T10:30:00Z"},
    {"status": "suspended", "from": "2026-04-04T10:30:00Z"}], "2026-06-01T00:00:00Z")


def _composition_findings(ep):
    return [(r, m) for r, m in _admission(COMPOSER_SUSPENDED, [ep])
            if "composition" in m]


def test_the_timestamp_carries_the_composition_instant():
    ep = _ep_stamped_at("2026-04-04T11:00:00Z")
    assert lc.sealed_at(ep) == "2026-04-04T11:00:00Z"


def test_a_composer_suspended_before_sealing_is_a_violation():
    """Every recorded act is admitted — they all precede the suspension. The
    package is sealed after it. Only the composition is refused."""
    got = _admission(COMPOSER_SUSPENDED, [_ep_stamped_at("2026-04-04T11:00:00Z")])
    assert [r for r, _ in got] == ["LINT-TRUST-06"], got
    assert "composition" in got[0][1] and "'suspended'" in got[0][1]


def test_the_same_package_sealed_before_the_suspension_passes():
    """The control: identical package, identical register, composed at 10:20.
    The verdict turns on the composition instant and on nothing else."""
    assert _admission(COMPOSER_SUSPENDED, [_ep_stamped_at("2026-04-04T10:20:00Z")]) == []


def test_a_package_whose_timestamp_has_no_time_is_unestablished_not_passed():
    """A legacy demo token, or one this verifier cannot read, leaves the
    composition instant unobtainable: the composer's admission is reported
    unestablished, never assumed."""
    import cbor2
    import mock_rdp as mock
    art = json.loads((ROOT / "samples" / "sample-EP-federated.json").read_text())
    cose, _qts = cbor2.loads(_b64.b64decode(art["sm_artifact_b64"]))
    legacy = {"format": "rfc3161", "tsa_id": "QTSA:MockEU:TS-01",
              "token_b64": _b64.b64encode(b"\x30\x22\x04\x20" + _hl.sha256(cose).digest()).decode()}
    ep = lc.reconstruct({"sm_artifact_b64": _b64.b64encode(mock._dcbor([cose, legacy])).decode(),
                         "projection": art["projection"]})
    assert lc.sealed_at(ep) is None
    got = _composition_findings(ep)
    assert [r for r, _ in got] == ["LINT-BND-I6"], got


def test_both_demo_token_shapes_keep_their_imprint_check():
    """R10-X5 reads the legacy shape too, so an artefact sealed before this
    change keeps LINT-PKG-08 rather than silently becoming "not a demo token"."""
    imprint = _hl.sha256(b"seal").digest()
    assert lc.parse_demo_qts(b"\x30\x22\x04\x20" + imprint) == (imprint, None)
    import mock_rdp as mock
    timed = _b64.b64decode(mock._qts_over_cose(b"seal", "2026-04-04T12:15:00+02:00")["token_b64"])
    assert lc.parse_demo_qts(timed) == (imprint, "2026-04-04T10:15:00Z")
    assert lc.parse_demo_qts(b"\x30\x03\x02\x01\x00") is None   # not a demo token
