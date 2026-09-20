# SPDX-License-Identifier: MIT
"""Negative fixtures for the semantic conformance validator (spec §9.4, V4).

Each case takes a good sample, applies a single mutation, and asserts that
`evidence_lint` reports the expected LINT-* rule. These are the executable
statement of the protocol invariants: an implementation that only checks
JSON-Schema validity would accept several of these (they are schema-valid but
protocol-non-conformant).

The reviewer's mutation set, one rule each:
  LINT-DE-01/02/03  s3_attestation must bind the DE's message/hash/policy
  LINT-EP-01        EP outcomes must share the enclosed SE's message_id
  LINT-DE-05        quorum/all acceptance ⇒ C.3-ConsignmentAcceptance
  LINT-MAN-01/02    manifest part_id uniqueness / canonical order
  LINT-PKG-01/03    seal / timestamp-token packaging structure
"""
import base64
import copy
import importlib.util
import json
import pathlib

import pytest

try:
    import cbor2 as _cbor2
    _HAVE_CBOR = True
except Exception:
    _HAVE_CBOR = False

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lint_mod = _load("evidence_lint", "evidence_lint.py")
reconstruct = lint_mod.reconstruct  # M4: decode artefacts


def _sample(name):
    return reconstruct(json.loads((ROOT / "samples" / name).read_text(encoding="utf-8")))


# (id, sample, expected_rule, mutation) — each mutated doc MUST trip expected_rule.
LINT_NEGATIVE_CASES = [
    ("de-s3-message-id-mismatch", "sample-DE.json", "LINT-DE-01",
     lambda d: d["s3_attestation"].update(message_id="01HZ0000000000000000000000")),
    ("de-s3-payload-hash-mismatch", "sample-DE.json", "LINT-DE-02",
     lambda d: d["s3_attestation"]["payload_hash"].update(hex="a" * 64)),
    ("de-s3-policy-ref-mismatch", "sample-DE.json", "LINT-DE-03",
     lambda d: d["s3_attestation"]["acceptance_policy_ref"].update(policy_version="9999-99-99.9")),
    ("ep-outcome-message-id-divergent", "sample-EP.json", "LINT-EP-01",
     lambda d: d["outcomes"][0].update(message_id="01HZ9999999999999999999999")),
    ("de-quorum-event-e1", "sample-DE.json", "LINT-DE-05",
     lambda d: d.update(event="E.1-ContentHandover")),  # kind=quorum ⇒ must be C.3
    # V0 (thirteenth review, §8.3b): delivery-grade coherence.
    ("de-missing-grade", "sample-DE.json", "LINT-DE-08",
     lambda d: d.pop("delivery_grade")),
    ("de-avail-wrong-event", "sample-DE-availability.json", "LINT-DE-08",
     lambda d: d.update(event="E.1-ContentHandover")),
    ("de-avail-with-s3", "sample-DE-availability.json", "LINT-DE-09",
     lambda d: d.update(s3_attestation={"message_id": d["message_id"]})),
    ("de-avail-wrong-basis", "sample-DE-availability.json", "LINT-DE-09",
     lambda d: d.update(integrity_basis="recipient-verified-digest")),
    ("de-acceptance-missing-s3", "sample-DE.json", "LINT-DE-10",
     lambda d: d.pop("s3_attestation")),
    ("de-verification-kind-mismatch", "sample-DE.json", "LINT-DE-10",
     lambda d: d.update(delivery_grade="verification", event="E.1-ContentHandover")),
    # X0 (fourteenth review): the grade commitment.
    ("de-avail-commitment-missing", "sample-DE-availability.json", "LINT-DE-11",
     lambda d: d.pop("grade_commitment")),
    ("de-avail-commitment-malformed", "sample-DE-availability.json", "LINT-DE-11",
     lambda d: d.update(grade_commitment="XYZ")),
    ("de-nonavail-commitment-present", "sample-DE.json", "LINT-DE-11",
     lambda d: d.update(grade_commitment="ab" * 32)),
    # S1 (fifteenth review, TS clause 6 INTF-1): a session-authenticated
    # confirmation requires the DE to record a member/device-level auth_context.
    ("de-session-auth-entity-context", "sample-DE.json", "LINT-DE-12",
     lambda d: d["auth_context"].update(identity="entity")),
    # A2 (Annex R): an agent-sent SE must carry the mandate it acted under;
    # a non-agent SE must not.
    ("se-agent-without-mandate", "sample-SE-agent.json", "LINT-DE-14",
     lambda d: d.pop("mandate_ref")),
    ("se-person-with-mandate", "sample-SE.json", "LINT-DE-14",
     lambda d: d.update(mandate_ref={"issuer": "x", "id": "y"})),
    # A1 (nineteenth review): an opposable agent SE must carry a mandate_commitment;
    # a non-opposable one must not.
    ("se-opposable-agent-without-commitment", "sample-SE-agent.json", "LINT-DE-15",
     lambda d: d["mandate_ref"].pop("mandate_commitment")),
    ("se-non-opposable-agent-with-commitment", "sample-SE-agent.json", "LINT-DE-15",
     lambda d: d["mandate_ref"].update(opposable=False)),
    ("de-all-wrong-event", "sample-DE.json", "LINT-DE-05",
     lambda d: (d.update(acceptance_policy_kind="all", event="D.6-ContentAccessTracking"))),
    ("manifest-duplicate-part-id", "sample-SE-multipart.json", "LINT-MAN-01",
     lambda d: d["manifest"][1].update(part_id=d["manifest"][0]["part_id"])),
    ("manifest-reversed-order", "sample-SE-multipart.json", "LINT-MAN-02",
     lambda d: d.update(manifest=list(reversed(d["manifest"])))),
    ("cose-not-base64-cbor", "sample-SE.json", "LINT-PKG-01",
     lambda d: d["seal"].update(cose_b64="abc")),
    ("token-not-base64", "sample-SE.json", "LINT-PKG-03",
     lambda d: d["seal"]["qualified_timestamp"].update(token_b64="@@@not-base64@@@")),
    # W1 — NDE recipient_confirmation binding
    ("nde-rc-message-id-mismatch", "sample-NDE-mismatch.json", "LINT-NDE-03",
     lambda d: d["recipient_confirmation"].update(message_id="01HZ0000000000000000000000")),
    ("nde-rc-hash-equals-nde", "sample-NDE-mismatch.json", "LINT-NDE-06",
     lambda d: d["recipient_confirmation"].__setitem__(
         "payload_hash", copy.deepcopy(d["payload_hash"]))),  # equality contradicts the mismatch
    # W8 — states[] are non-operative state records (no delivery-establishing field)
    ("ep-state-record-extra-field", "sample-EP.json", "LINT-EP-04",
     lambda d: d["states"][0].update(delivered_at="2026-04-04T10:16:10Z")),
    # X1 — post-seal field mutation must break the COSE payload binding
    ("se-post-seal-mutation", "sample-SE.json", "LINT-PKG-06",
     lambda d: d.update(recipient_uid="EU-DE-EOID-7K3D9W0Q2M5FW0")),
    ("de-post-seal-mutation", "sample-DE.json", "LINT-PKG-06",
     lambda d: d.update(delivered_at="2099-01-01T00:00:00Z")),
    ("ep-post-seal-mutation", "sample-EP.json", "LINT-PKG-06",
     lambda d: d.update(message_id="01HZ9999999999999999999999")),
    # M1/J0+ (twenty-fifth review): I-JSON integers must be in the safe range.
    # 2^53+1 is the exact C1 defect — a uint64-domain value JCS cannot round-trip.
    # (It also breaks the seal binding, LINT-PKG-06 — realistic; membership check.)
    ("se-integer-out-of-safe-range", "sample-SE.json", "LINT-PKG-09",
     lambda d: d.update(mls_epoch=9007199254740993)),
    # X3 — demo/mock timestamp imprint must equal SHA-256(seal)
    ("token-imprint-wrong", "sample-SE.json", "LINT-PKG-08",
     lambda d: d["seal"]["qualified_timestamp"].__setitem__(
         "token_b64", base64.b64encode(b"\x30\x22\x04\x20" + b"\x00" * 32).decode())),
    # X5 — auth_context.method must match the declared authentication method
    ("se-auth-method-mismatch", "sample-SE.json", "LINT-AUTH-01",
     lambda d: d["auth_context"].update(method="two-factor")),
    ("de-recipient-auth-mismatch", "sample-DE.json", "LINT-AUTH-02",
     lambda d: d["auth_context"].update(method="mfa")),
    # N3 — NDE reason binds to its EN 319 522-1 event (LINT-NDE-07); one per branch.
    ("nde-expired-wrong-event", "sample-NDE.json", "LINT-NDE-07",
     lambda d: d.update(reason="expired")),  # expired ⇒ C.5, sample has D.2
    ("nde-a2-reason-wrong-event", "sample-NDE.json", "LINT-NDE-07",
     lambda d: d.update(reason="unknown-uid")),  # unknown-uid ⇒ A.2, sample has D.2
    ("nde-routing-failed-bad-event", "sample-NDE.json", "LINT-NDE-07",
     lambda d: d.update(reason="routing-failed", event="A.2-SubmissionRejection")),  # ⇒ {B.3,D.2}
    # S4 (fifteenth review): duplicate-message-id ⇒ A.2 (sample has D.2).
    ("nde-duplicate-msgid-wrong-event", "sample-NDE.json", "LINT-NDE-07",
     lambda d: d.update(reason="duplicate-message-id")),
    # R7 (twenty-fourth review): keypackage-pool-exhausted is an A.2 submission
    # rejection; the sample NDE's event (D.2) is wrong for it.
    ("nde-keypackage-pool-exhausted-wrong-event", "sample-NDE.json", "LINT-NDE-07",
     lambda d: d.update(reason="keypackage-pool-exhausted")),
]


def _ep_with_nde_outcome():
    """Build an EP whose single outcome is a consistent NDE payload-hash-mismatch,
    so the EP-context rules LINT-NDE-04/05 can be exercised."""
    ep = copy.deepcopy(_sample("sample-EP.json"))
    nde = copy.deepcopy(_sample("sample-NDE-mismatch.json"))
    nde["message_id"] = ep["message_id"]
    rc = nde["recipient_confirmation"]
    rc["message_id"] = ep["message_id"]
    rc["mls_group_id"] = ep["se"]["mls_group_id"]
    rc["mls_epoch"] = ep["se"]["mls_epoch"]
    rc["acceptance_policy_ref"] = copy.deepcopy(ep["se"]["acceptance_policy_ref"])
    ep["outcomes"] = [nde]
    return ep, rc


def test_lint_nde04_ep_session_mismatch():
    ep, rc = _ep_with_nde_outcome()
    assert "LINT-NDE-04" not in [r for r, _ in lint_mod.lint(ep)]  # baseline consistent
    rc["mls_epoch"] = "999"  # mls_epoch is a decimal string (M1/J0+); differs from the SE's
    assert "LINT-NDE-04" in [r for r, _ in lint_mod.lint(ep)]


def test_lint_nde05_ep_policy_mismatch():
    ep, rc = _ep_with_nde_outcome()
    assert "LINT-NDE-05" not in [r for r, _ in lint_mod.lint(ep)]  # baseline consistent
    rc["acceptance_policy_ref"]["policy_version"] = "9999-99-99.9"
    assert "LINT-NDE-05" in [r for r, _ in lint_mod.lint(ep)]


def _cose_with_alg(alg):
    """A structurally-valid COSE_Sign1 (4-element array) whose protected header
    declares a given signature alg."""
    protected = _cbor2.dumps({1: alg})
    return base64.b64encode(_cbor2.dumps([protected, {}, b"payload", b"s" * 64])).decode()


@pytest.mark.skipif(not _HAVE_CBOR, reason="cbor2 required for the COSE alg allowlist (W2)")
def test_lint_pkg05_seal_wrong_alg():
    doc = _mutate("sample-SE.json",
                  lambda d: d["seal"].update(cose_b64=_cose_with_alg(-257)))  # RS256, disallowed
    assert "LINT-PKG-05" in [r for r, _ in lint_mod.lint(doc)]


@pytest.mark.skipif(not _HAVE_CBOR, reason="cbor2 required for the COSE alg allowlist (W2)")
def test_lint_pkg05_walletsig_wrong_alg():
    doc = _mutate("sample-DE-walletsig.json",
                  lambda d: d["s3_attestation"].update(wallet_signature_b64=_cose_with_alg(-257)))
    assert "LINT-PKG-05" in [r for r, _ in lint_mod.lint(doc)]


def _mutate(sample_name, fn):
    doc = copy.deepcopy(_sample(sample_name))
    fn(doc)
    return doc


@pytest.mark.parametrize("case", LINT_NEGATIVE_CASES, ids=[c[0] for c in LINT_NEGATIVE_CASES])
def test_lint_rejects(case):
    _id, sample, rule, fn = case
    issues = lint_mod.lint(_mutate(sample, fn))
    rules = [r for r, _ in issues]
    assert rule in rules, f"{_id}: expected {rule} in violations, got {rules}"


def test_reversed_manifest_keeps_ids_unique():
    """Guard: manifest-reversed-order isolates ordering (MAN-02), not
    duplication (MAN-01) — the reversed list still has unique part_ids."""
    doc = _mutate("sample-SE-multipart.json",
                  lambda d: d.update(manifest=list(reversed(d["manifest"]))))
    rules = [r for r, _ in lint_mod.lint(doc)]
    assert "LINT-MAN-02" in rules and "LINT-MAN-01" not in rules


def test_de11_se_de_commitment_pairing():
    """X0: within an EP, the SE must echo the availability DE's commitment —
    presence parity and equality (LINT-DE-11)."""
    de = _sample("sample-DE-availability.json")
    se = _sample("sample-SE.json")  # carries no grade_commitment
    v = lint_mod.Violations()
    lint_mod.lint_de(v, de, se)
    assert "LINT-DE-11" in [r for r, _ in v.items]
    se["grade_commitment"] = de["grade_commitment"]
    v2 = lint_mod.Violations()
    lint_mod.lint_de(v2, de, se)
    assert "LINT-DE-11" not in [r for r, _ in v2.items]


def test_de13_confirmation_policy_ref_matches_se():
    """S3 (TS clause 6 INTF-3): the confirmation's acceptance_policy_ref must
    equal the SE's; a differing ref is LINT-DE-13."""
    de = _sample("sample-DE.json")
    se = _sample("sample-SE.json")
    v = lint_mod.Violations()
    lint_mod.lint_de(v, de, se)
    assert "LINT-DE-13" not in [r for r, _ in v.items]  # baseline: refs agree
    se["acceptance_policy_ref"]["policy_version"] = "9999-99-99.9"
    v2 = lint_mod.Violations()
    lint_mod.lint_de(v2, de, se)
    assert "LINT-DE-13" in [r for r, _ in v2.items]
