# SPDX-License-Identifier: MIT
"""X-05 — portable quorum and session proofs.

Former defect: `quorum[]` items were bare `{mid, ack_at}` — unsigned RDP
assertions — while only ONE `s3_attestation` was retained for a quorum/all
acceptance; and the session arm retained only `session_authenticated: true`,
a boolean with no verifiable binding that nonetheless rode under a
member-grade auth_context claim.

Evidence 2.3: every quorum entry states HOW its member's act is attested —
`wallet-signed` (an independently portable per-member proof, device-named,
verified against the member's published confirmation_key anchor: the same
finding-D machinery as the s3 signed arm) or `provider` (an RDP assertion
that EXPLICITLY narrows the claim, stated in the entry itself). The session
arm gains a retained `session_binding` digest; a bare boolean stays valid
only as the provider-attested (narrowed) mode and can no longer claim
member-grade proof (LINT-DE-20).

TODO(legal): the Article 43(2) evidential weight of the provider-attested
(narrowed) modes relative to the wallet-signed mode awaits counsel review —
marked in the schema/TS and left OPEN; nothing here asserts legal effect.

Negative fixtures reproduce the former defect: the pre-2.3 bare {mid, ack_at}
shape is schema-rejected; a signed entry whose signature fails (foreign key)
is rejected; a member-grade session claim with no binding is flagged; a
replayed signed entry covering a different message is rejected.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]
DEW = json.load(open(ROOT / "samples" / "sample-DE-walletsig.json"))["projection"]
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def _de20(body, se=None):
    v = el.Violations()
    el.lint_de(v, body, se=copy.deepcopy(se) if se else None)
    return [msg for r, msg in v.items if r == "LINT-DE-20"]


# ---------------------------------------------------------------------------
# Schema: attested entries; the old bare shape is gone
# ---------------------------------------------------------------------------

def test_shipped_quorum_des_are_schema_valid():
    assert not lc.validate_body(copy.deepcopy(DE))
    assert not lc.validate_body(copy.deepcopy(DEW))


def test_the_pre23_bare_quorum_shape_is_schema_rejected():
    """The former defect verbatim: an unsigned, unattested {mid, ack_at}."""
    bad = copy.deepcopy(DE)
    bad["quorum"] = [{"mid": "F1N2C3D4P", "ack_at": "2026-04-04T10:16:20Z"}]
    assert lc.validate_body(bad), "a quorum entry without attestation must fail"


def test_wallet_signed_entry_requires_the_portable_proof_fields():
    for field in ("message_id", "device_id", "verified_at", "wallet_signature_b64"):
        bad = copy.deepcopy(DE)
        entry = next(q for q in bad["quorum"] if q["attestation"] == "wallet-signed")
        entry.pop(field)
        assert lc.validate_body(bad), f"wallet-signed entry without {field} must fail"


def test_provider_entry_must_not_carry_a_signature():
    bad = copy.deepcopy(DE)
    entry = next(q for q in bad["quorum"] if q["attestation"] == "provider")
    entry["wallet_signature_b64"] = "A" * 96
    assert lc.validate_body(bad), "a provider entry carrying a signature must fail"


def test_the_shipped_mixed_quorum_states_both_modes():
    """The narrowing is in the entry itself — the finding's acceptance."""
    modes = sorted(q["attestation"] for q in DE["quorum"])
    assert modes == ["provider", "wallet-signed"]
    assert all(q["attestation"] == "wallet-signed" for q in DEW["quorum"])


# ---------------------------------------------------------------------------
# LINT-DE-20: the bare boolean cannot claim member grade; no replays
# ---------------------------------------------------------------------------

def test_shipped_des_are_de20_clean():
    assert not _de20(copy.deepcopy(DE))
    assert not _de20(copy.deepcopy(DEW))


def test_negative_member_grade_session_claim_without_binding_is_flagged():
    """The former defect: wallet-eid-high/very-high over a bare boolean."""
    bad = copy.deepcopy(DE)
    bad["s3_attestation"].pop("session_binding")
    assert _de20(bad), "member-grade claim with no session_binding must flag LINT-DE-20"


def test_narrowed_session_claim_without_binding_stays_valid():
    """A bare boolean REMAINS valid as the provider-attested narrowed mode."""
    ok = copy.deepcopy(DE)
    ok["s3_attestation"].pop("session_binding")
    ok["auth_context"] = {"identity": "member", "method": "password-otp",
                          "loa": "substantial"}
    ok["recipient_auth_method"] = "password-otp"
    assert not _de20(ok), "a narrowed claim with no binding must stay LINT-DE-20-clean"


def test_negative_replayed_signed_entry_for_another_message_is_rejected():
    bad = copy.deepcopy(DE)
    entry = next(q for q in bad["quorum"] if q["attestation"] == "wallet-signed")
    entry["message_id"] = "01HZ3OTHERMESSAGE00000000"
    assert _de20(bad), "a signed entry covering another message must flag LINT-DE-20"


# ---------------------------------------------------------------------------
# Bundle: the portable proof verifies against the published anchor
# ---------------------------------------------------------------------------

def _bundle_with_de(de_body):
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    evidence = [_rc(x) for x in m["evidence"]
                if "DE" not in x or "availability" in x] + [de_body]
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], evidence]


def _bnd(de_body, rule):
    issues = bl.check_bundle(*_bundle_with_de(de_body))
    return [msg for r, msg in issues if r == rule]


def test_positive_the_shipped_quorum_resolves_and_verifies():
    assert not _bnd(copy.deepcopy(DE), "LINT-BND-21")
    assert not _bnd(copy.deepcopy(DE), "LINT-BND-12")


def test_negative_quorum_proof_minted_under_a_foreign_key_fails_bnd21():
    """Finding-D mirror at quorum level: an RDP-minted acknowledgement."""
    bad = copy.deepcopy(DE)
    entry = next(q for q in bad["quorum"] if q["attestation"] == "wallet-signed")
    resign = {k: v for k, v in entry.items() if k != "wallet_signature_b64"}
    import os
    os.environ["WALLET_SEED"] = "attacker-provider-key"
    try:
        entry["wallet_signature_b64"] = mock._wallet_sign(resign)
    finally:
        del os.environ["WALLET_SEED"]
    assert _bnd(bad, "LINT-BND-21"), "a foreign-key quorum proof must fail LINT-BND-21"


def test_negative_signed_entry_naming_an_unknown_device_fails():
    bad = copy.deepcopy(DE)
    entry = next(q for q in bad["quorum"] if q["attestation"] == "wallet-signed")
    entry["device_id"] = "dev-ghost"
    issues = bl.check_bundle(*_bundle_with_de(bad))
    assert any(r in ("LINT-BND-12", "LINT-BND-21") for r, _ in issues), issues


def test_negative_provider_entry_by_unknown_member_fails_bnd12():
    bad = copy.deepcopy(DE)
    entry = next(q for q in bad["quorum"] if q["attestation"] == "provider")
    entry["mid"] = "ZZZZZZZZ0"
    assert _bnd(bad, "LINT-BND-12"), "an unknown provider-entry mid must fail LINT-BND-12"


# ---------------------------------------------------------------------------
# Session binding shape
# ---------------------------------------------------------------------------

def test_session_binding_shape_is_schema_bound():
    bad = copy.deepcopy(DE)
    bad["s3_attestation"]["session_binding"] = {"kind": "post-it-note",
                                                "digest": "ab" * 32}
    assert lc.validate_body(bad), "an unknown session_binding kind must fail"
    bad = copy.deepcopy(DE)
    bad["s3_attestation"]["session_binding"] = {"kind": "token-digest",
                                                "digest": "not-hex"}
    assert lc.validate_body(bad), "a non-hex session_binding digest must fail"
