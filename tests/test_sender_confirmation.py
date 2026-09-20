# SPDX-License-Identifier: MIT
"""X-03 / D4 — the sender confirmation object.

Former defect: SE was sealed by RDP(out) only — no retained wallet-produced
signature over the submission tuple existed anywhere. A verifier proved that
the *provider attested* a submission, not that the named sender authorised
those bytes: the sending RDP (or anyone with its seal key) could technically
fabricate the whole act.

Evidence 2.3 (D4): every SE states `origin_proof`. `sender-signed` — the
default posture, REQUIRED for opposable submissions — embeds a
`sender_confirmation`: the sending member's wallet signature over the FULL
submission tuple, including Batch 5's byte-exact commitments
(envelope_hash/mls_state), so the sender independently signs the exact
transmitted octets. The key resolves from the SENDER entity's BW-MEMBER
confirmation_key anchor per (mid, device_id) — INTF-1b, the finding-D
machinery on the sender side. `provider-attested` stays as the
EXPLICITLY-narrowed fallback (proves provider attestation, not sender
authorisation).

TODO(legal): the clause stating the sender signature's relation to the
Article 44(1)(b) provider attestation (an additive second proof, never a
substitute) and the Article 43(2) weight of the two modes awaits counsel —
D4 LEGAL-CONFIRM; the finding stays Partially resolved and nothing here
asserts legal effect.

Negative fixtures reproduce the former defect: a sender-signed SE without a
confirmation is schema-rejected; a confirmation whose tuple diverges from the
SE is rejected (LINT-DE-19); a confirmation minted under a foreign key fails
the sender-side anchor check (LINT-BND-28).
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

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
SEA = json.load(open(ROOT / "samples" / "sample-SE-agent.json"))["projection"]

TUPLE = ("message_id", "sender_uid", "recipient_uid", "payload_hash",
         "envelope_hash", "mls_state", "acceptance_policy_ref", "scope_ref",
         "sent_at", "expires_at")


def _de19(body):
    v = el.Violations()
    el.lint_se(v, body)
    return [msg for r, msg in v.items if r == "LINT-DE-19"]


# ---------------------------------------------------------------------------
# Schema: the origin posture is explicit
# ---------------------------------------------------------------------------

def test_shipped_ses_are_sender_signed_and_schema_valid():
    for se in (SE, SEA):
        assert se["origin_proof"] == "sender-signed"
        assert not lc.validate_body(copy.deepcopy(se))


def test_origin_proof_is_required():
    """The former defect verbatim: an SE silent about WHO proves the origin."""
    bad = copy.deepcopy(SE); bad.pop("origin_proof")
    assert lc.validate_body(bad), "an SE without origin_proof must fail"


def test_sender_signed_requires_the_confirmation():
    bad = copy.deepcopy(SE); bad.pop("sender_confirmation")
    assert lc.validate_body(bad), \
        "origin_proof sender-signed without sender_confirmation must fail"


def test_provider_attested_is_accepted_but_carries_the_narrowed_marker():
    ok = copy.deepcopy(SE)
    ok["origin_proof"] = "provider-attested"
    ok.pop("sender_confirmation")
    assert not lc.validate_body(ok), "the narrowed fallback must stay valid"
    bad = copy.deepcopy(SE)
    bad["origin_proof"] = "provider-attested"   # keeps the confirmation
    assert lc.validate_body(bad), \
        "provider-attested with a sender_confirmation is incoherent"


def test_the_confirmation_signs_the_full_d4_tuple():
    sc = SE["sender_confirmation"]
    for field in TUPLE:
        assert field in sc, f"sender_confirmation missing tuple field {field}"
        bad = copy.deepcopy(SE)
        bad["sender_confirmation"].pop(field)
        assert lc.validate_body(bad), f"confirmation without {field} must fail"


# ---------------------------------------------------------------------------
# LINT-DE-19: the sender signed THESE bytes, not a paraphrase
# ---------------------------------------------------------------------------

def test_shipped_ses_are_de19_clean():
    assert not _de19(copy.deepcopy(SE))
    assert not _de19(copy.deepcopy(SEA))


def test_negative_every_diverging_tuple_field_is_rejected():
    """A confirmation over a DIFFERENT submission never binds to this SE."""
    other = {"message_id": "01HZ3OTHERMESSAGE00000000",
             "sender_uid": "EU-FR-PSBID-ZYWVTSRQPNM8M4",
             "recipient_uid": "EU-DE-EOID-7K3D9W0Q2M5FW0",
             "payload_hash": {"alg": "SHA-256", "hex": "f" * 64,
                              "hash_mode": "raw-sha256"},
             "envelope_hash": {"format": "mls10-message", "hex": "e" * 64},
             "mls_state": {"format": "mls10-group-context", "hex": "d" * 64},
             "acceptance_policy_ref": {"policy_version": "1970-01-01.0",
                                       "doc_digest": {"alg": "SHA-256",
                                                      "hex": "0" * 64,
                                                      "hash_mode": "raw-sha256"}},
             "scope_ref": {"scope_id": "records", "version": "9"},
             "sent_at": "2020-01-01T00:00:00Z",
             "expires_at": "2020-02-01T00:00:00Z"}
    for field in TUPLE:
        bad = copy.deepcopy(SE)
        bad["sender_confirmation"][field] = other[field]
        assert _de19(bad), f"diverging sender_confirmation.{field} must fail LINT-DE-19"


# ---------------------------------------------------------------------------
# LINT-BND-28: the sender-side anchor (the LINT-BND-21 mirror)
# ---------------------------------------------------------------------------

def _sender_bundle(se_body):
    """The SENDER entity's bundle: the German entity's roster + this SE."""
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    members = [_rc("sample-BW-MEMBER.json"), _rc("sample-BW-MEMBER-agent.json")]
    return ["EU-DE-EOID-7K3D9W0Q2M5FW0", {}, {}, members, [se_body]]


def _bnd28(se_body):
    issues = bl.check_bundle(*_sender_bundle(se_body))
    return [msg for r, msg in issues if r == "LINT-BND-28"]


def test_positive_the_shipped_sender_confirmations_resolve_and_verify():
    assert not _bnd28(copy.deepcopy(SE))
    assert not _bnd28(copy.deepcopy(SEA))   # the agent member signs its own


def test_negative_confirmation_minted_under_a_foreign_key_fails_bnd28():
    """The finding verbatim: an RDP minting 'the sender authorised these
    bytes' under its own key does not verify against the member's anchor."""
    bad = copy.deepcopy(SE)
    sc = {k: v for k, v in bad["sender_confirmation"].items()
          if k != "wallet_signature_b64"}
    import os
    os.environ["WALLET_SEED"] = "attacker-rdp-key"
    try:
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    finally:
        del os.environ["WALLET_SEED"]
    bad["sender_confirmation"] = sc
    assert _bnd28(bad), "a foreign-key sender confirmation must fail LINT-BND-28"


def test_negative_unknown_sender_member_fails_bnd28():
    bad = copy.deepcopy(SE)
    bad["sender_confirmation"]["mid"] = "ZZZZZZZZ0"
    assert _bnd28(bad), "an unknown sender mid must fail LINT-BND-28"


def test_negative_unknown_sender_device_fails_bnd28():
    bad = copy.deepcopy(SE)
    bad["sender_confirmation"]["device_id"] = "dev-ghost"
    assert _bnd28(bad), "no (mid, device_id) anchor -> LINT-BND-28"


def test_bnd28_is_scoped_to_the_sender_side_bundle():
    """In the RECIPIENT's bundle the SE's sender is the other entity — the
    sender-side check does not (and cannot) run there."""
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    issues = bl.check_bundle(m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
                             [_rc(x) for x in m["members"]],
                             [_rc(x) for x in m["evidence"]])
    assert not [r for r, _ in issues if r == "LINT-BND-28"], issues
