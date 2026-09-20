# SPDX-License-Identifier: MIT
"""Round 10 / B5 — R10-07: the wallet can report a digest mismatch.

`evidence-nde.schema.json` REQUIRES a recipient-produced proof on an NDE with
reason `payload-hash-mismatch`, and the published wallet-RDP request accepted
only `s3`, `refusal` and `reveal`. A conforming client could not report the
mandatory negative outcome at all; a provider cannot infer it from silence.

The review's acceptance: drive BOTH the matching and the mismatching
decryption through the published request Schema and recipient-side
processing; a mismatch reaches a valid NDE carrying the ACTUAL recipient
proof; a timeout cannot masquerade as it.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_current_claims as tc  # noqa: E402
from lint_cli import validate_body, validate_contract_object  # noqa: E402

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
PROOF = json.loads((ROOT / "samples" / "sample-NDE-mismatch.json").read_text())[
    "projection"]["recipient_confirmation"]
S3 = json.loads((ROOT / "samples" / "sample-DE.json").read_text())["projection"]["s3_attestation"]
RDP_IN = "urn:sbm:rdp:mockeu-002"
AT = "2026-04-04T10:47:00Z"
FR = SE["recipient_uid"]
MEMBER = {"kind": "member", "uid": FR, "mid": PROOF["mid"]}
# R11-03: issuance runs INTF-2 against the recipient's published members and
# evaluates the policy the SE pins, so it is given both.
MEMBERS = [json.loads((ROOT / "samples" / f"sample-BW-MEMBER-{x}.json").read_text())
           ["projection"] for x in ("fr", "fr2")]
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]


def _ev():
    spec = importlib.util.spec_from_file_location("ev_b5", ROOT / "scripts" / "evidence_lint.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _req(kind, conf):
    return {"issuing_rdp_id": SE["rdp_id"], "message_id": SE["message_id"],
            "confirmation_kind": kind, "confirmation": conf}


def _deliver(m, request, credential=MEMBER, at=AT):
    return m.deliver_confirmation(request, credential=credential, se=SE,
                                  rdp_id=RDP_IN, observed_at=at,
                                  members=MEMBERS, org=ORG)


# ---------------------------------------------------------------------------
# The request exists
# ---------------------------------------------------------------------------

def test_the_mismatch_proof_is_now_a_valid_request():
    """The review's probe: every published kind refused it, and an invented
    `mismatch` failed the enum."""
    assert validate_contract_object("wallet-rdp-openapi.yaml", "ConfirmationDelivery",
                                    _req("mismatch", PROOF)) == []


def test_the_kinds_stay_discriminated():
    """A matching attestation under `mismatch`, or the mismatch proof under
    `s3`, is refused: the discriminator decides the object, not its shape."""
    for kind, conf in (("mismatch", S3), ("s3", PROOF)):
        assert validate_contract_object("wallet-rdp-openapi.yaml",
                                        "ConfirmationDelivery", _req(kind, conf)), kind


# ---------------------------------------------------------------------------
# Both branches through the handler
# ---------------------------------------------------------------------------

def test_the_matching_branch_is_accepted_and_issues_no_nde():
    m = tc._load("mock_rdp", "mock_rdp.py")
    assert _deliver(m, _req("s3", S3), credential={"kind": "member", "uid": FR,
                                                   "mid": S3["mid"]}) is None


def test_the_mismatching_branch_issues_an_nde_carrying_the_actual_proof():
    m = tc._load("mock_rdp", "mock_rdp.py")
    art = _deliver(m, _req("mismatch", PROOF))
    nde = art["projection"]
    assert nde["reason"] == "payload-hash-mismatch"
    assert nde["recipient_confirmation"] == PROOF, "not the proof that was delivered"
    ev = _ev()
    assert [r for r, _ in ev.lint(art)] == [], "the sealed NDE does not lint clean"
    v = ev.Violations(); ev.lint_nde(v, ev.reconstruct(art), se=SE)
    assert v.items == [], "the NDE does not bind to its SE"


# ---------------------------------------------------------------------------
# Binding, idempotency, and the rules held BEFORE sealing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("credential,why", [
    ({"kind": "member", "uid": FR, "mid": "Z9Y8X7W6V"}, "another member"),
    ({"kind": "entity", "uid": SE["recipient_uid"]}, "an entity-level session"),
])
def test_the_confirmation_must_come_from_the_confirming_member(credential, why):
    m = tc._load("mock_rdp", "mock_rdp.py")
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, _req("mismatch", PROOF), credential=credential)
    assert exc.value.reason == "confirmation-not-member-bound", why


def test_a_named_device_must_be_the_authenticated_one():
    m = tc._load("mock_rdp", "mock_rdp.py")
    proof = dict(PROOF, device_id="DEV-1")
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, _req("mismatch", proof),
                 credential={"kind": "device", "uid": FR, "mid": PROOF["mid"],
                             "device_id": "DEV-2"})
    assert exc.value.reason == "confirmation-not-member-bound"


def test_a_repeat_converges_and_a_different_confirmation_is_refused():
    m = tc._load("mock_rdp", "mock_rdp.py")
    first = _deliver(m, _req("mismatch", PROOF))
    assert _deliver(m, _req("mismatch", PROOF)) == first
    other = dict(PROOF, verified_at="2026-04-04T10:46:31Z")
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, _req("mismatch", other))
    assert exc.value.reason == "confirmation-conflict"


def test_a_proof_inconsistent_with_its_se_is_refused_and_nothing_is_sealed():
    """The complete NDE is held to the retained-evidence rules BEFORE sealing.
    The probe is the defect B5 found in the shipped sample: a proof naming the
    policy key `default` for an SE that selected `procurement` (LINT-NDE-05) —
    never caught, because the sample was only ever linted alone."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    stale = copy.deepcopy(PROOF)
    stale["acceptance_policy_ref"]["policy_key"] = "default"
    # R11-03: INTF-3 now runs for EVERY kind before anything is built, so the
    # stale policy reference is refused as what it is, one step earlier.
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, _req("mismatch", stale))
    assert exc.value.reason == "confirmation-policy-mismatch"
    # ...and the complete NDE is still held to the retained rules before
    # sealing: a proof about another MLS epoch is LINT-NDE-04.
    other_epoch = dict(copy.deepcopy(PROOF), mls_epoch="4")
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, _req("mismatch", other_epoch))
    assert exc.value.reason == "confirmation-rejected" and "LINT-NDE-04" in exc.value.detail
    assert m._CONFIRMATION_ACTS == {} and m._CONFIRMATION_STATE == {}


# ---------------------------------------------------------------------------
# Silence is never a mismatch
# ---------------------------------------------------------------------------

def test_a_timeout_cannot_masquerade_as_a_mismatch():
    """No producer can issue `payload-hash-mismatch` without the recipient's
    proof: the published NDE refuses it. So the only route to one is a
    delivered `mismatch` confirmation — never a device that stayed silent."""
    bare = {k: v for k, v in _deliver(tc._load("mock_rdp", "mock_rdp.py"),
                                      _req("mismatch", PROOF))["projection"].items()
            if k != "recipient_confirmation"}
    assert validate_body(bare), "a mismatch NDE with no recipient proof validated"


def test_the_shipped_mismatch_nde_binds_to_its_se():
    """The gate that would have caught the sample defect: the mismatch NDE is
    linted BESIDE the SE it is about, so the SE-dependent rules (LINT-NDE-04/05)
    actually run on it."""
    ev = _ev()
    nde = ev.reconstruct(json.loads((ROOT / "samples" / "sample-NDE-mismatch.json").read_text()))
    v = ev.Violations(); ev.lint_nde(v, nde, se=SE)
    assert v.items == []
