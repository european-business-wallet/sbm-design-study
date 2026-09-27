# SPDX-License-Identifier: MIT
"""R23-01 — a detected multipart failure that had nowhere to go.

The Mode C re-verification rule added on 27 September was right to require each
received part to be checked before the manifest digest. It then directed every
failure into an ordinary `mismatch` confirmation carrying a recomputed
`payload_hash` — and `LINT-NDE-06` requires that value to DIFFER from the
sender's, because equality would contradict the mismatch claim.

Under Mode C it cannot differ. **`payload_hash` is the digest of the manifest,
not of the plaintext.** A recipient whose received parts are wrong recomputes the
digest of the same manifest the SE carries and gets the same value the sender
declared; and a payload that is not the framing yields no parts to describe at
all. So the recipient could detect the failure and not report it: it would have
to invent a digest, assert a comparison it never made, or fall silent and let the
message expire.

That is the defect `SBM-ADR-0014` names for an unusable salt — "a `mismatch`
confirmation asserts a comparison that **was made**" — reintroduced in the live
path by the pass that corrected the record. An external review of the r23 export
reproduced it with the shipped sample and fixture files.

The outcome is now a distinct, typed, recipient-attributed assertion:
`RecipientValidationFailure`, carried on an NDE with reason
`payload-validation-failed`, bound to the message, to the octets the recipient
decrypted and to the commitment it was checking — and carrying **no** recomputed
`payload_hash`, because there is none.
"""
import base64
import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import evidence_lint as ev  # noqa: E402
import lint_cli as lc  # noqa: E402
import multipart as mp  # noqa: E402
import test_current_claims as tc  # noqa: E402

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
SE_MP = _ld("sample-SE-multipart.json")
FIXTURES = ROOT / "samples" / "fixtures" / "multipart"
REASONS = json.loads((ROOT / "registries" / "reason-codes.json").read_text())


def _m():
    return tc._load("mock_rdp", "mock_rdp.py")


def parts():
    return {p["part_id"]: (FIXTURES / p["filename"]).read_bytes() for p in SE_MP["manifest"]}


# ===========================================================================
# The defect, reproduced before the outcome that answers it
# ===========================================================================

def test_the_honest_recomputation_equals_the_senders_so_a_mismatch_is_unreportable():
    """The review's vector: replace one part, and every part check fires while
    the only value a `mismatch` confirmation may carry is unchanged."""
    import hashlib
    broken = dict(parts(), p1=b"not the declared document")
    problems = mp.verify_against_manifest(mp.assemble(broken), SE_MP["manifest"],
                                          SE_MP["payload_hash"])
    assert problems, "the failure must be detected"

    honest = hashlib.sha256(lc.dcbor(SE_MP["manifest"])).hexdigest()
    assert honest == SE_MP["payload_hash"]["hex"], \
        "if these ever differ, Mode C hashes the plaintext and this finding dissolves"

    # And that equality is exactly what LINT-NDE-06 refuses.
    v = ev.Violations()
    ev.lint_nde_semantics(v, {
        "type": "NDE-v1", "reason": "payload-hash-mismatch",
        "event": "D.2-ContentConsignmentFailure",
        "message_id": SE_MP["message_id"],
        "payload_hash": SE_MP["payload_hash"],
        "recipient_confirmation": {"result": "mismatch",
                                   "message_id": SE_MP["message_id"],
                                   "payload_hash": dict(SE_MP["payload_hash"])}})
    assert any(r == "LINT-NDE-06" for r, _ in v.items), [r for r, _ in v.items]


# ===========================================================================
# The typed report, per cause the review's acceptance criteria name
# ===========================================================================

def _broken(**over):
    p = parts()
    p.update(over)
    return p


CASES = {
    "changed bytes": (lambda: _broken(p1=b"x" * 713), "part-digest-mismatch"),
    "wrong length": (lambda: _broken(p1=b"short"), "part-length-mismatch"),
    "absent part": (lambda: {k: v for k, v in parts().items() if k != "p2"}, "part-absent"),
    "extra part": (lambda: _broken(zz=b"undescribed"), "part-undescribed"),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_cause_is_typed_and_registered(name):
    build, expected = CASES[name]
    report = mp.failure_report(mp.assemble(build()), SE_MP["manifest"], SE_MP["payload_hash"])
    assert report is not None, f"{name}: not detected"
    causes = {p["failure"] for p in report["parts"]}
    assert expected in causes, (name, causes)
    for cause in causes | {report["failure"]}:
        assert cause in REASONS["recipient_validation_failures"], cause


def test_a_malformed_carrier_names_the_whole_payload_and_no_parts():
    """The case that has no parts to describe, and the reason the per-part
    detail is optional for exactly this cause and required for the others."""
    report = mp.failure_report(b"\xff\xff not cbor at all", SE_MP["manifest"],
                               SE_MP["payload_hash"])
    assert report["failure"] == "payload-framing-invalid"
    assert "parts" not in report


def test_a_duplicate_part_id_is_a_framing_failure_not_a_part_failure():
    """The framing forbids it, so the payload never parses into parts — the
    duplicate is a property of the carrier, not of one part."""
    p = parts()
    pid, data = sorted(p)[0], next(iter(p.values()))
    payload = lc.dcbor([{"part_id": pid, "octets": data},
                        {"part_id": pid, "octets": data}])
    report = mp.failure_report(payload, SE_MP["manifest"], SE_MP["payload_hash"])
    assert report["failure"] == "payload-framing-invalid"
    assert "duplicate part_id" in report["detail"]


def test_an_observed_digest_is_carried_only_where_a_comparison_was_made():
    """The rule the whole finding turns on, one level down: a digest on a part
    that was never received would assert a computation over octets nobody
    holds — the same false speech in miniature."""
    for name in sorted(CASES):
        build, _ = CASES[name]
        report = mp.failure_report(mp.assemble(build()), SE_MP["manifest"],
                                   SE_MP["payload_hash"])
        for part in report["parts"]:
            if part["failure"] == "part-digest-mismatch":
                assert part["observed"] and part["declared"]
                assert part["observed"] != part["declared"]
            else:
                assert "observed" not in part, (name, part)


# ===========================================================================
# End to end: detection → confirmation intake → a sealed outcome
# ===========================================================================

def _assertion(m, report, se=SE_MP):
    """What the recipient wallet signs and delivers."""
    conf = {
        "mid": "F1N2C3D4P",
        "device_id": "dev-01",
        "failure": report["failure"],
        "envelope_hash": copy.deepcopy(se["envelope_hash"]),
        "declared_payload_hash": copy.deepcopy(se["payload_hash"]),
        "verified_at": "2026-04-04T10:47:00Z",
        "message_id": se["message_id"],
        "mls_group_id": se["mls_group_id"], "mls_epoch": se["mls_epoch"],
        "mls_state": copy.deepcopy(se["mls_state"]),
        "acceptance_policy_ref": copy.deepcopy(se["acceptance_policy_ref"]),
    }
    if "parts" in report:
        conf["parts"] = copy.deepcopy(report["parts"])
    conf["wallet_signature_b64"] = m._wallet_sign(conf)
    return conf


MEMBERS = [_ld("sample-BW-MEMBER-fr.json"), _ld("sample-BW-MEMBER-fr2.json")]
ORG = _ld("sample-BW-ORG.json")


def _deliver(m, conf, se=SE_MP, members=None, org=None):
    org = org or ORG
    members = members or MEMBERS
    return m.deliver_confirmation(
        {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
         "confirmation_kind": "validation-failure", "confirmation": conf},
        credential={"kind": "device", "uid": se["recipient_uid"],
                    "mid": conf["mid"], "device_id": conf["device_id"]},
        se=se, rdp_id="urn:sbm:rdp:mockeu-002",
        observed_at="2026-04-04T10:47:00Z", members=members, org=org)


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_failure_reaches_a_sealed_outcome(name):
    """The acceptance criterion the review sets: a helper returning an error
    string is not sufficient. From the recipient's detection, through the
    published confirmation intake, to a sealed NDE that the retained-evidence
    linter accepts."""
    m = _m()
    m._CONFIRMATION_STATE.clear()
    build, _ = CASES[name]
    report = mp.failure_report(mp.assemble(build()), SE_MP["manifest"],
                               SE_MP["payload_hash"])
    art = _deliver(m, _assertion(m, report))
    assert art is not None, f"{name}: the intake sealed nothing"

    assert art["sm_artifact_b64"], f"{name}: no seal"
    nde = art["projection"]
    assert nde["reason"] == "payload-validation-failed", nde["reason"]
    assert "recipient_validation_failure" in nde
    assert "recipient_confirmation" not in nde, \
        "the two outcomes are mutually exclusive: one says a comparison was made"
    # No recomputed payload_hash anywhere in the recipient's assertion: there is
    # none to compute, and inventing one is what this outcome exists to prevent.
    assert "payload_hash" not in nde["recipient_validation_failure"]
    # And the RETAINED-evidence linter accepts what the issuing path sealed —
    # the two paths share `lint_nde_semantics`, and a rule that passed at
    # issuance and failed at verification would be the worse defect.
    assert lc.validate_body(nde) == [], lc.validate_body(nde)


def test_the_sealed_outcome_is_terminal_like_a_mismatch():
    """The failure is message-wide, so the message ends here — and an act
    arriving afterwards is retained and changes nothing."""
    m = _m()
    m._CONFIRMATION_STATE.clear()
    report = mp.failure_report(mp.assemble(_broken(p1=b"x" * 713)), SE_MP["manifest"],
                               SE_MP["payload_hash"])
    assert _deliver(m, _assertion(m, report)) is not None
    handle = (SE_MP["rdp_id"], SE_MP["message_id"])
    assert m._CONFIRMATION_STATE[handle]["state"] == "validation-failed"


# ===========================================================================
# The rule, and what it refuses
# ===========================================================================

def _nde(**over):
    base = {"type": "NDE-v1", "reason": "payload-validation-failed",
            "event": "D.2-ContentConsignmentFailure",
            "message_id": SE_MP["message_id"], "payload_hash": SE_MP["payload_hash"],
            "recipient_validation_failure": {
                "failure": "part-digest-mismatch",
                "message_id": SE_MP["message_id"],
                "declared_payload_hash": copy.deepcopy(SE_MP["payload_hash"]),
                "mls_group_id": SE_MP["mls_group_id"], "mls_epoch": SE_MP["mls_epoch"],
                "mls_state": copy.deepcopy(SE_MP["mls_state"]),
                "acceptance_policy_ref": copy.deepcopy(SE_MP["acceptance_policy_ref"]),
                "parts": [{"part_id": "p1", "failure": "part-digest-mismatch",
                           "declared": copy.deepcopy(SE_MP["manifest"][0]["digest"]),
                           "observed": dict(SE_MP["manifest"][0]["digest"], hex="a" * 64)}]}}
    base["recipient_validation_failure"].update(over.pop("vf", {}))
    base.update(over)
    return base


def _rules(nde):
    v = ev.Violations()
    ev.lint_nde_semantics(v, nde, se=SE_MP)
    return {r for r, _ in v.items}


def test_the_control_passes():
    assert "LINT-NDE-08" not in _rules(_nde())


def test_both_outcomes_on_one_nde_are_refused():
    assert "LINT-NDE-08" in _rules(_nde(recipient_confirmation={"result": "mismatch"}))


def test_an_unregistered_cause_is_refused():
    assert "LINT-NDE-08" in _rules(_nde(vf={"failure": "something-else"}))


def test_a_digest_mismatch_that_names_equal_digests_is_refused():
    same = copy.deepcopy(SE_MP["manifest"][0]["digest"])
    assert "LINT-NDE-08" in _rules(_nde(vf={"parts": [
        {"part_id": "p1", "failure": "part-digest-mismatch",
         "declared": same, "observed": copy.deepcopy(same)}]}))


def test_an_observed_digest_on_a_part_that_was_absent_is_refused():
    assert "LINT-NDE-08" in _rules(_nde(vf={"parts": [
        {"part_id": "p1", "failure": "part-absent",
         "observed": copy.deepcopy(SE_MP["manifest"][0]["digest"])}]}))


def test_an_assertion_about_another_message_is_refused():
    assert "LINT-NDE-08" in _rules(_nde(vf={"message_id": "01HZ0000000000000000000X"}))


def test_an_assertion_naming_the_wrong_commitment_is_refused():
    """It must name what it was checking, or a reader cannot tell which
    commitment the failure is about."""
    assert "LINT-NDE-08" in _rules(_nde(vf={
        "declared_payload_hash": dict(SE_MP["payload_hash"], hex="b" * 64)}))


# ===========================================================================
# The vocabulary, and the code that must not be reused
# ===========================================================================

def test_the_intake_reason_is_not_reused_for_a_post_decryption_failure():
    """`malformed-envelope` is bound to an intake stage and a relay stage,
    where nothing has been decrypted and no recipient has spoken."""
    assert "malformed-envelope" not in REASONS["recipient_validation_failures"]
    as_nde = REASONS["nde_reasons"]["malformed-envelope"]
    assert set(as_nde["stages"]) == {"intake", "relay"}, as_nde["stages"]
    new = REASONS["nde_reasons"]["payload-validation-failed"]
    assert set(new["stages"]) == {"consignment"}, new["stages"]
    assert new["allowed_events"] == ["D.2-ContentConsignmentFailure"]


def test_the_normative_text_states_the_distinction():
    id_text = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "A failure of the first step is not a mismatch, and MUST NOT be reported as one" \
        in id_text.replace("**", "")
    assert "the same value the sender declared" in id_text
    assert "`malformed-envelope` **MUST NOT** be reused" in id_text
    assert "A Mode A recipient is unaffected" in id_text
