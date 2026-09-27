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

import cddl_check  # noqa: E402
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
    # EVERY representation, not one. This assertion called `validate_body`
    # alone — the JSON projection — under a comment claiming the retained form
    # was checked. It was not: the authoritative CDDL had no arm for this
    # outcome, so the reference runtime sealed an object an implementation
    # following the CDDL refused, and the test that was meant to catch it said
    # it had looked. A docstring is not a check (R26-PUB-01).
    assert lc.validate_body(nde) == [], lc.validate_body(nde)
    assert cddl_check._check_body(nde, f"validation-failure/{name}"), \
        "sealed by the runtime and refused by the authoritative CDDL"
    assert ev.lint(art, verify_demo=True) == [], ev.lint(art, verify_demo=True)


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
# R26-PUB-02 — the proof is verified, and its member resolved
# ===========================================================================

def _issued(m=None):
    m = m or _m()
    report = mp.failure_report(mp.assemble(_broken(p1=b"x" * 713)), SE_MP["manifest"],
                               SE_MP["payload_hash"])
    return m, _deliver(m, _assertion(m, report))


def _reseal(m, art, mutate):
    """The outer RDP seal re-made over a mutated body — a faulty or malicious
    issuer's artefact, not a corrupted one. Without this the outer seal fails
    first and the recipient proof is never reached."""
    body = copy.deepcopy(art["projection"])
    mutate(body["recipient_validation_failure"])
    return m.evidence_artifact(body)


def _flip_signature(conf):
    import cbor2
    cose = cbor2.loads(base64.b64decode(conf["wallet_signature_b64"]))
    items = list(cose.value if hasattr(cose, "value") else cose)
    sig = bytearray(items[3]); sig[-1] ^= 1; items[3] = bytes(sig)
    conf["wallet_signature_b64"] = base64.b64encode(
        cbor2.dumps(cbor2.CBORTag(18, items) if hasattr(cose, "value") else items)).decode()


def test_a_flipped_signature_is_caught_by_the_retained_verifier():
    """The gap R26-PUB-02 reproduced: the signature helper checked COSE
    structure and binding, and the traversal that actually VERIFIES signatures
    enumerated the older proof names by hand. A flipped byte, re-sealed by a
    valid provider key, produced no violation at all — provider attestation
    standing in for the recipient attribution this object exists to carry."""
    m, art = _issued()
    assert ev.lint(art, verify_demo=True) == []
    bad = _reseal(m, art, _flip_signature)
    problems = ev.lint(bad, verify_demo=True)
    assert any(r == "LINT-VERIFY-01" for r, _ in problems), problems
    assert any("recipient_validation_failure" in msg for _, msg in problems), problems


def test_the_proof_fields_are_derived_and_not_enumerated():
    """Three hand-kept lists were the defect, so the set is derived from the
    schemas: a proof type is one carrying `wallet_signature_b64`, and a proof
    field is a property that `$ref`s one."""
    assert "recipient_validation_failure" in lc.WALLET_PROOF_FIELDS
    assert lc.WALLET_PROOF_FIELDS >= {"s3_attestation", "recipient_confirmation",
                                      "sender_confirmation", "refusal_confirmation"}
    # And the NARROWER set a recipient-side rule may use. Resolving a sender's
    # member against the recipient entity's roster asserts something false,
    # which is what the wider set did to four positive bundles.
    assert lc.RECIPIENT_ACK_PROOF_FIELDS == {"s3_attestation", "recipient_confirmation",
                                             "recipient_validation_failure"}
    assert "sender_confirmation" not in lc.RECIPIENT_ACK_PROOF_FIELDS


def test_a_signed_assertion_names_the_device_whose_key_signed_it():
    """A wallet signature is made by a device key. The CDDL has required this
    of a signed recipient confirmation since it was written; this Schema did
    not, and the two disagreed about the same object."""
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    for name in ("RecipientConfirmation", "RecipientValidationFailure"):
        arms = [set(a["required"]) for a in common["$defs"][name]["anyOf"]]
        signed = next(a for a in arms if "wallet_signature_b64" in a)
        assert "device_id" in signed, name
    cddl = " ".join((ROOT / "cddl" / "sm-mls-erd.cddl").read_text().split())
    for rule in ("rc-signed = { rc-common, device_id: tstr",
                 "rvf-signed = { rvf-common, device_id: tstr"):
        assert rule in cddl, rule


# ===========================================================================
# R26-PUB-03 — the sender's side of the comparison is the sender's
# ===========================================================================

@pytest.mark.parametrize("name,mutate", [
    ("a part the manifest never described",
     lambda r: {**r, "parts": [{**r["parts"][0], "part_id": "not-in-manifest"}]}),
    ("a declared digest the sender never declared",
     lambda r: {**r, "parts": [{**r["parts"][0],
                                "declared": dict(r["parts"][0]["declared"], hex="b" * 64)}]}),
    ("a part claimed undescribed that the manifest describes",
     lambda r: {**r, "parts": [{"part_id": "p1", "failure": "part-undescribed"}]}),
])
def test_a_contradicted_manifest_declaration_never_reaches_a_seal(name, mutate):
    """The recipient's OBSERVATION cannot be checked — the parts are encrypted
    and absent, which is why this is an attributable assertion. The sender's
    declaration can: it is in the SE. Allowing it to be replaced makes the
    evidence internally inconsistent, and all three reached a sealed terminal
    outcome before this."""
    m = _m()
    report = mp.failure_report(mp.assemble(_broken(p1=b"x" * 713)), SE_MP["manifest"],
                               SE_MP["payload_hash"])
    # R27-PUB-03: this read `assert not m._SE_LEDGER or True`, which is true
    # whatever the code does — the state claim the test's own name makes was
    # never asserted. The refusal must leave the aggregate EXACTLY as it was, so
    # the comparison is before against after, not against emptiness: a rejection
    # that recorded a partial outcome would satisfy "nothing new is sealed"
    # while still having moved the state a later confirmation reads.
    before = copy.deepcopy(m._CONFIRMATION_STATE), copy.deepcopy(m._SE_LEDGER)
    with pytest.raises(Exception) as caught:
        _deliver(m, _assertion(m, mutate(copy.deepcopy(report))))
    assert (m._CONFIRMATION_STATE, m._SE_LEDGER) == before, \
        "the refusal moved the confirmation aggregate or the SE ledger"
    assert "validation-failure" in str(caught.value) or "LINT-NDE-08" in str(caught.value), \
        caught.value


def test_the_observation_itself_is_not_claimed_to_be_verified():
    """The control that keeps the rule honest: an observed digest nobody can
    check must still pass, or the profile would be claiming to verify what a
    provider cannot see."""
    m = _m()
    report = mp.failure_report(mp.assemble(_broken(p1=b"x" * 713)), SE_MP["manifest"],
                               SE_MP["payload_hash"])
    report["parts"][0]["observed"] = dict(report["parts"][0]["observed"], hex="c" * 64)
    art = _deliver(m, _assertion(m, report))
    assert art["projection"]["reason"] == "payload-validation-failed"


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


# ===========================================================================
# R27-PUB-03 — the assertion's INTRINSIC consistency, checked without the SE
# ===========================================================================
#
# What one part's detail says about ITSELF needs no manifest: whether a cause
# carries the fields it must, whether a claimed mismatch actually differs,
# whether the two sides of a comparison are comparable at all. Those checks used
# to sit behind two `continue`s — one taken when no SE was supplied, one taken
# for every `part-undescribed` claim — so an assertion verified from retained
# evidence alone was never examined, and an undescribed-part claim was never
# examined even with the SE at hand. A digest mismatch whose two digests were
# equal passed standalone and failed the moment an SE was supplied, which is how
# we know the dependency was control flow and not evidence: the equality of an
# assertion's own two fields is visible without knowing anything the sender said.

def _rvf_report(**over):
    """The real recipient's report for a payload with a wrong part, as the base
    for each contradiction — so every probe below starts from something the
    recipient's own code produces."""
    report = mp.failure_report(mp.assemble(_broken(p1=b"x" * 713)),
                              SE_MP["manifest"], SE_MP["payload_hash"])
    report.update(over)
    return report


def _one_part(cause, **fields):
    return _rvf_report(failure=cause,
                       parts=[dict(part_id="p1", failure=cause, **fields)])


DIGEST = {"alg": "SHA-256", "hash_mode": "raw-sha256", "hex": "a" * 64}

CONTRADICTIONS = {
    "a digest mismatch whose digests are equal":
        lambda: _one_part("part-digest-mismatch", declared=dict(DIGEST),
                          observed=dict(DIGEST)),
    "a digest mismatch missing the observed side":
        lambda: _one_part("part-digest-mismatch", declared=dict(DIGEST)),
    "a digest mismatch across two digest domains":
        lambda: _one_part("part-digest-mismatch", declared=dict(DIGEST),
                          observed={"alg": "SHA-512", "hash_mode": "raw-sha512",
                                    "hex": "b" * 128}),
    "a digest mismatch carrying differing lengths":
        lambda: _one_part("part-digest-mismatch", declared=dict(DIGEST),
                          observed=dict(DIGEST, hex="c" * 64),
                          declared_length="713", observed_length="5"),
    "a length mismatch whose lengths are equal":
        lambda: _one_part("part-length-mismatch", declared_length="713",
                          observed_length="713"),
    "a length mismatch carrying no lengths":
        lambda: _one_part("part-length-mismatch"),
    "an undescribed part carrying an observed digest":
        lambda: _one_part("part-undescribed", observed=dict(DIGEST)),
    "an absent part carrying an observed length":
        lambda: _one_part("part-absent", declared=dict(DIGEST),
                          declared_length="713", observed_length="5"),
}


def _semantics(report, se):
    """LINT-NDE-08 over an NDE carrying this report, with or without its SE."""
    nde = _nde(recipient_validation_failure=dict(
        _assertion(_m(), copy.deepcopy(report)),
    ), reason="payload-validation-failed")
    v = ev.Violations()
    ev.lint_nde_semantics(v, nde, se=se)
    return [m for r, m in v.items if r == "LINT-NDE-08"]


@pytest.mark.parametrize("name", sorted(CONTRADICTIONS))
def test_a_self_contradictory_part_is_caught_without_the_senders_manifest(name):
    """The regression's sharpest edge: no SE at all, and still caught."""
    assert _semantics(CONTRADICTIONS[name](), None), \
        f"{name} passed standalone verification"


@pytest.mark.parametrize("name", sorted(CONTRADICTIONS))
def test_a_self_contradictory_part_is_caught_with_the_manifest_too(name):
    assert _semantics(CONTRADICTIONS[name](), SE_MP), \
        f"{name} passed verification with the SE supplied"


@pytest.mark.parametrize("name", sorted(CONTRADICTIONS))
def test_a_self_contradictory_part_never_reaches_a_seal(name):
    """Through the real authenticated intake. The undescribed-part case used to
    seal a terminal outcome that the retained-evidence linter then accepted."""
    m = _m()
    m._CONFIRMATION_STATE.clear()
    before = copy.deepcopy(m._CONFIRMATION_STATE), copy.deepcopy(m._SE_LEDGER)
    with pytest.raises(Exception) as caught:
        _deliver(m, _assertion(m, CONTRADICTIONS[name]()))
    assert (m._CONFIRMATION_STATE, m._SE_LEDGER) == before, \
        f"{name}: the refusal moved stored state"
    assert "LINT-NDE-08" in str(caught.value) or "validation-failure" in str(caught.value), \
        caught.value


def test_the_shipped_vector_is_what_the_recipient_code_produces():
    """The positive control, and a guard on the vector itself: its part detail is
    exactly `failure_report`'s output for a payload with one wrong length and one
    wrong digest. The vector carried a digest mismatch with DIFFERING lengths
    before this — a shape the recipient cannot produce, because a wrong length is
    reported as the more precise cause and stops there."""
    vector = _ld("sample-NDE-validation-failure.json")["recipient_validation_failure"]
    fixtures = parts()
    produced = mp.failure_report(
        mp.assemble(dict(fixtures, p1=b"short", p2=b"Z" * len(fixtures["p2"]))),
        SE_MP["manifest"], SE_MP["payload_hash"])
    assert vector["failure"] == produced["failure"]
    assert vector["parts"] == produced["parts"]
    # and every part-detail field stays exercised by it (XREP-01)
    carried = {k for p in vector["parts"] for k in p}
    assert {"declared", "observed", "declared_length", "observed_length"} <= carried
