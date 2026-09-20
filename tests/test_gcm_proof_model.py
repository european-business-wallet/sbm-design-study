# SPDX-License-Identifier: MIT
"""DR-03 — a grade-mismatch dispute must be PROVEN, not merely unequal.

Former defect (round-2 review, Blocker, reproduced end-to-end before this
was written): `LINT-BND-26` accepted a dispute whenever the recomputed
commitment DIFFERED from the sealed one — and difference is manufacturable.
Keep the sealed commitment correctly echoed, invent `salt = 00…00` and name
an availability-declared class, and the bundle linted `OK: 0 violation(s)`.
Any recipient provider could rebut ANY availability-grade DE. Two further
defects: the salt pattern admitted 1–64 bytes AND odd lengths, and an
odd-length (schema-VALID) salt raised an uncaught `ValueError` inside
`bundle_lint` — a denial of validation, not a lint failure.

Decision R2-M1: an ATTRIBUTABLE RECIPIENT ASSERTION. The dispute now carries
a recipient-device wallet signature over the full tuple, resolved against
the device's published key as of `read_at`; commitment inequality alone
proves nothing. Honest scope, stated in the spec and asserted below: this
proves an attributable claim, NOT objective extraction from the ciphertext.

The six acceptance tests are the review's own, verbatim.
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

GCM = json.load(open(ROOT / "samples" / "sample-GCM.json"))["projection"]


def _bundle(gcm):
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    ev = [_rc(x) for x in m["evidence"]] + [gcm]
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], ev]


def _bnd26(gcm):
    issues = bl.check_bundle(*_bundle(gcm))
    return [msg for r, msg in issues if r == "LINT-BND-26"]


def _resign(gcm):
    """Re-sign the confirmation over its own (possibly mutated) content."""
    conf = {k: v for k, v in gcm["reveal_confirmation"].items()
            if k != "wallet_signature_b64"}
    conf["wallet_signature_b64"] = mock._wallet_sign(conf)
    gcm["reveal_confirmation"] = conf
    return gcm


# ---------------------------------------------------------------------------
# The exploit the review demonstrated — now dead
# ---------------------------------------------------------------------------

def test_negative_the_reviews_exploit_as_run_is_rejected():
    """The exploit AS THE REVIEW RAN IT: keep grade_commitment correctly
    echoed, invent an all-zero salt and an availability-declared class, with
    NO recipient proof (none existed then). It produced ZERO violations."""
    bad = copy.deepcopy(GCM)
    bad["reveal"] = {"salt": "00" * 16, "content_class": "regulatory-filing"}
    msgs = _bnd26(bad)
    assert msgs, "the unproven invented-reveal rebuttal must no longer pass"


def test_the_RESIDUAL_is_pinned_honestly_an_attributable_lie_still_disputes():
    """WHAT R2-M1 DOES NOT DO, pinned so nobody later believes otherwise.

    A LEGITIMATE recipient member can still invent a reveal and sign it
    correctly: the dispute is ACCEPTED. That is the chosen model, not a gap
    in its implementation — an attributable assertion makes the claimant
    ACCOUNTABLE (a named device of a named member, resolvable through the
    accountability log and the dispute path), it does not make the claim
    true. Objective ciphertext-to-reveal proof would need the construction
    recorded as future work. What changed: before, ANY provider could rebut
    ANY availability delivery with no attribution whatsoever."""
    bad = copy.deepcopy(GCM)
    bad["reveal"] = {"salt": "00" * 16, "content_class": "regulatory-filing"}
    bad["reveal_confirmation"].update({"salt": "00" * 16,
                                       "content_class": "regulatory-filing"})
    _resign(bad)
    assert not _bnd26(bad), \
        "the model is attributability, not objective proof — if this ever " \
        "starts failing, the spec text must change with it"
    # ...and the specification says so, in the object that carries the claim:
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    desc = common["$defs"]["RecipientRevealConfirmation"]["description"]
    assert "does NOT prove" in desc


def test_negative_inequality_without_proof_proves_nothing():
    """The structural fix: strip the proof and the dispute is inert, whatever
    the arithmetic says."""
    bad = copy.deepcopy(GCM)
    bad.pop("reveal_confirmation")
    assert lc.validate_body(bad), "reveal_confirmation is schema-REQUIRED"
    msgs = _bnd26(bad)
    assert any("proves\nnothing" in m or "proves nothing" in m for m in msgs), msgs


# ---------------------------------------------------------------------------
# The review's six acceptance tests
# ---------------------------------------------------------------------------

def test_random_salt_random_class_and_foreign_member_are_rejected():
    for mutate in (
        lambda g: g["reveal"].__setitem__("salt", "ab" * 16),
        lambda g: g["reveal"].__setitem__("content_class", "x-invented-class"),
        lambda g: g.__setitem__("mid", "F2X3Y4Z55"),
    ):
        bad = copy.deepcopy(GCM)
        mutate(bad)
        assert _bnd26(bad), "mutation accepted where it must be rejected"


def test_malformed_or_odd_length_salt_is_rejected_without_an_exception():
    """The denial-of-validation defect: an odd-length salt used to raise an
    uncaught ValueError INSIDE the validator."""
    bad = copy.deepcopy(GCM)
    bad["reveal"]["salt"] = "abc"                 # odd length
    _resign(bad)
    assert lc.validate_body(bad), "the schema must reject a 3-char salt"
    issues = bl.check_bundle(*_bundle(bad))       # must NOT raise
    assert issues, "a malformed dispute must produce violations, not silence"
    v = el.Violations()
    el.lint_gcm(v, copy.deepcopy(bad))
    assert any(r == "LINT-GCM-02" for r, _ in v.items), v.items


def test_15_and_17_byte_salts_are_rejected():
    for n in (15, 17):
        bad = copy.deepcopy(GCM)
        bad["reveal"]["salt"] = "0" * (2 * n)
        assert lc.validate_body(bad), f"{n}-byte salt must fail the schema"
        v = el.Violations()
        el.lint_gcm(v, copy.deepcopy(bad))
        assert any(r == "LINT-GCM-02" for r, _ in v.items), n


def test_a_valid_proof_verifies_against_the_key_active_at_read_at():
    assert not lc.validate_body(copy.deepcopy(GCM))
    assert not _bnd26(copy.deepcopy(GCM)), _bnd26(copy.deepcopy(GCM))
    conf = GCM["reveal_confirmation"]
    assert conf["mid"] == GCM["mid"] and conf["read_at"] == GCM["read_at"]


def test_changing_any_signed_tuple_member_invalidates_the_dispute():
    """Every member of the review's tuple, one at a time."""
    OTHER = {"message_id": "01HZ3OTHERMESSAGE00000000",
             "envelope_hash": {"format": "mls10-message", "hex": "e" * 64},
             "grade_commitment": "f" * 64, "salt": "cd" * 16,
             "content_class": "x-other", "read_at": "2020-01-01T00:00:00Z",
             "recipient_uid": "EU-DE-EOID-7K3D9W0Q2M5FW0", "mid": "F2X3Y4Z55"}
    for field, value in OTHER.items():
        bad = copy.deepcopy(GCM)
        bad["reveal_confirmation"][field] = value
        _resign(bad)          # signature remains VALID over the mutated tuple
        assert _bnd26(bad), f"a confirmation not covering {field} must fail"


def test_the_spec_states_what_the_proof_does_and_does_not_prove():
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    desc = common["$defs"]["RecipientRevealConfirmation"]["description"]
    assert "ATTRIBUTABLE RECIPIENT ASSERTION" in desc
    assert "does NOT prove" in desc and "extracted from the disputed ciphertext" in desc
