# SPDX-License-Identifier: MIT
"""Batch A / A2: the Stage-1 federation MEMBERSHIP register —
samples/federation.stage1.demo.json.

Mirrors tests/test_registry_stage1.py, which covers the Stage-1 DIRECTORY, and
adds the two things that are specific to admission:

- every record validates against the `MembershipRecord` component of
  `federation-register-openapi.yaml`;
- every record's signature is a COSE_Sign1 by the FEDERATION-AUTHORITY demo key
  over the dCBOR record minus {signature, timestamp};
- the timestamp carries the SHA-256 imprint of the signature bytes;
- a tampered record fails seal verification;
- **the design-authority key does NOT verify a membership record.** §13.1 gives
  the Federation Authority and the design authority different rows, and a
  demonstration that signed both with one key would demonstrate the opposite of
  the independence it claims;
- **a `status_history` that overlaps, has a gap, or disagrees with `status` is
  refused.** The closed Schema constrains the shape of the entries and cannot
  express relations BETWEEN them, so those three live in
  `lint_cli.validate_status_history` — and this file drives it, because a
  reader who assumes the Schema covers them would not look.

The demo register is emitted by scripts/regen_samples.py — never hand-edit.
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _need(mod):
    try:
        __import__(mod)
    except Exception:
        pytest.skip(f"{mod} not installed; skipping Stage-1 federation tests",
                    allow_module_level=True)


_need("cbor2")
_need("nacl")

REGISTER = json.loads(
    (ROOT / "samples" / "federation.stage1.demo.json").read_text(encoding="utf-8"))
STORE = json.loads(
    (ROOT / "samples" / "trust-store.demo.json").read_text(encoding="utf-8"))
FA_PUB = STORE["entries"]["federation-authority"]["pubkey_b64"]
DA_PUB = STORE["entries"]["design-authority"]["pubkey_b64"]


def _verify_record(rec, pub_b64=FA_PUB):
    """Verify ONE record through the PRODUCTION authenticator.

    R10-01: this file used to carry its own verifier — seal, payload,
    timestamp — and Batch A's closure verified THAT, while the path that
    consumed registers never checked a seal at all. A second verifier that
    passes is evidence about itself. It now calls `authenticate_register`,
    under an anchor built from `pub_b64`, so every test below exercises the
    code a verifier actually runs (standing rule 3: the superseded check is
    deleted, not kept beside its replacement)."""
    fa = STORE["entries"]["federation-authority"]
    anchors = {"federation-authority": {
        "kid": "federation-authority", "pubkey_b64": pub_b64,
        "not_before": fa["not_before"], "not_after": fa["not_after"]}}
    got, issues = lc.authenticate_register({"records": [rec]}, anchors)
    assert got is not None, issues


# ---------------------------------------------------------------------------
# The four the directory's Stage-1 file already proves, for this one
# ---------------------------------------------------------------------------

def test_records_validate_against_the_published_component():
    assert REGISTER["records"], "the demo register is empty"
    for rec in REGISTER["records"]:
        assert lc.validate_contract_object(
            "federation-register-openapi.yaml", "MembershipRecord", rec) == [], \
            rec["participant_id"]


def test_every_record_seal_verifies_with_the_federation_authority_key():
    for rec in REGISTER["records"]:
        _verify_record(rec)


def test_a_tampered_record_fails_seal_verification():
    rec = copy.deepcopy(REGISTER["records"][0])
    rec["status"] = "excluded"
    with pytest.raises(AssertionError):
        _verify_record(rec)


def test_a_wrong_key_fails_seal_verification():
    import mock_rdp as m
    wrong = m.demo_public_key_b64("entity-admin-demo")
    with pytest.raises(AssertionError, match="does not verify"):
        _verify_record(REGISTER["records"][0], pub_b64=wrong)


# ---------------------------------------------------------------------------
# ...and the two that are specific to admission
# ---------------------------------------------------------------------------

def test_the_design_authority_key_does_not_verify_a_membership_record():
    """§13.1 gives the two roles different rows, so the demonstration gives
    them different signers. The control runs first: the Federation Authority's
    key DOES verify, or this proves nothing about which key was used."""
    rec = REGISTER["records"][0]
    _verify_record(rec, pub_b64=FA_PUB)          # control
    assert FA_PUB != DA_PUB, "the demonstration uses one key for both roles"
    with pytest.raises(AssertionError, match="does not verify"):
        _verify_record(rec, pub_b64=DA_PUB)


@pytest.mark.parametrize("mutate,reason", [
    (lambda h, r: h[0].__setitem__("until", "2026-06-01T00:00:00Z"),
     "membership-history-discontinuous"),                       # gap
    (lambda h, r: h[1].__setitem__("from", "2026-01-15T00:00:00Z"),
     "membership-history-discontinuous"),                       # overlap
    (lambda h, r: r.__setitem__("status", "excluded"),
     "membership-status-disagrees"),
    (lambda h, r: h[-1].__setitem__("until", "2027-01-01T00:00:00Z"),
     "membership-history-bounded"),
    (lambda h, r: h[0].__delitem__("until"),
     "membership-history-unbounded"),
])
def test_a_history_that_cannot_answer_an_as_of_question_is_refused(mutate, reason):
    """The relations a closed Schema cannot express. The control runs first
    (round 9's rule): the untouched record must pass, or a refusal below would
    be evidence of nothing."""
    good = next(r for r in REGISTER["records"]
                if len(r["status_history"]) > 1)
    assert lc.validate_status_history(good) == [], "the control failed"
    rec = copy.deepcopy(good)
    mutate(rec["status_history"], rec)
    reasons = [x for x, _ in lc.validate_status_history(rec)]
    assert reason in reasons, f"expected {reason}, got {reasons}"


def test_the_shipped_register_answers_for_every_provider_the_samples_name():
    """The positive bar depends on this: every provider identifier the shipped
    evidence carries must be in the register, admitted before the earliest act.
    A register that did not cover them would fail the sample bar for a reason
    that is the fixture's, not the rule's."""
    import glob
    named = set()
    for f in glob.glob(str(ROOT / "samples" / "sample-*.json")):
        p = json.loads(pathlib.Path(f).read_text()).get("projection") or {}
        for k in ("rdp_id", "sending_rdp_id", "receiving_rdp_id"):
            if isinstance(p.get(k), str):
                named.add(p[k])
        for entry in p.get("rdp_chain") or []:
            named.add(entry["rdp_id"])
    assert named, "no provider identifiers found in the samples"
    carried = {r["participant_id"] for r in REGISTER["records"]}
    assert named <= carried, f"not in the register: {sorted(named - carried)}"


# ---------------------------------------------------------------------------
# A3 — the provider's own descriptor
#
# Until BW-PROVIDER, a provider was named by URL inside the CUSTOMER's
# document: `BW-MED.rdp` carries its endpoints, sealed by the entity's key. A
# provider serving a thousand entities had its endpoints republished in a
# thousand documents sealed by a thousand different signers, with nothing
# saying they described the same provider.
# ---------------------------------------------------------------------------

import importlib.util  # noqa: E402

# The SEALED artefact is what a verifier receives. R10-03: these tests linted
# the bare projection and asserted zero findings — so the control encoded the
# defect as the passing case: an unsealed descriptor passing the modes that
# advertise demo cryptography and production structure.
ARTEFACT = json.loads(
    (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())
DESCRIPTOR = ARTEFACT["projection"]


def _seal(body):
    """Re-seal a (mutated) body with the participant's own descriptor key, so
    the ONLY thing wrong with it is the mutation under test. Linting a mutated
    projection instead would fail on the broken seal too, and a test naming
    LINT-DISC-32 would pass for a reason that is not LINT-DISC-32."""
    import mock_rdp as m
    short = body["participant_id"].rsplit(":", 1)[1]
    return m.discovery_artifact(body, kid=body["kid"],
                                seed=f"{short}-descriptor-demo")


def _discovery_lint():
    spec = importlib.util.spec_from_file_location(
        "discovery_lint", ROOT / "scripts" / "discovery_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _lint(doc, **kw):
    dl = _discovery_lint()
    return [(rid, msg) for rid, msg in dl.lint(doc, **kw)]


def test_the_shipped_descriptor_passes_and_names_a_registered_participant():
    """The control, first. It also has to be TRUE that the descriptor's
    participant is in the register — a descriptor for somebody the register
    does not carry describes a provider no verifier can place."""
    assert _lint(ARTEFACT, verify_demo=True) == []
    assert _seal(copy.deepcopy(DESCRIPTOR)) == ARTEFACT, \
        "re-sealing no longer reproduces the sample, so _seal is not neutral"
    carried = {r["participant_id"] for r in REGISTER["records"]}
    assert DESCRIPTOR["participant_id"] in carried


def test_a_descriptor_whose_window_runs_backwards_is_refused():
    """LINT-DISC-32. The window is compared as INSTANTS: a descriptor asserted
    at `08:00:00-02:00` (10:00Z) and expiring at `09:00:00Z` is chronologically
    inverted and lexically ordered — the R9-04 shape, in a document that
    carries exactly two timestamps."""
    doc = copy.deepcopy(DESCRIPTOR)
    doc["asserted_at"] = "2026-04-04T08:00:00-02:00"
    doc["expires_at"] = "2026-04-04T09:00:00Z"
    assert any(rid == "LINT-DISC-32" for rid, _ in _lint(_seal(doc)))


def test_an_expired_descriptor_is_refused_at_a_later_instant():
    """LINT-DISC-32, the other half: in force AT the verification instant."""
    assert _lint(ARTEFACT, now="2026-06-01T00:00:00Z") == [], "the control failed"
    assert any(rid == "LINT-DISC-32"
               for rid, _ in _lint(ARTEFACT, now="2030-01-01T00:00:00Z"))


# ---------------------------------------------------------------------------
# R10-03 — the descriptor carries the class's obligations, in every mode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kw", [{}, {"verify_demo": True},
                                {"profile": "production"},
                                {"verify_demo": True, "profile": "production"}],
                         ids=["plain", "demo", "production", "demo+production"])
def test_an_unsealed_descriptor_fails_in_every_mode(kw):
    """The review's probe: the bare projection under `--verify-demo --profile
    production` returned []. The same bare BW-MED gets LINT-DISC-01; a new
    document type inherits the class's obligations rather than opting out of
    them by omission."""
    assert "LINT-DISC-01" in {r for r, _ in _lint(copy.deepcopy(DESCRIPTOR), **kw)}


def test_a_descriptor_is_not_in_force_before_it_was_asserted():
    """R10-03: only the upper bound was checked, so a descriptor asserted in
    2026 was in force at a 2025 verification instant — before it existed."""
    assert any(r == "LINT-DISC-32" and "not in force before" in m
               for r, m in _lint(ARTEFACT, now="2025-06-01T00:00:00Z"))


def test_an_unreadable_verification_instant_is_refused_not_skipped():
    """R10-03: an unparseable `now` was swallowed, turning "check at this
    instant" into "do not check"."""
    assert any(r == "LINT-DISC-32" and "cannot be parsed" in m
               for r, m in _lint(ARTEFACT, now="not-a-time"))


def test_a_descriptor_claiming_an_undefined_role_is_refused():
    """LINT-DISC-33. Batch A closes the enum to `rdp`; `msp` arrives in Batch
    B, and until it does a descriptor claiming it makes a claim no verifier can
    act on."""
    doc = copy.deepcopy(DESCRIPTOR)
    doc["roles"] = ["msp"]
    assert any(rid == "LINT-DISC-33" for rid, _ in _lint(_seal(doc)))


def test_the_descriptor_seal_key_is_the_one_the_register_pins():
    """A3's binding, checked here as a FACT about the shipped material; the
    RULE that enforces it for any descriptor is A5's, and lives with the trust
    rules because it needs the register as an input."""
    import base64 as _b64
    import hashlib as _hl
    import mock_rdp as m
    rec = next(r for r in REGISTER["records"]
               if r["participant_id"] == DESCRIPTOR["participant_id"])
    pinned = {k["kid"]: k["spki_sha256"] for k in rec["authorized_seal_keys"]}
    assert DESCRIPTOR["kid"] in pinned, \
        "the descriptor is sealed by a key the register does not authorise"
    pub = m.demo_public_key_b64(
        f"{DESCRIPTOR['participant_id'].rsplit(':', 1)[1]}-descriptor-demo")
    assert _hl.sha256(_b64.b64decode(pub)).hexdigest() == pinned[DESCRIPTOR["kid"]]


# ---------------------------------------------------------------------------
# A4 — the admission rule
#
# `lint_cli.admission_at` is the ONE implementation of "was this participant
# admitted when it acted". A5's gate calls it; nothing restates it. It is
# driven here because a rule shipped without a driver is a rule nobody has
# watched answer, and round 9 (R9-04) closed exactly that: a capability that
# existed, was correct, and was never called.
#
# The demo register suspends `mockeu-003` for [2026-03-01, 2026-09-01) and
# admits it either side, so one participant exercises every window.
# ---------------------------------------------------------------------------

SUSPENDED = "urn:sbm:rdp:mockeu-003"


@pytest.mark.parametrize("at,expected", [
    ("2026-02-28T23:59:59Z", "admitted"),
    ("2026-04-04T09:58:41Z", "suspended"),   # a shipped act instant
    ("2026-09-01T00:00:00Z", "admitted"),    # the last covered instant
])
def test_admission_is_resolved_at_the_instant_asked_about(at, expected):
    assert lc.admission_at(REGISTER, SUSPENDED, at) == expected


def test_an_instant_after_the_assertion_is_not_covered():
    """R10-X1. This parametrisation used to include `2026-09-01T00:00:01Z` →
    `admitted`: one second after the record was asserted, answered from the
    open-ended final window. That was the R10-02 defect stated as a passing
    case — an assertion speaking about an instant it was made before. The
    same question answered by a record asserted LATER is `admitted`, which is
    the whole point: coverage comes from the assertion, not from the window."""
    assert lc.admission_at(REGISTER, SUSPENDED, "2026-09-01T00:00:01Z") \
        is lc.NOT_COVERED
    later = copy.deepcopy(REGISTER)
    next(r for r in later["records"]
         if r["participant_id"] == SUSPENDED)["asserted_at"] = "2026-12-01T00:00:00Z"
    assert lc.admission_at(later, SUSPENDED, "2026-09-01T00:00:01Z") == "admitted"


def test_a_record_without_an_assertion_instant_cannot_answer():
    reg = copy.deepcopy(REGISTER)
    next(r for r in reg["records"] if r["participant_id"] == SUSPENDED).pop("asserted_at")
    with pytest.raises(ValueError, match="asserted_at"):
        lc.admission_at(reg, SUSPENDED, "2026-04-04T09:58:41Z")


def test_the_window_is_half_open():
    """`[from, until)`, as everywhere else in the profile (X-17/DR-11, R3-04).
    The boundary instant belongs to the entry that BEGINS there — closed at
    both ends it would carry two statuses, open at both a participant would
    have none for one instant of the day it changed."""
    assert lc.admission_at(REGISTER, SUSPENDED, "2026-03-01T00:00:00Z") == "suspended"
    assert lc.admission_at(REGISTER, SUSPENDED, "2026-09-01T00:00:00Z") == "admitted"


def test_instants_are_compared_and_not_strings():
    """R9-04. `2026-02-28T23:00:00-02:00` IS `2026-03-01T01:00:00Z` — inside
    the suspension — but sorts BEFORE the window's `from` as text. A register
    and the evidence it is asked about come from different producers, so the
    two offsets meeting is the normal case, not the exotic one."""
    inside = "2026-02-28T23:00:00-02:00"
    assert inside < "2026-03-01T00:00:00Z", "the probe no longer discriminates"
    assert lc.admission_at(REGISTER, SUSPENDED, inside) == "suspended"


def test_a_participant_the_register_does_not_carry_has_no_status():
    assert lc.admission_at(REGISTER, "urn:sbm:rdp:mockeu-999",
                           "2026-04-04T09:58:41Z") is None


def test_an_instant_before_the_record_begins_has_no_status():
    """Not "admitted by default". The register vouches for a participant from
    the instant it says so and not before; an act older than the record is an
    act the federation never covered."""
    assert lc.admission_at(REGISTER, SUSPENDED, "2025-12-31T23:59:59Z") is None


def test_an_instant_in_a_gap_has_no_status():
    """A contiguous history is `validate_status_history`'s rule, not this
    one's. If a register slips through with a gap, admission must come back
    empty rather than fall to the nearest neighbour."""
    reg = copy.deepcopy(REGISTER)
    rec = next(r for r in reg["records"] if r["participant_id"] == SUSPENDED)
    rec["status_history"][0]["until"] = "2026-02-01T00:00:00Z"
    assert lc.admission_at(reg, SUSPENDED, "2026-02-15T00:00:00Z") is None


def test_two_records_for_one_participant_are_refused_not_reconciled():
    """Picking one would make admission depend on array order — the defect
    R7-04/R8-05 refused for a certificate naming two providers."""
    reg = copy.deepcopy(REGISTER)
    reg["records"].append(copy.deepcopy(
        next(r for r in reg["records"] if r["participant_id"] == SUSPENDED)))
    with pytest.raises(ValueError, match="2 records"):
        lc.admission_at(reg, SUSPENDED, "2026-04-04T09:58:41Z")


def test_an_unreadable_instant_is_refused_rather_than_answered():
    reg = copy.deepcopy(REGISTER)
    rec = next(r for r in reg["records"] if r["participant_id"] == SUSPENDED)
    rec["status_history"][0]["from"] = "1 January 2026"
    with pytest.raises(lc.TimestampError):
        lc.admission_at(reg, SUSPENDED, "2026-04-04T09:58:41Z")
