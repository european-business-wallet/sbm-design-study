# SPDX-License-Identifier: MIT
"""R16-07 / R16-08 — two defects inside a proposal, corrected before it is judged.

`SBM-ADR-0014` proposes salting the content digest. It stays `proposed` and
`not-implemented`, A12 stays open, and nothing on the wire changes — which is
exactly why its internal contradictions matter now: the group will be asked to
accept or reject the record as written.

**R16-07.** It said a missing or malformed salt was "a mismatch by construction",
while its own construction requires a sixteen-byte salt. A recipient without one
computes nothing, so it cannot honestly produce the differing digest a mismatch
confirmation carries. The Internet-Draft already states the principle in terms —
a `mismatch` asserts a comparison that was made, and the profile defines no
reason for one that was not — which is the rule A11 was closed to satisfy.
Salting the digest would open a *new* inability to compute, and calling it a
mismatch reintroduces the false speech A11 forbade, one field along.

**R16-08.** Its list of digests that stay bare omitted `submission_hash`, which
the Internet-Draft requires over the exact submitted octets *before any parsing*,
for a request the provider may never have parsed and certainly never decrypted. A
salt inside an encrypted envelope is unreachable there, so a salted construction
would leave an intake rejection unable to carry a digest at all.

These tests pin the corrections and the facts they rest on, so that neither can
be lost by a later edit to the record.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADR = ROOT / "docs" / "adr" / "SBM-ADR-0014.md"
ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"
REASONS = ROOT / "registries" / "reason-codes.json"


def adr():
    return ADR.read_text(encoding="utf-8")


# --- the record decides nothing --------------------------------------------

def test_the_record_is_still_a_proposal():
    """Correcting a proposal must not accept it. R16-07 and R16-08 are
    completeness defects, not the decision A12 asks for."""
    front = adr().split("---")[1]
    assert "decision_status: proposed" in front
    assert "implementation_status: [not-implemented]" in front
    agenda = (ROOT / "docs" / "REVIEW_AGENDA.md").read_text(encoding="utf-8")
    a12 = next(l for l in agenda.splitlines() if l.startswith("| A12 |"))
    assert "Decided" not in a12, "A12 stays open"


# --- R16-07 ----------------------------------------------------------------

def test_a_missing_salt_is_not_called_a_mismatch():
    """The withdrawn claim may be QUOTED as withdrawn and must not be asserted.

    Read flattened, because prose wraps: the first draft of this test searched
    the raw text for "a mismatch by construction", and the record's own
    quotation of the withdrawn phrase broke across a line, so the test passed
    while the phrase was on the page. That is the same blind spot the register
    checker had, and it is why the rule here is about the SENTENCE the phrase
    sits in rather than the phrase alone.
    """
    flat = " ".join(adr().split())
    assert "A missing salt is not a mismatch" in flat
    for m in re.finditer(r"[^.]*a mismatch by construction[^.]*\.", flat):
        sentence = m.group(0)
        assert re.search(r"an earlier draft|withdrawn|cannot be|no longer", sentence, re.I), \
            f"stated rather than quoted as withdrawn: {sentence.strip()[:160]}"


def test_the_four_cases_are_named_and_required_to_be_distinguishable():
    """Absent, wrong type, wrong length, and a well-formed salt with a differing
    digest. A proposal that cannot tell them apart cannot be implemented."""
    text = adr()
    for needed in ("salt absent", "not a sixteen-byte", "digest different",
                   "distinguishable"):
        assert needed in text, needed


def test_the_intake_reason_code_is_refused_by_name_with_its_registry_binding():
    """`malformed-envelope` is bound to an intake stage and a relay stage, where
    nothing has been decrypted and no recipient has spoken. The record must say
    so, and the registry must still say what the record claims it says."""
    assert "`malformed-envelope` must not be reused" in adr()
    registry = json.loads(REASONS.read_text(encoding="utf-8"))
    # The registry names it twice, and both say the same thing. A first draft of
    # this test walked the document and kept the last hit, which read the
    # weaker of the two entries and then failed on a key it does not carry.
    as_nde = registry["nde_reasons"]["malformed-envelope"]
    assert set(as_nde["allowed_events"]) == {"A.2-SubmissionRejection", "B.3-RelayFailure"}, \
        as_nde["allowed_events"]
    assert set(as_nde["stages"]) == {"intake", "relay"}, as_nde["stages"]
    as_rejection = registry["submission_rejection_reasons"]["malformed-envelope"]
    assert as_rejection["stage"] == "intake", as_rejection


def test_the_principle_the_correction_rests_on_is_in_the_internet_draft():
    """If this sentence ever leaves the I-D, the ADR's argument loses its
    ground and the contradiction can return unnoticed."""
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "a `mismatch` confirmation asserts a comparison that was made, and this " \
           "profile defines no reason for one that was not" in id_text


def test_the_record_ties_the_defect_to_the_question_it_reopens():
    assert "the defect A11 was closed to remove" in adr()


# --- R16-08 ----------------------------------------------------------------

def test_submission_hash_is_inside_the_boundary():
    text = adr()
    assert "`submission_hash` is the fourth" in text
    boundary = text[text.index("What stays bare"):text.index("- **Re-verification.**")]
    for needed in ("envelope_hash", "mls_state", "submission_hash", "doc_digest",
                   "before any parsing or decoding"):
        assert needed in boundary, needed
    assert "these five as the\n  boundary" in text or "these five as the boundary" in \
        " ".join(text.split()), "the count must follow the list"


def test_the_requirement_submission_hash_rests_on_is_in_the_internet_draft():
    """The I-D requires it over the octets as received, before parsing — which
    is why no salt can reach it."""
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "over the EXACT submitted octets as received at the intake boundary, BEFORE " \
           "any parsing or decoding" in id_text


def test_the_boundary_is_drawn_per_field_not_by_retiring_a_mode():
    """R16-08's second half, and the hinge to R16-03: retiring modes globally
    is what produced a boundary that forgot a field."""
    text = " ".join(adr().split())
    assert "drawn **per semantic field**, not by retiring a mode globally" in text
    assert "the same inventory the generic `Hash` type needs" in text


# --- the record still says what it said ------------------------------------

def test_nothing_else_about_the_construction_moved():
    text = adr()
    assert "sm-mls:content-digest:v1" in text
    assert "`content_digest_salt`" in text
    assert "2.10 → 2.11" in text, "the proposal states its cost against the editions in force"
    assert re.search(r"no reinterpretation of already-issued evidence", text, re.I)
