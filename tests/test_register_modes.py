# SPDX-License-Identifier: MIT
"""Round 11 / B5 — R11-05: the register answers two different questions.

R10-X1 made an assertion speak only up to its own `asserted_at`. The
register's `as_of` read still TRUNCATED the history to the requested instant
and set `status` to the status then, while `status` is defined as the status
at `asserted_at`. The review's counterexample — admitted on 1 March, act on
10 March, suspension on 15 March, query on 1 June: the archived March record
cannot cover the act; a June record truncated at 10 March ends in "admitted"
and contradicts its own assertion instant; backdating contradicts coverage.

R11-X3: history is EVALUATED — a complete record asserted at or after the act
answers for it — never truncated. Live use is a separate claim, a lease, with
one decision instant and one freshness test. The review's acceptance: an
as-of response, authenticated, admits a pre-suspension act and cannot
establish a post-suspension act from stale history; a live exchange has a
documented, implementable time of decision and freshness test, without
backdating or guessing future status.
"""
import copy
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import lint_cli as lc  # noqa: E402
import test_federation_gate as fg  # noqa: E402

PID = fg.PID
ACT, AFTER_SUSPENSION = "2026-03-10T00:00:00Z", "2026-03-20T00:00:00Z"


def _auth(reg):
    got, problems = lc.authenticate_register(reg, fg._anchor())
    assert got is not None and problems == [], problems
    return got


# ---------------------------------------------------------------------------
# History — evaluate the complete record, never a truncated one
# ---------------------------------------------------------------------------

def test_the_complete_later_record_answers_for_the_act_and_for_the_suspension():
    """The response the register now returns for `as_of=10 March`: a record
    asserted at or after it — here the one asserted 1 June — complete."""
    june = _auth(fg.NEW)
    assert lc.admission_at(june, PID, ACT) == "admitted"
    assert lc.admission_at(june, PID, AFTER_SUSPENSION) == "suspended"


def test_stale_history_cannot_establish_the_act():
    march = _auth(fg.OLD)
    assert lc.admission_at(march, PID, ACT) is lc.NOT_COVERED
    assert lc.admission_at(march, PID, AFTER_SUSPENSION) is lc.NOT_COVERED


def test_why_truncation_was_withdrawn():
    """What the old contract told the register to return for `as_of=10 March`:
    the June record cut back to 10 March. Even genuinely FA-sealed it is FALSE
    — it answers "admitted" for an act after the suspension it deleted, while
    claiming to speak up to 1 June. No verifier-side rule can repair a record
    that says the wrong thing inside its own coverage."""
    truncated = fg._register_where_001(
        [{"status": "admitted", "from": "2026-01-01T00:00:00Z"}], "2026-06-01T00:00:00Z")
    assert lc.admission_at(_auth(truncated), PID, AFTER_SUSPENSION) == "admitted"


# ---------------------------------------------------------------------------
# Live — a lease, decided at one instant
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("decision_at,verdict", [
    ("2026-03-01T00:00:00Z", "authorised"),       # at asserted_at
    ("2026-03-02T00:00:00Z", "authorised"),       # at the end of a P1D lease
    ("2026-03-02T00:00:01Z", "stale"),
    ("2026-02-28T23:59:59Z", "record-from-the-future"),
], ids=["at-assertion", "at-lease-end", "after-lease", "before-assertion"])
def test_the_lease_boundaries(decision_at, verdict):
    assert lc.live_authorisation(_auth(fg.OLD), PID, decision_at=decision_at,
                                 max_age="P1D")[0] == verdict


def test_a_fresh_record_that_says_suspended_does_not_authorise():
    assert lc.live_authorisation(_auth(fg.NEW), PID, decision_at="2026-06-01T01:00:00Z",
                                 max_age="P1D")[0] == "not-admitted"


def test_an_unknown_participant_is_no_record():
    assert lc.live_authorisation(_auth(fg.NEW), "urn:sbm:rdp:nobody-000",
                                 decision_at="2026-06-01T01:00:00Z",
                                 max_age="P1D")[0] == "no-record"


def test_there_is_no_live_decision_without_the_published_bound():
    with pytest.raises(ValueError):
        lc.live_authorisation(_auth(fg.OLD), PID, decision_at="2026-03-01T01:00:00Z",
                              max_age=None)


def test_only_an_authenticated_register_can_authorise():
    with pytest.raises(TypeError):
        lc.live_authorisation(copy.deepcopy(fg.OLD), PID,
                              decision_at="2026-03-01T01:00:00Z", max_age="P1D")


def test_a_live_authorisation_is_not_admission_at_the_act():
    """The two questions stay apart: the exchange at 12:00 on 1 March was
    authorised live, and evidence of it is still unestablished until a record
    asserted after it is obtained."""
    march = _auth(fg.OLD)
    at = "2026-03-01T12:00:00Z"
    assert lc.live_authorisation(march, PID, decision_at=at, max_age="P1D")[0] == "authorised"
    assert lc.admission_at(march, PID, at) is lc.NOT_COVERED
    assert lc.admission_at(_auth(fg.NEW), PID, at) == "admitted"
