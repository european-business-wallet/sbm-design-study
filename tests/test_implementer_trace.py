# SPDX-License-Identifier: MIT
"""G2 — the trace is current, and says what it is.

A worked example that drifts is worse than none: it reads as authoritative and
teaches a flow the code no longer has. `docs/implementer-trace.md` is generated
by driving the reference's published entry points, and this fails if the
committed document is not what a fresh run produces.

It also holds the document's limits in place. The trace is the reference
composing with itself — not an interoperability result, not the four-corner
path, not production trust, and it does not reach a Delivery Evidence object.
Those absences are the difference between answering G2 and appearing to.
"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "implementer-trace.md"


def test_the_trace_is_what_a_fresh_run_produces():
    out = subprocess.run([sys.executable, "scripts/trace_flow.py", "--check"],
                         cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_the_trace_composes_the_whole_flow_not_one_stage():
    """The point of G2: the state machines compose. A trace of one stage would
    be the passing helpers the review said do not answer it."""
    text = DOC.read_text(encoding="utf-8")
    for section in ("## Channel formation", "## Sending", "## Delivery",
                    "## Confirmation", "## Multipart"):
        assert section in text, section
    for operation in ("/keypackages/{uid}/reservations", "/welcomes", "/submissions",
                      "/messages", "/confirmations"):
        assert operation in text, operation


def test_the_negative_and_retry_branches_are_there_and_named():
    """G2 asks for them in terms, and they are where an implementer learns what
    the operation refuses rather than what it accepts."""
    text = DOC.read_text(encoding="utf-8")
    assert text.count("**Negative branch.**") >= 8, text.count("**Negative branch.**")
    assert text.count("**Retry branch.**") >= 3
    for reason in ("reservation-conflict", "invitation-unknown", "identity-incoherent",
                   "expiry-not-after-sent", "collection-token-required",
                   "confirmation-member-ineligible"):
        assert reason in text, reason


def test_the_document_states_what_it_is_not():
    """Every limit here is one a reader would otherwise have to discover. An
    example that omits them is how a demonstration becomes a claim."""
    text = DOC.read_text(encoding="utf-8")
    for limit in ("Not an interoperability result", "Not the four-corner path",
                  "Not the transformations", "Not production trust",
                  "does not reach a Delivery Evidence object"):
        assert limit in text, limit
    assert "claim 4" in text, "the unestablished claim must be named, not alluded to"


def test_the_gap_it_answers_and_the_ones_it_does_not():
    agenda = (ROOT / "docs" / "REVIEW_AGENDA.md").read_text(encoding="utf-8")
    g2 = next(l for l in agenda.splitlines() if l.startswith("| G2 |"))
    assert "implementer-trace" in g2, \
        "the row must point at what now answers it, or the answer is unfindable"
    # And the trace names the gap it exposes rather than hiding behind it.
    assert "**G1**" in DOC.read_text(encoding="utf-8")
