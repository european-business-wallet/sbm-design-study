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
import json
import pathlib
import re
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


def test_one_message_crosses_every_stage_that_handles_a_message():
    """R30-PUB-03 — the assertion this file was missing.

    Checking headings and operation names cannot tell a composition from a
    collection of scenarios, and it did not: the submission sealed
    `01HZ5INTAKE…` while delivery took its group from a shipped fixture and
    confirmation confirmed the fixture's `01HZ3ABCD…` entirely. A regression
    stopping the submitted message from reaching confirmation would have left
    every heading in place and the trace green.

    So the identity is asserted, not the layout: whatever message the run
    submits, that is the one the later stages handle, and no OTHER message id
    appears anywhere in the document.
    """
    sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
    import trace_flow

    recorded = trace_flow.run()[0]          # run() returns (trace, m, i, se)
    steps = recorded.steps
    by_section = {}
    for step in steps:
        by_section.setdefault(step["section"], []).append(json.dumps(step["detail"],
                                                                    default=str))

    sent = [i for i in re.findall(r"\b01HZ[0-9A-Z]{8,30}\b",
                                 " ".join(by_section.get("Sending", [])))]
    assert sent, "the Sending stage produced no message id to carry"
    carried = max(set(sent), key=sent.count)

    for section in ("Delivery", "Confirmation"):
        blob = " ".join(by_section.get(section, []))
        others = set(re.findall(r"\b01HZ[0-9A-Z]{8,30}\b", blob)) - {carried}
        assert carried in blob, (
            f"{section} handles no message the run produced — the stages are a "
            "collection of scenarios rather than a composition")
        assert not others, (
            f"{section} also handles {sorted(others)}, which the run did not "
            f"submit; the trace claims to compose {carried}")


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



def test_the_nominal_confirmations_actually_succeed():
    """R32-RES-01 — what the continuity check above could not see.

    Asserting that the submitted id APPEARS in the Confirmation section was
    satisfied by the mismatch branch, which carries the same id. So all three
    nominal confirmations could be — and were — REFUSED while the check passed,
    and the published document printed three refusals beside prose saying the
    quorum was satisfied. The confirmation relabelled the fixture instead of
    binding to the SE, and LINT-DE-16 rejected it, correctly.

    An outcome is not evidence of a state transition. This asserts the
    transition: the three nominal acts succeed, the retry does not double-count,
    and the policy ends SATISFIED.
    """
    sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "tests")]
    import trace_flow

    steps = trace_flow.run()[0].steps
    nominal = [s for s in steps
               if s["section"] == "Confirmation"
               and s["operation"].startswith("POST /confirmations (s3")]
    assert len(nominal) == 3, [s["operation"] for s in nominal]
    refused = [s["operation"] for s in nominal if s["outcome"] != "ok"]
    assert not refused, f"a nominal confirmation was refused: {refused}"

    state = next((s for s in steps if s["operation"] == "GET the confirmation state"), None)
    assert state and state["outcome"] == "ok", "the trace does not read the state back"
    assert state["detail"]["state"] == "satisfied", state["detail"]
    assert sorted(state["detail"]["counted"]) == ["F1N2C3D4P", "F2X3Y4Z55"], \
        "the quorum must be two DISTINCT members — a retry counted twice would " \
        "satisfy a count without satisfying the policy"


def test_the_document_shows_no_refusal_where_it_claims_success():
    """The cheapest guard, and the one that would have caught it on sight: a step
    whose prose says an act counts must not be rendered as a refusal."""
    text = DOC.read_text(encoding="utf-8")
    blocks = text.split("### ")[1:]
    contradictions = []
    for block in blocks:
        says_success = any(phrase in block for phrase in
                           ("this counts", "counted once", "quorum is satisfied"))
        if says_success and block.startswith("\u2717"):
            contradictions.append(block.splitlines()[0])
    assert not contradictions, contradictions
