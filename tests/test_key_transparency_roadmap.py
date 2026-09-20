# SPDX-License-Identifier: MIT
"""X-33 — key transparency is a ROADMAP item, not a delivered production control.

The over-claim (the TS conformance table marking it REQUIRED/assessable, the
umbrella saying it "applies") is downgraded to roadmap language consistent with
the I-D's "profile matter" framing. `doc_lint` now guards against the over-claim
returning; these tests are the negative fixture (the guard bites on the former
wording) plus a no-regression check on the live documents.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import doc_lint  # noqa: E402

NORMATIVE_DOCS = [
    "etsi/TS-SBM-QERDS-Binding-v0.1.md",
    "Secure-Business-Messaging-Profile.md",
    "ietf/draft-sbm-mls-erd-00.md",
]


def _flagged(line):
    if any(a.search(line) for a in doc_lint.ALLOW):
        return False
    return any(p.search(line) for p in doc_lint.FORBIDDEN)


def test_over_claim_wording_is_flagged():
    """The reproduced former defect: a present-tense delivered/REQUIRED claim."""
    assert _flagged("and key transparency applies in the production profile.")
    assert _flagged("| Key transparency | RECOMMENDED | REQUIRED |")


def test_roadmap_wording_is_not_flagged():
    """The replacement prose must pass the guard."""
    assert not _flagged(
        "Key transparency ... is a roadmap item — not yet profiled.")
    assert not _flagged(
        "| Key transparency | not required | roadmap target — not yet profiled |")


def test_live_documents_carry_no_over_claim():
    for rel in NORMATIVE_DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "key transparency applies" not in text.lower(), (
            f"{rel} still presents key transparency as a delivered control")
    # The TS conformance table must not mark key transparency REQUIRED.
    ts = (ROOT / NORMATIVE_DOCS[0]).read_text(encoding="utf-8")
    import re
    assert not re.search(r"Key transparency\s*\|[^|]*\|\s*REQUIRED", ts), (
        "the TS conformance table still marks key transparency REQUIRED")


def test_roadmap_framing_is_present():
    """Positive: the honest roadmap framing is actually stated."""
    ts = (ROOT / NORMATIVE_DOCS[0]).read_text(encoding="utf-8")
    assert "roadmap" in ts.lower() and "key transparency" in ts.lower()
