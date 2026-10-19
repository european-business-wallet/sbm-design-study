# SPDX-License-Identifier: MIT
"""`docs/end-to-end-encryption-explainer.md` states no claim of its own.

Every load-bearing sentence in it belongs to a normative document or to a
decision record, and this file holds it to them. An explainer that drifts from
what it explains is worse than no explainer: a reader cannot tell which of the
two is current.

The claim this file exists for is the one the note was asked to make: **the
content digest is unsalted, and salting it is PROPOSED and not implemented.**
Both halves are easy to get wrong in opposite directions — a reader who takes
SBM-ADR-0014's existence for a feature, or a note that omits the limit and leaves
`payload_hash` looking like a commitment.
"""
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

NOTE = ROOT / "docs" / "end-to-end-encryption-explainer.md"
UMBRELLA = ROOT / "Secure-Business-Messaging-Profile.md"
ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"


@pytest.fixture(scope="module")
def note():
    return " ".join(NOTE.read_text(encoding="utf-8").split())


def test_the_note_does_not_present_the_salted_digest_as_implemented(note):
    """SBM-ADR-0014 is `proposed` / `not-implemented`. A note that reads as though
    the salt shipped would be describing a repository that does not exist."""
    import adr_index
    rec = next(fm for _, fm, _ in adr_index.load() if fm["id"] == "SBM-ADR-0014")
    assert rec["decision_status"] == "proposed", rec["decision_status"]
    assert rec["implementation_status"] == ["not-implemented"], rec["implementation_status"]
    assert re.search(r"proposed and not implemented", note, re.I), \
        "the note must say so in those terms"
    assert re.search(r"today `payload_hash` is a bare digest", note, re.I)
    # and it must not claim the opposite anywhere
    assert not re.search(r"the (content )?digest is salted\b", note, re.I)
    assert not re.search(r"salted (content )?digest (is|has been) (implemented|in force)", note, re.I)


def test_every_document_it_points_at_exists():
    import doc_lint
    assert doc_lint.scan_links([NOTE]) == []


def test_it_is_on_the_security_route_and_in_the_companion_table():
    """An explainer a reader never reaches is one the review will find again."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "REVIEWER_GUIDE.md").read_text(encoding="utf-8")
    assert "](docs/end-to-end-encryption-explainer.md)" in readme
    assert "](end-to-end-encryption-explainer.md)" in guide
    row = next(l for l in guide.splitlines() if "**Security and privacy**" in l)
    assert "end-to-end-encryption-explainer.md" in row, row
