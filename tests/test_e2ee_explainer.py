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


def test_the_note_says_the_digest_is_unsalted_and_why_that_costs_something(note):
    assert "unsalted" in note
    assert re.search(r"take a guess at the content, hash it", note), \
        "the oracle has to be stated as a mechanism, not as a caveat"
    assert "confirms" in note and "entropy" in note


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


def test_the_note_keeps_the_two_digests_apart(note):
    """One identifies the bytes that travelled and every relaying party must be
    able to recompute it; the other identifies the content and only a holder of
    the content can. Conflating them is how a reader concludes the provider could
    read the message."""
    assert "envelope_hash" in note and "payload_hash" in note
    assert re.search(r"transmitted octets", note)
    assert re.search(r"not salted", note) or re.search(r"why they are not salted", note)


def test_the_note_states_the_boundary_the_profile_states(note):
    """`SBM-ADR-0010`'s consequence, in the words that record uses: the address is
    not the encryption boundary."""
    adr = (ROOT / "docs" / "adr" / "SBM-ADR-0010.md").read_text(encoding="utf-8")
    assert "The address is not the encryption boundary" in " ".join(adr.split())
    assert "address is not the encryption boundary" in note
    assert "records" in note and "visible" in note


def test_the_properties_it_credits_to_mls_are_the_ones_the_draft_claims(note):
    """Forward secrecy and post-compromise security hold PER EPOCH — the draft
    says so with that qualifier, and dropping it would overstate both."""
    draft = " ".join(ID.read_text(encoding="utf-8").split())
    assert "forward secrecy and post-compromise security hold per epoch" in draft.lower()
    assert re.search(r"forward secrecy and post-compromise security,? \*\*per epoch\*\*", note) \
        or re.search(r"hold \*\*per epoch\*\*", note), \
        "the per-epoch qualifier must survive into the note"
    assert "opaque" in note, "the draft's opaque-group-id claim is one of the properties"


def test_what_the_provider_sees_matches_the_umbrella(note):
    """The privacy section is the owner. The note may summarise it and must not
    contradict it: identifiers, group ids, sizes and times — never plaintext, and
    never the content class."""
    priv = " ".join(UMBRELLA.read_text(encoding="utf-8").split())
    assert "never plaintext, and never the `content_class`" in priv
    assert "content_class" in note
    assert re.search(r"not the plaintext", note, re.I)
    assert re.search(r"four-corner", note), "the path that sees MORE has to be named"


def test_the_note_restates_no_normative_requirement(note):
    """`scripts/rule_ownership.py` forbids a non-owner restating a rule in its
    normative form. The note describes; it does not legislate."""
    assert not re.search(r"\bMUST NOT\b", note), \
        "an explainer stating a prohibition in normative form is a second owner of it"
    assert not re.search(r"\bMUST\b(?! implement)", note), note[:0]


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


def test_the_evidence_explainer_carries_the_same_limit():
    """The two documents meet at the digest. The evidence explainer explains how
    evidence refers to content it cannot see and said nothing about the digest
    being testable — the gap this round closed — so both now carry it and point at
    each other."""
    ev = " ".join((ROOT / "docs" / "evidence-layer-explainer.md")
                  .read_text(encoding="utf-8").split())
    assert "UNSALTED" in ev or "unsalted" in ev
    assert "end-to-end-encryption-explainer.md" in ev
    assert re.search(r"proposed and not implemented", ev, re.I)
    assert "A12" in ev
