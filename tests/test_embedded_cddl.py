# SPDX-License-Identifier: MIT
"""A CDDL block quoted in a document says what the normative file says.

The Internet-Draft embeds five CDDL blocks, so a reader meets the wire format
where the rule is explained. Nothing compared them with `cddl/sm-mls-erd.cddl`,
and they had drifted:

- the manifest block said `digest: hash` — a type the per-field digest domains
  REMOVED on 27 September 2026 — where the file says `raw-hash`, and its comment
  described the value as `{ alg, hex }`, the reduced form the prose two lines
  above forbids by name;
- `sm-evidence-artifact` was embedded **twice with two different bodies**, and
  one copy named `cose-sign1`, which the normative file does not define at all.

Agreement between copies is not correctness — this repository learned that in
round 5 — and here the copies did not even agree. A reader building an
implementation from the draft, which is what a draft is for, would have been
building from the wrong definition with every gate green, because the gates read
the file and the reader reads the document.

These tests hold the gate honest: that it reproduces each defect it was built
for, that it tolerates layout, and that the declared exception is narrow.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cddl_embedded as ce  # noqa: E402

ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"


def test_the_tree_agrees_with_itself():
    assert ce.problems() == []


def test_the_gate_reaches_the_draft_and_skips_the_historical_record():
    """Driven by `versions.json`'s declared historical records rather than a
    second list, which is the rule this repository applies to every other
    generated set. `docs/OCTET_AUTHORITATIVE_DESIGN.md` carries a CDDL block
    recording what was said at the time, and is declared historical."""
    scanned = {p.relative_to(ROOT).as_posix() for p in ce.scanned()}
    assert "ietf/draft-sbm-mls-erd-00.md" in scanned
    assert "docs/OCTET_AUTHORITATIVE_DESIGN.md" not in scanned
    assert "CHANGELOG.md" not in scanned


def test_the_blocks_are_actually_read():
    """A gate that found no blocks would pass silently — the emptiness failure
    the resolved-shapes gate shipped once and was caught on.

    The count is not pinned. A first version asserted `== 5` and broke the next
    day, when A14 added the payload-framing block — a probe carrying a number it
    does not derive is invariant 13 in a test, and the repository has paid for
    that one before. What is asserted is that blocks are found, that none is
    empty, and that the rules a reader needs are among them.
    """
    blocks = ce.BLOCK.findall(ID.read_text(encoding="utf-8"))
    assert len(blocks) >= 5, blocks
    assert all(b.strip() for b in blocks)
    defined = set()
    for b in blocks:
        defined |= set(ce.rules(b))
    for needed in ("manifest-part", "payload-part", "sm-evidence-artifact"):
        assert needed in defined, needed


# --- the two defects it was built for --------------------------------------

def _patched(tmp_path, before, after):
    """A copy of the draft with one substitution, scanned in place of the tree."""
    text = ID.read_text(encoding="utf-8")
    assert text.count(before) == 1, before[:60]
    target = tmp_path / "ietf" / "draft-sbm-mls-erd-00.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text.replace(before, after), encoding="utf-8")
    return target


@pytest.fixture
def only(monkeypatch):
    def use(path):
        monkeypatch.setattr(ce, "scanned", lambda: [path])
        monkeypatch.setattr(ce, "ROOT", path.parents[1])
    return use


def test_a_type_the_profile_removed_is_reported(tmp_path, only):
    """The manifest block, as it stood: `digest: hash`, where the digest domains
    replaced `hash` with three named types and `raw-hash` is the part's."""
    only(_patched(tmp_path, "digest: raw-hash,", "digest: hash,"))
    found = ce.problems()
    assert any("`manifest-part` differs" in p for p in found), found
    # And it is reported as UNDEFINED as well, because `hash` no longer exists.
    # It did when this gate was written: the CDDL said `content-hash = hash`,
    # keeping the permissive shape under its old name and reachable by any rule
    # that named it — while the Schema's probe for the same pass requires that
    # shape to be gone, "not aliased". The alias is gone; the three domains are
    # spelled out.
    assert any("references `hash`" in p for p in found), found


def test_one_rule_defined_twice_with_two_bodies_is_reported(tmp_path, only):
    """`sm-evidence-artifact` was embedded twice and the copies disagreed. That
    is reportable even if neither copy happened to match the file, because two
    definitions of one rule cannot both be the rule."""
    only(_patched(tmp_path, "sm-evidence-artifact = [ cose-sign1-bytes, qualified-timestamp ]",
                  "sm-evidence-artifact = [ cose-sign1, qualified-timestamp ]"))
    found = ce.problems()
    assert any("is also defined at" in p and "they disagree" in p for p in found), found
    assert any("references `cose-sign1`" in p for p in found), found


# --- and what it must NOT report -------------------------------------------

def test_layout_is_not_a_difference(tmp_path, only):
    """A document wraps a rule to fit a column; a file does not. A gate that
    fired on that would be switched off within a week, and then it would catch
    nothing at all."""
    only(_patched(tmp_path, "manifest-def  = [ + manifest-part ]",
                  "manifest-def  = [\n    + manifest-part,\n]"))
    assert ce.problems() == []


def test_a_comment_is_not_a_difference(tmp_path, only):
    only(_patched(tmp_path, "; the full hash descriptor over the part's octets",
                  "; reworded, and the type is untouched"))
    assert ce.problems() == []


def test_the_illustrative_exception_is_declared_and_narrow(tmp_path, only):
    """The two commitment blocks name their elements — `salt`, `content_class` —
    because there the point is which value goes in which position. They say so
    in the block. What the exception does NOT cover is the domain-separation
    tag: a wrong tag is the one error such a block can make that silently
    breaks every verifier that computes the commitment."""
    draft = ID.read_text(encoding="utf-8")
    assert draft.count("; ILLUSTRATIVE —") == 2, "the exception is declared, not inferred"
    for marker in ("grade-commitment-input = [   ; ILLUSTRATIVE",
                   "mandate-commitment-input = [ ; ILLUSTRATIVE"):
        assert marker in draft, marker
    only(_patched(tmp_path, '"sm-mls:grade-commitment:v2",   ; tstr',
                  '"sm-mls:grade-commitment:v3",   ; tstr'))
    found = ce.problems()
    assert any("domain-separation tag" in p and "v3" in p for p in found), found
