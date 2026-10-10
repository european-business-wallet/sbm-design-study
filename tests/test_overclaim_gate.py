# SPDX-License-Identifier: MIT
"""A heading, a label, a cell or a takeaway may not claim more than its body.

The r42 clarity review found the same defect four times — EX-01, EX-02, EX-04
and EX-08 — and four instances in one review is a class. A reader who reads only
the summary carries away the stronger claim; the careful paragraph underneath
never reaches them.

**The unit is what a reader reads on its own.** One heading line, one
front-matter value, one table row, one bullet, one figure label. Taking the
body beneath as the unit would make every instance pass, because the body is
careful in all four — which is the defect, not a defence.

**Prose is not scanned.** `every device` occurs sixteen times in the reading
path's prose and almost all of them are legitimate: *"every device that can
decrypt is a visible leaf"*, *"every enrolled device must be able to receive"*
is a requirement. A gate that buried four findings under a dozen false ones
would be worse than none, so the scope is the position and not the file.

These probes build the units they test (invariant 13) rather than reading the
tree, so the gate cannot pass by the tree happening to be clean.
"""
import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _doc_lint(root=None):
    spec = importlib.util.spec_from_file_location("doc_lint_claims",
                                                  ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if root is not None:
        mod.ROOT = root
    return mod


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


dl = _doc_lint()


# ---------------------------------------------------------------------------
# The claims, each in the unit it was actually found in
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("unit,caught", [
    # EX-01 — the heading, as it stood
    ("### 7.1 The grade commitment — verifiable without revealing the content class", True),
    ("### 7.1 The grade commitment — hidden before opening, disclosed to the verifier when opened", False),
    # EX-02 — both halves
    ("| The evidence layer is what supplies the legal weight |", True),
    ("| The layer is designed to support registered-delivery claims |", False),
    ("## Availability is only lawful for declared classes", True),
    ("## Availability is permitted by this profile for declared classes", False),
    # EX-04 — the universal membership claim
    ("label: MLS, one pair of entities, every device", True),
    ("label: MLS, one pair of entities, every eligible device", False),
    ("- **Topology:** one leaf per participating device, every device of the pair", False),
    # EX-08 — the compromise scenario
    ("RD->>RD: evidence already issued stays valid", True),
    ("RD->>RD: evidence already issued remains presumptively valid", False),
    # EX-03 adjacent
    ("- **Reads as:** overreach is provable, not deniable.", True),
    ("- **Reads as:** overreach against the declared mandate is provable, not deniable.", False),
])
def test_the_claim_is_refused_unless_its_unit_qualifies_it(unit, caught):
    assert bool(dl.overclaim_hits(unit)) is caught, (unit, dl.overclaim_hits(unit))


def test_every_entry_carries_its_reasoning():
    """§3's requirement: a later session must be able to tell why an entry
    exists, and remove it when it stops earning its place."""
    for claim, _qualifier, why in dl.OVERCLAIM:
        assert why and len(why) > 40, claim.pattern
        assert "EX-" in why, f"{claim.pattern} does not say which finding put it here"


# ---------------------------------------------------------------------------
# The positions, and the prose the gate must leave alone
# ---------------------------------------------------------------------------

def test_each_covered_position_is_scanned(tmp_path):
    _write(tmp_path, "docs/a.md",
           "# Title\n\n"
           "## A heading with every device in it\n\n"
           "| cell | evidence already issued stays valid |\n"
           "- **Reads as:** overreach is provable, not deniable.\n")
    hits = _doc_lint(tmp_path).scan_overclaims()
    assert {h[2] for h in hits} == {"heading", "table cell", "takeaway bullet"}, hits


def test_prose_is_not_scanned(tmp_path):
    """The sixteen legitimate occurrences are the reason. If this ever fails,
    the gate has started reading paragraphs and will bury its own findings."""
    _write(tmp_path, "docs/a.md",
           "Every device that can decrypt is a visible leaf in the group.\n"
           "Every enrolled device must be able to receive, which is a requirement.\n"
           "The evidence layer is what supplies the legal weight, said in prose.\n")
    assert _doc_lint(tmp_path).scan_overclaims() == []


def test_a_folded_front_matter_value_is_read_whole(tmp_path):
    """The first version of this guard matched `^choice:` by line. Every ADR
    folds that value — `choice: >-` with the text on the lines after it — so it
    saw the key and never the claim, and reported a record clean on the field
    that carried it."""
    _write(tmp_path, "docs/adr/SBM-ADR-0099.md",
           "---\nid: SBM-ADR-0099\nlabel: \"A safe label\"\nchoice: >-\n"
           "  One group per pair, and every device of either entity is a leaf\n"
           "---\n\n# SBM-ADR-0099 — a probe\n")
    hits = _doc_lint(tmp_path).scan_overclaims()
    assert [h[2] for h in hits] == ["front-matter `choice`"], hits


def test_the_records_and_the_changelog_are_exempt(tmp_path):
    """A record of a moment keeps the words it used, like every other guard
    here: the class is about what a CURRENT summary claims.

    The exempt set is DERIVED, not listed. Naming `docs/DESIGN_FINDINGS.md`
    here passed in the source and failed in the export, which does not ship the
    review bodies — so the file was not a declared record there, not exempt,
    and the probe failed on a tree where the gate was behaving correctly. A
    probe that names a document only one tree has is a probe about that tree.
    """
    mod = _doc_lint(tmp_path)
    exempt = [rel for rel in mod.EXEMPT if rel.endswith(".md")]
    assert "CHANGELOG.md" in exempt, "the chronological record is always exempt"
    for rel in exempt:
        _write(tmp_path, rel, "## The heading said every device, and that was the defect\n")
    assert mod.scan_overclaims() == []


def test_the_gate_fails_the_run(monkeypatch, capsys):
    """A scan nothing acts on is a report, not a gate."""
    mod = _doc_lint()
    monkeypatch.setattr(mod, "scan_overclaims",
                        lambda *a, **k: [("README.md", 1, "heading",
                                          "every device", "# every device")])
    with pytest.raises(SystemExit) as exc:
        mod.main()
    assert exc.value.code == 2
    assert "claims more than the body" in capsys.readouterr().out
