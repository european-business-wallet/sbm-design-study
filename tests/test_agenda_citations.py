# SPDX-License-Identifier: MIT
"""An agenda entry cited in a document must be one the agenda has.

`docs/REVIEW_AGENDA.md` is the list of open questions, and several documents
point at it by identifier: the architecture decision records link `[A6]`, the
design study's `OPEN-ITEMS.md` ends each section with `Agenda: A12.`, and the
companions cite one where a claim depends on it. Nothing checked that the
identifier on the left is a row on the right.

It nearly went wrong once already. A work order written on 25 September named
`A11` for the salted-digest question, because A11 was free when it was written;
by the time it ran, A11 had been published for the hash-mode question and cited
from `CONTRIBUTING.md`. The collision was caught by reading, not by a check, and
the next one would be a citation pointing at a row that says something else.

**Only unambiguous citation forms are read.** A bare `A6` is not enough: the
umbrella writes `Annex R/A6` for an annex item, `(normative NOTE, A5)` for an
agent-profile rule, and `A2` inside a hardening table — none of them agenda
entries. So this reads two forms that can mean nothing else: a Markdown link
whose target is the agenda, and the `Agenda: ...` line the open-items document
ends its sections with.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENDA = ROOT / "docs" / "REVIEW_AGENDA.md"

LINKED = re.compile(r"\[([AL]\d+)\]\([^)]*REVIEW_AGENDA\.md[^)]*\)")
AGENDA_LINE = re.compile(r"^Agenda:\s*(.+?)\.\s*$", re.M)
IDENT = re.compile(r"\b([AL]\d+)\b")


def agenda_rows(agenda_text):
    """The identifiers the agenda actually has, one per table row."""
    return {m.group(1) for m in re.finditer(r"^\|\s*([AL]\d+)\s*\|", agenda_text, re.M)}


def citations(root):
    """{identifier: [where]} for every unambiguous agenda citation in the tree."""
    found = {}
    files = [root / "README.md", root / "OPEN-ITEMS.md", root / "CONTRIBUTING.md",
             *sorted((root / "docs").glob("*.md")),
             *sorted((root / "docs" / "adr").glob("*.md"))]
    for path in files:
        if not path.exists() or path.name == "REVIEW_AGENDA.md":
            continue
        rel = path.relative_to(root).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            seen = {m.group(1) for m in LINKED.finditer(line)}
            m = AGENDA_LINE.match(line)
            if m:                       # "Agenda: A12." / "Agenda: L1 to L9."
                seen |= set(IDENT.findall(m.group(1)))
            for ident in seen:
                found.setdefault(ident, []).append(f"{rel}:{n}")
    return found


def dangling_citations(root):
    """[(identifier, where)] — citations of a row the agenda does not have."""
    agenda = (root / "docs" / "REVIEW_AGENDA.md")
    if not agenda.exists():
        return []
    rows = agenda_rows(agenda.read_text(encoding="utf-8"))
    return [(ident, where) for ident, places in sorted(citations(root).items())
            for where in places if ident not in rows]


def test_every_cited_agenda_entry_exists():
    assert dangling_citations(ROOT) == []


def test_the_agenda_is_read_as_rows_not_as_prose():
    """A6 is a row; `Annex R/A6` in the umbrella is not, and the agenda's own
    prose mentioning an entry is not a row either."""
    rows = agenda_rows(AGENDA.read_text(encoding="utf-8"))
    assert {"A1", "A6", "A11", "A12", "L1", "L9"} <= rows
    assert all(re.fullmatch(r"[AL]\d+", r) for r in rows)


def test_something_is_actually_cited():
    """A check over an empty set passes and proves nothing."""
    found = citations(ROOT)
    assert len(found) >= 5, found
    assert "A12" in found, "the salted-digest question is cited by SBM-ADR-0014"


@pytest.fixture
def mini(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "adr").mkdir()
    (tmp_path / "docs" / "REVIEW_AGENDA.md").write_text(
        "| # | Question |\n|---|---|\n| A6 | The MSP as a participant |\n"
        "| A12 | The salted content digest |\n| L9 | The exclusion list |\n", encoding="utf-8")
    return tmp_path


def test_a_citation_of_a_row_that_does_not_exist_is_caught(mini):
    """The collision that nearly happened: a document naming an identifier the
    agenda gave to a different question, or never had."""
    (mini / "docs" / "adr" / "SBM-ADR-0099.md").write_text(
        "pending [A11](../REVIEW_AGENDA.md), assigned to nobody\n", encoding="utf-8")
    assert dangling_citations(mini) == [("A11", "docs/adr/SBM-ADR-0099.md:1")]


def test_an_agenda_line_naming_a_range_is_read_whole(mini):
    """`Agenda: L1 to L9.` cites both ends, and both must exist."""
    (mini / "OPEN-ITEMS.md").write_text("Some claim.\n\nAgenda: L1 to L9.\n", encoding="utf-8")
    assert [i for i, _ in dangling_citations(mini)] == ["L1"], "L9 exists; L1 does not"


def test_an_annex_item_is_not_read_as_an_agenda_entry(mini):
    """`Annex R/A6`, `(normative NOTE, A5)` and a bare `A2` in a table are real
    sentences in the umbrella, and none of them cites the agenda."""
    (mini / "docs" / "companion.md").write_text(
        "### Agent security posture (normative NOTE, Annex R/A6)\n"
        "Mandate validity is checked at `sent_at` (Annex R/A2), and A5 applies.\n",
        encoding="utf-8")
    assert dangling_citations(mini) == []
