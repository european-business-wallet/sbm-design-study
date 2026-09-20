# SPDX-License-Identifier: MIT
"""Architecture decision records — one authority, an index generated from it.
`docs/adr/SBM-ADR-NNNN.md` are the records; `docs/decisions-index.md` is rendered
from their front matter by `scripts/adr_index.py` and is never hand-edited. These
gates enforce the two defects the index used to have — rows numbered by position,
so a new choice renumbered the rest, and a status cell that ran the decision's
status and the implementation's together — and the drift a second hand-kept copy
invites.
The negative fixtures reproduce each: a record with a gap in the numbering, a
record whose statuses are not told apart, and an index edited by hand.
"""
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import adr_index as ai  # noqa: E402


def test_records_are_well_formed_and_index_is_current():
    problems = ai.check()
    assert not problems, "architecture decision records:\n" + "\n".join(problems)


def test_markdown_is_not_stale():
    assert ai.INDEX.read_text(encoding="utf-8") == ai.render_md(), \
        "docs/decisions-index.md differs from its render: run `python3 scripts/adr_index.py --render`"


def test_every_record_tells_the_two_statuses_apart():
    for path, fm, body in ai.load():
        assert fm["decision_status"] in ai.DECISION_STATUSES, path.name
        assert set(fm["implementation_status"]) <= set(ai.IMPLEMENTATION_TAGS), path.name
        status = body.split("## Status", 1)[1].split("## ", 1)[0]
        assert "**Decision:**" in status and "**Implementation:**" in status, \
            f"{path.name}: the Status section must state the decision and the implementation apart"


def test_every_open_question_is_on_the_agenda():
    known = ai.agenda_ids()
    for path, fm, _ in ai.load():
        for q in fm["open_questions"]:
            assert q in known, f"{path.name}: {q} is not a review-agenda question"


def _sandbox(tmp_path):
    (tmp_path / "docs").mkdir()
    shutil.copytree(ai.ADR_DIR, tmp_path / "docs" / "adr")
    shutil.copy(ai.AGENDA, tmp_path / "docs" / "REVIEW_AGENDA.md")
    (tmp_path / "docs" / "decisions-index.md").write_text(ai.render_md(), encoding="utf-8")
    saved = (ai.ROOT, ai.ADR_DIR, ai.INDEX, ai.AGENDA)
    ai.ROOT, ai.ADR_DIR, ai.INDEX, ai.AGENDA = (tmp_path, tmp_path / "docs" / "adr",
                                               tmp_path / "docs" / "decisions-index.md",
                                               tmp_path / "docs" / "REVIEW_AGENDA.md")
    return saved


def _restore(saved):
    ai.ROOT, ai.ADR_DIR, ai.INDEX, ai.AGENDA = saved


def test_negative_a_gap_in_the_numbering_is_caught(tmp_path):
    saved = _sandbox(tmp_path)
    try:
        last = sorted(ai.ADR_DIR.glob("SBM-ADR-*.md"))[-1]
        text = last.read_text(encoding="utf-8").replace(last.stem, "SBM-ADR-0099")
        last.unlink()
        (ai.ADR_DIR / "SBM-ADR-0099.md").write_text(text, encoding="utf-8")
        problems = ai.check()
        assert any("without gaps" in p for p in problems), problems
    finally:
        _restore(saved)


def test_negative_a_record_that_runs_the_statuses_together_is_caught(tmp_path):
    saved = _sandbox(tmp_path)
    try:
        first = ai.ADR_DIR / "SBM-ADR-0001.md"
        text = first.read_text(encoding="utf-8").replace(
            "decision_status: accepted", "decision_status: specified; in reference")
        first.write_text(text, encoding="utf-8")
        problems = ai.check()
        assert any("decision_status" in p for p in problems), problems
    finally:
        _restore(saved)


def test_negative_a_hand_edited_index_is_caught(tmp_path):
    saved = _sandbox(tmp_path)
    try:
        ai.INDEX.write_text(ai.INDEX.read_text(encoding="utf-8") + "\n| 14 | a fourteenth row |\n",
                            encoding="utf-8")
        problems = ai.check()
        assert any("is stale" in p for p in problems), problems
    finally:
        _restore(saved)
