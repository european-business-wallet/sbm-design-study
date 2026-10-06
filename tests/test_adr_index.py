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
import copy
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


# ---------------------------------------------------------------------------
# R3 — a closed question is not an open one, and a superseded record has no plan
#
# `adr_index.py --check` validated SHAPE: that an `open_questions` id is a real
# agenda row. A row stays on the agenda after it closes, so three weeks after
# SBM-ADR-0015 withdrew A6 and answered A9, three records still named them —
# `SBM-ADR-0004` (superseded, with a `planned` tag and both ids), `SBM-ADR-0007`
# (accepted, A9) and `SBM-ADR-0002` (accepted, a plan resting on A6) — and
# `docs/decisions-index.md` rendered them as current plans and open questions.
# ---------------------------------------------------------------------------

def test_the_agenda_closure_markers_are_found():
    closed = ai.closed_agenda_ids()
    assert {"A6", "A9"} <= closed, closed
    assert "A1" not in closed, "A1 is open and must not be read as closed"
    assert closed <= ai.agenda_ids(), "a closed id is still a row on the agenda"


def test_no_record_names_a_closed_question_as_open():
    for _, fm, _ in ai.load():
        assert not (set(fm.get("open_questions") or []) & ai.closed_agenda_ids()), fm["id"]


def test_a_closed_question_in_open_questions_is_caught():
    """Driven on a copy of the real front matter: the defect as it shipped."""
    records = ai.load()
    victim = next(r for r in records if r[1]["id"] == "SBM-ADR-0007")
    broken = copy.deepcopy(victim[1])
    broken["open_questions"] = ["A9"]
    problems = ai.check([(victim[0], broken, victim[2])])
    assert any("A9" in p and "records as closed" in p for p in problems), problems


def test_a_superseded_record_with_a_planned_tag_is_caught():
    records = ai.load()
    victim = next(r for r in records if r[1]["id"] == "SBM-ADR-0004")
    assert victim[1]["decision_status"] == "superseded"
    assert "planned" not in victim[1]["implementation_status"]
    broken = copy.deepcopy(victim[1])
    broken["implementation_status"] = list(broken["implementation_status"]) + ["planned"]
    problems = ai.check([(victim[0], broken, victim[2])])
    assert any("superseded record carries the `planned` tag" in p for p in problems), problems


def test_a_plan_resting_on_a_closed_question_is_caught():
    records = ai.load()
    victim = next(r for r in records if r[1]["id"] == "SBM-ADR-0002")
    broken = copy.deepcopy(victim[1])
    broken["implementation"] = ("specified; admission for messaging providers is "
                                "planned, not implemented ([A6](../REVIEW_AGENDA.md))")
    problems = ai.check([(victim[0], broken, victim[2])])
    assert any("same clause as A6" in p for p in problems), problems


def test_a_closed_question_named_as_closed_is_not_a_finding():
    """The rule must not forbid SAYING that a question closed. `SBM-ADR-0002`
    cites A6 to explain why its enum is now a decision, and separately records
    that an operated register remains planned — two sentences, no finding."""
    records = ai.load()
    victim = next(r for r in records if r[1]["id"] == "SBM-ADR-0002")
    assert "A6" in victim[1]["implementation"] and "planned" in victim[1]["implementation"]
    assert ai.check([victim]) == [] or all(
        "A6" not in p for p in ai.check([victim])), ai.check([victim])
