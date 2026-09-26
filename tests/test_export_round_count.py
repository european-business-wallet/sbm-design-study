# SPDX-License-Identifier: MIT
"""The export's round count is written from the source, not carried between editions.

`docs/review-rounds.json` exists only in the design-study export. The export's
CHANGELOG records the history of the artefacts rather than of the review
process, so the count cannot be derived from its headings the way the source
derives it — it is declared. Until 26 September 2026 it was also *carried*: the
rebuild listed it among the export's own files, so the number survived every
rebuild untouched and nothing tied it to the source it describes. An export
rebuilt from a later source could ship an earlier number, and no check would
notice — which is the one failure mode the whole counting apparatus exists to
eliminate, reproduced inside it.

It is now written on each rebuild from the source's generated
`docs/project-counts.json`, with the source revision recorded beside it. These
tests bind the two files to each other where they both exist, so a hand-edit of
either is caught in the repository that ships them.

In the source there is no such file and every check here is inert by
construction — which is why the fixtures below drive the same rules on a
miniature export, rather than asserting nothing and passing.
"""
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUNDS = ROOT / "docs" / "review-rounds.json"
COUNTS = ROOT / "docs" / "project-counts.json"
REV = r"^[0-9a-f]{7,40}$"


def _check(rounds, counts):
    """[(problem)] — the rules, applied to two already-loaded documents."""
    import re
    out = []
    if "completed_rounds" not in rounds:
        out.append("review-rounds.json declares no completed_rounds")
        return out
    if not re.match(REV, str(rounds.get("source_revision", ""))):
        out.append("review-rounds.json does not record the source revision it was "
                   "written from — it was carried, not written")
    if rounds["completed_rounds"] != counts.get("rounds"):
        out.append(f"the declared round count {rounds['completed_rounds']} is not the "
                   f"generated one {counts.get('rounds')} — one of the two was edited "
                   "by hand, or the export was rebuilt without regenerating the counts")
    return out


@pytest.mark.skipif(not ROUNDS.exists(), reason="no declared round count: this is the source")
def test_the_declared_round_count_matches_the_generated_one():
    assert _check(json.loads(ROUNDS.read_text()), json.loads(COUNTS.read_text())) == []


def test_a_carried_count_is_caught():
    """The before-state: a file with no source revision is one that was carried
    from the previous edition."""
    problems = _check({"completed_rounds": 12}, {"rounds": 12})
    assert any("carried, not written" in p for p in problems), problems


def test_a_stale_count_is_caught():
    """An export rebuilt from a source that has since run more rounds."""
    problems = _check({"completed_rounds": 12, "source_revision": "c865fbd"}, {"rounds": 13})
    assert any("not the generated one" in p for p in problems), problems


def test_a_matching_pair_passes():
    assert _check({"completed_rounds": 12, "source_revision": "c865fbd"}, {"rounds": 12}) == []


def test_the_source_derives_its_own_count_and_declares_nothing():
    """In the source the count comes from the CHANGELOG's round headings. If
    this file ever appears here, the export's mechanism has leaked into the
    source and the two would drift in the direction this suite cannot see."""
    if ROUNDS.exists():
        pytest.skip("this is the export")
    counts = json.loads(COUNTS.read_text())
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    import re
    heads = [int(h) for h in re.findall(r"^## Design review round (\d+)", changelog, re.M)]
    assert counts["rounds"] == (max(heads) if heads else 1)
