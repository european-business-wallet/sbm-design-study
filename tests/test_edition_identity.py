# SPDX-License-Identifier: MIT
"""The edition a snapshot declares is the edition it is.

The design-study export tells a reviewer which edition to cite, in its README,
and heads its CHANGELOG with the same identity. Both were declared by hand, in
files the rebuild carries forward from the previous edition, so they stayed at
`r9` while the commit was tagged `r16` — nineteen files further on. A reviewer
following the citation instruction named the wrong text, and nothing in a green
suite disagreed.

The rebuild now writes the identity from the edition it is building and records
it in `docs/review-rounds.json`, beside the source revision it already wrote.
This checks that the three agree.

**The tag is checked only when there is one, and that is not a weakening.** The
tag is cut after the commit, and the rebuild writes the identity into files that
are committed before it exists, so a check that demanded a tag would fail on
every tree at the moment the export's own bar runs — which is the moment before
the tag is created. Where the commit does carry an exact tag, it must be the
edition declared; where it does not, the three declarations must still agree with
each other. Between them the two cases leave no state in which a published
snapshot can name an edition that is not its own.

In the source there is no `docs/review-rounds.json` and no edition to declare,
so the checks are inert here and the rules are driven on fixtures.
"""
import json
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUNDS = ROOT / "docs" / "review-rounds.json"

EDITION = re.compile(r"design-study-\d{4}-\d{2}-\d{2}-r\d+")
HEADING = re.compile(r"^## Current — \d{4}-\d{2}-\d{2}, edition (r\d+)", re.M)


def declared_editions(root):
    """{where: edition} — every place a snapshot states its own identity."""
    out = {}
    rounds = root / "docs" / "review-rounds.json"
    if rounds.exists():
        declared = json.loads(rounds.read_text(encoding="utf-8")).get("edition")
        if declared:
            out["docs/review-rounds.json"] = declared
    readme = root / "README.md"
    if readme.exists():
        found = EDITION.findall(readme.read_text(encoding="utf-8"))
        if found:
            out["README.md"] = found[0]
    changelog = root / "CHANGELOG.md"
    if changelog.exists():
        m = HEADING.search(changelog.read_text(encoding="utf-8"))
        if m:
            out["CHANGELOG.md heading"] = m.group(1)
    return out


def exact_tag(root):
    """The edition tag of THIS commit, or None when there is not one yet.

    Only authoritative when the tree is clean. During a rebuild the working tree
    carries the edition being built while HEAD still points at the edition
    before it, tag and all — so a check that trusted HEAD's tag would report the
    new identity as wrong, at exactly the moment the rebuild has just written it
    correctly. That is how this function failed the first time it ran in the
    export: the tree said r17, HEAD said r16, and the tree was right.
    """
    dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                           capture_output=True, text=True)
    if dirty.returncode != 0 or dirty.stdout.strip():
        return None
    r = subprocess.run(["git", "-C", str(root), "describe", "--tags", "--exact-match"],
                       capture_output=True, text=True)
    tag = r.stdout.strip()
    return tag if r.returncode == 0 and EDITION.fullmatch(tag) else None


def identity_problems(root):
    """[(where, problem)] — a declaration that disagrees with the others, or
    with the tag where one exists."""
    declared = declared_editions(root)
    if not declared:
        return []                       # not a snapshot: nothing declares an edition
    problems = []
    full = {w: e for w, e in declared.items() if EDITION.fullmatch(e)}
    short = {w: e for w, e in declared.items() if not EDITION.fullmatch(e)}
    editions = set(full.values()) | {f"suffix {e}" for e in short.values()}
    if full:
        base = sorted(full.values())[0]
        for where, e in full.items():
            if e != base:
                problems.append((where, f"declares {e} where {base} is declared elsewhere"))
        suffix = base.rsplit("-", 1)[1]
        for where, e in short.items():
            if e != suffix:
                problems.append((where, f"declares edition {e} where {base} is declared elsewhere"))
    elif len(editions) > 1:
        problems.append(("declarations", f"disagree with each other: {sorted(editions)}"))
    tag = exact_tag(root)
    if tag and full and tag != sorted(full.values())[0]:
        problems.append(("the tag", f"this commit is tagged {tag} and the snapshot declares "
                                    f"{sorted(full.values())[0]}"))
    return problems


@pytest.mark.skipif(not ROUNDS.exists(), reason="no declared edition: this is the source")
def test_the_snapshot_declares_one_edition():
    assert identity_problems(ROOT) == []


@pytest.mark.skipif(not ROUNDS.exists(), reason="this is the source")
def test_the_edition_is_recorded_where_the_rebuild_writes_it():
    """Recorded beside the source revision, so the identity is generated rather
    than carried — the round count's remedy, applied to the edition."""
    declared = json.loads(ROUNDS.read_text(encoding="utf-8"))
    assert EDITION.fullmatch(declared.get("edition", "")), declared
    assert declared.get("source_revision"), declared


def _snapshot(root, readme_ed, heading_ed, recorded_ed):
    (root / "docs").mkdir(exist_ok=True)
    (root / "README.md").write_text(
        f"- **Edition.** This snapshot is the review edition `{readme_ed}`, cut from\n",
        encoding="utf-8")
    (root / "CHANGELOG.md").write_text(
        f"# CHANGELOG\n\n## Current — 2026-09-26, edition {heading_ed}\n\nthings.\n",
        encoding="utf-8")
    (root / "docs" / "review-rounds.json").write_text(
        json.dumps({"completed_rounds": 12, "source_revision": "abc1234",
                    "edition": recorded_ed}), encoding="utf-8")
    return root


def test_a_snapshot_that_agrees_with_itself_passes(tmp_path):
    root = _snapshot(tmp_path, "design-study-2026-09-20-r17", "r17", "design-study-2026-09-20-r17")
    assert identity_problems(root) == []


def test_the_defect_as_it_shipped_is_caught(tmp_path):
    """README at r9, heading at r9, the snapshot built as r16."""
    root = _snapshot(tmp_path, "design-study-2026-09-20-r9", "r9", "design-study-2026-09-20-r16")
    problems = dict(identity_problems(root))
    assert "README.md" in problems and "CHANGELOG.md heading" in problems, problems


def test_one_stale_heading_is_enough(tmp_path):
    root = _snapshot(tmp_path, "design-study-2026-09-20-r17", "r16", "design-study-2026-09-20-r17")
    assert [w for w, _ in identity_problems(root)] == ["CHANGELOG.md heading"]


def test_a_tree_being_rebuilt_is_not_judged_by_the_previous_tag(tmp_path):
    """The case the export found: HEAD tagged r16, the files written for r17,
    the commit not yet made. The tag describes the edition before this one."""
    import subprocess as sp
    root = _snapshot(tmp_path, "design-study-2026-09-20-r17", "r17",
                     "design-study-2026-09-20-r17")
    sp.run(["git", "init", "-q", str(root)], check=True)
    sp.run(["git", "-C", str(root), "add", "-A"], check=True)
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@e", "PATH": "/usr/bin:/bin:/usr/local/bin"}
    sp.run(["git", "-C", str(root), "commit", "-q", "-m", "r16"], env=env, check=True)
    sp.run(["git", "-C", str(root), "tag", "design-study-2026-09-20-r16"], check=True)
    assert exact_tag(root) == "design-study-2026-09-20-r16"
    (root / "README.md").write_text(
        "- **Edition.** This snapshot is the review edition "
        "`design-study-2026-09-20-r17`, cut from\nand rebuilt.\n", encoding="utf-8")
    assert exact_tag(root) is None, "a dirty tree is mid-rebuild; its HEAD tag is the old one"
    assert identity_problems(root) == []


def test_a_tree_with_no_tag_yet_is_not_failed_for_that(tmp_path):
    """The rebuild writes the identity, the bar runs, the commit is made and
    only then is the tag cut. A check that demanded a tag would fail at every
    rebuild — at exactly the moment it is supposed to be useful."""
    root = _snapshot(tmp_path, "design-study-2026-09-20-r17", "r17", "design-study-2026-09-20-r17")
    assert exact_tag(root) is None
    assert identity_problems(root) == []
