# SPDX-License-Identifier: MIT
"""DOC-03…DOC-06 (documentation completeness review) — the reading path holds.

The onboarding package is a set of links: the guide to the notes, the notes to
the figures, the agenda and the owning sections. A reading path is only as
good as its links, so every relative link and anchor in the active Markdown
must resolve (`doc_lint.scan_links`), the README must list every explainer it
says it lists, and the guide must not restate the numbers the generated files
own. These tests show the link gate firing rather than assume it does.
"""
import importlib.util
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _doc_lint(root=ROOT):
    spec = importlib.util.spec_from_file_location("doc_lint_links", ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = root
    return mod


def test_every_link_in_the_reading_path_resolves():
    dl = _doc_lint()
    files = {p.relative_to(ROOT).as_posix() for p in dl.link_files()}
    for note in ("docs/REVIEWER_GUIDE.md", "docs/architecture-identity-trust.md",
                 "docs/message-lifecycle.md", "docs/decisions-index.md", "README.md"):
        assert note in files, note
    assert dl.scan_links() == []


def test_a_broken_file_or_anchor_is_caught(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "target.md").write_text("# Title\n\n## A heading `with_code`\n")
    page = tmp_path / "docs" / "page.md"
    page.write_text("[ok](target.md#a-heading-with_code) [gone](missing.md) "
                    "[no anchor](target.md#nowhere) [self](#title-here)\n\n# Title here\n")
    dl = _doc_lint(tmp_path)
    problems = {(t, why) for _, t, why in dl.scan_links([page])}
    assert problems == {("missing.md", "no such file"),
                        ("target.md#nowhere", "no such heading or anchor")}


def test_duplicate_headings_and_code_are_handled(tmp_path):
    page = tmp_path / "page.md"
    page.write_text("# Notes\n\n## Notes\n\n```\n[not a link](nowhere.md)\n# not a heading\n```\n"
                    "`[also not](nowhere.md)` [external](https://example.org/x.md)\n")
    dl = _doc_lint(tmp_path)
    assert {"notes", "notes-1"} <= dl.anchors_of(page)
    assert "not-a-heading" not in dl.anchors_of(page)
    assert dl.scan_links([page]) == []


def test_the_readme_lists_every_explainer():
    """The README's companion table claims to list the explainers; an
    explainer it omits is one the review found readers never reach."""
    manifest = json.loads((ROOT / "versions.json").read_text())
    historical = set(manifest["prose_sweep_historical"]["paths"])
    generated = {"docs/lint-catalogue.md", "docs/rule-ownership.md"}
    readme = (ROOT / "README.md").read_text()
    for p in sorted((ROOT / "docs").glob("*.md")):
        rel = p.relative_to(ROOT).as_posix()
        if rel in historical or rel in generated:
            continue
        assert f"]({rel})" in readme, f"README does not list {rel}"


def test_the_guide_restates_no_version_or_count():
    """Counts and versions are quoted from the generated files, never
    restated: a guide that says '2069 checks' is wrong by the next commit."""
    guide = (ROOT / "docs" / "REVIEWER_GUIDE.md").read_text()
    guide = re.sub(r"<!--.*?-->", "", guide, flags=re.S)   # the licence header
    body = re.sub(r"\([^)]*\)", "", guide)             # link targets and asides
    assert not re.findall(r"\bv?\d+\.\d+(?:\.\d+)?\b", body)
    assert not re.findall(r"\b\d{3,}\b", body)
