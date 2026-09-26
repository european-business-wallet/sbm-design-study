# SPDX-License-Identifier: MIT
"""The gates that close PR-01, PR-02 and PR-04 — one defect in three places.

All three were prose describing the repository, sitting where no gate looked:
`LICENSE` is not Markdown, a version manifest's notes are not prose to a
Markdown scanner, and a file list is not a link. Fixed one at a time, the class
stays open and the next export reopens it.

Two checks close it. `doc_lint.scan_licence_files` resolves every path the
licence's scope sections name against the repository the file ships in.
`version_manifest.sweep_repository_prose` reads the licence, the README and the
manifest's own notes for a repository URL that is not this repository's, and
for the internal identifier families the source-prose cleanup removed from
text. Against the export at r6 the two report, between them, exactly the three
findings the publication review raised.

These tests drive both on copies, so each rule is shown to fire.
"""
import importlib.util
import json
import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import version_manifest as vm  # noqa: E402


def _doc_lint():
    spec = importlib.util.spec_from_file_location("doc_lint_pub", ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def repo(tmp_path):
    """A miniature repository: the licence, the README, the manifest, and a
    placeholder for every path the licence's scope sections name. The
    placeholders are DERIVED from the licence rather than listed here, so the
    fixture follows the file it tests — a copy of the licence that lists a
    different set of files (an export's) still gets a fixture that matches it."""
    (tmp_path / "docs").mkdir()
    shutil.copy(ROOT / "LICENSE", tmp_path / "LICENSE")
    shutil.copy(ROOT / "README.md", tmp_path / "README.md")
    for _, token in _doc_lint().licence_scope_paths(tmp_path / "LICENSE"):
        target = tmp_path / token.rstrip("/")
        if token.endswith("/") or (ROOT / token).is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("placeholder\n")
    manifest = json.loads((ROOT / "versions.json").read_text())
    return tmp_path, manifest


# --- the licence's file list ----------------------------------------------

def test_the_licence_lists_only_files_this_repository_has():
    assert _doc_lint().scan_licence_files() == []


def test_a_listed_file_the_repository_does_not_have_is_caught(repo):
    root, _ = repo
    assert _doc_lint().scan_licence_files(root) == []
    # the victim is taken from the licence itself, not named here: whichever
    # listed plain file comes first, in this repository or in an export's copy
    listed = [t for _, t in _doc_lint().licence_scope_paths(root / "LICENSE")
              if (root / t).is_file()]
    (root / listed[0]).unlink()          # what an export does to a file that does not travel
    missing = _doc_lint().scan_licence_files(root)
    assert [t for t, _ in missing] == [listed[0]]


def test_the_list_covers_directories_and_bare_names(repo):
    root, _ = repo
    named = [t for _, t in _doc_lint().licence_scope_paths(root / "LICENSE")]
    assert "scripts/" in named and "Makefile" in named, named
    shutil.rmtree(root / "schemas")
    (root / "Makefile").unlink()
    missing = {t for t, _ in _doc_lint().scan_licence_files(root)}
    assert {"schemas/", "Makefile"} <= missing


# --- the repository-describing prose --------------------------------------

def test_the_repository_prose_is_clean_here():
    manifest = json.loads((ROOT / "versions.json").read_text())
    assert vm.sweep_repository_prose(ROOT, manifest) == []
    assert manifest["repository"]["url"], "the shipping repository must be declared"


def test_a_foreign_repository_url_is_caught(repo):
    root, manifest = repo
    manifest = dict(manifest, repository={"url": "https://github.com/paolo-de-rosa/sbm-design-study",
                                          "related": []})
    kinds = {k for _, k, _ in vm.sweep_repository_prose(root, manifest)}
    assert {"foreign-repository-url", "attribution-names-another-repository"} <= kinds, \
        "an export shipping the source's attribution must fail"


def test_a_related_repository_is_allowed(repo):
    root, manifest = repo
    declared = manifest["repository"]["url"]
    manifest = dict(manifest, repository={"url": "https://github.com/paolo-de-rosa/sbm-design-study",
                                          "related": [declared]})
    kinds = {k for _, k, _ in vm.sweep_repository_prose(root, manifest)}
    assert "foreign-repository-url" not in kinds, \
        "an export may name the source it was built from, once that is declared"
    assert "attribution-names-another-repository" in kinds, \
        "but its own attribution must still name itself"


def test_an_internal_identifier_in_a_manifest_note_is_caught(repo):
    root, manifest = repo
    manifest = json.loads(json.dumps(manifest))
    manifest["dimensions"]["evidence"]["note"] += " Added by R12-04 (round 12)."
    found = [(w, d) for w, k, d in vm.sweep_repository_prose(root, manifest)
             if k == "internal-identifier"]
    assert found == [("versions.json evidence.note", "R12-04")]


def test_the_repository_blocks_own_prose_is_swept(repo):
    """The block that declares which repository this is is where prose about
    the repository accumulates, and it was outside the sweep that exists for
    that prose — the same blind spot as PR-01/PR-02/PR-04, one level in."""
    root, manifest = repo
    manifest = json.loads(json.dumps(manifest))
    manifest["repository"]["note"] += " Mirrored at https://github.com/someone-else/a-fork."
    kinds = {k for _, k, _ in vm.sweep_repository_prose(root, manifest)}
    assert "foreign-repository-url" in kinds
    labels = [w for w, _ in [(l, t) for l, t in vm.repository_prose_sources(root, manifest)]]
    assert "versions.json repository.note" in labels


def test_every_related_repository_is_accepted_and_a_foreign_one_refused(repo):
    """`related` names the spellings of this repository that are not foreign —
    here, `sbm-spec`, this repository under a rename. Every URL it names is
    accepted; a URL it does not name still fails. The list is read from the
    manifest, not restated here, so a manifest that declares no related
    repository (an export's) is tested on the same rule with an empty list."""
    root, manifest = repo
    related = list(manifest["repository"].get("related") or [])
    manifest = json.loads(json.dumps(manifest))
    for url in related:
        manifest["dimensions"]["evidence"]["note"] += f" See {url} for the register."
    kinds = {k for _, k, _ in vm.sweep_repository_prose(root, manifest)}
    assert "foreign-repository-url" not in kinds
    manifest["dimensions"]["evidence"]["note"] += " And https://github.com/someone-else/a-fork."
    kinds = {k for _, k, _ in vm.sweep_repository_prose(root, manifest)}
    assert "foreign-repository-url" in kinds, "a genuinely foreign URL must still fail"


def test_the_rules_own_names_and_agenda_identifiers_are_not_swept(repo):
    """LINT-* names the conformance rules; A1-A10 name the open questions."""
    root, manifest = repo
    manifest = json.loads(json.dumps(manifest))
    manifest["dimensions"]["evidence"]["note"] += " Checked by LINT-BND-40; see agenda A10 and G4."
    assert [k for _, k, _ in vm.sweep_repository_prose(root, manifest)] == []
