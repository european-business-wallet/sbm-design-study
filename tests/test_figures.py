# SPDX-License-Identifier: MIT
"""DOC-01 / DOC-02 (documentation completeness review) — a figure is a current
claim, and so is a companion's version line.

The umbrella embedded an architecture figure routing ciphertext MSP-to-MSP and
a stack figure with a canonicalisation-centred digest, DNS discovery and MSP↔MSP transport,
while `make doc-lint` stayed green: it never read an SVG. Run on the base
revision (5686498), the figure scan added here reports all of them. These tests
drive it on a copy of the figures, so each rule is shown to fire, not assumed
to — and the version sweep, widened to every active companion, is shown to
catch the `evidence v2.0` it missed.
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


def _doc_lint(root):
    spec = importlib.util.spec_from_file_location("doc_lint_fig", ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT, mod.DIAGRAMS = root, root / "docs" / "diagrams"
    mod.EXPORTS = mod.DIAGRAMS / "exports.json"
    return mod


@pytest.fixture
def figures(tmp_path):
    shutil.copytree(ROOT / "docs" / "diagrams", tmp_path / "docs" / "diagrams")
    return tmp_path, _doc_lint(tmp_path)


def _add_png_text(path, keyword, text):
    """Insert a tEXt chunk before IEND — the shape a render tool would write."""
    import struct, zlib
    data = path.read_bytes()
    i = data.rindex(b"IEND") - 4
    body = keyword + b"\x00" + text
    chunk = struct.pack(">I", len(body)) + b"tEXt" + body + \
        struct.pack(">I", zlib.crc32(b"tEXt" + body) & 0xffffffff)
    path.write_bytes(data[:i] + chunk + data[i:])


def _edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, old
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_the_figures_on_the_tree_pass():
    assert _doc_lint(ROOT).scan_figures() == []


@pytest.mark.parametrize("label", [
    "content digest (JCS / SHA-256)", "DNS + DNSSEC · WebFinger", "MSP↔MSP, RDP APIs",
    "evidence metadata", "acceptance / quorum", "hashes &amp; metadata only",
    "single trust root for identity", "every credential, seal and evidence",
])
def test_every_stale_label_the_review_found_is_caught(figures, label):
    root, dl = figures
    _edit(root / "docs/diagrams/protocol-stack.svg", "WebFinger: optional locator only", label)
    problems = [p for _, p in dl.scan_figures()]
    assert any("in figure text" in p for p in problems), (label, problems)


def test_the_removed_mode_is_gone_from_the_figure_and_cannot_return(figures):
    """PT-01. This test used to assert the OPPOSITE — that the figure's
    `jcs-sha256 optional mode` annotation was allow-listed, the mode being real.
    The mode left the profile on 2026-09-25, so the annotation is a claim the
    protocol no longer supports, and the allowance became the defect."""
    root, dl = figures
    svg = root / "docs/diagrams/protocol-stack.svg"
    assert "jcs-sha" not in svg.read_text(), "the figure must not offer a removed mode"
    assert dl.scan_figures() == []
    _edit(svg, "raw-sha256 · manifest-sha256", "raw-sha256 · jcs-sha256 optional")
    assert any("jcs-sha" in m for _, m in dl.scan_figures()), \
        "a figure reintroducing the removed mode must fail the gate"


def test_a_mermaid_label_is_scanned_and_its_comments_are_not(figures):
    """The scan reads what a figure draws, not what its commentary recalls.

    The ignored half used to be supplied by the tree itself — a `%%` note about
    a relay between two providers that was never published. That made the probe
    depend on a stale token surviving in a shipped source, and SBM-ADR-0015
    removed the last one. Both halves are planted here instead: a probe builds
    its world.
    """
    root, dl = figures
    src = root / "docs/diagrams/federated-flow.mermaid"
    assert "MSP" not in src.read_text(), \
        "no shipped mermaid token names a provider role the profile withdrew"

    # In a comment: recalling a withdrawn design is not drawing a claim.
    _edit(src, "%% end figure", "%% end figure\n%% an MSP↔MSP relay was drawn here before, and was never published")
    planted = [p for _, p in dl.scan_figures() if "MSP" in p]
    # Editing a source without re-rendering is itself a finding, and the right
    # one; what must not appear is the comment's own words.
    assert planted == [], planted

    # In a label: the same words, drawn for a reader, are a claim.
    _edit(src, "RO->>RI: POST /relay/messages", "MO->>MI: relay MSP→MSP; RO->>RI: POST /relay/messages")
    assert any("MSP→MSP" in p for _, p in dl.scan_figures())


def test_a_figure_without_front_matter_is_reported(figures):
    root, dl = figures
    _edit(root / "docs/diagrams/architecture-four-corner.svg", "<!-- figure", "<!-- no longer a figure block")
    problems = dict(dl.scan_figures())
    assert "front matter missing" in problems["docs/diagrams/architecture-four-corner.svg"]


def test_a_historical_figure_is_kept_but_not_token_scanned(figures):
    root, dl = figures
    fig = root / "docs/diagrams/protocol-stack.svg"
    _edit(fig, "status: current", "status: historical")
    _edit(fig, "WebFinger: optional locator only", "DNS + DNSSEC · WebFinger")
    assert dl.scan_figures() == []


def test_a_source_edited_without_re_rendering_is_caught(figures):
    root, dl = figures
    _edit(root / "docs/diagrams/functional-stack-technology-neutral.svg",
          "Delivery providers relay, asynchronously", "Delivery providers relay")
    problems = [p for rel, p in dl.scan_figures()
                if rel == "docs/diagrams/functional-stack-technology-neutral.png"]
    assert problems and "changed since it was rendered" in problems[0]


def test_an_export_nobody_lists_is_caught(figures):
    root, dl = figures
    shutil.copy(root / "docs/diagrams/functional-stack-technology-neutral.png",
                root / "docs/diagrams/stray.png")
    assert ("docs/diagrams/stray.png",
            "a rendered figure no manifest entry names — list it in docs/diagrams/exports.json "
            "with its source") in dl.scan_figures()


def test_the_manifest_is_the_trees_own():
    """Recording must be a no-op on a fresh tree: the committed digests are the
    committed bytes."""
    doc = json.loads((ROOT / "docs/diagrams/exports.json").read_text())
    dl = _doc_lint(ROOT)
    for e in doc["exports"]:
        assert dl.sha256(ROOT / e["source"]) == e["source_sha256"], e["source"]
        assert dl.sha256(ROOT / e["export"]) == e["export_sha256"], e["export"]


def test_the_rdp_is_never_described_as_seeing_hashes_only():
    """DOC-01's shorthand: the RDP relays the ciphertext with the SE."""
    dl = _doc_lint(ROOT)
    assert any(p.search("| Metadata and content hashes only |") for p in dl.FORBIDDEN)
    assert dl.scan() == []


# --- the raster figures: covered through a source, or not covered ----------

def test_a_raster_export_must_be_rendered_from_something_this_gate_can_read(figures):
    """Probe 1 — a PNG with no scannable source. Nothing required one before:
    an entry could name a source of any format, and the text scan runs only
    when the export itself is an SVG, so a raster figure's words reached a
    reader through a file the rules never applied to."""
    root, dl = figures
    manifest = json.loads((root / "docs/diagrams/exports.json").read_text())
    entry = next(e for e in manifest["exports"] if e["export"].endswith(".png"))
    exports = {e["export"]: e for e in manifest["exports"]}
    assert dl.raster_source_problems(exports) == [], "the tree must start clean"

    orphan = dict(entry, source="docs/diagrams/four-corner-architecture-technology-neutral.png")
    problems = dl.raster_source_problems({entry["export"]: orphan})
    assert any("cannot read" in p for _, p in problems), problems

    renamed = dict(entry, source="docs/diagrams/protocol-stack.svg")
    problems = dl.raster_source_problems({entry["export"]: renamed})
    assert any("different stem" in p for _, p in problems), problems


def test_a_raster_export_carrying_figure_text_is_read_not_assumed(figures):
    """Probe 2 — a PNG whose own text chunks teach a removed mechanism. The
    gate used to be unable to say anything about a PNG's words; now it reads
    them, so "a PNG carries no scannable text" is established each run."""
    root, dl = figures
    png = root / "docs/diagrams/four-corner-architecture-technology-neutral.png"
    assert dl.png_text_chunks(png) == [], "the shipped rasters carry no text chunks"
    _add_png_text(png, b"Description", "content digest (JCS / SHA-256)".encode())
    assert "JCS" in " ".join(dl.png_text_chunks(png))
    manifest = json.loads((root / "docs/diagrams/exports.json").read_text())
    exports = {e["export"]: e for e in manifest["exports"]}
    problems = dl.raster_source_problems(exports)
    assert any("in figure text" in p for _, p in problems), problems


def test_the_source_digest_is_the_reproducible_staleness_check(figures):
    """A PNG older than its source is the defect; mtime cannot express it,
    because git records no mtimes and a fresh clone stamps every file at
    checkout. `source_sha256` states the same relation in bytes: edit the
    source without re-rendering and the gate fails, in any clone, at any age."""
    root, dl = figures
    svg = root / "docs/diagrams/four-corner-architecture-technology-neutral.svg"
    svg.write_text(svg.read_text(encoding="utf-8").replace("</svg>", "<!-- edited --></svg>"),
                   encoding="utf-8")
    problems = [p for _, p in dl.scan_figures()]
    assert any("changed since it was" in p for p in problems), problems


def test_the_coverage_report_counts_sources_not_files(figures):
    root, dl = figures
    sources, rasters = dl.figure_coverage()
    diagrams = root / "docs/diagrams"
    listed = {e["export"] for e in json.loads((diagrams / "exports.json").read_text())["exports"]}
    scannable = [p for p in diagrams.iterdir() if p.suffix in dl.SCANNABLE]
    # A generated SVG is covered by its own source's scan and its digests, so it
    # is not counted twice; a raster is not counted as a source at all.
    assert sources == len([p for p in scannable
                           if p.relative_to(root).as_posix() not in listed])
    assert rasters == len(list(diagrams.glob("*.png"))) > 0
    assert sources < len(scannable), "the generated exports must not inflate the count"


# --- DOC-02: the version sweep covers every active companion ---------------

def test_the_sweep_reads_every_active_companion_and_no_historical_record():
    manifest = json.loads((ROOT / "versions.json").read_text())
    files = vm.prose_sweep_files(ROOT, manifest)
    active = {f"docs/{p.name}" for p in (ROOT / "docs").glob("*.md")} - \
        set(manifest["prose_sweep_historical"]["paths"])
    assert active <= set(files) and "README.md" in files
    assert not set(manifest["prose_sweep_historical"]["paths"]) & set(files)


def test_the_sweep_catches_evidence_v2_0_in_a_companion(tmp_path):
    manifest = json.loads((ROOT / "versions.json").read_text())
    (tmp_path / "docs").mkdir()
    current = manifest["dimensions"]["evidence"]["value"]   # derived: a pinned
    # number here would make this fixture stale at the next bump, which is the
    # very defect DOC-02 found in the companions.
    (tmp_path / "README.md").write_text(f"current: evidence {current}\n")
    (tmp_path / "docs" / "example.md").write_text("Applies to: evidence v2.0\n")
    # the record that must be skipped is whichever the manifest declares first
    # under docs/, not a name pinned here: an export's manifest declares only
    # the records that travel, and this test must hold there too
    record = next(p for p in manifest["prose_sweep_historical"]["paths"]
                  if p.startswith("docs/") and "/" not in p[len("docs/"):])
    (tmp_path / record).write_text("at the time, evidence v2.0\n")
    found = vm.sweep_active_prose(tmp_path, manifest)
    assert [(rel, tok) for rel, _, tok in found] == [("docs/example.md", "evidence v2.0")]
