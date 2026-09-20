# SPDX-License-Identifier: MIT
"""R-01 — the published version matrix is frozen to one manifest.

`test_version_matrix_consistent` is the gate: every binding declared in
`versions.json` (schema const, schema title, CDDL body, sample projection,
OpenAPI info.version, README table cell, TS change-history top row) MUST equal its
dimension's value. It fails when the manifest OR any single artefact drifts
independently.

The negative tests reproduce the EXACT former defect R-01 found — README /
schema-title publishing evidence `2.0` while the authoritative const is `2.1` —
and prove the checker rejects that drift (a positive matrix is never sufficient
evidence to close a finding).
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import version_manifest as vm  # noqa: E402


def test_version_matrix_consistent():
    manifest = vm.load_manifest()
    rows, mismatches = vm.check(ROOT, manifest)
    assert rows, "no bindings resolved — manifest empty or unreadable"
    assert not mismatches, (
        "version bindings disagree with versions.json:\n"
        + "\n".join(f"  {d}: {f} has {o!r}, manifest says {e!r}"
                    for d, f, o, e in mismatches)
    )


def test_manifest_covers_the_required_artefacts():
    """R-01 acceptance: schema title, const, sample and README all bound."""
    manifest = vm.load_manifest()
    ev = manifest["dimensions"]["evidence"]["bindings"]
    files = {b["file"] for b in ev}
    kinds = {(b["file"], b.get("path"), b["kind"]) for b in ev}
    assert any("schema.json" in f and k == "json" and p == "properties.version.const"
               for f, p, k in kinds), "no schema const binding for evidence"
    assert any(b.get("path") == "title" for b in ev), "no schema title binding"
    assert any("samples/" in f for f in files), "no sample binding for evidence"
    assert "README.md" in files, "no README binding for evidence"


def test_negative_readme_evidence_drift_is_rejected():
    """The reproduced defect: README publishes evidence 2.0 vs const 2.1."""
    doctored_readme = "| Evidence objects (SE/DE/NDE/RE/CE/EP) | **2.0** (octet-authoritative) |"
    binding = {"kind": "text",
               "pattern": r"Evidence objects[^|]*\|\s*\*{0,2}(\d+\.\d+)"}
    observed = vm.extract_text(binding, doctored_readme)
    expected = vm.load_manifest()["dimensions"]["evidence"]["value"]
    assert observed == "2.0"
    assert observed != expected, (
        "checker would MISS a README cell publishing the stale evidence version"
    )


def test_negative_schema_title_drift_is_rejected():
    """A schema title left at (v2.0) while const/manifest say 2.1."""
    doctored_title = "evidence-se (v2.0)"
    binding = {"kind": "json", "path": "title", "pattern": r"\(v(\d+\.\d+)\)"}
    observed = vm.extract_json(binding, {"title": doctored_title})
    expected = vm.load_manifest()["dimensions"]["evidence"]["value"]
    assert observed == "2.0"
    assert observed != expected


def test_negative_manifest_drift_is_rejected():
    """Drift on the OTHER side: bump the manifest alone, artefacts unchanged."""
    manifest = vm.load_manifest()
    manifest["dimensions"]["evidence"]["value"] = "9.9"
    _, mismatches = vm.check(ROOT, manifest)
    assert any(d == "evidence" for d, *_ in mismatches), (
        "changing only the manifest value must break the matrix"
    )
