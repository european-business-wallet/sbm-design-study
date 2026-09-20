# SPDX-License-Identifier: MIT
"""F-01 (reopened, closed this batch) — the artefact model has no seal-container residue.

After M4 the wire form is the evidence artefact [cose-sign1, qualified-timestamp]
and the projection carries no seal field; the flat {fields, seal} doc is purely
lint_cli.reconstruct's internal convention. The former defect: the TS (and
schemas/README/explainers) still described the superseded in-object `seal`
container, ICS rows claimed schema-verifiability of a field no schema has, and
orphaned Seal/QualifiedTimestamp $defs survived.

These tests are the regression guard: the doc-lint negative fixture reproduces the
former prose and proves it is now flagged; the orphan $defs stay deleted; the four
sealed-document endpoints keep declaring BOTH media types (the missing
content-negotiation regression the finding required).
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_doc_lint_flags_the_seal_container_model():
    """Negative fixture: the exact former wording must now be rejected."""
    probe = ROOT / "docs" / "_seal_probe.md"
    probe.write_text(
        "The seal is computed over the object minus the `seal` container; "
        "its qualified timestamp imprints SHA-256(seal.cose_b64).\n",
        encoding="utf-8")
    try:
        r = subprocess.run([sys.executable, "scripts/doc_lint.py"], cwd=ROOT,
                           capture_output=True, text=True)
        assert r.returncode == 2, r.stdout + r.stderr
        assert "_seal_probe.md" in r.stdout
    finally:
        probe.unlink(missing_ok=True)


def test_live_documents_carry_no_seal_container_prose():
    r = subprocess.run([sys.executable, "scripts/doc_lint.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_orphan_seal_defs_are_gone():
    common = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    defs = set(common["$defs"])
    assert not defs & {"Seal", "QualifiedTimestamp", "CoseB64"}, (
        "the orphaned in-object seal-container $defs returned")
    # and no projection schema grew a seal property
    for p in sorted((ROOT / "schemas").glob("evidence-*.schema.json")):
        assert '"seal"' not in p.read_text(), f"{p.name} has a seal property"


def test_sealed_document_endpoints_declare_both_media_types():
    """The M4 content-negotiation promise, pinned (the missing regression)."""
    import yaml
    spec = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text())
    # X-13: the evidence endpoint is a POINTER ONLY (302, no 200) — content
    # negotiation applies to the endpoints that actually SERVE sealed bytes.
    endpoints = ["/.well-known/bw/med/{uid}",
                 "/.well-known/bw/org/{uid}",
                 "/.well-known/bw/member/{uid}/{mid}"]
    for ep in endpoints:
        ok = spec["paths"][ep]["get"]["responses"]["200"]
        content = ok.get("content") or {}
        assert "application/cbor" in content, f"{ep} lost application/cbor"
        assert "application/json" in content, f"{ep} lost application/json"


def test_stage1_registry_comment_matches_the_wire():
    """The registry is signed over dCBOR (test-pinned elsewhere); its comment
    must say so — not JCS."""
    reg = json.loads((ROOT / "samples" / "registry.stage1.demo.json").read_text())
    assert "deterministic-CBOR" in reg["_comment"]
    assert "JCS" not in reg["_comment"]
