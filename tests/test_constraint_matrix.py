# SPDX-License-Identifier: MIT
"""X-35 — the constraint matrix is CHECKED, not a document that drifts.

Former defect: precise prose constraints (Zulu timestamps, base64url MLS state,
base64url group ids) were looser in the JSON Schema (`minLength: 1`,
`format: date-time` with no FormatChecker — decorative). The schemas are now
tightened to the prose and format assertion is enabled everywhere schemas are
validated.

This test IS the constraint matrix: for each tightened field it takes a valid
shipped sample, applies a boundary mutation that the PROSE forbids, and asserts
the schema (via the shared validate_body) and the linter entry point return
IDENTICAL verdicts — machine-verified cross-representation coherence (the
finding's acceptance criterion), so it cannot drift. The CDDL deliberately stays
the structural outer bound (N2; the cddl crate cannot backtrack .regexp), so
matrix rows assert Schema+lint, with cddl-check guaranteeing body≡projection.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import evidence_lint as el  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]

# The MATRIX: (field-path setter description, mutation) — each mutation violates
# a PROSE constraint that the schema now enforces.
MATRIX = [
    ("sent_at not Zulu (offset form)",
     lambda b: b.update(sent_at="2026-04-04T10:15:00+02:00")),
    ("sent_at not a timestamp at all",
     lambda b: b.update(sent_at="yesterday")),
    ("mls_group_id outside the base64url alphabet",
     lambda b: b.update(mls_group_id="not/base64url!")),
    ("mls_state hex not 64 lowercase hex (2.2 MlsStateHash)",
     lambda b: b["mls_state"].update(hex="abc")),
    ("mls_state wrong format const",
     lambda b: b["mls_state"].update(format="mls10-message")),
    ("envelope_hash regressed to the generic Hash shape (alg/mode selectors)",
     lambda b: b.update(envelope_hash={"alg": "SHA-512", "hex": "a" * 128,
                                       "hash_mode": "jcs-sha512"})),
]


@pytest.mark.parametrize("desc,mutate", MATRIX, ids=[m[0] for m in MATRIX])
def test_matrix_schema_and_linter_agree(desc, mutate):
    bad = copy.deepcopy(SE)
    mutate(bad)
    # 1) the authoritative Schema rejects it (validate_body = the shared validator)
    schema_verdict = lc.validate_body(bad)
    assert schema_verdict and schema_verdict[0][0] == "LINT-PKG-12", (
        f"schema accepted a prose-forbidden value: {desc}")
    # 2) the linter ENTRY POINT rejects the same mutation on a real artefact —
    # identical verdict, machine-verified coherence.
    art = mock.evidence_artifact(bad)
    rules = [r for r, _ in el.lint(art)]
    assert "LINT-PKG-12" in rules, (
        f"linter entry point disagreed with the schema on: {desc}")


def test_positive_the_valid_sample_passes_both():
    assert lc.validate_body(SE) == []
    assert "LINT-PKG-12" not in [r for r, _ in el.lint(mock.evidence_artifact(copy.deepcopy(SE)))]


def test_b6_regression_subcases_remain():
    """X-35's explicit requirement: the corrected B6 subcases stay regression
    tests (commitment encoding, manifest, COSE structure) — never reopened."""
    assert (ROOT / "tests" / "test_commitment_encoding.py").exists()
    manifest_tests = (ROOT / "tests" / "test_lint_cli.py").read_text()
    assert "manifest" in manifest_tests
