# SPDX-License-Identifier: MIT
"""CI workflow smoke test (W6).

Keeps the spec §9.4 'runs in CI' claim honest: the workflow must exist, parse,
and actually invoke the test / schema-smoke / lint make targets.
"""
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_exists():
    assert CI.is_file(), "the §9.4 'runs in CI' claim requires .github/workflows/ci.yml"


def test_ci_workflow_runs_the_conformance_targets():
    try:
        import yaml
    except Exception:
        pytest.skip("pyyaml not installed")
    spec = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert "jobs" in spec and spec["jobs"], "workflow has no jobs"
    runs = " ".join(
        str(step.get("run", ""))
        for job in spec["jobs"].values()
        for step in job.get("steps", []))
    # CI must be the exact equivalent of 'make conformance' (P3): the test job
    # runs test/schema-smoke/lint/lint-demo; the reuse job covers the REUSE gate.
    for target in ("make test", "make schema-smoke", "make lint", "make lint-demo"):
        assert target in runs, f"CI must run '{target}'"
    assert "reuse lint" in runs, "CI must run the REUSE gate (conformance parity)"
    assert "pip install -r scripts/requirements.txt" in runs
