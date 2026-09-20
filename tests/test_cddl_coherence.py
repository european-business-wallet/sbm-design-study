# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: 2026 Secure Business Messaging contributors
"""CDDL / JSON-Schema non-divergence (M4/C3, the CDDL cycle).

The samples must be CDDL-valid (via scripts/cddl_check.py), and a body that is
schema-INVALID must also be CDDL-invalid — otherwise the two descriptions have
drifted. Skips when the `cddl` tool is absent."""
import importlib.util
import sys
import pathlib
import shutil
import subprocess
import tempfile

import cbor2
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("cddl") is None, reason="cddl tool not installed")


def _lint_cli():
    spec = importlib.util.spec_from_file_location("lint_cli", ROOT / "scripts" / "lint_cli.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_every_sample_is_cddl_valid():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "cddl_check.py")], capture_output=True, text=True)
    if r.returncode == 3:
        pytest.skip("cddl tool not installed")
    assert r.returncode == 0, r.stdout + r.stderr


def _cddl_valid(body_cbor: bytes, rule: str) -> bool:
    cddl = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    with tempfile.NamedTemporaryFile("w", suffix=".cddl", delete=False) as cf:
        cf.write(f"_root = {rule}\n" + cddl)
        cp = cf.name
    with tempfile.NamedTemporaryFile(suffix=".cbor", delete=False) as bf:
        bf.write(body_cbor)
        bp = bf.name
    r = subprocess.run(["cddl", "--ci", "validate", "--cddl", cp, "--cbor", bp],
                       capture_output=True, text=True)
    return r.returncode == 0


def test_a_schema_invalid_body_is_also_cddl_invalid():
    """Non-divergence: a body the JSON Schema rejects (here, a bad `event` const)
    must also fail the CDDL — the two cannot describe different shapes."""
    dcbor = _lint_cli().dcbor
    se = {"type": "SE-v1", "version": "2.0", "profile": "pilot", "message_id": "m",
          "event": "A.1-SubmissionAcceptance"}
    assert not _cddl_valid(dcbor(se), "se-body")            # incomplete SE -> CDDL-invalid
    se_bad = dict(se, event="NOT-A-REAL-EVENT")
    assert not _cddl_valid(dcbor(se_bad), "se-body")        # bad event const -> CDDL-invalid
