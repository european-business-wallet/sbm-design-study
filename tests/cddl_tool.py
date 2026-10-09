# SPDX-License-Identifier: MIT
"""The one guard for tests that need the Rust `cddl` tool.

Not a test module: `requires_cddl` is the marker, and `tests/test_cddl_guard.py`
is the gate that a module needing the tool carries it.

**Why one marker and not a `skipif` per module.** Three modules reached
`cddl_check._check_body` with no guard at all, so on a machine without the tool
six tests FAILED where the convention is to skip — six failures that a session
verifying a change cannot tell apart, at a glance, from a regression. Two other
modules did guard themselves, with two hand-written copies of
`skipif(shutil.which("cddl") is None)`; a sixth module would have been written
without either.

**Why a probe and not `shutil.which`.** `which` answers a question about PATH,
and the failure that produced this file was not about PATH: the tool was
installed, found, and killed by the kernel on exec — an x86_64 build on an
arm64 machine. A `which`-only guard passes there and the six tests fail exactly
as before. `cddl_probe.unusable()` runs the tool once and reports what happened.

**Why it does not skip under CI.** `scripts/cddl_check.py` fails closed when the
tool is missing and `CI` is set, because the CDDL non-divergence guarantee is
the one CI owes (N4/D7); `.github/workflows/ci.yml` installs the tool for that
reason. A marker that skipped there would have quietly moved five modules out
of the guarantee. So locally the tool is OPTIONAL and these tests skip with the
reason; under `CI` they run, and fail loudly if it cannot.
"""
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cddl_probe  # noqa: E402

#: None when the tool runs here, else why it does not.
UNUSABLE = cddl_probe.unusable()

#: True where a skip is not allowed: the tool is a hard requirement in CI.
STRICT = bool(os.environ.get("CI"))

requires_cddl = pytest.mark.skipif(
    UNUSABLE is not None and not STRICT,
    reason=f"the Rust `cddl` tool is optional locally — {UNUSABLE}")
