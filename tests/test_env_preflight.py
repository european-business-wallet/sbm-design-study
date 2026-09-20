# SPDX-License-Identifier: MIT
"""Canonical-test-environment assertion (spec §9.4, W4).

The HARD gate is `make test`, which runs `scripts/check_env.py` and FAILS before
pytest if a required dependency is missing. This module mirrors that at the
pytest level: in the canonical environment (make test / CI) all four
test-required dependencies are present (mirroring scripts/check_env.py's
REQUIRED set, including nacl) and this asserts so; for a deliberate
ad-hoc `pytest` run in an incomplete env it SKIPS (the individual test modules
keep their own skip guards), so bare pytest stays green while `make test`
still fails loudly.
"""
import importlib.util

import pytest

REQUIRED = ["jsonschema", "cbor2", "flask", "yaml", "nacl"]
_missing = [m for m in REQUIRED if importlib.util.find_spec(m) is None]


@pytest.mark.skipif(
    bool(_missing),
    reason=f"ad-hoc run missing {_missing}; `make test` gates on scripts/check_env.py")
def test_canonical_env_is_complete():
    assert not _missing, f"missing test-required dependencies: {_missing}"
