#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dependency preflight for the canonical test environment (spec §9.4, W4).

`scripts/requirements.txt` IS the required test environment. `make test` runs
this preflight first so a missing dependency FAILS loudly (with the fix) rather
than letting pytest silently skip whole test modules — a silent skip can hide a
real regression and, for cbor2, would mean the conformance lint never ran.

The pytest skip guards remain for deliberate ad-hoc `pytest` invocations; this
preflight is the gate for the canonical `make test` run and CI.
"""
import importlib
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from cddl_probe import unusable  # noqa: E402 — one probe, three callers

# import-name -> why it is test-required
REQUIRED = {
    "jsonschema": "JSON-Schema validation (schema tests, schema_smoke)",
    "cbor2": "COSE structural/algorithm checks (evidence_lint conformance)",
    "flask": "reference mock RDP (mock evidence tests)",
    "yaml": "EDD OpenAPI smoke test (module 'yaml', from the pyyaml package)",
    "nacl": "real Ed25519 signing — default for samples/CI (module 'nacl', from pynacl)",
    "openapi_spec_validator": "DR-09: meta-validation of the four published contracts "
                              "(module 'openapi_spec_validator'); the release bar had no "
                              "OpenAPI validation step and two invalid documents shipped",
    "cryptography": "DR-12: ES256/ES384 confirmation verification — BW-MEMBER permits "
                    "EdDSA, ES256 and ES384, so Ed25519-only verification rejects "
                    "conforming evidence",
}


def _report_cddl():
    """The Rust `cddl` tool is a BINARY, not an import, and the policy is stated
    rather than discovered: **optional locally, required in CI.**

    `scripts/cddl_check.py` has said so since N4/D7 — exit 3 locally, exit 1
    when `CI` is set — and `.github/workflows/ci.yml` installs it for that
    reason. What was missing was the preflight saying it out loud: six tests
    executed the tool with no guard, so a machine without it reported six
    FAILURES, and nothing before pytest mentioned the tool at all. Now the
    preflight names it, and `tests/cddl_tool.requires_cddl` skips those tests
    locally while running them under CI.
    """
    reason = unusable()
    if reason is None:
        print("cddl: present — the CDDL non-divergence gate will run")
        return 0
    if os.environ.get("CI"):
        print(f"[FAIL] cddl: {reason}. CI is set, and the CDDL non-divergence "
              "gate MUST run in CI (N4/D7).", file=sys.stderr)
        return 1
    print(f"cddl: {reason}\n"
          "      OPTIONAL locally: `make cddl-check` exits 3 and the tests that "
          "need it SKIP.\n"
          "      Required in CI, where this is a hard failure.")
    return 0


def main():
    missing = []
    for mod, why in REQUIRED.items():
        try:
            importlib.import_module(mod)
        except Exception:
            missing.append((mod, why))
    if missing:
        print("Missing required test dependencies:", file=sys.stderr)
        for mod, why in missing:
            print(f"  - {mod}: {why}", file=sys.stderr)
        print("\nThe canonical test environment is scripts/requirements.txt. Install it:\n"
              "  pip install -r scripts/requirements.txt", file=sys.stderr)
        return 1
    # Derived, not hand-listed: the old message named five modules and would
    # have kept saying so after this map grew.
    print("env preflight OK — " + ", ".join(REQUIRED) + " present")
    return _report_cddl()


if __name__ == "__main__":
    sys.exit(main())
