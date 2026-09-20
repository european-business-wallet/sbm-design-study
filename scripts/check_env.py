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
import sys

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
