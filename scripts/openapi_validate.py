#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""DR-09 — meta-validate every published OpenAPI contract, offline.

The release bar had no OpenAPI validation step. The companion tests parsed the
YAML and checked that `openapi` began with `3.`, which is why two structurally
INVALID documents shipped green:

  * `rdp-relay-openapi.yaml` declared 3.0.3 and used security-scheme type
    `mutualTLS`, which exists only in 3.1;
  * `edd-resolver-openapi.yaml` put `description` inside Media Type Objects,
    where 3.0.3 permits only schema/example(s)/encoding and extensions.

Code generators and validators can reject a normative contract while our own
release stays green — the failure mode this gate exists to end.

Independence, deliberately: this uses `openapi-spec-validator`, a THIRD-PARTY
implementation of the specification, not our own reading of it. A gate written
from the same understanding that produced the documents would agree with them
and be wrong together — the round-2 lesson.

Offline: every `$ref` must resolve from the repository root with no network.
The validator is configured so that a remote fetch attempt is an ERROR rather
than a hang or a silent pass.
"""
import json
import pathlib
import sys
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Every published contract. Adding one here is deliberate: a contract absent
# from this list is a contract nothing validates.
CONTRACTS = (
    "wallet-rdp-openapi.yaml",
    "delivery-service-openapi.yaml",
    "rdp-relay-openapi.yaml",
    "edd-resolver-openapi.yaml",
    "federation-register-openapi.yaml",
)


class NetworkAccessAttempted(RuntimeError):
    """A $ref reached for the network. Offline resolution is the requirement:
    a contributor without connectivity, or CI in a sealed runner, must reach
    the same verdict."""


def _offline_guard():
    """Make an outbound fetch a loud failure rather than a hang or a silent
    pass. `file:` URIs are how the validator reads the contract and its local
    neighbours, so those go through; anything remote does not."""
    real = urllib.request.urlopen

    def _guarded(url, *a, **kw):
        target = getattr(url, "full_url", url)
        if isinstance(target, str) and not target.startswith("file:"):
            raise NetworkAccessAttempted(
                f"an OpenAPI $ref attempted a network fetch ({target[:120]}) — "
                "every reference must resolve from the repository (DR-09)")
        return real(url, *a, **kw)

    urllib.request.urlopen = _guarded


def validate(path):
    """Return a list of human-readable problems for one contract."""
    try:
        from openapi_spec_validator import validate as _validate
        from openapi_spec_validator.readers import read_from_filename
    except ImportError:
        return ["openapi-spec-validator is not installed — see "
                "scripts/requirements.txt (DR-09: the validator is part of the "
                "release bar, not an optional convenience)"]

    try:
        spec, base_uri = read_from_filename(str(path))
    except Exception as e:                       # unreadable / not YAML
        return [f"cannot read: {e}"]

    problems = []
    try:
        _validate(spec, base_uri=base_uri)
    except NetworkAccessAttempted as e:
        problems.append(str(e))
    except Exception as e:
        # The validator's own message names the offending path; keep it whole
        # rather than paraphrasing — the path is the actionable part.
        problems.append(" ".join(str(e).split())[:900])
    return problems


def main(argv):
    _offline_guard()
    failed = 0
    for name in CONTRACTS:
        path = ROOT / name
        if not path.exists():
            print(f"[FAIL] {name}: published contract is missing")
            failed += 1
            continue
        problems = validate(path)
        declared = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("openapi", "?")
        if problems:
            failed += 1
            print(f"[FAIL] {name} (openapi {declared}):")
            for p in problems:
                print(f"        {p}")
        else:
            print(f"[ ok ] {name} (openapi {declared})")
    if failed:
        print(f"\n[FAIL] {failed} of {len(CONTRACTS)} contracts do not validate "
              "against their declared OpenAPI version (DR-09)")
        return 1
    print(f"\n[OK] {len(CONTRACTS)} contracts valid, all $refs resolved offline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
