#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CDDL / JSON-Schema non-divergence gate (M4/C3, the CDDL cycle).

The authoritative wire form is deterministic CBOR defined by cddl/sm-mls-erd.cddl;
the JSON in schemas/ describes the non-authoritative projection. This gate checks
they cannot drift: every sealed sample must be BOTH

  * CDDL-valid — its authoritative artefact AND its decoded body (for an EP, each
    embedded sub-object body too) validate against the CDDL, and
  * schema-valid — its projection validates against JSON Schema (the existing
    schema_smoke / test_schemas gate).

Uses the `cddl` tool (RFC 8610; the Rust crate) via `cddl --ci`, which exits
non-zero on a validation failure. Because that crate does not backtrack map
CHOICES or strict-match several `tstr`-typed keys, each object is validated
against its SPECIFIC rule (resolved from the body's discriminator fields), and
the loosely-typed discovery bodies are validated on their `type`/`version`
discriminators — the JSON Schemas remain the strict validator for those.

If the tool is absent this exits 3 so the Makefile can treat the gate as skipped
LOCALLY — but when `CI` is set the absence is a hard failure (exit 1), so the
non-divergence guarantee is actually enforced in CI with a pinned `cddl` (N4/D7).
"""
import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import cbor2

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from lint_cli import projection_equals_decode, validate_body  # noqa: E402 — N1/N2
CDDL_TEXT = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text(encoding="utf-8")

_TYPE_RULE = {
    "SE-v1": "se-body", "RE-v1": "re-body", "CE-v1": "ce-body", "EP-v1": "ep-body",
    "BW-MED-v1": "bw-med-body", "BW-ORG-v1": "bw-org-body", "BW-MEMBER-v1": "bw-member-body",
    "BW-PROVIDER-v1": "bw-provider-body",
    "GCM-v1": "gcm-body",
    "STATUS-v1": "status-assertion-body",
    "ROSTER-v1": "roster-snapshot-body",
}


def _body_rule(body):
    t = body.get("type")
    if t == "DE-v1":
        return "de-availability" if body.get("delivery_grade") == "availability" else "de-confirmed"
    if t == "NDE-v1":
        r = body.get("reason")
        # The dispatch is BY REASON, so a reason with its own arm must be named
        # here as well as in the CDDL. R26-PUB-01: the arm was missing from both
        # for a day, and this map is the half a reader of the CDDL cannot see —
        # `nde-body` offers the choice, and this is what selects from it.
        return {"payload-hash-mismatch": "nde-mismatch",
                "payload-validation-failed": "nde-validation-failure",
                "uid-merged": "nde-merged"}.get(r, "nde-plain")
    if t == "RelayEvidence-v1":
        return "relay-reject" if body.get("event") == "B.2-RelayRejection" else "relay-accept"
    return _TYPE_RULE[t]


def _validate(raw: bytes, rule: str, label: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".cddl", delete=False) as cf:
        cf.write(f"_root = {rule}\n" + CDDL_TEXT)
        cddl_path = cf.name
    with tempfile.NamedTemporaryFile(suffix=".cbor", delete=False) as bf:
        bf.write(raw)
        cbor_path = bf.name
    try:
        r = subprocess.run(["cddl", "--ci", "validate", "--cddl", cddl_path, "--cbor", cbor_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            tail = (r.stderr or r.stdout).strip().splitlines()
            print(f"[FAIL] {label} (rule {rule}): {tail[0] if tail else '?'}")
            return False
        return True
    finally:
        pathlib.Path(cddl_path).unlink(missing_ok=True)
        pathlib.Path(cbor_path).unlink(missing_ok=True)


def _check_body(body, label):
    ok = _validate(cbor2.dumps(body, canonical=True), _body_rule(body), f"{label} body")
    if body.get("type") == "EP-v1":   # recurse into embedded sub-artefacts
        for sub in [body.get("se")] + list(body.get("outcomes") or []) + list(body.get("changes") or []):
            sub_cose = cbor2.loads(bytes(sub))[0]
            sub_body = cbor2.loads(cbor2.loads(bytes(sub_cose))[2])
            ok = _check_body(sub_body, f"{label}/{sub_body.get('type')}") and ok
    return ok


def main():
    if not shutil.which("cddl"):
        if os.environ.get("CI"):
            print("[FAIL] the `cddl` tool is not installed but CI is set — the CDDL "
                  "non-divergence gate MUST run in CI (N4/D7). Install it: "
                  "cargo install cddl --version 0.9.5 --locked.")
            return 1
        print("[skip] the `cddl` tool is not installed — CDDL coherence gate SKIPPED "
              "(install: cargo install cddl). Non-gating LOCALLY only.")
        return 3
    r = subprocess.run(["cddl", "--ci", "compile-cddl", "--cddl", str(ROOT / "cddl" / "sm-mls-erd.cddl")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"[FAIL] CDDL is not RFC 8610-conformant:\n{r.stderr or r.stdout}")
        return 1
    failed = n = 0
    for p in sorted((ROOT / "samples").glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if not (isinstance(d, dict) and "sm_artifact_b64" in d and "projection" in d):
            continue
        n += 1
        raw = base64.b64decode(d["sm_artifact_b64"])
        _t = str(d["projection"].get("type", ""))
        if _t.startswith("BW-") or _t in ("STATUS-v1", "ROSTER-v1"):
            cose, art_rule = raw, "sm-discovery-artifact"
        else:
            cose, art_rule = bytes(cbor2.loads(raw)[0]), "sm-evidence-artifact"
        body = cbor2.loads(cbor2.loads(cose)[2])   # the AUTHORITATIVE body (EP: sub-artefact bytes)
        ok = _validate(raw, art_rule, f"{p.name} artefact")
        ok = _check_body(body, p.name) and ok
        # N2: the CDDL is only a STRUCTURAL OUTER BOUND; the language is pinned by
        # the JSON Schema of the decoded body. schema-smoke validates the
        # projection; here we additionally assert the decoded body EQUALS that
        # projection (recursive; reaching each EP sub-artefact), so the two
        # descriptions cannot describe different documents. This also serves N1.
        pkg11 = projection_equals_decode(d)
        if pkg11:
            print(f"[FAIL] {p.name}: {pkg11[0][0]} {pkg11[0][1]}")
            ok = False
        # N-02: ONE gate executes all three properties — CDDL-valid (outer
        # bound) + body≡projection + Schema-valid (the AUTHORITATIVE validator
        # of the decoded body, LINT-PKG-12).
        pkg12 = validate_body(d["projection"])
        if pkg12:
            print(f"[FAIL] {p.name}: {pkg12[0][0]} {pkg12[0][1]}")
            ok = False
        if not ok:
            failed += 1
    print(f"CDDL coherence: {n - failed}/{n} samples valid "
          "(artefact + body CDDL, body==projection, body Schema-valid)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
