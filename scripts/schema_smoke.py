#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate EVERY sample against its JSON Schema (make schema-smoke).

The sample -> schema mapping is NOT defined here: it lives in
samples/sample_schema_map.json, the single source of truth shared with
tests/test_schemas.py (ninth review, P2), so the smoke script and the test
suite cannot drift. A samples/sample-*.json missing from the map fails the
test suite's coverage assertion.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_map():
    with open(ROOT / "samples" / "sample_schema_map.json", encoding="utf-8") as f:
        return json.load(f)["map"]


def main():
    try:
        import jsonschema
    except Exception:
        print("jsonschema not installed; run: pip install jsonschema")
        sys.exit(0)
    store = {}
    # Load every schema in the schemas/ directory so that cross-references
    # (e.g. EP -> NDE/RE via oneOf) resolve from the local store and never
    # trigger a network fetch of the placeholder $id URLs.
    for p in sorted((ROOT / "schemas").glob("*.schema.json")):
        with open(p, "r", encoding="utf-8") as f:
            sch = json.load(f)
            if "$id" in sch:
                store[sch["$id"]] = sch
            store[str(p)] = sch
    resolver = jsonschema.RefResolver(base_uri=str(ROOT.as_uri()) + "/", referrer=None, store=store)
    mapping = load_map()
    failed = 0
    for sample, schema_file in sorted(mapping.items()):
        sp = ROOT / "samples" / sample
        schp = ROOT / "schemas" / schema_file
        with open(schp, "r", encoding="utf-8") as f:
            schema = json.load(f)
        with open(sp, "r", encoding="utf-8") as f:
            inst = json.load(f)
        if isinstance(inst, dict) and "sm_artifact_b64" in inst and "projection" in inst:
            inst = inst["projection"]  # M4: the JSON Schema describes the projection
        try:
            # X-35: assert `format` (e.g. date-time) — without a FormatChecker,
            # jsonschema treats format as decorative and timestamps go unchecked.
            jsonschema.validate(instance=inst, schema=schema, resolver=resolver,
                                format_checker=jsonschema.FormatChecker())
            print(f"[OK] {sample} ✓")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {sample}: {e}")
    print(f"{len(mapping) - failed}/{len(mapping)} samples schema-valid")
    if failed:
        sys.exit(2)

if __name__ == "__main__":
    main()
