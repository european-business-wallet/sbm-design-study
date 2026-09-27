# SPDX-License-Identifier: MIT

import json, pathlib, pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
def _schemas():
    """Every schema on disk, so the offline resolver cannot be short of one.

    This was a hand-written list of eleven names, and it omitted
    `evidence-gcm.schema.json` among others. Nothing noticed, because no sealed
    vector carried an EP `disputes[]` — the only `$ref` that reaches the GCM
    schema. The first vector that did sent `jsonschema` to
    https://bw.example.eu/ for it: the store had no entry, so resolution fell
    through to the network, and a suite that is supposed to validate offline
    would have depended on a host that does not exist. Derived from the
    directory, which cannot fall behind it.
    """
    return sorted(p.name for p in (ROOT / "schemas").glob("*.schema.json"))


def _load_map():
    # Single source of truth shared with scripts/schema_smoke.py (P2).
    with open(ROOT / "samples" / "sample_schema_map.json", encoding="utf-8") as f:
        return json.load(f)["map"]


jsonschema = None
resolver = None

def setup_module():
    global jsonschema, resolver
    try:
        import jsonschema as _js
    except Exception:
        pytest.skip("jsonschema not installed; skipping schema smoke tests", allow_module_level=True)
    jsonschema = _js
    # Build a local resolver
    store = {}
    for name in _schemas():
        p = ROOT / "schemas" / name
        with open(p, "r", encoding="utf-8") as f:
            sch = json.load(f)
            if "$id" in sch:
                store[sch["$id"]] = sch
            store[str(p)] = sch
    resolver = jsonschema.RefResolver(base_uri=str(ROOT.as_uri()) + "/schemas", referrer=None, store=store)

def test_samples_validate_against_schemas():
    for sample, schema_file in sorted(_load_map().items()):
        sp = ROOT / "samples" / sample
        schp = ROOT / "schemas" / schema_file
        with open(schp, "r", encoding="utf-8") as f:
            schema = json.load(f)
        with open(sp, "r", encoding="utf-8") as f:
            inst = json.load(f)
        if isinstance(inst, dict) and "sm_artifact_b64" in inst and "projection" in inst:
            inst = inst["projection"]  # M4: schemas describe the projection
        jsonschema.validate(instance=inst, schema=schema, resolver=resolver, format_checker=jsonschema.FormatChecker())


def test_map_covers_every_sample_on_disk():
    """No samples/sample-*.json may escape schema coverage (P2). The bundle
    manifests are cross-document lists checked by bundle_lint, not schemas."""
    mapping = _load_map()
    on_disk = {p.name for p in (ROOT / "samples").glob("sample-*.json")}
    assert on_disk == set(mapping), (
        f"unmapped samples: {sorted(on_disk - set(mapping))}; "
        f"mapped but missing from disk: {sorted(set(mapping) - on_disk)}")
    missing_schemas = [s for s in set(mapping.values())
                       if not (ROOT / "schemas" / s).exists()]
    assert not missing_schemas
