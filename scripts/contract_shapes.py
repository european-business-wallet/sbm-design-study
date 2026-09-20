#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""R5-07 — a published contract's SURFACE cannot change without its version.

`schema_shapes.py` closed this for the discovery schemas after R3-09: a schema
gained a field while its version const stayed put, and the version gate could
not see it because every binding still agreed with a manifest that had not
moved either. **The same hole was still open one artefact over.** Round 5
changed three of the four OpenAPI contracts — a new operation, four new
security schemes, and `/messages` rebound from `memberAuth` to `rdpAuth`, which
is BREAKING for every existing client — and `make versions` stayed green,
because the gate answers *"do the copies agree?"* and nothing answered *"did
the surface change without the version?"*.

The fingerprint is the part a client is written against:

* every `path + method`, so a removed or added operation shows;
* each operation's `security` ALTERNATIVES, so rebinding one — or quietly
  widening it — shows;
* each declared `securityScheme`'s `type`/`scheme`, so swapping the mechanism
  under a scheme's name shows.

Deliberately NOT the descriptions: prose changes constantly and would make the
gate noise, and the R4-07/R5-06 checks already compare prose with structure.

Regenerate with `--write` when a bump is deliberate. The point is that the bump
becomes a decision rather than an omission.
"""
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHAPES = ROOT / "docs" / "contract-shapes.json"


def surface(doc):
    """The client-visible surface of one OpenAPI document."""
    ops = {}
    for path, item in (doc.get("paths") or {}).items():
        for method, op in (item or {}).items():
            if not isinstance(op, dict) or method == "parameters":
                continue
            blocks = op.get("security", doc.get("security") or [])
            ops[f"{method.upper()} {path}"] = sorted(
                ",".join(sorted(b)) for b in blocks)
    schemes = {
        name: f"{spec.get('type')}/{spec.get('scheme')}"
        for name, spec in
        ((doc.get("components") or {}).get("securitySchemes") or {}).items()}
    return {"version": doc["info"]["version"],
            "operations": dict(sorted(ops.items())),
            "security_schemes": dict(sorted(schemes.items())),
            "schemas": schema_shapes(doc)}


def schema_shapes(doc):
    """R9-B6 — the WIRE SHAPE of every published component.

    This gate fingerprinted operations and security alternatives and NOTHING
    ELSE, so a breaking SCHEMA change passed it in silence. Round 9 made three
    — a required response field added to `Reservation`, `KeyPackageRef` gaining
    a grammar, `collection_token` becoming mandatory — and each version bump
    was manual, which is exactly the "restated by hand" family this repository
    keeps finding. A gate that measures part of a surface reports on part of a
    surface.

    What is fingerprinted is what a generated client BREAKS on: the required
    set, the property names, and each property's type/`$ref`/`const`/`enum`.
    Descriptions are excluded deliberately — prose changes every round and
    would make the fingerprint noise rather than signal.
    """
    def shape(schema):
        if not isinstance(schema, dict):
            return None
        out = {}
        if "$ref" in schema:
            return {"$ref": schema["$ref"]}
        for key in ("type", "const", "enum", "format", "pattern",
                    "minLength", "minimum", "minItems",
                    "unevaluatedProperties", "additionalProperties"):
            if key in schema:
                out[key] = schema[key]
        if "required" in schema:
            out["required"] = sorted(schema["required"])
        if "properties" in schema:
            out["properties"] = {k: shape(v)
                                 for k, v in sorted(schema["properties"].items())}
        if "items" in schema:
            out["items"] = shape(schema["items"])
        return out

    comps = (doc.get("components") or {}).get("schemas") or {}
    return {name: shape(spec) for name, spec in sorted(comps.items())}


def observed(recorded):
    return {name: surface(yaml.safe_load((ROOT / name).read_text(encoding="utf-8")))
            for name in recorded["contracts"]}


def main(argv):
    recorded = json.loads(SHAPES.read_text(encoding="utf-8"))
    now = observed(recorded)
    if "--write" in argv:
        recorded["contracts"] = now
        SHAPES.write_text(json.dumps(recorded, indent=2, ensure_ascii=False) + "\n")
        print(f"[OK] recorded {len(now)} contract surfaces")
        return 0

    problems = []
    for name, seen in now.items():
        was = recorded["contracts"][name]
        changes = []
        added = sorted(set(seen["operations"]) - set(was["operations"]))
        removed = sorted(set(was["operations"]) - set(seen["operations"]))
        rebound = sorted(k for k in set(seen["operations"]) & set(was["operations"])
                         if seen["operations"][k] != was["operations"][k])
        if added:
            changes.append(f"operations added {added}")
        if removed:
            changes.append(f"operations REMOVED {removed}")
        if rebound:
            changes.append(f"security rebound on {rebound}")
        if seen["security_schemes"] != was["security_schemes"]:
            changes.append(
                f"security schemes {was['security_schemes']} -> "
                f"{seen['security_schemes']}")
        # R9-B6: schema shapes count as surface. A required field added to a
        # response, or a grammar added to a field, breaks a generated client
        # exactly as an operation change does.
        old_schemas = was.get("schemas", {})
        new_schemas = seen.get("schemas", {})
        s_added = sorted(set(new_schemas) - set(old_schemas))
        s_removed = sorted(set(old_schemas) - set(new_schemas))
        s_changed = sorted(k for k in set(new_schemas) & set(old_schemas)
                           if new_schemas[k] != old_schemas[k])
        if s_added:
            changes.append(f"schemas added {s_added}")
        if s_removed:
            changes.append(f"schemas REMOVED {s_removed}")
        if s_changed:
            changes.append(f"schema shape changed on {s_changed}")
        if not changes:
            continue
        if seen["version"] == was["version"]:
            problems.append(
                f"{name}: surface changed ({'; '.join(changes)}) but "
                f"info.version is still {seen['version']} — bump it, or run "
                "`scripts/contract_shapes.py --write` if the change is "
                "genuinely non-substantive and the version is right")
        else:
            problems.append(
                f"{name}: surface and version both changed "
                f"({was['version']} -> {seen['version']}); run "
                "`scripts/contract_shapes.py --write` to record the new surface")
    for p in problems:
        print(f"[FAIL] {p}")
    if problems:
        return 1
    print(f"[OK] {len(now)} published contract surfaces match their recorded "
          "versions")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
