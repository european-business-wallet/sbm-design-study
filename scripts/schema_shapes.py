#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""R3-09 follow-up — a versioned schema's SHAPE cannot change without its version.

BW-MED gained `ds_receipt_keys` in R3-04 and stayed at 2.0, and the version gate
could not see it: every binding still agreed with the manifest, because the
manifest had not moved either. The CHANGELOG and the pull request then claimed
a bump that had not happened — an active claim contradicting the artefact,
which is R3-09's own defect committed one batch after building the gate for it.

The gate compares each versioned discovery schema's top-level property set with
a recorded fingerprint. A changed shape whose version did not move is a FAILURE
naming the schema; regenerate with `--write` when the bump is deliberate.

R4-07 adds the second direction. The umbrella's §8.3 stated a "Full field list
(v2.4)" that omitted `supersedes` and named a version two releases behind, and
nothing compared that sentence with the schema it claims to enumerate: an
implementer following the normative prose builds a document the Schema rejects.
Since the property set is already read here, the prose claim is checked against
it rather than against a second restated list — the alternative would be one
more hand-maintained copy of exactly the thing that drifted.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHAPES = ROOT / "docs" / "schema-shapes.json"


def observed():
    recorded = json.loads(SHAPES.read_text(encoding="utf-8"))
    out = {}
    for name in recorded["shapes"]:
        d = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        out[name] = {"dimension": recorded["shapes"][name]["dimension"],
                     "version": d["properties"]["version"]["const"],
                     "properties": sorted(d["properties"])}
    return recorded, out


# A clause heading already declares which document it defines — `### 8.3
# BW-ORG-v1 …` — so the binding is READ, not restated.
SECTION_TYPE = re.compile(r"^#{2,4}\s+\S+\s+(BW-(?:MED|ORG|MEMBER))-v1\b")
FIELD_LIST = re.compile(r"Full field list \(v(\d+\.\d+)\):(.*)$")
IDENT = re.compile(r"`([a-z_][a-z0-9_]*)`")
SCHEMA_OF = {"BW-MED": "bw-med.schema.json", "BW-ORG": "bw-org.schema.json",
             "BW-MEMBER": "bw-member.schema.json"}


def claimed_fields(tail):
    """The field names in a 'Full field list' sentence.

    The sentence is a comma-separated list where each item BEGINS with the
    field name and may carry a parenthetical note after it. So: split on
    commas at parenthesis depth 0, take the first backticked identifier of
    each item. Identifiers inside a note (`default`, `records_role`, the
    `any-one`/`quorum:n` values) are describing a field, not naming one.
    """
    items, depth, start = [], 0, 0
    for i, ch in enumerate(tail):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            items.append(tail[start:i])
            start = i + 1
    items.append(tail[start:])
    out = []
    for item in items:
        m = IDENT.search(item)
        if m:
            out.append(m.group(1))
    return out


def check_prose_field_lists(docs):
    """Return [(file, line, message)] where a completeness claim disagrees
    with the schema it enumerates."""
    problems = []
    for rel in docs:
        path = ROOT / rel
        if not path.exists():
            continue
        section = None
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.startswith("#"):
                m = SECTION_TYPE.match(line)
                section = m.group(1) if m else None
                continue
            m = FIELD_LIST.search(line)
            if not m or section is None:
                continue
            schema = json.loads(
                (ROOT / "schemas" / SCHEMA_OF[section]).read_text(encoding="utf-8"))
            actual = set(schema["properties"])
            claimed = claimed_fields(m.group(2))
            version = schema["properties"]["version"]["const"]
            if m.group(1) != version:
                problems.append((rel, n, f"{section} field list claims v{m.group(1)}, "
                                         f"the schema is v{version}"))
            missing, extra = sorted(actual - set(claimed)), sorted(set(claimed) - actual)
            if missing:
                problems.append((rel, n, f"{section} 'full field list' OMITS "
                                         f"{missing} — an implementer following the "
                                         "normative prose builds a document the "
                                         "Schema rejects"))
            if extra:
                problems.append((rel, n, f"{section} 'full field list' names "
                                         f"{extra}, which the schema does not define"))
            if len(claimed) != len(set(claimed)):
                problems.append((rel, n, f"{section} 'full field list' repeats a field"))
    return problems


def main(argv):
    recorded, now = observed()
    if "--write" in argv:
        recorded["shapes"] = now
        SHAPES.write_text(json.dumps(recorded, indent=2, ensure_ascii=False) + "\n")
        print(f"[OK] recorded {len(now)} schema shapes")
        return 0
    problems = []
    for name, seen in now.items():
        was = recorded["shapes"][name]
        if seen["properties"] == was["properties"]:
            continue
        added = sorted(set(seen["properties"]) - set(was["properties"]))
        removed = sorted(set(was["properties"]) - set(seen["properties"]))
        if seen["version"] == was["version"]:
            problems.append(
                f"{name}: shape changed (+{added} -{removed}) but version is "
                f"still {seen['version']} — bump it, or run "
                "`scripts/schema_shapes.py --write` if the change is "
                "genuinely non-substantive and the version is right")
        else:
            problems.append(
                f"{name}: shape and version both changed ({was['version']} -> "
                f"{seen['version']}); run `scripts/schema_shapes.py --write` "
                "to record the new shape")
    # R4-07: the same property set, checked against the prose that claims to
    # enumerate it. Which documents are swept is the manifest's list, so a
    # document added to one gate is added to both.
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    docs = [d for d in manifest.get("active_claim_sweep", []) if d.endswith(".md")]
    prose = check_prose_field_lists(docs)
    for f, n, msg in prose:
        problems.append(f"{f}:{n}: {msg} (R4-07)")
    for p in problems:
        print(f"[FAIL] {p}")
    if problems:
        return 1
    print(f"[OK] {len(now)} versioned schema shapes match their recorded "
          f"versions; {len(docs)} document(s) swept for field-list claims")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
