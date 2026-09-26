#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""R16-04 — a versioned artefact's RESOLVED shape cannot change without its version.

Two gates already ask a version question and neither could see this one.
`schema_shapes.py` compares each discovery schema's top-level property set;
`contract_shapes.py` compares each contract's paths, methods and security. Both
read a file as it is written. **The dependency is not written in the file.**

`wallet-rdp-openapi.yaml` says

    payload_hash:
      $ref: 'schemas/evidence-common.schema.json#/$defs/Hash'

so when the JSON-canonicalisation modes left `$defs/Hash` on 25 September, the
contract stopped accepting inputs it had accepted the day before — while
`companion_contracts` stayed at 9.0.0, in a different version dimension from
the file that changed. An input valid against contract 9.0.0 on Tuesday was
invalid against contract 9.0.0 on Wednesday. That is R16-04, and it was
invisible because the versioning unit is a FILE and the dependency is a `$ref`.

This gate resolves the references and fingerprints what a validator actually
sees. For every artefact `versions.json` binds, every `$ref` is followed — into
`$defs` of the same document and across files — and the resolved tree is reduced
to the part that decides whether an input is valid: types, `required`, `enum`,
`const`, patterns, bounds, the combinators, and the property names. Prose is
dropped, because a reworded description changes no input's validity and a gate
that fired on it would be turned off.

A moved fingerprint with an unmoved version is a FAILURE naming the artefact,
the dimension that must move, and the dimension whose file actually changed when
the two differ — which is the sentence R16-04 needed and nobody could write.

Record the current shapes with `--write` when a bump is deliberate. Run by
`make versions`, beside the two gates it completes.
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RECORD = ROOT / "docs" / "resolved-shapes.json"

# Prose and plumbing: reworded text changes no input's validity, and a gate that
# fired on it would be turned off within a week. Everything else is kept,
# WHEREVER it appears — a schema keyword, an OpenAPI path, an operation's
# request body, a security requirement.
#
# The first draft of this file did the opposite: it allow-listed JSON Schema
# keywords and dropped every key it did not recognise. Applied to an OpenAPI
# document, whose top level is `openapi`/`paths`/`components`, that reduced all
# three contracts to `{}` — the same fingerprint, the SHA-256 of nothing — and
# the gate reported them unchanged because it was comparing emptiness with
# emptiness. A gate that passes by checking nothing is worse than no gate: it
# answers the question it was built to ask, incorrectly.
PROSE = {
    "description", "summary", "title", "$comment", "example", "examples",
    "externalDocs", "info", "servers", "$id", "$schema", "contact", "license",
}
CYCLE = {"$cycle": True}


_CACHE = {}


def _load(path):
    """A referenced document, parsed once per state.

    Resolution re-reads a referenced file at every `$ref` — `$defs/Hash` alone
    is reached fourteen times — which cost eight seconds a run before this. The
    key carries the file's mtime and size, so a document edited between two
    calls in the same process (which is what the tests do) is re-read rather
    than served stale.
    """
    stat = path.stat()
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _CACHE:
        text = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            import yaml
            _CACHE[key] = yaml.safe_load(text)
        else:
            _CACHE[key] = json.loads(text)
    return _CACHE[key]


def _pointer(doc, pointer):
    node = doc
    for token in pointer.lstrip("#/").split("/"):
        if not token:
            continue
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def resolve(node, base, seen=None):
    """The tree with every `$ref` followed, in-document and across files.

    `seen` carries the references open on this branch, not globally: a type used
    twice is resolved twice, and only a reference that reaches itself is cut.
    """
    seen = seen or ()
    if isinstance(node, list):
        return [resolve(v, base, seen) for v in node]
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str):
        target, _, pointer = ref.partition("#")
        path = (base.parent / target).resolve() if target else base
        key = f"{path}#{pointer}"
        if key in seen:
            return dict(CYCLE)
        try:
            doc = _load(path)
        except FileNotFoundError:
            return {"$unresolved": ref}
        resolved = resolve(_pointer(doc, pointer) if pointer else doc, path, seen + (key,))
        rest = {k: resolve(v, base, seen) for k, v in node.items() if k != "$ref"}
        if isinstance(resolved, dict) and rest:          # a $ref beside siblings
            merged = dict(resolved)
            merged.update(rest)
            return merged
        return resolved
    return {k: resolve(v, base, seen) for k, v in node.items()}


def validating(node):
    """The part of a resolved tree that decides an input's validity.

    Structure is kept and prose is dropped, at every depth, so the same walk
    serves a JSON Schema and an OpenAPI document without knowing which it is.
    """
    if isinstance(node, list):
        return [validating(v) for v in node]
    if not isinstance(node, dict):
        return node
    return {k: validating(v) for k, v in sorted(node.items()) if k not in PROSE}


def fingerprint(path):
    resolved = resolve(_load(path), path.resolve())
    shape = validating(resolved)
    canonical = json.dumps(shape, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def artefacts(root=None):
    """{relative path: dimension} — every versioned artefact the manifest binds.

    Driven by `versions.json` rather than a second list to keep in step, which
    is the rule this repository applies to every other generated set.
    """
    root = root or ROOT
    manifest = json.loads((root / "versions.json").read_text(encoding="utf-8"))
    out = {}
    for name, body in manifest["dimensions"].items():
        for binding in body.get("bindings", []):
            rel = binding["file"]
            if rel.endswith((".json", ".yaml")) and not rel.startswith("samples/") \
                    and rel != "versions.json":
                out.setdefault(rel, name)
    return out


def current(root=None):
    root = root or ROOT
    manifest = json.loads((root / "versions.json").read_text(encoding="utf-8"))
    out = {}
    for rel, dimension in sorted(artefacts(root).items()):
        out[rel] = {"dimension": dimension,
                    "version": manifest["dimensions"][dimension]["value"],
                    "sha256": fingerprint(root / rel)}
    return out


def drift(root=None):
    """[(artefact, problem)] — a resolved shape that moved without its version."""
    root = root or ROOT
    record_path = (root / "docs" / "resolved-shapes.json")
    if not record_path.exists():
        return [("docs/resolved-shapes.json", "missing — run `scripts/resolved_shapes.py --write`")]
    recorded = json.loads(record_path.read_text(encoding="utf-8"))["shapes"]
    now = current(root)
    problems = []
    for rel, state in sorted(now.items()):
        was = recorded.get(rel)
        if was is None:
            problems.append((rel, f"is versioned by `{state['dimension']}` and has no recorded "
                                  "shape — record it, so the next change to it is visible"))
            continue
        if was["sha256"] == state["sha256"]:
            continue
        if was["version"] != state["version"]:
            continue                                   # moved, and its version moved with it
        others = sorted({r for r, s in now.items()
                         if s["sha256"] != recorded.get(r, {}).get("sha256")
                         and s["dimension"] != state["dimension"]})
        elsewhere = (f" Its own file may be untouched: the shape reaches it through a `$ref`, "
                     f"and these changed too — {', '.join(others)}.") if others else ""
        problems.append((rel, f"the shape a validator sees changed while `{state['dimension']}` "
                              f"stayed at {state['version']}. An input valid against "
                              f"{state['dimension']} {state['version']} yesterday may be invalid "
                              f"against {state['dimension']} {state['version']} today.{elsewhere}"))
    for rel in sorted(set(recorded) - set(now)):
        problems.append((rel, "is recorded and no longer bound by versions.json — "
                              "remove it from the record deliberately"))
    return problems


def main(argv):
    if "--write" in argv:
        RECORD.write_text(json.dumps({
            "$comment": "R16-04 GENERATED by scripts/resolved_shapes.py. The fingerprint of each "
                        "versioned artefact's shape WITH EVERY $ref RESOLVED, because the "
                        "versioning unit is a file and the dependency is a reference: narrowing "
                        "one $defs narrowed a contract in another dimension, and both of the "
                        "other shape gates read files as written. Regenerate with "
                        "`python3 scripts/resolved_shapes.py --write` when a bump is deliberate.",
            "shapes": current(),
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"recorded {len(current())} resolved shapes")
        return 0
    problems = drift()
    for rel, problem in problems:
        print(f"[FAIL] {rel}: {problem}")
    if problems:
        print(f"\n{len(problems)} resolved shape(s) changed without a version. A `$ref` carries "
              "a change across version dimensions; this is the gate that can see it.")
        return 1
    shapes = current()
    dims = len({s["dimension"] for s in shapes.values()})
    print(f"[OK] {len(shapes)} versioned artefacts across {dims} dimensions: every resolved "
          "shape matches its recorded version")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
