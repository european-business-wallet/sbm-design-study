#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""X-20 normative lint catalogue — renderer and consistency checker.

`docs/lint-catalogue.json` is the single source of truth: one faithful entry per
`LINT-*` rule the reference conformance tools emit (identifier, input artefacts,
precondition, exact predicate, error outcome, profile applicability, owning
function). The scripts in `scripts/` are the *versioned reference implementation*
of this catalogue; a clean-room checker can reproduce every verdict from the
catalogue + the sample vectors without reading the Python.

This module:
  * `--render`  regenerates the human-readable `docs/lint-catalogue.md`;
  * `--check` (default) verifies the catalogue is CONSISTENT with the tree —
      1. completeness: every rule the scripts emit is catalogued (no rule may
         exist only in Python), and no catalogue entry is a phantom;
      2. drift: the committed Markdown equals the freshly rendered Markdown;
    and prints test-traceability coverage.

Run: `make lint-catalogue`. Enforced by `tests/test_lint_catalogue.py`.
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
JSON = ROOT / "docs" / "lint-catalogue.json"
MD = ROOT / "docs" / "lint-catalogue.md"
RULE_TOKEN = re.compile(r"LINT-[A-Z0-9]+(?:-[A-Z0-9]+)*")

PROFILE_ORDER = ["core", "production", "agent", "four-corner"]


def load():
    return json.loads(JSON.read_text(encoding="utf-8"))


def catalogue_ids(data):
    return [r["id"] for r in data["rules"]]


def emitted_ids():
    """Every LINT-* token the reference tools can emit.

    R6-05: rule ids became DATA. `docs/required-properties.json` declares the
    properties a complete verification must establish and the gap rule each
    yields, and `check_bundle` iterates it — so those ids never appear
    literally in any script. A scanner that reads only the sources would call
    them phantoms and, worse, would let a declared-but-uncatalogued rule
    through. The table is part of the emission surface, so it is read here.
    """
    ids = set()
    for p in sorted(ROOT.glob("scripts/*.py")):
        ids |= set(RULE_TOKEN.findall(p.read_text(encoding="utf-8")))
    table = ROOT / "docs" / "required-properties.json"
    if table.exists():
        for prop in json.loads(table.read_text(encoding="utf-8"))["properties"]:
            ids.add(prop["gap_rule"])
    return ids


def test_map(ids):
    """id -> sorted list of tests/*.py files that name it."""
    m = {i: set() for i in ids}
    for p in sorted(ROOT.glob("tests/*.py")):
        txt = p.read_text(encoding="utf-8")
        for i in ids:
            if i in txt:
                m[i].add(p.name)
    return {i: sorted(v) for i, v in m.items()}


def completeness(data):
    """(missing_from_catalogue, phantom_in_catalogue)."""
    cat = set(catalogue_ids(data))
    non_rule = set(data.get("non_rule_tokens", {}))
    emitted = emitted_ids()
    missing = sorted(emitted - non_rule - cat)
    # A phantom entry is a catalogue id that never appears in the scripts at all.
    script_blob = "\n".join(p.read_text(encoding="utf-8")
                            for p in ROOT.glob("scripts/*.py"))
    table = ROOT / "docs" / "required-properties.json"
    if table.exists():
        script_blob += "\n" + table.read_text(encoding="utf-8")
    phantom = sorted(i for i in cat if i not in script_blob)
    return missing, phantom


def _fam(rule_id):
    # LINT-DE-04 -> DE ; LINT-DISC-P-01 -> DISC-P ; LINT-000 -> 000
    body = rule_id[len("LINT-"):]
    parts = body.rsplit("-", 1)
    return parts[0] if len(parts) == 2 and re.fullmatch(r"[A-Z0-9]+", parts[1]) else body


FAMILY_TITLES = {
    "000": "Dispatch / unknown-type guards",
    "DISC-000": "Dispatch / unknown-type guards",
    "AUTH": "Authentication-context coherence (AUTH)",
    "DE": "Delivery / sending evidence invariants (DE)",
    "EP": "Evidence Package structure (EP)",
    "MAN": "Multipart manifest (MAN)",
    "NDE": "Non-delivery evidence (NDE)",
    "PKG": "Packaging, canonical bytes and projection (PKG)",
    "PROD": "Production-profile evidence prechecks (PROD)",
    "RLY": "Relay evidence (RLY)",
    "TRUST": "Trust-store resolution (TRUST)",
    "VERIFY": "Demo cryptographic verification (VERIFY)",
    "DISC": "Discovery documents (DISC)",
    "DISC-P": "Production-profile discovery prechecks (DISC-P)",
    "BND": "Cross-document bundle (BND)",
}
# stable presentation order of families
FAMILY_ORDER = ["000", "DISC-000", "AUTH", "DE", "EP", "MAN", "NDE", "PKG",
                "PROD", "RLY", "TRUST", "VERIFY", "DISC", "DISC-P", "BND"]


def render_md(data):
    tmap = test_map(set(catalogue_ids(data)))
    rules = data["rules"]
    by_fam = {}
    for r in rules:
        by_fam.setdefault(_fam(r["id"]), []).append(r)
    tested = sum(1 for r in rules if tmap.get(r["id"]))
    L = []
    # REUSE-IgnoreStart  (these are the licence header of the GENERATED file,
    # not of this script — REUSE must not read them as this file's tags)
    L.append("<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->")
    L.append("<!-- SPDX-License-Identifier: CC-BY-4.0 -->")
    # REUSE-IgnoreEnd
    L.append("")
    L.append("<!-- GENERATED FILE — do not edit by hand. Source of truth: "
             "docs/lint-catalogue.json. Regenerate with `make lint-catalogue` "
             "(scripts/lint_catalogue.py --render). -->")
    L.append("")
    L.append("# Normative lint catalogue (X-20)")
    L.append("")
    L.append("This catalogue is the **normative definition** of every `LINT-*` "
             "conformance rule referenced by the umbrella (§9.4) and the TS "
             "(Annex A ICS pro forma). It exists so an assessor can build an "
             "independent checker that reproduces every verdict from this "
             "document and the sample vectors **without reading the reference "
             "Python**. The scripts under `scripts/` "
             "(`evidence_lint.py`, `discovery_lint.py`, `bundle_lint.py`, "
             "`lint_cli.py`) are the **versioned reference implementation** of "
             "this catalogue, not its definition: a change to a rule's behaviour "
             "MUST be accompanied by a change to this catalogue and its tests "
             "(enforced by `tests/test_lint_catalogue.py`).")
    L.append("")
    L.append(f"**Rules:** {len(rules)} · **with a naming test:** {tested}/"
             f"{len(rules)} · **catalogue version:** "
             f"{data.get('catalogue_version')}.")
    L.append("")
    L.append("**Profile applicability.** `core` rules apply to every deployment; "
             "`production` rules apply only under `--profile production`; `agent` "
             "rules apply only where a system member (Annex R) is enrolled; "
             "`four-corner` rules apply only to relay/federated (profile-2) "
             "evidence.")
    L.append("")
    L.append("**Error outcome.** Every rule is *fail-closed*: a violation makes "
             "the artefact non-conformant (the reference tools exit non-zero and "
             "emit the message shown). The one exception is `LINT-BND-W1`, a "
             "non-fatal WARNING.")
    L.append("")
    for fam in FAMILY_ORDER:
        fam_rules = by_fam.get(fam)
        if not fam_rules:
            continue
        L.append(f"## {FAMILY_TITLES.get(fam, fam)}")
        L.append("")
        for r in sorted(fam_rules, key=lambda x: x["id"]):
            tests = tmap.get(r["id"]) or []
            tstr = ", ".join(f"`{t}`" for t in tests) if tests else \
                "_(no dedicated test names this id — coverage gap, tracked)_"
            L.append(f"### {r['id']} · `{r['profile']}`")
            L.append("")
            L.append(f"- **Input:** {r['input']}")
            L.append(f"- **Precondition:** {r['precondition']}")
            L.append(f"- **Predicate (PASS iff):** {r['predicate']}")
            L.append(f"- **Error outcome:** {r['error']}")
            L.append(f"- **Reference implementation:** `{r['owner_fn']}`")
            L.append(f"- **Tests:** {tstr}")
            L.append("")
    return "\n".join(L).rstrip() + "\n"


def cmd_render():
    MD.write_text(render_md(load()), encoding="utf-8")
    print(f"rendered {MD.relative_to(ROOT)} from {JSON.relative_to(ROOT)}")
    return 0


def cmd_check():
    data = load()
    missing, phantom = completeness(data)
    ok = True
    if missing:
        ok = False
        print("[FAIL] rules emitted by the reference tools but NOT in the "
              "catalogue (an undocumented conformance rule — X-20):")
        for i in missing:
            print(f"  - {i}")
    if phantom:
        ok = False
        print("[FAIL] catalogue entries that appear in NO reference tool "
              "(phantom rule id — typo or removed rule):")
        for i in phantom:
            print(f"  - {i}")
    if MD.exists():
        if MD.read_text(encoding="utf-8") != render_md(data):
            ok = False
            print("[FAIL] docs/lint-catalogue.md is stale — run "
                  "`make lint-catalogue` to regenerate from the JSON.")
    else:
        ok = False
        print("[FAIL] docs/lint-catalogue.md is missing — run "
              "`make lint-catalogue`.")
    tmap = test_map(set(catalogue_ids(data)))
    tested = sum(1 for i in catalogue_ids(data) if tmap.get(i))
    n = len(data["rules"])
    if not ok:
        return 1
    print(f"[OK] lint catalogue consistent: {n} rules, all emitted rules "
          f"catalogued, no phantoms, Markdown current; {tested}/{n} have a "
          f"naming test.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="lint catalogue renderer/checker")
    ap.add_argument("--render", action="store_true",
                    help="regenerate docs/lint-catalogue.md from the JSON")
    args = ap.parse_args()
    return cmd_render() if args.render else cmd_check()


if __name__ == "__main__":
    sys.exit(main())
