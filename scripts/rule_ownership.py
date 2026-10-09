#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""X-34 rule-ownership inventory — renderer and consistency checker.

`docs/rule-ownership.json` records, for each normative rule family, the SINGLE
document that owns it; every other document may carry only an informative summary
that references the owner. This tool enforces that model:

  * each family's owner document actually states the rule (`owner_present`);
  * no NON-owner document carries a BARE normative restatement of it
    (`non_owner_forbidden` — a MUST/SHALL form with no cross-reference);
  * the I-D's "Deployment-Defined Interfaces" prose count equals the number of
    interface bullets it lists (the review found "Two" while four are listed).

`--render` regenerates `docs/rule-ownership.md`; `--check` (default) runs the
gate. The registry / well-known ownership split is deferred to X-25 and is
deliberately out of scope here. Run: `make rule-ownership`.
"""
import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
JSON = ROOT / "docs" / "rule-ownership.json"
MD = ROOT / "docs" / "rule-ownership.md"

_WORD_TO_INT = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
                "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
                "ten": 10}


def load():
    return json.loads(JSON.read_text(encoding="utf-8"))


def _text(data, key):
    return (ROOT / data["doc_keys"][key]).read_text(encoding="utf-8")


def interface_count(data, id_text=None):
    """Return (count_word, word_as_int, bullet_count) for the DDI section."""
    spec = data["interfaces"]
    txt = id_text if id_text is not None else _text(data, spec["doc"])
    seg = txt.split(spec["section_heading"], 1)[1].split("\n# ", 1)[0]
    m = re.search(spec["count_regex"], txt)
    word = m.group(1) if m else None
    n_word = _WORD_TO_INT.get(word.lower()) if word else None
    bullets = re.findall(spec["bullet_regex"], seg)
    return word, n_word, len(bullets)


def check(data):
    problems = []
    for fam in data["families"]:
        owner = fam["owner"]
        owner_txt = _text(data, owner)
        if not re.search(fam["owner_present"], owner_txt):
            problems.append(
                f"family {fam['id']!r}: owner {owner!r} no longer states the rule "
                f"(owner_present /{fam['owner_present']}/ did not match)")
        for key in data["doc_keys"]:
            if key == owner:
                continue
            hits = [ln.strip() for ln in _text(data, key).splitlines()
                    if re.search(fam["non_owner_forbidden"], ln)]
            for h in hits:
                problems.append(
                    f"family {fam['id']!r}: non-owner {key!r} carries a BARE "
                    f"normative restatement (owner is {owner!r}): {h[:100]!r}")
    word, n_word, bullets = interface_count(data)
    exp = data["interfaces"]["expected"]
    if n_word is None:
        problems.append(f"interfaces: could not read the count word (got {word!r})")
    elif not (n_word == bullets == exp):
        problems.append(
            f"interfaces: prose says {word!r} ({n_word}) but the section lists "
            f"{bullets} interface bullets (expected {exp}) — the count is wrong")
    return problems


def render_md(data):
    L = []
    # REUSE-IgnoreStart  (licence header of the GENERATED file, not of this script)
    L.append("<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->")
    L.append("<!-- SPDX-License-Identifier: CC-BY-4.0 -->")
    # REUSE-IgnoreEnd
    L.append("")
    L.append("<!-- GENERATED FILE — do not edit by hand. Source of truth: "
             "docs/rule-ownership.json. Regenerate with `make rule-ownership` "
             "(scripts/rule_ownership.py --render). -->")
    L.append("")
    L.append("# Rule-ownership inventory")
    L.append("")
    L.append("Each normative rule family below has exactly **one owning document**. "
             "Other documents carry only *informative* summaries that reference the "
             "owner — never a second normative statement. "
             "`scripts/rule_ownership.py` (`make rule-ownership`) and "
             "`tests/test_rule_ownership.py` enforce this: the owner states the "
             "rule, no non-owner document carries a bare normative (MUST/SHALL) "
             "restatement, and the Internet-Draft's deployment-defined-interface "
             "count matches the interfaces it lists.")
    L.append("")
    L.append("This complements the verbatim-duplication guard "
             "(`tests/test_no_normative_duplication.py`), which catches identical "
             "sentences copied across the three specification documents; this "
             "inventory catches the same rule *reworded* and restated normatively "
             "in more than one place.")
    L.append("")
    L.append("**Out of scope, deferred:** the registry and "
             "well-known-resource ownership split. This inventory covers rule "
             "ownership and the interface-count correction only.")
    L.append("")
    names = data["doc_keys"]
    L.append("Document keys: " + ", ".join(f"`{k}` = `{v}`"
                                           for k, v in names.items()) + ".")
    L.append("")
    L.append("## Rule families")
    L.append("")
    for fam in data["families"]:
        L.append(f"### {fam['title']}")
        L.append("")
        L.append(f"- **Family id:** `{fam['id']}`")
        L.append(f"- **Normative owner:** `{fam['owner']}` — {fam['owner_anchor']}")
        if fam.get("rule_ids"):
            L.append(f"- **Machine-checked by:** "
                     + ", ".join(f"`{r}`" for r in fam["rule_ids"]))
        if fam.get("informative_refs"):
            L.append("- **Informative summaries (must reference the owner):**")
            for r in fam["informative_refs"]:
                L.append(f"    - `{r['doc']}` — {r['note']}")
        if fam.get("note"):
            L.append(f"- **Note:** {fam['note']}")
        L.append("")
    spec = data["interfaces"]
    L.append("## Interface count")
    L.append("")
    L.append(f"- **Owner:** `{spec['doc']}` — the *Deployment-Defined Interfaces* "
             "section.")
    L.append(f"- **Rule:** {spec['note']}")
    L.append(f"- **Expected count:** {spec['expected']} (Wallet-RDP, Delivery "
             "Service, RDP-RDP relay, Wallet-agent).")
    L.append("")
    return "\n".join(L).rstrip() + "\n"


def cmd_render():
    MD.write_text(render_md(load()), encoding="utf-8")
    print(f"rendered {MD.relative_to(ROOT)} from {JSON.relative_to(ROOT)}")
    return 0


def cmd_check():
    data = load()
    problems = check(data)
    if MD.exists() and MD.read_text(encoding="utf-8") != render_md(data):
        problems.append("docs/rule-ownership.md is stale — run `make rule-ownership`")
    elif not MD.exists():
        problems.append("docs/rule-ownership.md is missing — run `make rule-ownership`")
    if problems:
        print("[FAIL] rule-ownership inventory:")
        for p in problems:
            print(f"  - {p}")
        return 1
    word, n_word, bullets = interface_count(data)
    print(f"[OK] rule ownership consistent: {len(data['families'])} families, "
          f"each single-owner with no bare non-owner restatement; the I-D lists "
          f"{bullets} interfaces and its prose says {word!r}.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="rule-ownership renderer/checker")
    ap.add_argument("--render", action="store_true",
                    help="regenerate docs/rule-ownership.md from the JSON")
    args = ap.parse_args()
    return cmd_render() if args.render else cmd_check()


if __name__ == "__main__":
    sys.exit(main())
