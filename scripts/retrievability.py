#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""G3, part one — what must stay retrievable for a verdict to stay reachable.

The agenda's G3 asks who holds the retained evidence after a provider migrates or
exits. Answering it needed a prior question answered first, and nothing in the
tree answered it: *which material does a verification actually depend on, and who
serves it?*

Every check this repository performs reads material the verifier was **handed**.
No linter dereferences a URL; nothing consults live state. `test_lifecycle_claims`
demonstrates the strong form — rewrite every endpoint in an entity's discovery
document to a different provider and the bundle verifies unchanged. That property
is why `docs/lifecycle-and-custody.md` §1 can say "unaffected" so often, and it is
exactly why custody is the open question: a verdict is only as durable as
somebody's willingness to keep answering the read that supplies its inputs.

So this renders `docs/retrievability.json` to a document, and gates the registry
against three things the tree already states machine-readably, so no input can be
added without saying who keeps it retrievable:

  XREP is about surfaces agreeing; this is about material remaining reachable.

  RETR-01  every retained-material argument of `bundle_lint.check_bundle`
           appears in the registry. A verifier input nobody has described is an
           undocumented custody dependency.
  RETR-02  every declared incomplete-verification residual (`LINT-BND-I*`) is
           claimed by some row. Those rules exist precisely to say "the material
           to decide is absent" — so each must name whose material it was.
  RETR-03  every published read that takes an as-of selector (`as_of`,
           `version`, `doc_digest`, `epoch`) appears in some row's `operation`.
           A historical read nobody depends on is dead surface; one that is
           depended on and undeclared is the gap this whole document is about.

What the registry then shows, and what makes it worth generating: of the reads
that supply historical material, exactly one — the federation register's
`GET /participants/{id}?as_of=` — is served by a party that is *not* the exiting
provider. Every other historical read is served by the entity's own provider, and
a provider exit leaves no published successor. The failure is graceful (the
verdict degrades to INCOMPLETE, never to a silent pass), which is why this is a
specification gap and not a defect — but it is the gap, and it is now written
down per input rather than as one sentence of prose.

`--render` regenerates the Markdown; bare invocation checks and is wired into
`make conformance`.
"""
import argparse
import inspect
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

REGISTRY = ROOT / "docs" / "retrievability.json"
MD = ROOT / "docs" / "retrievability.md"

#: Arguments of `check_bundle` that are NOT retained material, with the reason.
NOT_MATERIAL = {
    "entity": "the UID being verified — the subject of the question, not evidence",
}

#: The selectors that make a published read a HISTORICAL read.
AS_OF_SELECTORS = ("as_of", "version", "doc_digest", "epoch")


def load():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def verifier_inputs():
    """Every retained-material argument `check_bundle` accepts."""
    import bundle_lint
    names = [n for n, p in inspect.signature(bundle_lint.check_bundle).parameters.items()
             if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
    return [n for n in names if n not in NOT_MATERIAL]


def declared_residuals():
    """The LINT-BND-I* rules — the tree's own list of "the material is absent"."""
    catalogue = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text(encoding="utf-8"))
    return sorted(r["id"] for r in catalogue["rules"]
                  if re.fullmatch(r"LINT-BND-I\d+", r["id"]))


def historical_reads():
    """Every published operation taking an as-of selector: path -> selectors."""
    import yaml
    found = {}
    for contract in sorted(ROOT.glob("*.yaml")):
        doc = yaml.safe_load(contract.read_text(encoding="utf-8"))
        for path, item in (doc.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            shared = item.get("parameters") or []
            for method, op in item.items():
                if not isinstance(op, dict) or method == "parameters":
                    continue
                names = {p.get("name") for p in list(shared) + list(op.get("parameters") or [])
                         if isinstance(p, dict)}
                selectors = sorted(n for n in names if n in AS_OF_SELECTORS)
                if selectors:
                    found[path] = selectors
    return found


def check(data):
    findings = []
    rows = data["inputs"]
    declared = {row["input"] for row in rows}

    for name in verifier_inputs():
        if name not in declared:
            findings.append(
                f"RETR-01 `check_bundle` takes `{name}` and the registry does not "
                "describe it — a verifier input nobody has described is an "
                "undocumented custody dependency. Add a row, or record it in "
                "NOT_MATERIAL with the reason it is not retained material")

    claimed = {r for row in rows for r in row.get("residuals") or []}
    for rule in declared_residuals():
        if rule not in claimed:
            findings.append(
                f"RETR-02 {rule} says the material to decide is absent, and no "
                "registry row claims it — the rule does not say WHOSE material, "
                "so nothing records who would have to keep it retrievable")

    operations = " ".join(row.get("operation", "") for row in rows)
    for path, selectors in sorted(historical_reads().items()):
        if path not in operations:
            findings.append(
                f"RETR-03 {path} takes the historical selector(s) {selectors} and no "
                "registry row depends on it — either a verification needs it and "
                "the row is missing, or the operation is surface nothing reads")

    for row in rows:
        for field in ("material", "operation", "served_by", "absent"):
            if not str(row.get(field, "")).strip():
                findings.append(f"RETR-01 row {row.get('input')!r} does not state `{field}`")
        if not isinstance(row.get("survives_provider_exit"), bool):
            findings.append(
                f"RETR-01 row {row.get('input')!r} does not say whether it survives a "
                "provider exit — the question this registry exists to answer")
    return findings


def render_md(data):
    rows = data["inputs"]
    broken = [r for r in rows if not r["survives_provider_exit"]]
    # REUSE-IgnoreStart — the licence header this GENERATES, not this file's own.
    out = [
        "<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->",
        "<!-- SPDX-License-Identifier: CC-BY-4.0 -->",
        # REUSE-IgnoreEnd
        "<!-- GENERATED by scripts/retrievability.py from docs/retrievability.json."
        " Do not edit by hand. -->",
        "",
        "# What must stay retrievable",
        "",
        "Every check in this repository reads material a verifier was **handed**. No",
        "linter dereferences a URL and nothing consults live state — rewrite every",
        "endpoint in an entity's discovery document to a different provider and a bundle",
        "verifies unchanged (`tests/test_lifecycle_claims.py`). That is why",
        "[`lifecycle-and-custody.md`](lifecycle-and-custody.md) §1 can say *unaffected*",
        "so often, and exactly why custody is the open question: a verdict is only as",
        "durable as somebody's willingness to keep answering the read that supplies it.",
        "",
        f"Of the {len(rows)} inputs a retained-evidence verification can take,",
        f"**{len(broken)} depend on material a provider exit leaves with no named",
        "server**. No absence turns into a silent pass — but the consequences differ,",
        "and each row below says which one applies. A REQUIRED input leaves a stated",
        "property unproven, and where a residual rule names it the verdict is reported",
        "INCOMPLETE. An OPTIONAL opening simply stays unopened, which is not a gap.",
        "And where a current binding can stand in for a historical one, the answer",
        "quietly becomes a question about today rather than about the act. So this is",
        "a specification gap and not a defect — the gap [G3](REVIEW_AGENDA.md) names —",
        "and saying which kind of absence each input has is part of stating it.",
        "",
        "Generated from `docs/retrievability.json` and gated: every argument",
        "`bundle_lint.check_bundle` accepts, every `LINT-BND-I*` residual and every",
        "published read taking an as-of selector must appear below.",
        "",
        "## Per input",
        "",
        "| Input | Retrieved by | Served by | Survives a provider exit |",
        "|---|---|---|---|",
    ]
    for row in rows:
        mark = "yes" if row["survives_provider_exit"] else "**no**"
        out.append(f"| `{row['input']}` | {row['operation']} | {row['served_by']} | {mark} |")
    out += ["", "## What each absence does to the verdict", ""]
    for row in rows:
        out.append(f"**`{row['input']}`** — {row['material']}")
        out.append("")
        out.append(f"- *Absent:* {row['absent']}")
        if row.get("residuals"):
            out.append(f"- *Declared residual:* {', '.join(row['residuals'])}")
        if row.get("note"):
            out.append(f"- {row['note']}")
        out.append("")
    out += [
        "## The shape that works",
        "",
        "One historical read is served by a party that is not the exiting provider: the",
        "federation register's `GET /participants/{participant_id}?as_of=`, held by the",
        "Federation Authority. Admission history therefore survives an exit for the same",
        "reason evidence does — a second, independent holder by design. Every other",
        "historical read is served by the entity's own provider, and no record carries a",
        "pointer to who answers for acts before a move.",
        "",
        "Specifying that pointer, and the fate of every in-flight item at exit, is the",
        "part of G3 this document does not attempt. It is recorded as an open item so a",
        "wire-visible change is taken deliberately rather than bundled into an analysis.",
        "",
    ]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="retrievability registry renderer/checker")
    ap.add_argument("--render", action="store_true",
                    help="regenerate docs/retrievability.md from the JSON")
    args = ap.parse_args()
    data = load()
    if args.render:
        MD.write_text(render_md(data), encoding="utf-8")
        print(f"rendered {MD.relative_to(ROOT)} from {REGISTRY.relative_to(ROOT)}")
        return 0
    findings = check(data)
    for line in findings:
        print(f"[FAIL] {line}")
    if MD.exists():
        if MD.read_text(encoding="utf-8") != render_md(data):
            findings.append("stale Markdown")
            print("[FAIL] docs/retrievability.md is stale — run "
                  "`python scripts/retrievability.py --render`.")
    else:
        findings.append("missing Markdown")
        print("[FAIL] docs/retrievability.md is missing.")
    if findings:
        return 1
    rows = data["inputs"]
    exposed = sum(1 for r in rows if not r["survives_provider_exit"])
    print(f"retrievability: {len(rows)} verification inputs described, "
          f"{len(declared_residuals())} declared residual(s) claimed, "
          f"{exposed} depend on material a provider exit leaves unserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
