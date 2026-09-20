#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: CC-BY-4.0
"""R8-05 requirement 2 — THE EXECUTABLE INVENTORY of provider-identity fields.

R7-04 made `RdpId` one precise definition and pointed the evidence Schemas at
it. The test that guarded the result asked whether each schema MENTIONS
`RdpId` and whether any restates the grammar — and a field declared
`{"type": "string"}` does neither, so it passed while saying nothing. That is
the round-4 corollary again: *a gate asserting `at least one` measures
existence, not coverage.*

This walks every published contract and Schema, finds every field whose NAME
makes it an RDP identifier, and asks the only question that matters: **is this
declaration a `$ref` to the one definition?** Anything else — an unconstrained
string, a local pattern, a near-miss copy — is reported.

Reproducing the round-8 finding with it turned up SIX occurrences where the
review named three: `AcceptanceRecord.issuing_rdp_id`, the relay request's
`origin_rdp_id` and the acknowledgement path parameter, PLUS
`evidence-ep.schema.json`'s `rdp_chain[].rdp_id` and both of
`evidence-relay.schema.json`'s `sending_rdp_id` / `receiving_rdp_id` — two of
them in evidence Schemas the review recorded as already canonical, because the
old gate only ever looked at top-level `rdp_id`.

    python3 scripts/rdp_identity_inventory.py          # verify
    python3 scripts/rdp_identity_inventory.py --list    # print the inventory
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A field is a provider identity if its NAME says so. `bw-med`'s `rdp` object
# (discovery and evidence URLs) is not an identifier and is not matched.
#
# `participant_id` joined the pattern in the federation cycle (Batch A), found
# by that cycle's own closure verification: the membership register and the
# provider descriptor name a provider in THE SAME value space under a different
# field name, and this inventory — the instrument whose job is to see every such
# declaration — could not see either of them. Both happened to be `$ref`s, which
# is exactly why it mattered: a gate that passes because the code is right, not
# because the gate looked, is the round-4 corollary this file was written to
# close. The three occurrences were checked for collision before widening: all
# three are provider identities, and no other document uses the name.
IS_RDP_ID = re.compile(r"(^|_)(rdp_id|participant_id)$")

# The one definition, by every spelling a `$ref` may legitimately use.
CANONICAL_REFS = {
    "evidence-common.schema.json#/$defs/RdpId",
    "schemas/evidence-common.schema.json#/$defs/RdpId",
    "https://bw.example.eu/schemas/evidence-common.schema.json#/$defs/RdpId",
}

def _contracts():
    """The published contracts, taken from `openapi_validate` rather than
    restated.

    This was a copy of that list, and A1 published a fifth contract into one of
    them and not the other — so the register's two `participant_id`
    declarations were outside this inventory for four commits, invisible for
    the same reason the round-8 defect was: the instrument was not looking.
    `openapi_validate.CONTRACTS` already carries the rule ("a contract absent
    from this list is a contract nothing validates"), which makes it the one
    place a new contract must be named (invariant 7).
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from openapi_validate import CONTRACTS as _c
    return list(_c)


def _declarations(node, path, src, out):
    """Every (source, pointer, declaration) whose field name is an RDP id."""
    if isinstance(node, dict):
        # OpenAPI parameter objects name the field in `name`, not as the key.
        if isinstance(node.get("name"), str) and IS_RDP_ID.search(node["name"]) \
                and isinstance(node.get("schema"), dict):
            out.append((src, f"{path}({node['name']})", node["schema"]))
        for k, v in node.items():
            if isinstance(k, str) and IS_RDP_ID.search(k) \
                    and isinstance(v, dict) and ("type" in v or "$ref" in v):
                out.append((src, f"{path}.{k}", v))
            _declarations(v, f"{path}.{k}", src, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _declarations(v, f"{path}[{i}]", src, out)


def inventory():
    import yaml
    out = []
    for name in _contracts():
        p = ROOT / name
        if p.exists():
            _declarations(yaml.safe_load(p.read_text(encoding="utf-8")), "",
                          name, out)
    for p in sorted((ROOT / "schemas").glob("*.json")):
        _declarations(json.loads(p.read_text(encoding="utf-8")), "",
                      f"schemas/{p.name}", out)
    return out


def verdict(decl):
    """`ok`, or why this declaration is not the one definition."""
    if decl.get("$ref") in CANONICAL_REFS:
        return None
    if "$ref" in decl:
        return f"$ref to {decl['$ref']!r}, which is not the shared definition"
    if decl.get("pattern"):
        return (f"a LOCAL pattern {decl['pattern']!r} — a second statement of "
                "one grammar, and the two drift")
    return ("an unconstrained %r — the identifier controlling idempotency and "
            "receipt namespaces has no value space here"
            % decl.get("type", "declaration"))


def check():
    return [(src, ptr, why) for src, ptr, decl in inventory()
            if (why := verdict(decl)) is not None]


def main(argv):
    if "--list" in argv:
        for src, ptr, decl in inventory():
            state = verdict(decl)
            print(f"{'[OK ]' if state is None else '[BAD]'} {src:34} {ptr}")
        return 0
    problems = check()
    for src, ptr, why in problems:
        print(f"[FAIL] {src}: {ptr} is {why}")
    if problems:
        print(f"\n{len(problems)} provider-identity field(s) do not $ref the "
              "one definition. `RdpId` is ONE value space (R7-X1/R8-05): a "
              "boundary that restates it admits values the reference rejects.")
        return 1
    total = len(inventory())
    print(f"[OK] {total} provider-identity field(s) all $ref the one "
          "`RdpId` definition")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
