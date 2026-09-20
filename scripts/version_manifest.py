#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""R-01 version-matrix consistency checker (`make versions`).

`versions.json` is the single source of truth for the CURRENT version of every
normative artefact. This tool resolves every declared *binding* — the exact place
a version value is written (a schema `const`, a schema title, a CDDL body line, a
sample `projection.version`, the OpenAPI `info.version`, a README table cell, the
TS change-history top row) — and asserts each equals its dimension's `value`.

It exits non-zero on ANY mismatch, so it fails when the manifest OR any single
artefact is changed independently (R-01 acceptance). It is the one command that
"reports the same current versions across every normative artefact".

Pure extractors (`extract_json`, `extract_text`) take content, not paths, so the
negative fixture can reproduce a drift (e.g. a doctored README cell) without
touching the tree. Run: `make versions`.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "versions.json"


def load_manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _dig(obj, dotted):
    """Follow a dotted path through dict keys / list indices."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def extract_json(binding, content):
    """Resolve a `json` binding against decoded JSON `content`."""
    value = _dig(content, binding["path"])
    if not isinstance(value, str):
        value = str(value)
    pattern = binding.get("pattern")
    if pattern:
        m = re.search(pattern, value)
        if not m:
            raise LookupError(f"pattern {pattern!r} did not match value {value!r}")
        return m.group(1)
    return value


def extract_text(binding, content):
    """Resolve a `text` binding against raw file `content`."""
    m = re.search(binding["pattern"], content, re.MULTILINE)
    if not m:
        raise LookupError(f"pattern {binding['pattern']!r} did not match in {binding['file']}")
    return m.group(1)


def observe(root, binding):
    """Read the bound file and return the observed version string."""
    text = (root / binding["file"]).read_text(encoding="utf-8")
    if binding["kind"] == "json":
        return extract_json(binding, json.loads(text))
    if binding["kind"] == "text":
        return extract_text(binding, text)
    raise ValueError(f"unknown binding kind: {binding['kind']!r}")


# R3-09: the bindings above check ONE occurrence each. An ACTIVE, reader-visible
# claim elsewhere in the same file was invisible to the gate — ICS row 191 stated
# the companion contracts at "(v1.0.0)" and "evidence-2.6" against actual 2.0.0
# and 2.7 while `make versions` reported 74 bindings consistent. DR-13 bound one
# paragraph; this is the same defect one artefact over, so the fix is a SWEEP
# rather than another single binding.
#
# The discriminator is grammatical, not positional, and a regex cannot guess it:
#
#     "the surfaces ARE published contracts (v1.0.0)"   <- a current claim
#     "as-of BW-MEMBER reads (SINCE EDD contract v1.4.0)" <- provenance
#
# So provenance is MARKED rather than inferred. A version token in an active
# conformance row must be either the current value or explicitly introduced by
# "since"/"as of"/"introduced in"/"added in". History TABLES are out of scope
# entirely: a changelog row correctly records what was true then, and sweeping
# it would force us to falsify the record.
SWEEP_TOKEN = re.compile(
    r"(?:companion |EDD )?[Cc]ontracts?\s*\(?v?(\d+\.\d+\.\d+)\)?"
    r"|evidence[- ](\d+\.\d+)")
SWEEP_PROVENANCE = re.compile(r"\b(since|as of|introduced in|added in)\s*\S*\s*$", re.I)
# Active conformance rows: the ICS pro forma, whose first cell is a row number.
# The revision history's first cell is a TS version (`| v0.31 |`), so the two
# are distinguishable without a heuristic.
SWEEP_ACTIVE_ROW = re.compile(r"^\|\s*\d+\s*\|")


# R4-07: the sweep above reads ICS ROWS. The normative umbrella states its
# current values in PROSE — "Field definitions (v2.4)", `version` = `"2.4"`,
# "Full field list (v2.4)" — so every one of them was invisible to it, and
# §8.2/§8.3/§8.4 sat three, two and two versions behind a green gate. That is
# R3-09 one artefact over for the second time, which is why this generalises
# the mechanism instead of adding a third special case.
#
# The DOCUMENT TYPE is read from the section heading — `### 8.3 BW-ORG-v1 ...`
# already says which document the clause defines — rather than restated in a
# map beside it. Anything restated by hand drifts; that is the whole finding.
SECTION_TYPE = re.compile(r"^#{2,4}\s+\S+\s+(BW-(?:MED|ORG|MEMBER))-v1\b")
# A version token, with whatever names its dimension immediately before it.
SECTION_TOKEN = re.compile(r"(evidence|application envelope)?\s*\(?v?\"?"
                           r"(\d+\.\d+)\"?\)?", re.I)
SECTION_DIMENSION = {"BW-MED": "discovery_bw_med", "BW-ORG": "discovery_bw_org",
                     "BW-MEMBER": "discovery_bw_member"}
# Which claims are swept: a claim ABOUT THE DOCUMENT'S OWN VERSION. Inside
# §8.3, "evidence 2.4 — F-08" is a claim about a different dimension and
# "quorum:n" is not a version at all, so the token must be introduced by one of
# these forms rather than merely appear.
# The marker may sit BETWEEN the label and the version — "Field definitions as
# of v2.4" is how a historical note actually reads — and SWEEP_PROVENANCE is
# anchored to what precedes the match, so it cannot see one inside it.
SECTION_PROVENANCE = re.compile(r"\b(since|as of|introduced in|added in)\b", re.I)
SECTION_CLAIM = re.compile(
    r"(?:Field definitions|Full field list|`version`\s*=|version\s*=\s*`?\"?)"
    r"[^.\n]{0,24}?\(?v?\"?(\d+\.\d+)", re.I)


def sweep_section_claims(root, manifest):
    """Return [(file, line_no, claimed, expected, dimension)] for current
    prose claims about a discovery document's own version that disagree with
    the manifest. History is EXCLUDED the same way as above — an explicit
    provenance marker — because a changelog row correctly records what was
    true then, and sweeping it would force us to falsify the record."""
    dims = manifest["dimensions"]
    findings = []
    for rel in manifest.get("active_claim_sweep", []):
        if not rel.endswith(".md"):
            continue
        section = None
        for n, line in enumerate((root / rel).read_text(encoding="utf-8")
                                .splitlines(), 1):
            head = SECTION_TYPE.match(line)
            if line.startswith("#"):
                section = head.group(1) if head else None
                continue
            if section is None or line.lstrip().startswith("|"):
                continue              # outside a document clause, or a table row
            dim = SECTION_DIMENSION[section]
            expected = dims[dim]["value"]
            for m in SECTION_CLAIM.finditer(line):
                if (SWEEP_PROVENANCE.search(line[:m.start()])
                        or SECTION_PROVENANCE.search(m.group(0))):
                    continue          # explicitly historical
                if m.group(1) != expected:
                    findings.append((rel, n, m.group(1), expected, dim))
    return findings


def sweep_active_claims(root, manifest):
    """Return [(file, line_no, token)] for stale UNMARKED version claims."""
    dims = manifest["dimensions"]
    # DELIBERATELY NARROW, and not a restatement of `versions.json`: these are
    # the streams whose values appear in the swept files as free-standing
    # version TOKENS ("contract v1.12.0", "evidence 2.8"). Deriving the set
    # from every dimension bound in a swept file was tried and rejected — the
    # umbrella paragraph binds nearly all of them, so the accepted set would
    # grow from four values to eleven and a stale "2.1" or "1.0" anywhere in
    # these files would stop being reported. A narrower set fails closed.
    #
    # The cost is that adding a CONTRACT stream means adding it here too, and
    # that cost is real: the federation register was bound correctly in
    # `versions.json`, stated correctly in the paragraph, green under
    # `make versions` — and still reported stale, because this line had not
    # been extended. If a third contract stream arrives, it belongs here.
    current = {dims["companion_contracts"]["value"], dims["evidence"]["value"],
               dims["edd_openapi"]["value"].lstrip("v"),
               dims["federation_register_openapi"]["value"].lstrip("v"),
               dims["ts"]["value"].lstrip("v")}
    findings = []
    for rel in manifest.get("active_claim_sweep", []):
        path = root / rel
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if rel.endswith(".md") and not SWEEP_ACTIVE_ROW.match(line):
                continue                      # prose outside the ICS table
            for m in SWEEP_TOKEN.finditer(line):
                value = m.group(1) or m.group(2)
                if value in current:
                    continue
                if SWEEP_PROVENANCE.search(line[:m.start()]):
                    continue                  # explicitly historical
                findings.append((rel, n, m.group(0)))
    return findings


# D11-02: the documents a reader meets FIRST state versions in running prose,
# outside any bound cell and outside the ICS rows the sweep above reads. The
# README said "evidence `version` 1.15" and "BW-ORG 1.4" as though current, and
# that a network may "run evidence 2.7"; the explainers said "evidence objects
# v2.0". Every one was green. These files are swept LINE BY LINE, for the same
# narrow token set, and a claim passes only if it is current or explicitly
# marked as history ("introduced in", "since", "as of", "added in").
PROSE_TOKEN = re.compile(SWEEP_TOKEN.pattern
                         + r"|evidence\s+(?:objects\s+)?`?version`?\s+v?(\d+\.\d+)"
                         + r"|evidence objects v(\d+\.\d+)"
                         # DOC-02: "evidence v2.0" matched none of the above.
                         + r"|evidence\s+v(\d+\.\d+)")


def prose_sweep_files(root, manifest):
    """The files the prose sweep reads: `active_prose_sweep` entries, globs
    expanded, less the historical records named in `prose_sweep_historical`
    (excluded by path, never edited to pass — DOC-02)."""
    historical = set((manifest.get("prose_sweep_historical") or {}).get("paths", []))
    out = []
    for entry in manifest.get("active_prose_sweep", []):
        paths = sorted(root.glob(entry)) if any(c in entry for c in "*?[") else [root / entry]
        for path in paths:
            rel = path.relative_to(root).as_posix()
            if rel not in historical and rel not in out:
                out.append(rel)
    return out


def sweep_active_prose(root, manifest):
    """Return [(file, line_no, token)] for stale unmarked version claims in
    the reader-facing prose listed under `active_prose_sweep`."""
    dims = manifest["dimensions"]
    current = {dims["companion_contracts"]["value"], dims["evidence"]["value"],
               dims["edd_openapi"]["value"].lstrip("v"),
               dims["federation_register_openapi"]["value"].lstrip("v"),
               dims["ts"]["value"].lstrip("v")}
    findings = []
    for rel in prose_sweep_files(root, manifest):
        for n, line in enumerate((root / rel).read_text(encoding="utf-8")
                                 .splitlines(), 1):
            for m in PROSE_TOKEN.finditer(line):
                value = next(g for g in m.groups() if g)
                if value in current or SWEEP_PROVENANCE.search(line[:m.start()]):
                    continue
                findings.append((rel, n, m.group(0)))
    return findings


def check(root, manifest):
    """Return (rows, mismatches). rows = (dim, file, observed, expected, ok)."""
    rows, mismatches = [], []
    for dim, spec in manifest["dimensions"].items():
        expected = spec["value"]
        for b in spec["bindings"]:
            try:
                observed = observe(root, b)
                ok = observed == expected
            except (LookupError, KeyError, IndexError, ValueError,
                    json.JSONDecodeError, FileNotFoundError) as e:
                observed, ok = f"<error: {e}>", False
            rows.append((dim, b["file"], observed, expected, ok))
            if not ok:
                mismatches.append((dim, b["file"], observed, expected))
    return rows, mismatches


def main():
    manifest = load_manifest()
    rows, mismatches = check(ROOT, manifest)
    stale = sweep_active_claims(ROOT, manifest) + sweep_active_prose(ROOT, manifest)
    drifted = sweep_section_claims(ROOT, manifest)
    width = max((len(d) for d, *_ in rows), default=10)
    last_dim = None
    for dim, f, observed, expected, ok in rows:
        head = dim if dim != last_dim else ""
        last_dim = dim
        mark = "✓" if ok else "✗"
        print(f"{head:<{width}}  {mark} {observed:<12} {f}")
    print()
    if mismatches:
        print(f"[FAIL] {len(mismatches)} version binding(s) disagree with versions.json:")
        for dim, f, observed, expected in mismatches:
            print(f"  - {dim}: {f} has {observed!r}, manifest says {expected!r}")
        return 1
    if drifted:
        print(f"[FAIL] {len(drifted)} current normative prose claim(s) state a "
              "discovery document's version wrongly (R4-07):")
        for f, n, claimed, expected, dim in drifted:
            print(f"  - {f}:{n}: says {claimed!r}, {dim} is {expected!r}")
        return 1
    if stale:
        print(f"[FAIL] {len(stale)} ACTIVE version claim(s) are stale (R3-09) — "
              "either update them, or mark them as history with "
              "'since'/'as of'/'introduced in':")
        for f, n, token in stale:
            print(f"  - {f}:{n}: {token!r}")
        return 1
    n = sum(len(s["bindings"]) for s in manifest["dimensions"].values())
    swept = len(manifest.get("active_claim_sweep", []))
    print(f"[OK] version matrix consistent: {n} bindings across "
          f"{len(manifest['dimensions'])} dimensions agree with versions.json; "
          f"active claims swept in {swept} artefact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
