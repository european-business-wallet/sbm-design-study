#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""A CDDL block quoted in a document says what `cddl/sm-mls-erd.cddl` says.

The Internet-Draft embeds five CDDL blocks so a reader meets the wire format
where the rule is explained rather than in an appendix. Nothing compared them
with the normative file, and they had drifted:

  * the manifest block said `digest: hash` — a type the per-field digest domains
    REMOVED on 27 September 2026 — where the file says `raw-hash`, and its
    comment described the value as `{ alg, hex }`, the reduced form the prose two
    lines above forbids by name;
  * `sm-evidence-artifact` was embedded TWICE with two different bodies, and one
    of them named `cose-sign1`, which the normative file does not define at all.

This is the failure mode the profile has met before and named: agreement between
copies is not correctness, and here the copies did not even agree. A reader
building an implementation from the draft — which is what a draft is for — would
have been building from the wrong definition, with every other gate green,
because the gates read the file and the reader reads the document.

Three checks, and an exception that has to be written down:

  1. a rule DEFINED in a block and also defined in the file must be identical
     after comments and whitespace are dropped;
  2. every rule name a block REFERENCES must be defined in the file, or be a
     CDDL prelude type, or be defined by the block itself;
  3. one rule must not be defined twice, in any two blocks, with two bodies.

A block that is deliberately illustrative — the two commitment blocks name their
elements (`salt`, `content_class`) and give the real types in trailing comments,
because the point there is which value goes in which position — declares itself
with a `; ILLUSTRATIVE — <reason>` line. Checks 1 and 2 are relaxed for such a
block; check 3 is not, and the domain-separation tag it carries is still compared
with the file, because a wrong tag is the one error such a block can make that
silently breaks every verifier.

Documents declared as historical records in `versions.json`
(`prose_sweep_historical`) are skipped: they record what was said at the time,
which is the same rule `doc_lint` applies to their prose.

Run by `make cddl-check`, beside the gate that validates the samples.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CDDL = ROOT / "cddl" / "sm-mls-erd.cddl"
BLOCK = re.compile(r"^(?:~~~|```)\s*cddl\s*\n(.*?)^(?:~~~|```)\s*$", re.S | re.M)
ASSIGN = re.compile(r"^([a-z][a-z0-9_-]*)\s*=", re.M)
IDENT = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]*")
ILLUSTRATIVE = re.compile(r";\s*ILLUSTRATIVE\s*[—-]\s*(\S.*)")

# RFC 8610 prelude and the control operators a block may use without the file
# defining them.
PRELUDE = {
    "any", "uint", "nint", "int", "bstr", "bytes", "tstr", "text", "tdate",
    "time", "number", "biguint", "bignint", "bigint", "integer", "unsigned",
    "decfrac", "bigfloat", "eb64url", "eb64legacy", "eb16", "encoded-cbor",
    "uri", "b64url", "b64legacy", "regexp", "mime-message", "cbor-any",
    "float16", "float32", "float64", "float16-32", "float32-64", "float",
    "false", "true", "bool", "nil", "null", "undefined", "size", "bits", "cbor",
    "cborseq", "within", "and", "default", "lt", "le", "gt", "ge", "eq", "ne",
}


def scanned():
    """The documents whose CDDL blocks are held to the file."""
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    historical = set(manifest.get("prose_sweep_historical", {}).get("paths", []))
    out = []
    for pattern in ("*.md", "ietf/*.md", "etsi/*.md", "docs/**/*.md"):
        for path in sorted(ROOT.glob(pattern)):
            rel = path.relative_to(ROOT).as_posix()
            if rel in historical or rel.startswith("docs/reviews/") or rel == "CHANGELOG.md":
                continue
            out.append(path)
    return out


def rules(text):
    """{name: normalised body} for every rule a CDDL text defines.

    A rule runs to the next line that starts a new assignment, so a multi-line
    map or array body is kept whole. Comments and runs of whitespace go, because
    a comment is prose and a line break is layout — neither changes the type.
    """
    starts = [(m.group(1), m.start()) for m in ASSIGN.finditer(text)]
    out = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(text)
        body = text[start:end].split("=", 1)[1]
        body = "\n".join(line.split(";")[0] for line in body.splitlines())
        out[name] = _layout(body)
    return out


def _layout(s):
    """Whitespace that is layout, removed; whitespace that is syntax, kept.

    A document wraps a rule to fit a column and a file does not, so
    `[ + manifest-part ]` and `[+ manifest-part]` are one type written twice.
    Spaces inside brackets and after an occurrence indicator are layout. The
    space in `bstr .size 16` is not touched, because a control operator's
    operand is not layout.
    """
    s = re.sub(r"\s+", " ", s).strip().rstrip(",")
    s = re.sub(r"([\[\{])\s+", r"\1", s)
    s = re.sub(r"\s+([\]\}])", r"\1", s)
    s = re.sub(r",(\s*[\]\}])", r"\1", s)      # a trailing comma is optional syntax
    return re.sub(r"([+*?])\s+", r"\1", s)


def tags(text):
    """The domain-separation tag literals a text carries, e.g. `sm-mls:...:v2`."""
    return set(re.findall(r'"(sm-mls:[^"]+)"', text))


def problems():
    file_rules = rules(CDDL.read_text(encoding="utf-8"))
    file_text = CDDL.read_text(encoding="utf-8")
    out = []
    seen = {}                                   # rule -> (where, body)
    for path in scanned():
        rel = path.relative_to(ROOT).as_posix()
        for n, block in enumerate(BLOCK.findall(path.read_text(encoding="utf-8")), 1):
            where = f"{rel} block {n}"
            illustrative = ILLUSTRATIVE.search(block)
            defined = rules(block)
            for name, body in defined.items():
                # (3) two copies of one rule may not disagree — illustrative or not.
                if name in seen and seen[name][1] != body:
                    out.append(f"{where}: `{name}` is also defined at {seen[name][0]} with a "
                               f"different body — one rule, two copies, and they disagree")
                seen.setdefault(name, (where, body))
                if illustrative:
                    continue
                # (1) a rule the file also defines must be the file's rule.
                if name in file_rules and file_rules[name] != body:
                    out.append(f"{where}: `{name}` differs from cddl/sm-mls-erd.cddl\n"
                               f"    document: {body}\n"
                               f"    file    : {file_rules[name]}")
            if illustrative:
                # A tag is the one thing such a block cannot get wrong quietly.
                for tag in tags(block) - tags(file_text):
                    out.append(f"{where}: domain-separation tag {tag!r} is not in "
                               "cddl/sm-mls-erd.cddl — an illustrative block may name its "
                               "elements, never a tag no verifier computes")
                continue
            # (2) every name a block references must exist somewhere real.
            known = set(file_rules) | set(defined) | PRELUDE
            # A map member's KEY is a name this profile chose, not a type it
            # references: `part_id: tstr` references `tstr` and defines nothing.
            # A first draft of this check read both sides of the colon and
            # reported every field name in the manifest as an undefined rule.
            body_text = "\n".join(line.split(";")[0] for line in block.splitlines())
            body_text = re.sub(r"^\s*\??\s*[a-zA-Z][a-zA-Z0-9_-]*\s*:", "", body_text,
                               flags=re.M)
            for ident in IDENT.findall(re.sub(r'"[^"]*"', "", body_text)):
                if ident not in known and not ident.isdigit():
                    out.append(f"{where}: references `{ident}`, which "
                               "cddl/sm-mls-erd.cddl does not define")
    return out


def main():
    found = problems()
    for one in found:
        print(f"[FAIL] {one}")
    if found:
        print(f"\n{len(found)} embedded CDDL problem(s). A reader builds from the document; "
              "the gates read the file. Where the two differ, the document wins for the "
              "implementer and loses for the conformance suite.")
        return 1
    blocks = sum(len(BLOCK.findall(p.read_text(encoding="utf-8"))) for p in scanned())
    print(f"[OK] {blocks} embedded CDDL block(s) agree with cddl/sm-mls-erd.cddl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
