#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regression guard (make doc-lint): no pre-inversion mechanism tokens in prose.

After the octet-authoritative inversion (PR #18) JCS was removed from every
signing path and the in-document `doc_cose_b64` seal field was replaced by the
COSE_Sign1 artefact (`sm_artifact_b64` over the deterministic-CBOR payload).
This guard fails if a document reintroduces JCS / RFC 8785 as the CURRENT
canonicalisation, or the removed `*_cose_b64` document fields, as prose. It
scans the spec-facing prose across the Markdown documents AND the human-readable
`description`/comment strings of the machine-layer spec artefacts (the JSON
Schemas, the CDDL, the EDD OpenAPI) — a stale schema `description` is as
misleading to a reader as a stale paragraph.

Scope: the unambiguous mechanism tokens only — NOT version numbers, which carry
legitimate historical "landed at 1.x" anchors (those are `make versions`'s).
Run: `make doc-lint`, one of the gates of `make conformance`. *This docstring
said it was not wired into the bar; it has been for several rounds.*

FIGURES (DOC-01, documentation completeness review). The prose rules never read
an SVG, so an embedded figure taught the MSP-to-MSP relay, a JCS-centred digest
and DNS discovery while this gate stayed green. `scan_figures` now reads every
figure under docs/diagrams/: the text of each SVG (`<text>`, `<title>`,
`<desc>`) and of each Mermaid source (its drawn lines, not its `%%` comments),
plus each front matter's `question` and `alt`, against the prose rules and
the figure rules below. It also requires every figure SOURCE to carry a front
matter block (owner, source, question, profile, status, references, alt), and
every rendered EXPORT to be listed in docs/diagrams/exports.json with the
digests of its source and of itself — a source edited without re-rendering
fails. A figure whose front matter says `status: historical` is not
token-scanned; it must still say what it was.

LINKS (documentation completeness review, gate 3). Every relative link and
`#anchor` in the active Markdown — README, CONTRIBUTING, the umbrella and
every docs/*.md except the historical records `versions.json` names — must
resolve: the file exists, and an anchor into Markdown names a heading (by
GitHub's slug rule, duplicates numbered) or an explicit `{#id}`. A reading
path is only as good as its links.

Legitimate JCS references are allow-listed:
  - any lowercase optional-mode token `jcs-...` (`jcs-sha256`/`jcs-sha512` enum
    values and the descriptions of those `payload_hash` modes);
  - the glossary term "JSON Canonicalization Scheme";
  - change-history table rows ("| v0.x | ... |");
  - whole-file exemptions for the CHANGELOG, the licence notices and the design
    record, which discuss the removal / retain the reference for the mode.

See docs/OCTET_AUTHORITATIVE_DESIGN.md for the octet-authoritative model.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Whole-file exemptions: these legitimately discuss JCS removal or retain the
# RFC 8785 reference for the optional `jcs-sha256` mode.
EXEMPT = {
    # The round-2 review's own document. It QUOTES the defects it found —
    # that is what a finding's evidence section is — so every guard added to
    # stop a defect returning necessarily matches the record of that defect.
    # A received review record is not repository prose, and editing it to
    # satisfy our own linter would destroy its value as evidence.
    "docs/DESIGN_REVIEW_FINDINGS_HANDOFF.md",
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    "IPR.md",
    "docs/OCTET_AUTHORITATIVE_DESIGN.md",
    # Generated (docs/lint-catalogue.json -> scripts/lint_catalogue.py). A
    # faithful transcription of the reference tools, so it legitimately names
    # internal reconstructed field tokens (e.g. the discovery seal
    # `doc_cose_b64`) and verbatim message strings. Its integrity is guarded by
    # tests/test_lint_catalogue.py (completeness/phantom/drift), not doc-lint.
    "docs/lint-catalogue.md",
    # The design-findings backlog / decisions record quote the residues and
    # removed fields they report (F-01, D2 etc.).
    "docs/DESIGN_FINDINGS.md",
    "docs/DESIGN_DECISIONS.md",
}

# Files scanned: the Markdown documents plus the machine-layer spec artefacts
# whose description/comment strings are spec-facing prose.
SCAN_GLOBS = ["*.md", "docs/*.md", "docs/adr/*.md", "ietf/*.md", "etsi/*.md",
              "schemas/*.json", "cddl/*.cddl", "edd-resolver-openapi.yaml"]

# A line matching any of these presents a pre-inversion mechanism as current.
FORBIDDEN = [
    re.compile(r"doc_cose_b64"),
    re.compile(r"rdp_cose_b64"),
    re.compile(r"ep_cose_b64"),
    re.compile(r"JCS[- ]canonical", re.IGNORECASE),
    re.compile(r"JCS-SHA", re.IGNORECASE),
    re.compile(r"RFC\s*8785 canonical", re.IGNORECASE),
    re.compile(r"canonical JSON hashing", re.IGNORECASE),
    re.compile(r"re-?canonicali[sz]e[d]?\s+with\s+JCS", re.IGNORECASE),
    re.compile(r"\(JCS[/)]"),
    # X-33: key transparency is a ROADMAP item, not a delivered/assessable
    # production control. Guard against the over-claim returning as current prose.
    re.compile(r"key transparency applies", re.IGNORECASE),
    # DR-15/R2-M5: the floor is MANDATORY. The permissive phrasing — a member
    # MAY refuse a suite below its locally configured floor — protected only
    # those who configured one.
    re.compile(r"MAY refuse to join a group whose selected suite", re.IGNORECASE),
    re.compile(r"locally configured floor", re.IGNORECASE),
    # DR-06: ONE expiry rule — the event time bounds every grade. Neither the
    # removed availability exemption nor a restatement of it may return.
    re.compile(r"exempt from the post-dating rule", re.IGNORECASE),
    re.compile(r"MAY post-date `?expires_at`?", re.IGNORECASE),
    # DR-01: the transmitted-octet commitment covers the whole MLSMessage —
    # the PrivateMessage phrasing understates what is hashed.
    re.compile(r"SHA-256 of the exact MLS `?PrivateMessage`? octets"),
    # F-09: S2 is ONE event (the acknowledged handover) — the ambiguous dual
    # phrasing cannot return.
    re.compile(r"made available to, or retrieved by"),
    # X-23: the profile is attributable BY DESIGN — the inverted deniability
    # claim cannot return.
    re.compile(r"deniable to\s+third parties", re.IGNORECASE),
    # X-09: the heterogeneous-interoperability claim is SCOPED — the unscoped
    # "shall be compatible with the ... Common Services Interface" cannot return.
    re.compile(r"relay shall be compatible with the EN 319 522-2"),
    # X-14: DNS aliasing is removed (future study) — the mechanism cannot
    # silently return as current prose.
    re.compile(r"DNS TXT \+ SRV \+ SVCB"),
    # F-11: ONE core-directory signature format — the dual-format text is gone.
    re.compile(r"COSE_Sign1 or JWS", re.IGNORECASE),
    # D1/F-07: bilateral only — the multiparty allowance cannot return.
    re.compile(r"devices from three or more entities", re.IGNORECASE),
    # X-24: the epoch-change CE type was unobservable by its issuer — removed.
    re.compile(r"mls-reencryption-epoch-change"),
    # X-26: sender membership is the author MEMBER's device set — the
    # single-author-leaf model broke multi-device continuity.
    re.compile(r"only its (own )?author leaf", re.IGNORECASE),
    # X-06: a resolver never handles payloads — transport rerouting of an
    # in-flight message is invalid; only the sender re-addresses (new SE).
    re.compile(r"rerouted? by the resolver", re.IGNORECASE),
    # X-10: acceptance-policy evaluation has ONE owner — RDP(in) (TS clause 6).
    # Guard against the MSP-evaluates phrasing returning as current prose.
    re.compile(r"MSP[^.\n]{0,90}evaluates?[^.\n]{0,40}polic", re.IGNORECASE),
    re.compile(r"Key transparency\s*\|[^|]*\|\s*REQUIRED"),
    # F-01: the in-object seal container is GONE (M4) — the wire form is the
    # evidence artefact [cose-sign1, qualified-timestamp]; the projection carries
    # no seal field. Guard against the superseded container model returning.
    re.compile(r"seal\.cose_b64"),
    re.compile(r"seal[` ]+container", re.IGNORECASE),
    re.compile(r"minus the `?seal`?", re.IGNORECASE),
    # F-13/D2: the third-party EP-authority delegation is REMOVED — the
    # sender-side RDP always composes. Guard against the field returning.
    re.compile(r"ep_authority"),
    # DOC-01: the RDP handles the ciphertext too (it relays it with the SE);
    # "no plaintext" is not "no ciphertext".
    re.compile(r"[Mm]etadata and content hashes only"),
]

# DOC-01 — what the figures taught that the protocol does not do. Applied to
# figure text only: prose has its own rules above, and several of these words
# are legitimate in a historical paragraph.
FIGURE_FORBIDDEN = [
    re.compile(r"\bJCS\b"),                       # JCS as the current digest
    re.compile(r"RFC\s*8785"),
    re.compile(r"\bDNS(?:SEC)?\b"),               # DNS aliasing removed, umbrella §5.5
    re.compile(r"MSP\s*(?:↔|<->|->|→|-to-)\s*MSP", re.IGNORECASE),   # FED-X4
    re.compile(r"evidence metadata", re.IGNORECASE),                    # the relay carries ciphertext + SE
    re.compile(r"acceptance\s*/\s*quorum", re.IGNORECASE),             # policy is RDP(in)'s, not the MSP's
    re.compile(r"hashes\s*(?:&amp;|&|and)\s*metadata only", re.IGNORECASE),
    re.compile(r"(?:single|one) trust root", re.IGNORECASE),            # qualification ≠ admission
    re.compile(r"every credential, seal", re.IGNORECASE),
]

DIAGRAMS = ROOT / "docs" / "diagrams"
EXPORTS = DIAGRAMS / "exports.json"
FRONT_MATTER_KEYS = ("owner", "source", "question", "profile", "status",
                     "references", "alt")
STATUSES = ("current", "planned", "historical")

# A line containing any of these is legitimate and never flagged.
ALLOW = [
    # Any lowercase optional-mode token: the `jcs-sha256`/`jcs-sha512` enum
    # values and the descriptions of those modes. The stale current-mechanism
    # prose uses uppercase "JCS"/"JCS-canonical", never the lowercase mode form.
    re.compile(r"jcs-"),
    re.compile(r"JSON Canonicalization Scheme"),
    # Change-history table rows ("| v0.16 | 2026-07-21 | ... |") describe what
    # changed AT a past version and are historical by construction — they may
    # legitimately name the pre-inversion fields they replaced. ICS pro-forma
    # rows ("| 032 | ... |") start with a number, not "vX.Y", so are NOT allowed.
    re.compile(r"^\s*\|\s*v\d+\.\d+\s*\|"),
]
# (The umbrella's front-matter change summary had an exemption here. D10-07
# moved it to CHANGELOG.md, which is exempt as history, so the exemption was
# dead and has been deleted rather than left to excuse a line that no longer
# exists.)


def scan():
    seen = set()
    files = []
    for g in SCAN_GLOBS:
        for p in sorted(ROOT.glob(g)):
            rel = p.relative_to(ROOT).as_posix()
            if rel in EXEMPT or rel in seen:
                continue
            seen.add(rel)
            files.append((rel, p))
    violations = []
    for rel, p in files:
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if any(a.search(line) for a in ALLOW):
                continue
            for pat in FORBIDDEN:
                m = pat.search(line)
                if m:
                    violations.append((rel, n, m.group(0), line.strip()))
                    break
    return violations


def front_matter(path):
    """The figure's front matter as {key: value}, or None. SVG: an XML comment
    opening `<!-- figure`; Mermaid: `%% figure` … `%% end figure`."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".svg":
        m = re.search(r"<!--\s*figure\s*\n(.*?)-->", text, re.S)
        lines = m.group(1).splitlines() if m else None
    else:
        m = re.search(r"^%% figure\s*$(.*?)^%% end figure\s*$", text, re.S | re.M)
        lines = [l[2:].strip() for l in m.group(1).splitlines()] if m else None
    if lines is None:
        return None
    out = {}
    for line in lines:
        k, sep, v = line.strip().partition(":")
        if sep and k.strip() in FRONT_MATTER_KEYS:
            out[k.strip()] = v.strip()
    return out


def figure_text(path, fm):
    """The words a reader of the figure sees, one entry per drawn label."""
    import xml.etree.ElementTree as ET
    if path.suffix == ".svg":
        words = []
        for el in ET.parse(path).getroot().iter():
            if el.tag.rsplit("}", 1)[-1] in ("text", "title", "desc"):
                label = " ".join("".join(el.itertext()).split())
                if label:
                    words.append(label)
    else:
        words = [l.strip() for l in path.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.strip().startswith("%%")]
    return words + [fm[k] for k in ("question", "alt") if fm and fm.get(k)]


def sha256(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_exports():
    import json
    if not EXPORTS.exists():
        return []
    return json.loads(EXPORTS.read_text(encoding="utf-8"))["exports"]


def scan_figures():
    """[(file, problem)] for every figure under docs/diagrams/ (DOC-01)."""
    exports = {e["export"]: e for e in load_exports()}
    problems, historical = [], set()
    figures = sorted(p for p in DIAGRAMS.iterdir()
                     if p.suffix in (".svg", ".mermaid", ".mmd", ".png"))
    for path in figures:
        rel = path.relative_to(ROOT).as_posix()
        if rel in exports:
            continue
        if path.suffix == ".png":
            problems.append((rel, "a rendered figure no manifest entry names — list "
                                  "it in docs/diagrams/exports.json with its source"))
            continue
        fm = front_matter(path)
        missing = [k for k in FRONT_MATTER_KEYS if not (fm or {}).get(k)]
        if missing:
            problems.append((rel, f"front matter missing {missing}"))
        elif fm["status"] not in STATUSES:
            problems.append((rel, f"status {fm['status']!r} is not one of {STATUSES}"))
        if fm and fm.get("status") == "historical":
            historical.add(rel)
            continue
        problems += [(rel, f"'{m}' in figure text: {label[:100]}")
                     for label, m in _figure_hits(figure_text(path, fm))]
    for rel, e in exports.items():
        export, source = ROOT / rel, ROOT / e["source"]
        if not export.exists() or not source.exists():
            problems.append((rel, f"export or its source {e['source']} is missing"))
            continue
        if sha256(source) != e["source_sha256"]:
            problems.append((rel, f"its source {e['source']} changed since it was "
                                  f"rendered — run `{e['command']}`, then --record-exports"))
        if sha256(export) != e["export_sha256"]:
            problems.append((rel, "the export changed without its manifest entry — "
                                  "re-render from the source, then --record-exports"))
        if e["source"] in historical:
            continue
        if export.suffix == ".svg":
            problems += [(rel, f"'{m}' in figure text: {label[:100]}")
                         for label, m in _figure_hits(figure_text(export, None))]
    return problems


def _figure_hits(labels):
    for label in labels:
        if any(a.search(label) for a in ALLOW):
            continue
        for pat in FORBIDDEN + FIGURE_FORBIDDEN:
            m = pat.search(label)
            if m:
                yield label, m.group(0)
                break


LINK_FILES = ["README.md", "CONTRIBUTING.md", "Secure-Business-Messaging-Profile.md"]
_FENCE = re.compile(r"^\s*(```|~~~)")


def _lines_outside_fences(text):
    fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            fence = not fence
            yield ""
            continue
        yield "" if fence else line


def anchors_of(path):
    """GitHub's heading slugs (duplicates suffixed -1, -2 …) plus explicit ids."""
    seen, out = {}, set()
    for line in _lines_outside_fences(path.read_text(encoding="utf-8")):
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            t = re.sub(r"<[^>]+>", "", m.group(2)).strip().lower()
            t = re.sub(r"[^\w\- ]", "", t).replace(" ", "-")
            n = seen.get(t, 0)
            seen[t] = n + 1
            out.add(t if n == 0 else f"{t}-{n}")
        for ids in re.findall(r"\{#([\w\-]+)\}|<a\s+(?:id|name)=\"([^\"]+)\"", line):
            out.update(x for x in ids if x)
    return out


def link_files():
    import json
    historical = set(json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
                     .get("prose_sweep_historical", {}).get("paths", []))
    files = [ROOT / f for f in LINK_FILES]
    files += [p for p in sorted((ROOT / "docs").glob("*.md"))
              if p.relative_to(ROOT).as_posix() not in historical]
    files += sorted((ROOT / "docs" / "adr").glob("SBM-ADR-*.md"))
    return [p for p in files if p.exists()]


def scan_links(files=None):
    """[(file, target, problem)] for relative links that do not resolve."""
    from urllib.parse import unquote
    problems, cache = [], {}
    for path in (files if files is not None else link_files()):
        text = "\n".join(re.sub(r"`[^`]*`", "", l)
                         for l in _lines_outside_fences(path.read_text(encoding="utf-8")))
        for target in re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                continue                      # an external URL, not ours to resolve
            file_part, _, frag = target.partition("#")
            dest = path if not file_part else (path.parent / unquote(file_part))
            rel = path.relative_to(ROOT).as_posix()
            if not dest.exists():
                problems.append((rel, target, "no such file"))
            elif frag and dest.suffix == ".md":
                key = dest.resolve()
                if key not in cache:
                    cache[key] = anchors_of(dest)
                if frag not in cache[key]:
                    problems.append((rel, target, "no such heading or anchor"))
    return problems


def record_exports():
    import json
    doc = json.loads(EXPORTS.read_text(encoding="utf-8"))
    for e in doc["exports"]:
        e["source_sha256"] = sha256(ROOT / e["source"])
        e["export_sha256"] = sha256(ROOT / e["export"])
    EXPORTS.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    print(f"recorded {len(doc['exports'])} export digest(s) in {EXPORTS.relative_to(ROOT)}")


def main():
    if "--record-exports" in sys.argv:
        record_exports()
        return
    v = scan()
    for rel, n, tok, text in v:
        snippet = text if len(text) <= 120 else text[:117] + "..."
        print(f"[STALE] {rel}:{n}: '{tok}' -> {snippet}")
    f = scan_figures()
    for rel, problem in f:
        print(f"[FIGURE] {rel}: {problem}")
    links = scan_links()
    for rel, target, problem in links:
        print(f"[LINK] {rel}: ({target}) — {problem}")
    f = f + links
    if v or f:
        if v:
            print(f"\n{len(v)} pre-inversion mechanism token(s) found in prose. "
                  f"See docs/OCTET_AUTHORITATIVE_DESIGN.md for the octet-authoritative model.")
        if f:
            print(f"{len(f)} figure or link problem(s): a figure is a current claim, "
                  "and a reading path is only as good as its links.")
        sys.exit(2)
    print("doc-lint: no pre-inversion mechanism tokens in prose or figures; "
          "every figure has front matter and a fresh export; every local link "
          "resolves ✓")


if __name__ == "__main__":
    main()
