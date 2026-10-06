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

THE LICENCE'S FILE LIST (publication review, PR-02). `LICENSE` lists the
documents each licence part covers. That list is prose about the repository,
in a file that is not Markdown and whose entries are not links, so no gate
read it: an export shipped a list naming a document it no longer had, which is
a licensing statement about nothing. `scan_licence_files` resolves every
repository path named in the licence's scope sections against the repository
the file ships in — directories and files alike.

LINKS (documentation completeness review, gate 3). Every relative link and
`#anchor` in the active Markdown — README, CONTRIBUTING, the umbrella and
every docs/*.md except the historical records `versions.json` names — must
resolve: the file exists, and an anchor into Markdown names a heading (by
GitHub's slug rule, duplicates numbered) or an explicit `{#id}`. A reading
path is only as good as its links.

THE MODE TOKENS (PT-01, 25 September 2026). `jcs-sha256` / `jcs-sha512` were
enum values of `payload_hash.hash_mode`, so a lowercase `jcs-` token was
allow-listed wholesale: it could only be the optional mode, and the mode was
real. The mode has been removed from the profile, so that allowance has been
NARROWED, not deleted — the tokens are now forbidden like the rest, and the only
lines that pass are the ones that state the removal (`removed`, `retired`, `no
longer`, `not part of the profile`, `refused`). A schema description saying the
mode was removed is documentation; the same token in a live instruction is the
defect this gate exists to catch.

The remaining legitimate references are allow-listed:
  - the glossary term "JSON Canonicalization Scheme";
  - change-history table rows ("| v0.x | ... |");
  - whole-file exemptions for the CHANGELOG, the licence notices and the design
    record, which discuss the removal / retain the reference for the mode.

See docs/adr/SBM-ADR-0008.md for the octet-authoritative model. (This pointed at
docs/OCTET_AUTHORITATIVE_DESIGN.md, the record of how the inversion was decided,
until 26 September 2026: that record describes a world in which the
canonicalisation modes still survived, it does not travel into the export, and
SBM-ADR-0008 has carried the reasons and the alternatives since PR #64.)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def _declared_records():
    """The docs/ files `versions.json` declares as historical records.

    DOC-02 established one declaration for what a record is — a file that says
    what was true, or what was decided, at a named revision — and the prose
    sweep excludes those BY PATH rather than editing them. This guard kept its
    own hand-written copy of part of that list, which held while the two agreed.
    Narrowing the `jcs-` allowance (PT-01) reached `DOCUMENTATION_COMPLETENESS_
    REVIEW.md`, a completed review body quoting the very mode it asked to be
    checked — a record by the declaration, and not by this file's copy of it.
    Deriving the set closes that gap in the only direction that does not edit a
    record. The token scope GREW in the same change; only the file list is
    shared, and a record is still a record in both sweeps.
    """
    import json
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    return set(manifest.get("prose_sweep_historical", {}).get("paths", []))


# Whole-file exemptions: the documents outside docs/ that legitimately discuss
# the removal of JCS (IPR.md left the set on 26 September 2026, when its
# exclusion list stopped naming RFC 8785), plus every record `versions.json`
# declares.
EXEMPT = {
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
} | _declared_records()

# Files scanned: the Markdown documents plus the machine-layer spec artefacts
# whose description/comment strings are spec-facing prose.
SCAN_GLOBS = ["*.md", "docs/*.md", "docs/adr/*.md", "brief/*.md", "ietf/*.md", "etsi/*.md",
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
    # PT-01: the removed `payload_hash` modes. They were enum values until
    # 2026-09-25 and were allow-listed as such; presented as available now,
    # they instruct a sender to emit a digest no verifier can recompute.
    re.compile(r"jcs-sha(?:256|512)", re.IGNORECASE),
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
    # PT-03: renaming a scope hides nothing. `scope_ref` travels in clear and
    # the `scope_map` that resolves it is signed and PUBLISHED, so the name
    # plays no part in what an observer learns. Offering neutral naming as a
    # mitigation told a deployer to do the one thing that does not help,
    # instead of the one that does — publish a coarser map.
    re.compile(r"neutral[-\s]?(?:id|identifier|name|scope)s?[^.\n]*"
               r"(?:guidance|mitigat|does not|hides|prevents)", re.IGNORECASE),
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

# A line that names a removed mode AND says it is gone. Deliberately narrow: the
# statement must be on the same line as the token, so a paragraph that mentions
# the removal once cannot excuse an instruction three lines below it.
REMOVAL_STATED = re.compile(
    r"jcs-sha(?:256|512)[^\n]*?\b(?:removed|retired|no longer|refused|"
    r"not part of the profile|left the profile)\b", re.IGNORECASE)

# A line containing any of these is legitimate and never flagged.
ALLOW = [
    REMOVAL_STATED,
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


# SBM-ADR-0015 — the MSP is not a role. The two roles were never apart on the
# wire (no Schema, contract or CDDL carries an MSP identity, and the register
# admits only `rdp`), so what could go stale is the TEXT: a reading path that
# still teaches a party the protocol does not have.
#
# This is its own check rather than another FORBIDDEN pattern because the
# decision records must keep the word. ADR-0004 decided the MSP WOULD be a
# participant and ADR-0015 records folding it away; a guard that swept
# `docs/adr/` would demand the rewriting of the history that explains the
# change. The other guards sweep the records deliberately — an ADR must not
# present JCS as current either — so the exclusion is this guard's, not the
# sweep's.
#
# `scripts/doc_lint.py`, `tests/test_figures.py` and
# `tests/test_policy_evaluator_owner.py` also keep the word, because they are
# what forbids it.
#: The role, however it is written. The abbreviation was the whole pattern at
#: first, which is a scan of the ACRONYM rather than of the role: the study's
#: outward-facing README spelled it out in plain language — "a messaging service
#: provider, which need not be qualified" — and the sweep that reported 113
#: occurrences closed reported it clean.
STALE_ROLE = re.compile(r"\bMSPs?\b|messaging service provider", re.IGNORECASE)
#: A path or URL that merely CONTAINS the word is not a role name: the
#: historical `docs/rdp-msp-trust-analysis/` folder keeps its name, and a
#: reading path is allowed to link to it. A path is what this matches: a
#: separator AND an extension, or a directory named with a trailing separator.
#: The first version of this guard blanked ANY token holding a slash, which read
#: `RDP/MSP` as a path — and so let the withdrawn name stand in a TS change-
#: indication clause, an I-D deployment note and the umbrella's own
#: minimum-viable box, while reporting the tree clean.
STALE_ROLE_PATH = re.compile(r"\b[\w.-]*[\w]/[\w./-]*(?:\.\w+|/)")
STALE_ROLE_GLOBS = ["*.md", "docs/*.md", "brief/*.md", "ietf/*.md", "etsi/*.md",
                    "schemas/*.json", "cddl/*.cddl", "*.yaml",
                    "docs/diagrams/*.svg", "docs/diagrams/*.mermaid"]
STALE_ROLE_EXEMPT_DIRS = ("docs/adr/", "docs/reviews/", "docs/rdp-msp-trust-analysis/")
#: Generated FROM the exempt records, so its mentions are theirs. Flagging it
#: would demand editing a file nobody edits by hand, to remove a word the
#: records it renders must keep.
STALE_ROLE_EXEMPT_FILES = ("docs/decisions-index.md",)

#: A generated document is exempt, which leaves its SOURCE as the only place a
#: withdrawn role can be corrected — and `docs/rule-ownership.json` is not a
#: scanned glob, so two rule TITLES naming the withdrawn role rendered into
#: `docs/rule-ownership.md` while this guard reported the tree clean. These are
#: the source's prose fields, scanned by name. The pattern fields are deliberately
#: NOT here: a detector that forbids "the MSP evaluates the acceptance policy"
#: must keep the word in order to find it.
STALE_ROLE_JSON_PROSE = ("docs/rule-ownership.json",)
STALE_ROLE_PROSE_FIELDS = ("title", "owner_anchor", "note")


def _json_prose(node, trail=()):
    """Every prose-field string in a generated document's source, with its path."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in STALE_ROLE_PROSE_FIELDS and isinstance(value, str):
                yield ".".join(trail + (key,)), value
            else:
                yield from _json_prose(value, trail + (str(key),))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _json_prose(item, trail + (str(i),))


def scan_stale_roles():
    """Every current-facing occurrence of a withdrawn role name (SBM-ADR-0015).

    Returns [(rel, line_no, line)]. The historical records keep the word; so do
    the three files that forbid it, and the detector patterns that catch it.
    """
    import json
    out, seen = [], set()
    for g in STALE_ROLE_GLOBS:
        for path in sorted(ROOT.glob(g)):
            rel = path.relative_to(ROOT).as_posix()
            if rel in seen or rel in EXEMPT:
                continue
            if rel in STALE_ROLE_EXEMPT_FILES or any(
                    rel.startswith(d) for d in STALE_ROLE_EXEMPT_DIRS):
                continue
            seen.add(rel)
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                # Blank out path-like tokens first, so a link to a historical
                # folder whose NAME carries the word is not read as a role.
                scrubbed = re.sub(r"\]\([^)]*\)", "]()", line)
                scrubbed = re.sub(r"`[\w./-]*[Mm][Ss][Pp][\w./-]*`", "``", scrubbed)
                scrubbed = STALE_ROLE_PATH.sub(" ", scrubbed)
                if STALE_ROLE.search(scrubbed):
                    out.append((rel, n, line.strip()))
    for rel in STALE_ROLE_JSON_PROSE:
        path = ROOT / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for field, value in _json_prose(json.loads(path.read_text(encoding="utf-8"))):
            if not STALE_ROLE.search(STALE_ROLE_PATH.sub(" ", value)):
                continue
            n = next((i for i, l in enumerate(lines, 1) if value[:60] in l), 0)
            out.append((rel, n, f"{field}: {value}"))
    return out


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


SCANNABLE = (".svg", ".mermaid", ".mmd")


def png_text_chunks(path):
    """The text a PNG carries in its tEXt/iTXt/zTXt chunks, one entry each.

    `figure_text` reads an SVG's elements and a Mermaid source's lines. For a
    PNG it can read nothing, because the labels are pixels — which is why a
    raster export is checked through its source. But a PNG is not textless: the
    format carries keyword/value text chunks, and a figure's words can sit there
    where neither the source scan nor a reader's eye meets them. They are read
    here so that "a PNG carries no scannable text" is something this gate
    establishes rather than assumes.
    """
    import struct, zlib
    data = path.read_bytes()
    out, i = [], 8                      # past the signature
    while i + 8 <= len(data):
        (length,) = struct.unpack(">I", data[i:i + 4])
        kind = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + length]
        if kind in (b"tEXt", b"iTXt", b"zTXt"):
            try:
                if kind == b"zTXt":
                    keyword, rest = body.split(b"\x00", 1)
                    text = zlib.decompress(rest[1:])
                elif kind == b"iTXt":
                    parts = body.split(b"\x00", 5)
                    keyword, text = parts[0], parts[-1]
                    if len(parts) > 2 and parts[2] == b"\x01":
                        text = zlib.decompress(text)
                else:
                    keyword, text = body.split(b"\x00", 1)
                label = f"{keyword.decode('latin-1')}: {text.decode('utf-8', 'replace')}"
                if label.strip():
                    out.append(" ".join(label.split()))
            except Exception:
                out.append(f"{kind.decode()} chunk this gate could not decode")
        i += 12 + length                # length + type + data + CRC
        if kind == b"IEND":
            break
    return out


def raster_source_problems(exports):
    """[(export, problem)] — a raster export must be rendered FROM something
    this gate can read.

    Nothing required it before: an entry could name a source of any format, and
    the text scan below runs only when the export itself is an SVG, so a raster
    figure's words reached a reader through a file the rules never applied to.
    The digests already bind the pair — `source_sha256` fails the moment a
    source changes without a re-render — but they bind bytes, not legibility.
    Same stem as well as scannable format, so the correspondence is visible in
    the directory listing and not only in the manifest.
    """
    problems = []
    for rel, e in exports.items():
        export, source = ROOT / rel, ROOT / e["source"]
        if export.suffix == ".svg":
            continue
        if source.suffix not in SCANNABLE:
            problems.append((rel, f"is rendered from {e['source']}, which this gate "
                                  f"cannot read — a raster export's source must be one of "
                                  f"{', '.join(SCANNABLE)}"))
        elif source.stem != export.stem:
            problems.append((rel, f"is rendered from {e['source']}, a different stem — "
                                  "a raster export and its source share a stem so the pair "
                                  "is legible in the directory, not only in the manifest"))
        if export.suffix == ".png" and export.exists():
            problems += [(rel, f"'{m}' in figure text: {label[:100]}")
                         for label, m in _figure_hits(png_text_chunks(export))]
    return problems


def sha256(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_exports():
    import json
    if not EXPORTS.exists():
        return []
    return json.loads(EXPORTS.read_text(encoding="utf-8"))["exports"]


def _is_generated(path):
    """A generated document is not a record kept as written.

    `versions.json` declares `docs/lint-catalogue.md` and `docs/rule-ownership.md`
    historical so the prose sweep skips them, and they are nothing like the
    design records: they are rewritten by their generator whenever their JSON
    source changes, and the README is right to cite the catalogue as the current
    normative rule list. They say so themselves, in a header this reads rather
    than a second list to keep in step.
    """
    if not path.exists():
        return False
    return "GENERATED FILE" in path.read_text(encoding="utf-8")[:1200].upper()


def scan_record_classification(root=None):
    """[(record, problem)] — a document cannot be a record and a companion.

    `versions.json` declares which documents are historical records. Three
    things follow from that declaration and had drifted apart: the prose sweep
    skips them, this guard exempts them wholly, and the README says they are
    "kept as written, and not part of the reading path". A record the README
    also lists among the current companions is claimed twice, and the two
    claims cannot both be acted on — one says leave it alone, the other invites
    a reader to rely on it. `OCTET_AUTHORITATIVE_DESIGN.md` was in exactly that
    position: declared historical, exempted, excluded from the export, and
    listed in the companion table as a current explainer.

    So: every declared record the README links must be linked inside the
    paragraph that says they are records. Nothing forbids linking one — a
    record is worth reaching — only presenting it as current.
    """
    root = root or ROOT
    import json
    manifest = json.loads((root / "versions.json").read_text(encoding="utf-8"))
    declared = [rel for rel in manifest.get("prose_sweep_historical", {}).get("paths", [])
                if not _is_generated(root / rel)]
    readme = (root / "README.md")
    if not readme.exists():
        return []
    text = readme.read_text(encoding="utf-8")
    linked = [rel for rel in declared if f"]({rel})" in text]
    if not linked:
        return []                 # nothing claimed twice; no paragraph needed
    marker = "**Records, not current claims**"
    if marker not in text:
        return [("README.md", f"no {marker!r} paragraph: the README must say "
                              "which documents are records before a record can be listed")]
    start = text.index(marker)
    end = text.find("\n\n", text.index("**Generated:**", start)) if "**Generated:**" in text[start:] \
        else text.find("\n\n\n", start)
    paragraph = text[start:end if end > start else len(text)]
    problems = []
    outside = text.replace(paragraph, "")     # every mention BUT the records one:
    for rel in linked:                        # a record may be linked there too
        link = f"]({rel})"
        if link in outside:
            problems.append((rel, "is declared a historical record in versions.json but the "
                                  "README links it outside the records paragraph — a document "
                                  "cannot be both a record kept as written and a current companion"))
    return problems


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
    problems += raster_source_problems(exports)
    # A public brief, where one exists (the design-study export carries one),
    # embeds its own figures; a superseded mechanism must not survive there
    # while the canonical figures are clean.
    for svg in sorted((ROOT / "brief" / "assets").glob("*.svg")):
        rel = svg.relative_to(ROOT).as_posix()
        problems += [(rel, f"'{m}' in figure text: {label[:100]}")
                     for label, m in _figure_hits(figure_text(svg, None))]
        canonical = DIAGRAMS / svg.name
        if canonical.exists() and canonical.read_bytes() != svg.read_bytes():
            problems.append((rel, f"differs from the canonical docs/diagrams/{svg.name} — copy it, do not edit it"))
    return problems


def figure_coverage():
    """(sources_scanned, rasters_checked) — what the gate actually read.

    The gate's line used to say "every figure has front matter and a fresh
    export", which is true and says nothing about how much of the set carries
    text this gate can read. A raster export is not scanned and cannot be: it is
    covered through its source and its digests. Counting sources rather than
    files keeps the report from implying a coverage the format does not allow.
    """
    exports = {e["export"] for e in load_exports()}
    sources = [p for p in DIAGRAMS.iterdir()
               if p.suffix in SCANNABLE and p.relative_to(ROOT).as_posix() not in exports]
    rasters = [p for p in DIAGRAMS.iterdir()
               if p.suffix not in SCANNABLE and p.relative_to(ROOT).as_posix() in exports]
    return len(sources), len(rasters)


def _figure_hits(labels):
    for label in labels:
        if any(a.search(label) for a in ALLOW):
            continue
        for pat in FORBIDDEN + FIGURE_FORBIDDEN:
            m = pat.search(label)
            if m:
                yield label, m.group(0)
                break


LICENCE_FILE = "LICENSE"
# The sections of LICENSE that enumerate covered files: Part A's scope and the
# Part C list. A path named anywhere in them must exist in this repository.
LICENCE_SCOPE_SECTIONS = ("### 2.1", "## 3.")
_PATHISH = re.compile(r"^[\w.@-]+(?:/[\w.@-]+)*/?$")
# Extensionless names that ARE paths. A token with neither a separator nor an
# extension is otherwise taken for a word in backticks, which would make every
# such word a missing file; these are named so the list's guarantee covers them.
LICENCE_BARE_NAMES = {"Makefile", "Dockerfile", "LICENSE", "CHANGELOG", "CODEOWNERS"}


def licence_scope_paths(path=None):
    """[(section, path)] — every repository path the licence's scope sections
    name, from their backticked tokens and link targets."""
    text = (path or (ROOT / LICENCE_FILE)).read_text(encoding="utf-8")
    out, section = [], None
    for line in text.splitlines():
        head = re.match(r"^(#{2,3})\s+(\S+)", line)
        if head:
            marker = f"{head.group(1)} {head.group(2)}"
            section = marker if any(marker.startswith(s) for s in LICENCE_SCOPE_SECTIONS) else None
        if not section:
            continue
        for token in re.findall(r"`([^`]+)`", line) + re.findall(r"\]\(([^)\s]+)\)", line):
            token = token.strip()
            if not token or " " in token or not _PATHISH.match(token):
                continue
            if "/" not in token and "." not in token and token not in LICENCE_BARE_NAMES:
                continue                      # a word in backticks, not a path
            out.append((section, token))
    return out


def scan_licence_files(root=None):
    """[(path, section)] for licence-listed paths this repository does not have."""
    root = root or ROOT
    return [(token, section)
            for section, token in licence_scope_paths(root / LICENCE_FILE)
            if not (root / token.rstrip("/")).exists()]


LINK_FILES = ["README.md", "CONTRIBUTING.md", "Secure-Business-Messaging-Profile.md",
              "brief/executive-brief.md", "brief/requirements.md"]   # the public brief, where one exists
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
    roles = scan_stale_roles()
    for rel, n, text in roles:
        snippet = text if len(text) <= 120 else text[:117] + "..."
        print(f"[ROLE] {rel}:{n}: a withdrawn role name (SBM-ADR-0015) -> {snippet}")
    f = scan_figures()
    for rel, problem in f:
        print(f"[FIGURE] {rel}: {problem}")
    links = scan_links()
    for rel, target, problem in links:
        print(f"[LINK] {rel}: ({target}) — {problem}")
    licence = scan_licence_files()
    for token, section in licence:
        print(f"[LICENCE] {LICENCE_FILE} {section} lists `{token}`, which this "
              "repository does not contain")
    records = scan_record_classification()
    for rel, problem in records:
        print(f"[RECORD] {rel}: {problem}")
    f = f + links + licence + records
    if v or f or roles:
        if roles:
            print(f"\n{len(roles)} occurrence(s) of a withdrawn role name in "
                  "current-facing text. SBM-ADR-0015 folds the Delivery Service "
                  "into the RDP: there is one provider role, and the text must not "
                  "teach a party the protocol does not have. The decision records "
                  "keep the word, and so do the three files that forbid it.")
        if v:
            print(f"\n{len(v)} pre-inversion mechanism token(s) found in prose. "
                  f"See docs/adr/SBM-ADR-0008.md for the octet-authoritative model.")
        if f:
            print(f"{len(f)} figure or link problem(s): a figure is a current claim, "
                  "and a reading path is only as good as its links.")
        sys.exit(2)
    scanned, rasters = figure_coverage()
    print("doc-lint: no pre-inversion mechanism tokens in prose or figures "
          f"({scanned} figure source(s) read; {rasters} raster export(s) covered "
          "through a scannable same-stem source, its digests and its text chunks); "
          "every figure has front matter and a fresh export; every local link "
          "resolves; every file the licence lists exists; every declared record is "
          "presented as one ✓")


if __name__ == "__main__":
    main()
