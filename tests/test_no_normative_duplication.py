# SPDX-License-Identifier: MIT
"""Guard the three-document split (restructure cycle).

(1) No normative-requirement sentence (MUST/SHALL/REQUIRED) may appear in two of
the three documents — every requirement lives in exactly one, the others
reference it. Modal verbs are normalised (SHALL->MUST) so a requirement moved
into the ETSI TS (SHALL) is still caught if it were also restated elsewhere.

(2) No dangling section references: every `§N.M` reference inside the umbrella
must resolve to a heading that still exists in the umbrella (a moved section
becomes a `[I-D]` / `[TS]` reference, not a dangling `§`).
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = {
    "umbrella": "Secure-Business-Messaging-Profile.md",
    "id": "ietf/draft-sbm-mls-erd-00.md",
    "ts": "etsi/TS-SBM-QERDS-Binding-v0.1.md",
}
NORM = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|REQUIRED)\b")


def _normative_sentences(text):
    for raw in re.split(r"(?<=[.:])\s+", text):
        s = " ".join(raw.split())
        if NORM.search(s) and len(s) > 60:
            n = s.lower().replace("shall not", "must not").replace("shall", "must")
            yield n


def test_no_cross_document_normative_duplication():
    seen = {}
    dups = []
    for name, rel in DOCS.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        for s in set(_normative_sentences(text)):
            if s in seen and seen[s] != name:
                dups.append(f"[{seen[s]} & {name}] {s[:90]}...")
            else:
                seen.setdefault(s, name)
    assert not dups, "normative sentence duplicated across documents:\n" + "\n".join(dups)


def test_umbrella_section_references_resolve():
    text = (ROOT / DOCS["umbrella"]).read_text(encoding="utf-8")
    headings = set(re.findall(r"(?m)^#{2,4}\s+(\d+(?:\.\d+)*)", text))
    refs = set(re.findall(r"§(\d+(?:\.\d+)*)", text))

    def resolves(r):
        return r in headings or any(h.startswith(r + ".") for h in headings)

    dangling = sorted(r for r in refs if not resolves(r))
    assert not dangling, f"dangling §-references in the umbrella (moved sections?): {dangling}"


def test_no_stale_section_refs_in_machine_artefacts():
    """N7/P7: schemas, scripts, tests and the OpenAPI file must not cite
    pre-restructure umbrella §7.x sections (that messaging/evidence content
    moved to the I-D/TS). Use stable anchors — 'the I-D (...)', 'the TS
    clause ...', 'umbrella §8.x'."""
    # The guard is about the UMBRELLA's pre-restructure section 7.x. A section
    # reference belonging to ANOTHER document (an RFC clause, for instance) is
    # not what N7 is about, and matching it would push authors to cite
    # standards vaguely — worse than the drift being prevented. Hence the
    # lookbehinds: a reference preceded by "RFC " or by a document number is
    # someone else's numbering. (Written without an example, since an example
    # would trip this very check.)
    stale = re.compile(r"(?<!RFC )(?<![0-9] )§7\.[0-9]")
    bad = []
    for pattern in ("schemas/*.json", "scripts/*.py", "tests/*.py",
                    "edd-resolver-openapi.yaml"):
        for p in ROOT.glob(pattern):
            if "__pycache__" in str(p):
                continue
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if stale.search(line):
                    bad.append(f"{p.relative_to(ROOT)}:{i}")
    assert not bad, f"stale umbrella §7.x refs in machine artefacts (N7): {bad}"
