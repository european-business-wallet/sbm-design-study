# SPDX-License-Identifier: MIT
"""PT-03 / PT-02 — what the evidence discloses: one correction, one question.

PT-03 is a claim the profile made about one of its own mitigations, and it was
false. §11.1 told a reader that "a scope named `litigation-x` leaks; a neutral
id does not". `scope_ref` is a required SE field travelling in clear and the
`scope_map` that gives it meaning is part of the signed, PUBLISHED BW-ORG, so
anyone who can read the evidence resolves one to the other and the name plays no
part in it. The guidance was worse than silence: a deployer who followed it
chose neutral ids instead of the mitigation that bears on the leak, a coarser
map, and was less protected for having complied.

PT-02 is not a false claim but a property of the design — the profile salts
commitments and not content digests — so this suite checks that it is OPEN and
answered nowhere, not that it is fixed. Deciding it would reach the envelope,
the evidence schemas, the recipient's re-verification, Mode C's per-part digests
and the reveal path; that is a wire change, not a paragraph.
"""
import importlib.util
import pathlib
import re
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
UMBRELLA = ROOT / "Secure-Business-Messaging-Profile.md"
AGENDA = ROOT / "docs" / "REVIEW_AGENDA.md"


def _doc_lint(root):
    spec = importlib.util.spec_from_file_location("doc_lint_priv", ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = root
    mod.DIAGRAMS = root / "docs" / "diagrams"
    mod.EXPORTS = mod.DIAGRAMS / "exports.json"
    return mod


# --- PT-03: the corrected statement ---------------------------------------

def test_the_profile_no_longer_offers_neutral_naming_as_a_mitigation():
    text = UMBRELLA.read_text(encoding="utf-8")
    assert "a neutral id does not" not in text
    assert "neutral-id guidance for scope naming" not in text


def test_it_says_instead_what_a_published_map_discloses():
    """The replacement must carry the meaning, not just drop the claim: what an
    observer learns is the SET of content classes the resolved scope covers."""
    text = UMBRELLA.read_text(encoding="utf-8")
    assert "the set of content classes the message could have belonged to" in text
    assert "a coarser scope map discloses less" in text.lower()
    assert "the organisation that publishes the map" in text, \
        "the choice belongs to the recipient organisation, and the text must say so"


def test_the_content_class_bullet_keeps_both_halves():
    """`content_class` is not echoed in evidence AND the echoed scope narrows it
    to a set. A reader must not be able to take the first without the second."""
    bullet = next(l for l in UMBRELLA.read_text(encoding="utf-8").splitlines()
                  if l.startswith("- **Content-class inference**"))
    assert "never echoed in evidence" in bullet
    assert "narrows the class to the set that scope covers" in bullet


@pytest.mark.parametrize("claim", [
    "neutral-id guidance for scope naming",
    "Scope ids are chosen by the publisher — a scope named `x` leaks; a neutral id does not.",
    "Deployments SHOULD adopt neutral scope names as a mitigation.",
])
def test_the_claim_cannot_return(tmp_path, claim):
    """The guard, driven. A correction kept only in a merged diff is a
    correction that comes back with the next editor."""
    shutil.copytree(ROOT / "docs", tmp_path / "docs", dirs_exist_ok=True)
    shutil.copy(UMBRELLA, tmp_path / UMBRELLA.name)
    probe = tmp_path / "docs" / "probe-note.md"
    probe.write_text(f"Mitigation: {claim}\n", encoding="utf-8")
    dl = _doc_lint(tmp_path)
    hits = [(rel, tok) for rel, _, tok, _ in dl.scan() if rel == "docs/probe-note.md"]
    assert hits, f"doc_lint accepted the removed claim: {claim}"


def test_the_normative_scope_descriptor_is_not_what_changed():
    """§8.3a states the scope rules; PT-03 changed an informative description of
    a mitigation, not a normative rule. Nothing here may become normative."""
    text = UMBRELLA.read_text(encoding="utf-8")
    start = text.index("### 11.1")
    end = text.index("### 11.2")
    section = text[start:end]
    assert "(informative)" in section.splitlines()[0]
    for word in ("MUST", "SHALL", "REQUIRED"):
        assert word not in section, f"§11.1 gained a normative keyword: {word}"


# --- PT-02: opened, and answered nowhere ----------------------------------

def test_the_salted_digest_question_is_on_the_agenda():
    row = next((l for l in AGENDA.read_text(encoding="utf-8").splitlines()
                if l.startswith("| A12 |")), None)
    assert row, "PT-02 must be an agenda entry, not a paragraph somewhere"
    assert row.count("|") == 6, "four columns, the shape its neighbours use"
    for reached in ("envelope schema", "per-part digests", "reveal path"):
        assert reached in row, f"the entry must say what a change would reach: {reached}"


def test_the_agenda_row_does_not_say_the_profile_is_silent():
    """The row said "the profile does not say which it assumes". It did not, on
    26 September; it does now, in the I-D's Security Considerations and in the
    umbrella's consolidated threat model. A reviewer reads this row before the
    specification — that is what the agenda is for — so a row describing the
    documents as silent would have them price the question they were assigned
    against a repository three days out of date.

    A12 stays OPEN. What moved is what is open: not whether to state the
    exposure, but whether stating it is enough."""
    row = next(l for l in AGENDA.read_text(encoding="utf-8").splitlines()
               if l.startswith("| A12 |"))
    assert "the profile does not say which it assumes" not in row
    assert "whether stating it is enough" in row
    assert "Guessable content behind an unsalted digest" in row
    assert "Decided" not in row, "A12 stays open"


def test_the_agenda_numbering_is_not_reused():
    """A11 was published with the hash-mode pass and is cited from
    CONTRIBUTING.md; identifiers are assigned once. PT-02's work order named
    A11 because it was free when the order was written, not after."""
    agenda = AGENDA.read_text(encoding="utf-8")
    ids = re.findall(r"^\| (A\d+) \|", agenda, re.M)
    assert len(ids) == len(set(ids)), f"duplicate agenda identifier: {ids}"
    assert "A11" in ids and "A12" in ids
    a11 = next(l for l in agenda.splitlines() if l.startswith("| A11 |"))
    assert "cannot compute" in a11, "A11 remains the reason-code question"


def test_nothing_claims_the_digest_conceals_guessable_content():
    """Criterion 3: no document may assert an answer to A12. The profile may
    say evidence carries no plaintext — it carries a digest, and says so — but
    not that a bare digest protects content that can be guessed."""
    overclaim = re.compile(
        r"(?:payload_hash|content_digest|digest)[^.\n]*"
        r"(?:reveals nothing|discloses nothing|conceals the content|"
        r"cannot be guessed|protects the content)", re.IGNORECASE)
    records = {"CHANGELOG.md", "docs/DESIGN_FINDINGS.md", "docs/DESIGN_DECISIONS.md",
               "docs/DESIGN_REVIEW_FINDINGS_HANDOFF.md", "docs/REVIEW_AGENDA.md"}
    offenders = []
    for path in [UMBRELLA, ROOT / "README.md", ROOT / "ietf" / "draft-sbm-mls-erd-00.md",
                 ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md",
                 *sorted((ROOT / "docs").glob("*.md"))]:
        rel = path.relative_to(ROOT).as_posix()
        if rel in records or not path.exists():
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if overclaim.search(line):
                offenders.append(f"{rel}:{n}")
    assert offenders == [], offenders
