# SPDX-License-Identifier: MIT
"""An absolute privacy claim is a claim, and two of them are false.

The profile hides two different things with two different mechanisms, and the
reading path collapsed them into one sentence in five places:

- a **salted commitment** hides the value it commits to. The grade commitment
  and the mandate commitment take sixteen fresh bytes from the encrypted
  envelope, so a holder of the evidence cannot dictionary-test the public
  content-class registry against them. That is true and it is about **that
  field**;
- the **bundle** hides less. `scope_ref` is echoed in clear and the recipient's
  scope map is published and signed, so the pair resolves to the set of classes
  that scope covers — a set of one where the scope covers one class. And
  `payload_hash` is **not** salted, so it confirms a guess about low-entropy
  content to anyone holding the evidence, which is A12, open.

So "providers and external verifiers learn nothing about the class" and "the
evidence discloses no class" were not overstatements of degree; they said the
opposite of what the design does. This checks the sentences by their meaning:
where a document makes a claim about what is hidden, the qualifier that makes it
true has to be in the same sentence.

The prose guard cannot do this. It matches tokens that must not return, and
these sentences contain no forbidden token — they are ordinary English, correct
in grammar, and wrong. The guard also never read `docs/adr/` or the export's
brief, and the claim reached the generated decisions index through an ADR field.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A sentence that says a party learns nothing / that nothing is disclosed.
ABSOLUTE = re.compile(
    r"[^.]*\b(?:learns? nothing|discloses? no\b|discloses? nothing|"
    r"reveals? nothing|without disclosing|not disclosed|cannot infer)[^.]*\.",
    re.IGNORECASE)

# What makes such a sentence true: it is about a field or a mechanism, not about
# the bundle; or it carries the resolution that narrows the class anyway.
QUALIFIER = re.compile(
    r"from the commitment|the \*\*commitment\*\*|grade commitment|mandate commitment|"
    r"without carrying it|scope map|scope_ref|set of (?:content )?classes|"
    r"the set it lies in|this field|A12|unsalted|without the salt", re.IGNORECASE)
# `salt` alone is NOT a qualifier, and that is the point. The sentence this pass
# corrected read "The salt travels only in the end-to-end-encrypted envelope, so
# providers and external verifiers learn nothing about the class": it named the
# salt and still overclaimed. A first draft of this list accepted `salt`, and the
# probe below passed while asserting the opposite.

# A claim the document says it does NOT make.
NEGATED = re.compile(r"not established|not claimed|not proven|does not claim|"
                     r"is not asserted|unproven", re.IGNORECASE)

SCANNED = ("README.md", "CONTRIBUTING.md", "OPEN-ITEMS.md",
           "Secure-Business-Messaging-Profile.md")
RECORDS = {"docs/DESIGN_DECISIONS.md", "docs/DESIGN_FINDINGS.md",
           "docs/DESIGN_REVIEW_FINDINGS_HANDOFF.md", "docs/DESIGN_REVIEW_ROUND11.md",
           "docs/DESIGN_REVIEW_ROUND12.md", "docs/DOCUMENTATION_COMPLETENESS_REVIEW.md",
           "docs/FEDERATION_PARTICIPANT_PLAN.md", "docs/OCTET_AUTHORITATIVE_DESIGN.md",
           "docs/REVIEW_AGENDA.md", "docs/lint-catalogue.md", "docs/rule-ownership.md"}


def scanned_files(root):
    """Everything on the reading path, the ADRs and the brief included.

    The ADRs were outside the prose guard, and the claim reached the generated
    decisions index through one of their fields; the brief exists only in the
    export, and travels there.
    """
    out = [root / n for n in SCANNED]
    out += sorted((root / "docs").glob("*.md"))
    out += sorted((root / "docs" / "adr").glob("*.md"))
    out += sorted((root / "brief").glob("*.md"))
    out += sorted((root / "ietf").glob("*.md"))
    out += sorted((root / "etsi").glob("*.md"))
    return [p for p in out
            if p.exists() and p.relative_to(root).as_posix() not in RECORDS]


def unqualified_claims(root):
    """[(where, sentence)] — a claim about what is hidden, with nothing in the
    same sentence to make it true."""
    out = []
    for path in scanned_files(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        flat = " ".join(text.split("\n"))
        for m in ABSOLUTE.finditer(flat):
            sentence = " ".join(m.group(0).split())
            # A claim framed as NOT established is the honest form, and the
            # open-items document is built out of them: "**Not established.**
            # That evidence discloses nothing about content where the content
            # has little entropy." The lead-in is its own sentence, so it is
            # looked for behind the match rather than inside it.
            lead_in = " ".join(flat[max(0, m.start() - 90):m.start()].split()).lower()
            if NEGATED.search(lead_in):
                continue
            if not QUALIFIER.search(sentence):
                out.append((rel, sentence[:180]))
    return out


def test_no_unqualified_privacy_claim_on_the_reading_path():
    assert unqualified_claims(ROOT) == []


def test_the_qualified_claims_are_still_there():
    """The fix is a qualifier, not a deletion: the documents must still say what
    the commitments do hide, or the correction has removed a true claim."""
    explainer = (ROOT / "docs" / "evidence-layer-explainer.md").read_text(encoding="utf-8")
    assert "learn nothing about the class **from the commitment**" in explainer
    assert "scope_ref" in explainer and "resolves to the set of content classes" in explainer
    examples = (ROOT / "docs" / "scope-resolution-examples.md").read_text(encoding="utf-8")
    assert "the **commitment** discloses no class" in examples


def test_the_internet_draft_sends_the_reader_to_the_consideration():
    """An open-items list records what is not proven; a security consideration
    tells an implementer what to do about it. R16-06."""
    id_text = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text(encoding="utf-8")
    assert "Guessable content behind an unsalted digest" in id_text
    consideration = id_text[id_text.index("**Guessable content behind an unsalted digest.**"):]
    consideration = consideration[:consideration.index("**Metadata privacy.**")]
    for needed in ("confirms a guess", "little entropy", "A12", "SBM-ADR-0014"):
        assert needed in consideration, needed
    assert "MUST" not in consideration and "SHALL" not in consideration, \
        "this is advice in a security consideration, not a new normative rule"


def test_the_observer_matrix_states_the_forwarding_path():
    """The Delivery Service sees an SE's fields on the four-corner forwarding
    path, because it decodes and verifies the origin's sealed SE to prove the
    namespace. The matrix described it as an observer of routing data alone."""
    umbrella = (ROOT / "Secure-Business-Messaging-Profile.md").read_text(encoding="utf-8")
    assert "Who observes what — and on which path" in umbrella
    for needed in ("forwarding path", "sealed SE", "payload_hash", "scope_ref",
                   "No collusion is assumed"):
        assert needed in umbrella, needed
    matrix = (ROOT / "docs" / "architecture-identity-trust.md").read_text(encoding="utf-8")
    row = next(l for l in matrix.splitlines() if l.startswith("| Delivery Service"))
    assert "forwarding path" in row and "payload_hash" in row, row


def test_a_new_absolute_claim_would_be_caught(tmp_path):
    """The probe: the sentence this pass corrected, in a new document."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_text(
        "The salt travels only in the envelope, so providers and external "
        "verifiers learn nothing about the class.\n", encoding="utf-8")
    found = unqualified_claims(tmp_path)
    assert [w for w, _ in found] == ["docs/note.md"], found


def test_a_claim_the_document_says_it_does_not_make_is_not_flagged(tmp_path):
    """The open-items document is built out of these, and the export found this
    the first time the check ran there: "**Not established.** That evidence
    discloses nothing about content where the content has little entropy." is
    the honest form, not the defect."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_text(
        "**Not established.** That evidence discloses nothing about content "
        "where the content has little entropy.\n", encoding="utf-8")
    assert unqualified_claims(tmp_path) == []


def test_a_qualified_claim_passes(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "note.md").write_text(
        "Providers learn nothing about the class from the commitment; the echoed "
        "scope_ref still resolves to the set of classes that scope covers.\n",
        encoding="utf-8")
    assert unqualified_claims(tmp_path) == []
