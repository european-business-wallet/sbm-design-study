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
#
# R23-04: the coverage was never the gap — `scanned_files` reaches the brief and
# every `docs/*.md`. The PATTERN was. It matched "learns nothing" and not
# "**nobody** learns … what kind of content was exchanged", and not "the class
# **stays private**" — two ordinary ways of writing the same absolute claim, and
# the two the executive brief and the production-verifier table happened to use.
# A guard built from the phrasings of the sentences that were wrong LAST time
# catches those sentences and no others.
#
# `cannot tell|know|determine|learn` was tried in the same pass and removed: it
# fired on two sentences that are not privacy claims at all — a relying party
# that "cannot tell that a version does not yet bind", and a creator that
# "cannot tell a capability refusal from a delivery failure". Both describe a
# DEFECT rather than assert a guarantee, and both would have had to be exempted
# one by one. A guard with exemptions nobody can justify is a guard that gets
# switched off, so the addition is confined to phrasings that are absolute
# claims about disclosure in any context they appear.
ABSOLUTE = re.compile(
    r"[^.]*\b(?:learns? nothing|discloses? no\b|discloses? nothing|"
    r"reveals? nothing|without disclosing|not disclosed|cannot infer|"
    r"no[\s-]?(?:body|one)\s+(?:can\s+)?(?:learns?|knows?|sees?)|"
    r"stays? private|remains? private|kept private)[^.]*\.",
    re.IGNORECASE)

# What makes such a sentence true: it is about a field or a mechanism, not about
# the bundle; or it carries the resolution that narrows the class anyway.
QUALIFIER = re.compile(
    r"from the commitment|the \*\*commitment\*\*|grade commitment|mandate commitment|"
    r"without carrying it|scope map|scope_ref|set of (?:content )?classes|"
    r"the set it lies in|th(?:is|at) field|A12|unsalted|without the salt", re.IGNORECASE)
# "that field" as well as "this field": the qualifier's job is to say the
# sentence is about ONE FIELD rather than about the bundle, and both spellings
# do that. The brief's corrected sentence used the one the list did not know,
# and the guard caught its own correction — in the EXPORT, because the brief
# exists only there and the widening that caught it had been run against the
# source alone.
#
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


def test_the_scan_reaches_every_document_of_its_path_that_exists_here():
    """Part of this guard's reading path is not in every tree it runs in.

    `brief/` and `OPEN-ITEMS.md` are the EXPORT's own documents. Running this
    suite in the source exercises the pattern and not those files — which is how
    a widened pattern was verified in the source, passed, and then rejected the
    very sentence that pass had written into the brief when the export was cut.

    The invariant is the same in both trees and is what this asserts: the scan
    covers each of those documents exactly where it exists. A first version of
    this test asserted instead that the brief is ABSENT — true in the source,
    false in the export, and it failed there the moment it travelled. A probe
    that states one tree's contents rather than the relation is the defect this
    repository calls invariant 13, committed inside the fix for a guard's own
    blind spot.
    """
    here = {p.relative_to(ROOT).as_posix() for p in scanned_files(ROOT)}
    assert "Secure-Business-Messaging-Profile.md" in here, "the core path must always be read"
    for rel in ("brief/executive-brief.md", "OPEN-ITEMS.md"):
        exists = (ROOT / rel).exists()
        assert (rel in here) == exists, (
            f"{rel}: exists={exists} but scanned={rel in here} — the scan must cover "
            "each document of its reading path exactly where that document exists")


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


def test_the_guard_catches_the_phrasings_that_got_past_it():
    """R23-04, as a regression rather than a description.

    The executive brief said "nobody learns from the evidence what kind of
    content was exchanged" and the production-verifier table said "the class
    stays private, and unchecked". Both are absolute disclosure claims, both are
    contradicted by the evidence explainer's own correction — a cleartext
    `scope_ref` resolved against the recipient's published scope map gives the
    set of classes that scope covers, and a singleton scope gives the class —
    and neither matched this guard, which knew "learns nothing" and not "nobody
    learns".

    The files were never the gap: `scanned_files` reaches the brief and every
    `docs/*.md`. A guard assembled from the phrasings of the last wrong
    sentences catches the last wrong sentences.
    """
    for claim in ("nobody learns from the evidence what kind of content was exchanged.",
                  "the class stays private, and unchecked.",
                  "no one knows which class it was.",
                  "the content class remains private."):
        assert ABSOLUTE.search(claim), claim
        assert not QUALIFIER.search(claim), f"unqualified, and must be reported: {claim}"
    # And the qualified form of the same claim must still pass, or the guard
    # forbids saying the true thing.
    ok = ("Nobody learns the class from the commitment, which is about that field: "
          "the resolved scope_ref gives the set of classes the scope covers.")
    assert ABSOLUTE.search(ok) and QUALIFIER.search(ok)
    # Both spellings of the qualifier, because the brief's corrected sentence
    # used one of them and this guard rejected its own correction.
    for spelling in ("this field", "that field"):
        assert QUALIFIER.search(f"so {spelling} discloses nothing: a reader cannot "
                                "test a guess against it."), spelling


def test_the_agent_branch_promises_no_more_than_the_evidence_branch():
    """R26-PUB-05. The two locations the previous review named were corrected;
    the agent branch was not, and a reviewer entering by agent expertise met a
    stronger guarantee than one entering by security.

    Two distinct claims had to be bounded. The commitment hides the class *from
    that field* — but the standing `mandate_ref.scope` is published in the
    signed member binding and the resolved `scope_ref` gives the set of classes
    the message could have belonged to. And an opening proves what the sender
    COMMITTED TO, not what it encrypted: a sender may commit to a permitted
    class and encrypt something else, because no party to the reveal inspects
    the plaintext.
    """
    agent = " ".join((ROOT / "docs" / "agent-profile-explainer.md").read_text(
        encoding="utf-8").split())
    assert "Before a dispute neither the mandate nor the class is disclosed" not in agent
    assert "The commitment itself discloses neither the mandate nor the class" in agent
    assert "a scope covering one class gives that class" in agent
    assert "not that the declared class describes the encrypted document" in agent

    umbrella = " ".join((ROOT / "Secure-Business-Messaging-Profile.md").read_text(
        encoding="utf-8").split())
    assert "without the mandate or the class leaking —" not in umbrella
    assert "from the commitment" in umbrella.replace("**", "")

    ts = " ".join((ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text(
        encoding="utf-8").split())
    assert "shows the agent acted within its mandate;" not in ts
    assert "the class the sender committed to lies within the mandate's scope" in \
        ts.replace("**", "")
    assert "an opening that fails to verify establishes neither misuse nor overreach" in ts


def test_the_consolidated_threat_model_carries_the_digest_residual():
    """The Internet-Draft's consideration defers to the umbrella for the
    consolidated threat model — "what the metadata reveals, to which observer,
    the current mitigations and the residual risks" — and §11.1's list of what
    the metadata can reveal did not include the one disclosure that
    consideration is about. R16-06 put the wire-level statement in the I-D and
    a guard on absolute claims in the umbrella; neither asked whether the
    document the reader is SENT to lists the risk. A reader following the
    pointer found five bullets and not this one.

    The rule is the same as the consideration's: state who can do it, who
    cannot, and that nothing is decided — no new normative language.
    """
    umbrella = (ROOT / "Secure-Business-Messaging-Profile.md").read_text(encoding="utf-8")
    start = umbrella.index("### 11.1 Metadata privacy threat model")
    model = umbrella[start:umbrella.index("### 11.2", start)]
    assert "**What the metadata can reveal.**" in model
    reveals = model[model.index("**What the metadata can reveal.**"):
                    model.index("**Who observes what")]
    flat = " ".join(reveals.split())
    assert "unsalted digest" in flat, "the residual the I-D defers here is missing"
    for needed in ("confirm a candidate document", "little entropy", "A12",
                   "nothing decided", "not** an observer of the network"):
        assert needed in flat, needed
    assert "MUST" not in flat and "SHALL" not in flat, \
        "an informative threat model states a residual; it does not legislate"


def test_the_record_does_not_ask_for_work_that_is_done():
    """`SBM-ADR-0014`'s first alternative — document the assumption rather than
    change the wire — was executed on 27 September 2026, in the I-D and now in
    the umbrella. A record that still proposes it as unwritten work would put a
    question to its reviewers that has already moved: the choice is no longer
    whether to document the exposure, but whether documenting it is enough."""
    adr = (ROOT / "docs" / "adr" / "SBM-ADR-0014.md").read_text(encoding="utf-8")
    flat = " ".join(adr.split())
    assert "This alternative has been executed" in flat.replace("**", "")
    assert "is the documented assumption enough?" in flat.replace("**", "")
    front = adr.split("---")[1]
    assert "decision_status: proposed" in front, "reporting the change must not accept it"


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
