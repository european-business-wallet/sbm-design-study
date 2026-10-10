# SPDX-License-Identifier: MIT
"""The r23 review's §5 — what a reviewer meets, and in what order.

None of these was a defect in the specification. They were defects in the way it
is *approached*: a route that began at the architecture and never stated the
problem; the one question an architectural reviewer asks first, recorded as
unanswered; a nine-column index that was a document to study rather than a map to
choose from; pointers into a historical analysis the export does not carry;
process history where a first-time reader meets it; and a claim about the gates
that was stronger than the gates.

They are held here because prose has no other gate: a reading path degrades by
addition, one reasonable-looking sentence at a time, and nothing else in this
repository would notice.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "REVIEWER_GUIDE.md"
ADR3 = ROOT / "docs" / "adr" / "SBM-ADR-0003.md"


def _flat(path):
    return " ".join(path.read_text(encoding="utf-8").split())


# --- the route starts at the problem ----------------------------------------

def test_the_short_path_begins_with_the_problem_not_the_architecture():
    """A reviewer who starts at the architecture is judging a solution whose
    problem statement they have not seen."""
    guide = GUIDE.read_text(encoding="utf-8")
    route = guide[guide.index("## The short path"):guide.index("## Then one branch")]
    steps = re.findall(r"^(\d)\. \[\*\*(.+?)\*\*\]", route, re.M)
    assert steps and steps[0][0] == "0", steps
    assert "problem" in steps[0][1].lower(), steps[0]
    assert [s[0] for s in steps] == ["0", "1", "2", "3", "4", "5"], steps
    assert "Read this before the architecture" in route


def test_step_zero_resolves_here_and_names_what_only_the_export_carries():
    """`brief/requirements.md` is the export's own file. Step 0 must work in
    this repository — where it points at the README's own problem sections —
    and still tell a reader of the export that the requirements list exists."""
    route = _flat(GUIDE)
    assert "README §§1–3" in route
    assert "brief/requirements.md" in route
    assert "this route works without it" in route
    target = "#1-the-problem-and-what-the-exercise-leaves-out"
    assert target in GUIDE.read_text(encoding="utf-8")
    heads = re.findall(r"^## (.+)$", (ROOT / "README.md").read_text(encoding="utf-8"), re.M)
    slugs = {re.sub(r"[^a-z0-9 -]", "", h.lower()).replace(" ", "-") for h in heads}
    assert target.lstrip("#") in slugs, sorted(slugs)[:6]


# --- the selection question, answered ---------------------------------------

def test_why_mls_is_answered_and_no_longer_listed_as_unanswered():
    """The review called this the most important missing explanation for an
    architectural reviewer. What stays unanswered is narrower and is said so:
    no named alternative is assessed."""
    body = ADR3.read_text(encoding="utf-8")
    assert "## Why this choice" in body
    section = " ".join(
        body[body.index("## Why this choice"):body.index("## Alternatives considered")].split())
    assert "**Why MLS at all.**" in section
    # The four requirements, the shapes they exclude, the costs, and the limits.
    for needed in ("Asynchrony", "Many devices per party", "never holds content keys",
                   "Persistent group state", "Roster synchronisation", "Epoch handling",
                   "KeyPackage"):
        assert needed in section, needed
    assert "What MLS does not give the profile" in section, \
        "a rationale that does not bound the choice invites everything to be read into it"
    unanswered = body[body.index("## Unanswered"):]
    assert "A comparison against named alternatives" in unanswered
    assert "no comparison is written down" not in unanswered


def test_the_rationale_argues_from_what_mls_supplies_not_from_impossibility():
    """R26-PUB-06. The first version said a pairwise protocol "gives no group
    object", that per-message key agreement "makes the device set a matter of
    who was online", and that MLS is "the one shape" in which membership is
    demonstrable state. The online-presence claim has direct counterexamples —
    X3DH publishes prekeys so a sender can encrypt to an offline recipient, and
    HPKE's single-shot encryption needs no live participation at all — and
    multi-device session management in that family is Sesame's subject.

    The defensible argument is narrower and is the one made now: MLS carries
    the group, its epochs and its transcript as reviewed machinery, and a
    pairwise base would need this profile to specify, implement and prove an
    equivalent. Assurance and complexity, not impossibility.
    """
    body = " ".join(ADR3.read_text(encoding="utf-8").split())
    section = body[body.index("## Why this choice"):body.index("## Alternatives considered")]
    assert "the one shape in which" not in section, "the impossibility claim must not return"
    assert "makes the device set a matter of who was online" not in section
    assert "not about what other protocols make impossible" in section
    for needed in ("X3DH", "HPKE", "Sesame",
                   "specified, implemented and proven by this profile",
                   "assurance and complexity"):
        assert needed in section.replace("**", ""), needed
    # And the one requirement that IS a boundary rather than a composition cost.
    assert "breaks the requirement that the provider never holds content keys" in section


def test_the_remaining_question_is_stated_once_and_the_index_agrees():
    """R26-PUB-07. The section answered the question while the front matter
    still said no comparison was written down, and the generated index
    reproduced the obsolete sentence — a reader got a different answered/open
    status depending on which file they opened."""
    body = ADR3.read_text(encoding="utf-8")
    front = body.split("---")[1]
    assert "not why it was chosen over other end-to-end protocols" not in front
    assert "against named alternatives" in front
    index = (ROOT / "docs" / "decisions-index.md").read_text(encoding="utf-8")
    assert "The record explains how MLS is profiled" not in index
    assert "Why MLS, against named alternatives?" in index
    unanswered = " ".join(body[body.index("## Unanswered"):].split())
    assert "no such comparison is written down" in unanswered
    assert "is not established either way" in unanswered


def test_the_rationale_section_is_a_declared_kind_not_a_one_off():
    """The record vocabulary is closed, so a new heading is a decision about
    the shape of every record, not a local edit."""
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import adr_index
    assert "Why this choice" in adr_index.OPTIONAL_SECTIONS
    assert "Why this choice" not in adr_index.REQUIRED_SECTIONS, \
        "most records inherit their mechanism; requiring this would invite filler"


# --- the index is a map ------------------------------------------------------

def test_the_decisions_index_is_a_map_and_the_detail_is_in_the_records():
    index = (ROOT / "docs" / "decisions-index.md").read_text(encoding="utf-8")
    header = next(l for l in index.splitlines() if l.startswith("| ADR |"))
    columns = [c.strip() for c in header.strip("|").split("|")]
    assert columns == ["ADR", "Choice", "Principal trade-off", "Decision",
                       "Implementation", "Open"], columns
    assert "one click away" in " ".join(index.split())
    # The trade-off column is the benefit AND its cost, not one of them — and
    # which half a reader is in must be LABELLED. The two were welded with
    # "— at the cost of", which made one sentence out of two lists and left the
    # reader to find the hinge. Asserted as the two labels, so a rewording of
    # either half does not fail this and dropping a half does.
    for row in [l for l in index.splitlines() if l.startswith("| [SBM-ADR-")]:
        cells = row.strip("|").split("|")
        trade = cells[2]
        assert "**Buys:**" in trade and "**Costs:**" in trade, row
        buys, _, costs = trade.partition("**Costs:**")
        assert len(buys.split()) > 4 and len(costs.split()) > 4, \
            f"a labelled half with nothing in it is worse than no label: {row}"


# --- pointers resolve for the reader who has the export ----------------------

def test_no_reader_facing_document_points_into_the_unexported_analysis():
    """The three S2 observer models are in a record the export carries. Every
    reading-path document pointed instead at a directory the export excludes,
    as a non-clickable path — a reference a reader could not follow."""
    reading_path = [GUIDE,
                    ROOT / "docs" / "architecture-identity-trust.md",
                    ROOT / "docs" / "decisions-index.md",
                    ROOT / "docs" / "REVIEW_AGENDA.md",
                    ROOT / "docs" / "adr" / "SBM-ADR-0004.md"]
    for path in reading_path:
        assert "rdp-msp-trust-analysis" not in path.read_text(encoding="utf-8"), path.name
    # The README is deliberately NOT in that list. Its mention is in the
    # catalogue of this repository's historical records, where naming the
    # analysis is the point, and it is a link that resolves HERE — the README
    # the export ships is the export's own file and carries no such reference.
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "rdp-msp-trust-analysis" in readme:
        assert "](docs/rdp-msp-trust-analysis/README.md)" in readme, \
            "provenance is a resolving link or it is a dangling pointer"
        assert (ROOT / "docs" / "rdp-msp-trust-analysis" / "README.md").exists()
    adr4 = _flat(ROOT / "docs" / "adr" / "SBM-ADR-0004.md")
    for model in ("accountable MSP observer", "authenticated independently of the MSP",
                  "inside the RDP's boundary"):
        assert model in adr4, model


# --- process history, and a claim the gates do not make ----------------------

def test_the_guide_opens_on_the_specification_not_on_its_process():
    """The first substantive paragraph explained two review counters and the
    mistakes earlier readers had made with them. The distinction is worth
    keeping; the anecdote is not first-contact material."""
    guide = _flat(GUIDE)
    assert "counts the completed **adversarial design reviews**" in guide, \
        "the two series are genuinely different and the guide must still say so"
    assert "two readers have now made" not in guide
    assert "a mistake" not in guide


def test_the_green_bar_claim_is_bounded_by_what_the_gates_check():
    readme = _flat(ROOT / "README.md")
    assert "The repository agrees with itself, as far as its gates can see" in \
        readme.replace("**", "")
    assert "not a claim that no semantic inconsistency remains" in readme
    assert "each time the answer was a new gate" in readme


def test_the_corrections_keep_what_a_reader_could_have_acted_on():
    """A corrections list that keeps everything stops being read. What survives
    is the entries where an earlier edition would have led a reader to a wrong
    conclusion, not the bookkeeping.

    They left the explainers on 10 October 2026 — process history belongs
    outside a document whose job is the design as it stands — and they live in
    `docs/corrections-to-earlier-editions.md`, which **the export ships**. The
    first attempt moved them to `CHANGELOG.md`, and the export's own bar refused
    it: the export writes its own CHANGELOG, so the pointer there resolved to a
    file that did not contain them. This checks the claim where it now is, and
    checks the other half of the move — that each explainer keeps a line
    pointing at it, so the corrections are relocated rather than erased.
    """
    corrections = _flat(ROOT / "docs" / "corrections-to-earlier-editions.md")
    assert "wrong in a way a reader could have acted on" in corrections
    assert "made available to (or retrieved by)" in corrections
    assert "proves misuse" in corrections
    assert "dropped from this" in corrections, \
        "what was removed is stated, or provenance is erased rather than trimmed"

    for rel in ("docs/evidence-layer-explainer.md", "docs/federated-flow-explainer.md",
                "docs/agent-profile-explainer.md"):
        doc = _flat(ROOT / rel)
        assert "Corrections, for readers of earlier editions" in doc, rel
        assert "](corrections-to-earlier-editions.md)" in doc, \
            f"{rel} drops its corrections instead of pointing at them"


#: The three companions that open with the layering template share one worked
#: case, so a reader can carry the instants from one to the next. Four instants,
#: and the one the evidence carries is the last.
RUNNING_CASE = ("09:58", "09:59", "10:14", "10:15")
LAYERED = ("docs/evidence-layer-explainer.md", "docs/message-lifecycle.md",
           "docs/architecture-identity-trust.md")


def test_the_three_layered_companions_share_one_worked_case():
    """Each of the three says it uses the same case as the other two, and a
    cross-reference is only worth making if it is true. The instants are the
    check: a document that changes one of them, or drops the case, breaks the
    comparison the other two invite a reader to make.

    `architecture-identity-trust.md` carries the first two — the submission and
    its seal are what its trust chains are about — and the other two carry all
    four.
    """
    for rel in LAYERED:
        doc = _flat(ROOT / rel)
        assert "One case, concretely" in doc, f"{rel} dropped the worked case"
        for other in LAYERED:
            if other != rel:
                assert pathlib.Path(other).name in doc, \
                    f"{rel} does not point at {other}"
        wanted = RUNNING_CASE if rel != "docs/architecture-identity-trust.md" \
            else RUNNING_CASE[:2]
        for instant in wanted:
            assert instant in doc, f"{rel} lost the instant {instant}"


def test_the_lifecycle_heading_counts_its_own_table():
    lifecycle = (ROOT / "docs" / "message-lifecycle.md").read_text(encoding="utf-8")
    heading = next(l for l in lifecycle.splitlines() if l.startswith("## 2. "))
    body = lifecycle[lifecycle.index(heading):]
    body = body[:body.index("\n## ", 1)] if "\n## " in body[1:] else body
    rows = [l for l in body.splitlines() if l.startswith("| **")]
    assert len(rows) == 5, rows
    assert "Five machines" in heading, heading
