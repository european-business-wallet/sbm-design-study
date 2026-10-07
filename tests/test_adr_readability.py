# SPDX-License-Identifier: MIT
"""The decision records must be readable by someone who did not write them.

A record is read in two places: as a row of the generated decisions index, and
on its own, by somebody who followed a citation to it. Both readings put the
same requirement on it — that it expands the vocabulary its own decision turns
on, rather than assuming the reader arrived with it.

These are the rules of that pass, shown firing. Two of them exist because this
file's first run found things the pass itself had missed:

  * `SBM-ADR-0001` expanded `EDD` as *"entity discovery directory"*. Every other
    document in the repository — the umbrella's glossary, two published
    contracts, the architecture figure, the vision document, `SBM-ADR-0002` —
    says *European Directory of Entities*. One record taught a reader a second
    name for the same institution, and nothing compared the two.
  * the index's trade-off cell welded `benefit` and `cost` together with
    "— at the cost of", which made one sentence out of two lists of noun
    phrases and left the reader to find the hinge before knowing which half they
    were in.
"""
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import adr_index  # noqa: E402

UMBRELLA = ROOT / "Secure-Business-Messaging-Profile.md"
#: Where an expansion may be stated. The umbrella's glossary compresses the
#: evidence family to *"Sending / Delivery / Non-Delivery / Refusal / Evidence
#: Package"*, so `Delivery Evidence` is spelled out in the Internet-Draft's
#: object list and nowhere in the umbrella. Both are normative text a record may
#: be held to; neither alone carries every name.
NORMATIVE = (UMBRELLA, ROOT / "ietf" / "draft-sbm-mls-erd-00.md")

#: The terms the records lean on, with the expansion the umbrella's glossary
#: gives. Checked against the glossary, so a record cannot drift from the
#: normative text by being edited on its own.
GLOSSARY_TERMS = {
    "RDP": "Registered Delivery Provider",
    "SE": "Sending Evidence",
    "DE": "Delivery Evidence",
    "EDD": "European Directory of Entities",
}

#: The WITHDRAWN role. SBM-ADR-0015 removed it from every current-facing
#: document, so its expansion cannot be read from the umbrella and must not be
#: required there — `tests/test_stale_roles.py` is the gate that keeps it out.
#: The decision records keep the name because they are the history that explains
#: it, which is why `docs/adr/` is exempt from that scan. A reader following a
#: citation into one of them still needs to be told what it was.
HISTORICAL_TERMS = {"MSP": "Messaging Service Provider"}

TERMS = {**GLOSSARY_TERMS, **HISTORICAL_TERMS}


def _records():
    return adr_index.load()


def _prose(body):
    """The body as a reader meets it: code spans and link targets removed, and
    wrapped lines joined — a term expanded across a line break is expanded."""
    text = re.sub(r"`[^`]*`", "", body)
    text = re.sub(r"\]\([^)]*\)", "]", text)
    return " ".join(text.split())


def test_the_glossary_states_the_expansions_these_rules_hold_records_to():
    """The expansions are not this file's opinion. If the umbrella renames an
    institution, this test fails before the records are judged against a stale
    name."""
    glossary = UMBRELLA.read_text(encoding="utf-8")
    assert "**EDD**: European Directory of Entities" in glossary
    assert "Sending / Delivery / Non-Delivery / Refusal / Evidence Package" in glossary
    normative = "\n".join(p.read_text(encoding="utf-8") for p in NORMATIVE)
    for term, full in GLOSSARY_TERMS.items():
        assert full in normative, (term, full)
    # And the withdrawn role is NOT in the current-facing text, which is the
    # other half of the same claim.
    for term, full in HISTORICAL_TERMS.items():
        assert full not in glossary, \
            f"{full!r} is back in current-facing text; see tests/test_stale_roles.py"


@pytest.mark.parametrize("stem", [p.stem for p in sorted(
    (ROOT / "docs" / "adr").glob("SBM-ADR-*.md"))])
def test_a_record_expands_the_terms_it_leans_on(stem):
    """Before or at its first use in the body. A title may carry the short form —
    the title is the record's name, and `SBM-ADR-0004` is cited by one that has
    two acronyms in it — but then the Context opens by saying what they mean."""
    p, fm, body = next(r for r in _records() if r[0].stem == stem)
    prose = _prose(body)
    for term, full in TERMS.items():
        m = re.search(rf"\b{term}s?\b", prose)
        if not m:
            continue
        before = prose[:m.end()].lower()
        if full.lower() in before:
            continue
        # not expanded yet: it may only be the title, and the body must then
        # expand it in the first section.
        context = prose.find("## Context")
        assert m.start() < context, \
            f"{stem}: `{term}` is used in the body before anything says it means {full!r}"
        opening = prose[context:context + 1200].lower()
        assert full.lower() in opening, \
            f"{stem}: the title uses `{term}` and the Context does not say it means {full!r}"


def test_no_record_gives_a_term_an_expansion_of_its_own():
    """The defect this file was written for. A second expansion of one acronym is
    worse than none: a reader cannot tell whether two names are two things."""
    wrong = {"EDD": ["entity discovery directory", "european discovery directory"],
             "RDP": ["registered delivery party"],
             "SE": ["submission evidence"],
             "DE": ["delivery event"]}
    found = []
    for p, fm, body in _records():
        low = _prose(body).lower()
        for term, bad_forms in wrong.items():
            for bad in bad_forms:
                if bad in low:
                    found.append((p.stem, term, bad))
    assert found == [], found


def test_the_index_labels_the_two_halves_of_the_trade_off():
    """The index's own readability, which is generated and so is a property of
    the renderer. Each cell says which half the reader is in, and each half has
    something in it."""
    index = (ROOT / "docs" / "decisions-index.md").read_text(encoding="utf-8")
    rows = [l for l in index.splitlines() if l.startswith("| [SBM-ADR-")]
    assert len(rows) >= 16, len(rows)
    for row in rows:
        trade = row.strip("|").split("|")[2]
        assert "**Buys:**" in trade and "**Costs:**" in trade, row
        buys, _, costs = trade.partition("**Costs:**")
        assert len(buys.split()) > 4 and len(costs.split()) > 4, row
    # and the welded form is gone, so a reader is not asked to find the hinge
    assert "— at the cost of" not in index


def test_a_summary_field_is_sentences_not_a_pile_of_clauses():
    """`benefit` and `cost` are what the index shows. They were semicolon-joined
    noun phrases — *"one accountable, qualified party observes, transfers and
    attests; A9 and L1 dissolve by construction; one fewer identity, contract,
    descriptor and interface"* — which is a telegram, not a sentence. A reader of
    the index meets these before anything else."""
    for p, fm, body in _records():
        for field in ("benefit", "cost"):
            text = " ".join(str(fm[field]).split())
            assert text[0].isupper() or text.startswith("`"), \
                f"{p.stem}: `{field}` does not begin a sentence: {text[:60]!r}"
            assert text.count(";") <= 1, \
                f"{p.stem}: `{field}` chains {text.count(';')} clauses with semicolons: {text[:90]!r}"
