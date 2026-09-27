# SPDX-License-Identifier: MIT
"""R16-02 / D2 — a part's digest is over that part's octets, and nothing else.

The Internet-Draft carried two rules about the same value. The manifest
definition said a part's `digest` is over the part's **decoded octets**; the
application-envelope section said a very large part MAY be chunked, "in which
case that part's manifest `digest` is the Merkle root over its chunks". Those
cannot both be true of one field, and the second defined nothing: no chunk size
or boundary rule, no leaf encoding, no node hashing, no domain separation, no
odd-node handling, and no discriminator telling a verifier which construction a
digest is.

So two implementations given identical bytes could choose different chunk sizes,
derive different roots, and violate no published rule — while the manifest
definition never admitted such a value in the first place. The maintainer's
decision of 27 September withdraws the sentence rather than repairing it;
profiling a construction is a decision with parameters and vectors attached, and
it is **A13** on the review agenda.

These tests hold the withdrawal in place: one rule for the value, the option
recorded where an open question lives, and no implementation left behind.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"
CDDL = ROOT / "cddl" / "sm-mls-erd.cddl"
AGENDA = ROOT / "docs" / "REVIEW_AGENDA.md"


def test_a_part_digest_has_one_rule_and_it_is_the_parts_octets():
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "`digest` over the part's decoded octets" in id_text
    cddl = " ".join(CDDL.read_text(encoding="utf-8").split())
    assert "over the part's decoded octets" in cddl, \
        "the machine-readable definition must carry the same rule"


def test_no_construction_is_profiled_for_a_chunked_part():
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "No Merkle construction is profiled" in id_text
    assert "the Merkle root over its chunks" not in id_text.replace(
        '"the Merkle root over its chunks"', ""), \
        "the withdrawn rule may be quoted as withdrawn, never stated as available"


def test_the_framing_that_exists_is_the_envelope_and_it_is_named_as_such():
    """This test used to assert the opposite half of its own docstring.

    D2 removed the Merkle construction and kept "a large part MAY be chunked in
    transport" as the surviving capability, and this test pinned that sentence
    while its own docstring noted that the profile's `chunking` transformation
    "is a different thing". They were not different things being kept apart —
    they were one mechanism described twice, once correctly at the envelope and
    once, with no descriptor, no evidence and no size bound, at the part. The
    profile bounds neither a message nor a part, nothing identifies a chunk of a
    part, no evidence records a part being split, and the TS says the only
    permitted transformations are on the envelope and its metadata because
    content cannot be transformed under end-to-end encryption.

    So the permission was withdrawn on 27 September and the invariant kept: the
    digest is over the part's whole decoded octets whatever framing carried
    them. A13 closes on that — no chunked part, so no construction question.
    """
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "Transport framing does not change what a part's `digest` covers" in id_text
    assert "reassembled before hashing" in id_text, "the invariant survives the permission"
    assert "MAY be chunked in transport" not in id_text.replace(
        '"MAY be chunked in transport"', ""), \
        "the withdrawn permission may be quoted as withdrawn, never stated as available"
    assert "Nothing in this profile splits a manifest part" in id_text
    # And the ground the closure ACTUALLY rests on. An earlier revision cited
    # the CE envelope transformations in its support, as "the framing operation
    # this profile defines". They are not defined — the output commitment of a
    # chunking operation is typed `mls10-message`, a complete MLSMessage, which
    # a fragment is not — so they are deferred and A13 stands on the part rule
    # alone, which is true independently of any envelope framing.
    assert "The two envelope transformations are NOT profiled, and are deferred" \
        in id_text.replace("**", "")
    assert "the framing operation this profile defines" not in id_text.replace(
        "described that as the framing operation this profile defines", ""), \
        "the withdrawn ground may be quoted as withdrawn, never relied on"
    ce = (ROOT / "schemas" / "evidence-ce.schema.json").read_text(encoding="utf-8")
    assert '"chunking"' in ce, "the envelope-framing transformation is untouched"
    assert '"part_envelope_hashes"' in ce


def test_the_word_part_is_disambiguated_where_both_meanings_meet():
    """`part_envelope_hashes` and a manifest `part_id` both say "part" and mean
    different objects — content, and a fragment of transmitted ciphertext. No
    normative text said which was which, and that collision is what let "that
    part's manifest `digest` is the Merkle root over its chunks" read as
    coherent: it joined a content part to transport fragments in one sentence.
    """
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "The word *part* in `part_envelope_hashes` names an emitted envelope and never a " \
           "manifest part" in id_text
    assert "that distinction survives the deferral" in id_text
    ts = " ".join((ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text(
        encoding="utf-8").split())
    assert "content transformation is forbidden" in ts, \
        "the confinement the closure rests on must still be in the TS"
    # This assertion used to require the TS to say that re-packaging and
    # chunking ARE the permitted transformations — the sentence the r26 review
    # found contradicting the I-D's prohibition. A probe that pins a claim can
    # hold a wrong claim in place, and this one did.
    assert "neither of the two the profile enumerates" in ts.replace("**", "")


def test_the_closure_records_what_would_have_to_come_first():
    """A13 is closed, not deleted, and the order matters.

    The reason the Merkle sentence survived a revision is that a construction
    reads like a small thing: pick a chunk size, hash the leaves. It is not. The
    row now says that if this reopens, the MECHANISM comes first — a descriptor,
    evidence of the split, a reassembly rule with a defined endpoint — and the
    construction only after, with its parameters and vectors. A closure that
    kept only the cryptographic shopping list would invite the same sentence
    back with better parameters and still no object to apply them to.
    """
    row = next(l for l in AGENDA.read_text(encoding="utf-8").splitlines()
               if l.startswith("| A13 |"))
    assert "Decided, 27 September 2026" in row
    assert "the question does not arise" in row
    for first in ("part-chunk descriptor", "evidence of the split",
                  "reassembly rule with a defined endpoint", "and only then the construction"):
        assert first in row, first
    for kept in ("chunk boundaries", "domain separation", "discriminator",
                 "odd number of chunks", "None is profiled"):
        assert kept in row, kept
    # NOT "per emitted envelope". That assertion made the wrong ground
    # MANDATORY: A13 was closed citing the CE envelope transformations as the
    # framing operation the profile defines, and they are not defined at all.
    # The closure stands on the part rule, which holds either way.
    assert "nothing in the profile splits a manifest part" in row.lower().replace("**", "")
    assert "deferred as" in row and "A15" in row, row[:200]


def test_no_record_still_defers_to_an_open_a13():
    """`SBM-ADR-0014` pointed forward — "if A13 ever profiles a chunk layer,
    whether it is salted is decided there". A13 is decided, and a proposal that
    routes a reviewer to an open question that has closed sends them nowhere."""
    adr = " ".join((ROOT / "docs" / "adr" / "SBM-ADR-0014.md").read_text(
        encoding="utf-8").split())
    assert "If A13 ever profiles a chunk layer" not in adr
    assert "A13 closed on 27 September 2026" in adr


def test_the_withdrawn_option_has_a_home():
    """An option removed without a record is an option that returns. A13 says
    what a construction would have to define before it could be admitted."""
    agenda = AGENDA.read_text(encoding="utf-8")
    row = next((l for l in agenda.splitlines() if l.startswith("| A13 |")), None)
    assert row, "the withdrawal must be recorded as an open question"
    for needed in ("Merkle", "chunk boundaries", "domain separation", "discriminator",
                   "odd number of chunks"):
        assert needed in row, needed
    assert "None is profiled" in row


def test_nothing_implements_a_merkle_construction():
    """It was never implemented: no script, test, sample, registry or schema
    carried a parameter for it. The withdrawal leaves nothing orphaned, and
    nothing may quietly appear without A13 being answered."""
    hits = []
    for pattern in ("scripts/*.py", "tests/*.py", "samples/*.json",
                    "registries/*.json", "schemas/*.json", "cddl/*.cddl"):
        for path in sorted(ROOT.glob(pattern)):
            if path.name == pathlib.Path(__file__).name:
                continue
            if re.search(r"merkle", path.read_text(encoding="utf-8"), re.I):
                hits.append(path.relative_to(ROOT).as_posix())
    assert hits == [], hits


def test_no_reader_facing_document_offers_the_withdrawn_construction():
    """The scan above covers code, samples and machine-readable authorities.
    It never read `docs/`, and `SBM-ADR-0014` went on asking the group whether
    "the Merkle chunk layer" should be salted for three days after the
    construction was withdrawn — a question about something the profile does
    not have, put to the reviewers A13 was opened for. An option removed
    without a record is an option that returns, and so is one removed from the
    specification and left standing in a proposal.

    A mention is allowed; an OFFER is not. Every block that names the
    construction must also say, in that block, that none is profiled.
    """
    WITHDRAWN = re.compile(r"not profiled|none is profiled|no merkle construction|"
                           r"withdrawn|withdraw|never admitted", re.I)
    problems = []
    for path in sorted(list(ROOT.glob("*.md")) + list(ROOT.glob("docs/**/*.md"))
                       + list(ROOT.glob("ietf/*.md")) + list(ROOT.glob("etsi/*.md"))):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("docs/reviews/") or rel == "CHANGELOG.md":
            continue                      # a review and a history record what WAS said
        for block in re.split(r"\n\s*\n", path.read_text(encoding="utf-8")):
            flat = " ".join(block.split())
            if re.search(r"merkle", flat, re.I) and not WITHDRAWN.search(flat):
                problems.append(f"{rel}: {flat[:140]}")
    assert problems == [], problems


def test_the_manifest_rules_still_say_what_the_digest_covers():
    """The rule the withdrawal rests on: a part's digest is over the part's
    octets. If that goes, reassembly has no defined endpoint and A13's closure
    loses its ground.

    The wording moved. "digests are over decoded octets (permitted content
    encodings `identity`, `gzip`)" named an encoding layer that does not exist
    inside the MLS application data and gave no field in which to declare one,
    so the term had no referent; the rule is now stated as the identity it is,
    and *decoded octets* is defined once against it.
    """
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "`length` is their count and `digest` is over them" in id_text
    assert "*decoded octets*, used throughout this document for this value, " \
           "therefore means exactly the part's octets" in id_text
    assert "permitted content encodings" not in id_text.replace(
        '"content encodings `identity`, `gzip`"', ""), \
        "the withdrawn permission may be quoted as withdrawn, never offered"


def test_a_manifest_is_flat_in_all_three_authorities():
    """The nesting rule was stated three ways: the prose permitted one level,
    the Schema and the CDDL permitted none, and the linter guarded a depth
    neither could produce. The prose was the outlier."""
    import json
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "**A manifest is flat.**" in id_text
    assert "nesting is at most one level" not in id_text.replace(
        '"nesting is at most one level"', ""), \
        "the withdrawn permission may be quoted as withdrawn, never stated"
    part = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text(
        encoding="utf-8"))["$defs"]["Manifest"]["items"]
    assert part["additionalProperties"] is False
    assert "manifest" not in part["properties"]
    cddl = " ".join(CDDL.read_text(encoding="utf-8").split())
    body = cddl[cddl.index("manifest-part ="):]
    assert "manifest:" not in body[:body.index("}")]
    # And the second, independent exclusion: a part digest cannot carry a mode
    # that commits to a structure.
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text(
        encoding="utf-8"))
    assert set(common["$defs"]["RawHash"]["properties"]["hash_mode"]["enum"]) == \
        {"raw-sha256", "raw-sha512"}


def test_the_retired_rule_is_recorded_and_its_identifier_is_not_reused():
    """An identifier is assigned once. A rule that leaves the catalogue is
    recorded with its reason, so a reader of an artefact sealed under an earlier
    edition — or of a checker built from an earlier catalogue — can still find
    out what it meant and why it is gone."""
    import json
    cat = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text(encoding="utf-8"))
    assert "LINT-MAN-03" not in [r["id"] for r in cat["rules"]]
    assert "LINT-MAN-03" not in cat["coverage_gap"], \
        "a retired rule is not a coverage gap; it is not a rule"
    retired = cat["retired"]["LINT-MAN-03"]
    assert retired["retired"] == "2026-09-27"
    for needed in ("not expressible", "observed-octets domain", "coverage_gap"):
        assert needed in retired["reason"], needed
    assert retired["was"]["predicate"], "what it used to say must survive verbatim"
    lint = (ROOT / "scripts" / "evidence_lint.py").read_text(encoding="utf-8")
    body = lint[lint.index("def lint_manifest("):]
    body = body[:body.index("\ndef ")]
    assert "depth" not in body.split('"""')[2], "the recursion must be gone, not guarded"
