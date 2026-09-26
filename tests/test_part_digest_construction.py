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


def test_chunking_survives_where_it_belongs():
    """Removing the construction must not remove the capability: a large part
    may still be chunked in transport, and the chunks are reassembled before
    hashing. The profile also carries a `chunking` transformation for envelope
    framing, which is a different thing and is untouched."""
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "MAY be chunked **in transport**" in id_text
    assert "reassembled before hashing" in id_text
    ce = (ROOT / "schemas" / "evidence-ce.schema.json").read_text(encoding="utf-8")
    assert '"chunking"' in ce, "the envelope-framing transformation is a separate mechanism"


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


def test_the_manifest_rules_still_say_what_the_digest_covers():
    """The rule that survives is the one the reassembly depends on: digests are
    over decoded octets. If that sentence goes, chunk reassembly has no defined
    endpoint and the withdrawal loses its ground."""
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "digests are over decoded octets" in id_text
