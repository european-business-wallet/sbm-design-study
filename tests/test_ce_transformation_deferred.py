# SPDX-License-Identifier: MIT
"""R23-02 — a Change-Indication Evidence transformation is not a defined operation.

A CE enumerates `re-packaging` and `chunking` and commits to the input octets and
to each output. The r23 edition leaned on that, closing the chunked-part question
by calling envelope framing "the framing operation this profile defines". It is
not one:

- the output commitment is typed `EnvelopeHash`, whose `format` is fixed to
  `mls10-message` — SHA-256 over a **complete** TLS-serialized MLSMessage. A
  fragment of an encrypted MLSMessage is not an MLSMessage, so a chunking CE's
  outputs are typed to a domain their values cannot be in;
- re-packaging an unchanged MLSMessage in an outer wrapper leaves the inner
  octets untouched, so the output commitment equals the input;
- no published contract defines a fragment descriptor, a chunk order, a
  reassembly operation, or the boundary at which the original message is
  reconstructed and checked.

So two providers given one message could not perform the same transformation, and
no verifier could reproduce either from the evidence. Both are **deferred** as
A15. What survives is the part rule, which was always true independently: nothing
in this profile splits a manifest part.

The seal still establishes who attested what. The **relation of the outputs to
the input** is what nothing establishes, and `LINT-BND-I7` is how a bundle says
so rather than reading a CE as an attested re-framing.
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"
AGENDA = ROOT / "docs" / "REVIEW_AGENDA.md"


def _id_flat():
    return " ".join(ID.read_text(encoding="utf-8").split())


# --- the type mismatch the finding rests on ---------------------------------

def test_the_output_commitment_is_typed_to_a_complete_message():
    """If this type ever admits a fragment, the finding changes shape — so the
    fact it rests on is asserted here and not only described."""
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text(
        encoding="utf-8"))
    eh = common["$defs"]["EnvelopeHash"]
    assert eh["properties"]["format"]["const"] == "mls10-message"
    assert "complete" in eh["description"] or "exact wire object" in eh["description"]
    ce = json.loads((ROOT / "schemas" / "evidence-ce.schema.json").read_text(encoding="utf-8"))
    parts = ce["properties"]["part_envelope_hashes"]
    assert parts["items"]["$ref"].endswith("EnvelopeHash"), parts["items"]
    assert parts["minItems"] == 2


# --- the deferral, stated where an implementer reads it ---------------------

def test_both_transformations_are_deferred_and_must_not_be_issued():
    flat = _id_flat().replace("**", "")
    assert "The two envelope transformations are NOT profiled, and are deferred" in flat
    assert "an RDP MUST NOT issue a CE with either transformation" in flat
    assert "treat the transformation as unproven rather than as an attested re-framing" in flat
    # The reasons, each of them, so a later reader cannot repair one and assume
    # the rest resolved with it.
    assert "a fragment of an MLSMessage is not an MLSMessage" in flat
    assert "leaves the inner octets untouched, so its output commitment equals its input" in flat
    assert "no published contract defines a fragment descriptor" in flat


def test_the_closure_it_wrongly_supported_now_rests_on_the_part_rule_alone():
    """A13 stands: nothing splits a manifest part, which is true whatever
    happens to envelope framing. What is withdrawn is the ground an earlier
    revision gave for it."""
    flat = _id_flat().replace("**", "")
    assert "Nothing in this profile splits a manifest part" in flat
    row = next(l for l in AGENDA.read_text(encoding="utf-8").splitlines()
               if l.startswith("| A13 |"))
    assert "Decided, 27 September 2026" in row, "A13 is not reopened by this"


def test_the_deferral_is_an_agenda_entry_with_what_a_definition_must_pin():
    row = next((l for l in AGENDA.read_text(encoding="utf-8").splitlines()
                if l.startswith("| A15 |")), None)
    assert row, "a deferred mechanism without a record is a mechanism that returns"
    assert "Deferred, 27 September 2026" in row
    for needed in ("fragment descriptor", "reassembly boundary", "repeated transformations",
                   "transport-frame commitment of its own", "published trace"):
        assert needed in row, needed
    # And the sample's own values, named rather than left to be discovered again.
    assert "demo-part:<message_id>:1" in row
    assert "hashing real bytes does not put them in the declared domain" in row


def test_no_document_still_presents_the_transformations_as_available():
    """R26-PUB-04's closure test, and the check that would have prevented it.

    The deferral went into the Internet-Draft and the agenda and stopped there.
    The TS went on saying re-packaging and chunking were "the only permitted
    transformations" and that an RDP "shall issue" a CE for one; the agenda's
    own A13 row said a provider "may re-package it or split it"; and the
    evidence explainer introduced CE as issued for permitted transformations.
    An implementer could satisfy the prohibition or the duty, not both.

    One status, swept across every document that states it. A mention is fine;
    an OFFER is not — so a sentence naming either transformation must carry the
    deferral in the same block.
    """
    DEFER = re.compile(r"not profiled|deferred|MUST NOT issue|shall not\s+issue|"
                       r"neither is profiled|neither of the two|unproven|none is defined",
                       re.I)
    NAMES = re.compile(r"re-packaging|chunking", re.I)
    # The word "chunking" also names the WITHDRAWN part-level chunking, which
    # is A13's subject and not a CE transformation. A block is in scope only if
    # it is about the evidence object — otherwise this sweep reports the
    # paragraph that records the other withdrawal, which is correct as written.
    CE_CONTEXT = re.compile(r"\bCE\b|Change-Indication|transformation", re.I)
    problems = []
    for pattern in ("*.md", "docs/*.md", "docs/adr/*.md", "ietf/*.md", "etsi/*.md"):
        for path in sorted(ROOT.glob(pattern)):
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith("docs/reviews/") or rel == "CHANGELOG.md" \
                    or rel.startswith("docs/DESIGN_") or rel.startswith("docs/FEDERATION_"):
                continue                       # reviews and histories record what WAS said
            for block in re.split(r"\n\s*\n", path.read_text(encoding="utf-8")):
                flat = " ".join(block.split())
                if NAMES.search(flat) and CE_CONTEXT.search(flat) and not DEFER.search(flat):
                    problems.append(f"{rel}: {flat[:150]}")
    assert problems == [], problems


def test_the_duty_to_evidence_a_transformation_survives_the_deferral():
    """Deferring the two operations must not delete the obligation: when a
    transformation IS defined, the provider still owes evidence for it. The TS
    keeps the duty and scopes it to what the profile has defined."""
    ts = " ".join((ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text(
        encoding="utf-8").split())
    assert "Whenever a transformation the profile has defined occurs — none is defined today " \
           "— the responsible RDP shall issue a Change-Indication Evidence" in ts
    assert "shall be made available to both the sender and the addressee" in ts


# --- the gap a bundle reports -----------------------------------------------

def test_the_bundle_verifier_reports_the_transformation_as_unestablished():
    """`LINT-BND-I7`, on the bundle that actually ships a CE — nested inside an
    Evidence Package's `changes[]`, which is why the precondition had to reach
    there: reporting the gap for a loose CE and not for the same CE inside a
    package would be reporting by the accident of packaging."""
    out = subprocess.run(
        [sys.executable, "scripts/bundle_lint.py", "--allow-incomplete",
         "--trust-store", "samples/trust-store.demo.json",
         "samples/bundle.federated.manifest.json"],
        cwd=ROOT, capture_output=True, text=True).stdout
    assert "LINT-BND-I7" in out, out[-600:]
    assert "NOT ESTABLISHED" in out
    # And it is a GAP, not a violation: the seal is valid and says who attested
    # what; only the relation of the outputs to the input is unproven.
    assert "0 violation(s)" in out, out[-400:]


def test_the_property_is_declared_and_mandatory():
    table = json.loads((ROOT / "docs" / "required-properties.json").read_text(encoding="utf-8"))
    row = next(p for p in table["properties"] if p["id"] == "envelope-transformation")
    assert row["gap_rule"] == "LINT-BND-I7"
    assert row["input"] == "transformation_traces", \
        "the input that WOULD establish it is named, so a definition has somewhere to arrive"
    assert row["when"]["kind"] == "evidence_or_nested_has_field"
    assert "envelope-transformation" in table["mandatory"], \
        "an undeclared property could be deleted without anything noticing"
    import bundle_lint
    assert "transformation_traces" in bundle_lint.RETAINED_MATERIAL_INPUTS
