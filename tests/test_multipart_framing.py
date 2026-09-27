# SPDX-License-Identifier: MIT
"""A14 — the published multipart manifest is derivable from the framing.

Before this pass the profile described the parts of a multipart payload and bound
them, and said nothing about how a recipient finds part N's octets. Two
independent implementations could satisfy every rule and fail to exchange one
multipart message. What let that survive a dozen review rounds is the shape of
the Mode C commitment: `payload_hash` is the digest of the **manifest**, not of
the plaintext, so every check a provider or a bundle verifier can run passes on
one implementation's own bytes, and a recipient that recomputed only
`payload_hash` compared the manifest with itself.

The framing decided on 27 September 2026: the payload is the dCBOR encoding of an
array of `{part_id, octets}` maps in byte-wise ascending `part_id` order, whose
`part_id` set equals the manifest's exactly.

The test that matters most is the first: the manifest `sample-SE-multipart.json`
publishes is reproduced from the two fixture files through the framing — so an
implementer who builds a payload as specified arrives at the digests this
repository ships, which is the whole interop claim.
"""
import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import multipart as mp  # noqa: E402

SE = json.loads((ROOT / "samples" / "sample-SE-multipart.json").read_text())["projection"]
FIXTURES = ROOT / "samples" / "fixtures" / "multipart"


def parts():
    """{part_id: octets} from the files the published manifest names."""
    return {p["part_id"]: (FIXTURES / p["filename"]).read_bytes() for p in SE["manifest"]}


# --- the interop claim ------------------------------------------------------

def test_the_published_manifest_is_reproduced_from_the_fixtures_through_the_framing():
    payload = mp.assemble(parts())
    assert mp.verify_against_manifest(payload, SE["manifest"], SE["payload_hash"]) == []


def test_assembly_is_deterministic_and_order_independent():
    """Two senders holding the same parts emit the same payload, whatever order
    they happened to hold them in. Without that, `envelope_hash` over a
    multipart message is not independently recomputable, which is the property
    the relay path's only integrity check rests on."""
    p = parts()
    reversed_input = {k: p[k] for k in reversed(list(p))}
    assert mp.assemble(p) == mp.assemble(reversed_input)
    assert [pid for pid, _ in mp.parse(mp.assemble(p))] == sorted(p)


def test_a_round_trip_returns_the_octets_unchanged():
    p = parts()
    assert dict(mp.parse(mp.assemble(p))) == p


# --- every deviation is refused, because a tolerated one is a second framing --

def test_a_positional_array_is_refused():
    """The encoding is keyed by `part_id`, for the reason the manifest is a list
    of maps rather than a fixed array: a positional encoding is one silent
    reordering away from attributing a part's octets to another descriptor."""
    positional = lc.dcbor([v for _, v in sorted(parts().items())])
    with pytest.raises(mp.MultipartError, match="not a map"):
        mp.parse(positional)


def test_an_out_of_order_payload_is_refused():
    p = parts()
    records = [{"part_id": pid, "octets": p[pid]} for pid in sorted(p, reverse=True)]
    with pytest.raises(mp.MultipartError, match="ascending part_id order"):
        mp.parse(lc.dcbor(records))


def test_a_duplicate_part_id_is_refused():
    pid, data = next(iter(parts().items()))
    with pytest.raises(mp.MultipartError, match="duplicate part_id"):
        mp.parse(lc.dcbor([{"part_id": pid, "octets": data},
                           {"part_id": pid, "octets": data}]))


def test_a_non_deterministic_encoding_is_refused():
    """A digest is a property of the bytes that travelled. An encoding that
    re-serialises to different bytes is not the framing, even where a decoder
    accepts it — this is the rule the whole profile turns on, applied one level
    down."""
    import cbor2
    p = parts()
    loose = cbor2.dumps([{"octets": p[pid], "part_id": pid} for pid in sorted(p)],
                        canonical=False)
    if loose == mp.assemble(p):
        pytest.skip("this encoder emits canonical bytes for the loose input too")
    with pytest.raises(mp.MultipartError):
        mp.parse(loose)


def test_an_empty_payload_is_refused():
    with pytest.raises(mp.MultipartError):
        mp.assemble({})
    with pytest.raises(mp.MultipartError, match="non-empty"):
        mp.parse(lc.dcbor([]))


# --- the recipient's obligation, in the order the I-D states it -------------

def test_a_part_whose_octets_differ_is_reported_even_though_payload_hash_matches():
    """The defect the ordering exists to catch, and the reason A14 could hide.

    `payload_hash` is the digest of the manifest, so it matches here by
    construction: the manifest is untouched and only the CONTENT was swapped. A
    recipient performing the old wording — "recompute `payload_hash`" — would
    have confirmed a match for a message whose every part was replaced.
    """
    p = parts()
    pid = sorted(p)[0]
    p[pid] = b"a different document entirely"
    problems = mp.verify_against_manifest(mp.assemble(p), SE["manifest"], SE["payload_hash"])
    assert problems, "content was replaced and the check passed"
    assert any("digest over the octets received" in x for x in problems), problems
    # And the manifest digest still matches, which is the point.
    import hashlib
    assert hashlib.sha256(lc.dcbor(SE["manifest"])).hexdigest() == SE["payload_hash"]["hex"]


def test_a_length_that_disagrees_with_the_octets_is_reported():
    manifest = copy.deepcopy(SE["manifest"])
    manifest[0]["length"] = str(int(manifest[0]["length"]) + 1)
    problems = mp.verify_against_manifest(mp.assemble(parts()), manifest, SE["payload_hash"])
    assert any("manifest length" in x for x in problems), problems


def test_a_part_on_one_side_only_is_reported_from_both_directions():
    p = parts()
    extra = dict(p, zz_extra=b"undescribed")
    problems = mp.verify_against_manifest(mp.assemble(extra), SE["manifest"], SE["payload_hash"])
    assert any("not described by the manifest" in x for x in problems), problems

    manifest = copy.deepcopy(SE["manifest"]) + [{
        "part_id": "zz_missing", "role": "attachment", "media_type": "text/plain",
        "length": "1", "digest": {"alg": "SHA-256", "hash_mode": "raw-sha256", "hex": "aa" * 32}}]
    problems = mp.verify_against_manifest(mp.assemble(p), manifest, SE["payload_hash"])
    assert any("absent from the payload" in x for x in problems), problems


def test_the_manifest_digest_is_checked_after_the_parts_and_not_instead():
    """Both steps exist. With the parts right and the declared `payload_hash`
    wrong, the second step must fire — otherwise the first would be the only
    check and a manifest could be swapped wholesale."""
    bad = dict(SE["payload_hash"], hex="b" * 64)
    problems = mp.verify_against_manifest(mp.assemble(parts()), SE["manifest"], bad)
    assert problems == ["the manifest's digest is not the declared payload_hash"], problems


# --- the documents say it ---------------------------------------------------

def test_the_framing_is_normative_in_both_authorities():
    id_text = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "payload-multipart = [ + payload-part ]" in id_text
    assert "byte-wise ascending `part_id`** order" in id_text
    assert "set of `part_id` values MUST be exactly the manifest's" in id_text
    assert "payload is therefore self-describing" in id_text
    cddl = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    assert "payload-multipart = [+ payload-part]" in cddl
    assert "payload-part  = {" in cddl


def test_mode_c_re_verification_names_both_steps_in_order():
    """The correction A14 made possible: with no framing there was no way to
    state the first step, so the rule said only "recompute `payload_hash`" —
    which a Mode C recipient satisfies without reading the content."""
    id_text = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "only the first touches the content" in id_text
    assert "recompute each part's `digest` from the octets it received" in id_text
    two = id_text[id_text.index("Under Mode C that is two recomputations"):]
    two = two[:two.index("**Confirmation object.**")]
    assert two.index("recompute each part") < two.index("recompute the manifest digest"), \
        "the order is the rule: the parts first, the manifest digest second"
    assert "`mismatch` confirmation" in two, \
        "a failure is reported as a mismatch is, not through a new outcome"


def test_the_carrier_is_a_stated_compatibility_boundary():
    """It adds no field and re-seals nothing, so it was reported as moving no
    version and nothing on the wire. That was wrong in the way that matters: a
    layout previously unconstrained is now the only conformant one, and an
    implementer had no number to name to say which of the two worlds it
    implements. The application-envelope version is that number, and it covers
    the layout of the application data as well as the headers."""
    id_text = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "first mandatory carrier for Mode C, and it is a compatibility boundary" \
        in id_text.replace("**", "")
    assert "declaring **1.4 or later**" in id_text
    assert "nothing may be assumed about the carrier of an implementation built to an " \
           "earlier one" in id_text
    assert "a later edition does not reach backwards" in id_text

    import json
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    dim = manifest["dimensions"]["application_envelope"]
    assert dim["value"] == "1.4"
    assert "the layout of the application data" in dim["note"], \
        "the dimension's own note scoped it to the headers, which is how the change " \
        "came to move no version"
    # The I-D's reference to the schema is BOUND now: it said v1.1 while the
    # schema title said v1.3, a number restated where nothing derived it.
    bound = [b["file"] for b in dim["bindings"]]
    assert "ietf/draft-sbm-mls-erd-00.md" in bound, bound
    assert "`schemas/envelope.schema.json` (v1.4)" in \
        (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text(encoding="utf-8")


def test_the_agenda_records_the_decision():
    row = next(l for l in (ROOT / "docs" / "REVIEW_AGENDA.md").read_text().splitlines()
               if l.startswith("| A14 |"))
    assert "Decided, 27 September 2026" in row
    assert "payload-multipart" in row
    for kept in ("no delimiter", "concatenated"):
        assert kept in row, kept
