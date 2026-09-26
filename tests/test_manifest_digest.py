# SPDX-License-Identifier: MIT
"""R16-01 — the outer manifest digest, and the digests that were typed.

Two claims were conflated, and only one of them is unverifiable from evidence:

- **each part carries the digest of its own octets** cannot be checked without
  the plaintext. The parts are end-to-end-encrypted and absent, so only a party
  holding them can recompute a part digest. The text was right about this;
- **`payload_hash` is the digest of the manifest present** can be checked by
  anyone holding the evidence, because the declared value and its input are both
  in the object. Nothing checked it.

So `samples/sample-SE-multipart.json` shipped a hand-typed `payload_hash`, a
hand-typed part digest, and a sender confirmation echoing the typed value —
through the Schema, the CDDL, the seal and the linter, because a seal covers
whatever body it is given. `samples/sample-CE.json` shipped a fourth typed value
in `envelope_digest_after`, and the same invented digest `e1f2a3b4c5d6e7f8…`
served as two unrelated things in the two samples.

An implementer reproducing a published vector got a different number with every
gate green, which is the one state a conformance suite cannot report. These tests
close that: LINT-MAN-04 checks the half that is checkable, and a shape scan
refuses a digest that was typed rather than computed.
"""
import glob
import hashlib
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_lint as el  # noqa: E402
from lint_cli import dcbor  # noqa: E402

MULTIPART = ROOT / "samples" / "sample-SE-multipart.json"
FIXTURES = ROOT / "samples" / "fixtures" / "multipart"

# A digest nobody computed. Real SHA-2 output does not walk the alphabet: these
# are the shapes a keyboard produces — ascending nibble runs and repeated pairs.
TYPED = re.compile(r"(0123456789abcdef|123456789a|a1b2c3d4|b2c3d4e5|c3d4e5f6|"
                   r"1122334455|2233445566|deadbeef|cafebabe|0{12,}|f{12,})")


def _projection(path):
    doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return doc.get("projection", doc)


# --- the half that is checkable ---------------------------------------------

def test_the_shipped_multipart_sample_is_reproducible():
    """The acceptance criterion: a second implementation computes the published
    value from the published manifest."""
    se = _projection(MULTIPART)
    computed = hashlib.sha256(dcbor(se["manifest"])).hexdigest()
    assert se["payload_hash"]["hex"] == computed, "the outer digest must be reproducible"
    assert se["payload_hash"]["hash_mode"] == "manifest-sha256"
    assert se["sender_confirmation"]["payload_hash"]["hex"] == computed, \
        "the sender's signed echo must be the same value, not a stale copy"


def test_every_part_digest_is_the_digest_of_a_fixture():
    """Every digest in a published sample is the digest of bytes this repository
    holds. The parts are files, and their declared lengths are those files'."""
    for part in _projection(MULTIPART)["manifest"]:
        fixture = FIXTURES / part["filename"]
        octets = fixture.read_bytes()
        assert part["length"] == str(len(octets)), part["part_id"]
        assert part["digest"]["hex"] == hashlib.sha256(octets).hexdigest(), part["part_id"]
        assert part["digest"]["hash_mode"] == "raw-sha256", \
            "a part digest is over that part's own octets"


def test_a_mutated_manifest_is_refused_even_when_validly_resealed():
    """The acceptance criterion the review asks for: mutating a manifest field
    without updating the digest must be rejected, *even after applying a new
    valid signature*. A seal proves who sealed the body, not that the body is
    faithful to itself."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
    mock = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mock)
    except Exception as exc:                      # pragma: no cover
        pytest.skip(f"mock_rdp not importable ({exc})")
    se = _projection(MULTIPART)
    se["manifest"][0]["media_type"] = "application/postscript"   # one field, digest left alone
    verdict = el.lint(mock.evidence_artifact(se))
    rules = [r for r, _ in verdict]
    assert "LINT-MAN-04" in rules, verdict
    assert "LINT-PKG-01" not in rules and "LINT-PKG-06" not in rules, \
        "the artefact is genuinely and validly sealed; the refusal is about the body"


def test_the_typed_value_that_shipped_is_refused():
    se = _projection(MULTIPART)
    se["payload_hash"]["hex"] = "9a3c1b7f2e5d4068a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778a"
    v = el.Violations()
    el.lint_manifest_digest(v, se)
    assert [r for r, _ in v.items] == ["LINT-MAN-04"], v.items


def test_a_manifest_with_a_raw_mode_is_refused():
    """A multipart payload is committed by the manifest modes. `raw-sha256`
    beside a manifest claims the digest is over transmitted octets that the
    manifest does not describe."""
    se = _projection(MULTIPART)
    se["payload_hash"]["hash_mode"] = "raw-sha256"
    v = el.Violations()
    el.lint_manifest_digest(v, se)
    assert [r for r, _ in v.items] == ["LINT-MAN-04"], v.items


def test_an_object_without_a_manifest_is_not_touched():
    se = _projection(ROOT / "samples" / "sample-SE.json")
    v = el.Violations()
    el.lint_manifest_digest(v, se)
    assert v.items == []


def test_sha512_is_computed_with_sha512():
    """`alg` selects the function; a 512-mode manifest must not be checked with
    SHA-256 and silently pass."""
    se = _projection(MULTIPART)
    manifest = se["manifest"]
    se["payload_hash"] = {"alg": "SHA-512", "hash_mode": "manifest-sha512",
                          "hex": hashlib.sha512(dcbor(manifest)).hexdigest()}
    v = el.Violations()
    el.lint_manifest_digest(v, se)
    assert v.items == []
    se["payload_hash"]["hex"] = hashlib.sha256(dcbor(manifest)).hexdigest() + "0" * 64
    v = el.Violations()
    el.lint_manifest_digest(v, se)
    assert [r for r, _ in v.items] == ["LINT-MAN-04"]


# --- no shipped digest was typed -------------------------------------------

def typed_digests(root):
    """[(sample, field, value)] — a digest whose shape says a person wrote it."""
    out = []
    for path in sorted(glob.glob(str(root / "samples" / "*.json"))):
        text = pathlib.Path(path).read_text(encoding="utf-8")
        for m in re.finditer(r'"([a-z_]*hex|[a-z_]*digest)":\s*"([0-9a-f]{64,128})"', text):
            if TYPED.search(m.group(2)):
                out.append((pathlib.Path(path).name, m.group(1), m.group(2)))
    return out


def test_no_shipped_digest_was_typed():
    assert typed_digests(ROOT) == []


def test_the_scan_finds_the_values_that_shipped(tmp_path):
    """The four that r17 published, in the shapes they had."""
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "s.json").write_text(json.dumps({
        "payload_hash": {"hex": "9a3c1b7f2e5d4068a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778a"},
        "manifest": [{"digest": {"hex": "e1f2a3b4c5d6e7f809a1b2c3d4e5f60718293a4b5c6d7e8f9012233445566778"}}],
    }), encoding="utf-8")
    found = typed_digests(tmp_path)
    assert len(found) == 2, found


def test_a_real_digest_is_not_mistaken_for_a_typed_one():
    """Every digest the repository actually computes must pass, or the scan is
    noise: this is the whole shipped set, checked above, plus the fixtures."""
    for fixture in sorted(FIXTURES.iterdir()):
        assert not TYPED.search(hashlib.sha256(fixture.read_bytes()).hexdigest())
    assert not TYPED.search(hashlib.sha256(dcbor(_projection(MULTIPART)["manifest"])).hexdigest())


# --- the CE sample's undefined fields --------------------------------------

def test_the_ce_sample_carries_only_commitments_the_profile_defines():
    """`envelope_digest_before`/`_after` appear in no normative text — only in
    the CDDL and the schema — and the chunking CE populated the `after` one with
    a typed value, naming "the" output envelope where chunking produces several.
    The schema constrains the byte-exact pair by transformation and says nothing
    about the generic one. Removed from the sample; the field's fate belongs to
    the Hash-consumer inventory (R16-03)."""
    ce = _projection(ROOT / "samples" / "sample-CE.json")
    assert ce["transformation"] == "chunking"
    assert "envelope_digest_after" not in ce and "envelope_digest_before" not in ce
    assert ce["envelope_hash_before"] and len(ce["part_envelope_hashes"]) >= 2, \
        "the commitments the profile does define are still there"
    assert el.lint(json.loads((ROOT / "samples" / "sample-CE.json").read_text())) == []
