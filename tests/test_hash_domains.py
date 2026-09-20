# SPDX-License-Identifier: MIT
"""F-14 — `payload_hash` never changes semantic domain again.

Former defect: for accepted messages `payload_hash` identified application
content; on a pre-acceptance rejection the SAME field held a hash of the
raw submitted bytes "as received" — one shape, two semantic domains,
distinguishable only by prose inference.

Evidence 2.6: an intake-stage NDE (`A.2-SubmissionRejection`) carries
**`submission_hash`** — SHA-256 over the EXACT submitted octets at the
intake boundary, before any parsing — and MUST NOT carry `payload_hash`;
every other NDE the reverse. The two domains are structurally distinct
fields (schema-enforced both directions) and are never compared (the I-D
Error-Handling hash-domain rule).
"""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402

NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]
IDD = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
IFLAT = " ".join(IDD.split()).replace("*", "").replace("`", "")

HASH = {"alg": "SHA-256", "hex": "a" * 64, "hash_mode": "raw-sha256"}


def _intake_nde():
    n = copy.deepcopy(NDE)
    n["event"] = "A.2-SubmissionRejection"
    n["reason"] = "malformed-envelope"
    n.pop("payload_hash", None)
    n["submission_hash"] = dict(HASH)
    return n


def test_an_intake_nde_with_submission_hash_validates():
    assert not lc.validate_body(_intake_nde())


def test_negative_the_former_domain_shift_is_rejected():
    """The former defect verbatim: payload_hash on a pre-acceptance
    rejection."""
    bad = _intake_nde()
    bad.pop("submission_hash")
    bad["payload_hash"] = dict(HASH)
    assert lc.validate_body(bad), \
        "an A.2 NDE carrying payload_hash must fail — wrong domain"


def test_negative_a_content_nde_cannot_carry_submission_hash():
    bad = copy.deepcopy(NDE)          # D.2 — the content domain
    bad.pop("payload_hash")
    bad["submission_hash"] = dict(HASH)
    assert lc.validate_body(bad)


def test_negative_both_fields_is_incoherent_either_way():
    bad = _intake_nde()
    bad["payload_hash"] = dict(HASH)
    assert lc.validate_body(bad)
    bad2 = copy.deepcopy(NDE)
    bad2["submission_hash"] = dict(HASH)
    assert lc.validate_body(bad2)


def test_the_shipped_content_ndes_still_validate():
    for f in ("sample-NDE.json", "sample-NDE-mismatch.json"):
        n = json.load(open(ROOT / "samples" / f))["projection"]
        assert n["event"] != "A.2-SubmissionRejection"
        assert not lc.validate_body(copy.deepcopy(n))


def test_the_byte_input_is_defined_exactly():
    assert "EXACT submitted octets as received at the intake boundary" in IFLAT
    assert "BEFORE any parsing or decoding" in IFLAT
    assert "byte-for-byte" in IFLAT


def test_cross_domain_comparison_is_forbidden():
    assert "Hash-domain rule." in IFLAT
    assert "hashes from different domains are NEVER compared" in IFLAT
    assert "MUST NOT drive any retry, duplicate or dispute decision" in IFLAT
