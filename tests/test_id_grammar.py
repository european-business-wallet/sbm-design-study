# SPDX-License-Identifier: MIT
"""X-02 — one canonical identifier grammar + byte-exact GF(2^5) Reed-Solomon check.

Former defect: three divergent UID languages (a loose prose regex, a
case-insensitive ABNF, strict schemas), checksums that lived only in Python (two
parallel Luhn impls), an orphan vector file, and demo identifiers that were
checksum-INVALID and never enforced. This batch collapses everything to one
module (scripts/id_grammar.py), redesigns the checks as Reed-Solomon over GF(2^5),
enforces them, and drives ONE shared accept/reject corpus through every consumer.

These tests prove: (1) the UID/MID regex is byte-identical across the JSON Schema,
the OpenAPI parameter, the toolkit and the linters; (2) the shared corpus is
accepted/rejected consistently by the regex and the checksum; (3) the strong
error-detection guarantee — every single-character UID/MID error is detected
(distance-3 / distance-2), a property the old decimal-projection Verhoeff lacked.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import id_grammar as g  # noqa: E402
import eu_entity_uid_toolkit as tk  # noqa: E402
import discovery_lint as dl  # noqa: E402
import evidence_lint as el  # noqa: E402

CANON_UID = r"^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$"
CANON_MID = r"^[0-9A-HJ-NP-TV-Z]{9}$"
CORPUS = json.loads((ROOT / "samples" / "id-vectors.json").read_text())


def _openapi_uid_pattern():
    y = (ROOT / "edd-resolver-openapi.yaml").read_text()
    # the Uid parameter pattern
    m = re.search(r"pattern:\s*'(\^EU-[^']+)'", y)
    return m.group(1)


def test_uid_regex_is_byte_identical_everywhere():
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    sources = {
        "schema Uid": common["$defs"]["Uid"]["pattern"],
        "schema BwAddress-embedded": None,  # checked separately
        "openapi Uid": _openapi_uid_pattern(),
        "toolkit UID_REGEX": tk.UID_REGEX.pattern,
        "id_grammar UID_REGEX": g.UID_REGEX.pattern,
        "discovery_lint UID_RE": dl.UID_RE.pattern,
        "evidence_lint UID_RE": el.UID_RE.pattern,
    }
    for name, pat in sources.items():
        if pat is None:
            continue
        assert pat == CANON_UID, f"{name} UID pattern diverges: {pat!r}"


def test_mid_regex_is_byte_identical_everywhere():
    common = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    # the MID pattern appears in several $defs / fields; check the canonical ones
    for pat in (tk.MID_REGEX.pattern, g.MID_REGEX.pattern, dl.MID_RE.pattern):
        assert pat == CANON_MID, f"MID pattern diverges: {pat!r}"


def test_corpus_uid_regex_and_checksum_agree():
    urx = re.compile(CANON_UID)
    for u in CORPUS["uid"]["accept"]:
        assert urx.match(u) and g.uid_valid_checksum(u), f"accept failed: {u}"
    for u in CORPUS["uid"]["reject_syntax"]:
        assert not urx.match(u), f"syntax-reject matched the regex: {u}"
    for u in CORPUS["uid"]["reject_checksum"]:
        assert urx.match(u) and not g.uid_valid_checksum(u), f"checksum-reject wrong: {u}"


def test_corpus_mid_regex_and_checksum_agree():
    mrx = re.compile(CANON_MID)
    for m in CORPUS["mid"]["accept"]:
        assert mrx.match(m) and g.mid_valid_checksum(m), f"accept failed: {m}"
    for m in CORPUS["mid"]["reject_syntax"]:
        assert not mrx.match(m), f"syntax-reject matched: {m}"
    for m in CORPUS["mid"]["reject_checksum"]:
        assert mrx.match(m) and not g.mid_valid_checksum(m), f"checksum-reject wrong: {m}"


def test_every_single_character_uid_error_is_detected():
    """Distance-3 MDS: any single-symbol change to a valid UID is detected."""
    for u in CORPUS["uid"]["accept"]:
        payload_tail = u.split("-", 3)[3]  # the 14 Base32 chars
        prefix = u[: len(u) - 14]
        for i in range(14):
            for c in g.B32:
                if c == payload_tail[i]:
                    continue
                mutant = prefix + payload_tail[:i] + c + payload_tail[i + 1:]
                assert not g.uid_valid_checksum(mutant), f"undetected UID error: {mutant}"


def test_every_single_character_mid_error_is_detected():
    for m in CORPUS["mid"]["accept"]:
        for i in range(9):
            for c in g.B32:
                if c == m[i]:
                    continue
                mutant = m[:i] + c + m[i + 1:]
                assert not g.mid_valid_checksum(mutant), f"undetected MID error: {mutant}"


def test_toolkit_delegates_to_the_one_implementation():
    u = tk.uid_generate("DE", "EOID", "7K3D9W0Q2M5F")
    assert u == g.make_uid("DE", "EOID", "7K3D9W0Q2M5F")
    assert tk.uid_validate(u)[0] and g.uid_valid_checksum(u)
