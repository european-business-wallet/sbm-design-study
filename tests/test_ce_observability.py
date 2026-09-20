# SPDX-License-Identifier: MIT
"""X-24 — CE attests only observable bytes.

Former defect: the CE `transformation` enum carried an epoch-change value
describing an operation NOBODY could observe — MLS epoch changes do not
re-encrypt queued application messages, and intermediaries cannot decrypt
or re-encrypt the E2EE envelope; worse, CE carried NO digest inputs at all,
so no CE assertion was independently checkable.

Evidence 2.5: the unobservable value is REMOVED from the value space
(schema + CDDL; resubmission after an epoch change is a NEW submission
chain), and the remaining OBSERVABLE transformations are byte-checkable —
REQUIRED `envelope_hash_before` (the SE's transmitted-octet commitment;
LINT-CE-01 chains it) plus `envelope_hash_after` (re-packaging) or
`part_envelope_hashes[]` (chunking), all over ciphertext framing bytes the
RDP legitimately observes.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")

CE = json.load(open(ROOT / "samples" / "sample-CE.json"))["projection"]
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def _ce01(body, se=None):
    v = el.Violations()
    el.lint_ce(v, body, se=copy.deepcopy(se) if se else None)
    return [m for r, m in v.items if r == "LINT-CE-01"]


# ---------------------------------------------------------------------------
# The unobservable type is gone
# ---------------------------------------------------------------------------

def test_negative_the_unobservable_type_is_schema_rejected():
    """The former defect verbatim: a CE asserting an epoch-change
    re-encryption nobody can observe."""
    bad = copy.deepcopy(CE)
    bad["transformation"] = "mls-reencryption" + "-epoch-change"
    assert lc.validate_body(bad), "the removed enum value must fail schema"


def test_the_id_models_resubmission_as_a_new_chain():
    idd = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "NEW submission chain (new SE)" in idd
    assert "re-encrypts NO queued application message" in idd


# ---------------------------------------------------------------------------
# The remaining types are byte-checkable
# ---------------------------------------------------------------------------

def test_the_shipped_chunking_ce_is_checkable_and_chains_to_the_se():
    assert CE["transformation"] == "chunking"
    assert len(CE["part_envelope_hashes"]) >= 2
    assert CE["envelope_hash_before"] == SE["envelope_hash"]
    assert not lc.validate_body(copy.deepcopy(CE))
    assert not _ce01(copy.deepcopy(CE), se=SE)


def test_negative_a_ce_without_the_input_commitment_fails():
    bad = copy.deepcopy(CE); bad.pop("envelope_hash_before")
    assert lc.validate_body(bad), "envelope_hash_before is REQUIRED"
    assert _ce01(bad)


def test_negative_a_mismatched_input_commitment_fails_the_chain():
    """The attested input must BE the transmitted message."""
    bad = copy.deepcopy(CE)
    bad["envelope_hash_before"] = {"format": "mls10-message", "hex": "e" * 64}
    assert _ce01(bad, se=SE), "before != se.envelope_hash must fail LINT-CE-01"


def test_negative_chunking_without_parts_fails():
    bad = copy.deepcopy(CE); bad.pop("part_envelope_hashes")
    assert lc.validate_body(bad)
    assert _ce01(bad)


def test_negative_cross_kind_commitments_fail():
    bad = copy.deepcopy(CE)   # chunking...
    bad["envelope_hash_after"] = {"format": "mls10-message", "hex": "a" * 64}
    assert lc.validate_body(bad), "chunking + after-hash is incoherent"
    assert _ce01(bad)
    repack = copy.deepcopy(CE)
    repack["transformation"] = "re-packaging"
    repack.pop("part_envelope_hashes")
    assert _ce01(repack), "re-packaging without envelope_hash_after must fail"


def test_a_valid_repackaging_ce_passes():
    ok = copy.deepcopy(CE)
    ok["transformation"] = "re-packaging"
    ok.pop("part_envelope_hashes")
    ok["envelope_hash_after"] = {"format": "mls10-message", "hex": "a" * 64}
    assert not lc.validate_body(ok)
    assert not _ce01(ok, se=SE)
