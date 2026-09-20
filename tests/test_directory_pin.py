# SPDX-License-Identifier: MIT
"""X-01 — a UID is authoritatively bound to its discovery-seal key-set.

The former defect (Blocker): nothing bound a UID to *which* key may seal its
BW-MED/ORG/MEMBER documents, so a valid QSealC authorised for another UID could
seal an entity's discovery documents. This batch pins the entity's authorized
seal key-set in the directory (DirectoryRecord.authorized_seal_keys), and
LINT-TRUST-05 rejects a seal whose key is not pinned for its own UID.

Demo/pilot scope: the pin is the raw seal-key spki_sha256; the production
QSealC-x5t / Trusted-List chain remains a production-verifier duty. The negative
fixtures reproduce the former defect — a seal key not authorised for the
document's UID is rejected fail-closed.
"""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402

STORE = lc.load_trust_store(str(ROOT / "samples/trust-store.demo.json"))
DIRECTORY = lc.load_directory(str(ROOT / "samples/directory.demo.json"))
# The real FR BW-ORG, sealed by the demo entity-admin key, UID EU-FR-...
FR_ORG = lc.reconstruct(json.load(open(ROOT / "samples/sample-BW-ORG.json")))
FR_UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
DE_SPKI = "2d0db17724d5de1a546458250c2e6f68d3e1985870e63c649ee338aaa84281ee"


def _pin(doc, directory):
    return lc.check_directory_pin(doc, doc.get("doc_cose_b64"), STORE, directory)


def test_positive_authorized_seal_passes():
    assert FR_ORG.get("uid") == FR_UID
    assert _pin(FR_ORG, DIRECTORY) == [], "a correctly-pinned seal must pass"


def test_negative_cross_uid_seal_is_rejected():
    """The reproduced Blocker: a key not pinned for this UID cannot seal it."""
    d = copy.deepcopy(DIRECTORY)
    # Pin a DIFFERENT key for UID-FR; the real seal (the entity-admin key,
    # authorised only where it is pinned) is now unauthorised for UID-FR.
    for rec in d["records"]:
        if rec["uid"] == FR_UID:
            rec["authorized_seal_keys"][0]["spki_sha256"] = "ff" * 32
    hits = _pin(FR_ORG, d)
    assert any(r == "LINT-TRUST-05" and "not an authorized seal key" in m
               for r, m in hits), hits


def test_negative_no_directory_record_fails_closed():
    d = {"records": [r for r in DIRECTORY["records"] if r["uid"] != FR_UID]}
    hits = _pin(FR_ORG, d)
    assert any(r == "LINT-TRUST-05" and "no directory record pins" in m
               for r, m in hits), hits


def test_negative_rotation_window_excludes_instant():
    """A pinned key whose window predates the document is rejected (rotation)."""
    d = copy.deepcopy(DIRECTORY)
    for rec in d["records"]:
        if rec["uid"] == FR_UID:
            rec["authorized_seal_keys"][0]["not_before"] = "2000-01-01T00:00:00Z"
            rec["authorized_seal_keys"][0]["not_after"] = "2000-12-31T23:59:59Z"
    hits = _pin(FR_ORG, d)
    assert any(r == "LINT-TRUST-05" and "outside its authorised key-set window" in m
               for r, m in hits), hits


def test_rotation_overlap_historical_key_still_verifies():
    """An additional (rotated-in) key does not break the still-valid old key."""
    d = copy.deepcopy(DIRECTORY)
    for rec in d["records"]:
        if rec["uid"] == FR_UID:
            rec["authorized_seal_keys"].insert(0, {
                "spki_sha256": "ab" * 32, "key_set_version": "2",
                "not_before": "2027-07-01T00:00:00Z",
                "not_after": "2029-01-01T00:00:00Z"})
    assert _pin(FR_ORG, d) == [], "the still-valid pinned key must keep verifying"


def test_directory_pin_binds_the_demo_seal_key():
    """Sanity: the fixture pins the actual demo entity-admin key thumbprint."""
    for rec in DIRECTORY["records"]:
        assert rec["authorized_seal_keys"][0]["spki_sha256"] == DE_SPKI
