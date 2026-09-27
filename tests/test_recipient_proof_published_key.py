# SPDX-License-Identifier: MIT
"""R27-PUB-02 — LINT-BND-21 runs for EVERY recipient proof, not the last one.

`check_bundle` selects the recipient-side proofs from a set derived from the
schemas (`RECIPIENT_ACK_PROOF_FIELDS`), and the published-key verification used
to sit AFTER that loop, reading whatever `conf` the final iteration had left
behind. `s3_attestation` sorts last, so every evidence object carrying a
`recipient_confirmation` or a `recipient_validation_failure` and no s3
attestation reached the check with `conf` as None: a proof could name a known,
active member and device, be signed by an unrelated key, satisfy LINT-BND-12,
and nothing else objected.

Two things made it invisible. It was a REGRESSION, not a new gap — the line had
read `conf = ev.get("s3_attestation") or ev.get("recipient_confirmation")`, so
the mismatch confirmation was verified before the derived-set loop replaced it —
and the only shipped negative case put its proof in `s3_attestation`, the one
field the leaked variable happened to hold.

So the probes here are parametrised over the field NAME, with the same proof and
the same corruption in each. A check whose result depends on which field carries
the proof is the defect; a test that exercises one field cannot see it.
"""
import copy
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_lint as bl  # noqa: E402
import lint_cli as lc  # noqa: E402
import mock_rdp as mock  # noqa: E402

SAMPLES = ROOT / "samples"
MANIFEST = json.loads((SAMPLES / "bundle.walletsig.manifest.json").read_text())
"""The walletsig bundle, because its s3 attestation is WALLET-SIGNED. The default
bundle's is session-authenticated, so it carries no signature to verify and could
not have exposed this: there, the post-loop check was inert for every field."""

_doc = lambda name: bl._load(str(SAMPLES / name))  # noqa: E731
ENTITY = MANIFEST["entity_uid"]
MED, ORG = _doc(MANIFEST["med"]), _doc(MANIFEST["org"])
MEMBERS = [_doc(m) for m in MANIFEST["members"]]
EVIDENCE = [_doc(e) for e in MANIFEST["evidence"]]
REVEALS = ({r["message_id"]: r for r in
            json.loads((SAMPLES / MANIFEST["grade_reveals"]).read_text())["reveals"]}
           if MANIFEST.get("grade_reveals") else {})

PROOF_FIELDS = sorted(lc.RECIPIENT_ACK_PROOF_FIELDS)


def _carried_as(field, *, nested=False):
    """The shipped wallet-signed proof, moved to `field`. Returns (evidence, proof).

    Moving it is the point: the same proof under a different key of the same
    object must be verified the same way.
    """
    evidence = copy.deepcopy(EVIDENCE)
    holder = next(e for e in evidence if isinstance(e.get("s3_attestation"), dict))
    if field != "s3_attestation":
        holder[field] = holder.pop("s3_attestation")
    if nested:
        evidence.remove(holder)
        evidence.append({"type": "EP-v1", "message_id": holder.get("message_id"),
                         "outcomes": [holder]})
    return evidence, holder[field]


def _run(evidence, members=None):
    return {rule for rule, _ in bl.check_bundle(
        ENTITY, MED, ORG, copy.deepcopy(members or MEMBERS),
        copy.deepcopy(evidence), reveals=REVEALS)}


def _sign_with(proof, seed):
    proof.pop("wallet_signature_b64", None)
    os.environ["WALLET_SEED"] = seed
    try:
        proof["wallet_signature_b64"] = mock._wallet_sign(proof)
    finally:
        del os.environ["WALLET_SEED"]


# ---------------------------------------------------------------------------
# The positive controls — without these the negatives below prove nothing
# ---------------------------------------------------------------------------

def test_the_shipped_bundle_verifies():
    assert "LINT-BND-21" not in _run(EVIDENCE)


@pytest.mark.parametrize("nested", [False, True], ids=["standalone", "ep-nested"])
@pytest.mark.parametrize("field", PROOF_FIELDS)
def test_a_correctly_signed_proof_passes_under_every_field(field, nested):
    """The proof is signed by the device it names, under its own historical key."""
    evidence, proof = _carried_as(field, nested=nested)
    _sign_with(proof, f"wallet:{proof['mid']}:{proof['device_id']}")
    assert "LINT-BND-21" not in _run(evidence)


# ---------------------------------------------------------------------------
# Foreign key — the provider mints the recipient's proof under its own key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("nested", [False, True], ids=["standalone", "ep-nested"])
@pytest.mark.parametrize("field", PROOF_FIELDS)
def test_a_foreign_key_proof_fails_under_every_field(field, nested):
    """The member and device are KNOWN and active, so LINT-BND-12 is satisfied
    and only the published-key check can object. Before the fix this passed for
    two of the three fields."""
    evidence, proof = _carried_as(field, nested=nested)
    _sign_with(proof, "attacker-provider-key")
    issues = _run(evidence)
    assert "LINT-BND-21" in issues, \
        f"a foreign-key {field} was accepted ({'nested' if nested else 'top-level'})"
    assert "LINT-BND-12" not in issues, \
        "the member must resolve — otherwise this tests the wrong boundary"


# ---------------------------------------------------------------------------
# Flipped signature, and no resolvable anchor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", PROOF_FIELDS)
def test_a_flipped_signature_fails_under_every_field(field):
    evidence, proof = _carried_as(field)
    raw = bytearray(__import__("base64").b64decode(proof["wallet_signature_b64"]))
    raw[-1] ^= 0x01
    proof["wallet_signature_b64"] = __import__("base64").b64encode(bytes(raw)).decode()
    assert "LINT-BND-21" in _run(evidence)


@pytest.mark.parametrize("field", PROOF_FIELDS)
def test_a_proof_with_no_published_anchor_fails_under_every_field(field):
    """No anchor is nowhere to verify, which is a refusal and not a pass."""
    evidence, proof = _carried_as(field)
    members = copy.deepcopy(MEMBERS)
    for member in members:
        if member.get("mid") != proof["mid"]:
            continue
        for device in member.get("devices") or []:
            if device.get("device_id") == proof["device_id"]:
                device.pop("confirmation_key", None)
    assert "LINT-BND-21" in _run(evidence, members=members)


@pytest.mark.parametrize("field", PROOF_FIELDS)
def test_a_proof_whose_anchor_is_another_devices_key_fails(field):
    """The anchor resolves, and to the wrong key: the signature is valid, made by
    a device that is not the one the published document binds."""
    evidence, proof = _carried_as(field)
    members = copy.deepcopy(MEMBERS)
    other = mock.demo_public_key_b64("wallet:F1N2C3D4P:some-other-device")
    for member in members:
        if member.get("mid") != proof["mid"]:
            continue
        for device in member.get("devices") or []:
            if device.get("device_id") == proof["device_id"]:
                device["confirmation_key"]["public_key_b64"] = other
    assert "LINT-BND-21" in _run(evidence, members=members)


def test_the_wallet_signed_proof_must_name_its_device():
    """A wallet signature is made by a device key, so a proof carrying one names
    the device whose published key verifies it — there is otherwise no anchor to
    resolve. Reported rather than skipped."""
    evidence, proof = _carried_as("recipient_validation_failure")
    proof.pop("device_id", None)
    assert "LINT-BND-21" in _run(evidence)
