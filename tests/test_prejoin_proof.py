# SPDX-License-Identifier: MIT
"""G1 — the pre-join proof, and what it replaced.

The Internet-Draft said a Welcome refusal was "authenticated by the refusing
device's KeyPackage credential" and stopped. The reference settled for what that
sentence permits: possession of `keypackage_ref`.

**That is a hash of the KeyPackage's PUBLIC bytes.** The reservation returns it
to the inviting creator, and the Delivery Service holds it — so the two parties
with a motive to forge a refusal attributed to a device are exactly the two that
could produce one. A refusal is consequential: it withdraws that invitation's
claim, and the creator acts on it.

The proof is now a signature under the KeyPackage's **leaf signature key**, whose
private half only the invited device holds, using RFC 9420 §5.1.2's own
`SignWithLabel` under the label `SBMWelcomeRefusal`, over a typed
domain-separated content carrying a single-use nonce the Delivery Service issued
with the Welcome. The Service verifies it against the key the package carries —
no discovery document, no wallet key, because the device has joined nothing.

Two properties here cost a design correction each, and both are held by tests
below: a refusal the Service rejects for another reason must **not** burn the
nonce, and an exact retry must converge **before** the proof is examined.
"""
import base64
import hashlib
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_wire as w  # noqa: E402
import prejoin  # noqa: E402
import test_current_claims as tc  # noqa: E402

SUITE = tc.SUITE


def _fresh():
    m = tc._mock()
    dep, pkg = tc._deposited(m)
    cred = dict(tc.TARGET_DEV, keypackage_ref=pkg["keypackage_ref"]
                if isinstance(pkg, dict) else tc.DEMO_KP_REF)
    return m, dep, cred


# --- what it replaced -------------------------------------------------------

def test_the_reference_value_is_public_and_therefore_not_a_proof():
    """`keypackage_ref` is a hash of the package's own bytes, derived the
    published way. Anyone holding the package derives it — which is the
    creator, who reserved it, and the Delivery Service, which stores it."""
    m = tc._mock()
    kp = m._demo_keypackage(tc.FR_UID, "F1N2C3D4P", "DEV-1", SUITE)
    assert w.keypackage_ref(kp, cipher_suite=SUITE) == tc.DEMO_KP_REF, \
        "the reference is a function of PUBLIC bytes and nothing else"


def test_a_refusal_without_the_proof_is_refused_by_the_PUBLISHED_request():
    """And by the published request, not by a hand check beside it. The proof
    was a keyword the reference required while `WelcomeRefusalRequest` had no
    field for it at all — the contract and the reference describing different
    operations, which is the defect this repository keeps finding one surface
    at a time."""
    m, dep, cred = _fresh()
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="group-info-mismatch", offered_suite=SUITE)
    assert exc.value.reason == "refusal-request-invalid", exc.value.reason
    assert "refusal_proof" in str(exc.value)

    contract = json.loads(json.dumps(__import__("yaml").safe_load(
        (ROOT / "delivery-service-openapi.yaml").read_text(encoding="utf-8"))))
    req = contract["components"]["schemas"]["WelcomeRefusalRequest"]
    assert "refusal_proof" in req["required"], \
        "the published request must carry it, or the reference is alone in requiring it"
    assert req["properties"]["refusal_proof"]["$ref"].endswith("/WelcomeRefusalProof")


# --- the proof --------------------------------------------------------------

def test_the_signature_is_SignWithLabel_over_the_typed_content():
    """The two halves an implementer needs byte-exactly: the RFC's SignContent
    framing, and the deterministic-CBOR array inside it."""
    content = w.welcome_refusal_content(
        welcome_id="wel-0001", keypackage_ref="ref", offered_suite=SUITE,
        required_floor=None, reason="group-info-mismatch", nonce="rn-1")
    import cbor2
    decoded = cbor2.loads(content)
    assert decoded == ["sm-mls:welcome-refusal:v1", "wel-0001", "ref", SUITE,
                       None, "group-info-mismatch", "rn-1"], decoded
    assert w.sign_content("SBMWelcomeRefusal", content).startswith(
        w.opaque_v(b"MLS 1.0 SBMWelcomeRefusal")), \
        "the label must be prefixed exactly as RFC 9420 §5.1.2 requires"


def test_the_signature_verifies_against_the_key_the_package_carries():
    """The Delivery Service needs nothing but the KeyPackage — the point of a
    PRE-join proof."""
    m = tc._mock()
    kp = m._demo_keypackage(tc.FR_UID, "F1N2C3D4P", "DEV-1", SUITE)
    leaf = m.demo_public_key_b64("leaf:F1N2C3D4P:DEV-1")
    assert leaf.encode() in kp, "the package must carry the key it is verified by"
    fields = dict(welcome_id="wel-0001", keypackage_ref="ref", offered_suite=SUITE,
                  required_floor=None, reason="group-info-mismatch", nonce="rn-1")
    sig = w.sign_welcome_refusal(m.demo_seed_bytes("leaf:F1N2C3D4P:DEV-1"), **fields)
    assert w.verify_welcome_refusal(base64.b64decode(leaf), sig, **fields)


@pytest.mark.parametrize("field,value", [
    ("reason", "suite-below-published-floor"),
    ("offered_suite", "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"),
    ("nonce", "rn-000000000000"),
    ("welcome_id", "wel-9999"),
    ("keypackage_ref", "another-ref"),
])
def test_every_asserted_value_is_inside_the_signature(field, value):
    """A reason, a suite or a floor cannot be swapped after signing — which is
    why the content is the whole assertion and not just the welcome id."""
    m = tc._mock()
    fields = dict(welcome_id="wel-0001", keypackage_ref="ref", offered_suite=SUITE,
                  required_floor=None, reason="group-info-mismatch", nonce="rn-1")
    sig = w.sign_welcome_refusal(m.demo_seed_bytes("leaf:F1N2C3D4P:DEV-1"), **fields)
    leaf = base64.b64decode(m.demo_public_key_b64("leaf:F1N2C3D4P:DEV-1"))
    assert not w.verify_welcome_refusal(leaf, sig, **dict(fields, **{field: value}))


def test_a_signature_by_another_device_does_not_verify():
    m = tc._mock()
    fields = dict(welcome_id="wel-0001", keypackage_ref="ref", offered_suite=SUITE,
                  required_floor=None, reason="group-info-mismatch", nonce="rn-1")
    sig = w.sign_welcome_refusal(m.demo_seed_bytes("leaf:F1N2C3D4P:DEV-2"), **fields)
    leaf = base64.b64decode(m.demo_public_key_b64("leaf:F1N2C3D4P:DEV-1"))
    assert not w.verify_welcome_refusal(leaf, sig, **fields)


# --- freshness, and the two corrections it cost -----------------------------

def test_a_refusal_carrying_another_welcomes_nonce_is_refused():
    m, dep, cred = _fresh()
    proof = m.welcome_refusal_proof(dep["welcome_id"], credential=cred,
                                    reason="group-info-mismatch", offered_suite=SUITE)
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="group-info-mismatch", offered_suite=SUITE,
                         refusal_proof=dict(proof, nonce="rn-000000000000"))
    assert exc.value.reason == "refusal-proof-invalid"


def test_an_accepted_refusal_spends_its_nonce():
    m, dep, cred = _fresh()
    accepted = prejoin.refuse(m, dep["welcome_id"], credential=cred,
                              reason="group-info-mismatch", offered_suite=SUITE,
                              refused_at=tc.IN_WINDOW)
    assert accepted["outcome_id"]
    assert m.welcome_refusal_proof(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE)["nonce"] in m._SPENT_REFUSAL_NONCES


def test_a_rejected_refusal_does_NOT_spend_its_nonce():
    """The first correction this cost. Spending the nonce before the refusal
    was known valid gave a device ONE attempt: an unresolvable floor, an
    out-of-window instant or an unregistered reason burned it, and the device
    had no way to correct a recoverable error."""
    m, dep, cred = _fresh()
    proof = m.welcome_refusal_proof(dep["welcome_id"], credential=cred,
                                    reason="group-info-mismatch", offered_suite=SUITE)
    with pytest.raises(m.InvitationError):
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="group-info-mismatch", offered_suite=SUITE,
                         refused_at="2099-01-01T00:00:00Z",      # out of window
                         refusal_proof=proof)
    assert proof["nonce"] not in m._SPENT_REFUSAL_NONCES, \
        "a rejected refusal must leave the device able to try again"
    assert prejoin.refuse(m, dep["welcome_id"], credential=cred,
                          reason="group-info-mismatch", offered_suite=SUITE,
                          refused_at=tc.IN_WINDOW)["outcome_id"]


def test_an_exact_retry_converges_and_a_replay_does_not():
    """The second correction. A retried refusal must return the first answer —
    a lost response converges — while a captured proof must not buy a
    DIFFERENT claim. The idempotent path answers before the proof is examined,
    which is what lets both hold at once."""
    m, dep, cred = _fresh()
    first = prejoin.refuse(m, dep["welcome_id"], credential=cred,
                           reason="group-info-mismatch", offered_suite=SUITE,
                           refused_at=tc.IN_WINDOW)
    again = prejoin.refuse(m, dep["welcome_id"], credential=cred,
                           reason="group-info-mismatch", offered_suite=SUITE,
                           refused_at=tc.IN_WINDOW)
    assert first["outcome_id"] == again["outcome_id"], "a retry must converge"

    proof = m.welcome_refusal_proof(dep["welcome_id"], credential=cred,
                                    reason="group-info-mismatch", offered_suite=SUITE)
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="suite-below-published-floor", offered_suite=SUITE,
                         required_floor=SUITE, refused_at=tc.IN_WINDOW,
                         members=tc.FLOOR_MEMBERS, refusal_proof=proof)
    assert exc.value.reason == "invitation-conflict", exc.value.reason


# --- the identity answer stays uniform --------------------------------------

def test_the_identity_checks_run_before_the_proof_is_examined():
    """Otherwise the refusal endpoint becomes an existence oracle: a caller
    could tell an item that exists from one that does not by which complaint it
    received about its proof."""
    m, dep, _ = _fresh()
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=tc.SIBLING_DEV_KP,
                         reason="group-info-mismatch", offered_suite=SUITE,
                         refusal_proof={"nonce": "rn-000000000000",
                                        "signature_b64": "AA=="})
    assert exc.value.reason == "invitation-unknown", exc.value.reason


# --- the text says all four things G1 asks for ------------------------------

def test_the_draft_specifies_key_bytes_transport_and_freshness():
    t = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text(
        encoding="utf-8").split())
    flat = t.replace("**", "").replace("`", "")
    assert "The proof, exactly (normative)" in flat
    # the key
    assert "KeyPackage's leaf signature key" in flat
    assert "signature_key of the LeafNode" in flat
    # the bytes
    assert "SignWithLabel of {{RFC9420}} §5.1.2 with the label SBMWelcomeRefusal" in flat
    assert "MLS 1.0 SBMWelcomeRefusal" in flat
    assert '[ "sm-mls:welcome-refusal:v1", welcome_id, keypackage_ref,' in t
    # the transport (already specified, and still there)
    assert "POST /welcome/{welcome_id}/refusal" in flat
    # freshness and replay
    assert "single-use nonce" in flat
    assert "spends it only when a refusal is accepted" in flat.lower()
    assert "converges on the stored outcome before the proof is examined" in flat
    # and why the old wording was not a proof
    assert "hash of the package's public bytes" in flat.lower()


def test_the_agenda_records_what_is_answered_and_what_is_not():
    row = next(l for l in (ROOT / "docs" / "REVIEW_AGENDA.md").read_text(
        encoding="utf-8").splitlines() if l.startswith("| G1 |"))
    assert "Answered" in row
    assert "SignWithLabel" in row or "leaf signature key" in row
