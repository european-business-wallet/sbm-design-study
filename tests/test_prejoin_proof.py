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
import copy
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
from lint_cli import request_schema  # noqa: E402
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
    proof = m.welcome_refusal_proof(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE,
        nonce=prejoin.nonce_for(m, dep["welcome_id"], credential=cred))
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="group-info-mismatch", offered_suite=SUITE,
                         refusal_proof=dict(proof, nonce="rn-000000000000"))
    assert exc.value.reason == "refusal-proof-invalid"


def test_an_accepted_refusal_spends_its_nonce():
    m, dep, cred = _fresh()
    # Held from collection, the way the device holds it: once the refusal is
    # accepted the invitation is handled and its item leaves the queue, so the
    # value cannot be fetched again — which is the point of it being single-use.
    nonce = prejoin.nonce_for(m, dep["welcome_id"], credential=cred)
    accepted = prejoin.refuse(m, dep["welcome_id"], credential=cred,
                              reason="group-info-mismatch", offered_suite=SUITE,
                              refused_at=tc.IN_WINDOW)
    assert accepted["outcome_id"]
    assert nonce in m._SPENT_REFUSAL_NONCES


def test_a_rejected_refusal_does_NOT_spend_its_nonce():
    """The first correction this cost. Spending the nonce before the refusal
    was known valid gave a device ONE attempt: an unresolvable floor, an
    out-of-window instant or an unregistered reason burned it, and the device
    had no way to correct a recoverable error."""
    m, dep, cred = _fresh()
    proof = m.welcome_refusal_proof(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE,
        nonce=prejoin.nonce_for(m, dep["welcome_id"], credential=cred))
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
    # Built once, from the queue item, and reused: it is both what an honest
    # client retries with and what a captor would replay.
    captured = m.welcome_refusal_proof(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE,
        nonce=prejoin.nonce_for(m, dep["welcome_id"], credential=cred))
    # A retry re-sends the SAME request — including the same proof. It cannot
    # fetch a fresh nonce, because the invitation is handled and its queue item
    # is gone; a client whose response was lost holds what it sent and sends it
    # again, which is exactly the case the idempotent path exists for.
    send = lambda: m.refuse_welcome(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE, refused_at=tc.IN_WINDOW, refusal_proof=captured)
    first, again = send(), send()
    assert first["outcome_id"] == again["outcome_id"], "a retry must converge"

    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="suite-below-published-floor", offered_suite=SUITE,
                         required_floor=SUITE, refused_at=tc.IN_WINDOW,
                         members=tc.FLOOR_MEMBERS, refusal_proof=captured)
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


# ===========================================================================
# R30-PUB-01 / R30-PUB-02 — the two things the demonstration did not do
# ===========================================================================

def test_a_client_holding_only_the_published_response_can_refuse():
    """The acceptance test for R30-PUB-01.

    The proof was made REQUIRED and the value it must sign was never published,
    so nobody holding the contract could build one. The reference looked
    finished because its own client helper read the nonce out of the service's
    private queue — an access no device has.

    So this client is given nothing but the SERIALISED response: the queue item
    round-trips through JSON, and the request is validated against the published
    `WelcomeRefusalRequest` before it is sent. Nothing here touches
    `_WELCOME_QUEUE`, `_INVITATIONS` or any other ledger.
    """
    m, dep, cred = _fresh()
    wire = json.loads(json.dumps(
        m.collect_welcomes(credential=cred, at=tc.IN_WINDOW)))
    assert m.validate_contract_object(
        "delivery-service-openapi.yaml", "WelcomeQueue", wire) == [], \
        "the queue a device receives must satisfy its own published schema"
    item = next(w for w in wire["welcomes"] if w["welcome_id"] == dep["welcome_id"])

    proof = m.welcome_refusal_proof(
        item["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=item["offered_suite"], nonce=item["refusal_nonce"])

    request = {"reason": "group-info-mismatch",
               "offered_suite": item["offered_suite"], "refusal_proof": proof}
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "WelcomeRefusalRequest")
    assert list(validator.iter_errors(request)) == [], "the request must be valid"

    outcome = m.refuse_welcome(item["welcome_id"], credential=cred,
                               refused_at=tc.IN_WINDOW, **request)
    assert outcome["outcome_id"], "a refusal built from the published response must land"


def test_the_builder_will_not_supply_a_nonce_the_caller_did_not_receive():
    """The other half: the helper must not quietly close the gap again."""
    m, dep, cred = _fresh()
    with pytest.raises(m.InvitationError) as exc:
        m.welcome_refusal_proof(dep["welcome_id"], credential=cred,
                                reason="group-info-mismatch", offered_suite=SUITE)
    assert exc.value.reason == "refusal-proof-required"


def _with_replaced_leaf_key(label="leaf:A-DIFFERENT-DEVICE:dev"):
    """A runtime whose demo packages carry ANOTHER valid leaf key.

    Changed before any operation, so reserve/commit/deposit run normally and the
    `keypackage_ref` correctly hashes the changed bytes. Nothing else moves.
    """
    m = tc._mock()
    original = m._demo_keypackage
    replacement = m.demo_public_key_b64(label)
    m._demo_keypackage = lambda uid, mid, did, cs: (
        original(uid, mid, did, cs).rsplit(b"|", 1)[0] + b"|" + replacement.encode())
    dep, pkg = tc._deposited(m)
    cred = dict(tc.TARGET_DEV, keypackage_ref=pkg["keypackage_ref"]
                if isinstance(pkg, dict) else tc.DEMO_KP_REF)
    return m, dep, cred, label


@pytest.mark.parametrize("signer,accepted", [
    ("the key the package carries", True),
    ("a key derived from the device's labels", False),
])
def test_the_verdict_follows_the_package_not_the_identity(signer, accepted):
    """The acceptance test for R30-PUB-02, and the defect it names.

    The Delivery Service must verify against the leaf key of the EXACT package
    the invitation consumed — that is the whole reason a pre-join refusal can be
    attributed to a device that has joined nothing. It instead recomputed
    `demo_public_key_b64(f"leaf:{mid}:{device_id}")`, the same label the fixture
    generator uses, so the two agreed for every shipped package and no test
    could tell them apart.

    Replacing the key inside the package made the inversion plain: a refusal
    signed with the key the package ACTUALLY carried was rejected, and one
    signed with a key that was not in the package at all was accepted.
    """
    m, dep, cred, replaced = _with_replaced_leaf_key()
    item = m.collect_welcomes(credential=cred, at=tc.IN_WINDOW)["welcomes"][0]
    inv = next(e for e in m._INVITATIONS.values()
               if e["welcome_id"] == dep["welcome_id"])
    seed = replaced if accepted else \
        f"leaf:{tc.TARGET_DEV['mid']}:{tc.TARGET_DEV['device_id']}"
    signature = w.sign_welcome_refusal(
        m.demo_seed_bytes(seed), welcome_id=dep["welcome_id"],
        keypackage_ref=inv["invitation"]["keypackage_ref"], offered_suite=SUITE,
        required_floor=None, reason="group-info-mismatch",
        nonce=item["refusal_nonce"])
    send = lambda: m.refuse_welcome(
        dep["welcome_id"], credential=cred, reason="group-info-mismatch",
        offered_suite=SUITE, refused_at=tc.IN_WINDOW,
        refusal_proof={"nonce": item["refusal_nonce"], "signature_b64": signature})
    if accepted:
        assert send()["outcome_id"], f"{signer} must verify"
    else:
        with pytest.raises(m.InvitationError) as exc:
            send()
        assert exc.value.reason == "refusal-proof-invalid", exc.value.reason


def test_a_malformed_proof_is_a_typed_refusal_that_changes_nothing():
    """R30-PUB-05: `proof["signature_b64"]` was read before the request shape
    was validated, so a proof missing it raised a bare KeyError — the one
    untyped escape from a function whose every other refusal is an
    `InvitationError`."""
    m, dep, cred = _fresh()
    item = m.collect_welcomes(credential=cred, at=tc.IN_WINDOW)["welcomes"][0]
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(dep["welcome_id"], credential=cred,
                         reason="group-info-mismatch", offered_suite=SUITE,
                         refused_at=tc.IN_WINDOW,
                         refusal_proof={"nonce": item["refusal_nonce"]})
    assert exc.value.reason == "refusal-request-invalid"
    assert item["refusal_nonce"] not in m._SPENT_REFUSAL_NONCES, \
        "a refusal refused for its shape must not spend the device's one nonce"


# ===========================================================================
# R32-RES-02 / R32-OBS-01 — every invalid request gets a typed answer
# ===========================================================================

def _live(m, dep, cred):
    return m.collect_welcomes(credential=cred, at=tc.IN_WINDOW)["welcomes"][0]


@pytest.mark.parametrize("label,overrides", [
    ("an unregistered reason, with a proof missing its signature",
     {"reason": "unknown-reason", "proof": lambda n: {"nonce": n}}),
    ("an unregistered reason, with a well-formed proof",
     {"reason": "unknown-reason", "proof": lambda n: {"nonce": n, "signature_b64": "a" * 90}}),
    ("a suite the invitation was not offered under",
     {"offered_suite": "UNKNOWN", "proof": lambda n: {"nonce": n, "signature_b64": "a" * 90}}),
    ("a proof that is not an object at all",
     {"proof": lambda n: "not-a-proof"}),
])
def test_every_invalid_refusal_is_typed_and_changes_nothing(label, overrides):
    """R32-RES-02. Two invalid things in one request must still give a typed
    answer about one of them.

    The shape check used to be conditional on the reason being registered, so an
    unregistered reason skipped it and fell through to the proof's fields — a
    bare `KeyError`. And the key resolution recomputed the package reference
    under the suite the REQUEST supplied, so a suite the registry does not know
    raised a `ValueError` out of the hash-function lookup: a path the fix for
    the key-resolution defect introduced.

    Neither is a demonstrated production fault — this is the reference's error
    handling — but an untyped escape from a function whose every other refusal
    is an `InvitationError` is a rule an implementer cannot follow.
    """
    m, dep, cred = _fresh()
    item = _live(m, dep, cred)
    before = (copy.deepcopy(m._OUTCOMES), copy.deepcopy(m._SPENT_REFUSAL_NONCES))
    with pytest.raises(m.InvitationError) as caught:
        m.refuse_welcome(
            dep["welcome_id"], credential=cred,
            reason=overrides.get("reason", "group-info-mismatch"),
            offered_suite=overrides.get("offered_suite", SUITE),
            refused_at=tc.IN_WINDOW,
            refusal_proof=overrides["proof"](item["refusal_nonce"]))
    assert caught.value.reason, f"{label}: refused without a reason code"
    assert (m._OUTCOMES, m._SPENT_REFUSAL_NONCES) == before, \
        f"{label}: an invalid request moved stored state"
    assert item["refusal_nonce"] not in m._SPENT_REFUSAL_NONCES, \
        f"{label}: spent the device's one nonce on a request it refused"


def test_the_queue_cannot_deliver_a_nonce_the_proof_would_reject():
    """R32-OBS-01: the response and the request constrained the same value
    differently — `minLength: 1` delivering, `minLength: 8` quoting — so a
    response its own validator accepted could carry a value the client was
    forbidden to echo. One shared definition now; this asserts the agreement
    rather than the number, so tightening either side keeps them together."""
    m, dep, cred = _fresh()
    queue = m.collect_welcomes(credential=cred, at=tc.IN_WINDOW)
    _, request_validator = request_schema("delivery-service-openapi.yaml",
                                          "WelcomeRefusalRequest")

    def refused_by(value):
        candidate = copy.deepcopy(queue)
        candidate["welcomes"][0]["refusal_nonce"] = value
        response_errors = m.validate_contract_object(
            "delivery-service-openapi.yaml", "WelcomeQueue", candidate)
        request_errors = list(request_validator.iter_errors(
            {"reason": "group-info-mismatch", "offered_suite": SUITE,
             "refusal_proof": {"nonce": value, "signature_b64": "a" * 90}}))
        return bool(response_errors), bool(request_errors)

    for value in ("x", "1234567", "12345678", queue["welcomes"][0]["refusal_nonce"]):
        response_rejects, request_rejects = refused_by(value)
        assert response_rejects == request_rejects, (
            f"the two surfaces disagree about {value!r}: the queue "
            f"{'rejects' if response_rejects else 'accepts'} it and the proof "
            f"{'rejects' if request_rejects else 'accepts'} it")
