# SPDX-License-Identifier: MIT
"""R3-04 — the DS receipt names a key that can actually be resolved.

Former defect (round-3 review, High). The I-D required RDP(out) to verify the
signed delivery receipt against "the DS's published key" before issuing the DE,
and the Delivery-Service contract carried the same obligation on `ds_signature`
— while **no DS signing-key field, discovery endpoint, key history, certificate
profile, key identifier or rollover mechanism existed anywhere**. The reference
mock's locally-known demo key is a convenience, not a trust relationship.

So two conforming implementations could not discover which key verifies a
receipt, could not validate a historical receipt after a rotation, and were
exposed to ambiguous key substitution. An obligation with no referent is not an
obligation.

**R3-T3** binds the keys into BW-MED — an object that is already signed and
already retained for the evidence period — rather than defining a new endpoint
that would need its own rotation, history and retention machinery for a single
key. The receipt carries `ds_kid` and `ds_alg`, and **validity is judged at the
receipt's own `server_time`**: that is what keeps a 2026 receipt verifiable in
2033, after the key that signed it has been rotated out.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402



def _staged(mock, *, issuing_rdp_id, message_id, recipient_uid, mid, device_id,
            octets, session_binding):
    """R7-02: a receipt now requires an item the DS ACCEPTED, QUEUED and
    TRANSFERRED. These fixtures run that lifecycle rather than bypassing it —
    a helper that faked the state would reintroduce exactly the orphan the
    finding is about, one layer down."""
    import base64
    mock.ds_accept_message(message_id, "demo-group",
                           base64.b64encode(octets).decode(),
                           principal=issuing_rdp_id)
    mock.queue_delivery(issuing_rdp_id, message_id, recipient_uid=recipient_uid,
                        mid=mid, device_id=device_id)
    # R9-01/R9-02: collect through the PUBLIC operation and RETURN the token it
    # issued. These fixtures used to call the private `transfer_delivery()` and
    # then acknowledge with no token at all — which is why nothing noticed that
    # a value the published request declares REQUIRED was optional in the
    # reference. A fixture that can skip a wire value cannot test that it is
    # needed.
    got = mock.collect_messages(
        credential={"kind": "device", "uid": recipient_uid, "mid": mid,
                    "device_id": device_id,
                    "session": session_binding["digest"]},
        session_binding=session_binding)
    return next(i["collection_token"] for i in got["items"]
                if i["message_id"] == message_id)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")
DS = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
# SBM-ADR-0015: the DS receipt key is the ISSUING RDP's, published in its
# BW-PROVIDER descriptor. It was on the entity's BW-MED while the Delivery
# Service was a second provider; the MED path is deleted, and a kid published
# only there must not resolve — which `test_a_kid_only_in_a_med_does_not_resolve`
# below asserts.
#: The shipped descriptor, as the RDP that issues these receipts would publish
#: it. The sample is `urn:sbm:rdp:mockeu-001`'s and the receipts built here are
#: issued by `urn:sbm:rdp:demo-out`; SBM-ADR-0015 makes a descriptor authorise
#: its OWN participant's receipts and nobody else's, so the two must agree. The
#: mismatch was harmless until this round only because nothing compared them.
ISSUER = "urn:sbm:rdp:demo-out"
SHIPPED_PROVIDER = json.loads(
    (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())["projection"]
PROVIDER = dict(SHIPPED_PROVIDER, participant_id=ISSUER)
MED = json.loads((ROOT / "samples" / "sample-BW-MED.json").read_text())["projection"]
SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]

OCTETS = b"\x00\x01" + b"the exact octets handed to the device" * 3
SESSION = {"kind": "token-digest", "digest": "a" * 64}
DEVICE = "DEV-1"
CRED = {"kind": "device", "uid": SE["recipient_uid"], "mid": "F1N2C3D4P",
        "device_id": DEVICE, "session": SESSION["digest"]}   # R11-01
EVENT = "2026-04-04T10:16:23Z"


def setup_function():
    # R7-02: the delivery items are server state like the ledgers, so a
    # test must not inherit a previous one's transfer.
    mock._DELIVERY_ITEMS.clear()
    mock._DS_LEDGER.clear()
    mock._ACK_LEDGER.clear()


def _ack(message_id="01HZ3KEY00000000000000001", *, server_clock=EVENT, **over):
    rdp = over.pop("issuing_rdp_id", "urn:sbm:rdp:demo-out")
    token = _staged(mock, issuing_rdp_id=rdp, message_id=message_id,
                    recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
                    device_id=DEVICE, octets=OCTETS, session_binding=SESSION)
    over.setdefault("collection_token", token)     # R9-01: required on the wire
    return mock.receipt_ack(message_id=message_id, issuing_rdp_id=rdp,
                            device_id=DEVICE, credential=CRED,
                            session_binding=SESSION, octets=OCTETS,
                            server_clock=server_clock, **over)


def _digest():
    import hashlib
    return {"format": "mls10-message", "hex": hashlib.sha256(OCTETS).hexdigest()}


def _provider(*keys, participant_id=None, kind="BW-PROVIDER-v1"):
    """A descriptor as its own participant publishes it.

    `type` and `participant_id` are not decoration: the receipt check refuses a
    document of another kind, and refuses one belonging to another RDP.
    """
    doc = {"type": kind, "participant_id": participant_id or PROVIDER["participant_id"],
           "ds_receipt_keys": list(keys)}
    return {k: v for k, v in doc.items() if v is not None}


DEMO_KEY = PROVIDER["ds_receipt_keys"][0]


# ---------------------------------------------------------------------------
# The obligation now has a referent
# ---------------------------------------------------------------------------


def _expect(receipt):
    """R7-02: the delivery context is a TYPE now — complete, or it raises. A
    bare mapping allowed `{}` and all-None contexts that asserted nothing."""
    from lint_cli import DeliveryContext
    return DeliveryContext(
        message_id=receipt.get("message_id"),
        issuing_rdp_id=receipt.get("issuing_rdp_id"),
        recipient_uid=receipt.get("recipient_uid"),
        mid=receipt.get("mid"),
        device_id=receipt.get("device_id"),
        session_binding=receipt.get("session_binding"),
        message_digest=receipt.get("message_digest"))


def test_the_receipt_names_its_verifying_key():
    receipt = _ack()
    assert receipt["ds_kid"] == "ds-demo-2026"
    assert receipt["ds_alg"] == "EdDSA"


def test_the_published_med_carries_the_key_the_receipt_names():
    """Published in a signed, retained object rather than behind an endpoint
    that would need its own rotation and retention machinery."""
    assert any(k["kid"] == _ack()["ds_kid"] for k in PROVIDER["ds_receipt_keys"])


def test_rdp_out_resolves_the_key_and_issues_the_de():
    receipt = _ack()
    assert mock.delivered_at_from_receipt(receipt, _digest(), provider=PROVIDER, expect=_expect(receipt)) == EVENT


def test_a_receipt_without_a_kid_yields_no_de():
    """The state before R3-04: a signature with no way to say which key."""
    receipt = copy.deepcopy(_ack())
    receipt.pop("ds_kid")
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(receipt, _digest(), provider=PROVIDER, expect=_expect(receipt))
    assert "no referent" in exc.value.detail


# ---------------------------------------------------------------------------
# Validity at the EVENT, which is the whole design
# ---------------------------------------------------------------------------

def test_a_receipt_verifies_after_the_key_is_rotated_out():
    """The property that decides between judging validity at event time and at
    verification time. A 2026 receipt must still verify in 2033."""
    rotated = _provider(dict(DEMO_KEY, valid_until="2026-06-01T00:00:00Z"),
                   dict(DEMO_KEY, kid="ds-demo-2027",
                        valid_from="2026-06-01T00:00:00Z"))
    key = lc.resolve_ds_receipt_key(rotated, "ds-demo-2026", EVENT)
    assert key["kid"] == "ds-demo-2026"
    # R9-01: `_ack()` collects to obtain its token and an acknowledged item is
    # not offered again, so ONE receipt is produced and reused rather than the
    # fixture being called twice for the same message.
    receipt = _ack()
    assert mock.delivered_at_from_receipt(
        receipt, _digest(), provider=rotated, expect=_expect(receipt)) == EVENT


def test_a_key_that_had_not_yet_taken_effect_cannot_have_signed_it():
    future = _provider(dict(DEMO_KEY, valid_from="2026-09-01T00:00:00Z"))
    with pytest.raises(lc.ReceiptKeyError) as exc:
        lc.resolve_ds_receipt_key(future, DEMO_KEY["kid"], EVENT)
    assert "after the" in str(exc.value)


def test_a_key_already_retired_at_the_event_fails():
    retired = _provider(dict(DEMO_KEY, valid_until="2026-02-01T00:00:00Z"))
    with pytest.raises(lc.ReceiptKeyError):
        lc.resolve_ds_receipt_key(retired, DEMO_KEY["kid"], EVENT)


def test_the_window_is_half_open_at_the_boundary():
    """Consistent with every other window in the profile: an instant on the
    boundary belongs to exactly one key."""
    boundary = _provider(dict(DEMO_KEY, valid_until=EVENT))
    with pytest.raises(lc.ReceiptKeyError):
        lc.resolve_ds_receipt_key(boundary, DEMO_KEY["kid"], EVENT)
    assert lc.resolve_ds_receipt_key(
        _provider(dict(DEMO_KEY, valid_from=EVENT)), DEMO_KEY["kid"], EVENT)


# ---------------------------------------------------------------------------
# Ambiguity fails closed
# ---------------------------------------------------------------------------

def test_an_unknown_kid_fails():
    with pytest.raises(lc.ReceiptKeyError) as exc:
        lc.resolve_ds_receipt_key(MED, "nobody-published-this", EVENT)
    assert "nobody published" in str(exc.value)


def test_two_keys_sharing_one_kid_fail_closed():
    """The substitution risk the identifier exists to remove — so a duplicate
    identifier cannot be resolved by picking one."""
    ambiguous = _provider(DEMO_KEY, dict(DEMO_KEY, public_key_b64="another-key"))
    with pytest.raises(lc.ReceiptKeyError) as exc:
        lc.resolve_ds_receipt_key(ambiguous, DEMO_KEY["kid"], EVENT)
    assert "ambiguous" in str(exc.value)


def test_an_algorithm_disagreement_is_rejected():
    """Three-way agreement, as for confirmation keys (DR-12): the receipt's
    declared algorithm must equal the published key's."""
    receipt = copy.deepcopy(_ack())
    receipt["ds_alg"] = "ES256"
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(receipt, _digest(), provider=PROVIDER, expect=_expect(receipt))
    assert "algorithm" in exc.value.detail


# ---------------------------------------------------------------------------
# The contract and the schema say so
# ---------------------------------------------------------------------------

def test_the_contract_requires_the_identifier_and_the_algorithm():
    receipt = DS["components"]["schemas"]["DeliveryReceipt"]
    assert {"ds_kid", "ds_alg", "ds_signature"} <= set(receipt["required"])
    assert set(receipt["properties"]["ds_alg"]["enum"]) == {"EdDSA", "ES256", "ES384"}


def test_the_provider_schema_defines_the_key_history():
    """SBM-ADR-0015: the history is published in the PROVIDER's descriptor.

    It was the entity's BW-MED, because the Delivery Service was a second
    provider and the customer's signed document was the only thing already
    retained for the evidence period. With one provider role the key is the
    RDP's own, and the shape — which fields, and that validity is judged at the
    receipt's own instant — is what had to survive the move.
    """
    prov = json.loads((ROOT / "schemas" / "bw-provider.schema.json").read_text())
    keys = prov["properties"]["ds_receipt_keys"]["items"]
    assert set(keys["required"]) == {"kid", "alg", "public_key_b64", "valid_from"}
    assert "valid_until" in keys["properties"]
    note = " ".join(prov["properties"]["ds_receipt_keys"]["description"].split())
    assert "at the receipt's `server_time`" in note
    assert "NOT at verification time" in note


def test_the_med_no_longer_publishes_the_receipt_key():
    """And the path is DELETED, not kept as a fallback (A4). A fallback would
    make the move a rename: a provider could keep publishing the key on its
    customers' documents and nothing would notice."""
    med = json.loads((ROOT / "schemas" / "bw-med.schema.json").read_text())
    assert "ds_receipt_keys" not in med["properties"]
    assert "msp" not in med["properties"], \
        "the MSP is not a role, so the MED names no MSP endpoint"


def test_a_kid_only_in_a_med_does_not_resolve():
    """The deleted fallback, asserted against the real thing.

    This test used to hand in a mapping with NO `ds_receipt_keys` at all, so it
    was refused for having nothing to resolve and proved the property by proxy:
    it passed against the base function, which read `ds_receipt_keys` off
    whatever it was given and would have resolved the key had the mapping
    carried one. What must be refused is a document that DOES carry the kid and
    is not the issuing provider's descriptor — otherwise SBM-ADR-0015's move is
    a rename, and a provider could keep publishing its receipt key on its
    customers' documents with nothing to notice.

    The MED here is built from the CURRENT sample plus the key. The 2.1 sample
    that really carried it is history and is not resurrected as a fixture.
    """
    receipt = _ack()
    assert receipt["ds_kid"] == DEMO_KEY["kid"], (
        "the receipt must name the key the document below publishes, or this "
        "passes for the wrong reason")
    med = dict(copy.deepcopy(MED), ds_receipt_keys=[copy.deepcopy(DEMO_KEY)])
    assert med["type"] == "BW-MED-v1" and "participant_id" not in med
    with pytest.raises(mock.AckRejected) as caught:
        mock.delivered_at_from_receipt(receipt, _digest(), provider=med,
                                       expect=_expect(receipt))
    assert caught.value.reason == "receipt-unverifiable"
    assert "BW-PROVIDER-v1" in caught.value.detail, caught.value.detail


def test_another_rdps_descriptor_does_not_authorise_this_receipt():
    """The sibling, and the half `_descriptor_for` gets right by selection: a
    genuine BW-PROVIDER-v1, publishing the very key the receipt names, that
    belongs to a different participant. A provider publishes its OWN receipt
    keys; the direct path compared nothing, so any descriptor carrying the kid
    would do."""
    receipt = _ack()
    other = _provider(DEMO_KEY, participant_id="urn:sbm:rdp:someone-else")
    with pytest.raises(mock.AckRejected) as caught:
        mock.delivered_at_from_receipt(receipt, _digest(), provider=other,
                                       expect=_expect(receipt))
    assert caught.value.reason == "receipt-unverifiable"
    assert "someone-else" in caught.value.detail and \
        receipt["issuing_rdp_id"] in caught.value.detail, caught.value.detail


def test_a_descriptor_with_no_participant_is_refused():
    """A BW-PROVIDER-v1 that names no participant authorises nothing: there is
    no party whose keys these are. Fail closed rather than fall through to the
    key lookup, which would have accepted it."""
    receipt = _ack()
    anonymous = {"type": "BW-PROVIDER-v1", "ds_receipt_keys": [copy.deepcopy(DEMO_KEY)]}
    with pytest.raises(mock.AckRejected) as caught:
        mock.delivered_at_from_receipt(receipt, _digest(), provider=anonymous,
                                       expect=_expect(receipt))
    assert caught.value.reason == "receipt-unverifiable"
