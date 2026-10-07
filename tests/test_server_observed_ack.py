# SPDX-License-Identifier: MIT
"""DR-10 — the S2 event time is observed by the server, not chosen by the client.

Former defect (round-2 review, High): the DS receipt endpoint took a
client-supplied `acked_at` and the profile defined `delivered_at = acked_at`.
No rule required a server-observed instant, bounded clock skew, or bound the
instant to a retained session. The receipt operation also inherited the DS's
generic security scheme, which admits a member- or entity-bound token,
although the operation requires DEVICE-bound authentication.

A device — or a compromised entity session — could therefore acknowledge after
`expires_at` while backdating into the valid window. That defeats the X-21
deadline (an availability DE is issued on this event, with no recipient
confirmation behind it) and hollows out the authenticated-S2 proof.

Now: the DS observes `server_time`, returns a signed receipt binding
(message_id, recipient_uid, mid, device_id, session_binding, server_time,
message_digest), and RDP(out) verifies that receipt before issuing the DE.
`client_acked_at` survives only as diagnostic metadata.

The four acceptance tests are the review's own. The contract assertions read
the PUBLISHED YAML, because the security-scheme half of this finding was a
contract defect rather than a code defect.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))



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
SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]

OCTETS = b"\x00\x01" + b"the exact octets handed to the device" * 3
SESSION = {"kind": "token-digest", "digest": "a" * 64}
OTHER_SESSION = {"kind": "token-digest", "digest": "b" * 64}
DEVICE = "DEV-1"
# R11-01: the credential names the device's entity and member, not only its label.
PRINCIPAL = (SE["recipient_uid"], "F1N2C3D4P", DEVICE)
DEVICE_CRED = {"kind": "device", "uid": PRINCIPAL[0], "mid": PRINCIPAL[1],
               "device_id": DEVICE, "session": SESSION["digest"]}

# The instants that matter: the message expires at 10:15:00.
EXPIRES = "2026-04-07T10:15:00Z"
IN_WINDOW = "2026-04-07T10:14:00Z"
AFTER_EXPIRY = "2026-04-07T10:16:00Z"


def setup_function():
    # R7-02: the delivery items are server state like the ledgers, so a
    # test must not inherit a previous one's transfer.
    mock._DELIVERY_ITEMS.clear()
    mock._DS_LEDGER.clear()
    mock._ACK_LEDGER.clear()


def _ack(message_id="01HZ3ACK00000000000000001", *, server_clock=AFTER_EXPIRY,
         credential=DEVICE_CRED, session=SESSION, octets=OCTETS, **over):
    rdp = over.pop("issuing_rdp_id", "urn:sbm:rdp:demo-out")
    # R7-02: the DS must have accepted, queued and TRANSFERRED the item. These
    # tests are about the observed instant and the first-ack rule, so they run
    # the real lifecycle rather than a shortcut — a shortcut would restore the
    # orphan this finding is about.
    # Stage for the device/session the call will actually present, so a test
    # that overrides one of them exercises the CHECK rather than tripping the
    # fixture: the negative cases below are about receipt_ack refusing, not
    # about staging refusing.
    token = _staged(
        mock, issuing_rdp_id=rdp, message_id=message_id,
        recipient_uid=over.get("recipient_uid", SE["recipient_uid"]),
        mid=over.get("mid", "F1N2C3D4P"),
        device_id=over.get("device_id", DEVICE),
        octets=octets, session_binding=over.get("session_binding", session))
    kw = dict(message_id=message_id, issuing_rdp_id=rdp,
              device_id=DEVICE, credential=credential,
              session_binding=session, octets=octets, server_clock=server_clock,
              collection_token=token)   # R9-01: required on the wire
    # R11-01: the entity and member stage the item; the acknowledgement takes
    # them from the authenticated credential, never from its arguments.
    kw.update({k: v for k, v in over.items() if k not in ("recipient_uid", "mid")})
    return mock.receipt_ack(**kw)


# ---------------------------------------------------------------------------
# The review's four acceptance tests
# ---------------------------------------------------------------------------


def _expect(receipt):
    """R7-02: the delivery context is a TYPE now — complete, or it raises. A
    bare mapping allowed `{}` and all-None contexts that asserted nothing."""
    from lint_cli import DeliveryContext
    return DeliveryContext(
        message_id=receipt.get("message_id"),
        issuing_rdp_id=receipt.get("issuing_rdp_id"),
        observed_by=receipt.get("observed_by"),
        recipient_uid=receipt.get("recipient_uid"),
        mid=receipt.get("mid"),
        device_id=receipt.get("device_id"),
        session_binding=receipt.get("session_binding"),
        message_digest=receipt.get("message_digest"))


def test_a_backdated_client_timestamp_cannot_change_delivered_at():
    """The attack verbatim: acknowledge after expiry, claim an instant inside
    the window. `delivered_at` must still be the server's observation, so the
    DE that follows is caught by the X-21 deadline."""
    from lint_cli import instant
    receipt = _ack(server_clock=AFTER_EXPIRY, client_acked_at=IN_WINDOW)
    # R4-03: the BW-MED is REQUIRED now. Verification resolves the published
    # key and checks the signature against it; without the published key there
    # is nothing to verify against, and issuing a DE anyway was the defect.
    delivered_at = mock.delivered_at_from_receipt(
        receipt, {"format": "mls10-message",
                  "hex": hashlib.sha256(OCTETS).hexdigest()},
        # SBM-ADR-0015: the receipt key is the issuing RDP's OWN, so the
        # descriptor must be that RDP's. The shipped sample belongs to
        # `urn:sbm:rdp:mockeu-001` and this receipt is issued by
        # `urn:sbm:rdp:demo-out`; the check now compares the two, so the fixture
        # states whose descriptor it is instead of relying on nobody looking.
        provider=dict(json.loads(
            (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())["projection"],
            participant_id=receipt["issuing_rdp_id"]),
        expect=_expect(receipt))
    assert delivered_at == AFTER_EXPIRY
    assert instant(delivered_at) > instant(EXPIRES), \
        "the late delivery must remain late once the client claim is ignored"
    assert receipt["client_acked_at"] == IN_WINDOW, \
        "the client reading is retained — as diagnostics, not as the event"


def test_a_future_client_timestamp_cannot_change_delivered_at_either():
    """Skew in the other direction: claiming an instant that has not happened
    must not move the event forward (it would extend an expired window by
    making a later deadline appear to be met)."""
    receipt = _ack(server_clock=IN_WINDOW, client_acked_at="2027-01-01T00:00:00Z")
    assert receipt["server_time"] == IN_WINDOW


def test_an_entity_only_token_cannot_create_a_device_handover():
    for credential in ({"kind": "entity", "session": SESSION["digest"]},
                       {"kind": "member", "uid": PRINCIPAL[0], "mid": "F1N2C3D4P",
                        "session": SESSION["digest"]},
                       None):
        with pytest.raises(mock.AckRejected) as exc:
            _ack(credential=credential)
        assert exc.value.reason == "device-auth-required"
    # nor may a device credential speak for a different device
    with pytest.raises(mock.AckRejected) as exc:
        _ack(credential={"kind": "device", "uid": PRINCIPAL[0], "mid": PRINCIPAL[1],
                         "device_id": "DEV-2",
                         "session": SESSION["digest"]})
    assert exc.value.reason == "device-auth-required"


def test_replay_outside_the_original_session_fails():
    with pytest.raises(mock.AckRejected) as exc:
        _ack(session=OTHER_SESSION)          # credential bound to SESSION
    assert exc.value.reason == "session-replay"


def test_the_first_server_observed_ack_wins_and_duplicates_cannot_alter_it():
    mid = "01HZ3ACK00000000000000002"
    first = _ack(mid, server_clock=IN_WINDOW)
    # a second ack, later, from a different device in the same entity
    again = _ack(mid, server_clock=AFTER_EXPIRY,
                 device_id="DEV-9",
                 credential={"kind": "device", "uid": PRINCIPAL[0],
                             "mid": PRINCIPAL[1], "device_id": "DEV-9",
                             "session": SESSION["digest"]})
    assert again == first, "a duplicate ack produced a different event"
    assert again["server_time"] == IN_WINDOW
    assert again["device_id"] == DEVICE, "the second device overwrote the first"


# ---------------------------------------------------------------------------
# RDP(out) verifies the receipt before issuing the DE
# ---------------------------------------------------------------------------

def _submitted(octets=OCTETS):
    return {"format": "mls10-message", "hex": hashlib.sha256(octets).hexdigest()}


def test_a_receipt_for_different_bytes_yields_no_de():
    """The digest binds the receipt to the octets RDP(out) committed to at
    submission (DR-02), so 'some delivery happened' is not enough."""
    receipt = _ack(octets=b"\x00\x01DIFFERENT octets entirely")
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(receipt, _submitted(), expect=_expect(receipt))
    assert exc.value.reason == "receipt-unverifiable"


def test_a_tampered_receipt_yields_no_de():
    receipt = copy.deepcopy(_ack())
    receipt["server_time"] = IN_WINDOW          # move the event into the window
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(receipt, _submitted(), expect=_expect(receipt))
    assert exc.value.reason == "receipt-unverifiable"


def test_an_unsigned_receipt_yields_no_de():
    receipt = copy.deepcopy(_ack())
    receipt.pop("ds_signature")
    with pytest.raises(mock.AckRejected):
        mock.delivered_at_from_receipt(receipt, _submitted(), expect=_expect(receipt))


# ---------------------------------------------------------------------------
# The published contract, which was half the finding
# ---------------------------------------------------------------------------

OP = DS["paths"]["/messages/{issuing_rdp_id}/{message_id}/receipt-ack"]["post"]


def test_the_operation_requires_device_bound_authentication():
    schemes = {k for arm in OP["security"] for k in arm}
    # R5-06: the operation offers a bearer credential OR its mutual-TLS
    # equivalent, which is how OpenAPI says 'either'. What matters is the
    # PROPERTY — every alternative binds the same party — so that is what
    # is asserted, rather than one spelling of the list.
    assert schemes == {"deviceAuth", "deviceMtls"}, \
        "the generic entity-level arm still satisfies the handover"
    desc = DS["components"]["securitySchemes"]["deviceAuth"]["description"]
    assert "bound to the enrolled device" in desc
    assert "NOT this scheme" in desc


def test_the_client_timestamp_is_optional_and_declared_non_authoritative():
    # R9-01: the request is a NAMED component now, so the reference can
    # validate its own call against it. Follow the `$ref` rather than
    # asserting against an inline object that no longer exists.
    ref = OP["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    body = DS["components"]["schemas"][ref.rsplit("/", 1)[1]]
    assert "acked_at" not in body["properties"], \
        "the authoritative-sounding field name is gone"
    # R8-03 requirement 6: the acknowledgement now REFERENCES the transfer
    # handle the public boundary produced, so a device names THE transfer it
    # collected rather than naming a message and leaving the DS to infer which
    # transfer was meant. The client's own clock stays optional.
    assert body["required"] == ["device_id", "collection_token"]
    assert "client_acked_at" not in body["required"]
    assert "NON-AUTHORITATIVE" in body["properties"]["client_acked_at"]["description"]


def test_the_response_is_the_signed_receipt_with_every_bound_field():
    ref = OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    receipt = DS["components"]["schemas"][ref.rsplit("/", 1)[1]]
    # R3-04 adds ds_kid and ds_alg: "verify against the DS's published key"
    # had no referent, so the signature was unverifiable or pinned by private
    # configuration.
    # R7-02: `issuing_rdp_id` was SIGNED by the code and absent from this
    # schema, so the wire contract described a receipt the implementation does
    # not produce. The set is asserted against the code's mandatory signed set
    # rather than restated, so the two cannot drift apart again.
    from lint_cli import DS_RECEIPT_MANDATORY_SIGNED
    assert set(receipt["required"]) == \
        set(DS_RECEIPT_MANDATORY_SIGNED) | {"ds_signature"}
    assert receipt.get("unevaluatedProperties") is False, \
        "an undeclared field could otherwise ride along unnoticed"


def test_the_id_states_the_server_observed_rule_and_the_forwarding():
    t = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md")
                 .read_text().replace("**", "").replace("`", "").split())
    assert "The event instant is SERVER-OBSERVED" in t
    assert "a client-supplied timestamp MUST NOT determine it" in t
    assert "forward to RDP(out), a signed receipt" in t
    assert "an unverifiable receipt yields NO DE" in t
    # R11-04: the receipt dates delivery at the availability grade only.
    assert "It is delivered_at at the availability grade only" in t
    assert "delivered_at is the receipt's server_time" not in t


# ===========================================================================
# R9-01 — the collection token is REQUIRED, at runtime as well as on paper
#
# The published request declares `[device_id, collection_token]`. The reference
# compared the token only `if collection_token is not None`, so omitting it
# skipped the comparison entirely — `None` as a hidden compatibility path
# around an OpenAPI `required` list, preserving exactly the pre-token flow the
# token was introduced to retire.
# ===========================================================================

def _direct(token, message_id="01HZ9TOK00000000000000001", **over):
    """`receipt_ack` called DIRECTLY, so nothing re-stages behind the test.
    `_ack()` collects to obtain its token, and an acknowledged item is not
    offered again — calling it twice for one message would restage nothing."""
    kw = dict(message_id=message_id, issuing_rdp_id="urn:sbm:rdp:demo-out",
              device_id=DEVICE, credential=DEVICE_CRED, session_binding=SESSION,
              octets=OCTETS, server_clock=IN_WINDOW)
    if token is not mock._REQUIRED:
        kw["collection_token"] = token
    kw.update(over)
    return mock.receipt_ack(**kw)


def _collected(message_id="01HZ9TOK00000000000000001", device=DEVICE,
               session=None):
    """Stage through the PUBLIC operations and return the issued token."""
    session = session or SESSION
    return _staged(mock, issuing_rdp_id="urn:sbm:rdp:demo-out",
                   message_id=message_id, recipient_uid=SE["recipient_uid"],
                   mid="F1N2C3D4P", device_id=device, octets=OCTETS,
                   session_binding=session)


def test_the_exact_token_succeeds_and_a_conforming_retry_returns_it_again():
    """The control, first: the value collection issued must work on this path,
    or every refusal below would prove nothing (cowork's §5 rule)."""
    setup_function()
    token = _collected()
    a = _direct(token)
    b = _direct(token)
    assert a == b, "a conforming retry must return the same receipt"
    assert len(mock._ACK_LEDGER) == 1


@pytest.mark.parametrize("token,reason", [
    (mock._REQUIRED, "collection-token-required"),   # omitted entirely
    (None, "collection-token-required"),             # explicit null
    ("", "acknowledgement-malformed"),               # too short for the grammar
    # `CollectionToken` is `minLength: 8` and NOT patterned, deliberately: it
    # is an opaque capability, and dictating its format would force every
    # Delivery Service to mint the reference's. So an 11-character string is
    # well-formed and simply wrong, which is a different answer.
    ("not a token", "delivery-token-mismatch"),
    ("dt-" + "0" * 32, "delivery-token-mismatch"),   # well-formed, wrong item
])
def test_no_other_token_value_creates_a_receipt(token, reason):
    """R9-01's first acceptance test. Only ABSENCE failed open, so the fix is
    one guard and these are regressions rather than repairs — except the
    malformed cases, which are new: the published request Schema runs now, so a
    value that is not a `CollectionToken` is refused before the item is
    resolved. Absence and malformation get DIFFERENT reasons; a client acts on
    them differently."""
    setup_function()
    _collected()
    with pytest.raises(mock.AckRejected) as exc:
        _direct(token)
    assert exc.value.reason == reason
    assert mock._ACK_LEDGER == {}, "a refused acknowledgement left a receipt"
    assert mock._DELIVERY_ITEMS[
        ("urn:sbm:rdp:demo-out", "01HZ9TOK00000000000000001",
         *PRINCIPAL)]["state"] == "transferred", \
        "a refused acknowledgement moved the item"


def test_another_devices_token_cannot_acknowledge_this_transfer():
    """R9-01's third acceptance test: the same `message_id`, a different
    device. The token names a transfer, and there is one per device."""
    setup_function()
    mine = _collected()
    theirs = _staged(mock, issuing_rdp_id="urn:sbm:rdp:demo-out",
                     message_id="01HZ9TOK00000000000000001",
                     recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
                     device_id="DEV-OTHER", octets=OCTETS,
                     session_binding=SESSION)
    assert mine != theirs
    with pytest.raises(mock.AckRejected) as exc:
        _direct(theirs)
    assert exc.value.reason == "delivery-token-mismatch"
    assert mock._ACK_LEDGER == {}


def test_a_token_from_a_superseded_session_is_refused():
    """R9-X2 reclaim, seen from the acknowledgement side: reclaiming reissues
    the token, so the one from the superseded transfer authorises nothing."""
    setup_function()
    stale = _collected()
    other = {"kind": "token-digest", "digest": "b" * 64}
    fresh = _collected(session=other)
    assert stale != fresh
    with pytest.raises(mock.AckRejected) as exc:
        _direct(stale, session_binding=other,
                credential=dict(DEVICE_CRED, session=other["digest"]))
    assert exc.value.reason == "delivery-token-mismatch"
def test_the_reference_validates_its_own_call_against_the_published_request():
    """R9-01 requirement 5. The two used to describe different protocols: the
    contract required the token, the reference did not."""
    doc = DS
    ref = doc["paths"]["/messages/{issuing_rdp_id}/{message_id}/receipt-ack"][
        "post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    schema = doc["components"]["schemas"][ref.rsplit("/", 1)[1]]
    assert schema["required"] == ["device_id", "collection_token"]
    assert schema["unevaluatedProperties"] is False
    src = (ROOT / "scripts" / "mock_rdp.py").read_text()
    assert '"ReceiptAckRequest"' in src, \
        "the reference does not validate against the published request"


def test_the_signed_tuple_prose_matches_what_is_actually_signed():
    """R9-01 requirement 4. The description listed seven fields and omitted
    `issuing_rdp_id`, which R6-03 added to the signed object and R7-02 made
    mandatory-signed — a stale claim about what the artefact binds."""
    from lint_cli import DS_RECEIPT_MANDATORY_SIGNED
    d = " ".join(OP["description"].split())
    tuple_text = d.split("binding (", 1)[1].split(")", 1)[0]
    named = {t.strip() for t in tuple_text.split(",")}
    assert "issuing_rdp_id" in named
    # The `ds_*` fields are the signature's own envelope — which key signed
    # this, with which algorithm — not facts the receipt attests ABOUT the
    # handover. The prose lists what is BOUND; those describe the binding.
    attested = {f for f in DS_RECEIPT_MANDATORY_SIGNED
                if not f.startswith("ds_")}
    assert attested <= named, \
        f"the prose omits mandatory-signed facts: {sorted(attested - named)}"
    # ...and the token is deliberately NOT signed: it is a capability, not an
    # attested fact, and evidence outlives the session it authorises.
    assert "collection_token" not in named
    assert "CAPABILITY, not an attested fact" in d
