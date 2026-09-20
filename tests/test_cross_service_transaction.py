# SPDX-License-Identifier: MIT
"""R3-06 and R3-07 — the MLS-secret boundary, and the submission transaction.

**R3-06.** Both `/welcome` operations took `memberAuth`, while `deviceAuth` —
added in round 2 for exactly this class of problem — sat unused in the same
contract. A Welcome carries the group secrets for ONE device, so an entity- or
member-level credential could collect the secrets of every device it covers.

**R3-07.** DR-02 fixed WHAT RDP(out) attests; it never said WHEN. `POST
/submissions` and `POST /messages` were independent operations with no
ordering, no durable state, no recovery and no response proof: `POST /messages`
returned a bare `202`, so nothing tied DS acceptance to the same
`(message_id, mls_group_id, bytes)`. An implementation could seal SE before the
DS accepted anything, deliver bytes with no recoverable SE, or let the two
ledgers bind one message_id to different octets.

And my own `test_atomic_submission.py` was the other half: it drove
`mock.accept_submission()` directly and asserted its fixture used declared
fields. It never exercised an operation, a failure between steps, or a retry.
These tests drive the **flow** — and the three interruption points the review
names are injected, not described.

The invariant, stated once: **one message_id, one byte binding, at most one SE,
at most one delivery.**
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


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")
DS = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]

BYTES_A = b"\x00\x01" + b"the exact octets handed to transport" * 3
BYTES_B = b"\x00\x01" + b"DIFFERENT octets under the same id!!" * 3


# R5-01: the discovery material intake now REQUIRES. The recipient's BW-ORG,
# because the acceptance policy is RECOMPUTED against the published document;
# the sender's BW-MEMBER, because the D4 confirmation is verified against that
# device's published confirmation key. A submission that cannot be checked is
# refused rather than accepted unchecked.
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
MEMBERS = [json.loads((ROOT / "samples" / "sample-BW-MEMBER.json").read_text())["projection"]]


def _submit(meta, **kw):
    """The transaction with the discovery material a real RDP holds."""
    kw.setdefault("org", ORG)
    kw.setdefault("members", MEMBERS)
    return mock.submit(meta, **kw)


RDP_A = "urn:sbm:rdp:fr-001"
RDP_B = "urn:sbm:rdp:de-002"


def setup_function():
    mock._SUBMISSION_LEDGER.clear()
    mock._DS_LEDGER.clear()
    mock._SE_LEDGER.clear()
    mock._WELCOME_QUEUE.clear()


def _meta(message_id="01HZ3TXN0000000000000001", octets=BYTES_A, **over):
    meta = {
        "message_id": message_id,
        "sender_uid": SE["sender_uid"], "sender_addr": SE["sender_addr"],
        "recipient_uid": SE["recipient_uid"], "recipient_addr": SE["recipient_addr"],
        "scope_ref": SE["scope_ref"], "payload_hash": SE["payload_hash"],
        "mls_message_b64": base64.b64encode(octets).decode(),
        "mls_group_id": SE["mls_group_id"], "mls_epoch": SE["mls_epoch"],
        "auth_method": SE["auth_method"], "auth_context": SE["auth_context"],
        "sent_at": SE["sent_at"], "expires_at": SE["expires_at"],
        "origin_proof": SE["origin_proof"],
        "acceptance_policy_ref": SE["acceptance_policy_ref"],
    }
    meta.update(over)
    # R3-01: origin_proof=sender-signed REQUIRES the D4 tuple, and LINT-DE-19
    # requires the tuple to describe THIS submission. A real wallet computes
    # the commitments it signs from the same octets it is sending, so the test
    # does the same rather than borrowing another message's tuple.
    import mls_wire
    octets_now = base64.b64decode(meta["mls_message_b64"])
    meta["envelope_hash"] = mls_wire.envelope_hash(octets_now)
    meta["mls_state"] = mls_wire.mls_state_hash(
        mls_wire.demo_group_context(meta["mls_group_id"], meta["mls_epoch"],
                                    scope_id=meta["scope_ref"]["scope_id"],
                                    scope_version=meta["scope_ref"]["version"]))
    if SE.get("sender_confirmation"):
        sc = copy.deepcopy(SE["sender_confirmation"])
        from lint_cli import D4_COPIED_FIELDS
        for field in D4_COPIED_FIELDS:
            sc[field] = meta[field]
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
        meta["sender_confirmation"] = sc
    return meta


# ===========================================================================
# R3-07 — the transaction
# ===========================================================================

_INV_SEQ = [0]


SUITE_X25519 = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"

# R9-03: derived the published way rather than invented — `kp-0001` and
# `gi-0000…` are not values the grammars admit, and a fixture that can make
# one up cannot notice that nothing produces it.
import mls_wire as _w  # noqa: E402
_KP_REF = _w.keypackage_ref(b"placeholder", cipher_suite=SUITE_X25519)
_GI = _w.group_info_commitment(b"a demo GroupInfo", cipher_suite=SUITE_X25519)


def _invitation(device, welcome, **over):
    """R7-03: a Welcome is deposited WITH its invitation record — the material
    the DS needs to VALIDATE a refusal instead of echoing it.

    R8-04: and the request IS the published `InvitationDeposit`, so
    `recipient_device` and `welcome_b64` live INSIDE it. They used to be
    separate function arguments, which made every fixture here a request the
    contract rejected."""
    _INV_SEQ[0] += 1
    n = _INV_SEQ[0]
    inv = {"invitation_id": f"inv-{n:04d}", "recipient_device": device,
           "welcome_b64": base64.b64encode(welcome.encode()).decode(),
           "mls_group_id": "Zzw1S4pWq9T5n7xYbXc2dQ",
           "group_info_commitment": _GI,
           "offered_suite": SUITE_X25519,
           "reservation_id": f"res-{n:04d}", "keypackage_ref": _KP_REF,
           "created_at": "2026-04-04T09:00:00Z",
           "expires_at": "2026-04-05T09:00:00Z"}
    inv.update(over)
    return inv


def _deposit(device, welcome, credential, **over):
    """Runs the published lifecycle: reserve -> commit -> deposit (R8-04
    requirement 3). A deposit against an uncommitted reservation names packages
    that may still return to the pool."""
    holder = credential if credential.get("kind") == "member" else \
        {"kind": "member", "uid": "EU-FR-PSBID-ZYWVTSRQPNM8M4", "mid": "F1N2C3D4P"}
    # R9-03: the reservation ASSIGNS the id and RETURNS the KeyPackage
    # reference. The fixture used to invent both and hand them in, which is why
    # nothing noticed that the public flow produced neither.
    _INV_SEQ[0] += 1
    res = mock.reserve_keypackages(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=holder,
        cipher_suite=over.get("offered_suite", SUITE_X25519),
        targets=[{"mid": "F1N2C3D4P", "device_id": device}],
        idempotency_key=f"idem-{_INV_SEQ[0]:012d}")
    mock.commit_reservation(res["reservation_id"], credential=holder)
    pkg = next(k for k in res["keypackages"] if k["device_id"] == device)
    over.setdefault("reservation_id", res["reservation_id"])
    over.setdefault("keypackage_ref", pkg["keypackage_ref"])
    inv = _invitation(device, welcome, **over)
    return mock.deposit_welcome(inv, credential=credential)


def test_the_happy_path_seals_only_after_ds_acceptance():
    se = _submit(_meta(), principal=RDP_A)
    assert mock._DS_LEDGER[(RDP_A, "01HZ3TXN0000000000000001")]["accepted_at"]
    # R4-05 point 6: the acceptance instant lives in the DS RECORD, not on the
    # SE. It used to be added there as an undeclared field on a purported
    # evidence object; standardising it would need a version bump and a defined
    # meaning, and it has neither.
    record = mock._DS_LEDGER[(RDP_A, "01HZ3TXN0000000000000001")]
    assert record["accepted_at"]
    assert "ds_accepted_at" not in se["projection"]


def test_a_verifier_can_correlate_ds_acceptance_and_se_to_the_same_bytes():
    """The review's fifth criterion, and the reason the bare 202 was the
    defect: without a record echoing the tuple there was nothing to correlate."""
    se = _submit(_meta(), principal=RDP_A)["projection"]
    record = mock._DS_LEDGER[(RDP_A, se["message_id"])]
    assert record["envelope_hash"] == se["envelope_hash"]
    assert record["envelope_hash"]["hex"] == hashlib.sha256(BYTES_A).hexdigest()


def test_the_ds_computes_the_digest_rather_than_echoing_it():
    """A DS echoing the submitter's digest would confirm the submitter's claim
    instead of its own receipt — DR-02's defect one layer down."""
    record = mock.ds_accept_message("01HZ3TXN0000000000000009",
                                    SE["mls_group_id"],
                                    base64.b64encode(BYTES_A).decode(),
                                    principal=RDP_A)
    assert record["envelope_hash"]["hex"] == hashlib.sha256(BYTES_A).hexdigest()


# ---------------------------------------------------------------------------
# The three interruption points, injected
# ---------------------------------------------------------------------------

def test_failure_before_ds_acceptance_leaves_no_se_and_the_retry_converges():
    meta = _meta()
    with pytest.raises(mock.TransportRejected):
        _submit(meta, principal=RDP_A, fail_at="before-acceptance")
    assert mock._SE_LEDGER == {}, "an SE existed for a message the DS never saw"
    assert mock._DS_LEDGER == {}
    se = _submit(meta, principal=RDP_A)["projection"]        # the wallet retries
    assert se["envelope_hash"]["hex"] == hashlib.sha256(BYTES_A).hexdigest()


def test_failure_after_acceptance_before_sealing_converges_without_a_second_delivery():
    meta = _meta()
    with pytest.raises(mock.TransportRejected):
        _submit(meta, principal=RDP_A, fail_at="after-acceptance")
    accepted = dict(mock._DS_LEDGER[(RDP_A, meta["message_id"])])
    assert mock._SE_LEDGER == {}, "sealed despite the interruption"
    se = _submit(meta, principal=RDP_A)["projection"]
    assert mock._DS_LEDGER[(RDP_A, meta["message_id"])] == accepted, \
        "the retry opened a second delivery"
    assert se["envelope_hash"] == accepted["envelope_hash"]


def test_failure_after_sealing_returns_the_SAME_se_on_retry():
    meta = _meta()
    with pytest.raises(mock.TransportRejected):
        _submit(meta, principal=RDP_A, fail_at="after-sealing")
    sealed = copy.deepcopy(mock._SE_LEDGER[(RDP_A, meta["message_id"])])
    again = _submit(meta, principal=RDP_A)
    assert again == sealed, "a second SE was issued for one message"
    assert len(mock._SE_LEDGER) == 1


def test_retries_converge_to_one_binding_one_se_and_no_second_delivery():
    """The invariant, stated as one test."""
    meta = _meta()
    results = [_submit(meta, principal=RDP_A) for _ in range(4)]
    assert all(r == results[0] for r in results)
    assert len(mock._SE_LEDGER) == 1 and len(mock._DS_LEDGER) == 1


# ---------------------------------------------------------------------------
# Conflicting bytes fail at BOTH boundaries
# ---------------------------------------------------------------------------

def test_conflicting_bytes_under_one_message_id_fail_at_the_rdp_boundary():
    _submit(_meta(), principal=RDP_A)
    with pytest.raises(mock.SubmissionRejected) as exc:
        # the SAME issuing RDP — a different one would be a different
        # namespace, which is the point of R4-U3 and is tested separately
        _submit(_meta(octets=BYTES_B), principal=RDP_A)
    assert exc.value.reason == "duplicate-message-id"


def test_conflicting_bytes_under_one_message_id_fail_at_the_ds_boundary():
    """Independently of the RDP, because a DS serving several RDPs cannot rely
    on one of them having checked."""
    mid = "01HZ3TXN0000000000000002"
    mock.ds_accept_message(mid, SE["mls_group_id"],
                           base64.b64encode(BYTES_A).decode(),
                           principal=RDP_A)
    with pytest.raises(mock.TransportRejected) as exc:
        mock.ds_accept_message(mid, SE["mls_group_id"],
                               base64.b64encode(BYTES_B).decode(),
                               principal=RDP_A)
    assert exc.value.reason == "duplicate-message-id"


def test_the_same_bytes_replayed_at_the_ds_return_the_same_record():
    mid = "01HZ3TXN0000000000000003"
    b64 = base64.b64encode(BYTES_A).decode()
    first = mock.ds_accept_message(mid, SE["mls_group_id"], b64, principal=RDP_A)
    assert mock.ds_accept_message(mid, SE["mls_group_id"], b64, principal=RDP_A) == first


# ---------------------------------------------------------------------------
# The contract states the ordering and the record
# ---------------------------------------------------------------------------

def test_the_contract_states_the_ordering_and_prohibits_early_sealing():
    op = DS["paths"]["/messages"]["post"]["description"]
    flat = " ".join(op.replace("`", "").split())
    assert "THE ORDERING IS NORMATIVE" in flat
    assert "Sealing before acceptance is PROHIBITED" in flat
    for point in ("before acceptance", "after acceptance, before sealing",
                  "after sealing, before the client response"):
        assert point in flat, point
    assert "one message_id, one byte binding, at most one SE, at most one delivery" in flat


def test_the_acceptance_response_is_typed_and_binds_the_tuple():
    resp = DS["paths"]["/messages"]["post"]["responses"]
    assert "201" in resp, "the bare 202 carried no binding"
    ref = resp["201"]["content"]["application/json"]["schema"]["$ref"]
    record = DS["components"]["schemas"][ref.rsplit("/", 1)[1]]
    # R4-05/R4-U3: issuing_rdp_id joins it — the normative handle is
    # (issuing-RDP, message_id), and the record echoes the AUTHENTICATED
    # principal rather than anything the client asserted.
    assert set(record["required"]) == {"message_id", "issuing_rdp_id",
                                       "mls_group_id", "envelope_hash",
                                       "accepted_at"}


# ===========================================================================
# R3-06 — the Welcome boundary
# ===========================================================================

# R11-01: principals name their entity, and a device its member too.
FR_UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
MEMBER = {"kind": "member", "uid": FR_UID, "mid": "F1N2C3D4P"}
ENTITY = {"kind": "entity"}
DEV_A = {"kind": "device", "uid": FR_UID, "mid": "F1N2C3D4P", "device_id": "DEV-A"}
DEV_B = {"kind": "device", "uid": FR_UID, "mid": "F1N2C3D4P", "device_id": "DEV-B"}


def test_an_entity_or_member_token_cannot_collect_any_welcome():
    """The review's first acceptance test."""
    _deposit("DEV-A", "w-a", MEMBER)
    for credential in (ENTITY, MEMBER, None):
        with pytest.raises(mock.WelcomeAccessDenied):
            mock.collect_welcomes(credential=credential)


def test_deposit_stays_member_level():
    """Handing a Welcome TO a device is not taking possession of its secrets,
    so the two authorisations are defined separately."""
    assert _deposit("DEV-A", "w-a", MEMBER)["welcome_id"]


def test_device_a_cannot_see_or_acknowledge_device_bs_welcome():
    """The second acceptance test."""
    b_item = _deposit("DEV-B", "w-b", MEMBER)
    assert mock.collect_welcomes(credential=DEV_A)["welcomes"] == []
    with pytest.raises(mock.WelcomeAccessDenied):
        mock.ack_welcome(b_item["welcome_id"], credential=DEV_A)
    assert len(mock.collect_welcomes(credential=DEV_B)["welcomes"]) == 1, \
        "A's failed acknowledgement removed B's item"


def test_queue_errors_do_not_reveal_another_devices_pending_state():
    """The fourth acceptance test. Another device's item and an id that never
    existed must be INDISTINGUISHABLE — otherwise the error is an oracle over
    another device's queue."""
    b_item = _deposit("DEV-B", "w-b", MEMBER)
    errors = []
    for welcome_id in (b_item["welcome_id"], "wel-never-existed"):
        with pytest.raises(mock.WelcomeAccessDenied) as exc:
            mock.ack_welcome(welcome_id, credential=DEV_A)
        errors.append((exc.value.reason, str(exc.value)))
    assert errors[0] == errors[1], f"the errors differ: {errors}"


def test_replays_and_concurrent_fetches_are_deterministic():
    """The third acceptance test. Fetching does not dequeue, so a lost response
    is retried harmlessly; acknowledgement is explicit and idempotent."""
    _deposit("DEV-A", "w-a", MEMBER)
    first = mock.collect_welcomes(credential=DEV_A)
    assert mock.collect_welcomes(credential=DEV_A) == first, \
        "a second fetch returned a different queue"
    wid = first["welcomes"][0]["welcome_id"]
    mock.ack_welcome(wid, credential=DEV_A)
    # R10-09: a repeat by the device that acknowledged is the 204 the contract
    # promises, so a lost response converges. This asserted the opposite —
    # "already gone == unknown" — which was the defect: the operation promised
    # 204 on repeat and answered the retry with a failure.
    assert mock.ack_welcome(wid, credential=DEV_A) is None
    assert mock.collect_welcomes(credential=DEV_A)["welcomes"] == []


def test_the_queue_is_typed_and_target_bound():
    """An array of unlabelled strings gave a device with two pending Welcomes
    no way to tell them apart or acknowledge one."""
    _deposit("DEV-A", "w-1", MEMBER)
    _deposit("DEV-A", "w-2", MEMBER)
    queue = mock.collect_welcomes(credential=DEV_A)
    assert queue["device_id"] == "DEV-A"
    assert len({w["welcome_id"] for w in queue["welcomes"]}) == 2
    assert all(w["recipient_device"] == "DEV-A" for w in queue["welcomes"])


def test_the_contract_requires_device_auth_for_collection_only():
    welcome = DS["paths"]["/welcome"]
    # R5-06: the operation offers a bearer credential OR its mutual-TLS
    # equivalent, which is how OpenAPI says 'either'. What matters is the
    # PROPERTY — every alternative binds the same party — so that is what
    # is asserted, rather than one spelling of the list.
    assert {k for b in welcome["get"]["security"] for k in b} == \
        {"deviceAuth", "deviceMtls"}
    assert {k for b in welcome["post"]["security"] for k in b} == \
        {"memberAuth", "memberMtls"}, \
        "deposit is member-level; only COLLECTION is device-bound"
    ack = DS["paths"]["/welcome/{welcome_id}"]["delete"]
    assert {k for b in ack["security"] for k in b} == {"deviceAuth", "deviceMtls"}
    assert "404" in ack["responses"] and "403" not in ack["responses"], \
        "a distinct 403 would confirm another device has a Welcome pending"


def test_the_queue_item_is_typed_in_the_contract():
    item = DS["components"]["schemas"]["WelcomeQueue"]["properties"]["welcomes"]["items"]
    # R10-05: the commitment the device must check, and the suite it is
    # computed under, are DELIVERED to it.
    assert set(item["required"]) == {"welcome_id", "recipient_device",
                                     "welcome_b64", "queued_at",
                                     "group_info_commitment", "offered_suite"}


# ===========================================================================
# R4-05 — the transaction produces the object it claims, in the right namespace
# ===========================================================================

def _projection(artefact):
    return artefact["projection"]


def test_the_happy_path_returns_a_REAL_sealed_se():
    """R4-05's first acceptance test, and the defect it names: `submit()`
    returned submission metadata plus a few computed fields, stored in a dict
    and CALLED a sealed SE. It carried no `type: SE-v1`, so `validate_body()`
    treated it as an unknown type and skipped Schema validation entirely —
    the conformance path did not construct the object it claimed to produce,
    and the tests drove this helper rather than the published surfaces."""
    from lint_cli import validate_body, projection_equals_decode
    art = _submit(_meta(), principal=RDP_A)
    assert set(art) == {"sm_artifact_b64", "projection"}, "not an M4 artefact"
    se = _projection(art)
    assert se["type"] == "SE-v1"
    assert not validate_body(se), validate_body(se)
    assert not list(projection_equals_decode(art)), "projection != decode(payload)"
    for required in ("evidence_id", "policy_id", "rdp_id", "event", "transport"):
        assert required in se, f"a sealed SE must carry {required}"


def test_the_sealed_se_passes_evidence_lint():
    """Schema-valid is not the same as lint-valid, and the finding asks for
    both."""
    el = _load("evidence_lint", "evidence_lint.py")
    art = _submit(_meta(), principal=RDP_A)
    rules = [r for r, _ in el.lint(art)]
    assert not rules, rules


def test_ds_accepted_at_is_NOT_smuggled_into_the_evidence():
    """R4-05 point 6. It was an UNDECLARED field on a purported evidence
    object; standardising it needs a version bump and a defined meaning, and it
    has neither. The acceptance instant stays in the DS record."""
    art = _submit(_meta(), principal=RDP_A)
    assert "ds_accepted_at" not in _projection(art)
    record = mock._DS_LEDGER[(RDP_A, _meta()["message_id"])]
    assert record["accepted_at"]


# ---------------------------------------------------------------------------
# The namespace (R4-U3)
# ---------------------------------------------------------------------------

def test_the_same_message_id_from_two_RDPs_does_not_collide():
    """The normative handle is (issuing-RDP, message_id); idempotency keyed by
    bare message_id put two providers in one namespace, so the same ULID from
    different providers collided."""
    a = mock.ds_accept_message("01HZ4NS0000000000000000A", SE["mls_group_id"],
                               base64.b64encode(BYTES_A).decode(), principal=RDP_A)
    b = mock.ds_accept_message("01HZ4NS0000000000000000A", SE["mls_group_id"],
                               base64.b64encode(BYTES_B).decode(), principal=RDP_B)
    assert a["issuing_rdp_id"] == RDP_A and b["issuing_rdp_id"] == RDP_B
    assert a["envelope_hash"] != b["envelope_hash"], "different bytes, both accepted"


def test_conflicting_bytes_from_the_SAME_rdp_still_collide():
    mid = "01HZ4NS0000000000000000B"
    mock.ds_accept_message(mid, SE["mls_group_id"],
                           base64.b64encode(BYTES_A).decode(), principal=RDP_A)
    with pytest.raises(mock.TransportRejected) as exc:
        mock.ds_accept_message(mid, SE["mls_group_id"],
                               base64.b64encode(BYTES_B).decode(), principal=RDP_A)
    assert exc.value.reason == "duplicate-message-id"


def test_an_unauthenticated_submission_has_no_namespace():
    with pytest.raises(mock.TransportRejected) as exc:
        mock.ds_accept_message("01HZ4NS0000000000000000C", SE["mls_group_id"],
                               base64.b64encode(BYTES_A).decode(), principal=None)
    assert exc.value.reason == "unauthenticated"


def test_principal_substitution_does_not_reach_another_rdps_binding():
    """R4-05: 'principal substitution and an AcceptanceRecord from another RDP
    fail.' One provider must not see, replay or displace another's."""
    mid = "01HZ4NS0000000000000000D"
    _submit(_meta(message_id=mid), principal=RDP_A)
    assert (RDP_A, mid) in mock._SE_LEDGER
    assert (RDP_B, mid) not in mock._SE_LEDGER
    # B submitting the same id with different bytes gets its OWN binding,
    # and A's is untouched.
    a_before = dict(mock._DS_LEDGER[(RDP_A, mid)])
    _submit(_meta(message_id=mid, octets=BYTES_B), principal=RDP_B)
    assert mock._DS_LEDGER[(RDP_A, mid)] == a_before


def test_the_record_echoes_the_principal_not_a_client_field():
    """R4-U3: a client-supplied issuing_rdp_id would have to be checked against
    the principal anyway, so it adds a spoofing surface without information."""
    record = mock.ds_accept_message("01HZ4NS0000000000000000E", SE["mls_group_id"],
                                    base64.b64encode(BYTES_A).decode(),
                                    principal=RDP_A)
    assert record["issuing_rdp_id"] == RDP_A
    body = DS["paths"]["/messages"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert "issuing_rdp_id" not in body.get("properties", {}), \
        "the issuing identity must come from authentication, not the request"


# ---------------------------------------------------------------------------
# The trust scope is narrowed, not implied (R4-U2)
# ---------------------------------------------------------------------------

def test_the_acceptance_record_claims_only_what_it_can_support():
    record = DS["components"]["schemas"]["AcceptanceRecord"]
    flat = " ".join(record["description"].replace("**", "").split())
    assert "LIVE TRANSACTION EVIDENCE ONLY" in flat
    assert "a later verifier CANNOT correlate it" in flat
    assert "requires an AUTHENTICATED CHANNEL" in flat
    assert "issuing_rdp_id" in record["required"]


def test_what_a_later_verifier_correlates_is_the_sealed_se():
    """The claim that replaced the withdrawn one, and it holds: the SE's
    commitment is over the same octets the DS accepted."""
    art = _submit(_meta(), principal=RDP_A)
    record = mock._DS_LEDGER[(RDP_A, _meta()["message_id"])]
    assert _projection(art)["envelope_hash"] == record["envelope_hash"]
