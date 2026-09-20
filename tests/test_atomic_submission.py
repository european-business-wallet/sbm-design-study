# SPDX-License-Identifier: MIT
"""DR-02 — RDP(out) attests only what it actually received.

Former defect (round-2 review, Blocker): `POST /submissions` carried a
wallet-CLAIMED `envelope_hash`/`mls_state` and NO bytes, while the octets
reached the Delivery Service by a separate `POST /messages` with no
normative binding to the submission. RDP(out) could only copy a sender
assertion into SE — contrary to the normative claim that it independently
attests the bytes accepted for transport — and a different message could be
delivered under the same metadata. The relay path was already correct (it
carries both the sealed SE and the bytes), which is what made the
sender-side gap visible.

Decision R2-M2: ATOMIC SUBMISSION. The exact MLSMessage octets travel with
the submission; RDP(out) computes the commitment from them and hashes the
RETAINED GroupContext for `mls_state`. Its attestation is then true by
construction.

The four acceptance tests are the review's own. They use only fields the
PUBLISHED contract defines — asserted below — and the final commitment is
recomputed by an independent verifier that does not import `mls_wire`.
"""
import base64
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))



# R5-01: intake now recomputes the acceptance policy against the recipient's
# published BW-ORG and verifies the D4 confirmation against the sender device's
# published key, so a submission arrives WITH that material or is refused. A
# thin wrapper keeps every existing case reading as it did.
_R5_ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
_R5_MEMBERS = [json.loads(
    (ROOT / "samples" / "sample-BW-MEMBER.json").read_text())["projection"]]


def _accept(meta, *a, **kw):
    kw.setdefault("org", _R5_ORG)
    kw.setdefault("members", _R5_MEMBERS)
    return mock.accept_submission(meta, *a, **kw)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")
CONTRACT = yaml.safe_load((ROOT / "wallet-rdp-openapi.yaml").read_text())
SUBMISSION_SCHEMA = CONTRACT["components"]["schemas"]["SubmissionMetadata"]
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]

BYTES_A = b"\x00\x01" + b"the exact octets handed to transport" * 3
BYTES_B = b"\x00\x01" + b"DIFFERENT octets delivered instead!!" * 3


def _submission(message_id="01HZ3ATOMIC0000000000000A", octets=BYTES_A, **over):
    """A submission built ONLY from fields the published contract defines."""
    # DR-07 completed this list: sender_uid, sent_at, auth_context and
    # acceptance_policy_ref are normative submission inputs the contract did
    # not declare, so a conformant submission could not previously be built
    # from it at all.
    meta = {
        "message_id": message_id,
        "sender_uid": SE["sender_uid"],
        # R3-01: explicit addressing is REQUIRED at intake and inside the
        # signed tuple, so a conformant submission cannot be built without it.
        "sender_addr": SE["sender_addr"],
        "recipient_uid": SE["recipient_uid"],
        "recipient_addr": SE["recipient_addr"],
        "scope_ref": SE["scope_ref"],
        "payload_hash": SE["payload_hash"],
        "mls_message_b64": base64.b64encode(octets).decode(),
        "mls_group_id": SE["mls_group_id"],
        "mls_epoch": SE["mls_epoch"],
        "auth_method": SE["auth_method"],
        "auth_context": SE["auth_context"],
        "sent_at": SE["sent_at"],
        "expires_at": SE["expires_at"],
        "origin_proof": SE["origin_proof"],
        "acceptance_policy_ref": SE["acceptance_policy_ref"],
    }
    meta.update(over)
    # R5-01: origin_proof 'sender-signed' REQUIRES the D4 confirmation — the SE
    # schema says so with an if/then, and intake now enforces it too. These
    # fixtures declared the posture and omitted the proof, and were accepted,
    # because nothing at intake had the material to check. A real wallet signs
    # the tuple it is actually sending, so the fixture does the same.
    if meta.get("origin_proof") == "sender-signed" and \
            "sender_confirmation" not in meta:
        import base64 as _b64
        import copy as _copy
        import mls_wire as _w
        from lint_cli import D4_COPIED_FIELDS
        # The two commitments are DERIVED from these octets, not borrowed from
        # another message: intake compares them with what RDP(out) computes, so
        # a tuple describing different bytes is exactly what must fail.
        _derived = {}
        try:
            _oct = _b64.b64decode(meta.get("mls_message_b64") or "", validate=True)
            _derived["envelope_hash"] = _w.envelope_hash(_oct)
            _derived["mls_state"] = _w.mls_state_hash(_w.demo_group_context(
                meta["mls_group_id"], meta["mls_epoch"],
                scope_id=(meta.get("scope_ref") or {}).get("scope_id", "default"),
                scope_version=(meta.get("scope_ref") or {}).get("version", "1")))
        except Exception:
            pass                       # a malformed-octets case: leave as given
        sc = _copy.deepcopy(SE["sender_confirmation"])
        for field in D4_COPIED_FIELDS:
            if field in _derived:
                sc[field] = _derived[field]
            elif field in meta:
                sc[field] = meta[field]
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
        meta["sender_confirmation"] = sc
    return meta


def setup_function():
    mock._SUBMISSION_LEDGER.clear()


# ---------------------------------------------------------------------------
# The review's four acceptance tests
# ---------------------------------------------------------------------------

def test_metadata_hash_A_with_transport_bytes_B_is_rejected_before_sealing():
    """The defect verbatim: a claimed digest that does not describe the
    submitted octets. Nothing may be sealed."""
    import mls_wire as w                      # to BUILD the mismatch only
    meta = _submission(octets=BYTES_B, envelope_hash=w.envelope_hash(BYTES_A))
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta)
    assert exc.value.reason == "envelope-hash-mismatch"
    assert mock._SUBMISSION_LEDGER == {}, "a rejected submission left state behind"


def test_replaying_a_message_id_with_different_bytes_is_rejected():
    mid = "01HZ3ATOMIC0000000000000B"
    _accept(_submission(message_id=mid, octets=BYTES_A))
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(_submission(message_id=mid, octets=BYTES_B))
    assert exc.value.reason == "duplicate-message-id"
    # ...and the same bytes remain idempotent, not a second delivery
    again = _accept(_submission(message_id=mid, octets=BYTES_A))
    assert again["envelope_hash"]["hex"] == hashlib.sha256(BYTES_A).hexdigest()


def test_the_flow_uses_only_fields_the_published_contract_defines():
    """'over the published APIs only, with no private callback'."""
    meta = _submission()
    declared = set(SUBMISSION_SCHEMA["properties"])
    assert set(meta) <= declared, set(meta) - declared
    assert set(SUBMISSION_SCHEMA["required"]) <= set(meta)
    assert "mls_message_b64" in SUBMISSION_SCHEMA["required"], \
        "the octets must be REQUIRED by the contract, not optional"


def test_the_commitment_is_recomputed_by_an_independent_verifier():
    """No `mls_wire` here: SHA-256 over the captured transport bytes, per the
    I-D definition of the transmitted-octet commitment."""
    accepted = _accept(_submission(octets=BYTES_A))
    assert accepted["envelope_hash"] == {
        "format": "mls10-message",
        "hex": hashlib.sha256(BYTES_A).hexdigest(),
    }


# ---------------------------------------------------------------------------
# The mls_state half of R2-M2
# ---------------------------------------------------------------------------

def test_mls_state_comes_from_the_retained_group_context_not_the_sender():
    """The sub-decision whose absence produced DR-02: RDP(out) hashes the
    RETAINED context. A sender-claimed state that disagrees is rejected."""
    accepted = _accept(_submission())
    assert accepted["mls_state"]["format"] == "mls10-group-context"
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(_submission(
            message_id="01HZ3ATOMIC0000000000000C",
            mls_state={"format": "mls10-group-context", "hex": "f" * 64}))
    assert exc.value.reason == "mls-group-invalid"


def test_a_submission_without_the_octets_is_rejected():
    """R7-01 changed WHICH layer answers first, and that is the right order:
    an omitted contract-required field is a malformed REQUEST, answered by the
    published request Schema, before any semantic rule runs."""
    meta = _submission()
    meta.pop("mls_message_b64")
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta)
    assert exc.value.reason == "submission-incomplete"
    assert "mls_message_b64" in exc.value.detail


def test_octets_present_but_empty_still_hit_the_DR_02_rule():
    """And the semantic rule is still there for what it was always for: a
    field the contract sees as present, carrying nothing RDP(out) can attest.
    Keeping this proves the contract check did not SUPERSEDE the semantic one,
    only precede it."""
    meta = _submission()
    meta["mls_message_b64"] = ""
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta)
    assert "has not seen" in exc.value.detail


def test_the_typed_reason_is_registered_with_its_stage_and_event():
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    row = reg["nde_reasons"]["envelope-hash-mismatch"]
    assert row["stages"] == {"intake": "A.2-SubmissionRejection"}
    assert "no-equivalent" in row["en_319_522"]
