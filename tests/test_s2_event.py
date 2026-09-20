# SPDX-License-Identifier: MIT
"""F-09 — one exact S2 event: the acknowledged handover.

Former defect: S2 was described both as "a leaf retrieved the message" and
as the message being "made available to, or retrieved by" an authenticated
endpoint — two distinct events with different evidence and legal-effect
implications, and no protocol proof, replay or duplicate rule for either.

Chosen semantics (approved): S2 = the ACKNOWLEDGED HANDOVER — the message
bytes TRANSFERRED to an enrolled leaf within an authenticated session AND
the session transport's receipt acknowledgement received. The DS receipt
ack (message_id, device_id, session, ack instant) is the retained protocol
proof; delivered_at = the ack instant; a session whose queue merely holds
the message is NOT S2 (explicitly not the selected semantics); the first
ack is the event, later acks are idempotent, an ack replayed outside its
session is invalid. The availability DE OBJECT is unchanged — the event
DEFINITION is sharpened, no wire change.
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


dl = _load("doc_lint", "doc_lint.py")
IDD = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
TS = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
IFLAT = " ".join(IDD.split()).replace("*", "").replace("`", "")
TFLAT = " ".join(TS.split()).replace("*", "").replace("`", "")


def test_negative_the_dual_phrasing_is_gone_and_forbidden():
    for doc in (IDD, TS):
        assert "made available to, or retrieved by" not in doc
    assert any(p.search("made available to, or retrieved by")
               for p in dl.FORBIDDEN)


def test_exactly_one_transition_definition():
    """The acceptance: one exact transition into S2, in both owners."""
    assert "S2 — acknowledged handover to the recipient device" in IDD
    assert "ONE exact event — the acknowledged handover" in IFLAT
    assert "acknowledged handover (the I-D delivery-state model)" in TFLAT


def test_a_session_without_transfer_cannot_create_a_de():
    """The acceptance's second half, explicitly."""
    assert "merely HOLDS the message is NOT S2" in IFLAT
    assert "MUST NOT yield a DE" in IFLAT
    assert "explicitly not the selected semantics" in IFLAT
    assert "merely holds the message shall NOT be treated as delivery" in TFLAT


def test_the_ack_is_the_retained_protocol_proof():
    for flat in (IFLAT, TFLAT):
        assert "receipt acknowledgement" in flat
        # DR-10: the proof is no longer a four-tuple with a client-chosen
        # instant — it is a SIGNED receipt whose time the DS observed.
        assert "message_digest" in flat and "server_time" in flat
        for revived in ("delivered_at is the ACK INSTANT",
                        "delivered_at shall be the ack instant",
                        "(message_id, device_id, session, ack instant)"):
            assert revived.lower() not in flat.lower(), \
                f"the client-chosen event instant is back: {revived!r}"
    assert "MUST be retained for the evidence-retention" in IFLAT
    # DR-10: the I-D names the receipt's server-observed instant — and R11-04:
    # as the delivery instant at the AVAILABILITY grade only. This asserted
    # the unconditional sentence, which was the contradiction round 11 found.
    assert "It is delivered_at at the availability grade only" in IFLAT
    assert "delivered_at is the receipt's server_time" not in IFLAT
    assert "The event instant is SERVER-OBSERVED" in IFLAT


def test_duplicates_are_idempotent_and_replay_is_session_bound():
    assert "FIRST acknowledged handover per (message_id, recipient entity) is THE event" in IFLAT
    assert "MUST NOT yield a second DE" in IFLAT
    assert "replayed outside its session is invalid" in IFLAT


def test_the_availability_de_object_is_unchanged():
    """No wire change: the shipped availability DE still validates."""
    de = json.load(open(ROOT / "samples" / "sample-DE-availability.json"))["projection"]
    assert de["delivery_grade"] == "availability"
    assert not lc.validate_body(copy.deepcopy(de))
