# SPDX-License-Identifier: MIT
"""Round 12 / B2 — R12-03: a forwarded message keeps its origin's namespace.

The relay preserves `(origin_rdp_id, message_id)`, and the recipient-side RDP
then hands the octets to ITS Delivery Service under its own credential. The DS
derived the namespace from that credential alone: the acceptance named RDP(in)
as the issuer, so items and receipts carried the wrong handle, and a second
origin reusing the local `message_id` was refused `duplicate-message-id` at the
common DS. The round-11 closure fixture never saw it: each origin submitted
directly under its own identity.

R12-X2: a forwarded submission carries the origin and the origin's sealed SE;
the DS keys on the ORIGIN once the SE proves it. The review's acceptance: two
origins with equal local IDs traverse a common RDP(in) and a separate recipient
DS, both arrive once with the correct origin handles, and an unauthorized
origin claim is rejected.
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

import test_principals as pr  # noqa: E402

A, B = "urn:sbm:rdp:mockeu-001", "urn:sbm:rdp:mockeu-003"     # two origins
R_IN = "urn:sbm:rdp:mockeu-002"                               # one recipient-side RDP
MSG = "01HZR12FORWARDED000000001"                             # one local id, both origins
OCTETS = {A: b"origin A's ciphertext", B: b"origin B's ciphertext"}
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


def _world(tmp_path):
    """A recipient-side DS that accepts forwarding from R_IN only, trusting the
    federation's evidence key for both origins; one recipient device joined."""
    m = pr._m()
    store = json.loads((ROOT / "samples" / "trust-store.demo.json").read_text())
    store["entries"]["rdp"]["identities"] = sorted({*store["entries"]["rdp"]["identities"], B})
    path = tmp_path / "trust-store.json"; path.write_text(json.dumps(store))
    m.DS_TRUST_STORE, m.DS_FORWARDERS = path, {R_IN}
    pr._form(m, [pr.FR_DEV])
    for w in m.collect_welcomes(credential=pr._dev(pr.FR_DEV))["welcomes"]:
        m.ack_welcome(w["welcome_id"], credential=pr._dev(pr.FR_DEV))
    return m


def _se(m, origin, octets, **over):
    """The origin's genuinely sealed SE for these octets under MSG — its
    sender confirmation re-derived, so the only thing a test changes is what
    it names."""
    se = copy.deepcopy(json.loads((ROOT / "samples" / "sample-SE.json").read_text())
                       ["projection"])
    se.update({"rdp_id": origin, "message_id": MSG, "mls_group_id": pr.GROUP,
               "envelope_hash": {"format": "mls10-message",
                                 "hex": hashlib.sha256(octets).hexdigest()}, **over})
    sc = se["sender_confirmation"]
    se["sender_confirmation"] = m._sender_confirmation(se, sc["mid"], sc["device_id"])
    return m.evidence_artifact(se, kid="rdp")


def _forward(m, origin, octets, se=None, principal=R_IN):
    return m.ds_accept_message(MSG, pr.GROUP, b64(octets), principal=principal,
                               origin={"origin_rdp_id": origin,
                                       "se": se or _se(m, origin, octets)})


# ---------------------------------------------------------------------------

def test_two_origins_sharing_a_local_id_arrive_once_each_under_their_own_handle(tmp_path):
    m = _world(tmp_path)
    a, b = _forward(m, A, OCTETS[A]), _forward(m, B, OCTETS[B])
    assert (a["issuing_rdp_id"], a["forwarding_rdp_id"]) == (A, R_IN)
    assert (b["issuing_rdp_id"], b["forwarding_rdp_id"]) == (B, R_IN)
    items = pr._collect(m, pr.FR_DEV)
    assert sorted(i["issuing_rdp_id"] for i in items) == [A, B], "each origin exactly once"
    for i in items:
        r = m.receipt_ack(message_id=MSG, issuing_rdp_id=i["issuing_rdp_id"],
                          device_id=pr.FR_DEV[2], credential=pr._dev(pr.FR_DEV),
                          session_binding=pr._session(pr.FR_DEV),
                          octets=OCTETS[i["issuing_rdp_id"]],
                          server_clock="2026-04-04T10:20:00Z",
                          collection_token=i["collection_token"])
        assert r["issuing_rdp_id"] == i["issuing_rdp_id"], "the receipt names the ORIGIN"


def test_a_forwarded_retry_converges(tmp_path):
    m = _world(tmp_path)
    first = _forward(m, A, OCTETS[A])
    assert _forward(m, A, OCTETS[A]) == first
    assert len(pr._collect(m, pr.FR_DEV)) == 1


@pytest.mark.parametrize("case", [
    "claims another origin", "SE for other octets", "SE for another message",
    "SE seal tampered", "not the origin's SE at all"])
def test_an_origin_claim_the_se_does_not_prove_is_refused(tmp_path, case):
    m = _world(tmp_path)
    if case == "claims another origin":
        se, claim = _se(m, A, OCTETS[A]), B
    elif case == "SE for other octets":
        se, claim = _se(m, A, b"some other ciphertext"), A
    elif case == "SE for another message":
        se, claim = _se(m, A, OCTETS[A], message_id="01HZR12OTHERMESSAGE000001"), A
    elif case == "SE seal tampered":
        se, claim = _se(m, A, OCTETS[A]), A
        se = dict(se, projection=dict(se["projection"], sent_at="2026-04-04T10:14:59Z"))
    else:
        se, claim = json.loads((ROOT / "samples" / "sample-DE.json").read_text()), A
    with pytest.raises(m.TransportRejected) as exc:
        _forward(m, claim, OCTETS[A], se=se)
    assert exc.value.reason == "origin-unproven", exc.value
    assert m._DS_LEDGER == {} and not [k for k in m._DELIVERY_ITEMS if k[1] == MSG]


def test_only_a_forwarder_this_ds_serves_may_forward(tmp_path):
    m = _world(tmp_path)
    with pytest.raises(m.TransportRejected) as exc:
        _forward(m, A, OCTETS[A], principal="urn:sbm:rdp:mockeu-001")
    assert exc.value.reason == "forwarder-not-authorised"


def test_an_origin_without_its_proof_is_not_a_submission(tmp_path):
    m = _world(tmp_path)
    with pytest.raises(m.TransportRejected) as exc:
        m.ds_accept_message(MSG, pr.GROUP, b64(OCTETS[A]), principal=R_IN,
                            origin={"origin_rdp_id": A})
    assert exc.value.reason == "submission-malformed"


def test_a_direct_submission_is_still_its_own_origin(tmp_path):
    m = _world(tmp_path)
    rec = m.ds_accept_message(MSG, pr.GROUP, b64(OCTETS[A]), principal=A)
    assert rec["issuing_rdp_id"] == A and "forwarding_rdp_id" not in rec
    # ...and the same message forwarded later converges on it
    assert _forward(m, A, OCTETS[A])["issuing_rdp_id"] == A
