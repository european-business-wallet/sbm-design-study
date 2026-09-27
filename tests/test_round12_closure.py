# SPDX-License-Identifier: MIT
"""Round 12 — the closure fixture the review asked for, verbatim:

"two genuinely separate DS stores, two originating RDPs sharing a local
message ID, one recipient RDP, a normal MLS creator without a self-Welcome, a
reply on that group, and all four confirmation kinds. Include two entities
with equal member/device labels but different suite floors, plus a later
capability change and retained formation history. Reuse one committed package
in a negative branch and repeat client invitation handles across independent
creators. Require evidence that invalid inputs are rejected at consumption,
not merely that a retained linter can reject an output later. A successful
composition test should not obtain missing inputs through private ledger
mutation, self-invitations absent from the protocol, or an unstated provider
credential substitution."

The world, built only through published operations:

  DS_A   the originating side's Delivery Service — its own store
  DS_B   the recipient side's Delivery Service, co-located with RDP(in)
         (mockeu-002) — another store; it accepts forwarding from RDP(in)

  DE  F1N2C3D4P/dev-01   the creator; floor P-384; routed as FOUNDER, no Welcome
  FR  F1N2C3D4P/dev-01   member A; the same MID and label; floor P-256
  FR  F2X3Y4Z55/dev-01   member B; no raise          (procurement: quorum:2)

  O1 (mockeu-001) and O2 (mockeu-003) each send local id MSG — different
  ciphertext — accepted at DS_A, relayed with their SEs to RDP(in), forwarded
  into DS_B with the origin proven. O1 also sends MSG2. FR's A replies.

  O1/MSG   s3 (A, session) + s3 (B, wallet-signed)  → satisfied
  O2/MSG   refusal (A) → refused, the member's RE; then a reveal → unchanged
  O1/MSG2  mismatch (B) → terminal, the NDE's proof

Where the fixture reads the reference's state, it reads — it never writes.
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys

import prejoin
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_suite as ms  # noqa: E402
import mls_wire as w  # noqa: E402
import test_current_claims as tc  # noqa: E402
import test_group_params_semantics as g  # noqa: E402

FR, DE = "EU-FR-PSBID-ZYWVTSRQPNM8M4", "EU-DE-EOID-7K3D9W0Q2M5FW0"
LABEL = ("F1N2C3D4P", "dev-01")
CREATOR_DEV, A_DEV, B_DEV = (DE, *LABEL), (FR, *LABEL), (FR, "F2X3Y4Z55", "dev-01")
A, B = A_DEV[1], B_DEV[1]
CREATOR = {"kind": "member", "uid": DE, "mid": LABEL[0]}
FR_CREATOR = {"kind": "member", "uid": FR, "mid": "G7H8J9K0Q"}   # an independent creator
O1, O2, R_IN = "urn:sbm:rdp:mockeu-001", "urn:sbm:rdp:mockeu-003", "urn:sbm:rdp:mockeu-002"
GROUP, OTHER_GROUP, FR_GROUP, FLOOR_GROUP = (
    "R12ClosureGroupR12CloA", "R12OtherGroupR12OtherA", "R12FrenchGroupR12FrenA",
    "R12FloorGroupR12FlooA")
EPOCH = "3"
MSG, MSG2, REPLY = ("01HZR12CLOSURE00000000001", "01HZR12CLOSURE00000000002",
                    "01HZR12CLOSUREREPLY000001")
OCTETS = {(O1, MSG): b"O1's ciphertext", (O2, MSG): b"O2's ciphertext",
          (O1, MSG2): b"O1's second ciphertext", (R_IN, REPLY): b"A's reply"}
S2 = "2026-04-04T10:16:00Z"
FORMED, LATER = "2026-04-01T09:00:00Z", "2026-09-01T09:00:00Z"
BASE, P256, P384 = (ms.BASELINE, "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
                    "MLS_256_DHKEMP384_AES256GCM_SHA384_P384")
CODE = {name: value for value, name in w.IANA_CODE_POINTS.items()}
REV1 = json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
ORG, S3 = _ld("sample-BW-ORG.json"), _ld("sample-DE.json")["s3_attestation"]
PROOF = _ld("sample-NDE-mismatch.json")["recipient_confirmation"]
REFUSAL = _ld("sample-RE.json")["refusal_confirmation"]
REVEAL = _ld("sample-GCM.json")["reveal_confirmation"]
AUTH = {"method": "wallet-eid-high", "loa": "high"}
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


def _member(sample, *, uid=None, mid=None, floor=None):
    """A published BW-MEMBER with one addressable device publishing the three
    classical suites, and the floor it raises to, if any."""
    doc = copy.deepcopy(_ld(sample))
    doc.update({k: v for k, v in (("uid", uid), ("mid", mid)) if v})
    dev = copy.deepcopy(doc["devices"][0])
    dev.update(device_id="dev-01", cipher_suites=[BASE, P256, P384])
    dev.pop("min_cipher_suite", None)
    if floor:
        dev["min_cipher_suite"] = floor
    doc["devices"] = [dev]
    return doc


FR_A = _member("sample-BW-MEMBER-fr.json", floor=P256)
FR_B = _member("sample-BW-MEMBER-fr2.json")
DE_C = _member("sample-BW-MEMBER.json", mid=LABEL[0], floor=P384)
FR_MEMBERS = [FR_A, FR_B]


def _dev(p, **extra):
    return {"kind": "device", "uid": p[0], "mid": p[1], "device_id": p[2],
            "session": (p[0][3] + p[1][1]) * 32, **extra}


def _session(p):
    return {"kind": "token-digest", "digest": _dev(p)["session"]}


# --- the suite decision, from its formation --------------------------------

def _formation(members):
    return w.formation_inputs(members, {
        (m["uid"], m["mid"], d["device_id"]): d["cipher_suites"]
        for m in members for d in ms.addressable_devices(m)})


FORMATION = _formation([DE_C, FR_A, FR_B])
SUITE = ms.select_suite_for_devices(
    FORMATION["members"],
    {(e["uid"], e["mid"], e["device_id"]): e["suites"] for e in FORMATION["package_suites"]},
    preference=REV1["preference_vector"]["order"])
PARAMS = w.demo_group_params(
    inputs=FORMATION, formed_at=FORMED, selected_suite=SUITE,
    device_raises=sorted([(*CREATOR_DEV, P384), (*A_DEV, P256)]))
PARAMS["effective_floor"] = P384
CONTEXT = w.demo_group_context(
    GROUP, EPOCH, cipher_suite=CODE[SUITE],
    extensions=w.sm_mls_extensions("default", "1", group_params=PARAMS))


def _se(m, origin, message_id, **over):
    """The origin's genuinely sealed SE for its octets, committing to the
    group's retained context."""
    octets = OCTETS[(origin, message_id)]
    se = copy.deepcopy(_ld("sample-SE.json"))
    se.update({"rdp_id": origin, "message_id": message_id, "mls_group_id": GROUP,
               "mls_epoch": EPOCH, "mls_state": w.mls_state_hash(CONTEXT),
               "envelope_hash": {"format": "mls10-message",
                                 "hex": hashlib.sha256(octets).hexdigest()},
               "payload_hash": dict(se["payload_hash"], hex=hashlib.sha256(
                   b"plaintext of " + octets).hexdigest()), **over})
    se["sender_confirmation"] = m._sender_confirmation(se, *LABEL)
    return m.evidence_artifact(se, kid="rdp")


def _invite(m, creator, uid, targets, *, group, key, handles, suite):
    res = m.reserve_keypackages(uid, credential=creator, cipher_suite=suite,
                                targets=[{"mid": t[1], "device_id": t[2]} for t in targets],
                                idempotency_key=key)
    m.commit_reservation(res["reservation_id"], credential=creator)
    refs = {}
    for handle, pkg in zip(handles, res["keypackages"]):
        refs[(uid, pkg["mid"], pkg["device_id"])] = pkg["keypackage_ref"]
        m.deposit_welcome(tc._record(
            invitation_id=handle, recipient_device=pkg["device_id"], mls_group_id=group,
            reservation_id=res["reservation_id"], keypackage_ref=pkg["keypackage_ref"],
            offered_suite=suite,
            group_info_commitment=w.group_info_commitment(b"a demo GroupInfo",
                                                          cipher_suite=suite)),
            credential=creator)
    return res["reservation_id"], refs


def _collect(m, p):
    return m.collect_messages(credential=_dev(p), session_binding=_session(p))["items"]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    ds_a = tc._load("r12_closure_ds_a", "mock_rdp.py")
    ds_b = tc._load("r12_closure_ds_b", "mock_rdp.py")
    store = json.loads((ROOT / "samples" / "trust-store.demo.json").read_text())
    store["entries"]["rdp"]["identities"] = sorted({*store["entries"]["rdp"]["identities"], O2})
    path = tmp_path_factory.mktemp("r12") / "trust-store.json"
    path.write_text(json.dumps(store))
    ds_a.DS_TRUST_STORE = ds_b.DS_TRUST_STORE = path
    ds_b.DS_FORWARDERS, ds_a.DS_FORWARDERS = {R_IN}, {O1}
    out = {"ds_a": ds_a, "ds_b": ds_b, "rejected": {}}

    # Formation, at the recipient's DS: the creator invites FR's two devices
    # under the suite its decision selected, and registers ITSELF as founder.
    reservation, refs = _invite(ds_b, CREATOR, FR, [A_DEV, B_DEV], group=GROUP,
                                key="r12-closure-formation-1",
                                handles=["invitation-1", "invitation-2"], suite=SUITE)
    ds_b.register_founder(GROUP, credential=_dev(CREATOR_DEV))
    for p in (A_DEV, B_DEV):
        for item in ds_b.collect_welcomes(credential=_dev(p))["welcomes"]:
            ds_b.ack_welcome(item["welcome_id"], credential=_dev(p))
    assert ds_b.collect_welcomes(credential=_dev(CREATOR_DEV))["welcomes"] == [], \
        "no self-Welcome"

    # Negative: a committed package reused for another invitation, refused at
    # the deposit — before a queue item or a routing claim exists.
    with pytest.raises(ds_b.InvitationError) as exc:
        ds_b.deposit_welcome(tc._record(
            invitation_id="invitation-9", recipient_device="dev-01",
            mls_group_id=OTHER_GROUP, reservation_id=reservation,
            keypackage_ref=refs[A_DEV], offered_suite=SUITE,
            group_info_commitment=w.group_info_commitment(b"another GroupInfo",
                                                          cipher_suite=SUITE)),
            credential=CREATOR)
    out["rejected"]["package-reuse"] = exc.value.reason

    # An independent creator reuses the client handle `invitation-1`.
    _invite(ds_b, FR_CREATOR, FR, [B_DEV], group=FR_GROUP, key="r12-closure-fr-grp-1",
            handles=["invitation-1"], suite=BASE)

    # Transport: each origin is accepted at ITS DS, seals its SE, relays to
    # RDP(in), which forwards into DS_B with the origin proven.
    out["se"], out["accepted_a"], out["forwarded"] = {}, {}, {}
    for origin, mid_ in ((O1, MSG), (O2, MSG), (O1, MSG2)):
        octets = OCTETS[(origin, mid_)]
        out["accepted_a"][(origin, mid_)] = ds_a.ds_accept_message(
            mid_, GROUP, b64(octets), principal=origin)
        extra = {"grade_commitment": REVEAL["grade_commitment"]} if origin == O2 else {}
        se = out["se"][(origin, mid_)] = _se(ds_b, origin, mid_, **extra)
        out["forwarded"][(origin, mid_)] = ds_b.ds_accept_message(
            mid_, GROUP, b64(octets), principal=R_IN,
            origin={"origin_rdp_id": origin, "se": se})

    # Negative: an origin claim its SE does not prove, refused at the DS.
    with pytest.raises(ds_b.TransportRejected) as exc:
        ds_b.ds_accept_message(MSG, GROUP, b64(OCTETS[(O1, MSG)]), principal=R_IN,
                               origin={"origin_rdp_id": O2, "se": out["se"][(O1, MSG)]})
    out["rejected"]["origin-claim"] = exc.value.reason

    # The reply: A's own RDP is the origin, and submits to its own DS.
    out["reply"] = ds_b.ds_accept_message(REPLY, GROUP, b64(OCTETS[(R_IN, REPLY)]),
                                          principal=R_IN)
    reply_se = _se(ds_b, R_IN, REPLY)
    # ...and relays it to the creator's side, which forwards into DS_A.
    out["reply_at_a"] = ds_a.ds_accept_message(
        REPLY, GROUP, b64(OCTETS[(R_IN, REPLY)]), principal=O1,
        origin={"origin_rdp_id": R_IN, "se": reply_se})

    # S2: every routed device collects and acknowledges what DS_B holds for it.
    out["items"], out["receipts"] = {}, {}
    for p in (CREATOR_DEV, A_DEV, B_DEV):
        out["items"][p] = _collect(ds_b, p)
        for item in out["items"][p]:
            prov, mid_ = item["issuing_rdp_id"], item["message_id"]
            out["receipts"][(prov, mid_, p)] = ds_b.receipt_ack(
                message_id=mid_, issuing_rdp_id=prov, device_id=p[2],
                credential=_dev(p), session_binding=_session(p),
                octets=OCTETS[(prov, mid_)], server_clock=S2,
                collection_token=item["collection_token"])

    # Confirmations at RDP(in) — all four kinds.
    def deliver(kind, origin, mid_, conf, cred, at):
        se = out["se"][(origin, mid_)]["projection"]
        return ds_b.deliver_confirmation(
            {"issuing_rdp_id": origin, "message_id": mid_,
             "confirmation_kind": kind, "confirmation": conf},
            credential=cred, se=se, rdp_id=R_IN, observed_at=at,
            members=FR_MEMBERS, org=ORG)

    def bound(conf, origin, mid_, **extra):
        se = out["se"][(origin, mid_)]["projection"]
        conf = dict(copy.deepcopy(conf), message_id=mid_)
        conf.update({k: copy.deepcopy(se[k]) for k in (
            "payload_hash", "envelope_hash", "mls_state", "mls_group_id", "mls_epoch",
            "acceptance_policy_ref") if k in conf})
        conf.update(extra)
        return conf

    def signed(conf):
        conf = {k: v for k, v in conf.items()
                if k not in ("session_authenticated", "wallet_signature_b64",
                             "session_binding")}
        conf["device_id"] = "dev-01"
        conf["wallet_signature_b64"] = ds_b._wallet_sign(conf)
        return conf

    member = lambda mid: {"kind": "member", "uid": FR, "mid": mid}  # noqa: E731

    # Negative: an S3 for O1's message about O2's octets — refused, nothing stored.
    wrong = bound(S3, O1, MSG, mid=A, verified_at="2026-04-04T10:16:30Z",
                  envelope_hash=out["se"][(O2, MSG)]["projection"]["envelope_hash"])
    before = copy.deepcopy(ds_b._CONFIRMATION_ACTS)
    with pytest.raises(ds_b.ConfirmationRejected) as exc:
        deliver("s3", O1, MSG, wrong, member(A), "2026-04-04T10:17:00Z")
    out["rejected"]["s3-other-content"] = exc.value.reason
    assert ds_b._CONFIRMATION_ACTS == before

    out["acts"] = {
        "s3-A": deliver("s3", O1, MSG, bound(S3, O1, MSG, mid=A,
                                              verified_at="2026-04-04T10:16:30Z"),
                        member(A), "2026-04-04T10:17:00Z"),
        "s3-B": deliver("s3", O1, MSG, signed(bound(S3, O1, MSG, mid=B,
                                                     verified_at="2026-04-04T10:17:00Z")),
                        _dev(B_DEV), "2026-04-04T10:18:00Z"),
        "refusal": deliver("refusal", O2, MSG, signed(bound(REFUSAL, O2, MSG)),
                           _dev(A_DEV, **AUTH), "2026-04-04T10:21:00Z"),
        "reveal": deliver("reveal", O2, MSG, signed(dict(
            copy.deepcopy(REVEAL), message_id=MSG, recipient_uid=FR,
            envelope_hash=out["se"][(O2, MSG)]["projection"]["envelope_hash"])),
            _dev(A_DEV), "2026-04-09T10:00:00Z"),
        # the digest B RECOMPUTED — which is what makes it a mismatch
        "mismatch": deliver("mismatch", O1, MSG2, bound(PROOF, O1, MSG2, mid=B,
                                                         verified_at="2026-04-04T10:18:00Z",
                                                         payload_hash=PROOF["payload_hash"]),
                            member(B), "2026-04-04T10:19:00Z"),
    }
    return out


# ---------------------------------------------------------------------------
# Two stores, two origins, one local id
# ---------------------------------------------------------------------------

def test_the_two_stores_are_separate(world):
    ds_a, ds_b = world["ds_a"], world["ds_b"]
    assert ds_a is not ds_b and ds_a._DS_LEDGER is not ds_b._DS_LEDGER
    assert set(ds_a._DS_LEDGER) == {(O1, MSG), (O2, MSG), (O1, MSG2), (R_IN, REPLY)}
    assert set(ds_b._DS_LEDGER) == {(O1, MSG), (O2, MSG), (O1, MSG2), (R_IN, REPLY)}


def test_each_origin_arrives_once_under_its_own_handle(world):
    for origin, mid_ in ((O1, MSG), (O2, MSG), (O1, MSG2)):
        rec = world["forwarded"][(origin, mid_)]
        assert (rec["issuing_rdp_id"], rec["forwarding_rdp_id"]) == (origin, R_IN)
    for p in (A_DEV, B_DEV):
        got = sorted((i["issuing_rdp_id"], i["message_id"]) for i in world["items"][p])
        assert got == sorted([(O1, MSG), (O2, MSG), (O1, MSG2), (R_IN, REPLY)])


def test_an_origin_its_se_does_not_prove_is_refused_at_the_ds(world):
    assert world["rejected"]["origin-claim"] == "origin-unproven"


# ---------------------------------------------------------------------------
# The creator, without a self-Welcome, and the reply
# ---------------------------------------------------------------------------

def test_the_creator_is_routed_as_founder_and_receives_the_reply(world):
    ds_b = world["ds_b"]
    assert CREATOR_DEV in ds_b.group_roster(GROUP, at=S2)
    got = sorted((i["issuing_rdp_id"], i["message_id"]) for i in world["items"][CREATOR_DEV])
    assert got == sorted([(O1, MSG), (O2, MSG), (O1, MSG2), (R_IN, REPLY)]), \
        "the creator holds the reply, and a transport copy of each original"


def test_each_receipt_names_the_origin_and_its_entitys_first_acknowledgement(world):
    """One legal event per (origin, message, recipient ENTITY): the creator's
    is its own, FR's is A's — who acknowledged first — and B gets FR's event
    back (R10-09). DE's creator and FR's A share the MID and the label."""
    receipts = world["receipts"]
    assert len(receipts) == 12
    for (prov, mid_, p), r in receipts.items():
        assert (r["issuing_rdp_id"], r["message_id"]) == (prov, mid_)
        first = p if p != B_DEV else A_DEV
        assert (r["recipient_uid"], r["mid"], r["device_id"]) == first
        if p == B_DEV:
            assert r == receipts[(prov, mid_, A_DEV)]


def test_the_creators_own_ds_routes_none_of_the_group(world):
    """What the four-corner composition implies today, pinned so a change is
    seen: the group was formed at DS_B, so DS_A routes none of it — neither
    the originals it accepted for the SE, nor the reply forwarded to it. The
    creator's copies exist at DS_B only. Whether each entity should be served
    by its own DS is review agenda A10, not a finding of this fixture."""
    ds_a = world["ds_a"]
    assert world["reply_at_a"]["issuing_rdp_id"] == R_IN
    assert [k for k in ds_a._DELIVERY_ITEMS if k[1] in (MSG, MSG2, REPLY)] == []


# ---------------------------------------------------------------------------
# All four confirmation kinds, each its own result
# ---------------------------------------------------------------------------

def test_s3_from_two_members_satisfies_the_quorum(world):
    ds_b = world["ds_b"]
    st = ds_b.confirmation_state(O1, MSG)
    assert st["state"] == "satisfied" and st["counted"] == [A, B]
    assert st["at"] == "2026-04-04T10:18:00Z"
    se = world["se"][(O1, MSG)]["projection"]
    assert ds_b.delivery_decision(se, "acceptance", s2_at=S2, state=st)["outcome"] == "delivered"


def test_a_refusal_ends_the_other_origins_message_and_a_reveal_changes_nothing(world):
    ds_b = world["ds_b"]
    re = world["acts"]["refusal"]["projection"]
    assert (re["type"], re["mid"], re["message_id"], re["rdp_id"]) == ("RE-v1", A, MSG, R_IN)
    assert world["acts"]["reveal"] is None
    st = ds_b.confirmation_state(O2, MSG)
    assert st["state"] == "refused"
    se = world["se"][(O2, MSG)]["projection"]
    assert ds_b.delivery_decision(se, "acceptance", s2_at=S2, state=st)["outcome"] == "refused"


def test_one_member_acting_on_two_origins_is_two_acts(world):
    """A confirmed O1's MSG and refused O2's MSG: two messages, two ledgers."""
    ds_b = world["ds_b"]
    assert ds_b.confirmation_state(O1, MSG)["state"] == "satisfied"
    assert ds_b.confirmation_state(O2, MSG)["state"] == "refused"


def test_a_mismatch_is_terminal_and_carries_the_proof(world):
    ds_b = world["ds_b"]
    nde = world["acts"]["mismatch"]["projection"]
    assert (nde["type"], nde["reason"], nde["message_id"]) == \
        ("NDE-v1", "payload-hash-mismatch", MSG2)
    assert nde["recipient_confirmation"]["mid"] == B
    assert ds_b.confirmation_state(O1, MSG2)["state"] == "mismatch"


def test_an_s3_about_another_origins_octets_is_refused_before_anything_moves(world):
    assert world["rejected"]["s3-other-content"] == "confirmation-rejected"


# ---------------------------------------------------------------------------
# Equal labels, different floors; the decision and its formation
# ---------------------------------------------------------------------------

def test_the_group_runs_the_suite_its_formation_selects(world):
    assert SUITE == P384
    offered = [e["invitation"]["offered_suite"] for e in world["ds_b"]._INVITATIONS.values()
               if e["invitation"]["mls_group_id"] == GROUP]
    assert offered == [P384, P384]


def test_the_decision_names_both_same_labelled_devices_and_recomputes(world):
    decoded = w.group_params_from(w.parse_group_context(CONTEXT)["extensions"])
    assert {(r["uid"], r["mid"], r["device_id"], r["suite"]) for r in decoded["device_raises"]} \
        == {(*CREATOR_DEV, P384), (*A_DEV, P256)}
    assert ms.verify_group_params(decoded, cipher_suite_name=P384, formation=FORMATION,
                                  registry=REV1) == []
    assert _bundle(world, [FORMATION]) == []


def test_a_later_capability_change_does_not_rewrite_the_decision(world):
    """In September FR's A lowers its floor and drops P-384. The retained
    formation still decides; today's members cannot be substituted for it."""
    later = _member("sample-BW-MEMBER-fr.json")
    later["devices"][0]["cipher_suites"] = [BASE, P256]
    today = _formation([DE_C, later, FR_B])
    decoded = w.group_params_from(w.parse_group_context(CONTEXT)["extensions"])
    with pytest.raises(ms.UnverifiableDecision):
        ms.verify_group_params(decoded, cipher_suite_name=P384, formation=today,
                               registry=REV1)
    assert _bundle(world, [FORMATION, today]) == []
    assert {r for r, _ in _bundle(world, [today])} == {"LINT-BND-I5"}


def test_the_refusing_devices_own_floor_is_checked_at_consumption(world):
    """The DE creator offers the baseline to FR's A in another group. A may
    refuse citing ITS floor, P-256 — not its DE twin's P-384."""
    ds_b = world["ds_b"]
    _, refs = _invite(ds_b, CREATOR, FR, [A_DEV], group=FLOOR_GROUP,
                      key="r12-closure-floor-grp1", handles=["invitation-3"], suite=BASE)
    # The queue does not name the group — the device learns it from the
    # Welcome; this is the only one offering the baseline.
    [item] = [i for i in ds_b.collect_welcomes(credential=_dev(A_DEV))["welcomes"]
              if i["offered_suite"] == BASE]
    cred = _dev(A_DEV, keypackage_ref=refs[A_DEV])
    with pytest.raises(ds_b.InvitationError):
        prejoin.refuse(ds_b, item["welcome_id"], credential=cred,
                            reason="suite-below-published-floor", offered_suite=BASE,
                            required_floor=P384, members=[DE_C, FR_A, FR_B])
    prejoin.refuse(ds_b, item["welcome_id"], credential=cred,
                        reason="suite-below-published-floor", offered_suite=BASE,
                        required_floor=P256, members=[DE_C, FR_A, FR_B])
    outcomes = ds_b.collect_outcomes(credential=CREATOR)
    assert [(o["mid"], o["device_id"], o["required_floor"]) for o in outcomes
            if o["mls_group_id"] == FLOOR_GROUP] == [(A, "dev-01", P256)]


# ---------------------------------------------------------------------------
# Deposit identity
# ---------------------------------------------------------------------------

def test_a_reused_committed_package_is_refused_at_the_deposit(world):
    ds_b = world["ds_b"]
    assert world["rejected"]["package-reuse"] == "keypackage-already-deposited"
    assert ds_b.group_roster(OTHER_GROUP) == []


def test_equal_handles_from_independent_creators_do_not_interfere(world):
    ds_b = world["ds_b"]
    handles = sorted((e["creator"], e["invitation"]["invitation_id"])
                     for e in ds_b._INVITATIONS.values()
                     if e["invitation"]["invitation_id"] == "invitation-1")
    assert handles == sorted([((DE, LABEL[0]), "invitation-1"),
                              ((FR, "G7H8J9K0Q"), "invitation-1")])
    assert B_DEV in ds_b.group_roster(FR_GROUP)


# ---------------------------------------------------------------------------

def _bundle(world, formations):
    """check_bundle over O1's SE, committing to the group's retained context;
    only the suite-decision rules."""
    se = world["se"][(O1, MSG)]["projection"]
    return sorted({(r, m) for r, m in g.bl.check_bundle(
        FR, {}, {}, FR_MEMBERS, [copy.deepcopy(se)],
        group_contexts={(GROUP, EPOCH): CONTEXT}, formation_inputs=formations,
        suite_registry=REV1) if r in ("LINT-BND-40", "LINT-BND-I5")})
