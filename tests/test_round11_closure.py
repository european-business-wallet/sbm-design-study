# SPDX-License-Identifier: MIT
"""Round 11 — the closure fixture the review asked for.

"For the next closure pass, require an end-to-end fixture with two entities on
one DS, repeated local IDs, multiple members, quorum:2, more than one
invitation, different S2/S3/S4 times, and a retained older registry. Also
include a second originating provider using the same local message ID.
Isolated happy-path tests with globally distinct labels and one confirmation
cannot cover these boundaries."

One world, built only through public operations, in which every collision the
identifier scopes permit happens at once:

  FR  member F1N2C3D4P  device dev-01
  FR  member F2X3Y4Z55  device dev-01      the same label, the same entity
  DE  member F1N2C3D4P  device dev-01      the same MID and label, another entity

  FR/F2X3Y4Z55/dev-01 is invited TWICE; it acknowledges the newer and refuses
  the older.

  Two originating providers each submit message 01HZR11CLOSURE00000000001
  into the group. Provider 1's quorum completes AFTER expiry, provider 2's
  before it; S2, S3, S4, the deadline and the seal are five distinct instants.
"""
import base64
import copy
import json
import pathlib
import sys

import prejoin
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_wire as w  # noqa: E402
import test_current_claims as tc  # noqa: E402
import test_group_params_semantics as g  # noqa: E402

FR, DE = "EU-FR-PSBID-ZYWVTSRQPNM8M4", "EU-DE-EOID-7K3D9W0Q2M5FW0"
A_FR, B_FR, A_DE = (FR, "F1N2C3D4P", "dev-01"), (FR, "F2X3Y4Z55", "dev-01"), (DE, "F1N2C3D4P", "dev-01")
DEVICES = [A_FR, B_FR, A_DE]
GROUP = tc._record()["mls_group_id"]
MSG = "01HZR11CLOSURE00000000001"
P1, P2 = "urn:sbm:rdp:mockeu-001", "urn:sbm:rdp:mockeu-003"
OCTETS = {P1: b"provider one's ciphertext", P2: b"provider two's ciphertext"}
S2, EXPIRY, SEALED = "2026-04-04T10:16:00Z", "2026-04-04T10:20:00Z", "2026-04-04T10:30:00Z"
CONFIRMED = {P1: ("2026-04-04T10:18:00Z", "2026-04-04T10:25:00Z"),     # completes late
             P2: ("2026-04-04T10:17:00Z", "2026-04-04T10:19:00Z")}     # completes in time
CREATOR = {"kind": "member", "uid": DE, "mid": "F1N2C3D4P"}

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
MEMBERS = [_ld("sample-BW-MEMBER-fr.json"), _ld("sample-BW-MEMBER-fr2.json")]
ORG, S3 = _ld("sample-BW-ORG.json"), _ld("sample-DE.json")["s3_attestation"]


def _dev(p, **extra):
    return {"kind": "device", "uid": p[0], "mid": p[1], "device_id": p[2],
            "session": (p[0][3] + p[1][1]) * 32, **extra}


def _session(p):
    return {"kind": "token-digest", "digest": _dev(p)["session"]}


def _invite(m, uid, targets, key, inv_prefix):
    res = m.reserve_keypackages(uid, credential=CREATOR, cipher_suite=tc.SUITE,
                                targets=[{"mid": t[1], "device_id": t[2]} for t in targets],
                                idempotency_key=key)
    m.commit_reservation(res["reservation_id"], credential=CREATOR)
    refs = {}
    for n, pkg in enumerate(res["keypackages"]):
        p = (uid, pkg["mid"], pkg["device_id"])
        refs[p] = pkg["keypackage_ref"]
        m.deposit_welcome(tc._record(
            invitation_id=f"{inv_prefix}-{n}", recipient_device=pkg["device_id"],
            reservation_id=res["reservation_id"], keypackage_ref=pkg["keypackage_ref"],
            group_info_commitment=w.group_info_commitment(b"a demo GroupInfo",
                                                          cipher_suite=tc.SUITE)),
            credential=CREATOR)
    return refs


def _se(provider):
    se = copy.deepcopy(_ld("sample-SE.json"))
    se.update(rdp_id=provider, message_id=MSG, expires_at=EXPIRY)
    return se


@pytest.fixture(scope="module")
def world():
    m = tc._load("mock_rdp", "mock_rdp.py")
    first = _invite(m, FR, [A_FR, B_FR], "closure-fr-000000001", "inv-fr")
    _invite(m, DE, [A_DE], "closure-de-000000001", "inv-de")
    second = _invite(m, FR, [B_FR], "closure-fr-000000002", "inv-fr-again")
    # every device joins; B_FR acknowledges the NEWER invitation, refuses the older
    for p in DEVICES:
        for item in m.collect_welcomes(credential=_dev(p))["welcomes"]:
            older = p == B_FR and item["welcome_id"] != \
                m.collect_welcomes(credential=_dev(p))["welcomes"][-1]["welcome_id"]
            if older:
                prejoin.refuse(m, item["welcome_id"],
                                 credential=_dev(p, keypackage_ref=first[p]),
                                 reason="group-info-mismatch", offered_suite=tc.SUITE)
            else:
                m.ack_welcome(item["welcome_id"], credential=_dev(p))
    # The DEMO pool derives a package from (entity, member, device, suite), so
    # re-reserving a device yields the same reference — the stand-in the
    # review declared out of scope ("a new reservation ID alone does not prove
    # real fresh single-use KeyPackage material"). What this world needs is two
    # INVITATIONS, and it has them: distinct invitation and Welcome ids.
    assert set(second) == {B_FR}
    for provider in (P1, P2):
        m.ds_accept_message(MSG, GROUP, base64.b64encode(OCTETS[provider]).decode(),
                            principal=provider)
    receipts = {}
    for p in DEVICES:
        for item in m.collect_messages(credential=_dev(p), session_binding=_session(p))["items"]:
            prov = item["issuing_rdp_id"]
            receipts[(prov, p)] = m.receipt_ack(
                message_id=MSG, issuing_rdp_id=prov, device_id=p[2], credential=_dev(p),
                session_binding=_session(p), octets=OCTETS[prov], server_clock=S2,
                collection_token=item["collection_token"])
    for provider in (P1, P2):
        se = _se(provider)
        for (mid, device), at in zip(((A_FR[1], "dev-01"), (B_FR[1], "dev-01")),
                                     CONFIRMED[provider]):
            conf = dict(copy.deepcopy(S3), mid=mid, device_id=device, verified_at=at,
                        message_id=MSG)
            m.deliver_confirmation(
                {"issuing_rdp_id": provider, "message_id": MSG,
                 "confirmation_kind": "s3", "confirmation": conf},
                credential=_dev((FR, mid, device)), se=se,
                rdp_id="urn:sbm:rdp:mockeu-002", observed_at=at,
                members=MEMBERS, org=ORG)
    return m, receipts


# ---------------------------------------------------------------------------

def test_every_device_has_exactly_its_own_items(world):
    m, _ = world
    owners = sorted(k[2:] for k in m._DELIVERY_ITEMS if k[1] == MSG)
    assert owners == sorted(DEVICES * 2), "one item per (provider, device principal)"


def test_each_entitys_event_names_the_principal_that_acknowledged_first(world):
    """One legal event per (provider, message, recipient ENTITY): FR's is its
    first acknowledging device's, DE's is DE's own — never the other entity's,
    though they share the MID and the label. FR's second device gets FR's
    event back (R10-09), and its own transport item still terminates."""
    m, receipts = world
    assert len(receipts) == 6
    for provider in (P1, P2):
        for p in (A_FR, A_DE):
            r = receipts[(provider, p)]
            assert (r["issuing_rdp_id"], r["recipient_uid"], r["mid"], r["device_id"]) == \
                (provider, *p)
        assert receipts[(provider, B_FR)] == receipts[(provider, A_FR)]
        assert m._DELIVERY_ITEMS[(provider, MSG, *B_FR)]["state"] == "acknowledged"


def test_the_twice_invited_device_is_routed_by_the_invitation_it_joined(world):
    m, _ = world
    assert B_FR in m.group_roster(GROUP, at="2026-04-04T10:15:01Z")


def test_the_same_message_id_from_two_providers_is_two_messages(world):
    m, _ = world
    one, two = m.confirmation_state(P1, MSG), m.confirmation_state(P2, MSG)
    assert one["counted"] == two["counted"] == [A_FR[1], B_FR[1]]
    assert (one["at"], two["at"]) == (CONFIRMED[P1][1], CONFIRMED[P2][1])


@pytest.mark.parametrize("provider,grade,outcome", [
    (P1, "availability", "delivered"),     # S2 10:16 < 10:20
    (P1, "acceptance", "expired"),         # S4 10:25 > 10:20 — S2 cannot rescue it
    (P2, "acceptance", "delivered"),       # S4 10:19 < 10:20
])
def test_each_grade_is_dated_by_its_own_event(world, provider, grade, outcome):
    m, _ = world
    got = m.delivery_decision(_se(provider), grade, s2_at=S2,
                              state=m.confirmation_state(provider, MSG))
    assert got["outcome"] == outcome


def test_the_sealing_instant_is_not_the_event(world):
    """Provider 2's DE, sealed at 10:30 — after the deadline — dated 10:19."""
    import bundle_lint as bl
    import importlib.util
    spec = importlib.util.spec_from_file_location("ev_cl", ROOT / "scripts" / "evidence_lint.py")
    ev = importlib.util.module_from_spec(spec); spec.loader.exec_module(ev)
    de = copy.deepcopy(_ld("sample-DE.json"))
    de.update(message_id=MSG, delivered_at=CONFIRMED[P2][1])
    de["s3_attestation"] = dict(de["s3_attestation"], verified_at=CONFIRMED[P2][0],
                                message_id=MSG)
    de["quorum"] = [dict(q, ack_at=at, message_id=MSG)
                    for q, at in zip(de["quorum"], CONFIRMED[P2])]
    import lint_cli as lc
    assert lc.instant(SEALED) > lc.instant(EXPIRY)
    v = ev.Violations(); ev.lint_de(v, de)
    found = {r for r, _ in v.items} | {r for r, _ in bl.check_bundle(FR, {}, {}, [], [_se(P2), de])}
    assert not found & {"LINT-DE-21", "LINT-BND-22"}


def test_the_group_verifies_under_its_retained_older_registry(world):
    """The demo group was formed under registry revision 1; today's is 2."""
    rev1 = json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())
    rev2 = json.loads((ROOT / "registries" / "cipher-suites.json").read_text())
    gc = g._context()
    se = g._se_committing_to(gc)

    def found(reg):
        out = g.bl.check_bundle(se["recipient_uid"], {}, {}, g._members(), [se],
                                group_contexts={(g.GROUP, g.EPOCH): gc},
                                suite_registry=reg)
        return {r for r, msg in out if r == "LINT-BND-40"
                or (r == "LINT-BND-I5" and "pins registry revision" in msg)}
    assert found(rev1) == set()
    assert found(rev2) == {"LINT-BND-I5"}, "judged against today's registry"
