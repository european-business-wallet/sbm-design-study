# SPDX-License-Identifier: MIT
"""Round 12 / B5 — a suite decision names whole principals (R12-05), and is
recomputed from the inputs it was taken on or not at all (R12-06, R12-X4).

R12-05. `sbm_group_params` v1 named a device raise by (mid, device_id), and
the verifier keyed publications the same way. A MID is unique only within an
entity, and a group spans two: FR's and DE's `F1N2C3D4P/dev-01` were one
device to the decision layer. Both legitimate raises could not be encoded
("duplicate (mid, device_id)"), and a record carrying only the weaker one was
ACCEPTED with members ordered FR, DE and refused as stale with DE, FR — the
verdict decided by input order. Invariant 10, in the layer beside the
Delivery Service, which round 11's inventory never entered.

R12-06. Round 11 retained the registry revision a decision was taken under
and left the other input live: `verify_group_params` recomputed from whatever
members it was handed today. A correct April decision was refused once a
member later raised its floor, and a later lowering would have erased an
April violation. v2 commits `formed_at` and `inputs_digest` — the digest of
the exact members and package availability — and a verifier recomputes from
the retained formation matching that digest, or reports INCOMPLETE.
"""
import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_suite as ms  # noqa: E402
import mls_wire as w  # noqa: E402
import test_group_params_semantics as g  # noqa: E402

REV1 = json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())
BASE = ms.BASELINE
P256 = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
P384 = "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"
CODE = {name: value for value, name in w.IANA_CODE_POINTS.items()}
SEPTEMBER_GROUP = "SeptemberGroupSeptembA"


def _projection(name):
    return json.loads((ROOT / "samples" / name).read_text())["projection"]


def _twins():
    """The review's pair: FR's and DE's member `F1N2C3D4P`, each with a
    `dev-01` — equal labels, different entities, different floors (FR P-384,
    DE P-256)."""
    fr, de = _projection("sample-BW-MEMBER-fr.json"), _projection("sample-BW-MEMBER.json")
    de["mid"] = fr["mid"]
    for body, raised in ((fr, P384), (de, P256)):
        body["devices"] = [copy.deepcopy(body["devices"][0])]
        dev = body["devices"][0]
        dev["device_id"] = "dev-01"
        dev["cipher_suites"] = [BASE, P256, P384]
        dev["min_cipher_suite"] = raised
    assert fr["uid"] != de["uid"]
    return fr, de


def _formation(members, packages=None):
    return w.formation_inputs(members, packages or {
        (m["uid"], m["mid"], d["device_id"]): d.get("cipher_suites") or []
        for m in members for d in ms.addressable_devices(m)})


def _raise(member, suite):
    return (member["uid"], member["mid"], member["devices"][0]["device_id"], suite)


def _decision(formation, *, raises, floor, selected):
    params = w.demo_group_params(inputs=formation)
    params.update(device_raises=sorted(raises), effective_floor=floor,
                  selected_suite=selected)
    return params


def _on_the_wire(params, cipher_suite=None):
    """Through the real encoder and decoder, so what is verified is what a
    GroupContext actually carries."""
    gc = g._context(params, cipher_suite=cipher_suite or CODE[params["selected_suite"]])
    return gc, w.group_params_from(w.parse_group_context(gc)["extensions"])


def _verify(params, formation):
    return ms.verify_group_params(params, cipher_suite_name=params["selected_suite"],
                                  formation=formation, registry=REV1)


# ---------------------------------------------------------------------------
# R12-05 — the entity is part of the device's identity
# ---------------------------------------------------------------------------

def test_both_same_labelled_raises_are_encodable():
    """v1 could not carry both legitimate raises at all."""
    fr, de = _twins()
    both = sorted([_raise(fr, P384), _raise(de, P256)])
    with pytest.raises(ValueError, match="duplicate"):
        w.serialize_group_params(REV1["preference_vector"]["id"], REV1["floor"]["id"],
                                 "1", P384, P384, [r[1:] for r in both])
    _, decoded = _on_the_wire(_decision(_formation([fr, de]), raises=both,
                                        floor=P384, selected=P384))
    assert decoded["params_version"] == 2
    assert {(r["uid"], r["suite"]) for r in decoded["device_raises"]} == \
        {(fr["uid"], P384), (de["uid"], P256)}


@pytest.mark.parametrize("order", ["FR,DE", "DE,FR"])
def test_the_correct_decision_verifies_in_either_order(order):
    fr, de = _twins()
    members = [fr, de] if order == "FR,DE" else [de, fr]
    formation = _formation(members)
    _, decoded = _on_the_wire(_decision(
        formation, raises=[_raise(fr, P384), _raise(de, P256)],
        floor=P384, selected=P384))
    assert _verify(decoded, formation) == []


def test_the_formation_is_canonical_in_member_order():
    fr, de = _twins()
    assert w.formation_inputs_digest(_formation([fr, de])) == \
        w.formation_inputs_digest(_formation([de, fr]))


@pytest.mark.parametrize("order", ["FR,DE", "DE,FR"])
def test_the_weaker_decision_is_refused_in_both_orders(order):
    """The review's reproduction: a context recording only DE's P-256 raise.
    ACCEPTED with FR, DE and refused as 'stale' with DE, FR before B5 — now
    refused either way, and for the right reason: FR's raise is omitted."""
    fr, de = _twins()
    members = [fr, de] if order == "FR,DE" else [de, fr]
    formation = _formation(members)
    _, decoded = _on_the_wire(_decision(formation, raises=[_raise(de, P256)],
                                        floor=P256, selected=P256))
    problems = _verify(decoded, formation)
    assert any(f"omits {fr['uid']}/{fr['mid']}/dev-01" in p for p in problems), problems
    assert not any("stale" in p for p in problems), problems


def test_no_floor_overwrites_another():
    fr, de = _twins()
    assert ms.floor_for([fr, de])[0] == ms.floor_for([de, fr])[0] == P384
    formation = _formation([fr, de])
    for kept, dropped in ((fr, de), (de, fr)):
        _, decoded = _on_the_wire(_decision(
            formation, raises=[_raise(kept, kept["devices"][0]["min_cipher_suite"])],
            floor=P384, selected=P384))
        assert any(f"omits {dropped['uid']}/" in p for p in _verify(decoded, formation))


@pytest.mark.parametrize("order", ["FR,DE", "DE,FR"])
def test_selection_reads_each_entitys_own_availability(order):
    """DE's packages must not answer for FR's same-labelled device."""
    fr, de = _twins()
    members = [fr, de] if order == "FR,DE" else [de, fr]
    packages = {_raise(fr, None)[:3]: [BASE], _raise(de, None)[:3]: [BASE, P256, P384]}
    assert ms.select_suite_for_devices(members, packages, preference=REV1[
        "preference_vector"]["order"]) == BASE


# ---------------------------------------------------------------------------
# R12-06 — the decision is recomputed from the inputs it was taken on
# ---------------------------------------------------------------------------

def _april():
    """The demo groups' retained formation and decision (1 April)."""
    return w.demo_formation_inputs(), w.demo_group_params()


def _with_fr_dev01_raised(members, suite=P256):
    members = copy.deepcopy(members)
    dev = next(d for d in ms.addressable_devices(members[0]) if d["device_id"] == "dev-01")
    dev["cipher_suites"] = sorted({*dev["cipher_suites"], suite})
    dev["min_cipher_suite"] = suite
    return members


def _bundle(groups, formations, members):
    """check_bundle over one SE per group, each committing to its context;
    only the suite-decision rules are returned."""
    evidence, contexts = [], {}
    for gid, gc in groups.items():
        se = g._se_committing_to(gc)
        se["mls_group_id"] = gid
        evidence.append(se)
        contexts[(gid, g.EPOCH)] = gc
    return sorted({(r, m) for r, m in g.bl.check_bundle(
        evidence[0]["recipient_uid"], {}, {}, members, evidence,
        group_contexts=contexts, formation_inputs=formations, suite_registry=REV1)
        if r in ("LINT-BND-40", "LINT-BND-I5")})


def test_a_later_raise_does_not_invalidate_an_april_decision():
    """The review's reproduction: the April decision was refused ('omits a
    raise') once the same member was supplied with a later P-256 floor."""
    april, params = _april()
    today = _with_fr_dev01_raised(april["members"])
    assert _verify(params, april) == []
    with pytest.raises(ms.UnverifiableDecision):
        _verify(params, _formation(today))
    gc = g._context(params)
    assert _bundle({g.GROUP: gc}, [april], today) == []
    found = _bundle({g.GROUP: gc}, [_formation(today)], today)
    assert [r for r, _ in found] == ["LINT-BND-I5"], found
    assert "no retained formation matches" in found[0][1]


def test_a_later_lowering_does_not_erase_an_april_violation():
    """In April FR's dev-01 published a P-256 floor and the decision omitted
    it. The device later lowered its floor; the April violation stands."""
    april = _formation(_with_fr_dev01_raised(w.demo_formation_inputs()["members"]))
    params = w.demo_group_params(inputs=april)          # no raise: the violation
    today = copy.deepcopy(april["members"])
    for d in ms.addressable_devices(today[0]):
        d.pop("min_cipher_suite", None)
    assert any("omits" in p for p in _verify(params, april))
    found = _bundle({g.GROUP: g._context(params)}, [april], today)
    assert found and {r for r, _ in found} == {"LINT-BND-40"}, found
    assert any("omits" in m for _, m in found)


def test_formations_coexist_in_one_bundle():
    """Two groups formed at different times, each bound to its own inputs."""
    april, params_a = _april()
    members = _with_fr_dev01_raised(april["members"])
    for m in members:                    # by September every device holds P-256
        for d in ms.addressable_devices(m):
            d["cipher_suites"] = sorted({*d["cipher_suites"], P256})
    september = _formation(members)
    fr = september["members"][0]
    params_s = w.demo_group_params(
        inputs=september, formed_at="2026-09-01T09:00:00Z",
        device_raises=[(fr["uid"], fr["mid"], "dev-01", P256)])
    params_s.update(effective_floor=P256, selected_suite=P256)
    groups = {g.GROUP: g._context(params_a),
              SEPTEMBER_GROUP: w.demo_group_context(
                  SEPTEMBER_GROUP, g.EPOCH, cipher_suite=CODE[P256],
                  extensions=w.sm_mls_extensions("default", "1", group_params=params_s))}
    assert _bundle(groups, [april, september], september["members"]) == []
    found = _bundle(groups, [april], september["members"])
    assert [r for r, _ in found] == ["LINT-BND-I5"] and SEPTEMBER_GROUP in found[0][1], found


def test_a_missing_or_altered_formation_is_incomplete():
    april, params = _april()
    gc = g._context(params)
    for formations in (None, [], [_formation(_with_fr_dev01_raised(april["members"]))]):
        found = _bundle({g.GROUP: gc}, formations, april["members"])
        assert found and {r for r, _ in found} == {"LINT-BND-I5"}, (formations, found)


def test_a_v1_decision_is_incomplete_never_recomputed():
    """A v1 record binds no inputs and names no entity: it is history, not a
    decision a verifier can recompute — neither passed nor failed."""
    april, params = _april()
    v1 = dict(params, params_version=1)
    gc = w.demo_group_context(g.GROUP, g.EPOCH,
                              extensions=w.sm_mls_extensions("default", "1", group_params=v1))
    decoded = w.group_params_from(w.parse_group_context(gc)["extensions"])
    assert decoded["params_version"] == 1
    with pytest.raises(ms.UnverifiableDecision):
        _verify(decoded, april)
    found = _bundle({g.GROUP: gc}, [april], april["members"])
    assert [r for r, _ in found] == ["LINT-BND-I5"] and "v1" in found[0][1], found
