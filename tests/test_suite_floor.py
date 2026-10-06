# SPDX-License-Identifier: MIT
"""DR-15 — the cipher-suite floor is published, mandatory and enforceable.

Former defect (round-2 review, Medium). The profile permitted a member to
refuse a suite below a "locally configured floor": optional, unpublished,
unverifiable — and ambiguous, because "below what it advertised" cannot be read
when the advertised list also contains the mandatory baseline. A provider could
withhold stronger-suite KeyPackages, and (until DR-08) a creator could not
distinguish legitimate per-device absence from provider-induced withholding.

R2-M5, settled and then AMENDED TWICE. The first form put a signed floor per
entity in BW-MED; the second per device in BW-MEMBER. Both shared a defect the
maintainer identified: a floor each participant DECLARES protects only the
participants who declare one, and a member that publishes nothing is exactly
where a downgrade lands — the majority case. The settled form is two-layer:

  1. `mls-suite-floor/v1`, a MANDATORY versioned constant of the federation
     registry, binding on everybody including one who publishes nothing;
  2. an OPTIONAL per-device raise that may never lower it.

The level is the baseline, deliberately, and the reasoning is recorded rather
than assumed: the baseline is REQUIRED of every implementation and ranks LAST
in the preference vector, so a floor there adds no cryptographic STRENGTH — it
adds uniform ENFORCEMENT. `MAY refuse` becomes `MUST NOT form`.

X-33 is untouched: a floor does not make provider WITHHOLDING detectable.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_suite as ms  # noqa: E402

REGISTRY = json.loads((ROOT / "registries" / "cipher-suites.json").read_text())
BASELINE = ms.BASELINE
HW = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
PQ = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"


def _member(name):
    return json.loads((ROOT / "samples" / f"{name}.json").read_text())["projection"]


MEMBERS = [_member("sample-BW-MEMBER-fr"), _member("sample-BW-MEMBER-fr2")]


def _disc30(member):
    spec = importlib.util.spec_from_file_location(
        "discovery_lint", ROOT / "scripts" / "discovery_lint.py")
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)
    v = dl.Violations()
    for i, dev in enumerate(member.get("devices") or []):
        dl._check_device_floor(v, member, dev, i)
    return [m for r, m in v.items if r == "LINT-DISC-30"]


# ---------------------------------------------------------------------------
# The mandatory layer — the half a per-participant floor could not provide
# ---------------------------------------------------------------------------

def test_a_group_below_the_floor_is_rejected_for_a_member_that_published_nothing():
    """The case the earlier forms missed entirely, and the majority case: no
    device declares anything, and the group is STILL bound."""
    members = copy.deepcopy(MEMBERS)
    for m in members:
        for d in m["devices"]:
            d.pop("min_cipher_suite", None)
    assert ms.enforce_floor(members, BASELINE) == BASELINE
    with pytest.raises(ms.SuiteBelowFloor) as exc:
        ms.enforce_floor(members, "MLS_128_SOMETHING_WEAKER")
    assert exc.value.reason == "suite-below-published-floor"


def test_the_floor_is_a_registry_constant_not_a_number_in_prose():
    """Raising it is a governance action with an audit trail."""
    assert REGISTRY["floor"]["id"] == "mls-suite-floor/v1"
    assert REGISTRY["floor"]["suite"] == BASELINE
    assert ms.FLOOR == REGISTRY["floor"]["suite"]
    assert ms.PREFERENCE == REGISTRY["preference_vector"]["order"], \
        "the vector is loaded from the registry, not restated in code"


def test_the_level_is_the_baseline_and_the_reason_is_recorded():
    """A floor at the baseline adds no cryptographic strength; it adds uniform
    enforcement. Recording why stops it being read as a stronger claim."""
    note = " ".join(REGISTRY["floor"]["$comment"].split())
    assert "adds no cryptographic STRENGTH" in note
    assert "uniform ENFORCEMENT" in note
    assert "would exclude implementations that support only the mandatory baseline suite" in note


def test_two_creators_with_the_same_signed_inputs_decide_alike():
    """The review's third acceptance test — trivially true for the mandatory
    layer, which is the point: no fetch, no local configuration, no divergence."""
    a = copy.deepcopy(MEMBERS)
    b = list(reversed(copy.deepcopy(MEMBERS)))
    assert ms.floor_for(a)[0] == ms.floor_for(b)[0]


# ---------------------------------------------------------------------------
# The raise, one-directional
# ---------------------------------------------------------------------------

def test_a_device_may_raise_the_floor():
    """The case the floor exists to serve: an HSM leaf beside a phone."""
    members = copy.deepcopy(MEMBERS)
    dev = ms.addressable_devices(members[0])[0]
    dev["cipher_suites"] = list(set(dev["cipher_suites"]) | {HW})
    dev["min_cipher_suite"] = HW
    floor, who = ms.floor_for(members)
    # R12-05: the raiser is named by its whole principal.
    assert floor == HW and who == (members[0]["uid"], members[0]["mid"], dev["device_id"])
    with pytest.raises(ms.SuiteBelowFloor) as exc:
        ms.enforce_floor(members, BASELINE)
    assert "raised by" in exc.value.detail


def test_a_device_may_not_lower_the_floor():
    """A weaker published value is not a weaker policy the federation honours —
    it is non-conformant, and honouring it would restore what R2-M5 removed."""
    members = copy.deepcopy(MEMBERS)
    dev = ms.addressable_devices(members[0])[0]
    dev["cipher_suites"] = list(set(dev["cipher_suites"]) | {HW})
    dev["min_cipher_suite"] = HW
    # ...and the mandatory floor is never lowered by a "weaker" declaration
    weak = copy.deepcopy(MEMBERS)
    wdev = ms.addressable_devices(weak[0])[0]
    wdev["min_cipher_suite"] = "MLS_128_SOMETHING_WEAKER"
    assert ms.floor_for(weak)[0] == BASELINE, \
        "an unrecognised or weaker raise must not move the mandatory floor"


def test_a_weaker_published_floor_is_a_discovery_violation():
    members = copy.deepcopy(MEMBERS)
    dev = members[0]["devices"][0]
    dev["cipher_suites"] = [BASELINE, HW]
    dev["min_cipher_suite"] = BASELINE      # equal is fine
    assert not _disc30(members[0])
    dev["min_cipher_suite"] = "MLS_128_SOMETHING_WEAKER"
    issues = _disc30(members[0])
    assert issues and f"not in {ms.PREFERENCE_ID}" in issues[0]


def test_demanding_a_suite_the_device_does_not_publish_is_a_violation():
    """A denial of service wearing a policy's clothes: every group becomes
    unformable for that device."""
    members = copy.deepcopy(MEMBERS)
    dev = members[0]["devices"][0]
    dev["cipher_suites"] = [BASELINE]
    dev["min_cipher_suite"] = PQ
    issues = _disc30(members[0])
    assert any("does not publish it" in i for i in issues)


# ---------------------------------------------------------------------------
# Withholding cannot silently lower the suite where the floor forbids it
# ---------------------------------------------------------------------------

def test_removing_a_stronger_package_cannot_silently_lower_a_raised_suite():
    """The review's second acceptance test. Withholding still succeeds in
    LOWERING the selection — that is X-33's residual — but it can no longer do
    so SILENTLY: the group fails to form with a typed outcome."""
    members = copy.deepcopy(MEMBERS)
    for m in members:
        for d in m["devices"]:
            d["cipher_suites"] = [BASELINE, HW]
            d["min_cipher_suite"] = HW
    pool = {(uid, mid, did): {BASELINE, HW}                  # whole principals (R12-05)
            for uid, mid, did, _ in ms.device_capability_sets(members)}
    assert ms.select_suite_for_devices(members, pool) == HW
    assert ms.enforce_floor(members, HW) == HW

    victim = next(iter(pool))
    pool[victim] = {BASELINE}            # the provider withholds the stronger
    lowered = ms.select_suite_for_devices(members, pool)
    assert lowered == BASELINE
    with pytest.raises(ms.SuiteBelowFloor):
        ms.enforce_floor(members, lowered)


def test_the_typed_refusal_is_registered_under_group_establishment():
    """R3-08 moved this. I registered it as the INTAKE event
    A.2-SubmissionRejection, and this test pinned that — but a declined Welcome
    happens BEFORE any submission: there is no message_id, no SE and no chain,
    so no NDE can carry it. The stage is group-establishment, and the outcome
    travels as an authenticated MLS message to the group creator (R4-U4) —
    tests/test_group_params_semantics.py owns the withdrawal of the standalone
    object that round 3 introduced for it."""
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    assert "suite-below-published-floor" not in reg["nde_reasons"], \
        "a pre-group refusal cannot be an NDE reason"
    row = reg["group_establishment_reasons"]["suite-below-published-floor"]
    assert row["status"] == "active"
    assert row["stage"] == "group-establishment"


def test_the_pinned_selection_lives_in_the_group_context():
    """R3-08: my C5 test asserted that a PROSE SENTENCE existed — the exact
    criticism round 2 levelled at round 1's tests. The value is in the
    artefact now, and tests/test_mls_wire_kat.py decodes it from the bytes
    mls_state commits to with an independent reader."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("mls_wire", ROOT / "scripts" / "mls_wire.py")
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    types = [ty for ty, _ in w.sm_mls_extensions(
        "default", "1", group_params=w.demo_group_params())]
    # R12-X4: the decision is pinned in version 2 of the extension now.
    assert w.SBM_GROUP_PARAMS_V2_EXTENSION_TYPE in types
    assert w.SBM_GROUP_PARAMS_EXTENSION_TYPE not in types, "v1 is history, never produced"
    assert types == sorted(types), "canonical ascending order"


# ---------------------------------------------------------------------------
# The prose says what the code does — and does not overclaim
# ---------------------------------------------------------------------------

def _flat(path):
    return " ".join((ROOT / path).read_text().replace("**", "").replace("`", "").split())


def test_the_id_states_the_mandatory_floor_and_the_one_directional_raise():
    t = _flat("ietf/draft-sbm-mls-erd-00.md")
    assert "A MANDATORY floor, mls-suite-floor/v1" in t
    assert "MUST NOT be formed" in t
    assert "may only RAISE the mandatory floor and never lower it" in t
    assert "pin the selected suite and that floor in the group-establishment state" in t


def test_the_permissive_phrasing_cannot_return():
    src = (ROOT / "scripts" / "doc_lint.py").read_text()
    assert "MAY refuse to join a group whose selected suite" in src
    assert "locally configured floor" in src
    t = _flat("ietf/draft-sbm-mls-erd-00.md")
    assert "A member MAY refuse to join a group whose selected suite is below its configured floor" not in t
