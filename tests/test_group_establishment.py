# SPDX-License-Identifier: MIT
"""DR-08 — discovery and reservation compose into a group a creator can form.

Former defect (round-2 review, High). The EDD contract said its KeyPackage
redirect target serves a `KeyPackagesResponse` from a GET containing actual
packages; the Delivery-Service contract defined that same GET as availability
COUNTS, with packages obtained through a separate POST reservation. The EDD's
`target_mid` query existed on neither DS operation. The reservation request
carried only `cipher_suite` and `count` — it could not name the (mid,
device_id) set that scope resolution selected — and its response was an array
of OPAQUE packages with no device association.

Meanwhile the normative suite selector requires per-member/device capability
sets, and neither BW-MEMBER nor the member-enumeration API published any: the
round-1 tests supplied SYNTHETIC capability arrays. So the algorithm the
profile calls normative could not be executed from the published contracts at
all, the X-26 all-device property could not be demonstrated, and the two
contracts described incompatible clients for one URL.

The tests here therefore drive a group establishment from the PUBLISHED
surfaces only — BW-MEMBER 2.2's per-device `cipher_suites`, the DS reservation
request's target selectors, and the typed association each returned package
now carries. Nothing synthetic: the capability sets come out of the shipped
discovery fixtures.
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

import mls_suite as ms  # noqa: E402

DS = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
EDD = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text())

RESERVE = DS["paths"]["/keypackages/{uid}/reservations"]["post"]
RESERVE_BODY = RESERVE["requestBody"]["content"]["application/json"]["schema"]
RESERVATION = DS["components"]["schemas"]["Reservation"]

BASELINE = ms.BASELINE
HW = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"


def _member(name):
    return json.loads((ROOT / "samples" / f"{name}.json").read_text())["projection"]


MEMBERS = [_member("sample-BW-MEMBER-fr"), _member("sample-BW-MEMBER-fr2")]


# ---------------------------------------------------------------------------
# A mock pool that honours the published reservation contract
# ---------------------------------------------------------------------------

def _pool(members, suites_by_device=None):
    """(uid, mid, device_id) -> the suites that device has a current package
    for — the whole principal (R12-05). Defaults to exactly what discovery
    publishes, which is the point: the two must agree, and the association is
    what makes the agreement checkable."""
    pool = {}
    for uid, mid, did, published in ms.device_capability_sets(members):
        pool[(uid, mid, did)] = set(suites_by_device.get((uid, mid, did), published)
                                    if suites_by_device else published)
    return pool


def _reserve(targets, suite, pool, *, drop=(), duplicate=None, extra=None):
    """The DS's response, shaped by the published Reservation schema."""
    packages = []
    # A reservation is for ONE entity, so within it the label pair names the
    # device; the pool is keyed by the whole principal.
    by_label = {(k[1], k[2]): v for k, v in pool.items()}
    for t in targets:
        key = (t["mid"], t["device_id"])
        if key in drop or suite not in by_label.get(key, ()):
            continue
        packages.append({"mid": key[0], "device_id": key[1],
                         "cipher_suite": suite,
                         "keypackage_b64": f"KP-{key[0]}-{key[1]}-{suite}"})
    if duplicate is not None:
        packages.append({"mid": duplicate[0], "device_id": duplicate[1],
                         "cipher_suite": suite,
                         "keypackage_b64": "KP-DUPLICATE"})
    if extra is not None:
        packages.append({"mid": extra[0], "device_id": extra[1],
                         "cipher_suite": suite,
                         "keypackage_b64": "KP-EXTRA"})
    return {"reservation_id": "01J8RESERVE0000000000000A",
            "cipher_suite": suite, "expires_at": "2026-04-04T10:20:00Z",
            "committed": False, "keypackages": packages}


# ---------------------------------------------------------------------------
# The review's acceptance tests
# ---------------------------------------------------------------------------

def test_a_multi_member_multi_device_group_forms_from_the_published_surfaces():
    """The first acceptance test. Every input comes from discovery: no
    synthetic capability array appears anywhere in this flow."""
    targets = ms.plan_targets(MEMBERS)
    assert len({(t["mid"], t["device_id"]) for t in targets}) >= 3, \
        "the shipped fixtures no longer describe a multi-device group"
    pool = _pool(MEMBERS)
    suite = ms.select_suite_for_devices(MEMBERS, pool)
    reservation = _reserve(targets, suite, pool)
    got = ms.check_reservation(targets, reservation)
    assert set(got) == {(t["mid"], t["device_id"]) for t in targets}


def test_omitting_one_eligible_device_fails():
    """The X-26 all-device property, made checkable. A group missing one of a
    member's addressable devices is a group that member cannot fully read."""
    targets = ms.plan_targets(MEMBERS)
    pool = _pool(MEMBERS)
    suite = ms.select_suite_for_devices(MEMBERS, pool)
    dropped = (targets[-1]["mid"], targets[-1]["device_id"])
    reservation = _reserve(targets, suite, pool, drop={dropped})
    with pytest.raises(ms.ReservationMismatch) as exc:
        ms.check_reservation(targets, reservation)
    assert exc.value.reason == "keypackage-target-unavailable"
    assert f"{dropped[0]}/{dropped[1]}" in exc.value.detail


def test_two_packages_for_one_device_and_none_for_another_fails():
    """The review's exact third test — and it is one failure, not two: at equal
    count, a duplicate IS a missing device."""
    targets = ms.plan_targets(MEMBERS)
    pool = _pool(MEMBERS)
    suite = ms.select_suite_for_devices(MEMBERS, pool)
    first = (targets[0]["mid"], targets[0]["device_id"])
    dropped = (targets[-1]["mid"], targets[-1]["device_id"])
    reservation = _reserve(targets, suite, pool, drop={dropped}, duplicate=first)
    assert len(reservation["keypackages"]) == len(targets), \
        "the count matches — only the association reveals the substitution"
    with pytest.raises(ms.ReservationMismatch) as exc:
        ms.check_reservation(targets, reservation)
    assert exc.value.reason == "keypackage-target-duplicate"


def test_a_package_for_an_unrequested_device_fails():
    targets = ms.plan_targets(MEMBERS)
    pool = _pool(MEMBERS)
    suite = ms.select_suite_for_devices(MEMBERS, pool)
    reservation = _reserve(targets, suite, pool,
                           extra=("F9Z9Z9Z9Z", "dev-intruder"))
    with pytest.raises(ms.ReservationMismatch) as exc:
        ms.check_reservation(targets, reservation)
    assert exc.value.reason == "keypackage-target-unrequested"


def test_a_stronger_suite_is_skipped_only_when_an_exact_target_lacks_a_package():
    """The fourth acceptance test. The distinction matters: a member-level
    intersection would skip a suite because SOME member lacked it; the property
    required is that an EXACT device target lacks a usable package."""
    members = copy.deepcopy(MEMBERS)
    for m in members:                       # everyone can do the stronger suite
        for d in m["devices"]:
            if HW not in d["cipher_suites"]:
                d["cipher_suites"] = list(d["cipher_suites"]) + [HW]

    full = _pool(members)
    assert ms.select_suite_for_devices(members, full) == HW, \
        "with packages for every device, the stronger suite must be chosen"

    caps = ms.device_capability_sets(members)
    one = caps[-1][:3]
    partial = {k: (v - {HW} if k == one else v) for k, v in full.items()}
    assert ms.select_suite_for_devices(members, partial) == BASELINE, \
        "one device without a package for the stronger suite must lower it"
    # ...and it is THAT device's absence, not a member-level one
    assert HW in dict(((u, m, d), s) for u, m, d, s in caps)[one], \
        "the device still PUBLISHES the suite — only its package is missing"


def test_the_edd_flow_matches_the_ds_contract():
    """The fifth: one URL, one client. The EDD must point at the reservation
    lifecycle rather than describe a different response for the same GET."""
    edd = EDD["paths"]["/uid/{uid}/keypackages"]["get"]
    flat = " ".join(edd["description"].replace("`", "").split())
    assert "availability counts only" in flat
    assert "RESERVATION" in flat or "reservation lifecycle" in flat.lower()
    # The word survives in the note explaining the defect, which is worth
    # keeping; what must not survive is the CLAIM.
    for revived in ("serves single-use KeyPackages",
                    "in the KeyPackagesResponse shape",
                    "which serves KeyPackages"):
        assert revived not in flat, \
            f"the EDD again describes what the target serves: {revived!r}"
    assert "used to say" in flat, \
        "the correction is stated as a correction, so it is not re-litigated"
    # and the DS's own GET is unambiguously the counts read
    ds_get = DS["paths"]["/keypackages/{uid}"]["get"]
    # R9-B6: a NAMED component now — an inline response body is one nothing
    # can reference and therefore nothing validates against.
    ref = ds_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    body = DS["components"]["schemas"][ref.rsplit("/", 1)[1]]
    assert body["required"] == ["suites"]


# ---------------------------------------------------------------------------
# The contract carries what the flow needs
# ---------------------------------------------------------------------------

def test_the_reservation_request_carries_target_selectors_not_a_count():
    assert RESERVE_BODY["required"] == ["targets"]
    assert "count" not in RESERVE_BODY["properties"], \
        "a count cannot name a device — that was the defect"
    item = RESERVE_BODY["properties"]["targets"]["items"]
    assert set(item["required"]) == {"mid", "device_id"}


def test_every_returned_package_is_associated_with_its_target_and_suite():
    item = RESERVATION["properties"]["keypackages"]["items"]
    # R9-03: `keypackage_ref` joins the REQUIRED set. The invitation requires
    # the value and nothing produced it; a response allowed to omit it would
    # leave a conforming client exactly where it was.
    assert set(item["required"]) == {"mid", "device_id", "cipher_suite",
                                     "keypackage_b64", "keypackage_ref"}


def test_the_commit_is_atomic():
    commit = DS["paths"]["/reservations/{reservation_id}/commit"]["post"]
    flat = " ".join(commit["description"].split())
    assert "ATOMIC (DR-08)" in flat
    assert "no partial commit" in flat


def test_the_typed_per_target_failures_are_registered():
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    for code in ("keypackage-target-unavailable", "keypackage-target-duplicate",
                 "keypackage-target-unrequested"):
        row = reg["nde_reasons"][code]
        assert row["status"] == "active"
        assert row["stages"] == {"intake": "A.2-SubmissionRejection"}


# ---------------------------------------------------------------------------
# The capability input exists in discovery now
# ---------------------------------------------------------------------------

def test_every_shipped_device_publishes_its_suites():
    for f in sorted((ROOT / "samples").glob("sample-BW-MEMBER*.json")):
        m = json.loads(f.read_text())["projection"]
        for d in m.get("devices") or []:
            assert d.get("cipher_suites"), f"{f.name}: {d.get('device_id')}"
            assert BASELINE in d["cipher_suites"], f.name


def test_a_device_without_published_suites_fails_closed():
    """Fail closed rather than assume the baseline: assuming it is how a device
    silently ends up in a group it cannot decrypt."""
    members = copy.deepcopy(MEMBERS)
    members[0]["devices"][0]["cipher_suites"] = []
    with pytest.raises(ms.MissingDeviceCapabilities):
        ms.plan_targets(members)


def test_the_selector_is_per_device_not_per_member():
    """A member whose second device supports less must not have that hidden by
    a member-level union."""
    members = copy.deepcopy(MEMBERS)
    for d in members[0]["devices"]:
        d["cipher_suites"] = [BASELINE, HW]
    weak = ms.addressable_devices(members[0])[-1]
    weak["cipher_suites"] = [BASELINE]          # one device cannot do HW
    for d in members[1]["devices"]:
        d["cipher_suites"] = [BASELINE, HW]
    assert ms.select_suite_for_devices(members, _pool(members)) == BASELINE


# ---------------------------------------------------------------------------
# LINT-DISC-29 — discovery publishes the selector's input, checkably
# ---------------------------------------------------------------------------

def _disc29(member):
    spec = importlib.util.spec_from_file_location(
        "discovery_lint", ROOT / "scripts" / "discovery_lint.py")
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)
    v = dl.Violations()
    for i, dev in enumerate(member.get("devices") or []):
        dl._check_device_suites(v, member, dev, i)
    return [m for r, m in v.items if r == "LINT-DISC-29"]


def test_the_shipped_members_pass_the_capability_rule():
    for m in MEMBERS:
        assert not _disc29(m)


def test_a_device_publishing_no_suites_is_a_violation():
    m = copy.deepcopy(MEMBERS[0])
    m["devices"][0].pop("cipher_suites")
    assert _disc29(m)


def test_a_device_omitting_the_baseline_is_a_violation():
    """The invariant the selector rests on: the baseline is in every
    intersection, so a selection always exists. One device could otherwise
    make every group unformable — indistinguishable from a denial of service."""
    m = copy.deepcopy(MEMBERS[0])
    m["devices"][0]["cipher_suites"] = [HW]
    issues = _disc29(m)
    assert issues and "baseline" in issues[0]


def test_a_repeated_suite_is_a_violation():
    m = copy.deepcopy(MEMBERS[0])
    m["devices"][0]["cipher_suites"] = [BASELINE, BASELINE]
    assert _disc29(m)
