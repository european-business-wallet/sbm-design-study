# SPDX-License-Identifier: MIT
"""X-21 — delivered_at is the event time, bounded by expiry at EVERY grade.

Former defect: LINT-BND-22 exempted the availability grade from
delivered_at <= expires_at — the one grade without a recipient confirmation
lacked the temporal guard, so an availability DE post-dating expires_at was
accepted. The exemption is removed; delivered_at is normatively the S2/S4
EVENT time (the qualified timestamp stays the possibly-later issuance time).

Boundary vectors: before / at / after expiry for an availability DE (the
previously-exempt case).
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DEAV = json.load(open(ROOT / "samples" / "sample-DE-availability.json"))["projection"]


def _bundle_with(de):
    m = bl.reconstruct(json.loads(
        (ROOT / "samples" / "bundle.default.manifest.json").read_text()))
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    # a synthetic SE sharing the availability DE's message_id, expiring at T
    se = copy.deepcopy(SE)
    se["message_id"] = de["message_id"]
    se["expires_at"] = "2026-04-07T10:15:00Z"
    ev = [_rc(x) for x in m["evidence"]] + [se, de]
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], ev]


def _rules(de):
    return [r for r, _ in bl.check_bundle(*_bundle_with(de))]


def test_availability_before_expiry_delivers():
    de = copy.deepcopy(DEAV); de["delivered_at"] = "2026-04-07T10:14:59Z"
    assert "LINT-BND-22" not in _rules(de)


def test_availability_at_expiry_delivers():
    """The tie-break: event == expiry instant is DELIVERED."""
    de = copy.deepcopy(DEAV); de["delivered_at"] = "2026-04-07T10:15:00Z"
    assert "LINT-BND-22" not in _rules(de)


def test_negative_availability_after_expiry_fails():
    """The reproduced defect: the availability grade was EXEMPT — an
    availability DE post-dating expires_at was accepted. Now it fails."""
    de = copy.deepcopy(DEAV); de["delivered_at"] = "2026-04-07T10:15:01Z"
    assert "LINT-BND-22" in _rules(de)


def test_prose_states_the_event_time_rule():
    idtxt = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "Event time vs artefact time" in idtxt
    assert "the former availability exemption is removed" in idtxt.replace("\n", " ")
