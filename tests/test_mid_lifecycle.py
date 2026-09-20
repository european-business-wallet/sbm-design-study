# SPDX-License-Identifier: MIT
"""X-17 — MID rotation and non-reuse lifecycle.

Former defect: MID rotation was SHOULD with no procedure and no non-reuse
invariant, and `bundle_lint`'s active-member map silently collapsed duplicate
MIDs — so reassigning a retired MID to a different person would silently
re-attribute old, indefinitely-retained confirmations. This batch adds the
non-reuse invariant (LINT-BND-23) and the atomic-rotation / as-of-resolution
rules, and demonstrates as-of resolution.

Negative fixture: a UID whose MID is bound to two different accountability chains
is rejected. Positive: an old confirmation resolves, as of its `verified_at`, to
the member/key valid at its event time — not to what the MID currently binds.
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


bl = _load("bundle_lint", "bundle_lint.py")


def _bundle(manifest="bundle.default.manifest.json"):
    m = bl.reconstruct(json.loads((ROOT / "samples" / manifest).read_text()))
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], [_rc(x) for x in m["evidence"]]]


def test_positive_bundles_have_no_mid_reuse():
    for manifest in ("bundle.default.manifest.json", "bundle.scoped.manifest.json"):
        issues = bl.check_bundle(*_bundle(manifest))
        assert not [r for r, _ in issues if r == "LINT-BND-23"], issues


def test_negative_mid_reassigned_to_a_different_chain_is_rejected():
    """The reproduced defect: one MID, two different authorisation chains."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle())
    clash = copy.deepcopy(members[0])
    clash["accountability"]["authorisation_ref"] = "urn:org:OTHER:authz:9999"  # different person/chain
    members.append(clash)  # same mid as members[0], different accountability
    rules = [r for r, _ in bl.check_bundle(entity, med, org, members, evidence)]
    assert "LINT-BND-23" in rules, rules


def test_same_mid_same_chain_is_not_reuse():
    """Re-publishing the SAME member (same authorisation_ref) is not reassignment."""
    entity, med, org, members, evidence = copy.deepcopy(_bundle())
    members.append(copy.deepcopy(members[0]))  # identical accountability -> OK
    rules = [r for r, _ in bl.check_bundle(entity, med, org, members, evidence)]
    assert "LINT-BND-23" not in rules, rules


# --- as-of resolution: resolve an old confirmation to the then-valid binding ---

# A MID's binding history: v1 (old confirmation key) then, after a rotation, v2
# (new key). Same MID, distinct validity windows.
HISTORY = [
    {"version": 1, "confirmation_pubkey": "OLD_KEY_v1",
     "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"},
    {"version": 2, "confirmation_pubkey": "NEW_KEY_v2",
     "valid_from": "2026-06-01T00:00:00Z"},  # open-ended (current)
]


def test_as_of_resolution_picks_the_binding_valid_at_event_time():
    # An old confirmation made at verified_at inside v1's window.
    old = lc.as_of_resolve(HISTORY, at="2026-03-15T12:00:00Z")
    assert old is not None and old["version"] == 1
    assert old["confirmation_pubkey"] == "OLD_KEY_v1", (
        "an old confirmation must resolve to the key valid at its event time")


def test_current_resolution_would_use_the_wrong_key_after_rotation():
    now = lc.as_of_resolve(HISTORY, at="2026-09-01T00:00:00Z")
    assert now["version"] == 2 and now["confirmation_pubkey"] == "NEW_KEY_v2"
    # The point of as-of: resolving the OLD confirmation naively "at now" would
    # pick v2's key and fail — so the verifier MUST resolve as-of verified_at.
    assert now["confirmation_pubkey"] != HISTORY[0]["confirmation_pubkey"]


def test_before_history_resolves_to_nothing():
    assert lc.as_of_resolve(HISTORY, at="2025-01-01T00:00:00Z") is None
