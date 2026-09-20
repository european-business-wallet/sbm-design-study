# SPDX-License-Identifier: MIT
"""N3 (deterministic cipher-suite selection): the group creator picks the
highest-preference suite in the intersection of members' capabilities, using the
versioned vector mls-suite-preference/v1. The property that matters: two
conforming creators pick the SAME suite from the same capability sets — so the
"strongest mutually supported suite" is no longer under-specified."""
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ms = _load("mls_suite", "mls_suite.py")

PQ = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"
P384 = "MLS_256_DHKEMP384_AES256GCM_SHA384_P384"
P256 = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
BASE = ms.BASELINE


def test_deterministic_regardless_of_member_order():
    a = [BASE, P384, PQ]
    b = [BASE, P256, P384]
    assert ms.select_suite([a, b]) == ms.select_suite([b, a]) == P384


def test_prefers_pq_then_margin_then_hardware_then_baseline():
    assert ms.select_suite([[BASE, P256, P384, PQ], [BASE, P256, P384, PQ]]) == PQ
    assert ms.select_suite([[BASE, P256, P384], [BASE, P256, P384]]) == P384
    assert ms.select_suite([[BASE, P256], [BASE, P256]]) == P256
    assert ms.select_suite([[BASE], [BASE, P384]]) == BASE  # intersection is baseline only


def test_two_hardware_only_peers_negotiate_p256():
    assert ms.select_suite([[BASE, P256], [BASE, P256, PQ]]) == P256


def test_empty_intersection_when_baseline_omitted_raises():
    with pytest.raises(ValueError):
        ms.select_suite([[P384], [P256]])
    with pytest.raises(ValueError):
        ms.select_suite([])


# ---------------------------------------------------------------------------
# N-03 — selection returns only suites with usable KeyPackages
# ---------------------------------------------------------------------------

def test_n03_capability_without_keypackage_is_skipped():
    """The finding's negative verbatim: both members ADVERTISE the PQ suite,
    but one has KeyPackages only for the baseline — the PQ suite must be
    skipped, not selected into an unusable group."""
    caps = [[ms.PREFERENCE[0], ms.BASELINE], [ms.PREFERENCE[0], ms.BASELINE]]
    kps = [[ms.PREFERENCE[0], ms.BASELINE], [ms.BASELINE]]
    assert ms.select_usable_suite(caps, kps) == ms.BASELINE
    # capability-only selection would have picked the PQ suite:
    assert ms.select_suite(caps) == ms.PREFERENCE[0]


def test_n03_selection_needs_a_keypackage_for_every_member():
    caps = [[ms.BASELINE], [ms.BASELINE], [ms.BASELINE]]
    kps = [[ms.BASELINE], [ms.BASELINE], [ms.BASELINE]]
    assert ms.select_usable_suite(caps, kps) == ms.BASELINE


def test_n03_no_usable_suite_is_the_typed_failure():
    """Capabilities intersect fine, but one member's pool is EMPTY — the
    typed establishment failure (keypackage-pool-exhausted), never a silent
    fallback."""
    caps = [[ms.BASELINE], [ms.BASELINE]]
    kps = [[ms.BASELINE], []]
    import pytest
    with pytest.raises(ms.NoUsableSuite):
        ms.select_usable_suite(caps, kps)


def test_n03_determinism_is_member_order_independent():
    caps_a = [[ms.PREFERENCE[2], ms.BASELINE], [ms.BASELINE]]
    kps_a = [[ms.PREFERENCE[2], ms.BASELINE], [ms.BASELINE]]
    assert ms.select_usable_suite(caps_a, kps_a) == \
        ms.select_usable_suite(list(reversed(caps_a)), list(reversed(kps_a)))


def test_n03_member_count_mismatch_is_rejected():
    import pytest
    with pytest.raises(ValueError, match="disagree"):
        ms.select_usable_suite([[ms.BASELINE]], [[ms.BASELINE], [ms.BASELINE]])


def test_n03_the_id_states_per_suite_pools_and_vector_pinning():
    import pathlib
    idd = (pathlib.Path(__file__).resolve().parents[1]
           / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "partitioned **per cipher suite**" in idd
    assert "pinned at group creation" in idd
    assert "capability support\n  alone never suffices" in idd or \
        "capability support alone never suffices" in idd.replace("\n  ", " ")
