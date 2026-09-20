# SPDX-License-Identifier: MIT
"""Round 11 / B6 — R11-08: a retained group decodes under its own revision.

`bundle_lint` decoded a retained GroupContext's cipher suite through TODAY's
map before the retained registry revision was consulted, so a revision-1
group was refused "not in the profile's vector" while direct verification
under revision 1 passed it. Phase 1 found the sharper form: revision 1 has no
wire map at all — `0x004D` was never specified by any revision; it lived only
in the reference's literal map, which R10-11 deleted.

R11-X4: wire maps are per revision and retained; a group decodes under the
revision it pinned; a revision without a wire map resolves IANA allocations
only, and a group of it claiming anything else is INCOMPLETE — never a
violation, never decoded by a later map. The review's acceptance: old and new
PQ groups verify under their own retained revisions; wrong-revision and
missing-mapping cases give the specified verdict; test a CHANGED suite, not
only the unchanged classical baseline.
"""
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_suite as ms  # noqa: E402
import mls_wire as w  # noqa: E402
import test_group_params_semantics as g  # noqa: E402

REV1 = json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())
REV2 = json.loads((ROOT / "registries" / "cipher-suites.json").read_text())
PQ1, PQ2 = REV1["preference_vector"]["order"][0], REV2["preference_vector"]["order"][0]


def _rev3():
    """A FUTURE revision in which IANA has allocated the hybrid a value and a
    new revision moved it there — the migration the registry promises."""
    r = copy.deepcopy(REV2)
    r["registry_version"] = "3"
    r["preference_vector"]["id"] = "mls-suite-preference/v3"
    r["code_points"][PQ2] = {"value": "0x00AB", "status": "iana"}
    return r


def _group(rev, suite, code_point, members=None):
    """A group formed under `rev` on `suite`, its decision committed to the
    formation it was taken on (R12-X4): these members, each addressable
    device holding a package for `suite` and the baseline — so the
    strongest-usable arm runs too, and any LINT-BND-I5 left is about decoding,
    not about missing inputs."""
    members = members or g._members()
    formation = w.formation_inputs(members, {
        (m["uid"], m["mid"], d["device_id"]): sorted({suite, ms.BASELINE})
        for m in members for d in ms.addressable_devices(m)})
    params = w.demo_group_params(inputs=formation)
    params.update(preference_vector_id=rev["preference_vector"]["id"],
                  floor_version=str(rev["registry_version"]), selected_suite=suite)
    return params, g._context(params, cipher_suite=code_point), formation


def _members_advertising(suite):
    ms_ = g._members()
    for m in ms_:
        for d in m.get("devices", []):
            if "cipher_suites" in d:
                d["cipher_suites"] = [suite] + [s for s in d["cipher_suites"] if "MLKEM" not in s]
    return ms_


def _bundle(gc, formation, registry):
    """The bundle path, given EVERYTHING it asks for — the retained formation
    included."""
    se = g._se_committing_to(gc)
    return sorted({(r, m) for r, m in g.bl.check_bundle(
        se["recipient_uid"], {}, {}, formation["members"], [se],
        group_contexts={(g.GROUP, g.EPOCH): gc}, formation_inputs=[formation],
        suite_registry=registry)
        if r in ("LINT-BND-40", "LINT-BND-I5")})


def _rules(found):
    return [r for r, _ in found]


# ---------------------------------------------------------------------------

def test_a_revision_2_pq_group_verifies_under_revision_2():
    """The CHANGED suite: the hybrid under its revision-2 name and value."""
    params, gc, formation = _group(REV2, PQ2, 0xF5C1, _members_advertising(PQ2))
    assert ms.verify_group_params(params, cipher_suite_name=PQ2,
                                  formation=formation, registry=REV2) == []
    assert _bundle(gc, formation, REV2) == []


def test_a_revision_1_pq_group_is_incomplete_not_a_violation():
    """The review's reproduction. Before B6: LINT-BND-40, "0x004d is not in
    the profile's vector" — a violation verdict about a group that direct
    verification under the same retained registry passed."""
    params, gc, formation = _group(REV1, PQ1, 0x004D, _members_advertising(PQ1))
    assert ms.verify_group_params(params, cipher_suite_name=PQ1,
                                  formation=formation, registry=REV1) == []
    found = _bundle(gc, formation, REV1)
    assert _rules(found) == ["LINT-BND-I5"], found
    assert "published no wire values" in found[0][1]


def test_the_revision_1_classical_group_still_verifies():
    params, gc, formation = _group(REV1, ms.BASELINE, w.CIPHER_SUITE_BASELINE)
    assert _bundle(gc, formation, REV1) == []


def test_a_later_migration_strands_no_earlier_group():
    """Revision 3 moves the hybrid to an IANA value. A revision-2 group on
    0xF5C1 still decodes by revision 2; a revision-3 group on 0x00AB decodes
    by revision 3. Decoding by today's map would have stranded the first."""
    rev3 = _rev3()
    params2, gc2, f2 = _group(REV2, PQ2, 0xF5C1, _members_advertising(PQ2))
    assert _bundle(gc2, f2, REV2) == []
    params3, gc3, f3 = _group(rev3, PQ2, 0x00AB, _members_advertising(PQ2))
    assert _bundle(gc3, f3, rev3) == []


def test_the_wrong_revision_is_incomplete():
    """A revision-2 group checked against revision 3: the material supplied is
    not what the group was formed under, so nothing can be concluded — which
    is INCOMPLETE, and INCOMPLETE is never a pass."""
    params, gc, formation = _group(REV2, PQ2, 0xF5C1, _members_advertising(PQ2))
    found = _bundle(gc, formation, _rev3())
    assert _rules(found) == ["LINT-BND-I5"] and "pins registry revision '2'" in found[0][1]


def test_a_value_the_pinned_revision_does_not_define_is_a_violation():
    params, gc, formation = _group(REV2, PQ2, 0x00FF, _members_advertising(PQ2))
    assert _rules(_bundle(gc, formation, REV2)) == ["LINT-BND-40"]


def test_each_revision_has_its_own_wire_map():
    assert w.wire_map(REV1) == w.IANA_CODE_POINTS, "revision 1 published no wire values"
    assert 0x004D not in w.wire_map(REV1) and 0x004D not in w.wire_map(REV2)
    assert w.wire_map(REV2)[0xF5C1] == PQ2
    assert w.wire_map(_rev3())[0x00AB] == PQ2 and 0xF5C1 not in w.wire_map(_rev3())
