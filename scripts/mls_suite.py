#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic MLS cipher-suite selection (N3, projection-integrity cycle).

The group creator (RFC 9420 §11) selects the group's cipher suite from the
intersection of all members' KeyPackage capabilities, using the versioned
preference vector `mls-suite-preference` (strongest-first; the revision
in force is `PREFERENCE_ID`, read from the registry). Two conforming
creators therefore pick the SAME suite from the same capability sets — closing the
"strongest mutually supported suite" under-specification. See the I-D (Cipher
Suites).
"""

import json as _json
import pathlib as _pathlib

_REGISTRY = _json.loads(
    (_pathlib.Path(__file__).resolve().parents[1] / "registries" /
     "cipher-suites.json").read_text(encoding="utf-8"))

# mls-suite-preference — strongest first. LOADED from the registry, not
# restated here: the vector and the floor are registry-governed (X-25 pattern),
# so changing either is a governance action with an audit trail rather than a
# code edit that a reviewer has to notice.
# R10-11: this was `PREFERENCE_V1` — a name encoding the version it happened
# to load. It loads whatever revision the registry holds (v2 since R10-11),
# so the version is DATA, read from the registry, never spelled in code.
PREFERENCE = list(_REGISTRY["preference_vector"]["order"])
PREFERENCE_ID = _REGISTRY["preference_vector"]["id"]
BASELINE = PREFERENCE[-1]

# mls-suite-floor/v1 (DR-15/R2-M5) — the MANDATORY minimum, binding on every
# conforming deployment INCLUDING one that publishes nothing. That is the half
# a per-participant floor could not provide, and the majority case.
FLOOR = _REGISTRY["floor"]["suite"]
FLOOR_ID = _REGISTRY["floor"]["id"]


class SuiteBelowFloor(ValueError):
    """DR-15: the selected suite is below the mandatory floor, or below a
    device's published raise. Carries the registry reason."""

    reason = "suite-below-published-floor"

    def __init__(self, detail):
        super().__init__(f"{self.reason}: {detail}")
        self.detail = detail


def floor_for(members, preference=PREFERENCE):
    """The floor IN FORCE for a group: the mandatory one, RAISED by the
    strongest floor any addressable device publishes. A device may demand more
    than the common minimum — an HSM leaf beside a phone — and may never demand
    less: a published value weaker than the mandatory floor is non-conformant
    and is rejected at discovery (LINT-DISC-30), not quietly honoured here."""
    rank = {s: i for i, s in enumerate(preference)}       # 0 = strongest
    best, who = FLOOR, None
    for m in members:
        for d in addressable_devices(m):
            raised = d.get("min_cipher_suite")
            if raised and rank.get(raised, len(rank)) < rank.get(best, len(rank)):
                best, who = raised, (m.get("uid"), m.get("mid"), d.get("device_id"))
    return best, who


def enforce_floor(members, suite, preference=PREFERENCE):
    """DR-15: a group at or above the floor may form; below it MUST NOT. Raises
    SuiteBelowFloor. `MAY refuse` was optional, local and unverifiable — this
    is uniform and checkable by a third party from the signed inputs alone."""
    rank = {s: i for i, s in enumerate(preference)}
    floor, who = floor_for(members, preference)
    if suite not in rank:
        raise SuiteBelowFloor(f"{suite!r} is not in {_REGISTRY['preference_vector']['id']}")
    if rank[suite] > rank[floor]:
        source = (f"the floor raised by {'/'.join(who)}" if who
                  else f"the mandatory {FLOOR_ID}")
        raise SuiteBelowFloor(
            f"the group would use {suite}, below {floor} — {source}. The group "
            "MUST NOT be formed")
    return floor


def select_suite(capability_sets, preference=PREFERENCE):
    """The suite the group creator picks: the highest-preference suite present in
    the INTERSECTION of every member's advertised `cipher_suites`. Every member
    MUST advertise the baseline (the I-D), so the intersection always contains it
    and a selection always exists. Deterministic in the capability sets, regardless
    of member order.

    Raises ValueError on no members, or on an empty intersection (a non-conforming
    member omitted the REQUIRED baseline)."""
    if not capability_sets:
        raise ValueError("no members")
    common = set(capability_sets[0])
    for caps in capability_sets[1:]:
        common &= set(caps)
    for suite in preference:
        if suite in common:
            return suite
    raise ValueError("empty intersection — a member omitted the REQUIRED baseline suite")


class NoUsableSuite(ValueError):
    """N-03: no suite has an unused, current KeyPackage for every member —
    the typed establishment failure (surfaced as the NDE reason
    `keypackage-pool-exhausted`)."""


def select_usable_suite(capability_sets, keypackage_suites,
                        preference=PREFERENCE):
    """N-03 (completing N3): the suite the creator ACTUALLY uses. An RFC 9420
    KeyPackage pins ONE `cipher_suite` while LeafNode capabilities may list
    several — so capability intersection alone can select a suite for which
    no unused KeyPackage was retrievable. Selection here returns the
    highest-preference suite that is (a) in EVERY member's capability set
    AND (b) backed by an unused, unexpired KeyPackage of that suite for
    EVERY added member (`keypackage_suites[i]` = the suites for which member
    i has an available KeyPackage — the per-suite pool / suite-filtered
    reservation of the I-D KeyPackage rules). A capability-supported suite
    with no matching KeyPackage is SKIPPED; no usable suite raises
    NoUsableSuite (`keypackage-pool-exhausted`). Deterministic in the
    inputs, regardless of member order."""
    if not capability_sets:
        raise ValueError("no members")
    if len(capability_sets) != len(keypackage_suites):
        raise ValueError("capability_sets and keypackage_suites disagree on members")
    common = set(capability_sets[0])
    for caps in capability_sets[1:]:
        common &= set(caps)
    usable = set(keypackage_suites[0])
    for kps in keypackage_suites[1:]:
        usable &= set(kps)
    for suite in preference:
        if suite in common and suite in usable:
            return suite
    if not any(s in common for s in preference):
        raise ValueError("empty intersection — a member omitted the REQUIRED baseline suite")
    raise NoUsableSuite(
        "no suite in the capability intersection has an unused KeyPackage "
        "for every member — keypackage-pool-exhausted (N-03)")


# ---------------------------------------------------------------------------
# DR-08 — per-DEVICE selection, from PUBLISHED capabilities
# ---------------------------------------------------------------------------
#
# The functions above take capability sets as arguments and say nothing about
# where they come from. That was the gap: the normative selector required
# per-member/device capability sets, BW-MEMBER and the member-enumeration API
# published none, and the tests supplied synthetic arrays — so the algorithm
# could not be executed from the published contracts at all. Since BW-MEMBER
# 2.2 each device publishes its own `cipher_suites`, and these functions read
# THAT, so the selector's input is discoverable rather than invented.
#
# Per DEVICE, not per member: X-26 is an ALL-DEVICE property. A member whose
# phone supports a suite and whose HSM leaf does not cannot join that group
# with both devices, and a member-level intersection hides exactly that.

ADDRESSABLE = ("receive", "ack")


def addressable_devices(member):
    """The devices that must be in the group for this member to be reachable —
    the X-26 all-device set. A device that can neither receive nor acknowledge
    is not a delivery target."""
    return [d for d in (member.get("devices") or [])
            if set(d.get("capabilities") or []) & set(ADDRESSABLE)]


def device_capability_sets(members):
    """[(uid, mid, device_id, frozenset(suites))] from PUBLISHED discovery.

    R12-05: the device's WHOLE principal. A group spans two entities, and a
    MID is unique only within one: keyed by (mid, device_id), FR's and DE's
    `F1N2C3D4P/dev-01` were one device here, and whichever came second in the
    input decided the verdict (invariant 10, in the layer round 11 did not
    reach)."""
    out = []
    for m in members:
        for d in addressable_devices(m):
            out.append((m.get("uid"), m.get("mid"), d.get("device_id"),
                        frozenset(d.get("cipher_suites") or ())))
    return out


class MissingDeviceCapabilities(ValueError):
    """A device publishes no `cipher_suites`. Fail closed rather than assume
    the baseline: assuming it is how a device silently ends up in a group it
    cannot decrypt."""


def plan_targets(members):
    """The exact (mid, device_id) selectors for a reservation — every
    addressable device of every member, which is what the DS request now
    carries instead of a count."""
    targets = []
    for _uid, mid, device_id, suites in device_capability_sets(members):
        if not suites:
            raise MissingDeviceCapabilities(
                f"{mid}/{device_id} publishes no cipher_suites (BW-MEMBER 2.2) "
                "— the suite selection cannot be executed for it")
        targets.append({"mid": mid, "device_id": device_id})
    return targets


def select_suite_for_devices(members, package_suites, preference=PREFERENCE):
    """The suite a creator picks for a multi-device group.

    `package_suites` maps (uid, mid, device_id) -> the suites that device has
    a CURRENT KeyPackage for (the DS availability read) — the whole principal
    (R12-05). A suite is usable only
    where EVERY addressable device both publishes it AND has a package for it;
    the highest-preference usable suite wins. A stronger suite is skipped only
    when an EXACT target lacks a usable package — the review's fourth
    acceptance test — never because some other member's device was absent from
    a member-level intersection.
    """
    caps = device_capability_sets(members)
    if not caps:
        raise ValueError("no addressable devices")
    for uid, mid, device_id, suites in caps:
        if not suites:
            raise MissingDeviceCapabilities(
                f"{uid}/{mid}/{device_id} publishes no cipher_suites")
    for suite in preference:
        if all(suite in suites and
               suite in set(package_suites.get((uid, mid, device_id), ()))
               for uid, mid, device_id, suites in caps):
            return suite
    raise NoUsableSuite(
        "no suite is published AND package-backed for every addressable "
        "device — keypackage-pool-exhausted (N-03/DR-08)")


class ReservationMismatch(ValueError):
    """A reservation that does not correspond one-for-one with its targets.
    Carries the registry reason so the caller can surface it verbatim."""

    def __init__(self, reason, detail):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def check_reservation(targets, reservation):
    """DR-08: the CLIENT verifies the correspondence rather than trusting the
    DS to have honoured it. Exactly one package per requested target, all of
    the group's suite, no duplicates, no extras. Raises ReservationMismatch
    with the registry reason; returns the (mid, device_id) -> package map."""
    want = {(t["mid"], t["device_id"]) for t in targets}
    if len(want) != len(targets):
        raise ReservationMismatch("keypackage-target-duplicate",
                                  "the request itself names a device twice")
    suite = reservation.get("cipher_suite")
    got = {}
    for pkg in reservation.get("keypackages") or []:
        key = (pkg.get("mid"), pkg.get("device_id"))
        if key in got:
            raise ReservationMismatch(
                "keypackage-target-duplicate",
                f"two packages for {key[0]}/{key[1]} — and therefore, at equal "
                "count, none for some other selected device")
        if key not in want:
            raise ReservationMismatch(
                "keypackage-target-unrequested",
                f"a package for {key[0]}/{key[1]}, which was not selected — "
                "accepting it would add a device the scope resolution excluded")
        if pkg.get("cipher_suite") != suite:
            raise ReservationMismatch(
                "keypackage-target-unavailable",
                f"the package for {key[0]}/{key[1]} is for {pkg.get('cipher_suite')!r}, "
                f"not the group's {suite!r}")
        got[key] = pkg
    missing = want - set(got)
    if missing:
        raise ReservationMismatch(
            "keypackage-target-unavailable",
            "no package for " + ", ".join(f"{m}/{d}" for m, d in sorted(missing))
            + " — a group formed from a partial reservation is a group missing "
              "a member's device")
    return got


# ---------------------------------------------------------------------------
# R4-06 — RECOMPUTE the pinned decision, do not merely read it
# ---------------------------------------------------------------------------

class GroupParamsInvalid(ValueError):
    """R4-06: the pinned cipher-suite decision does not survive recomputation."""


class UnverifiableDecision(ValueError):
    """The decision cannot be recomputed AS IT WAS TAKEN (R12-X4): a v1 record
    binds no inputs, or the formation supplied is not the one it committed to.
    Raised, never returned as a problem: a problem list is a verdict about the
    decision, and nothing has been concluded about it."""


def verify_group_params(params, *, cipher_suite_name, formation, registry):
    """Check that a committed `sbm_group_params` record states a decision that
    is actually TRUE of the group it is committed to.

    R3-08 made `mls_state` commit to the record; nothing checked the record.
    Hashing the GroupContext proves those bytes were retained, so a creator
    could commit a self-consistent but FALSE or DOWNGRADED decision and a
    verifier would validate the hash rather than the selection rule.

    Returns a list of human-readable problems; empty means the decision
    recomputes.

    RETENTION (R4-06 point 4). Everything is judged against the material the
    record itself pins — `floor_version` and the participants' published
    capabilities — not against today's registry. Registry evolution after group
    creation must not invalidate a correctly retained historical decision, and
    checking against the current registry is exactly how it would.

    FORMATION (R12-X4). `formation` is the retained `formation_inputs` record
    — the BW-MEMBER documents and the package availability the decision was
    taken on — and it must be the one the record's `inputs_digest` commits
    to. Members and availability were separate arguments, read from whatever
    the caller held TODAY: a later raise invalidated a correct April decision,
    and a later lowering erased an April violation (R12-06). The unbound form
    is no longer callable.
    """
    import mls_wire
    if params.get("params_version") != 2:
        raise UnverifiableDecision(
            "an sbm_group_params v1 record binds neither the entity of its "
            "raises nor the inputs it was taken on; it cannot be recomputed as "
            "it was taken")
    if formation is None or \
            mls_wire.formation_inputs_digest(formation) != params.get("inputs_digest"):
        raise UnverifiableDecision(
            "the formation supplied is not the one this decision commits to "
            f"(inputs_digest {str(params.get('inputs_digest'))[:16]}…); a "
            "decision is recomputed from its own inputs or not at all")
    members = formation["members"]
    package_suites = {(e["uid"], e["mid"], e["device_id"]): e["suites"]
                      for e in formation["package_suites"]}
    # R10-11: `registry` is REQUIRED. It defaulted to TODAY's registry — the
    # very thing the paragraph above says a retained decision must not be
    # judged against. While the live and the retained registry were both
    # revision 1 nobody could tell; R10-11 was the first registry evolution,
    # and every caller that omitted the argument began judging the demo
    # group's April decision against a September vector. There is no correct
    # default: only the retained material knows which revision a group was
    # formed under.
    if registry is None:
        raise ValueError(
            "verify_group_params needs the RETAINED registry revision the group "
            "was formed under; judging against today's registry is how registry "
            "evolution would invalidate a correct historical decision")
    problems = []
    reg = registry
    # R5-05: the ranking comes from the RETAINED registry, not from the module
    # constant. Everything else here is judged against the revision the record
    # pins — and then the ordering used to compare suites was read from
    # PREFERENCE regardless, so supplying a historical registry changed the
    # ids that were checked but not the order they were checked in. A retained
    # decision must be re-evaluated entirely in its own terms or not at all.
    rank = {s: i for i, s in enumerate(reg["preference_vector"]["order"])}

    # (a) the record names the vector and floor it claims to have applied
    if params.get("preference_vector_id") != reg["preference_vector"]["id"]:
        problems.append(
            f"preference_vector_id {params.get('preference_vector_id')!r} is not "
            f"{reg['preference_vector']['id']!r}")
    if params.get("floor_id") != reg["floor"]["id"]:
        problems.append(
            f"floor_id {params.get('floor_id')!r} is not {reg['floor']['id']!r}")
    if params.get("floor_version") != str(reg["registry_version"]):
        # NOT an error on its own: a historical decision legitimately pins an
        # older registry revision. It IS an error to check such a record
        # against today's floor, so say which revision governs and stop.
        problems.append(
            f"floor_version {params.get('floor_version')!r} is not the current "
            f"{reg['registry_version']!r} — supply the retained registry "
            "revision to verify this decision")
        return problems

    # (b) the selected suite IS the group's actual suite
    if params.get("selected_suite") != cipher_suite_name:
        problems.append(
            f"selected_suite {params.get('selected_suite')!r} is not the "
            f"GroupContext's cipher suite {cipher_suite_name!r} — the record "
            "names one suite while the group runs on another")

    # (c) the device raises match the addressable participants EXACTLY
    # R12-05: raises and publications keyed by the WHOLE principal. Keyed by
    # (mid, device_id), FR's and DE's `F1N2C3D4P/dev-01` collided, and
    # whichever came second in `members` decided the verdict.
    raises = {(r["uid"], r["mid"], r["device_id"]): r["suite"]
              for r in params.get("device_raises") or []}
    if len(raises) != len(params.get("device_raises") or []):
        problems.append("device_raises names one device twice")
    expected = {}
    for m in members:
        for d in addressable_devices(m):
            raised = d.get("min_cipher_suite")
            if raised:
                expected[(m.get("uid"), m.get("mid"), d.get("device_id"))] = raised
    who = "/".join
    for key in raises.keys() - expected.keys():
        problems.append(
            f"device_raises invents a raise for {who(key)} "
            "that the device does not publish")
    for key in expected.keys() - raises.keys():
        problems.append(
            f"device_raises omits {who(key)}, which publishes a raise "
            "to {}".format(expected[key]))
    for key in raises.keys() & expected.keys():
        if raises[key] != expected[key]:
            problems.append(
                f"device_raises says {who(key)} raised to "
                f"{raises[key]!r}, but it publishes {expected[key]!r} — a stale "
                "raise")

    # (d) the effective floor is the MAXIMUM of the mandatory floor and the raises
    strongest = reg["floor"]["suite"]
    for suite in raises.values():
        if rank.get(suite, len(rank)) < rank.get(strongest, len(rank)):
            strongest = suite
    if params.get("effective_floor") != strongest:
        problems.append(
            f"effective_floor {params.get('effective_floor')!r} is not the "
            f"maximum of the mandatory floor and the device raises "
            f"({strongest!r})")

    # (e) the selection is not below that floor, and IS the strongest usable
    selected = params.get("selected_suite")
    if selected in rank and strongest in rank and rank[selected] > rank[strongest]:
        problems.append(
            f"selected_suite {selected!r} is BELOW the effective floor "
            f"{strongest!r} — the group must not have been formed")
    # The availability is part of the formation now, so the strongest-usable
    # arm always runs: there is no call in which it is skipped.
    try:
        # R5-05: the RETAINED vector here too. Fixing only the `rank`
        # map above would have left the recomputation itself ordering by
        # the module constant — the same defect one call deeper, which is
        # how "routed around" happens.
        want = select_suite_for_devices(
            members, package_suites,
            preference=reg["preference_vector"]["order"])
    except (NoUsableSuite, MissingDeviceCapabilities, ValueError) as e:
        problems.append(f"the selection cannot be recomputed: {e}")
    else:
        if selected != want:
            problems.append(
                f"selected_suite {selected!r} is not the strongest usable "
                f"suite for these participants ({want!r}) — a downgrade the "
                "committed record asserts as correct")
    return problems
