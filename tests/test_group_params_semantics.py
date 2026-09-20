# SPDX-License-Identifier: MIT
"""R4-06 — the pinned cipher-suite decision is recomputed, not merely read.

Former defect (round-4 review). R3-08 put the decision into an
`sbm_group_params` GroupContext extension so `mls_state` would commit to it —
and the **only decoder lived inside the KAT test**. The bytes were pinned and
the *decision they encode* was never recomputed, so a creator could commit a
self-consistent but **false or downgraded** record and a verifier would
validate the hash rather than the selection rule.

The review puts it exactly: *hashing the GroupContext proves only that these
bytes were retained, not that the claimed decision was valid.*

That is round 3's fourth invariant again — *a test that asserts a sentence
exists is not a test of the behaviour* — one level up: a test that asserts
**bytes** exist is not a test of the **decision** those bytes assert.

The tampering tests below all **recompute `mls_state` after tampering**, which
is the point: a forged record with a matching hash must still fail. Checking
the hash was never the hard part.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_suite as ms  # noqa: E402
import mls_wire as w  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

GROUP, EPOCH = "Zzw1S4pWq9T5n7xYbXc2dQ", 3
BASELINE = ms.BASELINE
HW = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"


def _members():
    return [json.loads((ROOT / "samples" / f"sample-BW-MEMBER-{x}.json").read_text())
            ["projection"] for x in ("fr", "fr2")]


def _formation(members=None):
    """R12-X4: the inputs a decision is taken on — these members, and each
    addressable device's package availability as it publishes it."""
    members = members or _members()
    return w.formation_inputs(members, {
        (m["uid"], m["mid"], d["device_id"]): d.get("cipher_suites") or []
        for m in members for d in ms.addressable_devices(m)})


def _params(formation=None, **over):
    """A forged record. Built by MUTATING what production writes, so a field
    the producer stops emitting breaks these tests instead of being silently
    absent from the fixture — and so `demo_group_params` keeps the signature
    production needs rather than growing knobs only tests turn.

    R12-X4: the record commits to `formation`, so a forgery here is what
    R4-06 feared — a creator committing to the inputs it really had, and a
    false decision about them."""
    params = w.demo_group_params(inputs=formation)
    params.update(over)
    return params


def _context(params=None, cipher_suite=w.CIPHER_SUITE_BASELINE):
    """A GroupContext whose sbm_group_params says whatever the test wants —
    and whose hash is recomputed over the tampered bytes, so the commitment
    always matches. A forgery with a broken hash proves nothing."""
    return w.demo_group_context(
        GROUP, EPOCH, cipher_suite=cipher_suite,
        extensions=w.sm_mls_extensions(
            "default", "1", group_params=params or w.demo_group_params()))


def _verify(gc, formation=None):
    parsed = w.parse_group_context(gc)
    params = w.group_params_from(parsed["extensions"])
    return ms.verify_group_params(
        params,
        cipher_suite_name=w.CIPHER_SUITE_NAMES.get(parsed["cipher_suite"]),
        formation=formation or _formation(),
        # R10-11: the revision the demo group was FORMED under, not today's.
        registry=json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text()))


# ---------------------------------------------------------------------------
# A production decoder exists at all
# ---------------------------------------------------------------------------

def test_production_can_read_what_production_wrote():
    """The finding: the only decoder was in a test, so nothing outside the
    tests could inspect the committed record."""
    gc = _context()
    parsed = w.parse_group_context(gc)
    params = w.group_params_from(parsed["extensions"])
    assert params["params_version"] == 2
    assert params["floor_id"] == "mls-suite-floor/v1"
    assert params["selected_suite"] == BASELINE


def test_the_shipped_decision_recomputes():
    assert _verify(_context()) == []


def test_a_malformed_extension_fails_closed():
    with pytest.raises(w.GroupParamsError):
        w.parse_group_params(b"\x05not-a-record")
    with pytest.raises(w.GroupParamsError):
        w.parse_group_params_v2(b"\x05not-a-record")


# ---------------------------------------------------------------------------
# The review's acceptance tests — every one recomputes the commitment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("preference_vector_id", "mls-suite-preference/v9"),
    ("floor_id", "mls-suite-floor/v9"),
    ("effective_floor", HW),
])
def test_tampering_a_field_fails_even_with_a_matching_hash(field, value):
    """'Tampering each group-parameter field while recomputing mls_state still
    fails semantic verification.' The hash matches by construction here."""
    params = w.demo_group_params()
    params[field] = value
    gc = _context(params)
    assert hashlib.sha256(gc).hexdigest() == w.mls_state_hash(gc)["hex"], \
        "the fixture must present a VALID commitment over the forged bytes"
    assert _verify(gc), f"a forged {field} passed"


def test_a_selected_suite_that_is_not_the_groups_suite_fails():
    """The record named one suite while the group ran on another, and nothing
    compared them."""
    params = w.demo_group_params(selected_suite=HW)
    problems = _verify(_context(params))          # the context is still baseline
    assert problems and "is not the GroupContext's cipher suite" in problems[0]


def test_an_invented_device_raise_fails():
    params = w.demo_group_params(
        device_raises=[(_members()[0]["uid"], "F1N2C3D4P", "dev-01", HW)])
    problems = _verify(_context(params))
    assert any("invents a raise" in p for p in problems)


def test_an_omitted_device_raise_fails():
    """A creator that drops a raise gets a weaker floor — the downgrade the
    committed record would otherwise assert as correct."""
    members = _members()
    dev = ms.addressable_devices(members[0])[0]
    dev["cipher_suites"] = list(set(dev["cipher_suites"]) | {HW})
    dev["min_cipher_suite"] = HW
    formation = _formation(members)
    problems = _verify(_context(_params(formation)), formation)   # no raises
    assert any("omits" in p for p in problems)


def test_a_stale_device_raise_fails():
    members = _members()
    dev = ms.addressable_devices(members[0])[0]
    dev["cipher_suites"] = list(set(dev["cipher_suites"]) | {HW})
    dev["min_cipher_suite"] = HW
    formation = _formation(members)
    params = _params(formation, effective_floor=HW, selected_suite=BASELINE,
                     device_raises=[(members[0]["uid"], members[0]["mid"],
                                     dev["device_id"], BASELINE)])
    problems = _verify(_context(params), formation)
    assert any("a stale" in p for p in problems)


def test_a_duplicated_device_raise_fails():
    members = _members()
    dev = ms.addressable_devices(members[0])[0]
    dev["cipher_suites"] = list(set(dev["cipher_suites"]) | {HW})
    dev["min_cipher_suite"] = HW
    uid, mid, did = members[0]["uid"], members[0]["mid"], dev["device_id"]
    params = _params(effective_floor=HW, selected_suite=HW,
                     device_raises=[(uid, mid, did, HW), (uid, mid, did, HW)])
    with pytest.raises(ValueError):
        _context(params)         # the serializer rejects it before the wire


def test_a_selection_below_the_effective_floor_fails():
    members = _members()
    for m in members:
        for d in ms.addressable_devices(m):
            d["cipher_suites"] = list(set(d["cipher_suites"]) | {HW})
            d["min_cipher_suite"] = HW
    raises = [(m["uid"], m["mid"], d["device_id"], HW)
              for m in members for d in ms.addressable_devices(m)]
    formation = _formation(members)
    params = _params(formation, effective_floor=HW, selected_suite=BASELINE,
                     device_raises=sorted(raises))
    problems = _verify(_context(params), formation)
    assert any("BELOW the effective floor" in p for p in problems)


def test_registry_evolution_does_not_invalidate_a_retained_decision():
    """The review's fourth acceptance test, and the reason the check reads the
    record's OWN floor_version: a correct historical decision must not become
    wrong because the registry moved."""
    params = w.demo_group_params()
    params["floor_version"] = "1"
    future = {"preference_vector": {"id": "mls-suite-preference/v1",
                                    "order": ms.PREFERENCE},
              "floor": {"id": "mls-suite-floor/v1", "suite": HW},
              "registry_version": 2}
    parsed = w.parse_group_context(_context(params))
    decoded = w.group_params_from(parsed["extensions"])
    problems = ms.verify_group_params(
        decoded, cipher_suite_name=BASELINE, formation=_formation(),
        registry=future)
    assert problems and "supply the retained registry revision" in problems[0], \
        "a stale-registry decision must be reported as unverifiable HERE, not " \
        "silently judged against a floor that did not exist when it was made"


# ---------------------------------------------------------------------------
# The bundle layer runs it
# ---------------------------------------------------------------------------

def _se_committing_to(gc):
    """An SE whose `mls_state` commits to THESE bytes.

    R6-05 made the bundle layer compare the retained context with the
    commitment, so a tampered context is now caught as a SUBSTITUTION before
    semantics. That is right, and it would let the semantic test pass for the
    wrong reason — so the fixture models R4-06's actual threat: a creator that
    commits to its own forged record, self-consistent and false."""
    se = copy.deepcopy(
        json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"])
    se["mls_state"] = w.mls_state_hash(gc)
    return se


def test_the_bundle_layer_recomputes_the_decision():
    params = w.demo_group_params()
    params["effective_floor"] = HW                    # a forged floor
    gc = _context(params)
    se = _se_committing_to(gc)
    issues = [m for r, m in bl.check_bundle(
        se["recipient_uid"], {}, {}, _members(), [se],
        group_contexts={(GROUP, EPOCH): gc},
        # R10-11: the retained revision, as a real bundle carries it. This
        # recomputed against TODAY's registry by default, which is how the
        # first registry evolution would have invalidated the demo decision.
        suite_registry=json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text()),
        formation_inputs=[_formation()]) if r == "LINT-BND-40"]
    assert issues and "effective_floor" in issues[0], issues


def test_a_context_without_the_extension_is_reported():
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    bare = w.demo_group_context(
        GROUP, EPOCH, extensions=[w.required_capabilities_extension(),
                                  w.sbm_scope_extension("default", "1")])
    se = _se_committing_to(bare)
    issues = [m for r, m in bl.check_bundle(
        se["recipient_uid"], {}, {}, _members(), [se],
        group_contexts={(GROUP, EPOCH): bare}) if r == "LINT-BND-40"]
    assert issues and "carries no sbm_group_params" in issues[0], issues


# ---------------------------------------------------------------------------
# R4-U4 — the refusal travels over MLS, and the half-built object is gone
# ---------------------------------------------------------------------------

def test_the_standalone_refusal_schema_is_withdrawn():
    """It had a Schema and no operation, no transport, no signature rule, no
    CDDL, no destination field and no sample — 'addressed to the group creator'
    without representing or authenticating a creator. Half-plumbed is worse
    than either alternative."""
    assert not (ROOT / "schemas" / "group-establishment-refusal.schema.json").exists()
    from lint_cli import TYPE_SCHEMA
    assert "GroupEstablishmentRefusal-v1" not in TYPE_SCHEMA


def test_the_id_specifies_the_PRE_JOIN_return_channel():
    """R5-04/R5-V2 supersedes R4-U4, and the defective sentence was mine.

    R4-U4 routed the refusal over MLS because "the refusing device is already
    an invited member of the group being formed". Invited is not joined: to
    send an authenticated message in that group the device must process the
    Welcome and run the key schedule under the very suite it is refusing as
    below its floor. The transport required doing the thing the refusal exists
    to avoid.
    """
    t = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md")
                 .read_text().replace("**", "").replace("`", "").split())
    assert "POST /welcome/{welcome_id}/refusal" in t
    assert "KeyPackage credential" in t
    assert "INVITED IS NOT JOINED" in t, \
        "the correction should be legible, not silently swapped"
    assert "MUST NOT instantiate a suite it has rejected" in t
    # the alternative, and why it was not taken
    assert "key-distribution problem in order to solve a reporting problem" in t
    # and a silent non-join is still not acceptable
    assert "indistinguishable from an offline device" in t


def test_the_refusal_operation_exists_and_is_device_bound():
    """The R4-U4 failure was a transport that had no operation, no destination
    and no authentication. This one is checked for all three."""
    import yaml
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    op = doc["paths"]["/welcome/{welcome_id}/refusal"]["post"]
    assert {k for b in op["security"] for k in b} == {"deviceAuth", "deviceMtls"}, \
        "a refusal authenticated at member level lets a sibling device refuse"
    ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    # R10-05: a NAMED component, so the reference can execute it.
    body = doc["components"]["schemas"][ref.rsplit("/", 1)[1]]
    assert body["required"] == ["reason", "offered_suite"]
    # R10-05: `required_floor` is required for the floor reason and forbidden
    # for a GroupInfo mismatch.
    assert body["then"] == {"required": ["required_floor"]}
    assert body["else"] == {"not": {"required": ["required_floor"]}}
    reasons = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    # The enum IS the registry: derived, so a registered reason cannot be
    # missing from the wire, nor an unregistered one present on it.
    assert sorted(body["properties"]["reason"]["enum"]) == sorted(
        k for k in reasons["group_establishment_reasons"] if not k.startswith("$"))
    assert "404" in op["responses"], "no cross-device existence oracle"


def test_the_withdrawn_schema_stays_withdrawn():
    assert not (ROOT / "schemas" / "group-establishment-refusal.schema.json").exists()
    from lint_cli import TYPE_SCHEMA
    assert "GroupEstablishmentRefusal-v1" not in TYPE_SCHEMA


# ===========================================================================
# R6-05 — the CLASS: absence, substitution, and incomplete recomputation
# ===========================================================================

def _manifest(**changes):
    """The default manifest with keys removed or replaced, run through the CLI."""
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    for k, v in changes.items():
        if v is None:
            m.pop(k, None)
        else:
            m[k] = v
    t = ROOT / "samples" / "bundle.__r6g.manifest.json"
    t.write_text(json.dumps(m))
    try:
        import subprocess
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bundle_lint.py"), str(t)],
            capture_output=True, text=True)
        return r.returncode, r.stdout
    finally:
        t.unlink()


def test_class_1_ABSENCE_of_the_retained_context_is_not_a_pass():
    """The asymmetry cowork named: round 5 built a verdict so a
    required-but-unestablished property could not pass, then wired it to ONE of
    the two properties it was built for. `bundle.scoped` without
    `group_contexts` printed [OK] exit 0, while the same manifest without
    `policy_history` reported a gap."""
    code, out = _manifest(group_contexts=None)
    assert code != 0, out
    assert "LINT-BND-I4" in out


def test_class_2_SUBSTITUTION_of_a_foreign_context_is_caught():
    """A valid context for another group, filed under this bundle's key. The
    map key was taken on trust, so the evidence committed to one state while
    the verifier semantically inspected another."""
    foreign = w.demo_group_context(
        "XXwrongGroupXXXXXXXXXX", 99,
        extensions=w.sm_mls_extensions("default", "1",
                                       group_params=w.demo_group_params()))
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    issues = [m for r, m in bl.check_bundle(
        se["recipient_uid"], {}, {}, _members(), [copy.deepcopy(se)],
        group_contexts={(se["mls_group_id"], se["mls_epoch"]): foreign})
        if r == "LINT-BND-40"]
    assert issues and "substituted context" in issues[0], issues


def test_an_extra_context_nothing_commits_to_is_reported():
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    extra = w.demo_group_context("OtherGroupOtherGroupAA", 1)
    issues = [m for r, m in bl.check_bundle(
        se["recipient_uid"], {}, {}, _members(), [copy.deepcopy(se)],
        group_contexts={(se["mls_group_id"], se["mls_epoch"]):
                        w.demo_group_context(se["mls_group_id"], se["mls_epoch"]),
                        ("OtherGroupOtherGroupAA", 1): extra})
        if r == "LINT-BND-40"]
    assert issues and "no evidence in this bundle commits to" in issues[0]


def test_class_3_the_CLI_catches_the_downgrade_direct_verification_caught():
    """Round 6's reproduction: every addressable device supports the stronger
    suite and has a package for it, so the baseline selection is a downgrade.
    Direct verification with `package_suites` reported it; the bundle path
    reported nothing, because `_bnd40` passed only the current roster."""
    members = _members()
    for m in members:
        for d in ms.addressable_devices(m):
            d["cipher_suites"] = sorted({*d["cipher_suites"], HW})
    formation = w.formation_inputs(members, {
        (m["uid"], m["mid"], d["device_id"]): [HW, BASELINE]
        for m in members for d in ms.addressable_devices(m)})
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    gc = w.demo_group_context(
        se["mls_group_id"], se["mls_epoch"],
        extensions=w.sm_mls_extensions(
            "default", "1", group_params=w.demo_group_params(inputs=formation)))
    se = copy.deepcopy(se)
    se["mls_state"] = w.mls_state_hash(gc)
    issues = [m for r, m in bl.check_bundle(
        se["recipient_uid"], {}, {}, members, [se],
        group_contexts={(se["mls_group_id"], se["mls_epoch"]): gc},
        formation_inputs=[formation], suite_registry=json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())) if r == "LINT-BND-40"]
    assert issues and "strongest usable" in issues[0], issues


def test_missing_semantic_inputs_yield_a_gap_not_a_clean_verdict():
    """Requirement: 'Missing/stale registry, roster, member version, or
    KeyPackage proof yields incomplete/non-success, never [OK]'."""
    for missing in ("formation_inputs", "suite_registry"):
        code, out = _manifest(**{missing: None})
        assert code != 0, (missing, out)
        assert "LINT-BND-I5" in out, missing


# --- the instrument that stops the third instance ---------------------------

def test_every_required_property_is_declared_and_wired():
    """cowork's proposed instrument, and the reason R6-05 happened: the set of
    properties a green verdict depends on was scattered across call sites, so
    one of them was simply never guarded. It is a declared list now, and
    `check_bundle` iterates it — a property added here fails closed until it is
    wired."""
    decl = json.loads((ROOT / "docs" / "required-properties.json").read_text())
    props = decl["properties"]
    assert props, "the table must not be empty"
    catalogue = {r["id"] for r in json.loads(
        (ROOT / "docs" / "lint-catalogue.json").read_text())["rules"]}
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    for prop in props:
        assert prop["gap_rule"] in catalogue, \
            f"{prop['id']}: its gap rule {prop['gap_rule']} is not catalogued"
        assert prop["input"] in src, \
            f"{prop['id']}: nothing in bundle_lint reads `{prop['input']}`"
        for field in ("establishes", "precondition"):
            assert len(prop.get(field, "")) > 20, f"{prop['id']}: no {field}"
    assert "required-properties.json" in src, \
        "the table must be ITERATED, not merely present"


def test_an_undeclared_property_cannot_be_silently_unguarded(tmp_path):
    """The table fails closed: a property whose material is absent produces its
    gap rule, so adding an entry without wiring the input is visible."""
    decl = json.loads((ROOT / "docs" / "required-properties.json").read_text())
    ids = {p["input"] for p in decl["properties"]}
    assert {"policy_history", "group_contexts", "formation_inputs",
            "suite_registry", "counterparty_members"} <= ids
