# SPDX-License-Identifier: MIT
"""X-12 — BW-ORG and default-policy semantics are self-contained.

Former defect: the umbrella introduced BW-ORG as "Unchanged from v1.0 review
except" (a baseline not in the document set), presented `acceptance_policy`
as a scalar while schema/samples use a RoleName-keyed map, and defined no
required default key and no selection algorithm for unscoped entity
addressing — the upstream defect behind F-08.

BW-ORG 2.4: `acceptance_policy` is REQUIRED, non-empty, with the reserved
key `default` REQUIRED (eligible set = the ENTIRE active membership); the
umbrella §8.3 defines the deterministic three-case selection algorithm,
implemented once as `lint_cli.select_policy_key`; LINT-DISC-24 rejects a
published ORG without the default key.

Negative fixtures reproduce the former defect: an ORG without the map, or
without `default`, is rejected (schema + LINT-DISC-24); an unsatisfiable
`default` fails the bundle rules; every address/scope tuple selects exactly
one key across the shipped ORGs.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("discovery_lint", "discovery_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")

def _load_org(name):
    """The projection is the schema-facing body; reconstruct() adds the seal
    material lint_org needs — keep the projection so validate_body applies."""
    return json.loads((ROOT / "samples" / name).read_text())["projection"]


ORG = _load_org("sample-BW-ORG.json")
ORGS = _load_org("sample-BW-ORG-scoped.json")


def _disc24(org):
    v = dl.Violations()
    dl.lint_org(v, org)
    return [msg for r, msg in v.items if r == "LINT-DISC-24"]


# ---------------------------------------------------------------------------
# Schema + LINT-DISC-24: the default key is REQUIRED
# ---------------------------------------------------------------------------

def test_shipped_orgs_carry_the_default_key_and_validate():
    for org in (ORG, ORGS):
        assert org["acceptance_policy"]["default"] == "any-one"
        assert not lc.validate_body(copy.deepcopy(org))
        assert not _disc24(copy.deepcopy(org))


def test_negative_org_without_acceptance_policy_is_rejected():
    """The former defect: nothing required any policy map at all."""
    bad = copy.deepcopy(ORG); bad.pop("acceptance_policy")
    assert lc.validate_body(bad), "BW-ORG without acceptance_policy must fail schema"
    assert _disc24(bad), "and must fail LINT-DISC-24"


def test_negative_org_without_the_default_key_is_rejected():
    bad = copy.deepcopy(ORG); bad["acceptance_policy"].pop("default")
    assert lc.validate_body(bad), "no 'default' key must fail schema"
    assert _disc24(bad), "and must fail LINT-DISC-24"


def test_negative_empty_policy_map_is_rejected():
    bad = copy.deepcopy(ORG); bad["acceptance_policy"] = {}
    assert lc.validate_body(bad)


# ---------------------------------------------------------------------------
# The deterministic selection algorithm (one implementation)
# ---------------------------------------------------------------------------

ADDR = "bw:uid:EU-FR-PSBID-ZYWVTSRQPNM8M4"


def test_scoped_message_selects_the_scope_policy_key():
    # R3-01: these used to pass None for "the address is irrelevant to a
    # scoped selection". It IS irrelevant to the outcome — but a submission
    # without one is now rejected before the outcome is reached, so the tests
    # carry a real address like every conforming message.
    assert lc.select_policy_key(
        ORGS, {"scope_id": "legal", "version": "1"}, ADDR) == "legal"
    assert lc.select_policy_key(
        ORGS, {"scope_id": "finance", "version": "1"}, ADDR) == "finance"


def test_default_scope_role_addressed_selects_the_role_key():
    assert lc.select_policy_key(
        ORG, {"scope_id": "default", "version": "1"},
        f"{ADDR}/r/procurement") == "procurement"


def test_default_scope_role_without_own_key_falls_back_to_default():
    """A declared role with no policy key of its own selects `default` —
    deterministic, and distinguishable in evidence (F-08 records the key)."""
    org = copy.deepcopy(ORG)
    org.setdefault("roles", []).append("shipping")
    assert lc.select_policy_key(
        org, {"scope_id": "default", "version": "1"},
        f"{ADDR}/r/shipping") == "default"


def test_default_scope_entity_addressed_selects_default():
    assert lc.select_policy_key(ORG, {"scope_id": "default", "version": "1"},
                                ADDR) == "default"
    assert lc.select_policy_key(ORG, None, ADDR) == "default"


def test_an_unaddressed_submission_is_rejected_not_defaulted():
    """R3-01 (Blocker), the reproduction. `default` used to be reached BOTH by
    an explicit entity address and by omitting the address, so stripping the
    address from a role-addressed submission silently selected the weaker
    policy — and the sender's signature could not reveal it, since
    `recipient_addr` was not even a property of the signed tuple."""
    scope = {"scope_id": "default", "version": "1"}
    assert lc.select_policy_key(ORG, scope, f"{ADDR}/r/procurement") == "procurement"
    for missing in (None, "", "   "):
        with pytest.raises(lc.UnaddressedSubmission):
            lc.select_policy_key(ORG, scope, missing)


def test_the_address_is_inside_the_signed_tuple():
    """The half that makes the rest enforceable: an address the sender does
    not sign is an address that can be changed after the fact."""
    import json
    sc = json.loads((ROOT / "schemas" / "evidence-common.schema.json")
                    .read_text())["$defs"]["SenderConfirmation"]
    for field in ("recipient_addr", "sender_addr"):
        assert field in sc["properties"], field
        assert field in sc["required"], field
    assert field in lc.D4_COPIED_FIELDS


def test_unmatched_scope_selects_nothing():
    """No implicit choice: the unmatched scope is the upstream typed
    rejection (no-matching-scope / LINT-BND-04)."""
    assert lc.select_policy_key(
        ORGS, {"scope_id": "ghost", "version": "1"}, ADDR) is None


def test_every_tuple_selects_exactly_one_key_across_the_shipped_orgs():
    for org in (ORG, ORGS):
        keys = set(org["acceptance_policy"])
        scopes = ((org.get("scope_map") or {}).get("scopes") or [])
        tuples = [({"scope_id": s["scope_id"], "version": s["version"]}, ADDR)
                  for s in scopes]
        tuples += [({"scope_id": "default", "version": "1"}, f"{ADDR}/r/{r}")
                   for r in (org.get("roles") or [])]
        tuples += [({"scope_id": "default", "version": "1"}, ADDR)]
        for sref, addr in tuples:
            k = lc.select_policy_key(org, sref, addr)
            assert k in keys, (sref, addr, k)


# ---------------------------------------------------------------------------
# Bundle: the default key must be satisfiable over the whole membership
# ---------------------------------------------------------------------------

def _bundle_rules(org):
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    issues = bl.check_bundle(m["entity_uid"], _rc(m["med"]), org,
                             [_rc(x) for x in m["members"]],
                             [_rc(x) for x in m["evidence"]])
    return [r for r, _ in issues]


def test_positive_the_shipped_default_key_is_satisfiable():
    rules = _bundle_rules(copy.deepcopy(ORG))
    assert "LINT-BND-08" not in rules and "LINT-BND-09" not in rules, rules


def test_negative_unsatisfiable_default_fails_the_bundle():
    """default's eligible set is the ENTIRE active membership — a quorum
    larger than the roster is unsatisfiable."""
    bad = copy.deepcopy(ORG)
    bad["acceptance_policy"]["default"] = "quorum:99"
    assert "LINT-BND-08" in _bundle_rules(bad)


# ---------------------------------------------------------------------------
# Self-containment: the delta framing is gone
# ---------------------------------------------------------------------------

def test_the_umbrella_definition_is_self_contained():
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    assert "Unchanged from v1.0 review except" not in umb
    assert "Acceptance-policy selection (normative)" in umb
