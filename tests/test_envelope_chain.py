# SPDX-License-Identifier: MIT
"""F-02 — the transmitted-octet commitment at every transport boundary.

Former defect: the availability-grade DE (the one grade without a recipient
confirmation) and RelayEvidence carried NO transmitted-octet commitment, so a
substituted ciphertext under unchanged metadata was undetectable at those
boundaries. Evidence 2.2 makes `envelope_hash` REQUIRED on both, with the chain
SE = availability-DE (LINT-DE-17) and SE = each relay hop (LINT-BND-25).

Negative fixtures reproduce the former defect: a hop / availability DE attesting
DIFFERENT octets than the SE is rejected; the field is schema-REQUIRED.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import mls_wire as w  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DEAV = json.load(open(ROOT / "samples" / "sample-DE-availability.json"))["projection"]
B1 = json.load(open(ROOT / "samples" / "sample-RELAY-b1.json"))["projection"]
EPF = json.load(open(ROOT / "samples" / "sample-EP-federated.json"))["projection"]


def test_availability_de_and_relay_carry_the_commitment():
    assert DEAV["envelope_hash"]["format"] == "mls10-message"
    assert B1["envelope_hash"]["format"] == "mls10-message"


def test_schema_requires_the_commitment_at_both_boundaries():
    bad = copy.deepcopy(DEAV); bad.pop("envelope_hash")
    assert lc.validate_body(bad), "availability DE without envelope_hash must fail"
    bad = copy.deepcopy(B1); bad.pop("envelope_hash")
    assert lc.validate_body(bad), "relay evidence without envelope_hash must fail"


def test_negative_availability_de_with_substituted_octets_fails_de17():
    """The chain SE = availability-DE: different octets -> LINT-DE-17."""
    de = copy.deepcopy(DEAV)
    de["envelope_hash"] = w.envelope_hash(b"substituted ciphertext")
    v = el.Violations()
    el.lint_de(v, de, se=copy.deepcopy(SE))
    assert any(r == "LINT-DE-17" for r, _ in v.items), v.items


def test_positive_matching_availability_de_passes_de17():
    de = copy.deepcopy(DEAV)
    de["envelope_hash"] = copy.deepcopy(SE["envelope_hash"])
    v = el.Violations()
    el.lint_de(v, de, se=copy.deepcopy(SE))
    assert not any(r == "LINT-DE-17" for r, _ in v.items), v.items


def _federated_bundle():
    """The shipped federated bundle, reconstructed (docs carry their seals)."""
    m = bl.reconstruct(json.loads(
        (ROOT / "samples" / "bundle.federated.manifest.json").read_text()))
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], [_rc(x) for x in m["evidence"]]]


def test_negative_relay_hop_with_substituted_octets_fails_bnd25():
    """The chain SE = each hop: a hop attesting different octets -> LINT-BND-25."""
    entity, med, org, members, evidence = _federated_bundle()
    mutated = False
    for ev in evidence:
        if ev.get("type") == "RelayEvidence-v1" and ev.get("message_id") == B1["message_id"]:
            ev["envelope_hash"] = w.envelope_hash(b"substituted ciphertext at the hop")
            mutated = True
    assert mutated, "the federated bundle no longer carries the B.1 hop"
    issues = bl.check_bundle(entity, med, org, members, evidence)
    assert any(r == "LINT-BND-25" for r, _ in issues), issues


def test_positive_federated_bundle_chain_is_clean():
    issues = bl.check_bundle(*_federated_bundle())
    assert not [r for r, _ in issues if r == "LINT-BND-25"], issues


def test_positive_the_shipped_hop_chains_with_the_federated_se():
    """b1 shares the federated EP's message_id and the SAME commitment."""
    assert B1["message_id"] == EPF["se"]["message_id"]
    assert B1["envelope_hash"] == EPF["se"]["envelope_hash"]
