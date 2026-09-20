# SPDX-License-Identifier: MIT
"""Discovery-document conformance tests (X8) for scripts/discovery_lint.py."""
import base64
import copy
import importlib.util
import json
import pathlib

import pytest

try:
    import cbor2
except Exception:  # pragma: no cover
    cbor2 = None

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


disc = _load("discovery_lint", "discovery_lint.py")
reconstruct = disc.reconstruct  # M4: decode artefacts

BW_SAMPLES = ["sample-BW-MED.json", "sample-BW-MED-scoped.json", "sample-BW-ORG.json",
              "sample-BW-ORG-scoped.json", "sample-BW-MEMBER.json", "sample-BW-MEMBER-fr.json"]


def _sample(name):
    return reconstruct(json.loads((ROOT / "samples" / name).read_text(encoding="utf-8")))


def _detach_payload(d):
    """Re-encode doc_cose_b64 with a nil (detached) payload — COSE element 2 set
    to None — so the seal no longer embeds the document (M2 / LINT-DISC-07)."""
    cose = cbor2.loads(base64.b64decode(d["doc_cose_b64"]))
    cose[2] = None
    d["doc_cose_b64"] = base64.b64encode(cbor2.dumps(cose)).decode("ascii")


@pytest.mark.parametrize("sample", BW_SAMPLES)
def test_bw_sample_lint_clean(sample):
    assert disc.lint(_sample(sample)) == [], sample


@pytest.mark.parametrize("sample", BW_SAMPLES)
def test_bw_sample_verify_demo_signer(sample):
    """N4/LINT-DISC-15: every discovery sample is sealed by the entity-admin
    signer, so --verify-demo reports no signer-kid violation."""
    rules = [r for r, _ in disc.lint(_sample(sample), verify_demo=True)]
    assert "LINT-DISC-15" not in rules, sample


def _reseal_kid(d, kid):
    """Swap the COSE protected-header kid (label 4) without re-signing — enough to
    exercise the signer-kid check (LINT-DISC-15 reads the kid, not the signature)."""
    cose = cbor2.loads(base64.b64decode(d["doc_cose_b64"]))
    ph = cbor2.loads(cose[0]) if cose[0] else {}
    ph[4] = kid.encode("utf-8")
    cose[0] = cbor2.dumps(ph)
    d["doc_cose_b64"] = base64.b64encode(cbor2.dumps(cose)).decode("ascii")


def test_verify_demo_rejects_wrong_signer_kid():
    """A discovery doc sealed with the RDP evidence kid (not entity-admin) fails --verify-demo."""
    org = copy.deepcopy(_sample("sample-BW-ORG.json"))
    _reseal_kid(org, "rdp")
    rules = [r for r, _ in disc.lint(org, verify_demo=True)]
    assert "LINT-DISC-15" in rules, rules


@pytest.mark.parametrize("sample", BW_SAMPLES)
def test_production_rejects_demo_discovery(sample):
    """N5/LINT-DISC-P: a demo discovery document is not production-conformant — no
    resolvable QSealC identity (P-01) and it carries demo identifiers (P-03)."""
    rules = [r for r, _ in disc.lint(_sample(sample), profile="production")]
    assert "LINT-DISC-P-01" in rules and "LINT-DISC-P-03" in rules, (sample, rules)


def test_production_rejects_rdp_signer():
    """LINT-DISC-P-02: a discovery document sealed by the RDP evidence signer."""
    org = copy.deepcopy(_sample("sample-BW-ORG.json"))
    _reseal_kid(org, "rdp")
    rules = [r for r, _ in disc.lint(org, profile="production")]
    assert "LINT-DISC-P-02" in rules, rules


# (id, sample, expected_rule, mutation)
DISC_NEGATIVE_CASES = [
    ("med-post-seal-mutation", "sample-BW-MED.json", "LINT-DISC-01",
     lambda d: d.update(asserted_at="2099-01-01T00:00:00Z")),
    ("med-bad-ds-url", "sample-BW-MED.json", "LINT-DISC-05",
     lambda d: d["mls"].update(ds_url="http://insecure.example/ds")),
    ("med-bad-uid", "sample-BW-MED.json", "LINT-DISC-03",
     lambda d: d.update(uid="not-a-uid")),
    ("org-missing-policy-version", "sample-BW-ORG.json", "LINT-DISC-04",
     lambda d: d.pop("policy_version")),
    ("org-bad-policy-value", "sample-BW-ORG.json", "LINT-DISC-04",
     lambda d: d["acceptance_policy"].update(invoices="sometimes")),
    ("member-bad-mid", "sample-BW-MEMBER.json", "LINT-DISC-06",
     lambda d: d.update(mid="TOOSHORT")),
    ("member-device-missing-leaf", "sample-BW-MEMBER.json", "LINT-DISC-06",
     lambda d: d["devices"][0].pop("mls_leaf_node_ref")),
    # M1 — BW-MEMBER signed by default: an unsigned member document is rejected.
    ("member-unsigned", "sample-BW-MEMBER.json", "LINT-DISC-01",
     lambda d: d.pop("doc_cose_b64")),
    # M2 — a detached/non-byte COSE payload is a violation (parity with LINT-PKG-06).
    ("med-detached-payload", "sample-BW-MED.json", "LINT-DISC-07", _detach_payload),
    # S1 — confidentiality scope descriptor checks (§8.3a).
    ("scope-missing-recoverability", "sample-BW-ORG-scoped.json", "LINT-DISC-08",
     lambda d: d["scope_map"]["scopes"][0].pop("recoverability")),
    ("scope-bad-recoverability", "sample-BW-ORG-scoped.json", "LINT-DISC-08",
     lambda d: d["scope_map"]["scopes"][0].update(recoverability="loose")),
    ("scope-bad-fallback", "sample-BW-ORG-scoped.json", "LINT-DISC-09",
     lambda d: d["scope_map"].update(fallback="anything-else")),
    # N1 — scope-map semantic integrity (§8.3a). The first three are the reviewer-verified mutations.
    ("scope-duplicate-id", "sample-BW-ORG-scoped.json", "LINT-DISC-10",
     lambda d: d["scope_map"]["scopes"][1].update(scope_id=d["scope_map"]["scopes"][0]["scope_id"])),
    ("scope-duplicate-content-class", "sample-BW-ORG-scoped.json", "LINT-DISC-11",
     lambda d: d["scope_map"]["scopes"][1]["content_classes"].append(
         d["scope_map"]["scopes"][0]["content_classes"][0])),
    ("scope-dangling-policy-ref", "sample-BW-ORG-scoped.json", "LINT-DISC-12",
     lambda d: d["scope_map"]["scopes"][0].update(acceptance_policy_ref="nonexistent-policy")),
    ("scope-unknown-role", "sample-BW-ORG-scoped.json", "LINT-DISC-13",
     lambda d: d["scope_map"]["scopes"][0]["roles"].append("ghost-role")),
    ("scope-reserved-default", "sample-BW-ORG-scoped.json", "LINT-DISC-14",
     lambda d: d["scope_map"]["scopes"][0].update(scope_id="default")),
    # Q5 (tenth review): two-tier content-class registry discipline.
    ("scope-unprefixed-nonstandard-class", "sample-BW-ORG-scoped.json", "LINT-DISC-16",
     lambda d: d["scope_map"]["scopes"][0].update(content_classes=["litigation"])),
    ("scope-malformed-class-shape", "sample-BW-ORG-scoped.json", "LINT-DISC-16",
     lambda d: d["scope_map"]["scopes"][0].update(content_classes=["Legal Notice!"])),
    ("scope-empty-private-class-name", "sample-BW-ORG-scoped.json", "LINT-DISC-16",
     lambda d: d["scope_map"]["scopes"][0].update(content_classes=["x-"])),
    # V0 (thirteenth review, §8.3b): delivery-grade declaration.
    ("grades-bad-value", "sample-BW-ORG.json", "LINT-DISC-17",
     lambda d: d.update(delivery_grades={"invoice": "mailbox"})),
    ("grades-bad-class-key", "sample-BW-ORG.json", "LINT-DISC-17",
     lambda d: d.update(delivery_grades={"UPPER": "availability"})),
    # legal-notice routes to scope 'legal' whose policy is 'all' ⇒ acceptance;
    # declaring verification-grade for it is incoherent.
    ("grades-policy-incoherent", "sample-BW-ORG-scoped.json", "LINT-DISC-18",
     lambda d: d.update(delivery_grades={"legal-notice": "verification"})),
    # F14 (sixteenth review, §8.3a): a scoped entity MUST advertise a
    # member-enumeration surface so the scope-eligible set is resolvable.
    ("scope-map-without-member-endpoint", "sample-BW-ORG-scoped.json", "LINT-DISC-19",
     lambda d: d.pop("member_endpoint")),
    # A2 (Annex R): a system member must publish its scoped mandate.
    ("system-member-without-mandate", "sample-BW-MEMBER-agent.json", "LINT-DISC-20",
     lambda d: d.pop("mandate_ref")),
    # F16 (eighteenth review, §8.3a): the records leaf is declared per scope via
    # records_role — required for records, forbidden for strict, a non-scope org role.
    ("records-scope-without-records-role", "sample-BW-ORG-scoped.json", "LINT-DISC-21",
     lambda d: next(s for s in d["scope_map"]["scopes"]
                    if s["recoverability"] == "records").pop("records_role")),
    ("strict-scope-with-records-role", "sample-BW-ORG-scoped.json", "LINT-DISC-21",
     lambda d: next(s for s in d["scope_map"]["scopes"]
                    if s["recoverability"] == "strict").update(records_role="records")),
    ("records-role-is-a-scope-role", "sample-BW-ORG-scoped.json", "LINT-DISC-21",
     lambda d: next(s for s in d["scope_map"]["scopes"]
                    if s["recoverability"] == "records").update(records_role="finance")),
    # D (twenty-second review): an ack/sign-capable device must publish a usable
    # confirmation_key anchor — present, base64-decodable public key, permitted alg.
    ("ack-device-without-confirmation-key", "sample-BW-MEMBER.json", "LINT-DISC-22",
     lambda d: d["devices"][0].pop("confirmation_key")),
    ("confirmation-key-not-decodable", "sample-BW-MEMBER.json", "LINT-DISC-22",
     lambda d: d["devices"][0]["confirmation_key"].update(public_key_b64="not base64!!")),
    ("confirmation-key-bad-alg", "sample-BW-MEMBER.json", "LINT-DISC-22",
     lambda d: d["devices"][0]["confirmation_key"].update(alg="HS256")),
]


def test_standard_and_private_content_classes_accepted():
    """Q5: every seed standard class and any x- private class pass LINT-DISC-16."""
    doc = copy.deepcopy(_sample("sample-BW-ORG-scoped.json"))
    doc["scope_map"]["scopes"][0]["content_classes"] = sorted(disc.STANDARD_CONTENT_CLASSES)
    doc["scope_map"]["scopes"][1]["content_classes"] = ["x-anything-goes-here"]
    assert not [r for r, _ in disc.lint(doc) if r == "LINT-DISC-16"]


@pytest.mark.parametrize("case", DISC_NEGATIVE_CASES, ids=[c[0] for c in DISC_NEGATIVE_CASES])
def test_discovery_lint_rejects(case):
    _id, sample, rule, fn = case
    doc = copy.deepcopy(_sample(sample))
    fn(doc)
    rules = [r for r, _ in disc.lint(doc)]
    assert rule in rules, f"{_id}: expected {rule}, got {rules}"
