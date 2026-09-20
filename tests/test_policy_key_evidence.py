# SPDX-License-Identifier: MIT
"""F-08 — evidence identifies the exact acceptance-policy key.

Former defect: `acceptance_policy_ref` carried {policy_version, doc_digest}
only — the document, never the KEY selected within it. The shipped samples
proved the indeterminism: the SE addressed `…/r/invoices` (policy `any-one`)
while the DE evaluated `quorum`, and nothing tied the evaluated kind to any
key — two keys in one BW-ORG produced indistinguishable evidence.

Evidence 2.4: `acceptance_policy_ref.policy_key` (REQUIRED) records the key
selected by the X-12 deterministic algorithm. It rides everywhere the ref
already is — SE, DE, the s3/refusal confirmations, and the X-03 sender tuple
(`sender_confirmation.acceptance_policy_ref` copies the whole ref), so the
sender's wallet SIGNS the selected key. LINT-BND-30 recomputes the selection
from the pinned ORG and binds the DE's evaluated kind to the keyed policy.

Negative fixtures reproduce the former defect: the 2.3 ref shape (no key) is
schema-rejected; a key differing from the recomputed selection, a key unknown
to the pinned ORG, and a DE kind differing from the keyed policy (the shipped
mismatch, verbatim) all fail LINT-BND-30.
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

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]
SES = json.load(open(ROOT / "samples" / "sample-SE-scoped.json"))["projection"]
DES = json.load(open(ROOT / "samples" / "sample-DE-scoped.json"))["projection"]


# ---------------------------------------------------------------------------
# Schema: the ref names the key; the 2.3 shape is gone
# ---------------------------------------------------------------------------

def test_shipped_evidence_names_the_selected_key():
    assert SE["acceptance_policy_ref"]["policy_key"] == "procurement"
    assert DE["acceptance_policy_ref"]["policy_key"] == "procurement"
    assert SES["acceptance_policy_ref"]["policy_key"] == "finance"
    assert DES["acceptance_policy_ref"]["policy_key"] == "finance"
    for body in (SE, DE, SES, DES):
        assert not lc.validate_body(copy.deepcopy(body))


def test_negative_the_23_ref_shape_without_a_key_is_schema_rejected():
    """The former defect verbatim: a ref naming the document but no key."""
    bad = copy.deepcopy(SE)
    bad["acceptance_policy_ref"].pop("policy_key")
    bad["sender_confirmation"]["acceptance_policy_ref"].pop("policy_key")
    assert lc.validate_body(bad), "acceptance_policy_ref without policy_key must fail"


def test_the_sender_signs_the_selected_key():
    """The X-03 tuple copies the whole ref — the key is under the sender's
    wallet signature, so a swapped key cannot go unnoticed."""
    sc = SE["sender_confirmation"]
    assert sc["acceptance_policy_ref"]["policy_key"] == "procurement"
    assert sc["acceptance_policy_ref"] == SE["acceptance_policy_ref"]


def test_the_confirmation_ref_matches_the_des(  # LINT-DE-13 rides along
):
    assert DE["s3_attestation"]["acceptance_policy_ref"] == \
        DE["acceptance_policy_ref"]


# ---------------------------------------------------------------------------
# LINT-BND-30: the selection is recomputed, the kind is bound
# ---------------------------------------------------------------------------

def _bundle(manifest):
    m = json.loads((ROOT / "samples" / manifest).read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], [_rc(x) for x in m["evidence"]]]


def _bnd30(entity, med, org, members, evidence):
    issues = bl.check_bundle(entity, med, org, members, evidence)
    return [msg for r, msg in issues if r == "LINT-BND-30"]


def test_positive_the_shipped_bundles_recompute_clean():
    for manifest in ("bundle.default.manifest.json",
                     "bundle.scoped.manifest.json",
                     "bundle.walletsig.manifest.json",
                     "bundle.federated.manifest.json"):
        b = _bundle(manifest)
        assert not _bnd30(*b), (manifest, _bnd30(*b))


def test_negative_a_key_differing_from_the_selection_fails():
    """Role-addressed to procurement, but the evidence claims 'legal'."""
    b = _bundle("bundle.default.manifest.json")
    for ev in b[4]:
        apr = ev.get("acceptance_policy_ref")
        if isinstance(apr, dict):
            apr["policy_key"] = "legal"
    assert _bnd30(*b), "a policy_key != the recomputed selection must fail"


def test_negative_a_key_unknown_to_the_pinned_org_fails():
    b = _bundle("bundle.default.manifest.json")
    se = next(e for e in b[4] if e.get("type") == "SE-v1")
    se["acceptance_policy_ref"]["policy_key"] = "ghost-key"
    assert _bnd30(*b)


def test_negative_the_former_shipped_mismatch_now_fails():
    """The finding's reproduction: an invoices (any-one) selection under a
    quorum-evaluated DE — indistinguishable in 2.3, rejected in 2.4."""
    b = _bundle("bundle.default.manifest.json")
    for ev in b[4]:
        apr = ev.get("acceptance_policy_ref")
        if isinstance(apr, dict):
            apr["policy_key"] = "invoices"
        s3 = ev.get("s3_attestation")
        if isinstance(s3, dict) and isinstance(s3.get("acceptance_policy_ref"), dict):
            s3["acceptance_policy_ref"]["policy_key"] = "invoices"
        if ev.get("type") == "SE-v1":
            ev["recipient_addr"] = ev["recipient_addr"].rsplit("/r/", 1)[0] + "/r/invoices"
    msgs = _bnd30(*b)
    assert any("acceptance_policy_kind" in m for m in msgs), \
        "the quorum DE under the any-one key must fail the kind binding"


def test_negative_a_scoped_chain_claiming_another_scopes_key_fails():
    b = _bundle("bundle.scoped.manifest.json")
    se = next(e for e in b[4] if e.get("type") == "SE-v1")
    se["acceptance_policy_ref"]["policy_key"] = "legal"
    assert _bnd30(*b), "the finance scope's chain cannot claim the legal key"
