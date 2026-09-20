# SPDX-License-Identifier: MIT
"""F-04 — the MLS leaf credential is bound to the entity by a signed device binding.

The former defect: the I-D said the leaf credential "chains to the entity's
QSealC" with no mechanism, and the RFC 9420 rule that the LeafNode signature key
IS the credential key was stated nowhere. This batch profiles a signed device
binding (BW-MEMBER 2.1, mls_leaf_binding) — a COSE_Sign1 by the entity seal key
over {uid, mid, device_id, leaf_sig_pubkey_b64} — and LINT-DISC-23 enforces
leaf-key equality, the binding content, and (demo) the binding signature.

Pilot/demo scope: the production certificate profile (Basic Constraints / KU /
EKU / name constraints / revocation) and QSealC-chain validation are deferred to
the production verifier. The negative fixtures reproduce the machine-checkable
half — a leaf key that is not the bound key, a binding for another device, and a
binding not signed by the entity — each rejected fail-closed.
"""
import base64
import copy
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import discovery_lint as dl  # noqa: E402
import mock_rdp as mock  # noqa: E402
from lint_cli import reconstruct  # noqa: E402

MEMBER = reconstruct(json.load(open(ROOT / "samples/sample-BW-MEMBER.json")))


def _hits(doc, dev, i=0):
    v = dl.Violations()
    dl._check_leaf_binding(v, doc, dev, i)
    return [r for r, _ in v.items]


def test_positive_valid_binding_passes():
    dev = MEMBER["devices"][0]
    assert dev.get("mls_leaf_binding"), "the re-sealed sample must carry a binding"
    assert _hits(MEMBER, dev) == [], "a valid signed binding must pass"


def test_negative_leaf_key_is_not_the_bound_key():
    """RFC 9420: the LeafNode signature key must equal the credential key."""
    doc = copy.deepcopy(MEMBER)
    dev = doc["devices"][0]
    dev["mls_leaf_node_ref"]["signature_key_hash"] = "ab" * 32  # wrong hash
    assert "LINT-DISC-23" in _hits(doc, dev)


def test_negative_binding_is_for_another_device():
    """A binding that binds a different device_id must be rejected."""
    doc = copy.deepcopy(MEMBER)
    dev = doc["devices"][0]
    skh, other = mock._leaf_binding(doc["uid"], doc["mid"], "SOME-OTHER-DEVICE")
    # keep leaf-key equality (so only the content check can fire), swap the binding
    dev["mls_leaf_node_ref"]["signature_key_hash"] = skh
    dev["mls_leaf_binding"] = other
    hits = _hits(doc, dev)
    assert "LINT-DISC-23" in hits


def test_negative_binding_not_signed_by_the_entity():
    """A binding signed by a non-entity key must not verify."""
    doc = copy.deepcopy(MEMBER)
    dev = doc["devices"][0]
    lpk = dev["mls_leaf_binding"]["leaf_sig_pubkey_b64"]
    content = {"uid": doc["uid"], "mid": doc["mid"],
               "device_id": dev["device_id"], "leaf_sig_pubkey_b64": lpk}
    # correct content + kid, but signed by the wallet key, not the entity key.
    forged = mock.cose_sign(mock._dcbor(content), kid="entity-admin", seed="wallet-demo")
    dev["mls_leaf_binding"]["binding_cose_b64"] = base64.b64encode(forged).decode()
    assert "LINT-DISC-23" in _hits(doc, dev)


def test_binding_is_optional_when_absent():
    doc = copy.deepcopy(MEMBER)
    dev = doc["devices"][0]
    dev.pop("mls_leaf_binding", None)
    assert _hits(doc, dev) == [], "the binding is OPTIONAL in the pilot profile"
