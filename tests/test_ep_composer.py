# SPDX-License-Identifier: MIT
"""F-13 / D2 — the sender-side RDP composes the Evidence Package, always.

Former defect: BW-ORG could designate a third-party ep_authority while the TS
normatively said the sender-side RDP composes — a contradiction, and the EP body
had no authority field so the rule was not self-describing. Per the settled D2
the delegation field is REMOVED (BW-ORG 2.3); the EP signer is bound to
se.rdp_id in the trust store (CF-6, LINT-TRUST-02) — a non-sender-RDP composer
cannot produce a valid aggregate EP.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def test_bw_org_with_ep_authority_is_schema_rejected():
    """The removed field cannot return silently (additionalProperties: false)."""
    org = json.load(open(ROOT / "samples" / "sample-BW-ORG.json"))["projection"]
    bad = dict(org, ep_authority="EU-DE-EOID-7K3D9W0Q2M5FW0")
    assert lc.validate_body(bad), "a BW-ORG carrying the removed field must fail"


def test_ep_signer_is_bound_to_the_sender_rdp():
    """D2's negative: an EP sealed under a kid whose trust-store identities do
    not include se.rdp_id is rejected (LINT-TRUST-02 with identity=se.rdp_id)."""
    store = lc.load_trust_store(str(ROOT / "samples" / "trust-store.demo.json"))
    ep = lc.reconstruct(json.load(open(ROOT / "samples" / "sample-EP.json")))
    seal = ep["seal"]["cose_b64"]
    # the real signer identity (the composing sender-side RDP)
    ok = lc.check_trust(ep, seal, store, "evidence-rdp",
                        identity=ep["se"]["rdp_id"])
    assert ok == [], ok
    # a third-party composer: an identity the store does not list for this kid
    bad = lc.check_trust(ep, seal, store, "evidence-rdp",
                         identity="urn:sbm:rdp:thirdparty-999")
    assert any(r == "LINT-TRUST-02" for r, _ in bad), bad


def test_composer_rule_prose_is_single_owner():
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    assert "sender-side RDP, always" in umb
    ep_schema = (ROOT / "schemas" / "evidence-ep.schema.json").read_text()
    assert "SENDER-SIDE RDP, always" in ep_schema
