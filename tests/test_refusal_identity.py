# SPDX-License-Identifier: MIT
"""X-29 — refusal identity: WHO refused, with proof.

Former defect: RE-v1 was an RDP-only assertion. Nothing distinguished "the
member refused" from "our policy refused", and a provider could claim a user
act (refused-by-user) with no user proof at all — the mirror image of the
acceptance hole that finding D closed for confirmations.

Evidence 2.3: `refusal_kind` ("member" | "organisation-policy") is REQUIRED.
A member refusal names the mid, carries auth_context and a recipient-produced
`refusal_confirmation` (the s3-style wallet-signed / session-authenticated
choice) covering the refused message; a policy refusal names the published
acceptance_policy_ref and never claims a user act. LINT-RE-01 enforces the
coherence; LINT-BND-29 resolves the refusing member against the roster and
verifies the wallet signature against the published confirmation_key anchor —
the same finding-D machinery as an acceptance.

TODO(legal): the respective Article 43(2) evidential weight of the two kinds
(and of the provider-attested narrowed session mode) awaits counsel review —
marked in the schema descriptions and left OPEN; nothing here asserts legal
effect.

Negative fixtures reproduce the former defect: an RDP-only "the user refused",
a policy refusal claiming a user act, a confirmation covering a different
message, an unknown refusing member, and a refusal minted under a foreign key
are all rejected.
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


el = _load("evidence_lint", "evidence_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

RE = json.load(open(ROOT / "samples" / "sample-RE.json"))["projection"]
REP = json.load(open(ROOT / "samples" / "sample-RE-policy.json"))["projection"]
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def _re01(body):
    v = el.Violations()
    el.lint_re(v, body)
    return [msg for r, msg in v.items if r == "LINT-RE-01"]


# ---------------------------------------------------------------------------
# Schema: the shape is enforced
# ---------------------------------------------------------------------------

def test_both_shipped_refusals_are_schema_valid():
    assert not lc.validate_body(copy.deepcopy(RE))
    assert not lc.validate_body(copy.deepcopy(REP))


def test_refusal_kind_and_scope_ref_are_required():
    for field in ("refusal_kind", "scope_ref"):
        bad = copy.deepcopy(RE); bad.pop(field)
        assert lc.validate_body(bad), f"RE without {field} must fail"


def test_member_refusal_requires_the_member_proof_trio():
    for field in ("mid", "auth_context", "refusal_confirmation"):
        bad = copy.deepcopy(RE); bad.pop(field)
        assert lc.validate_body(bad), f"member RE without {field} must fail"


def test_policy_refusal_never_claims_a_user_act():
    bad = copy.deepcopy(REP)
    bad["reason"] = "refused-by-user"
    assert lc.validate_body(bad), \
        "organisation-policy refusal with reason refused-by-user must fail"
    bad = copy.deepcopy(REP)
    bad["refusal_confirmation"] = copy.deepcopy(RE["refusal_confirmation"])
    assert lc.validate_body(bad), \
        "organisation-policy refusal carrying a member confirmation must fail"


def test_policy_refusal_requires_the_published_policy_ref():
    bad = copy.deepcopy(REP); bad.pop("acceptance_policy_ref")
    assert lc.validate_body(bad), "policy RE without acceptance_policy_ref must fail"


def test_session_arm_is_valid_and_the_two_arms_are_exclusive():
    ok = copy.deepcopy(RE)
    rc = ok["refusal_confirmation"]
    rc.pop("device_id"); rc.pop("wallet_signature_b64")
    rc["session_authenticated"] = True
    rc["session_binding"] = {"kind": "token-digest", "digest": "ab" * 32}
    assert not lc.validate_body(ok), "session-authenticated refusal arm must validate"
    both = copy.deepcopy(RE)
    both["refusal_confirmation"]["session_authenticated"] = True
    assert lc.validate_body(both), "a confirmation claiming BOTH arms must fail"


# ---------------------------------------------------------------------------
# LINT-RE-01: kind/reason/proof coherence (the former defect, reproduced)
# ---------------------------------------------------------------------------

def test_shipped_refusals_are_re01_clean():
    assert not _re01(copy.deepcopy(RE))
    assert not _re01(copy.deepcopy(REP))


def test_negative_rdp_only_user_refusal_is_rejected():
    """The former defect verbatim: refused-by-user with no member proof."""
    bad = copy.deepcopy(RE); bad.pop("refusal_confirmation")
    assert _re01(bad), "an RDP-only assertion of a user act must fail LINT-RE-01"


def test_negative_policy_refusal_claiming_a_user_act_is_rejected():
    bad = copy.deepcopy(REP)
    bad["reason"] = "refused-by-user"
    assert _re01(bad), "organisation-policy + refused-by-user must fail LINT-RE-01"


def test_negative_member_refusal_with_wrong_reason_is_rejected():
    bad = copy.deepcopy(RE)
    bad["reason"] = "legal-hold"   # registry-bound to organisation-policy
    assert _re01(bad)


def test_negative_confirmation_covering_a_different_message_is_rejected():
    """The proof must cover the refused message — not be a replayed one."""
    for field, other in (("message_id", "01HZ3OTHERMESSAGE00000000"),
                         ("mid", "F2X3Y4Z55")):
        bad = copy.deepcopy(RE)
        bad["refusal_confirmation"][field] = other
        assert _re01(bad), f"refusal_confirmation.{field} mismatch must fail"
    bad = copy.deepcopy(RE)
    bad["refusal_confirmation"]["payload_hash"] = \
        {"alg": "SHA-256", "hex": "f" * 64, "hash_mode": "raw-sha256"}
    assert _re01(bad), "refusal_confirmation.payload_hash mismatch must fail"


# ---------------------------------------------------------------------------
# LINT-BND-29: the refusing member resolves, the signature verifies
# ---------------------------------------------------------------------------

def _bundle_with(re_body):
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    evidence = [_rc(x) for x in m["evidence"]] + [re_body]
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], evidence]


def _bnd29(re_body):
    issues = bl.check_bundle(*_bundle_with(re_body))
    return [msg for r, msg in issues if r == "LINT-BND-29"]


def test_positive_the_shipped_member_refusal_resolves_in_the_bundle():
    assert not _bnd29(copy.deepcopy(RE))


def test_negative_unknown_refusing_member_fails_bnd29():
    bad = copy.deepcopy(RE)
    bad["mid"] = "ZZZZZZZZ0"
    bad["refusal_confirmation"]["mid"] = "ZZZZZZZZ0"
    assert _bnd29(bad), "a refusal by an unknown mid must fail LINT-BND-29"


def test_negative_refusal_minted_under_a_foreign_key_fails_bnd29():
    """Finding-D mirror: a provider minting 'the user refused' under its own
    key does not verify against the member's PUBLISHED confirmation key."""
    bad = copy.deepcopy(RE)
    rc = {k: v for k, v in bad["refusal_confirmation"].items()
          if k != "wallet_signature_b64"}
    import os
    os.environ["WALLET_SEED"] = "attacker-provider-key"
    try:
        rc["wallet_signature_b64"] = mock._wallet_sign(rc)
    finally:
        del os.environ["WALLET_SEED"]
    bad["refusal_confirmation"] = rc
    assert _bnd29(bad), "a foreign-key refusal signature must fail LINT-BND-29"


def test_negative_wallet_signed_refusal_without_device_id_fails_bnd29():
    bad = copy.deepcopy(RE)
    bad["refusal_confirmation"].pop("device_id")
    assert _bnd29(bad), "no device_id -> no resolvable anchor -> LINT-BND-29"


# ---------------------------------------------------------------------------
# Chain coherence with the SE
# ---------------------------------------------------------------------------

def test_the_shipped_refusal_covers_the_se_message():
    assert RE["message_id"] == SE["message_id"]
    assert RE["payload_hash"] == SE["payload_hash"]
    assert RE["refusal_confirmation"]["payload_hash"] == SE["payload_hash"]
