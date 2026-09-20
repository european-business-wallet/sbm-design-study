# SPDX-License-Identifier: MIT
"""R3-01 (Blocker) — a message says what it is addressed to, and signs it.

Former defect (round-3 review). `select_policy_key` returned `'default'` for a
missing or empty `recipient_addr` exactly as it did for an explicitly
entity-addressed message:

    addr='bw:uid:…/r/procurement'  ->  'procurement'
    addr=None                      ->  'default'      # silent
    addr=''                        ->  'default'      # silent

So a role-addressed submission could be stripped of its address, sealed under
the weaker `default` policy, and pass both schema validation and LINT-BND-30's
recomputation — because the recomputation used the same stripped input.

And the sender's own signature could not reveal it. `recipient_addr` was not
merely absent from `required` in the SE schema, `SubmissionMetadata` and the D4
tuple: **it was not a property of the signed tuple at all**, so no wallet could
have covered the addressing decision even if it wanted to.

R3-T1: every message is explicitly entity-, role- or member-addressed;
`recipient_addr` and `sender_addr` are REQUIRED in all three artefacts and
inside the signed tuple; absence is the typed rejection
`unaddressed-submission`. Entity addressing is written down, not reached by
omission.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402



# R5-01: intake now recomputes the acceptance policy against the recipient's
# published BW-ORG and verifies the D4 confirmation against the sender device's
# published key, so a submission arrives WITH that material or is refused. A
# thin wrapper keeps every existing case reading as it did.
_R5_ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
_R5_MEMBERS = [json.loads(
    (ROOT / "samples" / "sample-BW-MEMBER.json").read_text())["projection"]]


def _accept(meta, *a, **kw):
    kw.setdefault("org", _R5_ORG)
    kw.setdefault("members", _R5_MEMBERS)
    return mock.accept_submission(meta, *a, **kw)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")
el = _load("evidence_lint", "evidence_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
DEFAULT_SCOPE = {"scope_id": "default", "version": "1"}
ROLE_ADDR = f"bw:uid:{ORG['uid']}/r/procurement"


# ---------------------------------------------------------------------------
# The reproduction, as a negative test
# ---------------------------------------------------------------------------

def test_the_omission_no_longer_reaches_a_policy():
    """The four lines of the finding. The first two still work; the last two
    are rejections now, not silent downgrades."""
    assert lc.select_policy_key(ORG, DEFAULT_SCOPE, ROLE_ADDR) == "procurement"
    assert lc.select_policy_key(ORG, DEFAULT_SCOPE, f"bw:uid:{ORG['uid']}") == "default"
    for missing in (None, "", "   "):
        with pytest.raises(lc.UnaddressedSubmission):
            lc.select_policy_key(ORG, DEFAULT_SCOPE, missing)


def test_stripping_the_address_can_no_longer_downgrade_the_policy():
    """The attack end to end: take a role-addressed submission, drop the
    address, and try to have it govern under `default`."""
    assert lc.select_policy_key(ORG, DEFAULT_SCOPE, ROLE_ADDR) == "procurement"
    with pytest.raises(lc.UnaddressedSubmission):
        lc.select_policy_key(ORG, DEFAULT_SCOPE, None)


# ---------------------------------------------------------------------------
# REQUIRED in all three artefacts
# ---------------------------------------------------------------------------

def test_the_se_schema_requires_both_addresses():
    se = json.loads((ROOT / "schemas" / "evidence-se.schema.json").read_text())
    for field in ("recipient_addr", "sender_addr"):
        assert field in se["required"], field


def test_the_signed_tuple_carries_and_requires_both_addresses():
    """The half that makes the rest enforceable. Before R3-01 the tuple had no
    such property, so the addressing decision sat outside the signature."""
    sc = json.loads((ROOT / "schemas" / "evidence-common.schema.json")
                    .read_text())["$defs"]["SenderConfirmation"]
    for field in ("recipient_addr", "sender_addr"):
        assert field in sc["properties"], field
        assert field in sc["required"], field
        assert field in lc.D4_COPIED_FIELDS, field


def test_the_submission_contract_requires_both_addresses():
    sub = yaml.safe_load((ROOT / "wallet-rdp-openapi.yaml").read_text())[
        "components"]["schemas"]["SubmissionMetadata"]
    for field in ("recipient_addr", "sender_addr"):
        assert field in sub["required"], field


def test_one_definition_of_the_signed_field_set():
    """R3-01 had to be applied in three places — the builder, the regenerator
    and the comparison. Missing one produced samples whose tuple disagreed with
    its own schema, so the list has one home now."""
    for name in ("mock_rdp.py", "regen_samples.py", "evidence_lint.py"):
        src = (ROOT / "scripts" / name).read_text()
        assert "D4_COPIED_FIELDS" in src, name


# ---------------------------------------------------------------------------
# Rejected at intake, and again at verification
# ---------------------------------------------------------------------------

def _submission(**over):
    meta = {
        "message_id": "01HZ3ADDR0000000000000001",
        "sender_uid": SE["sender_uid"], "sender_addr": SE["sender_addr"],
        "recipient_uid": SE["recipient_uid"], "recipient_addr": SE["recipient_addr"],
        "scope_ref": SE["scope_ref"], "payload_hash": SE["payload_hash"],
        "mls_message_b64": "AAECAwQF" * 4,
        "mls_group_id": SE["mls_group_id"], "mls_epoch": SE["mls_epoch"],
        "auth_method": SE["auth_method"], "auth_context": SE["auth_context"],
        "sent_at": SE["sent_at"], "expires_at": SE["expires_at"],
        "origin_proof": SE["origin_proof"],
        "acceptance_policy_ref": SE["acceptance_policy_ref"],
    }
    meta.update(over)
    # R5-01: origin_proof 'sender-signed' REQUIRES the D4 confirmation — the SE
    # schema says so with an if/then, and intake now enforces it too. These
    # fixtures declared the posture and omitted the proof, and were accepted,
    # because nothing at intake had the material to check. A real wallet signs
    # the tuple it is actually sending, so the fixture does the same.
    if meta.get("origin_proof") == "sender-signed" and \
            "sender_confirmation" not in meta:
        import base64 as _b64
        import copy as _copy
        import mls_wire as _w
        from lint_cli import D4_COPIED_FIELDS
        # The two commitments are DERIVED from these octets, not borrowed from
        # another message: intake compares them with what RDP(out) computes, so
        # a tuple describing different bytes is exactly what must fail.
        _derived = {}
        try:
            _oct = _b64.b64decode(meta.get("mls_message_b64") or "", validate=True)
            _derived["envelope_hash"] = _w.envelope_hash(_oct)
            _derived["mls_state"] = _w.mls_state_hash(_w.demo_group_context(
                meta["mls_group_id"], meta["mls_epoch"],
                scope_id=(meta.get("scope_ref") or {}).get("scope_id", "default"),
                scope_version=(meta.get("scope_ref") or {}).get("version", "1")))
        except Exception:
            pass                       # a malformed-octets case: leave as given
        sc = _copy.deepcopy(SE["sender_confirmation"])
        for field in D4_COPIED_FIELDS:
            if field in _derived:
                sc[field] = _derived[field]
            elif field in meta:
                sc[field] = meta[field]
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
        meta["sender_confirmation"] = sc
    return meta


def setup_function():
    mock._SUBMISSION_LEDGER.clear()


@pytest.mark.parametrize("field", ["recipient_addr", "sender_addr"])
def test_an_unaddressed_submission_is_rejected_before_sealing(field):
    meta = _submission()
    meta.pop(field)
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta)
    assert exc.value.reason == "unaddressed-submission"
    assert mock._SUBMISSION_LEDGER == {}, "a rejected submission left state behind"


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_address_is_not_an_address(empty):
    with pytest.raises(mock.SubmissionRejected):
        _accept(_submission(recipient_addr=empty))


def test_an_addressed_submission_is_accepted():
    accepted = _accept(_submission())
    assert accepted["envelope_hash"]["format"] == "mls10-message"


def test_a_verifier_also_fails_closed_on_an_unaddressed_se():
    """A bundle is verified long after the RDP that accepted it, so the
    verifier must reach the same verdict rather than trusting intake."""
    se = copy.deepcopy(SE)
    se.pop("recipient_addr")
    issues = bl.check_bundle(SE["recipient_uid"], {}, ORG, [], [se])
    assert [m for r, m in issues if r == "LINT-BND-30" and "no recipient_addr" in m]


# ---------------------------------------------------------------------------
# The signature now covers the addressing decision
# ---------------------------------------------------------------------------

def test_re_addressing_a_sealed_se_breaks_its_signed_tuple():
    """The property R3-01 exists to create: change what the message was
    addressed to, and the sender's own signed act no longer describes it."""
    se = copy.deepcopy(SE)
    assert se["sender_confirmation"]["recipient_addr"] == se["recipient_addr"]
    se["recipient_addr"] = f"bw:uid:{ORG['uid']}/r/legal"      # a stronger policy
    issues = [m for r, m in el.lint(mock.evidence_artifact(se)) if r == "LINT-DE-19"]
    assert issues, "the re-addressed SE was not caught by the signed tuple"
    assert "recipient_addr" in issues[0]


def test_every_shipped_se_is_explicitly_addressed():
    """Including the ones that are entity-addressed: the entity address is
    written down, which is the decision R3-T1 made."""
    checked = 0
    for f in sorted((ROOT / "samples").glob("sample-*.json")):
        proj = json.loads(f.read_text()).get("projection")
        if not isinstance(proj, dict):
            continue
        bodies = [proj] + ([proj["se"]] if isinstance(proj.get("se"), dict) else [])
        for se in bodies:
            if se.get("type") != "SE-v1":
                continue
            assert se.get("recipient_addr"), f.name
            assert se.get("sender_addr"), f.name
            checked += 1
    assert checked >= 4


def test_the_typed_reason_is_registered():
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    row = reg["nde_reasons"]["unaddressed-submission"]
    assert row["status"] == "active"
    assert row["stages"] == {"intake": "A.2-SubmissionRejection"}
