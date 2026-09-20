# SPDX-License-Identifier: MIT
"""R5-01 (Blocker) — intake performs what the contract assigns it.

Two halves, one finding.

**(a) The obligations were structurally impossible.** The published wallet-RDP
contract says RDP(out) "RECOMPUTES the selection (`lint_cli.select_policy_key`)
and REJECTS a disagreeing submission with a typed reason BEFORE sealing",
"validates the sender_confirmation", and "checks that the pinned policy version
was in force at `sent_at`". The signature was:

    accept_submission(meta, retained_group_context=None, *, principal=...)

No BW-ORG. No member roster. No confirmation key. **Not a missing call — a
missing input.** On addresses it checked `isinstance(str)` and non-empty. A
contract describing behaviour the reference implementation cannot perform is
worse than one describing none, because implementers calibrate against the
reference.

**(b) Two parsers agreed with each other and neither agreed with the Schema.**
The round-4 test asserted the two spellings equal, under a docstring saying
that two spellings of one grammar is the R4 family. They were equal, and both
were wrong: each put `(u|r)` in front of BOTH value alternatives, so kind and
value were not bound and all four combinations parsed —
`…/u/procurement` and `…/r/F1N2C3D4P` are accepted by the parsers and forbidden
by the Schema. **Agreement between copies is not correctness.** The fix is not
to reconcile the copies but to remove the second authority: acceptance is now
the Schema's own `BwAddress` pattern, read from the published file.

Note what is checked against WHAT. Two of the D4 fields — `envelope_hash` and
`mls_state` — are compared with the values RDP(out) DERIVED from the octets it
received, not with the submission's own copies. Comparing a sender-supplied
confirmation against sender-supplied metadata compares two statements by one
party and proves nothing; this is DR-02's pattern applied to the D4 tuple.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import re
import sys

import yaml

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import mls_wire as w  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
MEMBERS = [json.loads(
    (ROOT / "samples" / "sample-BW-MEMBER.json").read_text())["projection"]]
OCTETS = b"\x01\x02" + b"intake obligations" * 4


def setup_function():
    mock._SUBMISSION_LEDGER.clear()


def _meta(**over):
    meta = {
        "message_id": "01HZ5INTAKE00000000000001",
        "sender_uid": SE["sender_uid"], "sender_addr": SE["sender_addr"],
        "recipient_uid": SE["recipient_uid"],
        "recipient_addr": SE["recipient_addr"],
        "scope_ref": SE["scope_ref"], "payload_hash": SE["payload_hash"],
        "mls_message_b64": base64.b64encode(OCTETS).decode(),
        "mls_group_id": SE["mls_group_id"], "mls_epoch": SE["mls_epoch"],
        "auth_method": SE["auth_method"], "auth_context": SE["auth_context"],
        "sent_at": SE["sent_at"], "expires_at": SE["expires_at"],
        "origin_proof": SE["origin_proof"],
        "acceptance_policy_ref": copy.deepcopy(SE["acceptance_policy_ref"]),
    }
    meta.update(over)
    if meta.get("origin_proof") == "sender-signed" and \
            "sender_confirmation" not in meta:
        try:
            meta["sender_confirmation"] = _confirmation(meta)
        except (ValueError, TypeError, KeyError):
            # R8-01: the D4 tuple commits to values DERIVED from the
            # submission, so a submission malformed enough (a non-integer
            # epoch, an incomplete `scope_ref`) cannot have one computed for
            # it at all. That is the honest state for such a request — a
            # wallet could not have produced a tuple either.
            pass
    return meta


def _other_valid(field, value):
    """A DIFFERENT value that is still valid under the published Schema.

    R8-01: these fixtures used the literal string `"tampered"` (and `{"x": 1}`
    for objects). Once intake executed the whole request Schema rather than two
    projections of it, those values were refused as MALFORMED — so the test
    passed on a structural error while claiming to prove a semantic one, and
    the copied-field rule it names was never reached. A mismatch has to be
    well-formed to be a mismatch; a malformed value is a different finding.
    """
    if isinstance(value, dict):
        out = copy.deepcopy(value)
        for key in ("hex", "scope_id", "policy_version", "version"):
            if isinstance(out.get(key), str):
                cur = out[key]
                if key == "hex":
                    out[key] = ("f" * len(cur) if not cur.startswith("f")
                                else "0" * len(cur))
                elif key == "version":
                    out[key] = str(int(cur) + 1) if cur.isdigit() else cur + "9"
                else:
                    out[key] = cur + "-other"
                return out
        raise AssertionError(f"no alternative valid value defined for {field}")
    if field.endswith("_at"):                      # IsoTimestamp
        return value.replace("2026", "2025", 1)
    if field.endswith("_uid"):                     # Uid: keep the grammar
        return value[:-1] + ("A" if value[-1] != "A" else "B")
    if field.endswith("_addr"):                    # BwAddress: change the role
        return value.rsplit("/", 1)[0] + "/other"
    return value[:-1] + ("A" if value[-1] != "A" else "B")   # message_id


def _confirmation(meta, **tamper):
    """A D4 tuple signed over what this submission actually carries."""
    octets = base64.b64decode(meta["mls_message_b64"], validate=True)
    derived = {
        "envelope_hash": w.envelope_hash(octets),
        "mls_state": w.mls_state_hash(w.demo_group_context(
            meta["mls_group_id"], meta["mls_epoch"],
            scope_id=meta["scope_ref"]["scope_id"],
            scope_version=meta["scope_ref"]["version"])),
    }
    sc = copy.deepcopy(SE["sender_confirmation"])
    for field in lc.D4_COPIED_FIELDS:
        sc[field] = derived.get(field, meta.get(field))
    sc.update(tamper)
    sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    return sc


def _accept(meta, **kw):
    kw.setdefault("org", ORG)
    kw.setdefault("members", MEMBERS)
    return mock.accept_submission(meta, **kw)


def _rejects(meta, reason, **kw):
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta, **kw)
    assert exc.value.reason == reason, f"got {exc.value.reason!r}"
    return exc.value


# ===========================================================================
# (a) the obligations, each proved to FIRE
# ===========================================================================

def test_a_coherent_submission_is_accepted():
    accepted = _accept(_meta())
    assert accepted["envelope_hash"]["hex"]


def test_the_policy_key_is_RECOMPUTED_and_a_disagreement_is_refused():
    """The contract's central sentence: 'the wallet's copy is a commitment; the
    RDP's computation is the authority'. Nothing recomputed anything."""
    meta = _meta()
    meta["acceptance_policy_ref"]["policy_key"] = "invoices"     # not what it is
    meta["sender_confirmation"] = _confirmation(meta)
    e = _rejects(meta, "policy-key-mismatch")
    assert "the published BW-ORG selects" in e.detail
    # ...and the authority is the shared implementation, not a second copy.
    assert lc.select_policy_key(ORG, meta["scope_ref"],
                                meta["recipient_addr"]) == "procurement"


def test_a_policy_reference_to_another_document_is_refused():
    meta = _meta()
    meta["acceptance_policy_ref"]["doc_digest"]["hex"] = "b" * 64
    meta["sender_confirmation"] = _confirmation(meta)
    _rejects(meta, "policy-digest-mismatch")


def test_a_policy_not_yet_in_force_at_sent_at_is_refused():
    """LINT-BND-33's rule, applied where refusing is still possible. A verifier
    catches it years later; intake can decline to seal."""
    future = copy.deepcopy(ORG)
    future["valid_from"] = "2026-09-01T00:00:00Z"          # after sent_at
    # The reference must PIN this document, or the digest check fires first and
    # this arm is never reached — the ordering is correct, so the fixture
    # follows it rather than the assertion being relaxed.
    meta = _meta()
    meta["acceptance_policy_ref"]["doc_digest"]["hex"] = mock._org_body_digest(future)
    meta["sender_confirmation"] = _confirmation(meta)
    e = _rejects(meta, "policy-not-in-force", org=future)
    assert "did not yet exist when the act took place" in e.detail


def test_a_foreign_recipient_address_is_refused_at_intake_too():
    """R4-01 closed this for the verifier. Intake could not perform it at all,
    because it had no BW-ORG to select from."""
    meta = _meta(recipient_addr="bw:uid:EU-DE-EOID-7K3D9W0Q2M5FW0/r/procurement")
    meta["sender_confirmation"] = _confirmation(meta)
    # R6-01: the reason sharpened. R4-01 could only say "this address is
    # foreign to the policy being selected"; the identity resolver says WHICH
    # two statements disagree, and it fires before any commitment is computed.
    _rejects(meta, "identity-incoherent")


# --- the sender confirmation ------------------------------------------------

def test_a_sender_signed_submission_without_the_tuple_is_refused():
    """The SE schema requires `sender_confirmation` when origin_proof is
    'sender-signed' (an if/then). Intake accepted such submissions, so the
    reference produced what its own schema rejects."""
    meta = _meta()
    del meta["sender_confirmation"]
    _rejects(meta, "sender-confirmation-missing")


def test_a_tuple_signed_over_OTHER_octets_is_refused():
    """The check that matters, and the reason it compares against the DERIVED
    commitment: a confirmation whose `envelope_hash` describes a different
    message is a signature over a different act."""
    meta = _meta()
    meta["sender_confirmation"] = _confirmation(
        meta, envelope_hash=w.envelope_hash(b"entirely different octets"))
    e = _rejects(meta, "sender-confirmation-mismatch")
    assert "RDP(out) computed from the submitted octets" in e.detail


@pytest.mark.parametrize("field", ["message_id", "recipient_uid", "sender_addr",
                                   "recipient_addr", "scope_ref", "sent_at"])
def test_every_copied_field_must_equal_the_submission(field):
    """The field list is `lint_cli.D4_COPIED_FIELDS`, shared with the verifier
    (R3-01), so the tuple cannot drift between intake and verification."""
    assert field in lc.D4_COPIED_FIELDS
    meta = _meta()
    sc = _confirmation(meta)
    sc[field] = _other_valid(field, sc[field])
    sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    meta["sender_confirmation"] = sc
    _rejects(meta, "sender-confirmation-mismatch")


def test_a_confirmation_that_does_not_verify_is_refused():
    """R8-01: the signature must be WELL-FORMED and wrong. It used to be the
    base64 of `b"not a signature"`, which the published Schema rejects on
    length — so once intake ran the contract the test proved a structural
    refusal, not a failed verification. A signature of the right shape over the
    wrong thing is what this rule is for."""
    meta = _meta()
    sc = _confirmation(meta)
    good = base64.b64decode(sc["wallet_signature_b64"])
    forged = bytes(b ^ 0xFF for b in good[:1]) + good[1:]
    sc["wallet_signature_b64"] = base64.b64encode(forged).decode()
    meta["sender_confirmation"] = sc
    _rejects(meta, "sender-confirmation-invalid")


def test_a_confirmation_from_an_unpublished_device_is_refused():
    meta = _meta()
    sc = _confirmation(meta)
    sc["device_id"] = "dev-99-not-published"
    sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    meta["sender_confirmation"] = sc
    e = _rejects(meta, "sender-confirmation-unverifiable")
    assert "is not published by member" in e.detail, e.detail


# --- fail closed ------------------------------------------------------------

@pytest.mark.parametrize("missing,reason", [
    ({"org": None}, "policy-unresolvable"),
    ({"members": None}, "sender-confirmation-unverifiable"),
])
def test_missing_discovery_material_refuses_rather_than_skips(missing, reason):
    """The direction that decides whether this fix is real. 'Skip the check
    when the material is absent' is how R4-02's silent downgrade worked and how
    R5-02's false green survived; an unperformable check must refuse."""
    _rejects(_meta(), reason, **missing)


# ===========================================================================
# (b) one parser, and the authority is the Schema
# ===========================================================================

def _schema_pattern():
    schema = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    return re.compile(schema["$defs"]["BwAddress"]["pattern"])


UID = ORG["uid"]
ADDRESSES = [
    f"bw:uid:{UID}",
    f"bw:uid:{UID}/r/procurement",
    f"bw:uid:{UID}/u/F1N2C3D4P",
    f"bw:uid:{UID}/u/procurement",          # kind/value crossed
    f"bw:uid:{UID}/r/F1N2C3D4P",            # kind/value crossed
    f"bw:uid:{UID}/x/other",
    f"bw:uid:{UID}/r/",
    f"bw:uid:{UID}/u/TOOLONGMID12",
    "bw:uid:NOPE", "not-an-address", "",
    f"BW:UID:{UID}",
    f"bw:uid:{UID}/r/UPPER",
]


@pytest.mark.parametrize("addr", ADDRESSES)
def test_the_parser_accepts_exactly_what_the_schema_accepts(addr):
    """The review's own probe, generalised. The round-4 test compared the two
    parsers with each other; this compares the parser with the AUTHORITY."""
    assert bool(_schema_pattern().fullmatch(addr)) == \
        (lc.parse_bw_address(addr) is not None), addr


def test_the_crossed_forms_are_the_ones_that_used_to_pass():
    """Named individually so the regression is legible rather than buried in a
    parametrised sweep."""
    for addr in (f"bw:uid:{UID}/u/procurement", f"bw:uid:{UID}/r/F1N2C3D4P"):
        assert lc.parse_bw_address(addr) is None, addr
        with pytest.raises(lc.ForeignAddress):
            lc.select_policy_key(ORG, {"scope_id": "default", "version": "1"}, addr)


def test_there_is_only_one_parser_now():
    """Invariant 3: the superseded spelling is DELETED, not left reachable.
    Two implementations of one grammar is how this defect existed at all."""
    bl_src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert "_BW_ADDR_RE" not in bl_src, \
        "bundle_lint still carries its own address regex"
    assert bl_src.count("re.compile(\n    r\"^bw:uid:") == 0
    # and the one that remains takes its grammar from the published schema
    cli_src = (ROOT / "scripts" / "lint_cli.py").read_text()
    assert 'schema["$defs"]["BwAddress"]["pattern"]' in cli_src


def test_the_bundle_layer_uses_the_same_parser():
    bl = _load("bundle_lint", "bundle_lint.py")
    for addr in ADDRESSES:
        assert bl._parse_bw_address(addr) == lc.parse_bw_address(addr), addr


# ===========================================================================
# The reasons are REGISTERED, not invented at the surface
# ===========================================================================

def test_every_intake_reason_is_in_the_registry():
    """The contract promised 'the registry reasons (no-matching-scope, ...)'
    while no registry section held them, so 'typed' meant 'a string the mock
    happened to use'. A client switching on these needs them enumerated."""
    # R6-01: intake reasons now come from TWO places — mock_rdp's own
    # rejections and the shared identity resolver in lint_cli, which returns
    # (reason, detail) pairs. Both are scanned, because a reason a client must
    # switch on is no less real for being raised by the shared helper.
    src = (ROOT / "scripts" / "mock_rdp.py").read_text()
    shared = (ROOT / "scripts" / "lint_cli.py").read_text()
    raised = set(re.findall(r'SubmissionRejected\(\s*"([a-z-]+)"', src))
    for pat in (r'add\("([a-z-]+)"', r'out\.append\(\("([a-z-]+)"',
                r'return \[\("([a-z-]+)"',
                # R7-04: the identity adapter raises its own typed error, which
                # the entry points re-raise verbatim via `e.reason` — so those
                # reasons reach a client and must be registered like any other.
                r'RdpIdentityError\(\s*"([a-z-]+)"',
                # R7-01: the request validator raises its own typed error,
                # re-raised verbatim by intake — same rule as the identity
                # adapter above.
                r'SubmissionInvalid\(\s*"([a-z-]+)"'):
        raised |= set(re.findall(pat, shared))
    # Batch A: `validate_status_history` lives in this module and raises
    # MEMBERSHIP-register reasons — no message is involved, so they are not
    # submission rejections and are registered in their own block. Scanning the
    # whole file and checking everything against the intake block would file
    # them by which module they happen to share, not by what they are.
    membership_body = shared[shared.index("def validate_status_history"):]
    membership_body = membership_body[:membership_body.index("\ndef ")]
    membership = set(re.findall(r'\(\s*"(membership-[a-z-]+)"', membership_body))
    raised -= membership

    registry = json.loads(
        (ROOT / "registries" / "reason-codes.json").read_text())
    assert membership <= set(registry["membership_register_reasons"]), \
        "raised but unregistered (membership): " \
        f"{sorted(membership - set(registry['membership_register_reasons']))}"
    registered = set(registry["submission_rejection_reasons"])
    assert raised - registered == set(), \
        f"raised but unregistered: {sorted(raised - registered)}"
    assert registered - raised == set(), \
        f"registered but never raised — a phantom: {sorted(registered - raised)}"


def test_the_contract_points_at_the_registry_section():
    y = (ROOT / "wallet-rdp-openapi.yaml").read_text()
    assert "submission_rejection_reasons" in y, \
        "the 422 response should name the registry section a client reads"


# ===========================================================================
# R6-01 (Blocker) — the identity tuple must be COHERENT, not merely valid
# ===========================================================================
#
# R5-01 made intake verify each statement. It never compared them. The review's
# vector re-signs the D4 tuple so it is internally consistent with the
# mutation, which is the whole point: the only thing standing between the old
# code and this was "an attacker cannot re-sign", and the sender's own wallet
# is exactly the party the check exists to constrain. Cowork could not run it
# without the signing key; with the key, five of six vectors were accepted and
# one SEALED an SE naming two different legal entities.

DE_UID = "EU-DE-EOID-7K3D9W0Q2M5FW0"


def _submit(meta, members=None, org=None):
    mock._SUBMISSION_LEDGER.clear()
    mock._DS_LEDGER.clear()
    mock._SE_LEDGER.clear()
    return mock.submit(meta, org=org or ORG, members=members or MEMBERS)


def _submit_fails(meta, reason, members=None, org=None):
    with pytest.raises(mock.SubmissionRejected) as exc:
        _submit(meta, members, org)
    assert exc.value.reason == reason, f"got {exc.value.reason!r}"
    return exc.value


def test_the_recipient_tuple_must_name_ONE_entity():
    """The review's vector verbatim: a German `recipient_uid` with a French
    `recipient_addr` and a French BW-ORG. It was accepted, transported, and
    sealed into an SE, with no Schema issue — every field independently valid.
    """
    _submit_fails(_meta(recipient_uid=DE_UID), "identity-incoherent")


def test_the_sender_tuple_must_name_ONE_entity():
    """The symmetric case, and it fails EVEN WITH A VALID D4 SIGNATURE — the
    signature is over a tuple whose own fields disagree."""
    e = _submit_fails(_meta(sender_uid=ORG["uid"]), "identity-incoherent")
    assert "the signature is valid and it is not this entity's" in e.detail \
        or "the acting entity and the addressed entity differ" in e.detail


def test_a_member_addressed_sender_must_name_the_member_that_signed():
    _submit_fails(
        _meta(sender_addr=f"bw:uid:{SE['sender_uid']}/u/F1N2C3D4P"),
        "identity-incoherent")


def test_a_role_addressed_sender_must_hold_that_role():
    _submit_fails(
        _meta(sender_addr=f"bw:uid:{SE['sender_uid']}/r/legal"),
        "identity-incoherent")


def test_the_entity_addressed_sender_case_is_permitted():
    """Required change 4 asks for this case to be DEFINED, not merely left
    working by accident: an entity-addressed sender means 'this entity,
    unspecified member', and the confirmation still has to resolve."""
    _submit(_meta(sender_addr=f"bw:uid:{SE['sender_uid']}"))


@pytest.mark.parametrize("status", ["suspended", "retired"])
def test_a_member_not_active_at_the_act_cannot_sign(status):
    m = copy.deepcopy(MEMBERS[0])
    m["status"] = status
    _submit_fails(_meta(), "member-not-active", members=[m])


def test_a_device_without_the_sign_capability_cannot_sign():
    """`sign` was a declared capability with NO stated meaning that nothing
    enforced — and the shipped samples signed the D4 tuple with a device
    published as ["receive", "ack"]. The umbrella now defines the capability as
    an authorisation and this refuses a device that lacks it."""
    m = copy.deepcopy(MEMBERS[0])
    for d in m["devices"]:
        if d["device_id"] == "dev-01":
            d["capabilities"] = ["receive", "ack"]
    _submit_fails(_meta(), "device-not-sign-capable", members=[m])


def test_the_shipped_signing_devices_declare_sign():
    """The sample fix, asserted so it cannot regress: a device that signs in
    the published evidence must be authorised to."""
    for name, device in (("sample-BW-MEMBER.json", "dev-01"),
                         ("sample-BW-MEMBER-agent.json", "agent-host-01")):
        doc = json.loads((ROOT / "samples" / name).read_text())
        body = doc.get("projection", doc)
        dev = next(d for d in body["devices"] if d["device_id"] == device)
        assert "sign" in dev["capabilities"], f"{name}:{device}"


def test_a_device_added_after_the_act_cannot_have_signed_it():
    m = copy.deepcopy(MEMBERS[0])
    for d in m["devices"]:
        if d["device_id"] == "dev-01":
            d["added_at"] = "2026-06-01T00:00:00Z"        # after sent_at
    _submit_fails(_meta(), "device-not-in-force", members=[m])


def test_a_device_removed_before_the_act_cannot_have_signed_it():
    m = copy.deepcopy(MEMBERS[0])
    for d in m["devices"]:
        if d["device_id"] == "dev-01":
            d["removed_at"] = "2026-01-01T00:00:00Z"
    _submit_fails(_meta(), "device-not-in-force", members=[m])


# --- the scope, exactly ------------------------------------------------------

SCOPED_ORG = json.loads(
    (ROOT / "samples" / "sample-BW-ORG-scoped.json").read_text())["projection"]


def _scoped_meta(**over):
    meta = _meta(recipient_addr=f"bw:uid:{SCOPED_ORG['uid']}/r/procurement",
                 **over)
    meta["acceptance_policy_ref"]["doc_digest"]["hex"] = \
        mock._org_body_digest(SCOPED_ORG)
    meta["acceptance_policy_ref"]["policy_version"] = SCOPED_ORG["policy_version"]
    meta["sender_confirmation"] = _confirmation(meta)
    return meta


def test_an_undeclared_scope_version_is_refused():
    """`select_policy_key` matched on `scope_id` alone, so a submitted version
    nobody published still reached a real policy key."""
    _submit_fails(_scoped_meta(scope_ref={"scope_id": "finance", "version": "9"}),
                  "no-matching-scope", org=SCOPED_ORG)


def test_a_scope_not_yet_in_force_at_the_act_is_refused():
    org = copy.deepcopy(SCOPED_ORG)
    for s in org["scope_map"]["scopes"]:
        s["valid_from"] = "2026-09-01T00:00:00Z"          # after sent_at
    meta = _scoped_meta(scope_ref={"scope_id": "finance", "version": "1"})
    meta["acceptance_policy_ref"]["doc_digest"]["hex"] = mock._org_body_digest(org)
    meta["sender_confirmation"] = _confirmation(meta)
    _submit_fails(meta, "scope-not-in-force", org=org)


# --- the ledger binds the whole submission identity --------------------------

def test_reusing_the_handle_for_another_message_is_a_typed_collision():
    """Requirement 8. The reservation recorded the envelope digest alone, so
    the same ciphertext under a different recipient, payload, scope or policy
    was not a collision — the path returned the previously sealed SE and the
    changed metadata went unreported."""
    first = _meta()
    _submit(first)
    # payload changed, everything else identical
    again = _meta(payload_hash={"alg": "SHA-256", "hex": "c" * 64,
                                "hash_mode": "raw-sha256"})
    with pytest.raises(mock.SubmissionRejected) as exc:
        mock.submit(again, org=ORG, members=MEMBERS)
    assert exc.value.reason == "duplicate-message-id"
    assert "payload_hash" in exc.value.detail

    # a different ADDRESS, with its policy key updated so the submission is
    # otherwise coherent — otherwise the policy gate fires first, which is the
    # correct order and would leave this arm untested.
    other = _meta(recipient_addr=f"bw:uid:{ORG['uid']}")
    other["acceptance_policy_ref"]["policy_key"] = "default"
    other["sender_confirmation"] = _confirmation(other)
    with pytest.raises(mock.SubmissionRejected) as exc:
        mock.submit(other, org=ORG, members=MEMBERS)
    assert exc.value.reason == "duplicate-message-id"
    assert "recipient_addr" in exc.value.detail


def test_nothing_is_reserved_when_the_identity_is_incoherent():
    """Requirement 7: the semantic gate runs BEFORE any ledger mutation, so a
    refused submission leaves nothing to reconcile."""
    mock._SUBMISSION_LEDGER.clear()
    mock._DS_LEDGER.clear()
    with pytest.raises(mock.SubmissionRejected):
        mock.submit(_meta(recipient_uid=DE_UID), org=ORG, members=MEMBERS)
    assert mock._SUBMISSION_LEDGER == {}, "a rejected submission was reserved"
    assert mock._DS_LEDGER == {}, "a rejected submission reached the DS"


# --- and the verifier reaches the same verdict -------------------------------

def test_the_resolver_is_SHARED_with_bundle_validation():
    """Requirement 1. R6-01 exists at all because a check lived on one side of
    a boundary, so the fix is one implementation called from both."""
    import helper_integration as hi
    sites = hi.call_sites("check_identity_coherence", hi.production_modules())
    assert {s.module for s in sites} == {"mock_rdp.py", "bundle_lint.py"}


def _bl():
    return _load("bundle_lint", "bundle_lint.py")


def _bundle_rules(se, members=None, counterparty=None, org=None):
    bl = _bl()
    return [(r, m) for r, m in bl.check_bundle(
        (org or ORG)["uid"], {}, org or ORG, members or [], [copy.deepcopy(se)],
        counterparty_members=counterparty)]


def test_LINT_BND_41_reaches_the_same_verdict_as_intake():
    """The shared resolver over RETAINED evidence: a verifier holding the SE
    years later must reach the verdict the provider should have reached. R6-01
    exists because a check lived on one side of that boundary."""
    se = copy.deepcopy(SE)
    se["recipient_uid"] = DE_UID                    # the review's own vector
    rules = [r for r, _ in _bundle_rules(se, counterparty=MEMBERS)]
    assert "LINT-BND-41" in rules


def test_LINT_BND_41_catches_a_device_that_may_not_sign():
    m = copy.deepcopy(MEMBERS[0])
    for d in m["devices"]:
        if d["device_id"] == "dev-01":
            d["capabilities"] = ["receive", "ack"]
    msgs = [msg for r, msg in _bundle_rules(copy.deepcopy(SE), counterparty=[m])
            if r == "LINT-BND-41"]
    assert msgs and "sign" in msgs[0]


def test_LINT_BND_I2_reports_the_undecidable_half_rather_than_passing_it():
    """Without the counterparty roster the sender-side tuple cannot be checked
    from this material. Round 5 built a verdict for exactly that, and using it
    is the difference between an honest gap and a silent pass."""
    bl = _bl()
    issues = _bundle_rules(copy.deepcopy(SE), counterparty=None)
    gaps = [m for r, m in issues if r == "LINT-BND-I2"]
    assert gaps and "cannot be checked from this material" in gaps[0]
    assert bl.incomplete_of(issues), "it must be INCOMPLETE, not a violation"
    assert not [r for r, _ in bl.violations(issues) if r == "LINT-BND-41"]


def test_every_positive_bundle_carries_the_counterparty_roster():
    for name in ("bundle.default", "bundle.federated", "bundle.scoped",
                 "bundle.walletsig"):
        m = json.loads((ROOT / "samples" / f"{name}.manifest.json").read_text())
        assert m.get("counterparty_members"), name


# ===========================================================================
# R7-04 (X1) — the canonical identity governs the value space it names
# ===========================================================================

def test_the_grammar_is_ONE_definition_reused_everywhere():
    """The finding: `rdpAuth` stated a precise grammar and `RdpId` was
    `{type: string, minLength: 1}`, so the rule governed nothing downstream.
    A precise identity rule over an unconstrained value space is a rule about
    nothing."""
    common = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    rdp = common["$defs"]["RdpId"]
    assert rdp.get("pattern", "").startswith("^urn:sbm:rdp:")
    # No schema states the grammar a second time.
    for f in (ROOT / "schemas").glob("*.json"):
        if f.name == "evidence-common.schema.json":
            continue
        assert "urn:sbm:rdp" not in f.read_text(), \
            f"{f.name} restates the grammar instead of $ref-ing RdpId"
    # R8-05: the "at least 7 schemas MENTION RdpId" half is DELETED, not kept
    # alongside. It measured existence, not coverage — a field declared
    # `{"type": "string"}` mentions neither `RdpId` nor the grammar, so it
    # satisfied both halves while saying nothing, and three such fields sat in
    # these very Schemas. `test_every_provider_identity_field_refs_the_one_
    # definition` asks the question this one could not.


def test_the_code_reads_the_grammar_from_the_schema():
    """A second copy of the pattern in Python would be the same defect with a
    smaller radius."""
    src = (ROOT / "scripts" / "lint_cli.py").read_text()
    pattern = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text()
    )["$defs"]["RdpId"]["pattern"]
    assert pattern not in src, "the pattern is restated in lint_cli.py"
    assert '["$defs"]["RdpId"]["pattern"]' in src


def test_every_shipped_rdp_id_is_canonical():
    """Requirement 2: samples, trust store and relay chains regenerated. A
    grammar nothing on disk satisfies is a claim, not a rule."""
    bad = []
    for f in sorted((ROOT / "samples").glob("*.json")):
        for m in re.finditer(r'"(?:rdp_id|issuing_rdp_id)"\s*:\s*"([^"]+)"',
                             f.read_text()):
            if not m.group(1).startswith("urn:sbm:rdp:"):
                bad.append(f"{f.name}: {m.group(1)}")
    assert not bad, bad


@pytest.mark.parametrize("principal", [
    "not-a-canonical-rdp", "RDP:MockEU:001", "", "urn:sbm:rdp:", "URN:SBM:RDP:x",
])
def test_a_non_canonical_principal_is_refused_at_every_entry_point(principal):
    """Requirement 4, and the reason it is not merely cosmetic: an identity
    that cannot be attributed has no namespace to be idempotent within, so
    accepting one silently shares a namespace — R4-U3's collision through the
    back door. Refused even though the federation register is unavailable,
    because WHICH provider this is and WHETHER it is admitted are different
    questions and only the second is external."""
    mock._DS_LEDGER.clear()
    with pytest.raises(Exception) as exc:
        mock.ds_accept_message("01HZ7A", "G", "AAEC", principal=principal)
    assert getattr(exc.value, "reason", "") in (
        "rdp-identity-invalid", "unauthenticated"), exc.value
    assert mock._DS_LEDGER == {}, "a refused principal still keyed the ledger"

    mock._SUBMISSION_LEDGER.clear()
    with pytest.raises(mock.SubmissionRejected) as exc2:
        mock.submit(_meta(), org=ORG, members=MEMBERS, principal=principal)
    assert mock._SUBMISSION_LEDGER == {}


def test_the_identity_adapter_requires_exactly_one_canonical_uri():
    """Requirement 3. Zero cannot be attributed; two cannot be attributed
    EITHER, and choosing would make the namespace depend on the order a library
    returned extensions."""
    from lint_cli import canonical_rdp_id, RdpIdentityError
    assert canonical_rdp_id(["urn:sbm:rdp:fr-001"]) == "urn:sbm:rdp:fr-001"
    # other names may ride along; they cannot supply the identity
    assert canonical_rdp_id(["mailto:ops@example.eu",
                             "urn:sbm:rdp:fr-001"]) == "urn:sbm:rdp:fr-001"
    with pytest.raises(RdpIdentityError) as a:
        canonical_rdp_id(["https://example.eu/rdp"])
    assert a.value.reason == "rdp-identity-absent"
    with pytest.raises(RdpIdentityError) as b:
        canonical_rdp_id(["urn:sbm:rdp:fr-001", "urn:sbm:rdp:de-002"])
    assert b.value.reason == "rdp-identity-ambiguous"


def test_no_alias_policy_is_defined_and_that_is_deliberate():
    """R7-X1: requirement 5 asks for an alias policy IF legacy identifiers must
    survive. They do not — an alias resolving to the same namespace is a second
    name for one thing, and two names for one namespace is how R4-U3's
    collision returns. Stated so a future reader does not add one as an
    obvious convenience."""
    ds = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    d = " ".join(ds["components"]["securitySchemes"]["rdpAuth"]["description"].split())
    assert "NO ALIASES" in d
    assert "A deployment migrating must re-issue" in d


def test_authorisation_stays_external():
    """Requirement 6: the grammar check does not complete trust validation."""
    ds = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    d = " ".join(ds["components"]["securitySchemes"]["rdpAuth"]["description"].split())
    assert "AUTHORISATION IS NOT AUTHENTICATION" in d and "X-01" in d


# ===========================================================================
# R7-01 — the request contract runs, and a failure moves no ledger
# ===========================================================================
#
# Nine of sixteen contract-required fields produced a SEALED SE that fails its
# own authoritative Schema. The request contract was correct, the evidence
# Schema was correct, and the path between them ran NEITHER — cowork's naming
# for the round: a declared authority with no path to it.
#
# The cause was `check_identity_coherence` guarding every comparison with
# `if r_uid and …`: an absent UID is falsy, so the comparison was SKIPPED. A
# coherence check that reads absence as agreement is not a coherence check.

CONTRACT_REQUIRED = yaml.safe_load(
    (ROOT / "wallet-rdp-openapi.yaml").read_text()
)["components"]["schemas"]["SubmissionMetadata"]["required"]


def _ledgers():
    return (len(mock._SUBMISSION_LEDGER), len(mock._DS_LEDGER),
            len(mock._SE_LEDGER))


def _clear():
    mock._SUBMISSION_LEDGER.clear()
    mock._DS_LEDGER.clear()
    mock._SE_LEDGER.clear()


def _resigned(drop):
    """A submission missing one field, with the D4 tuple RE-SIGNED over what
    remains — so the signature is genuinely valid and cannot be what saves us
    (the review's third acceptance test)."""
    meta = _meta()
    meta.pop(drop, None)
    sc = copy.deepcopy(meta.get("sender_confirmation") or {})
    for f in lc.D4_COPIED_FIELDS:
        if f == drop:
            sc.pop(f, None)
        elif f in meta:
            sc[f] = meta[f]
    if sc:
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
        meta["sender_confirmation"] = sc
    return meta


@pytest.mark.parametrize("field", CONTRACT_REQUIRED)
def test_every_contract_required_field_fails_before_any_ledger_moves(field):
    """Driven from the CONTRACT's own list, not from a table — which is how
    round 7 found that `scope_ref` sealed too, a field the hand-off had listed
    as unverified rather than safe.

    The assertion is the LEDGERS, per cowork's amendment: atomicity is a
    property, and inspecting the raised reason would not have caught that an
    omitted `message_id` wrote `_SUBMISSION_LEDGER[(principal, None)]` and then
    raised an untyped KeyError.
    """
    _clear()
    with pytest.raises(mock.SubmissionRejected) as exc:
        mock.submit(_resigned(field), org=ORG, members=MEMBERS,
                    principal="urn:sbm:rdp:demo-out")
    assert exc.value.reason, "every pre-seal failure is typed"
    assert _ledgers() == (0, 0, 0), \
        f"omitting {field} left ledger residue {_ledgers()}"


def test_no_omission_produces_an_untyped_crash():
    """`message_id` omitted raised a bare KeyError — not a registered reason,
    and after the submission ledger had already been written."""
    for field in CONTRACT_REQUIRED:
        _clear()
        try:
            mock.submit(_resigned(field), org=ORG, members=MEMBERS,
                        principal="urn:sbm:rdp:demo-out")
        except mock.SubmissionRejected:
            continue
        except Exception as e:                       # pragma: no cover
            pytest.fail(f"omitting {field} raised untyped {type(e).__name__}")
        pytest.fail(f"omitting {field} SEALED an SE")


def test_the_identity_comparisons_are_unconditional():
    """Requirement 3: truthiness must not stand in for presence validation."""
    src = (ROOT / "scripts" / "lint_cli.py").read_text()
    body = src[src.index("def check_identity_coherence"):]
    body = body[:body.index("\ndef _member_as_of")]
    for guard in ("if r_uid and", "elif s_uid and", "and r_uid and",
                  "if s_uid and member"):
        assert guard not in body, f"absence is still read as agreement: {guard}"


def test_a_valid_submission_still_seals():
    """The bar is not 'refuse everything'."""
    _clear()
    art = mock.submit(_meta(), org=ORG, members=MEMBERS,
                      principal="urn:sbm:rdp:demo-out")
    assert art["projection"]["type"] == "SE-v1"
    assert not (lc.validate_body(art["projection"]) or [])
    assert _ledgers() == (1, 1, 1)


# ===========================================================================
# R8-01 — the contract is EXECUTED, and the transaction is honest
#
# Round 7 established that the required-field list was read from the contract.
# It then reimplemented two of the contract's keywords by hand, which is the
# same defect one level in: the contract owned the truth, a projection of it
# ran, and the projection was checked faithfully. These tests drive BEHAVIOUR —
# the two they replaced asserted that a source file contained a string and that
# one statement preceded another, and both would have passed unchanged while
# a malformed value reserved a message id and produced a real DS record.
# ===========================================================================

# One violation per constraint kind the contract actually uses.
MALFORMED = {
    "grade_commitment": "not-a-sha256-digest",          # pattern
    "sender_uid": "not a uid",                          # $ref'd pattern
    "recipient_uid": "",                                # empty, not absent
    "sender_addr": "not-a-bw-address",                  # BwAddress grammar
    "sent_at": "4 April, about ten past ten",           # IsoTimestamp
    "expires_at": "2026-04-07",                         # date, not timestamp
    "origin_proof": "invented-proof-kind",              # enum
    "payload_hash": "deadbeef",                         # object, not string
    "mls_epoch": "three",                               # type
    "scope_ref": {"scope_id": "default"},               # incomplete object
    "auth_context": {"unexpected": "nested"},           # closed nested object
    "acceptance_policy_ref": {"policy_version": 1},     # wrong leaf type
}


@pytest.mark.parametrize("field,bad", sorted(MALFORMED.items()))
def test_a_value_the_contract_rejects_never_moves_a_ledger(field, bad):
    """R8-01 requirement 1 and its first two acceptance tests, as ONE
    behavioural assertion: the request is refused, and all three ledgers are
    where they were. The reproduced defect is `grade_commitment` — it reserved
    a message identifier AND produced a real DS acceptance record before the SE
    gate refused it, while the error text said no ledger had moved."""
    _clear()
    meta = _meta(**{field: bad})
    # the published contract rejects it...
    with pytest.raises(lc.SubmissionInvalid):
        lc.validate_submission_metadata(meta)
    # ...and so does the whole transaction, with nothing left behind.
    with pytest.raises(mock.SubmissionRejected) as exc:
        mock.submit(meta, org=ORG, members=MEMBERS,
                    principal="urn:sbm:rdp:demo-out")
    assert exc.value.reason != "evidence-schema-invalid", (
        f"{field} was caught by the OUTPUT gate, not the request contract — "
        "which is the finding: by then the DS has already accepted the bytes")
    assert _ledgers() == (0, 0, 0), \
        f"malformed {field} left ledger residue {_ledgers()}"


def test_intake_and_the_published_contract_agree():
    """R8-01 acceptance test 5 — the differential. Intake and a generated
    client must not disagree about what the contract admits, in EITHER
    direction: a reference that is stricter than the contract refuses conformant
    traffic, and one that is laxer seals what the contract forbids."""
    import jsonschema
    schema, validator = lc.request_schema("wallet-rdp-openapi.yaml",
                                          "SubmissionMetadata")
    corpus = [_meta()] + [_meta(**{f: bad}) for f, bad in MALFORMED.items()]
    for meta in corpus:
        try:
            lc.validate_submission_metadata(meta)
            intake_admits = True
        except lc.SubmissionInvalid:
            intake_admits = False
        contract_admits = not list(validator.iter_errors(meta))
        assert intake_admits == contract_admits, (
            f"intake and the contract disagree (intake={intake_admits}, "
            f"contract={contract_admits}) on {json.dumps(meta)[:200]}")


def test_the_candidate_is_refused_before_the_delivery_service_is_contacted():
    """R8-01 requirements 3 and 5 / R8-X4. The output gate used to run after
    `_SUBMISSION_LEDGER` and `_DS_LEDGER` had both moved, and said "nothing is
    sealed and no ledger moves". Nothing in the SE waits on the DS, so the
    complete candidate is built and validated BEFORE the remote side effect.

    Driven by making the SEALED object invalid in a way the request contract
    cannot see: `POLICY_ID` is server-derived, so no request validation can
    catch it and only the candidate gate can."""
    _clear()
    original = mock.POLICY_ID
    mock.POLICY_ID = ""            # `PolicyId` is minLength 1
    try:
        with pytest.raises(mock.SubmissionRejected) as exc:
            mock.submit(_meta(), org=ORG, members=MEMBERS,
                        principal="urn:sbm:rdp:demo-out")
    finally:
        mock.POLICY_ID = original
    assert exc.value.reason == "evidence-schema-invalid"
    assert "BEFORE the Delivery Service was contacted" in exc.value.detail
    assert mock._DS_LEDGER == {}, \
        "the DS accepted octets for a message no SE can ever be sealed for"
    assert mock._SE_LEDGER == {}


def test_no_invalid_artefact_is_ever_signed():
    """R8-01 acceptance test 4. Whatever the reason, the failure must happen
    with nothing sealed — a signature over an invalid object is the artefact
    this whole finding exists to prevent, and it cannot be unsigned afterwards."""
    _clear()
    original = mock.POLICY_ID
    mock.POLICY_ID = ""            # `PolicyId` is minLength 1
    try:
        with pytest.raises(mock.SubmissionRejected):
            mock.submit(_meta(), org=ORG, members=MEMBERS,
                        principal="urn:sbm:rdp:demo-out")
    finally:
        mock.POLICY_ID = original
    assert mock._SE_LEDGER == {}
    # ...and the same submission seals cleanly once the defect is gone, so the
    # refusal is retryable rather than a poisoned handle.
    art = mock.submit(_meta(), org=ORG, members=MEMBERS,
                      principal="urn:sbm:rdp:demo-out")
    assert not (lc.validate_body(art["projection"]) or [])


def test_a_caller_decides_on_fields_not_on_the_message_text():
    """R8-01: `SubmissionInvalid.fields` is data. `accept_submission` answers
    `unaddressed-submission` for a missing address, and it used to decide that
    by substring-matching the error prose. Once the whole Schema ran, a `oneOf`
    failure rendered the entire instance into that message — so every address
    present in the submission looked like the offending field, and an unrelated
    defect was answered with the wrong typed reason."""
    meta = _meta()
    del meta["sender_confirmation"]      # a `oneOf` failure, not an address one
    with pytest.raises(mock.SubmissionRejected) as exc:
        _accept(meta)
    assert exc.value.reason == "sender-confirmation-missing"
    for value in (meta["sender_addr"], meta["recipient_addr"]):
        assert value not in exc.value.detail, \
            "the refusal renders submitted values into its message"


# ===========================================================================
# R8-05 — ONE value space, at every boundary, counted by occurrence
#
# R7-04 gave `RdpId` its exact grammar and pointed the evidence Schemas at it.
# The gate that guarded the result asked whether each schema MENTIONS `RdpId`
# and whether any restates the grammar — and a field declared
# `{"type": "string"}` does neither, so it passed while saying nothing.
# ===========================================================================

def test_every_provider_identity_field_refs_the_one_definition():
    """R8-05 requirement 1 and its first acceptance test, driven by the
    INVENTORY rather than by a list of the boundaries someone remembered.

    That distinction is the finding: the review named three restatements, and
    walking every contract and Schema found six. Two of the extra three were in
    evidence Schemas the review recorded as already canonical, because the old
    gate only ever looked at a top-level `rdp_id`."""
    inv = _load("rdp_identity_inventory", "rdp_identity_inventory.py")
    assert inv.check() == []
    assert len(inv.inventory()) >= 14, \
        "the walker found almost nothing, so the gate above is vacuous"


def test_the_inventory_walks_EVERY_published_contract():
    """Batch A's closure verification found this one. The inventory carried its
    OWN copy of the published-contract list, so A1's fifth contract — the
    membership register — was outside it, and the register's two
    `participant_id` declarations went unexamined for four commits. Both were
    `$ref`s, which is exactly why it mattered: the gate passed because the code
    happened to be right, not because the gate looked. The list is now taken
    from `openapi_validate`, where a new contract must be named."""
    inv = _load("rdp_identity_inventory", "rdp_identity_inventory.py")
    from openapi_validate import CONTRACTS
    assert inv._contracts() == list(CONTRACTS)
    sources = {src for src, _ptr, _d in inv.inventory()}
    # A contract may legitimately declare no provider identity, so presence in
    # `sources` is not required of all of them. The register is not one of
    # those: it declares `participant_id` twice, and its absence here would
    # mean the walk skipped it.
    assert "federation-register-openapi.yaml" in sources, \
        "the membership register declares participant_id and is not walked"


def test_a_provider_identity_is_recognised_by_EVERY_name_it_has():
    """`participant_id` is an `RdpId` under another name: the register admits
    the same providers the evidence names, or it is answering about somebody
    else. A matcher keyed to `rdp_id` alone measured the fields it already knew
    about."""
    inv = _load("rdp_identity_inventory", "rdp_identity_inventory.py")
    for name in ("rdp_id", "sending_rdp_id", "participant_id"):
        assert inv.IS_RDP_ID.search(name), name
    for name in ("rdp", "message_id", "mid", "policy_id"):
        assert not inv.IS_RDP_ID.search(name), name
    ptrs = {ptr for _s, ptr, _d in inv.inventory() if "participant_id" in ptr}
    assert len(ptrs) >= 3, f"only {sorted(ptrs)} participant_id declarations found"


def test_the_inventory_catches_a_restatement_anywhere():
    """The guard on the guard: a gate that cannot fail proves nothing. Each of
    the three shapes that were actually found is injected."""
    inv = _load("rdp_identity_inventory", "rdp_identity_inventory.py")
    for decl, expected in (
            ({"type": "string"}, "unconstrained"),
            ({"type": "string", "pattern": "^urn:sbm:rdp:"}, "LOCAL pattern"),
            ({"$ref": "somewhere-else.json#/$defs/RdpId"}, "not the shared")):
        why = inv.verdict(decl)
        assert why and expected in why, (decl, why)
    assert inv.verdict(
        {"$ref": "evidence-common.schema.json#/$defs/RdpId"}) is None


@pytest.mark.parametrize("bad", [
    "urn:sbm:rdp:",                      # empty suffix
    "urn:sbm:rdp:provider/child",        # a slash
    "urn:sbm:rdp:x:alias",               # a second colon
    "XXurn:sbm:rdp:evil",                # unanchored prefix match
    "RDP:MockEU:001",                    # the pre-R7-04 shape
])
def test_every_layer_rejects_the_same_invalid_corpus(bad):
    """R8-05's second acceptance test. The acknowledgement path parameter
    restated the grammar as an UNANCHORED `^urn:sbm:rdp:`, so it accepted the
    first four of these while the reference rejected all five — the two value
    spaces disagreed at adjacent interfaces."""
    import jsonschema
    with pytest.raises(lc.RdpIdentityError):
        lc.require_rdp_id(bad)
    for contract, schema_name, field in (
            ("delivery-service-openapi.yaml", "AcceptanceRecord",
             "issuing_rdp_id"),
            ("delivery-service-openapi.yaml", "DeliveryReceipt",
             "issuing_rdp_id"),
            ("delivery-service-openapi.yaml", "CollectedMessage",
             "issuing_rdp_id")):
        _, validator = lc.request_schema(contract, schema_name)
        errors = [e for e in validator.iter_errors({field: bad})
                  if list(e.path) == [field]]
        assert errors, f"{schema_name}.{field} accepted {bad!r}"
    # ...and the path parameter, which is where the unanchored copy lived
    import yaml
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    param = next(p for p in doc["paths"][
        "/messages/{issuing_rdp_id}/{message_id}/receipt-ack"]["post"]["parameters"]
        if p["name"] == "issuing_rdp_id")
    assert "$ref" in param["schema"] and "pattern" not in param["schema"]


@pytest.mark.parametrize("sans,ok", [
    ([], False),                                                 # zero
    (["urn:sbm:rdp:a"], True),                                   # exactly one
    (["urn:sbm:rdp:a", "urn:sbm:rdp:a"], False),                 # duplicate-identical
    (["urn:sbm:rdp:a", "urn:sbm:rdp:b"], False),                 # duplicate-distinct
    (["urn:sbm:rdp:a", "urn:sbm:rdp:b", "urn:sbm:rdp:c"], False),  # more than two
    (["mailto:ops@example.eu", "urn:sbm:rdp:a", "dns:rdp.example.eu"], True),
])
def test_the_adapter_counts_occurrences_not_distinct_values(sans, ok):
    """R8-05 requirement 3 and its third acceptance test. The code tested
    `len(set(canonical)) > 1`, so the SAME canonical URI encoded twice passed —
    the set normalised the duplicate away. The docstring said "exactly one"
    throughout, and the docstring is the normative half: a duplicate SAN is
    evidence of malformed issuance, and deduplicating it decides that a
    certificate we cannot explain is fine."""
    if ok:
        assert lc.canonical_rdp_id(sans) == "urn:sbm:rdp:a"
    else:
        with pytest.raises(lc.RdpIdentityError) as exc:
            lc.canonical_rdp_id(sans)
        assert exc.value.reason in ("rdp-identity-absent",
                                    "rdp-identity-ambiguous")


def test_a_duplicate_san_reports_every_occurrence():
    """"...report all matching occurrences for diagnostics without
    deduplicating the decision." An operator debugging a refused certificate
    needs to see that it carried the name twice."""
    with pytest.raises(lc.RdpIdentityError) as exc:
        lc.canonical_rdp_id(["urn:sbm:rdp:a", "urn:sbm:rdp:a"])
    assert "2 canonical subjectAltName URIs" in exc.value.detail
    assert "encoded more than once" in exc.value.detail


def test_a_server_derived_acceptance_record_is_validated_before_it_is_stored():
    """R8-05 requirement 4. `issuing_rdp_id` was an unconstrained string on
    this object, so the one field deciding the idempotency namespace had no
    value space at the boundary that mints it."""
    _clear()
    with pytest.raises(mock.TransportRejected) as exc:
        mock.ds_accept_message("01HZ8R805000000000000001", "demo-group",
                               base64.b64encode(b"bytes").decode(),
                               principal="urn:sbm:rdp:demo-out",
                               accepted_at="not a timestamp")
    assert exc.value.reason == "acceptance-record-invalid"
    assert mock._DS_LEDGER == {}, "an invalid record was stored anyway"


def test_two_services_of_one_entity_keep_distinct_namespaces():
    """R8-05's fourth acceptance test, and R4-U3's whole point: the entity-only
    fallback was removed because one legal entity may operate several RDPs."""
    _clear()
    mid = "01HZ8R805000000000000002"
    octets = base64.b64encode(b"same bytes both ways").decode()
    a = mock.ds_accept_message(mid, "demo-group", octets,
                               principal="urn:sbm:rdp:acme-one")
    b = mock.ds_accept_message(mid, "demo-group", octets,
                               principal="urn:sbm:rdp:acme-two")
    assert a["issuing_rdp_id"] != b["issuing_rdp_id"]
    assert len(mock._DS_LEDGER) == 2, \
        "two services of one entity collided in a shared namespace"


def test_the_grammar_the_code_enforces_IS_the_schemas(monkeypatch):
    """R8-06 requirement 5 — the BEHAVIOURAL half of "the code reads the
    grammar from the schema".

    The criterion rested on a source assertion: the pattern string does not
    appear in `lint_cli.py`, and the subscript expression does. Both would
    still hold if the code read the file and then ignored what it found. This
    narrows the PUBLISHED grammar and watches the reference's acceptance
    follow, which is the only evidence that the schema is the authority rather
    than the documentation.
    """
    original = lc._rdp_id_pattern().pattern
    assert lc.require_rdp_id("urn:sbm:rdp:demo-out")

    real_read = pathlib.Path.read_text

    def narrowed(self, *a, **kw):
        text = real_read(self, *a, **kw)
        if self.name == "evidence-common.schema.json":
            return text.replace(original, "^urn:sbm:rdp:only-this-one$")
        return text

    monkeypatch.setattr(pathlib.Path, "read_text", narrowed)
    monkeypatch.setattr(lc, "RDP_ID_PATTERN", None)
    assert lc._rdp_id_pattern().pattern == "^urn:sbm:rdp:only-this-one$", \
        "the reference does not take its grammar from the schema at all"
    with pytest.raises(lc.RdpIdentityError):
        lc.require_rdp_id("urn:sbm:rdp:demo-out")
    assert lc.require_rdp_id("urn:sbm:rdp:only-this-one")

    monkeypatch.undo()
    lc.RDP_ID_PATTERN = None
    assert lc._rdp_id_pattern().pattern == original
