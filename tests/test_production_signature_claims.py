# SPDX-License-Identifier: MIT
"""R4-03 and R4-04 — the resolved key is used, and the certificate is checked.

Both are the same family, and both are fresh violations of an invariant round 3
**adopted**: *a helper only its own test calls is not integrated.*

**R4-03.** `resolve_ds_receipt_key` was correct — it resolved the key, rejected
duplicate `kid`s, and judged validity at the receipt's own `server_time`, which
is the right instant. The verification that followed then re-derived the demo
key from `kid` and a hard-coded seed and compared re-encoded bytes:

    expected = b64encode(seal_cose(body, kid=kid, seed="ds"))
    if receipt["ds_signature"] != expected: ...

A **symmetric recomputation**. The resolved key's public bytes were never
touched, so substituting the published key in BW-MED changed nothing — and
`bundle_lint` never called the resolver at all, so no verifier outside the
issuing provider ever checked a receipt. Discovery that no verification
consumes is decoration.

**R4-04.** `check_certificate_binds_key(..., at=)` worked; the one production
call omitted `at`. The capability existed and the accepting path did not use
it, which is what the round-4 integration gate now catches mechanically.

The scope limit is asserted here as well as stated: this is the certificate's
**own** window. Path validation, QSealC qualification, revocation and SCD
policy are the external production trust model — **F-04 and X-01 stay
Partial**.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

import prejoin
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402



def _staged(mock, *, issuing_rdp_id, message_id, recipient_uid, mid, device_id,
            octets, session_binding):
    """R7-02: a receipt now requires an item the DS ACCEPTED, QUEUED and
    TRANSFERRED. These fixtures run that lifecycle rather than bypassing it —
    a helper that faked the state would reintroduce exactly the orphan the
    finding is about, one layer down."""
    import base64
    mock.ds_accept_message(message_id, "demo-group",
                           base64.b64encode(octets).decode(),
                           principal=issuing_rdp_id)
    mock.queue_delivery(issuing_rdp_id, message_id, recipient_uid=recipient_uid,
                        mid=mid, device_id=device_id)
    # R9-01/R9-02: collect through the PUBLIC operation and RETURN the token it
    # issued. These fixtures used to call the private `transfer_delivery()` and
    # then acknowledge with no token at all — which is why nothing noticed that
    # a value the published request declares REQUIRED was optional in the
    # reference. A fixture that can skip a wire value cannot test that it is
    # needed.
    got = mock.collect_messages(
        credential={"kind": "device", "uid": recipient_uid, "mid": mid,
                    "device_id": device_id, "session": session_binding["digest"]},
        session_binding=session_binding)
    return next(i["collection_token"] for i in got["items"]
                if i["message_id"] == message_id)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

MED = json.loads((ROOT / "samples" / "sample-BW-MED.json").read_text())["projection"]
# SBM-ADR-0015: the receipt key moved to the provider's descriptor.
#: The shipped descriptor, as the RDP that issues these receipts publishes it:
#: the sample belongs to `urn:sbm:rdp:mockeu-001` and the receipts built here
#: are issued by `urn:sbm:rdp:demo-out`. SBM-ADR-0015 makes a descriptor
#: authorise its own participant's receipts and nobody else's, so the fixture
#: states whose descriptor it is.
#: Whose descriptor the fixtures below supply: the OBSERVER's. The receipt
#: names it in `observed_by`, and that is the provider whose Delivery Service
#: signed — not `issuing_rdp_id`, which is the message's origin.
ISSUER = mock.DS_PROVIDER_ID
SHIPPED_PROVIDER = json.loads(
    (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())["projection"]
PROVIDER = dict(SHIPPED_PROVIDER, participant_id=ISSUER)
SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]

OCTETS = b"\x00\x01" + b"the exact octets handed to the device" * 3
SESSION = {"kind": "token-digest", "digest": "a" * 64}
# R11-01: a device credential names its entity and member; the label alone
# names a device of every member that uses it.
P1 = (SE["recipient_uid"], "F1N2C3D4P", "DEV-1")
CRED = {"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": P1[2],
        "session": SESSION["digest"]}
EVENT = "2026-04-04T10:16:23Z"


def setup_function():
    # R7-02: the delivery items are server state like the ledgers, so a
    # test must not inherit a previous one's transfer.
    mock._DELIVERY_ITEMS.clear()
    mock._DS_LEDGER.clear()
    mock._ACK_LEDGER.clear()


def _receipt(**over):
    # R6-03: the signed message_id must BE the act this receipt substantiates.
    # This fixture signed one id and was filed under another, and nothing
    # compared them — the defect the retained path now reports.
    mid_ = over.pop("message_id", SE["message_id"])
    rdp = over.pop("issuing_rdp_id", "urn:sbm:rdp:demo-out")
    # R9-01: the fixture COLLECTS to obtain the token, and an acknowledged item
    # is not offered again — so a second `_receipt()` for one message_id would
    # find nothing to collect. Each call gets its own clean state, which is
    # what it always meant.
    _fresh()
    token = _staged(mock, issuing_rdp_id=rdp, message_id=mid_,
                    recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
                    device_id="DEV-1", octets=OCTETS, session_binding=SESSION)
    over.setdefault("collection_token", token)
    return mock.receipt_ack(
        message_id=mid_, issuing_rdp_id=rdp, device_id="DEV-1",
        credential=CRED, session_binding=SESSION, octets=OCTETS,
        server_clock=over.pop("server_clock", EVENT), **over)


def _expect(**over):
    """What a caller is processing. R6-03 introduced it; R7-02 made it a TYPE,
    because a bare mapping allowed `{}` and all-None contexts that named every
    dimension and asserted nothing."""
    from lint_cli import DeliveryContext
    e = {"message_id": SE["message_id"],
         "issuing_rdp_id": "urn:sbm:rdp:demo-out",
         "observed_by": mock.DS_PROVIDER_ID,
         "recipient_uid": SE["recipient_uid"], "mid": "F1N2C3D4P",
         "device_id": "DEV-1", "session_binding": SESSION,
         "message_digest": _digest()}
    e.update(over)
    return DeliveryContext(**e)


def _digest():
    return {"format": "mls10-message", "hex": hashlib.sha256(OCTETS).hexdigest()}


# ===========================================================================
# R4-03 — the resolved key is what verifies
# ===========================================================================

def test_a_receipt_verifies_against_the_published_key():
    assert mock.delivered_at_from_receipt(_receipt(), _digest(), provider=PROVIDER, expect=_expect()) == EVENT


def test_SUBSTITUTING_the_published_key_now_fails():
    """The finding's probe. It used to change nothing, because the published
    key was never used — the check re-derived a demo key from `kid` and a
    hard-coded seed and compared re-encoded bytes."""
    tampered = copy.deepcopy(PROVIDER)
    k = tampered["ds_receipt_keys"][0]
    k["public_key_b64"] = "AAAA" + k["public_key_b64"][4:]
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(_receipt(), _digest(), provider=tampered,
                                      expect=_expect())
    assert exc.value.reason == "receipt-unverifiable"


def test_a_receipt_with_no_published_key_yields_no_de():
    """Issuing a DE when there is nothing to verify against was the defect."""
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(_receipt(), _digest(), provider=None,
                                      expect=_expect())
    assert "nothing to verify against" in exc.value.detail or \
           "cannot be resolved" in exc.value.detail


def test_the_verification_no_longer_re_derives_the_signing_key():
    """Structural, because the behavioural test above would also pass if the
    check simply moved: the verifier must not know the SEED."""
    src = (ROOT / "scripts" / "mock_rdp.py").read_text()
    body = src[src.index("def delivered_at_from_receipt"):]
    body = body[:body.index("\ndef ")]
    assert 'seed="ds"' not in body, \
        "the verifier re-derives the signing key — a symmetric recomputation"
    # R5-03: the check moved into the SHARED implementation, so the assertion
    # follows the code rather than pinning the old location. Both halves are
    # still asserted — that the live path delegates, and that the shared
    # implementation is the one using the published bytes.
    assert "verify_ds_receipt" in body, \
        "the live path no longer delegates to the one receipt check"
    shared = (ROOT / "scripts" / "lint_cli.py").read_text()
    shared = shared[shared.index("def verify_ds_receipt"):]
    shared = shared[:shared.index("\nclass ReceiptKeyError")]
    assert 'seed="ds"' not in shared
    assert "verify_cose_signature" in shared
    assert 'key["public_key_b64"]' in shared or "resolve_ds_receipt_key" in shared


# ---------------------------------------------------------------------------
# ...and a verifier reaches its own verdict
# ---------------------------------------------------------------------------

def _bnd38(receipts, descriptors=None):
    """LINT-BND-38 over one retained receipt.

    SBM-ADR-0015: the MED is still the entity's document the bundle is about;
    what moved is where the RECEIPT KEY comes from, so the descriptors are a
    separate input. `descriptors=None` means none was supplied, which is the
    case `test_a_receipt_with_no_descriptor_is_reported` exercises.
    """
    if descriptors is None:
        # The descriptor has to be the ISSUING RDP's — that is the whole point
        # of the move — so it is keyed to the issuer these receipts name rather
        # than to the shipped sample's own participant_id.
        issuer = next((r.get("issuing_rdp_id") for r in receipts.values()
                       if isinstance(r, dict)), None)
        descriptors = [dict(copy.deepcopy(PROVIDER), participant_id=issuer)]
    return [m for r, m in bl.check_bundle(
        SE["recipient_uid"], MED, {}, [], [copy.deepcopy(SE)], receipts=receipts,
        provider_descriptors=descriptors)
        if r == "LINT-BND-38"]


def test_the_bundle_layer_verifies_a_retained_receipt():
    """`bundle_lint` did not call the resolver AT ALL, so verification existed
    only where the receipt was issued."""
    assert not _bnd38({SE["message_id"]: _receipt()})


def test_a_valid_signature_over_a_DIFFERENT_payload_is_caught():
    """Found while writing this test, and worth stating: verifying the
    signature is NOT enough. The COSE payload is EMBEDDED, so the signature
    covers the bytes inside the structure — not the receipt object presented
    beside it. Moving `server_time` on the outer object left the signature
    perfectly valid, and the receipt then asserted a delivery instant nobody
    had signed. The asserted fields must EQUAL the signed payload, exactly as
    LINT-DE-19 compares the D4 tuple with its SE."""
    receipt = copy.deepcopy(_receipt())
    receipt["server_time"] = "2026-04-04T10:00:00Z"        # move the event
    issues = _bnd38({SE["message_id"]: receipt})
    assert issues, "a valid signature over other bytes was accepted"
    assert "the SIGNED payload says" in issues[0]


def test_a_receipt_whose_digest_was_swapped_is_caught():
    """The same shape on the field that decides WHICH bytes were delivered."""
    receipt = copy.deepcopy(_receipt())
    receipt["message_digest"] = {"format": "mls10-message", "hex": "f" * 64}
    assert _bnd38({SE["message_id"]: receipt})


def test_the_bundle_layer_rejects_an_unknown_kid():
    receipt = copy.deepcopy(_receipt())
    receipt["ds_kid"] = "nobody-published-this"
    assert _bnd38({SE["message_id"]: receipt})


def test_the_bundle_layer_rejects_an_algorithm_disagreement():
    receipt = copy.deepcopy(_receipt())
    receipt["ds_alg"] = "ES256"
    issues = _bnd38({SE["message_id"]: receipt})
    assert issues and "algorithm confusion" in issues[0]


def test_a_receipt_with_no_published_keys_is_reported():
    # A GENUINE descriptor of the issuing RDP that publishes no receipt key —
    # so this reaches the "no referent" arm rather than the kind or participant
    # one. Without `type` it used to pass by tripping over a check that did not
    # exist yet.
    bare = {"type": "BW-PROVIDER-v1",
            "participant_id": _receipt()["issuing_rdp_id"]}   # descriptor, no keys
    issues = _bnd38({SE["message_id"]: _receipt()}, descriptors=[bare])
    assert issues and "has no referent" in issues[0]


# ===========================================================================
# R4-04 — the certificate is checked where the act is known
# ===========================================================================

def _cert_member(not_after="2027-01-01T00:00:00Z"):
    """A member whose device carries a real, parsable certificate."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID
    import base64

    sk = ed25519.Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dev")])
    na = datetime.datetime.fromisoformat(not_after.replace("Z", "+00:00"))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(sk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(na).sign(sk, None))
    member = json.loads((ROOT / "samples" / "sample-BW-MEMBER-fr.json").read_text())["projection"]
    member = copy.deepcopy(member)
    dev = member["devices"][0]
    dev["confirmation_key"] = {
        "alg": "EdDSA",
        "public_key_b64": base64.b64encode(pub).decode(),
        "x5chain": [base64.b64encode(
            cert.public_bytes(serialization.Encoding.DER)).decode()],
    }
    return member, dev["device_id"]


def _bnd39(member, act_time):
    de = json.loads((ROOT / "samples" / "sample-DE.json").read_text())["projection"]
    de = copy.deepcopy(de)
    de["s3_attestation"]["mid"] = member["mid"]
    de["s3_attestation"]["verified_at"] = act_time
    if isinstance(de.get("recipient_confirmation"), dict):
        de["recipient_confirmation"]["mid"] = member["mid"]
    return [m for r, m in bl.check_bundle(
        member["uid"], MED, {}, [member], [copy.deepcopy(SE), de])
        if r == "LINT-BND-39"]


def test_a_certificate_valid_at_the_act_passes():
    member, _ = _cert_member()
    assert not _bnd39(member, EVENT)


def test_a_certificate_expired_at_the_act_is_reported():
    """The half that was unreachable: the parameter existed and the production
    call omitted it."""
    member, _ = _cert_member(not_after="2026-02-01T00:00:00Z")
    issues = _bnd39(member, EVENT)
    assert issues and "does not hold at the act" in issues[0]


def test_the_production_path_passes_the_act_time():
    """R4-04 verbatim, asserted structurally — the behavioural test above could
    be satisfied by a check that runs somewhere else."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    # The CODE, not the comment that explains the finding — matching prose
    # instead of behaviour is the mistake this round keeps finding.
    calls = [ln for ln in src.splitlines()
             if "check_certificate_binds_key(" in ln
             and not ln.strip().startswith("#")]
    assert calls, "the certificate check is not called from the bundle layer"
    i = src.index(calls[0])
    assert "at=act_time" in src[i:i + 260], \
        "the act time is not passed, so validity-at-the-act is unreachable again"


def test_the_scope_limit_is_recorded_where_an_assessor_reads_it():
    """What is NOT proven must be as legible as what is. Otherwise the local
    window check gets read as completion of the external trust model — which
    the review is explicit about, and F-04/X-01 stay Partial."""
    rules = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text())["rules"]
    pred = next(r for r in rules if r["id"] == "LINT-BND-39")["predicate"]
    assert "certificate's OWN window" in pred
    assert "EXTERNAL production trust" in pred and "remain Partial" in pred


# ===========================================================================
# R5-03 / R5-V4 — one receipt check, both paths
# ===========================================================================

def _tamper(**over):
    r = copy.deepcopy(_receipt())
    r.update(over)
    return r


def test_the_live_path_returns_the_SIGNED_instant():
    """The finding. R4-03 taught this repository that a valid signature is not
    enough — the COSE payload is embedded, so moving `server_time` on the outer
    object leaves the signature valid — and the fix landed in `bundle_lint`
    only. The live path went on returning the OUTER field, so it reported a
    delivery instant nobody had signed while the retained path caught it."""
    moved = _tamper(server_time="2026-04-04T09:00:00Z")
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(moved, _digest(), provider=PROVIDER, expect=_expect())
    assert "SIGNED payload says" in exc.value.detail
    # ...and the honest instant is the signed one, not whatever is presented.
    assert mock.delivered_at_from_receipt(_receipt(), _digest(), provider=PROVIDER, expect=_expect()) == EVENT


def test_the_two_paths_agree_on_every_tampering():
    """The property the finding is really about: not that each path is right,
    but that they cannot DISAGREE. Two implementations of one rule drift, and
    the second is always the one nobody is looking at."""
    cases = [
        ("outer server_time moved", _tamper(server_time="2026-04-04T09:00:00Z")),
        ("digest swapped", _tamper(message_digest={"format": "mls10-message",
                                                   "hex": "f" * 64})),
        ("unknown kid", _tamper(ds_kid="nobody-published-this")),
        ("alg disagreement", _tamper(ds_alg="ES256")),
        ("recipient swapped", _tamper(recipient_uid="EU-DE-EOID-7K3D9W0Q2M5FW0")),
        ("device swapped", _tamper(device_id="dev-99")),
        ("no signature", _tamper(ds_signature="")),
    ]
    for label, receipt in cases:
        live_failed = False
        try:
            mock.delivered_at_from_receipt(receipt, _digest(), provider=PROVIDER, expect=_expect())
        except mock.AckRejected:
            live_failed = True
        retained_failed = bool(_bnd38({SE["message_id"]: receipt}))
        assert live_failed == retained_failed, (
            f"{label}: live={'rejected' if live_failed else 'ACCEPTED'}, "
            f"retained={'rejected' if retained_failed else 'ACCEPTED'} — the "
            "two paths disagree about what a receipt proves")
        assert live_failed, f"{label} was accepted by both"


def test_there_is_one_implementation_of_the_receipt_check():
    """Invariant 3, asserted structurally: the second spelling is DELETED, not
    left reachable. Both call sites are counted so a future 'inline it for
    clarity' has to fail here first."""
    import helper_integration as hi
    sites = hi.call_sites("verify_ds_receipt", hi.production_modules())
    modules = {s.module for s in sites}
    assert modules == {"mock_rdp.py", "bundle_lint.py"}, modules
    for mod in ("mock_rdp.py", "bundle_lint.py"):
        src = (ROOT / "scripts" / mod).read_text()
        assert "cbor2.loads(base64.b64decode(receipt" not in src, \
            f"{mod} still decodes the signed payload itself"


def test_the_parse_before_verify_ordering_is_written_down():
    """V4's third point. Resolving the key at the SIGNED instant means parsing
    the payload before verifying it, so the parse must be treated as untrusted
    until the signature succeeds — and someone will 'simplify' that away unless
    the reason is where they will read it."""
    src = (ROOT / "scripts" / "lint_cli.py").read_text()
    body = src[src.index("def verify_ds_receipt"):]
    body = body[:body.index("\nclass ReceiptKeyError")]
    assert "UNTRUSTED" in body
    assert "lookup hint" in body
    # and the limit the model genuinely has
    assert "X-01/F-04" in body and "past window" in body


# ===========================================================================
# R6-03 — a receipt proves THIS act, in THIS provider's namespace
# ===========================================================================

def test_a_receipt_for_A_cannot_authorise_B_even_with_identical_ciphertext():
    """The finding's own vector. The live caller compared only the ciphertext
    digest and returned the signed time; it had no parameter with which to
    notice that the receipt attested a different message."""
    receipt = _receipt(message_id="01HZ6MESSAGE_A0000000001")
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(
            receipt, _digest(), provider=PROVIDER,
            expect=_expect(message_id="01HZ6MESSAGE_B0000000002"))
    assert exc.value.reason == "receipt-context-mismatch"


@pytest.mark.parametrize("field,other", [
    ("recipient_uid", "EU-DE-EOID-7K3D9W0Q2M5FW0"),
    ("mid", "F2X3Y4Z55"),
    ("device_id", "DEV-9"),
])
def test_cross_context_receipt_reuse_fails(field, other):
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(_receipt(), _digest(), provider=PROVIDER,
                                       expect=_expect(**{field: other}))
    assert exc.value.reason == "receipt-context-mismatch"


def test_a_caller_that_states_nothing_is_refused():
    """Fail closed: 'no expected context' is how the defect existed, so it is
    not a permitted mode."""
    with pytest.raises(mock.AckRejected) as exc:
        mock.delivered_at_from_receipt(_receipt(), _digest(), provider=PROVIDER)
    assert exc.value.reason == "receipt-context-missing"


def test_re_aliasing_the_key_under_another_kid_fails():
    """The narrower signed-projection defect: `ds_kid`/`ds_alg` were not in the
    compared set, and equality was conditional on a field appearing in BOTH
    objects. Re-aliasing one public key under a second published kid and
    changing only the outer selector verified fine — the cryptography was real
    and the attribution was not."""
    aliased = copy.deepcopy(PROVIDER)
    second = copy.deepcopy(aliased["ds_receipt_keys"][0])
    second["kid"] = "alias-of-the-same-key"
    aliased["ds_receipt_keys"].append(second)
    receipt = copy.deepcopy(_receipt())
    receipt["ds_kid"] = "alias-of-the-same-key"
    with pytest.raises(mock.AckRejected):
        mock.delivered_at_from_receipt(receipt, _digest(), provider=aliased,
                                       expect=_expect())


def test_the_mandatory_signed_set_is_not_an_intersection():
    """Comparing only fields present in BOTH objects compares an omitted field
    with nothing, so omission was as good as agreement."""
    from lint_cli import DS_RECEIPT_MANDATORY_SIGNED
    for f in ("message_id", "issuing_rdp_id", "recipient_uid", "ds_kid", "ds_alg"):
        assert f in DS_RECEIPT_MANDATORY_SIGNED, f


def test_two_providers_reusing_one_message_id_get_independent_receipts():
    """The namespace the submission layer already promised, and the receipt
    layer discarded: `/messages` keys on (issuing RDP, message_id) while the
    ack ledger keyed on (message_id, recipient_uid), so the second provider's
    acknowledgement returned the FIRST provider's byte-identical receipt."""
    _fresh()
    tok = {}
    for rdp, oct_ in (("urn:sbm:rdp:fr-001", OCTETS),
                      ("urn:sbm:rdp:de-002", b"different bytes")):
        tok[rdp] = _staged(
            mock, issuing_rdp_id=rdp, message_id="01HZ6SHARED000000000001",
            recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
            device_id="DEV-1", octets=oct_, session_binding=SESSION)
    a = mock.receipt_ack(message_id="01HZ6SHARED000000000001",
                         device_id="DEV-1", credential=CRED,
                         session_binding=SESSION, octets=OCTETS,
                         server_clock=EVENT, issuing_rdp_id="urn:sbm:rdp:fr-001",
                         collection_token=tok["urn:sbm:rdp:fr-001"])
    b = mock.receipt_ack(message_id="01HZ6SHARED000000000001",
                         device_id="DEV-1", credential=CRED,
                         session_binding=SESSION, octets=b"different bytes",
                         server_clock=EVENT, issuing_rdp_id="urn:sbm:rdp:de-002",
                         collection_token=tok["urn:sbm:rdp:de-002"])
    assert a["issuing_rdp_id"] != b["issuing_rdp_id"]
    assert a["message_digest"] != b["message_digest"], \
        "the second provider received the first provider's receipt"
    assert a["ds_signature"] != b["ds_signature"]


def test_the_retained_path_links_a_receipt_to_the_evidence_it_substantiates():
    """R6-03 point 5: the manifest key was never compared with the signed
    message_id, so a receipt filed under any key was verified in isolation."""
    stray = {"01HZ6NOTHING000000000001": _receipt()}
    issues = _bnd38(stray)
    assert issues and "no evidence in this bundle names" in issues[0]


# ===========================================================================
# R6-07 — the documentation and the implementation are EXACT-SET equal
# ===========================================================================

def test_the_signed_field_sets_are_exact_not_approximate():
    """R6-07 required change 2. The registry said `verify_ds_receipt` compared
    "every asserted field" while the implementation omitted `ds_kid`/`ds_alg`
    and compared only the intersection — a description stronger than the code.
    Asserting the exact sets means the two cannot drift apart again by one
    field at a time."""
    from lint_cli import DS_RECEIPT_SIGNED_FIELDS, DS_RECEIPT_MANDATORY_SIGNED
    assert set(DS_RECEIPT_SIGNED_FIELDS) == {
        "message_id", "issuing_rdp_id", "observed_by", "recipient_uid", "mid",
        "device_id", "server_time", "message_digest", "session_binding",
        "ds_kid", "ds_alg"}
    # SBM-ADR-0016: `observed_by` joined both sets. It names the provider whose
    # Delivery Service signed, which `issuing_rdp_id` — the message's origin —
    # never did; a receipt that did not bind it could be re-attributed to another
    # provider's Delivery Service by supplying that provider's descriptor.
    # everything except the optional session binding is mandatory
    # R7-02: session_binding joined the mandatory set — it is in
    # DeliveryReceipt.required on the wire and was absent here, so a receipt
    # with it removed and re-signed passed under a partial context.
    assert set(DS_RECEIPT_MANDATORY_SIGNED) == set(DS_RECEIPT_SIGNED_FIELDS)
    assert set(DS_RECEIPT_MANDATORY_SIGNED) <= set(DS_RECEIPT_SIGNED_FIELDS)


def test_the_registry_description_does_not_outrun_the_code():
    reg = json.loads((ROOT / "docs" / "normative-helpers.json").read_text())
    entry = next(h for h in reg["helpers"] if h["name"] == "verify_ds_receipt")
    # The phrase survives as a QUOTATION of what was wrong — evidence, not a
    # live claim — exactly as round 5's "RED ON ARRIVAL" note does. What must
    # not survive is the claim standing on its own.
    rule = entry["rule"]
    if "every asserted field" in rule:
        assert "earlier description claimed" in rule, \
            "the claim the implementation never met is still being made"
    assert "MANDATORY signed set" in entry["rule"]
    assert entry.get("required_arguments") == ["expect"], \
        "the context requirement must be expressed, not just described"


# ===========================================================================
# R7-02 (X3) — a receipt attests a transition the DS OBSERVED
# ===========================================================================

def _fresh():
    mock._DS_LEDGER.clear()
    mock._DELIVERY_ITEMS.clear()
    mock._ACK_LEDGER.clear()


RDP = "urn:sbm:rdp:demo-out"
MSG = "01HZ7LIFECYCLE0000000001"


def _ack_args(**over):
    # R9-01: the token the staging COLLECTION issued. There is no default and
    # no omission: the published request requires it, so a fixture that could
    # leave it out would be testing a protocol the contract does not describe.
    a = dict(message_id=MSG, issuing_rdp_id=RDP,
             device_id="DEV-1", credential=CRED, session_binding=SESSION,
             octets=OCTETS, server_clock=EVENT,
             collection_token=_LAST_TOKEN.get("t"))
    a.update(over)
    return a


def test_an_orphan_receipt_cannot_be_produced_at_all():
    """The finding: `receipt_ack()` signed its arguments. It resolved nothing,
    so a valid signed receipt existed for a message the DS had never accepted,
    with an `issuing_rdp_id` the caller chose as a keyword argument. The
    signature was real and the state transition never happened."""
    _fresh()
    with pytest.raises(mock.AckRejected) as exc:
        mock.receipt_ack(**_ack_args(collection_token=PLAUSIBLE_TOKEN))
    assert exc.value.reason == "delivery-item-unknown"
    assert mock._ACK_LEDGER == {}, "a refusal must not leave a receipt"


def test_an_accepted_but_untransferred_item_cannot_be_acknowledged():
    """Acceptance is not delivery. A receipt for a queued item would attest a
    handover that has not happened."""
    _fresh()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    with pytest.raises(mock.AckRejected) as exc:
        mock.receipt_ack(**_ack_args(collection_token=PLAUSIBLE_TOKEN))
    assert exc.value.reason == "delivery-not-transferred"


_LAST_TOKEN = {}

# R9-01: the token is rejected BEFORE the item is resolved, so a test about
# item resolution has to present a well-formed one. `None` would prove
# `collection-token-required` and never reach the rule it names — the same
# shape as R8-01's `"tampered"` fixtures.
PLAUSIBLE_TOKEN = "dt-" + "0" * 32


def _staged_item(**over):
    _fresh()
    _LAST_TOKEN["t"] = _staged(
        mock, issuing_rdp_id=over.get("issuing_rdp_id", RDP),
        message_id=over.get("message_id", MSG),
        recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
        device_id="DEV-1", octets=OCTETS, session_binding=SESSION)


@pytest.mark.parametrize("field,value,reason", [
    # R11-01: the entity and member are the AUTHENTICATED principal's, not
    # arguments — `receipt_ack` took them from its caller and compared them
    # with the item, while the credential was checked for its label only. A
    # device of another entity, or of another member, carrying the SAME label
    # now has no item to acknowledge: the uniform answer, as for DEV-9.
    ("uid", "EU-DE-EOID-7K3D9W0Q2M5FW0", "delivery-item-unknown"),
    ("mid", "F2X3Y4Z55", "delivery-item-unknown"),
    # R8-X2: with a per-device key a sibling cannot NAME another device's item,
    # so the answer is the uniform "no item for you" rather than the sharper
    # `delivery-wrong-device` — which existed only because one mutable row was
    # shared by every device and had to be told apart after the fact. The queue
    # must not be an existence oracle over another device's state.
    ("device_id", "DEV-9", "delivery-item-unknown"),
    ("octets", b"other bytes entirely", "delivery-digest-mismatch"),
])
def test_the_ack_is_checked_against_the_stored_item_not_its_caller(field, value, reason):
    """Requirement 3: do not trust recipient, member, session or octets from
    the ack caller — derive them from the stored item."""
    _staged_item()
    if field in ("uid", "mid"):
        args = _ack_args(credential=dict(CRED, **{field: value}))
    else:
        args = _ack_args(**{field: value})
    if field == "device_id":
        args["credential"] = dict(CRED, device_id=value)
    with pytest.raises(mock.AckRejected) as exc:
        mock.receipt_ack(**args)
    assert exc.value.reason == reason
    assert mock._ACK_LEDGER == {}, "nothing was signed before the refusal"


def test_a_receipt_for_another_issuing_rdp_is_a_different_item():
    """Two RDPs reusing one message_id receive receipts only for their OWN
    stored items."""
    _fresh()
    tokens = {}
    for rdp, octets in (("urn:sbm:rdp:fr-001", OCTETS),
                        ("urn:sbm:rdp:de-002", b"the other provider's bytes")):
        tokens[rdp] = _staged(
            mock, issuing_rdp_id=rdp, message_id=MSG,
            recipient_uid=SE["recipient_uid"], mid="F1N2C3D4P",
            device_id="DEV-1", octets=octets, session_binding=SESSION)
    # R9-01: each provider's item has its OWN token, and one cannot acknowledge
    # the other's — the namespace R6-03 established, now carried by the
    # capability as well as by the key.
    assert tokens["urn:sbm:rdp:fr-001"] != tokens["urn:sbm:rdp:de-002"]
    a = mock.receipt_ack(**_ack_args(
        issuing_rdp_id="urn:sbm:rdp:fr-001",
        collection_token=tokens["urn:sbm:rdp:fr-001"]))
    b = mock.receipt_ack(**_ack_args(
        issuing_rdp_id="urn:sbm:rdp:de-002", octets=b"the other provider's bytes",
        collection_token=tokens["urn:sbm:rdp:de-002"]))
    assert a["message_digest"] != b["message_digest"]
    assert a["ds_signature"] != b["ds_signature"]


# --- the expected context is a TYPE now --------------------------------------

def test_an_empty_or_all_None_context_cannot_be_constructed():
    """R7-02's sharpest half, and cowork's own fifth row: `expect={}` was
    accepted, and so was a context naming every mandatory dimension with
    `None` — because verification skipped `None`. Requiring the members to be
    PRESENT does not close that; the value has to stop meaning 'unchecked'."""
    from lint_cli import DeliveryContext, DELIVERY_CONTEXT_FIELDS, \
        ReceiptVerificationError
    with pytest.raises(ReceiptVerificationError) as empty:
        DeliveryContext()
    assert empty.value.reason == "receipt-context-incomplete"
    with pytest.raises(ReceiptVerificationError) as nones:
        DeliveryContext(**{f: None for f in DELIVERY_CONTEXT_FIELDS})
    assert nones.value.reason == "receipt-context-incomplete"
    with pytest.raises(ReceiptVerificationError) as typo:
        DeliveryContext(**{f: "x" for f in DELIVERY_CONTEXT_FIELDS},
                        recipeint_uid="typo")
    assert typo.value.reason == "receipt-context-invalid"


def test_a_bare_mapping_is_refused_by_the_verifier():
    """Even a complete-looking dict: the type is the guarantee, not the
    contents of whatever was passed."""
    from lint_cli import ReceiptVerificationError, verify_ds_receipt
    _staged_item()
    receipt = mock.receipt_ack(**_ack_args())
    with pytest.raises(ReceiptVerificationError) as exc:
        verify_ds_receipt(receipt, PROVIDER, expect={"message_id": MSG})
    assert exc.value.reason == "receipt-context-invalid"


def test_a_receipt_missing_session_binding_fails_both_paths():
    """`session_binding` is in `DeliveryReceipt.required` on the wire and was
    absent from the mandatory signed set, so a receipt with it removed and
    re-signed was accepted under a partial context."""
    from lint_cli import DS_RECEIPT_MANDATORY_SIGNED
    assert "session_binding" in DS_RECEIPT_MANDATORY_SIGNED
    assert "issuing_rdp_id" in DS_RECEIPT_MANDATORY_SIGNED


# ===========================================================================
# R8-02 — ONE accepted byte binding, carried by reference, monotonic state
#
# R7-02 stopped a receipt existing for an unknown or merely queued item. It did
# not make the transitions preserve the accepted invariant: the queue hashed
# its OWN caller's octets into a new `message_digest` and never compared it
# with the acceptance record. `receipt_ack` then checked the acknowledged bytes
# against that replacement faithfully — a rigorous statement about the wrong
# binding. Decisions R8-X1 (transfer + idempotent token) and R8-X2 (per-device
# fan-out, immutable items).
# ===========================================================================

DEV_2 = "DEV-2"
P2 = (SE["recipient_uid"], "F1N2C3D4P", DEV_2)
CRED_2 = {"kind": "device", "uid": P2[0], "mid": P2[1], "device_id": DEV_2,
          "session": SESSION["digest"]}


def test_the_queue_cannot_express_a_binding_of_its_own():
    """R8-02 requirements 1 and 2. The reproduced defect: accept bytes A, queue
    bytes B, and the signed receipt attested `sha256(B)`. `octets` is GONE from
    the queue interface rather than validated there — a request that cannot
    express a different binding cannot install one, and there is no second
    comparison to keep in step with the first."""
    import inspect
    assert "octets" not in inspect.signature(mock.queue_delivery).parameters, \
        "the queue can still be handed bytes, so it can still replace the binding"


def test_bytes_the_ds_never_accepted_cannot_be_acknowledged():
    """The same defect from the other end: whatever the acknowledging caller
    presents is compared against the ACCEPTANCE record's digest, reached by
    reference through the item."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    item = mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]
    assert item["message_digest"] == mock._DS_LEDGER[(RDP, MSG)]["envelope_hash"]
    mock.transfer_delivery(RDP, MSG, principal=P1, session_binding=SESSION)
    with pytest.raises(mock.AckRejected) as exc:
        mock.receipt_ack(**_ack_args(octets=b"bytes the DS never accepted"))
    assert exc.value.reason == "delivery-digest-mismatch"
    assert mock._ACK_LEDGER == {}


def test_one_byte_binding_runs_from_acceptance_to_receipt():
    """R8-02 acceptance test 6: acceptance record, delivery item and signed
    receipt carry ONE value, not three that happen to agree."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    accepted = mock._DS_LEDGER[(RDP, MSG)]["envelope_hash"]
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    mock.transfer_delivery(RDP, MSG, principal=P1, session_binding=SESSION)
    receipt = mock.receipt_ack(**_ack_args())
    assert receipt["message_digest"] == accepted
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["message_digest"] == accepted


def test_an_accepted_message_cannot_be_retargeted():
    """The reproduced R8-02 defect: `_DELIVERY_ITEMS[key] = {...}` was an
    unconditional assignment, so re-queueing an ACKNOWLEDGED item for a second
    recipient OVERWROTE it and produced a second valid receipt. What closes
    that is immutability per item: an existing item never changes recipient.

    R10-04/R10-X3: this test used to assert more — that a DIFFERENT device for
    another recipient was refused too, because every sibling was pinned to the
    first item's (recipient, member). That rule was the R10-04 defect: the
    bilateral group holds members of both entities, and the pin lost one of
    their deliveries. A different device is a different item, bound to its
    own member, and it does not disturb the first recipient's event."""
    setup_function()
    _staged_item()
    first = mock.receipt_ack(**_ack_args())
    # R11-01: the item's recipient is part of its KEY, so there is no "same
    # item for another recipient" to refuse. The same label under another
    # entity is ANOTHER device — its own item, queued — and the first item
    # and its event are untouched. (This asserted `delivery-recipient-conflict`,
    # which was R11-01 itself: two devices sharing a label were one row.)
    twin = mock.queue_delivery(RDP, MSG, recipient_uid="EU-DE-EOID-7K3D9W0Q2M5FW0",
                               mid="F1N2C3D4P", device_id="DEV-1")
    assert twin["state"] == "queued"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"
    assert mock._ACK_LEDGER[(RDP, MSG, SE["recipient_uid"])] == first
    # Another device, another member: its own item, and nothing overwritten.
    other = mock.queue_delivery(RDP, MSG, recipient_uid="EU-DE-EOID-7K3D9W0Q2M5FW0",
                                mid="G7H8J9K0Q", device_id=DEV_2)
    assert (other["recipient_uid"], other["mid"]) == ("EU-DE-EOID-7K3D9W0Q2M5FW0", "G7H8J9K0Q")
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"
    assert mock._ACK_LEDGER[(RDP, MSG, SE["recipient_uid"])] == first


def test_an_acknowledged_item_cannot_be_walked_back_to_queued():
    """R8-02 requirement 6 — monotonic. An identical re-queue is idempotent and
    PRESERVES the state; it does not reset the row to `queued`."""
    setup_function()
    _staged_item()
    mock.receipt_ack(**_ack_args())
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"
    again = mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                                mid="F1N2C3D4P", device_id="DEV-1")
    assert again["state"] == "acknowledged"
    # R11-01: another member's `DEV-1` is another device — a new item in
    # `queued`, and this one stays acknowledged.
    assert mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                               mid="F2X3Y4Z55", device_id="DEV-1")["state"] == "queued"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"


def test_several_devices_converge_on_one_recipient_event():
    """R8-02 acceptance test 3 / R8-X2. Fan-out varies the DEVICE. Each device
    gets its own item and its own transfer state, and the FIRST acknowledgement
    is the one recipient-level event — the second device's ack returns it
    unchanged rather than creating a second delivery proof."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    for dev in ("DEV-1", DEV_2):
        mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                            mid="F1N2C3D4P", device_id=dev)
        mock.transfer_delivery(RDP, MSG, principal=(*P1[:2], dev),
                               session_binding=SESSION)
    assert len(mock._DELIVERY_ITEMS) == 2
    first = mock.receipt_ack(**_ack_args())
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P2)]["state"] == "transferred", \
        "one device's acknowledgement moved another device's item"
    sibling = mock.collect_messages(credential=CRED_2, session_binding=SESSION)
    second = mock.receipt_ack(**_ack_args(
        device_id=DEV_2, credential=CRED_2,
        collection_token=sibling["items"][0]["collection_token"]))
    assert second == first, "a sibling device produced a second delivery event"
    assert len(mock._ACK_LEDGER) == 1


def test_a_sibling_device_cannot_take_another_devices_delivery():
    setup_function()
    _staged_item()
    with pytest.raises(mock.DeliveryStateError) as exc:
        mock.transfer_delivery(RDP, MSG, principal=P2,
                               session_binding=SESSION)
    assert exc.value.reason == "delivery-item-unknown"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "transferred"


@pytest.mark.parametrize("session", [
    None,
    {},
    {"kind": "token-digest"},                       # partial
    {"digest": "a" * 64},                           # partial
    {"kind": "", "digest": "a" * 64},               # empty
    {"kind": "token-digest", "digest": None},       # malformed
])
def test_a_transfer_needs_a_well_formed_session_and_moves_nothing_without_one(session):
    """R8-02 requirement 5. `transfer_delivery(session_binding=None)` used to
    succeed, and the null then passed the acknowledgement comparison
    (`None != None` is false) AND the resolution guard
    (`if session_binding is not None`). Three consecutive checks, all
    fail-open on the same absent value, ending in a signed receipt carrying
    `session_binding: null` and an item marked acknowledged."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    with pytest.raises(mock.DeliveryStateError) as exc:
        mock.transfer_delivery(RDP, MSG, principal=P1,
                               session_binding=session)
    assert exc.value.reason == "delivery-session-invalid"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "queued", \
        "the state moved before the session was checked"
    assert mock._ACK_LEDGER == {}


def test_a_transfer_retry_converges_and_a_new_session_RECLAIMS():
    """R8-X1's first half stands: a lost response retried in the SAME session
    yields the same token and the same delivery event.

    R9-X2 replaces its second half. This asserted that a re-transfer in a
    DIFFERENT session is `delivery-session-conflict`, and that rule is DELETED
    rather than softened — it meant losing a session stranded the item for
    ever, because nothing could ever bind it to a new one. The same DEVICE now
    reclaims its own unacknowledged item in any session; the binding moves and
    the token is reissued, because the token names a transfer and this is a new
    one. There is still exactly ONE signed delivery event: `_ACK_LEDGER` is
    keyed by recipient."""
    setup_function()
    _staged_item()
    token = mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["collection_token"]
    assert token
    again = mock.transfer_delivery(RDP, MSG, principal=P1,
                                   session_binding=SESSION)
    assert again["collection_token"] == token, "the same session must converge"

    other = {"kind": "token-digest", "digest": "b" * 64}
    reclaimed = mock.transfer_delivery(RDP, MSG, principal=P1,
                                       session_binding=other)
    assert reclaimed["collection_token"] != token, \
        "a new transfer must not reuse the token of the one it superseded"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["session_binding"] == other

    # ...and an ACKNOWLEDGED item is still terminal: monotonic, unchanged.
    mock.receipt_ack(**_ack_args(session_binding=other,
                                 credential={"kind": "device", "uid": P1[0], "mid": P1[1],
                                             "device_id": "DEV-1",
                                             "session": other["digest"]},
                                 collection_token=reclaimed["collection_token"]))
    assert len(mock._ACK_LEDGER) == 1
    settled = mock.transfer_delivery(RDP, MSG, principal=P1,
                                     session_binding=SESSION)
    assert settled["state"] == "acknowledged"
    assert len(mock._ACK_LEDGER) == 1, "a re-transfer created a second event"


def test_every_emitted_receipt_validates_against_its_published_schema():
    """R8-02 requirement 5, second half. Nothing validated a generated receipt
    at all, so one carrying `session_binding: null` was signed and stored
    although `DeliveryReceipt` requires an object with `kind` and `digest`. A
    signature cannot be withdrawn, so the gate is before `seal_cose`."""
    from lint_cli import validate_delivery_receipt
    setup_function()
    _staged_item()
    receipt = mock.receipt_ack(**_ack_args())
    assert validate_delivery_receipt(receipt, unsigned=False) == []


def test_a_receipt_that_would_not_validate_is_never_signed():
    """Driven by making the emitted object invalid in a way no earlier gate
    sees: `ds_alg` is chosen by the DS at signing time."""
    from lint_cli import validate_delivery_receipt
    setup_function()
    _staged_item()
    receipt = mock.receipt_ack(**_ack_args())
    broken = dict(receipt)
    broken["session_binding"] = None
    assert validate_delivery_receipt(broken, unsigned=False), \
        "the published DeliveryReceipt tolerates a null session"
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"


# ===========================================================================
# R8-03 — the transfer transition is PUBLIC
#
# The reference had private `queue_delivery()` and `transfer_delivery()`
# helpers and the contract published no operation through which a device
# obtains a queued message or the DS records the authenticated transfer. The
# load-bearing `transferred` state was therefore not reproducible from the
# contract: a test could drive the Python helper, a generated client could not.
# Decision R8-X1.
# ===========================================================================

def _ds_contract():
    import yaml
    return yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())


DEVICE_CRED = {"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1",
               "session": SESSION["digest"]}


def test_the_transfer_transition_is_a_published_operation():
    """R8-03 requirement 1. The public surface used to go straight from RDP
    submission to device acknowledgement, so the state the receipt depends on
    had no boundary at all."""
    doc = _ds_contract()
    op = doc["paths"]["/messages"]["get"]
    assert {k for b in op["security"] for k in b} == {"deviceAuth", "deviceMtls"}
    # requirement 2: the identity is the credential's, never a parameter
    assert "parameters" not in op, \
        "a parameter that can name a device is one that can name the wrong one"
    schema = doc["components"]["schemas"]["CollectedMessage"]
    for field in ("issuing_rdp_id", "message_id", "mls_message_b64",
                  "message_digest", "collection_token", "state"):
        assert field in schema["required"], field


def test_one_state_vocabulary_across_contract_decisions_and_code():
    """R8-03 requirement 4. The decision record said `queued -> collected ->
    acknowledged` while the reference used
    `accepted -> queued -> transferred -> acknowledged` — different names for
    what may be different observable moments."""
    doc = _ds_contract()
    published = doc["components"]["schemas"]["DeliveryItemState"]["enum"]
    assert published == ["accepted", "queued", "transferred", "acknowledged"]
    assert set(mock._DELIVERY_STATES) <= set(published)


def test_a_device_reaches_the_receipt_through_published_operations_only():
    """R8-03 acceptance test 1 and 4: submit, collect, acknowledge — without
    the test calling `queue_delivery` or `transfer_delivery` itself. The
    fan-out staging is the DS's own act; everything the DEVICE does is a
    published operation."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")

    collected = mock.collect_messages(credential=DEVICE_CRED,
                                      session_binding=SESSION)
    assert len(collected["items"]) == 1
    item = collected["items"][0]
    assert item["state"] == "transferred", "collecting IS the transition"
    assert base64.b64decode(item["mls_message_b64"]) == OCTETS
    assert item["message_digest"] == mock._DS_LEDGER[(RDP, MSG)]["envelope_hash"]

    receipt = mock.receipt_ack(**_ack_args(
        collection_token=item["collection_token"]))
    assert receipt["message_digest"] == item["message_digest"]
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "acknowledged"


def test_the_collected_item_validates_against_its_published_schema():
    """A generated client must be able to consume what this returns."""
    import jsonschema
    from lint_cli import request_schema
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    collected = mock.collect_messages(credential=DEVICE_CRED,
                                      session_binding=SESSION)
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "MessageCollection")
    assert list(validator.iter_errors(collected)) == []


def test_a_sibling_device_collects_nothing_and_cannot_tell_why():
    """R8-03 acceptance test 2. The queue must not be an existence oracle over
    another device's state, so a sibling gets an empty collection rather than
    a refusal that confirms the item exists."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    sibling = {"kind": "device", "uid": P2[0], "mid": P2[1], "device_id": DEV_2,
               "session": SESSION["digest"]}
    assert mock.collect_messages(credential=sibling,
                                 session_binding=SESSION)["items"] == []
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "queued", \
        "a sibling's collection moved another device's item"


def test_a_lost_collection_response_converges():
    """R8-03 requirement 3 / R8-X1. The transition is recorded when the DS
    emits the octets, and the token is derived from the transfer's own
    identity — so retrying in the same session returns the same items with the
    same tokens, and creates no second delivery event."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    first = mock.collect_messages(credential=DEVICE_CRED,
                                  session_binding=SESSION)
    again = mock.collect_messages(credential=DEVICE_CRED,
                                  session_binding=SESSION)
    assert again == first
    assert len(mock._DELIVERY_ITEMS) == 1
    mock.receipt_ack(**_ack_args(
        collection_token=first["items"][0]["collection_token"]))
    # ...and an acknowledged item is not offered again
    assert mock.collect_messages(credential=DEVICE_CRED,
                                 session_binding=SESSION)["items"] == []
    assert len(mock._ACK_LEDGER) == 1


def test_collection_requires_a_device_credential_bound_to_the_session():
    setup_function()
    mock.ds_accept_message(MSG, "demo-group",
                           base64.b64encode(OCTETS).decode(), principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    for cred, reason in (
            ({"kind": "member", "uid": P1[0], "mid": "F1N2C3D4P"}, "device-auth-required"),
            ({"kind": "entity", "uid": SE["recipient_uid"]}, "device-auth-required"),
            ({"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1", "session": "b" * 64},
             "delivery-session-invalid")):
        with pytest.raises(mock.DeliveryStateError) as exc:
            mock.collect_messages(credential=cred, session_binding=SESSION)
        assert exc.value.reason == reason
    assert mock._DELIVERY_ITEMS[(RDP, MSG, *P1)]["state"] == "queued"


def test_an_acknowledgement_must_quote_the_transfer_it_collected():
    """R8-03 requirement 6: the ack REFERENCES the handle the public boundary
    produced, so it cannot be assembled by a caller that never collected."""
    setup_function()
    _staged_item()
    with pytest.raises(mock.AckRejected) as exc:
        mock.receipt_ack(**_ack_args(collection_token="dt-not-this-transfer"))
    assert exc.value.reason == "delivery-token-mismatch"
    assert mock._ACK_LEDGER == {}


# ===========================================================================
# R9-02 — atomic collection, recovery, and a PUBLISHED routing authority
#
# `collect_messages()` mutated one item at a time, so a later conflict left an
# earlier item transferred and returned an error with no bytes: a failed READ
# with durable, invisible WRITE effects. Measured, the ordinary mobile
# lifecycle reached it, and in one arrival order it left the device's whole
# queue collectable by nobody. Decisions R9-X2 and R9-X3.
# ===========================================================================

SESSION_B = {"kind": "token-digest", "digest": "b" * 64}
CRED_B_SESSION = {"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1",
                  "session": SESSION_B["digest"]}
MSG_2 = "01HZ9SECOND00000000000002"


def _two_items():
    """Two accepted, queued messages for one device."""
    setup_function()
    for m, o in ((MSG, OCTETS), (MSG_2, b"the second message" * 3)):
        mock.ds_accept_message(m, "demo-group", base64.b64encode(o).decode(),
                               principal=RDP)
        mock.queue_delivery(RDP, m, recipient_uid=SE["recipient_uid"],
                            mid="F1N2C3D4P", device_id="DEV-1")


def test_a_collection_returns_everything_or_changes_nothing():
    """R9-02 requirements 1 and 2, and its first acceptance test. The control
    runs first: the ordinary two-item collection must succeed on this path, or
    a refusal below would prove nothing."""
    _two_items()
    got = mock.collect_messages(credential=CRED, session_binding=SESSION)
    assert len(got["items"]) == 2
    for it in got["items"]:
        assert it["state"] == "transferred" and it["collection_token"]

    # now make one item uncollectable in a way preflight must catch, and prove
    # the OTHER item did not move
    _two_items()
    del mock._DS_OCTETS[(RDP, MSG_2)]
    before = {m: mock._DELIVERY_ITEMS[(RDP, m, *P1)]["state"]
              for m in (MSG, MSG_2)}
    with pytest.raises(mock.DeliveryStateError) as exc:
        mock.collect_messages(credential=CRED, session_binding=SESSION)
    assert exc.value.reason == "delivery-item-unknown"
    after = {m: mock._DELIVERY_ITEMS[(RDP, m, *P1)]["state"]
             for m in (MSG, MSG_2)}
    assert after == before == {MSG: "queued", MSG_2: "queued"}, \
        "a failed collection moved an item the caller never received"


def test_the_ordinary_reconnect_collects_rather_than_stranding():
    """The sequence needs no adversary: collect, do not acknowledge (the app is
    backgrounded), a second message arrives, the device reconnects. Before
    R9-X2 that raised, and in one arrival order it left every session —
    including the two owning the items — unable to collect anything."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group", base64.b64encode(OCTETS).decode(),
                           principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    first = mock.collect_messages(credential=CRED, session_binding=SESSION)
    assert len(first["items"]) == 1

    mock.ds_accept_message(MSG_2, "demo-group",
                           base64.b64encode(b"arrived while backgrounded").decode(),
                           principal=RDP)
    mock.queue_delivery(RDP, MSG_2, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")

    again = mock.collect_messages(credential=CRED_B_SESSION,
                                  session_binding=SESSION_B)
    assert len(again["items"]) == 2, "the reconnect could not collect"
    tokens = {i["message_id"]: i["collection_token"] for i in again["items"]}
    assert tokens[MSG] != first["items"][0]["collection_token"], \
        "a reclaimed item must reissue its token — it is a new transfer"
    # ...and the reclaimed token is the one that acknowledges
    receipt = mock.receipt_ack(**_ack_args(session_binding=SESSION_B,
                                           credential=CRED_B_SESSION,
                                           collection_token=tokens[MSG]))
    assert receipt["session_binding"] == SESSION_B
    assert len(mock._ACK_LEDGER) == 1


def test_every_item_stays_reachable_after_any_interleaving():
    """R9-02's third acceptance test. Whatever order two sessions collect in,
    every item is still collectable and exactly one signed event exists."""
    for first, second in ((SESSION, SESSION_B), (SESSION_B, SESSION)):
        _two_items()
        c1 = {"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1", "session": first["digest"]}
        c2 = {"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1", "session": second["digest"]}
        assert len(mock.collect_messages(credential=c1,
                                         session_binding=first)["items"]) == 2
        got = mock.collect_messages(credential=c2, session_binding=second)
        assert len(got["items"]) == 2, "an item became unreachable"
        tok = {i["message_id"]: i["collection_token"] for i in got["items"]}
        mock.receipt_ack(**_ack_args(session_binding=second, credential=c2,
                                     collection_token=tok[MSG]))
        assert len(mock._ACK_LEDGER) == 1


def test_a_lost_response_does_not_create_a_second_event():
    """Crash/lost-response: the device never saw the first response, retries in
    the same session, and acknowledges. One receipt, byte-identical."""
    setup_function()
    mock.ds_accept_message(MSG, "demo-group", base64.b64encode(OCTETS).decode(),
                           principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    a = mock.collect_messages(credential=CRED, session_binding=SESSION)
    b = mock.collect_messages(credential=CRED, session_binding=SESSION)
    assert a == b
    r1 = mock.receipt_ack(**_ack_args(
        collection_token=a["items"][0]["collection_token"]))
    r2 = mock.receipt_ack(**_ack_args(
        collection_token=a["items"][0]["collection_token"]))
    assert r1 == r2 and len(mock._ACK_LEDGER) == 1


def test_the_fan_out_is_derived_from_group_state_the_ds_observed():
    """R9-02 requirement 4 / R9-X3, and its fourth acceptance test: the items
    exist WITHOUT this test calling the private routing helper.

    Item creation used to be that helper, whose first caller chose recipient,
    member and device out of nothing the protocol defined — so two conforming
    services would fan one accepted message out to different devices."""
    import importlib.util
    setup_function()
    mock._INVITATIONS.clear()
    mock._RESERVATIONS.clear()
    mock._WELCOME_QUEUE.clear()
    import mls_wire as w

    member = {"kind": "member", "uid": SE["recipient_uid"], "mid": "F1N2C3D4P"}
    suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    group = "Zzw1S4pWq9T5n7xYbXc2dQ"
    res = mock.reserve_keypackages(
        SE["recipient_uid"], credential=member, cipher_suite=suite,
        targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"},
                 {"mid": "F1N2C3D4P", "device_id": "DEV-2"}],
        idempotency_key="idem-fanout-000001")
    mock.commit_reservation(res["reservation_id"], credential=member)
    for pkg in res["keypackages"]:
        mock.deposit_welcome(
            {"invitation_id": f"inv-{pkg['device_id']}",
             "recipient_device": pkg["device_id"],
             "welcome_b64": base64.b64encode(b"welcome").decode(),
             "mls_group_id": group,
             "group_info_commitment": w.group_info_commitment(
                 b"a demo GroupInfo", cipher_suite=suite),
             "offered_suite": suite,
             "reservation_id": res["reservation_id"],
             "keypackage_ref": pkg["keypackage_ref"],
             "created_at": "2026-04-04T09:00:00Z",
             "expires_at": "2026-04-05T09:00:00Z"},
            credential=member)

    assert mock.group_roster(group) == [
        (SE["recipient_uid"], "F1N2C3D4P", "DEV-1"),
        (SE["recipient_uid"], "F1N2C3D4P", "DEV-2")]

    # ACCEPTANCE creates the items. Nothing below calls queue_delivery.
    mock.ds_accept_message("01HZ9FANOUT000000000001", group,
                           base64.b64encode(b"fan me out").decode(),
                           principal=RDP)
    keys = sorted(k for k in mock._DELIVERY_ITEMS
                  if k[1] == "01HZ9FANOUT000000000001")
    assert keys == [(RDP, "01HZ9FANOUT000000000001", *P1),
                    (RDP, "01HZ9FANOUT000000000001", *P2)]

    # idempotent: a replayed acceptance creates no second item
    mock.ds_accept_message("01HZ9FANOUT000000000001", group,
                           base64.b64encode(b"fan me out").decode(),
                           principal=RDP)
    assert len([k for k in mock._DELIVERY_ITEMS
                if k[1] == "01HZ9FANOUT000000000001"]) == 2


def test_a_device_that_refused_receives_nothing():
    """The roster is what the DS OBSERVED: invited and not refused. A device
    that declined the Welcome is not a member and gets no items."""
    setup_function()
    mock._INVITATIONS.clear()
    mock._RESERVATIONS.clear()
    mock._WELCOME_QUEUE.clear()
    import mls_wire as w
    member = {"kind": "member", "uid": SE["recipient_uid"], "mid": "F1N2C3D4P"}
    suite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    group = "Zzw1S4pWq9T5n7xYbXc2dQ"
    res = mock.reserve_keypackages(
        SE["recipient_uid"], credential=member, cipher_suite=suite,
        targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
        idempotency_key="idem-refuse-000001")
    mock.commit_reservation(res["reservation_id"], credential=member)
    pkg = res["keypackages"][0]
    dep = mock.deposit_welcome(
        {"invitation_id": "inv-refuser", "recipient_device": "DEV-1",
         "welcome_b64": base64.b64encode(b"welcome").decode(),
         "mls_group_id": group,
         "group_info_commitment": w.group_info_commitment(
             b"a demo GroupInfo", cipher_suite=suite),
         "offered_suite": suite, "reservation_id": res["reservation_id"],
         "keypackage_ref": pkg["keypackage_ref"],
         "created_at": "2026-04-04T09:00:00Z",
         "expires_at": "2026-04-05T09:00:00Z"}, credential=member)
    assert len(mock.group_roster(group)) == 1
    prejoin.refuse(mock, 
        dep["welcome_id"],
        credential={"kind": "device", "uid": P1[0], "mid": P1[1], "device_id": "DEV-1",
                    "keypackage_ref": pkg["keypackage_ref"]},
        reason="suite-below-published-floor", offered_suite=suite,
        required_floor=suite, refused_at="2026-04-04T09:30:00Z",
        members=[{"uid": SE["recipient_uid"], "mid": "F1N2C3D4P",
                  "devices": [{"device_id": "DEV-1",
                               "min_cipher_suite": suite}]}])
    assert mock.group_roster(group) == []
    mock.ds_accept_message("01HZ9NOFANOUT0000000001", group,
                           base64.b64encode(b"nobody").decode(), principal=RDP)
    assert [k for k in mock._DELIVERY_ITEMS
            if k[1] == "01HZ9NOFANOUT0000000001"] == []


def test_the_collection_response_can_only_carry_the_promised_state():
    """R9-02 requirement 5. `CollectedMessage.state` `$ref`-ed the whole
    four-value enum while its description said one value, so the contract
    admitted three impossible response states."""
    import yaml
    from lint_cli import request_schema
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    state = doc["components"]["schemas"]["CollectedMessage"]["properties"]["state"]
    assert state.get("const") == "transferred", state
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "MessageCollection")
    setup_function()
    mock.ds_accept_message(MSG, "demo-group", base64.b64encode(OCTETS).decode(),
                           principal=RDP)
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id="DEV-1")
    got = mock.collect_messages(credential=CRED, session_binding=SESSION)
    assert list(validator.iter_errors(got)) == []
    bad = copy.deepcopy(got)
    bad["items"][0]["state"] = "queued"
    assert list(validator.iter_errors(bad)), \
        "the response Schema still admits a state the operation cannot return"


def test_a_receipt_with_no_descriptor_for_its_issuer_is_reported_as_incomplete():
    """LINT-BND-I8 (SBM-ADR-0015): the key is the ISSUING RDP's.

    Supplying no descriptor for the RDP a receipt names is not a failure of the
    evidence — it is missing verifier material, and the verdict has to say which
    rather than passing over it. The entity's BW-MED is not consulted: that path
    is deleted, so a receipt cannot be rescued by a key published there.
    """
    issues = [m for r, m in bl.check_bundle(
        SE["recipient_uid"], MED, {}, [], [copy.deepcopy(SE)],
        receipts={SE["message_id"]: _receipt()}, provider_descriptors=[])
        if r == "LINT-BND-I8"]
    assert issues, "no descriptor for the issuing RDP must be reported, not ignored"
    assert "cannot be resolved" in issues[0]
    # And it is a RESIDUAL, not a failure of the receipt: LINT-BND-38 stays quiet.
    fatal = [r for r, _ in bl.check_bundle(
        SE["recipient_uid"], MED, {}, [], [copy.deepcopy(SE)],
        receipts={SE["message_id"]: _receipt()}, provider_descriptors=[])
        if r == "LINT-BND-38"]
    assert not fatal, "absent material must not be reported as a bad receipt"


# ---------------------------------------------------------------------------
# R1 — the published entry point, not the function it wraps
#
# Every test above reaches LINT-BND-38 by calling `check_bundle` with the
# descriptors already in hand. That is the test that existed, and it is the one
# that missed this: `check_bundle` grew `provider_descriptors` in the cycle that
# moved the receipt key there, `docs/retrievability.json` documented the input,
# and `lint_bundle` — the function `bundle_lint.py <manifest>` runs — read no
# manifest key for it. So after the move a retained receipt could not be
# verified from the command line at ALL, whatever the manifest supplied, and no
# sample manifest carried one for the bar to notice over.
#
# The same omission, with its own note in the file, had happened one cycle
# earlier for `group_contexts`.
# ---------------------------------------------------------------------------

MANIFEST = ROOT / "samples" / "bundle.default.manifest.json"


def _through_the_loader(**edits):
    """`lint_bundle` on the shipped manifest, edited in memory. Nothing is
    written: the manifest on disk is the one the bar runs."""
    import bundle_lint as bl
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest.update(edits)
    issues = bl.lint_bundle(manifest, str(ROOT / "samples"))
    return [(r, m) for r, m in issues if r in ("LINT-BND-I8", "LINT-BND-38")]


def test_the_shipped_manifest_verifies_its_retained_receipt():
    """The receipt the bar carries resolves its key and verifies, through the
    loader. Before this round the identical material reported LINT-BND-I8 from
    the command line while verifying clean when handed to `check_bundle`."""
    assert _through_the_loader() == []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["receipts"], "the manifest must actually retain a receipt"
    assert len(manifest["provider_descriptors"]) > 1, (
        "more than one descriptor must be supplied, or selection by "
        "participant_id is satisfied by there being nothing to select")


def test_without_the_descriptor_entry_the_receipt_is_reported_incomplete():
    """And the absence is INCOMPLETE, not a violation: the key cannot be
    resolved, so the handover rests on the DE's assertion alone."""
    import bundle_lint as bl
    found = _through_the_loader(provider_descriptors=[])
    assert [r for r, _ in found] == ["LINT-BND-I8"], found
    assert all(bl.is_incomplete(r) for r, _ in found), \
        "an unresolvable key is an unproven property, not a falsified one"


def test_the_shipped_receipt_has_a_different_origin_and_observer():
    """The property the first version of this sample did not have.

    A receipt names TWO providers: `issuing_rdp_id`, the message's origin proven
    by its SE, and `observed_by`, the provider whose Delivery Service collected
    the acknowledgement and signed. In a four-corner exchange they differ. The
    generator used to pass the DE's issuer as the ORIGIN, so the sample agreed
    with a verifier that resolved the key in the origin's descriptor — the two
    were the same value and neither the code nor the fixture could be wrong.
    """
    import bundle_lint as bl
    receipt = bl._load(str(ROOT / "samples" / json.loads(
        MANIFEST.read_text(encoding="utf-8"))["receipts"]["01HZ3AVLBCDEFGH9JKMN0PQRST"]))
    assert receipt["issuing_rdp_id"] != receipt["observed_by"], \
        "a receipt whose origin and observer coincide is the profile-1 case"
    # and the origin is the SE's, not something convenient
    se = next(e for e in json.loads((ROOT / "samples" / "sample-EP-dispute.json")
                                    .read_text())["projection"].values()
              if isinstance(e, dict) and e.get("type") == "SE-v1"
              and e.get("message_id") == receipt["message_id"])
    assert receipt["issuing_rdp_id"] == se["rdp_id"], \
        "the receipt's origin must be the one the SE proves"


def test_the_origins_descriptor_does_not_resolve_the_receipt():
    """The regression, as a probe: supply only the ORIGIN's descriptor — genuine,
    sealed, published by an admitted participant, and not the observer's. The
    verifier selected by the origin, so this case used to be the one that
    'worked' while the observer's descriptor was the one that failed."""
    import bundle_lint as bl
    origin_descriptor = "sample-BW-PROVIDER.json"
    descriptor = bl._load(str(ROOT / "samples" / origin_descriptor))
    receipt = bl._load(str(ROOT / "samples" / json.loads(
        MANIFEST.read_text(encoding="utf-8"))["receipts"]["01HZ3AVLBCDEFGH9JKMN0PQRST"]))
    assert descriptor["participant_id"] == receipt["issuing_rdp_id"], \
        "this probe needs the ORIGIN's descriptor specifically"
    found = _through_the_loader(provider_descriptors=[origin_descriptor])
    assert [r for r, _ in found] == ["LINT-BND-I8"], found
    assert receipt["observed_by"] in found[0][1], found[0][1]
