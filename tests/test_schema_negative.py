# SPDX-License-Identifier: MIT
"""Negative and offline-resolution tests for the BW JSON Schemas.

`test_schemas.py` checks that the *valid* samples validate. This module
complements it by checking that the schemas actually *reject* malformed
documents — one case per important normative constraint — and that every
sample resolves entirely from the local schema store with no network access
(the failure mode that previously broke `scripts/schema_smoke.py`).

Each negative case takes a known-good sample, applies a single mutation, and
asserts the document no longer validates. The mutations are deliberately
minimal so a failure points at exactly one constraint.

Only keyword-asserted constraints are exercised (const / enum / pattern /
required / minItems / contains / additionalProperties); `format` is advisory
in jsonschema unless a format checker is registered, so these tests do not
rely on it.
"""

import copy
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# sample -> schema it must validate against
MAPPING = {
    "sample-SE.json": "evidence-se.schema.json",
    "sample-SE-multipart.json": "evidence-se.schema.json",
    "sample-SE-scoped.json": "evidence-se.schema.json",
    "sample-SE-agent.json": "evidence-se.schema.json",
    "sample-DE.json": "evidence-de.schema.json",
    "sample-DE-walletsig.json": "evidence-de.schema.json",
    "sample-DE-scoped.json": "evidence-de.schema.json",
    "sample-NDE.json": "evidence-nde.schema.json",
    "sample-NDE-mismatch.json": "evidence-nde.schema.json",
    "sample-RE.json": "evidence-re.schema.json",
    "sample-RELAY-b1.json": "evidence-relay.schema.json",
    "sample-RELAY-b2.json": "evidence-relay.schema.json",
    "sample-CE.json": "evidence-ce.schema.json",
    "sample-EP.json": "evidence-ep.schema.json",
    "sample-EP-scoped.json": "evidence-ep.schema.json",
    "sample-EP-federated.json": "evidence-ep.schema.json",
    "sample-BW-MED.json": "bw-med.schema.json",
    "sample-BW-MED-scoped.json": "bw-med.schema.json",
    "sample-BW-ORG.json": "bw-org.schema.json",
    "sample-BW-ORG-scoped.json": "bw-org.schema.json",
    "sample-BW-ORG-de.json": "bw-org.schema.json",
    "sample-BW-MEMBER.json": "bw-member.schema.json",
    "sample-BW-MEMBER-fr.json": "bw-member.schema.json",
    "sample-BW-MEMBER-agent.json": "bw-member.schema.json",
    "sample-BW-MEMBER-records.json": "bw-member.schema.json",
    "sample-ENVELOPE.json": "envelope.schema.json",
    "sample-DE-availability.json": "evidence-de.schema.json",
    "sample-ENVELOPE-availability.json": "envelope.schema.json",
}


def _require_jsonschema():
    try:
        import jsonschema  # noqa: F401
    except Exception:
        pytest.skip("jsonschema not installed; skipping schema tests",
                    allow_module_level=True)


_require_jsonschema()
import jsonschema  # noqa: E402


def _build_resolver():
    """Resolver pre-loaded with *every* schema in schemas/.

    Loading the whole directory (not just the ones directly mapped to a
    sample) means cross-references such as EP -> NDE/RE via `oneOf` resolve
    from the store instead of triggering a network fetch of the placeholder
    `$id` URLs.
    """
    store = {}
    for p in sorted((ROOT / "schemas").glob("*.schema.json")):
        sch = json.loads(p.read_text(encoding="utf-8"))
        if "$id" in sch:
            store[sch["$id"]] = sch
        store[str(p)] = sch
    return jsonschema.RefResolver(
        base_uri=str(ROOT.as_uri()) + "/schemas", referrer=None, store=store
    )


RESOLVER = _build_resolver()


def _schema(name):
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _sample(name):
    d = json.loads((ROOT / "samples" / name).read_text(encoding="utf-8"))
    # M4: the JSON Schema describes the projection (body); artefacts wrap it.
    if isinstance(d, dict) and "sm_artifact_b64" in d and "projection" in d:
        return d["projection"]
    return d


def _is_valid(instance, schema_name):
    try:
        jsonschema.validate(instance=instance, schema=_schema(schema_name),
                            resolver=RESOLVER, format_checker=jsonschema.FormatChecker())
        return True
    except jsonschema.ValidationError:
        return False


# --- offline-resolution guard (regression for the schema_smoke EP bug) -------

@pytest.mark.parametrize("sample,schema", sorted(MAPPING.items()))
def test_samples_resolve_offline(sample, schema):
    """Every sample must validate with refs resolved purely from the store.

    A RefResolutionError here means a `$ref` escaped to the network — the
    exact regression that made schema_smoke.py fail on sample-EP.json.
    """
    jsonschema.validate(instance=_sample(sample), schema=_schema(schema),
                        resolver=RESOLVER, format_checker=jsonschema.FormatChecker())


# --- negative cases ----------------------------------------------------------

def _mutate(sample_name, fn):
    doc = copy.deepcopy(_sample(sample_name))
    fn(doc)
    return doc


def _del(d, *keys):
    for k in keys:
        d.pop(k, None)


# (id, sample, schema, mutation) — each mutated doc MUST be invalid.
NEGATIVE_CASES = [
    # F1 (PoC feedback) — application envelope headers: content_digest is the
    # evidence Hash object {alg, hex, hash_mode} (the I-D (Application Envelope))
    ("env-missing-content-digest", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: _del(d, "content_digest")),
    ("env-digest-missing-hash-mode", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d["content_digest"].pop("hash_mode")),
    ("env-digest-truncated-hex", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d["content_digest"].update(hex="d8bae9a71f8d30c5")),
    ("env-bad-content-class", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d.update(content_class="Invoice")),
    ("env-noninteger-ttl", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d.update(ttl="3d")),
    ("env-bad-sender-addr", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d.update(sender_addr="mailto:ops@example.eu")),
    ("env-extra-header", "sample-ENVELOPE.json", "envelope.schema.json",
     lambda d: d.update(x_routing_hint="msp-3")),
    # V0 (thirteenth review, §8.3b): delivery grades in the DE (v1.10).
    ("de-missing-delivery-grade", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "delivery_grade")),
    ("de-missing-integrity-basis", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "integrity_basis")),
    ("de-avail-with-s3", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: d.update(s3_attestation={})),
    ("de-avail-with-kind", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: d.update(acceptance_policy_kind="any-one")),
    ("de-avail-wrong-event", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: d.update(event="E.1-ContentHandover")),
    ("de-avail-wrong-basis", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: d.update(integrity_basis="recipient-verified-digest")),
    ("de-acceptance-event-mismatch", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(event="E.1-ContentHandover")),
    ("de-d1-event-without-availability", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(event="D.1-ContentConsignment")),
    ("org-bad-grade-value", "sample-BW-ORG.json", "bw-org.schema.json",
     lambda d: d.update(delivery_grades={"invoice": "mailbox"})),
    ("org-bad-grade-class-key", "sample-BW-ORG.json", "bw-org.schema.json",
     lambda d: d.update(delivery_grades={"UPPER": "availability"})),
    # X0 (fourteenth review): the grade commitment (v1.11).
    ("de-avail-missing-commitment", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: _del(d, "grade_commitment")),
    ("de-nonavail-with-commitment", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(grade_commitment="ab" * 32)),
    ("de-malformed-commitment", "sample-DE-availability.json", "evidence-de.schema.json",
     lambda d: d.update(grade_commitment="not-hex")),
    ("env-avail-bad-salt", "sample-ENVELOPE-availability.json", "envelope.schema.json",
     lambda d: d.update(grade_commitment_salt="too-short")),
    # SE-v1
    ("se-wrong-version", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(version="1.0")),
    # F1 — object-level seal REQUIRED on every evidence object (SEAL-2)
    ("se-missing-profile", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "profile")),
    ("se-bad-profile", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(profile="qualified")),
    ("se-missing-auth-context", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "auth_context")),
    ("se-auth-context-bad-identity", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["auth_context"].update(identity="robot")),
    ("se-missing-acceptance-policy-ref", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "acceptance_policy_ref")),
    # S3/D6 — scope_ref REQUIRED on SE and DE
    ("se-missing-scope-ref", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "scope_ref")),
    ("de-missing-scope-ref", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "scope_ref")),
    ("se-scope-ref-missing-version", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["scope_ref"].pop("version")),
    # Multipart manifest (the I-D, Canonicalisation and Payload Hashing — Mode C / MANIFEST-1)
    ("se-multipart-part-missing-digest", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"][0].pop("digest")),
    ("se-multipart-empty-manifest", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d.update(manifest=[])),
    # F7 — manifest part_id / role
    ("se-manifest-missing-part-id", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"][0].pop("part_id")),
    ("se-manifest-missing-role", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"][0].pop("role")),
    ("se-manifest-bad-role", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"][0].update(role="cover-letter")),
    ("se-missing-mls-epoch", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "mls_epoch")),
    # M1/J0+ (twenty-fifth review): mls_epoch and manifest length are DECIMAL
    # STRINGS (uint64 / byte count); an integer or a leading-zero string is rejected.
    ("se-mls-epoch-as-integer", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(mls_epoch=3)),
    ("se-mls-epoch-leading-zero", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(mls_epoch="03")),
    ("se-multipart-length-as-integer", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"][0].update(length=42)),
    ("se-missing-mls-group-id", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "mls_group_id")),
    ("se-hash-mode-as-sibling", "sample-SE.json", "evidence-se.schema.json",
     lambda d: (d.__setitem__("hash_mode", d["payload_hash"].pop("hash_mode"))),),
    ("se-payload-hash-missing-mode", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["payload_hash"].pop("hash_mode")),
    ("se-legacy-auth-method", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(auth_method="oidc4vp+mls-credential")),
    ("se-legacy-transport", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(transport="SM-DR-1.0")),
    ("se-uid-colon-separator", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(sender_uid="EU:DE:EOID:7K3D9W0Q2M5FW0")),
    ("se-hex-uppercase", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["payload_hash"].update(
         hex=d["payload_hash"]["hex"].upper())),
    # Qualified timestamp (Art. 44(1)(f)) — REQUIRED and typed on SE/DE/NDE/RE
    # Relay evidence (RelayEvidence-v1; finding 1, twentieth review): a B.2
    # rejection requires a typed reason; a B.1 acceptance forbids one; the event
    # is a B.x relay event.
    ("relay-b2-missing-reason", "sample-RELAY-b2.json", "evidence-relay.schema.json",
     lambda d: _del(d, "reason")),
    ("relay-b1-has-reason", "sample-RELAY-b1.json", "evidence-relay.schema.json",
     lambda d: d.update(reason="policy-violation")),
    ("relay-bad-event", "sample-RELAY-b1.json", "evidence-relay.schema.json",
     lambda d: d.update(event="B.9-Nonsense")),
    # X-25: the reason VALUE SPACE is registry-governed (pattern-open) — the
    # schema now rejects only a LEXICALLY invalid code; registered-set semantics
    # are the linter's (LINT-NDE-07/W1) against registries/reason-codes.json.
    ("relay-bad-reason", "sample-RELAY-b2.json", "evidence-relay.schema.json",
     lambda d: d.update(reason="NOT-Lowercase-Kebab!")),
    ("relay-missing-receiving-rdp", "sample-RELAY-b1.json", "evidence-relay.schema.json",
     lambda d: _del(d, "receiving_rdp_id")),
    # DE recipient authentication (Art. 44(1)(c) / REQ-QERDS-5.2.2-03A)
    ("de-missing-recipient-auth", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "recipient_auth_method")),
    ("de-bad-recipient-auth", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(recipient_auth_method="device-ack")),
    # Evidence semantics (EN 319 522-2 clause 8 components G01/G03/R01)
    ("se-missing-event", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "event")),
    ("se-bad-event", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d.update(event="E.1-ContentHandover")),
    ("se-missing-evidence-id", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "evidence_id")),
    # R1 (twenty-fourth review): the SE carries an authenticated absolute expiry.
    ("se-missing-expires-at", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "expires_at")),
    # R3 (twenty-fourth review): a WALLET-SIGNED confirmation must identify its device.
    ("de-signed-confirmation-without-device-id", "sample-DE-walletsig.json",
     "evidence-de.schema.json", lambda d: _del(d["s3_attestation"], "device_id")),
    ("se-missing-policy-id", "sample-SE.json", "evidence-se.schema.json",
     lambda d: _del(d, "policy_id")),
    ("de-bad-event", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(event="A.1-SubmissionAcceptance")),
    # Delivery state model (the I-D, Message Flows and Delivery States / DELIV-1, DELIV-2)
    ("de-missing-s3", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "s3_attestation")),
    ("de-s3-hash-not-verified", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].update(hash_verified=False)),
    ("de-s3-missing-result", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("result")),
    ("de-s3-no-proof", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("session_authenticated")),
    # F2 — confirmation bound to message/session/policy; verified_at rename
    ("de-s3-missing-message-id", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("message_id")),
    ("de-s3-missing-mls-group-id", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("mls_group_id")),
    ("de-s3-missing-mls-epoch", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("mls_epoch")),
    ("de-s3-missing-acceptance-policy-ref", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].pop("acceptance_policy_ref")),
    ("de-s3-legacy-attested-at", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d["s3_attestation"].__setitem__("attested_at", d["s3_attestation"].pop("verified_at"))),
    ("de-event-d1-not-allowed", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(event="D.1-ContentConsignment")),
    ("de-missing-auth-context", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "auth_context")),
    ("de-missing-acceptance-policy-ref", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "acceptance_policy_ref")),
    ("nde-missing-event", "sample-NDE.json", "evidence-nde.schema.json",
     lambda d: _del(d, "event")),
    # S4/X-25 — the reason value space is PATTERN-bounded, not enum-closed: a
    # lexically invalid code fails the schema; an unknown-but-well-formed code is
    # accepted and handled generically (LINT-NDE-W1, registry-governed).
    ("nde-bogus-reason", "sample-NDE.json", "evidence-nde.schema.json",
     lambda d: d.update(reason="Not_A_Valid_Reason")),
    # CE-v1 change indication (Art. 44(1)(e))
    ("ce-bad-transformation", "sample-CE.json", "evidence-ce.schema.json",
     lambda d: d.update(transformation="content-rewrite")),
    ("ce-missing-transformation", "sample-CE.json", "evidence-ce.schema.json",
     lambda d: _del(d, "transformation")),
    # EP-v1
    ("ep-empty-outcomes", "sample-EP.json", "evidence-ep.schema.json",
     lambda d: d.update(outcomes=[])),
    # BW-MED-v1
    ("med-protocols-missing-mls", "sample-BW-MED.json", "bw-med.schema.json",
     lambda d: d.update(protocols=["SM-DR-1.0"])),
    ("med-ciphersuites-missing-baseline", "sample-BW-MED.json",
     "bw-med.schema.json",
     lambda d: d["mls"].update(cipher_suites=["MLS_256_DHKEMP384_AES256GCM_SHA384_P384"])),
    ("med-credential-mixed-oneof", "sample-BW-MED.json", "bw-med.schema.json",
     lambda d: d["identity_credential"].update(qeaa_ref="https://x/ref")),
    # BW-MEMBER-v1
    ("member-bad-mid", "sample-BW-MEMBER.json", "bw-member.schema.json",
     lambda d: d.update(mid="A1B2C3D4")),  # 8 chars, needs 9
    ("member-device-missing-leaf-ref", "sample-BW-MEMBER.json",
     "bw-member.schema.json",
     lambda d: _del(d["devices"][0], "mls_leaf_node_ref")),
    ("member-bad-leaf-key-hash", "sample-BW-MEMBER.json", "bw-member.schema.json",
     lambda d: d["devices"][0]["mls_leaf_node_ref"].update(
         signature_key_hash="deadbeef")),  # not 64 hex chars
    # M1 — BW-MEMBER signed by default: doc_cose_b64 is REQUIRED.
    # MID accountability (the QERDS-binding TS, clause 6 / ACCT-1)
    ("member-missing-accountability", "sample-BW-MEMBER.json", "bw-member.schema.json",
     lambda d: _del(d, "accountability")),
    ("member-accountability-bad-condition", "sample-BW-MEMBER.json", "bw-member.schema.json",
     lambda d: d["accountability"].update(access_conditions=["marketing"])),
    # A1 (Annex R): member_type is a closed enum person|system.
    ("member-bad-member-type", "sample-BW-MEMBER-agent.json", "bw-member.schema.json",
     lambda d: d.update(member_type="robot")),
    # A1 (Annex R): a system acting identity must name the acting agent's MID.
    ("se-system-identity-without-mid", "sample-SE-agent.json", "evidence-se.schema.json",
     lambda d: d["auth_context"].pop("mid")),
    # BW-ORG acceptance-policy publication/versioning (§8.3 / POL-1)
    ("org-missing-policy-version", "sample-BW-ORG.json", "bw-org.schema.json",
     lambda d: _del(d, "policy_version")),
    # S1 — confidentiality scope descriptor (§8.3a): recoverability REQUIRED, enum strict|records (D2)
    ("scope-missing-recoverability", "sample-BW-ORG-scoped.json", "bw-org.schema.json",
     lambda d: d["scope_map"]["scopes"][0].pop("recoverability")),
    ("scope-bad-recoverability", "sample-BW-ORG-scoped.json", "bw-org.schema.json",
     lambda d: d["scope_map"]["scopes"][0].update(recoverability="loose")),
    ("scope-bad-fallback", "sample-BW-ORG-scoped.json", "bw-org.schema.json",
     lambda d: d["scope_map"].update(fallback="anything-else")),
    ("scope-descriptor-extra-prop", "sample-BW-ORG-scoped.json", "bw-org.schema.json",
     lambda d: d["scope_map"]["scopes"][0].update(bogus="x")),
    # N1 — scope_id 'default' is reserved (schema belt for LINT-DISC-14)
    ("scope-reserved-default-schema", "sample-BW-ORG-scoped.json", "bw-org.schema.json",
     lambda d: d["scope_map"]["scopes"][0].update(scope_id="default")),
    # F3a — Hash alg/hash_mode/hex coherence (HASH-4)
    ("se-hash-alg-len-mismatch", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["payload_hash"].update(hex="a" * 128)),  # SHA-256 but 128 chars
    ("se-hash-mode-alg-mismatch", "sample-SE.json", "evidence-se.schema.json",
     lambda d: d["payload_hash"].update(hash_mode="manifest-sha512")),  # sha512 mode, SHA-256 alg
    # F3b — NDE reason conditionals (REASON-2)
    ("nde-mismatch-missing-confirmation", "sample-NDE.json", "evidence-nde.schema.json",
     lambda d: d.update(reason="payload-hash-mismatch")),  # no recipient_confirmation
    ("nde-merged-missing-redirect", "sample-NDE.json", "evidence-nde.schema.json",
     lambda d: d.update(reason="uid-merged")),  # no redirect_uid
    # F3c — DE acceptance_policy_kind (REQUIRED enum) + quorum conditional (DELIV-4)
    ("de-missing-acceptance-policy-kind", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "acceptance_policy_kind")),  # field itself is REQUIRED
    ("de-bad-acceptance-policy-kind", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(acceptance_policy_kind="majority")),  # not in enum
    ("de-quorum-missing-array", "sample-DE.json", "evidence-de.schema.json",
     lambda d: _del(d, "quorum")),  # kind=quorum but no quorum array
    ("de-quorum-empty-array", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(quorum=[])),  # empty quorum
    # F2 — RecipientConfirmation binding (same message/session/policy binding as
    # S3Attestation; exercised on the NDE-mismatch sample that carries one).
    ("nde-confirmation-missing-message-id", "sample-NDE-mismatch.json", "evidence-nde.schema.json",
     lambda d: d["recipient_confirmation"].pop("message_id")),
    ("nde-confirmation-missing-mls-group-id", "sample-NDE-mismatch.json", "evidence-nde.schema.json",
     lambda d: d["recipient_confirmation"].pop("mls_group_id")),
    ("nde-confirmation-missing-acceptance-policy-ref", "sample-NDE-mismatch.json", "evidence-nde.schema.json",
     lambda d: d["recipient_confirmation"].pop("acceptance_policy_ref")),
    ("nde-confirmation-legacy-attested-at", "sample-NDE-mismatch.json", "evidence-nde.schema.json",
     lambda d: d["recipient_confirmation"].__setitem__(
         "attested_at", d["recipient_confirmation"].pop("verified_at"))),
    ("nde-confirmation-no-proof", "sample-NDE-mismatch.json", "evidence-nde.schema.json",
     lambda d: d["recipient_confirmation"].pop("session_authenticated")),
    # V5 — schema tightening (belt to the evidence_lint braces)
    ("se-manifest-exact-duplicate", "sample-SE-multipart.json", "evidence-se.schema.json",
     lambda d: d["manifest"].append(json.loads(json.dumps(d["manifest"][0])))),  # uniqueItems
    ("de-quorum-wrong-event", "sample-DE.json", "evidence-de.schema.json",
     lambda d: d.update(event="E.1-ContentHandover")),  # kind=quorum ⇒ event must be C.3
]


@pytest.mark.parametrize("case", NEGATIVE_CASES, ids=[c[0] for c in NEGATIVE_CASES])
def test_malformed_documents_are_rejected(case):
    _id, sample, schema, mutate = case
    doc = _mutate(sample, mutate)
    assert not _is_valid(doc, schema), (
        f"{_id}: mutated document unexpectedly validated against {schema}")


def test_baseline_samples_are_valid():
    """Sanity check that the un-mutated samples do validate, so the negative
    cases above are isolating the mutation rather than a pre-existing fault."""
    for sample, schema in MAPPING.items():
        assert _is_valid(_sample(sample), schema), f"baseline {sample} invalid"


def test_reference_artefacts_never_claim_production():
    """F8: 'production' is a claim that a verifier must independently validate, so
    the reference mock and samples emit 'pilot' (non-qualified) and never assert
    'production'."""
    for p in sorted((ROOT / "samples").glob("sample-*.json")):
        txt = p.read_text(encoding="utf-8")
        assert '"production"' not in txt, f"{p.name} claims production"
    mock = (ROOT / "scripts" / "mock_rdp.py").read_text(encoding="utf-8")
    assert '"profile": "production"' not in mock, "mock_rdp emits production"


def test_mock_rdp_emits_object_level_seals():
    """F5: the reference mock seals every SE/DE it emits (rdp_cose_b64) and the
    output validates against the hardened schemas."""
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location(
            "mock_rdp", ROOT / "scripts" / "mock_rdp.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # ImportError (e.g. no flask) -> skip
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"mock_rdp not importable ({exc})")
    ep = mod.make_evidence({
        "from_uid": "EU-DE-EOID-7K3D9W0Q2M5FW0",
        "to_uid": "EU-FR-PSBID-ZYWVTSRQPNM8M4",
        "payload_hash": {
            "alg": "SHA-256",
            "hex": "d8bae9a71f8d30c5cf47817ac8299037541d1a46aa1ee2edd476e3b1119ec77e",
            "hash_mode": "raw-sha256"},
    })
    proj = ep["projection"]
    se, de = proj["se"], proj["outcomes"][0]
    assert "sm_artifact_b64" in ep
    assert se["profile"] == "pilot" and de["profile"] == "pilot"
    assert _is_valid(se, "evidence-se.schema.json")
    assert _is_valid(de, "evidence-de.schema.json")
    assert _is_valid(proj, "evidence-ep.schema.json")


def test_content_class_pattern_rejected_by_schema():
    """Q5 (tenth review): bw-org content_classes items carry the lexical
    two-tier pattern ^(x-)?[a-z][a-z0-9-]{0,62}$ — shape only; the registry-
    membership discipline is LINT-DISC-16."""
    org = _sample("sample-BW-ORG-scoped.json")
    # "x-" alone passes the schema's lexical shape but is rejected by the
    # stricter LINT-DISC-16 (empty private name) — see test_discovery_lint.
    for bad in ("Legal Notice!", "UPPER", "x:", "-leading"):
        doc = copy.deepcopy(org)
        doc["scope_map"]["scopes"][0]["content_classes"] = [bad]
        assert not _is_valid(doc, "bw-org.schema.json"), f"{bad!r} must fail the pattern"
    for good in ("invoice", "x-litigation"):
        doc = copy.deepcopy(org)
        doc["scope_map"]["scopes"][0]["content_classes"] = [good]
        assert _is_valid(doc, "bw-org.schema.json"), f"{good!r} must pass the pattern"


def test_edd_openapi_is_a_real_contract():
    """F6/N8: the EDD OpenAPI is a real contract, not a stub — it parses; its
    version is an INDEPENDENT API-contract version (not the evidence version);
    the member endpoint (on the key-discovery trust path) fails closed; and every
    declared GET response carries a schema, redirect, or typed error."""
    try:
        import yaml  # noqa: F401
    except Exception:
        pytest.skip("pyyaml not installed; skipping OpenAPI smoke test")
    spec = yaml.safe_load(
        (ROOT / "edd-resolver-openapi.yaml").read_text(encoding="utf-8"))

    # N8: the API contract is versioned independently of evidence/spec edition.
    # DERIVED, not restated: `make versions` is the single source of truth for
    # every version binding (R-01), and a hand-copied number here only ever
    # fails one release late. What this test is actually about is that the API
    # contract versions INDEPENDENTLY of evidence and of the spec edition.
    expected = json.loads((ROOT / "versions.json").read_text())["dimensions"]["edd_openapi"]["value"]
    assert spec["info"]["version"] == expected, \
        "OpenAPI is an independent API contract version"
    evidence = json.loads((ROOT / "versions.json").read_text())["dimensions"]["evidence"]["value"]
    assert spec["info"]["version"] != evidence

    # F14 (sixteenth review): the member-enumeration surface for scope resolution.
    members = spec["paths"]["/uid/{uid}/members"]["get"]["responses"]
    assert "200" in members, "members surface must serve the active-member enumeration"
    mr = spec["components"]["schemas"]["MembersResponse"]
    dev = mr["properties"]["members"]["items"]["properties"]["devices"]["items"]
    assert {"device_id", "mls_leaf_node_ref", "capabilities"} <= set(dev["required"])

    # F5 (PoC feedback, twelfth review): /uid/{uid}/keypackages is a
    # non-cacheable 302 POINTER — no direct-serve 200 (the EDD holds no pool,
    # so consume-once accounting lives solely at the RDP that serves it), and
    # the redirect
    # declares Cache-Control: no-store.
    kp = spec["paths"]["/uid/{uid}/keypackages"]["get"]["responses"]
    assert "200" not in kp, "EDD keypackages must not direct-serve (single-pool accounting)"
    assert "302" in kp and "Cache-Control" in kp["302"]["headers"]
    assert "409" not in kp, "replay rejection belongs to the serving pool, not the EDD pointer"
    assert "independently" in spec["info"]["description"].lower()
    # N8: BW-MEMBER is on the key-discovery trust path — fail closed on non-active.
    member = spec["paths"]["/.well-known/bw/member/{uid}/{mid}"]["get"]["responses"]
    assert "409" in member and "410" in member, "member endpoint must fail closed (409/410)"
    schemas = spec["components"]["schemas"]
    # Typed, machine-readable errors (fail-closed) and the core payload schemas.
    assert {"Error", "DirectoryRecord", "KeyPackagesResponse"} <= set(schemas)
    reasons = schemas["Error"]["properties"]["reason"]["enum"]
    # X-36: keypackage-replay is a DELIVERY-time NDE reason (X-30 registry),
    # removed from the directory error model — it must NOT reappear here.
    assert {"uid-suspended", "uid-merged"} <= set(reasons)
    assert "keypackage-replay" not in reasons

    # P9 (ninth review): discovery trust-path semantics are evidence-grade.
    # Member-level typed failure modes exist alongside the UID-level ones.
    assert {"member-suspended", "member-retired"} <= set(reasons)
    # The contract states what the client MUST verify on sealed responses.
    desc = spec["info"]["description"]
    assert "MUST verify" in desc and "deterministic-CBOR" in desc
    # Per-document-type freshness bounds: record/MED/ORG/MEMBER all bounded.
    headers = spec["components"]["headers"]
    assert {"CacheControlRecord", "CacheControlMed", "CacheControlOrg",
            "CacheControlMember"} <= set(headers)
    org200 = spec["paths"]["/.well-known/bw/org/{uid}"]["get"]["responses"]["200"]
    assert "Cache-Control" in org200.get("headers", {}), "BW-ORG response must be freshness-bounded"
    # The stale in-step versioning claim (pre-N8) must not resurface.
    assert "versioned in step" not in desc

    # Fail-closed: /resolve serves a typed error for a non-active UID, not a
    # stale 200.
    resolve = spec["paths"]["/resolve/{uid}"]["get"]["responses"]
    assert "409" in resolve, "/resolve must fail-closed (409) on suspended UID"

    # No response is a bare description: it must carry content or a Location
    # (redirect) or reference a typed-error response component.
    def _resolves(resp):
        if "$ref" in resp:
            return True  # reusable response component (NotFound/Suspended/Gone)
        return bool(resp.get("content") or (resp.get("headers", {}).get("Location")))

    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            for code, resp in op["responses"].items():
                assert _resolves(resp), f"{method.upper()} {path} {code} has no schema/redirect"
