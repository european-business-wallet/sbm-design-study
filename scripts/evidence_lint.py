#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Semantic conformance validator for SM-MLS-1.0 evidence.

The LINT-* rule ids are the conformance index of the TS ICS pro forma
(etsi/TS-SBM-QERDS-Binding-v0.1.md, Annex A, REQ-SMB); the schema-valid-AND-
lint-clean conformance definition is umbrella §9.4.

Schema-valid is NECESSARY but not SUFFICIENT. A document can satisfy every
JSON-Schema keyword yet violate cross-field protocol invariants that Schema
cannot express — for example an ``s3_attestation`` whose ``message_id``
disagrees with the DE it is attached to, an EP whose outcomes reference a
different message, or a manifest that is not in canonical order. This linter
checks those invariants. Each rule has a stable ID (``LINT-<AREA>-NN``) so a
violation is machine-triageable.

Structural packaging checks (LINT-PKG-01/02/03) parse the Base64 seal/token
payloads; the CBOR COSE_Sign1 structure and algorithm checks (LINT-PKG-01/02/05)
need ``cbor2``. cbor2 is therefore a HARD REQUIREMENT for a conformance result:
without it the CLI exits non-zero unless ``--dev-mode`` (alias ``--no-cbor-check``)
is passed, and that degraded mode is never used by ``make lint`` or CI. The V1
*cryptographic* sign-then-timestamp verification (LINT-PKG-04) is a mock-output
check — it needs the signing key — and lives in tests/test_evidence_lint.py.

Usage:
    python scripts/evidence_lint.py samples/*.json      # conformance lint (needs cbor2)
    python scripts/evidence_lint.py --dev-mode a.json   # degraded, NOT a conformance result
Exit 0 = clean, 1 = at least one violation, 2 = usage / missing cbor2.
"""
import base64
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lint_cli import flat_projection  # noqa: E402  — R11-09
from lint_cli import (parse_demo_qts,  # noqa: E402  — R10-X5
                      D4_COPIED_FIELDS,  # noqa: E402  — R3-01 one definition
                      parse_common_flags, load_trust_store, check_trust,  # noqa: E402  — shared (P1/P10)
                      RELAY_B2_REASONS, find_unsafe_numbers, load_ijson,
                      hash_mode_violations,
                      DuplicateKeyError, reconstruct, dcbor, ep_signed_body,
                      projection_equals_decode, validate_body)

EVIDENCE_DOC_TYPES = {"SE-v1", "DE-v1", "NDE-v1", "RE-v1", "CE-v1", "EP-v1",
                      "RelayEvidence-v1", "GCM-v1"}
SEAL_STRIP = ("seal",)  # M2/T3: the signed payload excludes the single seal container
DE_ACCEPTANCE_EVENT = "C.3-ConsignmentAcceptance"
DE_HANDOVER_EVENTS = {"E.1-ContentHandover", "D.6-ContentAccessTracking"}
DE_AVAILABILITY_EVENT = "D.1-ContentConsignment"  # DE event only at the declared availability grade (V0)
# NDE reason -> allowed EN 319 522-1 event(s) (TS clause 8.1; N3, LINT-NDE-07).
# routing-failed is stage-dependent (relay vs consignment); scope-violation on an
# NDE is the pre-submission case (A.2) — the recipient-refusal case is an RE (C.4).
# X-25: loaded from registries/reason-codes.json via lint_cli — registering a
# reason (or binding its events) is a registry action, not a lint-code change.
from lint_cli import RECIPIENT_VALIDATION_FAILURES  # noqa: E402  — R23-01
from lint_cli import (NDE_REASON_EVENT, REGISTERED_NDE_REASONS,  # noqa: E402
                      REGISTERED_RE_REASONS, REASON_LEXICAL, RE_REASON_KIND,
                      AUTH_ASSURANCE)
UID_RE = re.compile(
    r"^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$")

try:
    import cbor2
    _HAVE_CBOR = True
except Exception:  # pragma: no cover
    _HAVE_CBOR = False


class Violations:
    def __init__(self):
        self.items = []

    def add(self, rule, msg):
        self.items.append((rule, msg))


def _b64_ok(s):
    if not isinstance(s, str):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


COSE_ALG_ALLOWLIST = {-8, -7, -35}  # EdDSA, ES256, ES384 (the I-D (Evidence Objects and COSE Packaging))


def _check_cose(v, field, b64, rule):
    """LINT-PKG-01/02: base64 -> parseable CBOR COSE_Sign1 (4-element array).
    LINT-PKG-05: the protected-header alg is in the allowlist (EdDSA/ES256/ES384)."""
    if not _b64_ok(b64):
        v.add(rule, f"{field} is not valid Base64")
        return
    if not _HAVE_CBOR:
        return  # soft skip: structural CBOR check needs cbor2 (see W3 strict mode)
    try:
        obj = cbor2.loads(base64.b64decode(b64))
    except Exception:
        v.add(rule, f"{field} does not decode to CBOR")
        return
    if not (isinstance(obj, list) and len(obj) == 4):
        v.add(rule, f"{field} is not a 4-element COSE_Sign1 array")
        return
    # LINT-PKG-05: decode the protected header (element 0, a bstr wrapping a map)
    # and require the signature alg (label 1) to be in the allowlist.
    try:
        protected = cbor2.loads(obj[0]) if obj[0] else {}
        alg = protected.get(1) if isinstance(protected, dict) else None
    except Exception:
        v.add("LINT-PKG-05", f"{field} protected header is not decodable CBOR")
        return
    if alg not in COSE_ALG_ALLOWLIST:
        v.add("LINT-PKG-05",
              f"{field} COSE alg {alg!r} not in allowlist {{EdDSA(-8), ES256(-7), ES384(-35)}}")


def _check_payload_binding(v, obj, b64, strip_fields, label):
    """LINT-PKG-06 (X1): the COSE_Sign1 payload (array element 2) MUST equal the
    deterministic-CBOR signed payload reconstructed from the surrounding object
    (with the seal container / signature field removed). Catches stale/tampered
    evidence: a field mutated after sealing no longer matches the sealed payload."""
    if not _HAVE_CBOR or not _b64_ok(b64):
        return  # LINT-PKG-01/02 already flag structural problems
    try:
        cose = cbor2.loads(base64.b64decode(b64))
        cose_payload = cose[2]
    except Exception:
        return
    if not isinstance(cose_payload, (bytes, bytearray)):
        v.add("LINT-PKG-06", f"{label} COSE payload is detached (not embedded)")
        return
    if obj.get("type") == "EP-v1" and "seal" in strip_fields:
        # the EP body embeds its sub-objects as artefact bytes (M4)
        expected = dcbor(ep_signed_body(obj))
    else:
        expected = dcbor({k: val for k, val in obj.items() if k not in strip_fields})
    if bytes(cose_payload) != expected:
        v.add("LINT-PKG-06",
              f"{label} COSE payload does not match the object's canonical signed payload "
              "(stale or tampered evidence)")


def _check_evidence_seal(v, obj, cose_rule="LINT-PKG-01"):
    """M2/T3 (twenty-fifth review): an evidence object's seal is a CONTAINER
    `seal = {cose_b64, qualified_timestamp}`. The inner COSE is checked for
    structure/alg, its embedded payload MUST bind to the object minus `seal`
    (LINT-PKG-06), the timestamp token is structural (LINT-PKG-03), and its
    imprint MUST equal SHA-256 of the inner-COSE bytes (LINT-PKG-08)."""
    seal = obj.get("seal")
    if not isinstance(seal, dict):
        v.add(cose_rule, "seal container missing or not an object")
        return
    cose_b64 = seal.get("cose_b64")
    _check_cose(v, "seal.cose_b64", cose_b64, cose_rule)
    _check_payload_binding(v, obj, cose_b64, SEAL_STRIP, "seal.cose_b64")
    _check_token(v, seal.get("qualified_timestamp"))
    _check_imprint(v, cose_b64, seal.get("qualified_timestamp"), "seal.cose_b64")


def _check_wallet_sig(v, conf, label):
    """LINT-PKG-05: when a confirmation is signed, wallet_signature_b64 is a
    COSE_Sign1 whose alg must be in the allowlist (the I-D (Canonicalisation and Payload Hashing)/the I-D (COSE algorithms), W5).
    LINT-PKG-06: its payload binds to the canonical confirmation object."""
    ws = conf.get("wallet_signature_b64")
    if ws is not None:
        _check_cose(v, f"{label}.wallet_signature_b64", ws, "LINT-PKG-05")
        _check_payload_binding(v, conf, ws, ("wallet_signature_b64",),
                               f"{label}.wallet_signature_b64")


def wallet_signature_binding(conf, label="confirmation"):
    """LINT-PKG-05/06 for one confirmation, as a list of (rule, message) — the
    shape and payload-binding half of a wallet signature. The SIGNATURE half is
    `lint_cli.verify_cose_signature` against the device's published key; an
    issuing path must run both (R11-03: this half alone let a flipped
    signature byte through to a sealed NDE)."""
    v = Violations()
    _check_wallet_sig(v, conf, label)
    return list(v.items)


def _check_token(v, qts):
    """LINT-PKG-03: token_b64 is base64 that decodes to a DER SEQUENCE."""
    tok = (qts or {}).get("token_b64")
    if not _b64_ok(tok):
        v.add("LINT-PKG-03", "qualified_timestamp.token_b64 is not valid Base64")
        return
    raw = base64.b64decode(tok)
    if not raw or raw[0] != 0x30:
        v.add("LINT-PKG-03",
              "qualified_timestamp.token_b64 does not decode to a DER SEQUENCE (leading 0x30)")


def _check_imprint(v, cose_b64, qts, label):
    """LINT-PKG-08 (X3): where the timestamp token is the recognisable demo/mock
    format (SEQUENCE{ OCTET STRING(32) }), verify the message imprint ==
    SHA-256(inner-COSE bytes). Real RFC 3161 / ETSI EN 319 422 tokens require full
    cryptographic validation by a production verifier (out of lint scope, §9.4)."""
    tok = (qts or {}).get("token_b64")
    if not (_b64_ok(cose_b64) and _b64_ok(tok)):
        return
    demo = parse_demo_qts(base64.b64decode(tok))  # R10-X5: both demo shapes
    if demo is not None:
        if demo[0] != hashlib.sha256(base64.b64decode(cose_b64)).digest():
            v.add("LINT-PKG-08",
                  f"{label} qualified_timestamp imprint != SHA-256(seal)")


DEMO_KIDS = {b"rdp", b"wallet"}
DEMO_MARKERS = ("example.eu", "MockEU", "example.")


def _production_identity(v, cose_b64, label="seal.cose_b64"):
    """LINT-PROD-01/03: a production seal MUST carry a verifier-resolvable signing
    identity (COSE x5chain/x5t) and MUST NOT use a demo COSE kid."""
    if not (_HAVE_CBOR and _b64_ok(cose_b64)):
        return
    try:
        cose = cbor2.loads(base64.b64decode(cose_b64))
        ph = cbor2.loads(cose[0]) if cose[0] else {}
    except Exception:
        return
    if not (isinstance(ph, dict) and (33 in ph or 34 in ph)):  # x5chain / x5t
        v.add("LINT-PROD-01",
              f"{label}: production seal must embed a verifier-resolvable QSealC "
              "identity (COSE x5chain/x5t)")
    if isinstance(ph, dict) and ph.get(4) in DEMO_KIDS:
        v.add("LINT-PROD-03", f"{label}: demo COSE kid {ph.get(4)!r} in production evidence")


def _production_object(v, obj):
    """LINT-PROD-02/03: TSA identifier present; no demo profile/identifiers."""
    if "profile" in obj and obj.get("profile") != "production":
        v.add("LINT-PROD-03", f"profile is {obj.get('profile')!r}, not 'production'")
    qts = (obj.get("seal") or {}).get("qualified_timestamp")
    if isinstance(qts, dict):
        if not qts.get("tsa_id"):
            v.add("LINT-PROD-02", "production qualified_timestamp must carry a tsa_id")
        if isinstance(qts.get("tsa_id"), str) and any(m in qts["tsa_id"] for m in DEMO_MARKERS):
            v.add("LINT-PROD-03", f"tsa_id contains a demo marker: {qts['tsa_id']}")
    for f in ("rdp_id", "policy_id"):
        val = obj.get(f)
        if isinstance(val, str) and any(m in val for m in DEMO_MARKERS):
            v.add("LINT-PROD-03", f"{f} contains a demo marker: {val}")


def _production_wallet_sig(v, obj):
    """Finding D (twenty-second review): a production wallet advanced electronic
    signature on a recipient confirmation MUST carry a verifier-resolvable x5chain
    and MUST NOT use a demo COSE kid — the SAME identity rule as the RDP seal
    (LINT-PROD-01/03). Without it the confirmation key cannot be anchored to a
    QSealC / Trusted List, which is what makes it an *advanced* signature (TS
    clause 5.1) rather than a bare key."""
    conf = obj.get("s3_attestation") or obj.get("recipient_confirmation")
    if isinstance(conf, dict) and conf.get("wallet_signature_b64"):
        _production_identity(v, conf.get("wallet_signature_b64"), "wallet_signature_b64")


def _production_pass(v, obj):
    t = obj.get("type")
    if t in EVIDENCE_DOC_TYPES:
        _production_identity(v, (obj.get("seal") or {}).get("cose_b64"))
        _production_object(v, obj)
        _production_wallet_sig(v, obj)
        if t == "EP-v1":  # a confirmation may be nested in an EP outcome
            for o in obj.get("outcomes", []):
                _production_wallet_sig(v, o)
    if t == "EP-v1":
        if "se" in obj:
            _production_pass(v, obj["se"])
        for o in obj.get("outcomes", []):
            _production_pass(v, o)
        for c in obj.get("changes") or []:
            _production_pass(v, c)


def lint_manifest(v, manifest):
    """A manifest is FLAT (the I-D, Canonicalisation and Payload Hashing).

    This recursed, and raised LINT-MAN-03 on a nesting depth above one. Nothing
    could reach it: a part descriptor admits no `manifest` member in the Schema
    (`additionalProperties: false`) or in the CDDL, so a nested manifest is not
    expressible, and the digest domains exclude it a second way — a part's
    `digest` is in the observed-octets domain, and a digest committing to a
    nested structure would need a manifest mode there. The catalogue filed the
    rule under `coverage_gap` for as long as it existed, which recorded the
    symptom.

    Three authorities said three things: the prose permitted one level, the two
    machine-readable definitions permitted none, and this function guarded a
    depth neither could produce. The prose was the outlier and was corrected;
    the rule is retired (`docs/lint-catalogue.json`, `retired`), and the
    identifier is not reused.
    """
    ids = [p.get("part_id") for p in manifest]
    if len(ids) != len(set(ids)):
        v.add("LINT-MAN-01", "duplicate part_id in manifest")
    if ids != sorted(ids):
        v.add("LINT-MAN-02", "manifest is not in byte-wise ascending part_id order")


def lint_manifest_digest(v, obj):
    """LINT-MAN-04 (R16-01): where a manifest is present, `payload_hash` MUST be
    the digest of THAT manifest.

    Two different claims were conflated, and only one of them is unverifiable.
    That each part carries the digest of its own octets cannot be checked from
    the evidence: the parts are end-to-end encrypted and absent, so only a party
    holding the plaintext can recompute a part digest. That the declared
    `payload_hash` is the digest of the manifest the evidence carries can be
    checked by anyone holding the evidence — and nothing checked it, so a
    published sample shipped a hand-typed value through the Schema, the CDDL,
    the seal and this linter.

    The input is the deterministic-CBOR encoding of the manifest as the CDDL
    defines it: a list of maps, each carrying the full hash descriptor. It is not
    a fixed-position array; that wording described the commitments and was stale
    here.
    """
    ph = obj.get("payload_hash")
    manifest = obj.get("manifest")
    if not (isinstance(ph, dict) and isinstance(manifest, list) and manifest):
        return
    mode, alg, declared = ph.get("hash_mode"), ph.get("alg"), ph.get("hex")
    if not str(mode).startswith("manifest-"):
        v.add("LINT-MAN-04",
              f"a manifest is present and payload_hash declares {mode!r}: a "
              "multipart payload is committed by the manifest modes")
        return
    try:
        body = dcbor(manifest)
    except Exception as exc:                      # an unencodable manifest
        v.add("LINT-MAN-04", f"the manifest does not encode as deterministic CBOR: {exc}")
        return
    digest = hashlib.sha512(body) if alg == "SHA-512" else hashlib.sha256(body)
    if digest.hexdigest() != declared:
        v.add("LINT-MAN-04",
              f"payload_hash {declared} is not the digest of the manifest present "
              f"({digest.hexdigest()}) — SHA-256/512 over the deterministic-CBOR "
              "encoding of the manifest, a list of maps per the CDDL")


def check_auth_assurance(v, auth_context, context, arm=None):
    """LINT-AUTH-03 (X-27): the (identity, method, LoA) tuple must be
    admissible — per the REGISTERED method's own LoA ceiling AND per the
    evidence context's admissible-tuple row in registries/auth-assurance.json
    (an explicit table, never a scalar ordering: the required assurance
    depends on the full combination, and a wallet signature elevates a lower
    session per the stated elevation rows). The floors are the PILOT
    profile's provisional set — TODO(legal): their adoption against the
    applicable standards/legal framework awaits counsel and is left open.
    An UNREGISTERED well-formed method is accepted, preserved verbatim and
    treated as unassessed (LINT-AUTH-W1, the X-25 safe-generic-processing
    convention). Fail-closed for registered methods."""
    if not isinstance(auth_context, dict):
        return
    method, loa = auth_context.get("method"), auth_context.get("loa")
    identity = auth_context.get("identity")
    reg = AUTH_ASSURANCE["methods"].get(method)
    if reg is None:
        if isinstance(method, str) and method:
            v.add("LINT-AUTH-W1",
                  f"auth method {method!r} is not REGISTERED in "
                  "registries/auth-assurance.json — accepted and preserved "
                  "verbatim; the assurance claim is UNASSESSED (X-27)")
        return
    if loa not in reg["admissible_loa"]:
        v.add("LINT-AUTH-03",
              f"method {method!r} cannot claim loa {loa!r} — its registered "
              f"admissible set is {reg['admissible_loa']} (X-27)")
    rule = AUTH_ASSURANCE["contexts"].get(context)
    if rule is None:
        return
    if arm is not None:
        rule = rule.get(arm)
        if rule is None:
            return
    if identity not in rule["identities"] or loa not in rule["admissible_loa"]:
        v.add("LINT-AUTH-03",
              f"({identity!r}, {method!r}, {loa!r}) is not an admissible "
              f"tuple for the {context!r}"
              + (f"/{arm}" if arm else "")
              + f" context — identities {rule['identities']}, "
              f"loa {rule['admissible_loa']} (X-27, pilot floors)")


def lint_se(v, se):
    check_auth_assurance(v, se.get("auth_context"), "se-submission",
                         arm=se.get("origin_proof"))
    # LINT-DE-19 (X-03/D4, evidence 2.3): the sender confirmation's copied
    # tuple MUST equal the SE's own values — the sender's wallet signed the
    # exact submission the provider sealed (message, parties, byte-exact
    # commitments, policy, scope, timing). A diverging field means the sealed
    # SE and the sender's signed act describe DIFFERENT submissions. The
    # signature itself is checked as every wallet confirmation is
    # (LINT-PKG-05/06 payload binding; roster/anchor resolution is
    # bundle-level, LINT-BND-28). TODO(legal): the Art. 44(1)(b)/43(2) clause
    # for the provider-attested narrowed mode awaits counsel (D4).
    sc = se.get("sender_confirmation")
    if isinstance(sc, dict):
        _check_wallet_sig(v, sc, "sender_confirmation")
        # R3-01: the ADDRESSES are compared too — they are the input to the
        # §8.3 selection, so a tuple agreeing with the SE on everything except
        # who it was addressed to describes a different submission. The field
        # list is shared (lint_cli.D4_COPIED_FIELDS), not restated here.
        for field in D4_COPIED_FIELDS:
            if sc.get(field) != se.get(field):
                v.add("LINT-DE-19",
                      f"sender_confirmation.{field} != se.{field} — the sender's "
                      "signed act and the sealed SE describe different "
                      "submissions (X-03/D4)")
    # LINT-DE-18 (X-22): the sender-computed expiry is VALIDATED, not echoed —
    # expires_at MUST be strictly later than sent_at. Through the ONE X-22
    # validator (R10-08), which intake now runs before sealing: this comment
    # used to say "a reversed or zero TTL is rejected at intake" while intake
    # ran no expiry rule at all, so the retained check here was the only one.
    # The policy maximum is bundle-level (LINT-BND-27), where the recipient's
    # BW-ORG is in hand.
    sent, exp = se.get("sent_at"), se.get("expires_at")
    if sent and exp:
        from lint_cli import expiry_problems
        # Only the ordering reasons are this rule's; the maximum is LINT-BND-27's.
        for reason, detail in expiry_problems(sent, exp):
            if reason == "expiry-not-after-sent":
                v.add("LINT-DE-18", detail)
            elif reason == "submission-invalid":     # an unreadable instant
                v.add("LINT-DE-18",
                      f"SE expiry ordering cannot be evaluated: {detail} (DR-05)")
    _check_evidence_seal(v, se)
    # LINT-AUTH-01 (X5): the auth_context method must match the declared method.
    if (se.get("auth_context") or {}).get("method") != se.get("auth_method"):
        v.add("LINT-AUTH-01", "SE auth_context.method != auth_method")
    # LINT-DE-14 (A2, Annex R): an SE whose acting identity is a system member
    # (auth_context.identity=system) MUST carry the mandate it acted under; a
    # non-system SE MUST NOT carry a mandate_ref.
    is_system = (se.get("auth_context") or {}).get("identity") == "system"
    has_mandate = se.get("mandate_ref") is not None
    if is_system and not has_mandate:
        v.add("LINT-DE-14",
              "SE with a system acting identity must carry a mandate_ref "
              "(the mandate the agent acted under; Annex R, A2)")
    if has_mandate and not is_system:
        v.add("LINT-DE-14",
              "SE carries a mandate_ref but its acting identity is not system "
              "(mandate_ref is only for agent-sent evidence; Annex R, A2)")
    # LINT-DE-15 (A1, nineteenth review): an OPPOSABLE agent SE (mandate_ref
    # present and opposable != false) MUST carry a well-formed mandate_commitment
    # so the act's mandate-scope is externally verifiable; a NON-opposable agent
    # SE (opposable=false) MUST NOT carry one.
    if is_system and has_mandate:
        mref = se["mandate_ref"]
        opposable = mref.get("opposable", True)
        mc = mref.get("mandate_commitment")
        if opposable:
            if not (isinstance(mc, str) and re.fullmatch(r"[a-f0-9]{64}", mc)):
                v.add("LINT-DE-15",
                      "opposable agent SE requires a well-formed mandate_commitment "
                      "(64 lowercase hex; the I-D (Mandate Commitment), A1)")
        elif mc is not None:
            v.add("LINT-DE-15",
                  "non-opposable agent SE (mandate_ref.opposable=false) must not "
                  "carry a mandate_commitment (A1)")
    if isinstance(se.get("manifest"), list):
        lint_manifest(v, se["manifest"])
        lint_manifest_digest(v, se)


def lint_s3_binding(v, s3, de, se=None):
    """R12-01 — what an S3 attestation is ABOUT, stated once: the message, the
    content digest and the policy of the DE it would sit in (LINT-DE-01/02/03)
    and, with the SE, the MLS session, the transmitted octets and the group
    state (LINT-DE-04/16) and the SE's policy (LINT-DE-13) — plus the wallet
    signature's shape and payload binding. The retained verifier calls it on a
    DE; the issuing path (`mock_rdp.deliver_confirmation`) calls it on the DE
    the act would support, BEFORE the act is stored or counted. Intake used to
    check who made the act and count it without asking what it was about, so
    two members' authentic statements about another message satisfied a
    quorum that this function would have refused afterwards."""
    _check_wallet_sig(v, s3, "s3_attestation")
    if s3.get("message_id") != de.get("message_id"):
        v.add("LINT-DE-01", "s3_attestation.message_id != message_id")
    if s3.get("payload_hash") != de.get("payload_hash"):
        v.add("LINT-DE-02", "s3_attestation.payload_hash != payload_hash")
    if s3.get("acceptance_policy_ref") != de.get("acceptance_policy_ref"):
        v.add("LINT-DE-03", "s3_attestation.acceptance_policy_ref != acceptance_policy_ref")
    if se is not None:
        if (s3.get("mls_group_id") != se.get("mls_group_id")
                or s3.get("mls_epoch") != se.get("mls_epoch")):
            v.add("LINT-DE-04",
                  "s3_attestation MLS session != se.mls_group_id/mls_epoch")
        # LINT-DE-16 (findings 2/3, evidence 2.1): the confirmation commits to
        # the SAME transmitted octets (envelope_hash) and MLS GroupContext state
        # (mls_state) as the SE, so the delivered ciphertext and group state the
        # recipient attests to are the ones the sender's evidence bound.
        if s3.get("envelope_hash") != se.get("envelope_hash"):
            v.add("LINT-DE-16", "s3_attestation.envelope_hash != se.envelope_hash")
        if s3.get("mls_state") != se.get("mls_state"):
            v.add("LINT-DE-16", "s3_attestation.mls_state != se.mls_state")
        # LINT-DE-13 (S3, TS clause 6 INTF-3): the confirmation's
        # acceptance_policy_ref must equal the SE's — the DE takes its
        # top-level ref from the SE, so a differing confirmation ref would
        # make the DE internally inconsistent. Complements the SE↔DE policy
        # binding (bundle_lint LINT-BND-10) with the confirmation leg.
        if s3.get("acceptance_policy_ref") != se.get("acceptance_policy_ref"):
            v.add("LINT-DE-13",
                  "s3_attestation.acceptance_policy_ref != se.acceptance_policy_ref")


def lint_de(v, de, se=None):
    _check_evidence_seal(v, de)
    if de.get("delivery_grade") == "availability":
        check_auth_assurance(v, de.get("auth_context"), "de-availability")
    else:
        _s3 = de.get("s3_attestation") or {}
        check_auth_assurance(v, de.get("auth_context"), "de-confirmation",
                             arm="wallet-signed" if _s3.get("wallet_signature_b64")
                             else "session")
    # LINT-AUTH-02 (X5): the recipient auth_context method must match the declared method.
    if (de.get("auth_context") or {}).get("method") != de.get("recipient_auth_method"):
        v.add("LINT-AUTH-02", "DE auth_context.method != recipient_auth_method")
    # The s3_attestation bindings apply where a confirmation exists (the
    # verification/acceptance grades); its REQUIRED presence there — and its
    # required ABSENCE at the availability grade — is LINT-DE-09/10 (V0).
    s3 = de.get("s3_attestation")
    if s3 is not None:
        lint_s3_binding(v, s3, de, se)
        # LINT-DE-12 (S1, TS clause 6 INTF-1): a confirmation whose only proof is
        # session_authenticated (no wallet_signature_b64) may be relied upon only
        # within a recipient session bound to the confirming member; the DE must
        # record that session at member- or device-level auth_context granularity
        # (an entity-level session cannot stand in for a member-bound signature).
        # The static floor is checked here; the transport-level caller<->member
        # binding itself is verifier-side.
        if s3.get("session_authenticated") and not s3.get("wallet_signature_b64"):
            if (de.get("auth_context") or {}).get("identity") not in ("member", "device"):
                v.add("LINT-DE-12",
                      "session-authenticated s3_attestation requires the DE "
                      "auth_context at member/device identity granularity "
                      "(TS clause 6 INTF-1)")
        # LINT-DE-20 (X-05, evidence 2.3): a bare session boolean cannot claim
        # the stronger proof mode. A session-authenticated confirmation whose
        # DE-level auth_context claims wallet/eID member-grade authentication
        # (a wallet-* method or high/very-high LoA) must retain a verifiable
        # session_binding (token digest / TLS exporter / transcript digest,
        # kept under the §4.3 duty); without one the confirmation is the
        # provider-attested (narrowed) mode and the claim must be narrowed to
        # match. TODO(legal): the narrowed mode's Article 43(2) weight awaits
        # counsel.
        if s3.get("session_authenticated") and not s3.get("wallet_signature_b64") \
                and not s3.get("session_binding"):
            ac = de.get("auth_context") or {}
            method, loa = str(ac.get("method") or ""), ac.get("loa")
            if method.startswith("wallet-") or loa in ("high", "very-high"):
                v.add("LINT-DE-20",
                      f"session-authenticated confirmation with no session_binding "
                      f"claims member-grade authentication (method={method!r}, "
                      f"loa={loa!r}) — a bare boolean is the provider-attested "
                      "narrowed mode and cannot claim the stronger proof (X-05)")
    # LINT-DE-21 (R11-04 / R11-X2): `delivered_at` DATES the delivery event.
    # At the verification and acceptance grades that event is the confirmation
    # that completed the policy, as RDP(in) observed it, so no act the DE rests
    # on can be later than it. Nothing related the two: a DE dated with the S2
    # instant, before its own s3 attestation and both quorum acknowledgements,
    # linted clean — and that is exactly the value the DS contract told every
    # issuer to copy.
    dat = de.get("delivered_at")
    if dat and de.get("delivery_grade") in ("verification", "acceptance"):
        from lint_cli import instant, TimestampError
        acts = [("s3_attestation.verified_at",
                 (de.get("s3_attestation") or {}).get("verified_at"))]
        acts += [(f"quorum[{i}].ack_at", q.get("ack_at"))
                 for i, q in enumerate(de.get("quorum") or []) if isinstance(q, dict)]
        for label, at in acts:
            if at is None:
                continue
            try:
                early = instant(dat) < instant(at)
            except TimestampError as exc:
                v.add("LINT-DE-21", f"an instant is unreadable, so the order of "
                      f"delivered_at and {label} cannot be established: {exc}")
                continue
            if early:
                v.add("LINT-DE-21",
                      f"delivered_at {dat} precedes {label} {at}: the DE dates its "
                      "delivery before an act it rests on — at this grade the event "
                      "is the completing confirmation as RDP(in) observed it, not "
                      "the Delivery Service's S2 instant (R11-04)")
    kind = de.get("acceptance_policy_kind")
    ev = de.get("event")
    # LINT-DE-20 (X-05): a wallet-signed quorum entry is a portable proof of
    # THIS message's acceptance — its message_id must equal the DE's.
    for q in (de.get("quorum") or []):
        if isinstance(q, dict) and q.get("attestation") == "wallet-signed" \
                and q.get("message_id") != de.get("message_id"):
            v.add("LINT-DE-20",
                  f"wallet-signed quorum entry by {q.get('mid')!r} covers "
                  f"message_id {q.get('message_id')!r}, not this DE's "
                  f"{de.get('message_id')!r} — not a proof of this acceptance (X-05)")
    if kind in ("quorum", "all") and ev != DE_ACCEPTANCE_EVENT:
        v.add("LINT-DE-05",
              f"acceptance_policy_kind={kind} requires event {DE_ACCEPTANCE_EVENT}, got {ev}")
    if kind in ("any-one", "device-class") and ev not in DE_HANDOVER_EVENTS:
        v.add("LINT-DE-05",
              f"acceptance_policy_kind={kind} requires event in {sorted(DE_HANDOVER_EVENTS)}, got {ev}")
    if kind == "quorum":
        q = de.get("quorum")
        if not (isinstance(q, list) and len(q) >= 1):
            v.add("LINT-DE-06", "acceptance_policy_kind=quorum requires a non-empty quorum array")
    # LINT-DE-07 (S3/D6): scope_ref present and, for the same message, equal to the SE's.
    if "scope_ref" not in de:
        v.add("LINT-DE-07", "DE missing scope_ref")
    elif se is not None and se.get("scope_ref") is not None \
            and de.get("scope_ref") != se.get("scope_ref"):
        v.add("LINT-DE-07", "DE scope_ref != SE scope_ref for the same message")
    # LINT-DE-08..10 (V0, spec §8.3b / the I-D delivery state model): the
    # delivery grade is explicit and coherent with event, attestation and
    # integrity basis.
    grade = de.get("delivery_grade")
    if grade not in ("availability", "verification", "acceptance"):
        v.add("LINT-DE-08", f"missing or unknown delivery_grade: {grade!r}")
    else:
        expected = {"availability": {DE_AVAILABILITY_EVENT},
                    "verification": DE_HANDOVER_EVENTS,
                    "acceptance": {DE_ACCEPTANCE_EVENT}}[grade]
        if ev not in expected:
            v.add("LINT-DE-08",
                  f"delivery_grade={grade} requires event in {sorted(expected)}, got {ev}")
        if grade == "availability":
            for f in ("s3_attestation", "acceptance_policy_kind", "quorum"):
                if f in de:
                    v.add("LINT-DE-09",
                          f"availability-grade DE must not carry {f} (no recipient "
                          "confirmation exists at this grade — the TS clause 6)")
            if de.get("integrity_basis") != "sender-declared-digest":
                v.add("LINT-DE-09",
                      "availability-grade DE requires integrity_basis="
                      "sender-declared-digest")
        else:
            if s3 is None:
                v.add("LINT-DE-10",
                      f"{grade}-grade DE requires an s3_attestation")
            if de.get("integrity_basis") != "recipient-verified-digest":
                v.add("LINT-DE-10",
                      f"{grade}-grade DE requires integrity_basis="
                      "recipient-verified-digest")
            if grade == "acceptance" and kind not in ("quorum", "all"):
                v.add("LINT-DE-10",
                      f"acceptance-grade DE requires acceptance_policy_kind "
                      f"quorum/all, got {kind!r}")
            if grade == "verification" and kind not in ("any-one", "device-class"):
                v.add("LINT-DE-10",
                      f"verification-grade DE requires acceptance_policy_kind "
                      f"any-one/device-class, got {kind!r}")
    # LINT-DE-11 (X0, §8.3b / the I-D (Grade Commitment)): the grade commitment
    # exists exactly at the availability grade, well-formed, and — within an EP
    # — equal to the SE's.
    gc = de.get("grade_commitment")
    if grade == "availability":
        if not (isinstance(gc, str) and re.fullmatch(r"[a-f0-9]{64}", gc)):
            v.add("LINT-DE-11",
                  "availability-grade DE requires a well-formed grade_commitment "
                  "(64 lowercase hex; the I-D (Grade Commitment))")
    elif gc is not None:
        v.add("LINT-DE-11",
              "grade_commitment is only defined at the availability grade")
    if se is not None and se.get("grade_commitment") != gc:
        v.add("LINT-DE-11",
              "DE grade_commitment != SE grade_commitment for the same message")
    # LINT-DE-17 (F-02, evidence 2.2): the availability-grade DE carries the
    # transmitted-octet commitment itself (no confirmation exists at that
    # grade) — within an EP it MUST equal the SE's, so the chain SE = DE holds
    # at every grade (confirmed grades bind via s3_attestation, LINT-DE-16).
    if (se is not None and grade == "availability"
            and de.get("envelope_hash") != se.get("envelope_hash")):
        v.add("LINT-DE-17",
              "availability DE envelope_hash != se.envelope_hash — the "
              "transmitted-octet chain breaks at the delivery boundary (F-02)")


def lint_nde(v, nde, se=None):
    _check_evidence_seal(v, nde)
    lint_nde_semantics(v, nde, se=se)


def lint_nde_semantics(v, nde, se=None):
    """Everything an NDE must satisfy APART FROM its seal (R10-07).

    Split out so RDP(in) can hold a COMPLETE candidate NDE to these rules
    before sealing it (`mock_rdp.deliver_confirmation`) — one home for the
    NDE rules, called by the retained-evidence linter and by the issuing path
    alike, rather than the issuing path re-stating them or filtering this
    linter's output by rule-id prefix."""
    reason = nde.get("reason")
    if reason == "payload-hash-mismatch":
        rc = nde.get("recipient_confirmation") or {}
        _check_wallet_sig(v, rc, "recipient_confirmation")
        if rc.get("result") != "mismatch":
            v.add("LINT-NDE-01",
                  "reason=payload-hash-mismatch requires recipient_confirmation.result == 'mismatch'")
        # W1: bind the recipient_confirmation to the message / session / policy,
        # mirroring the DE s3_attestation bindings (LINT-DE-01..05).
        if rc.get("message_id") != nde.get("message_id"):
            v.add("LINT-NDE-03", "recipient_confirmation.message_id != NDE message_id")
        if se is not None:
            if (rc.get("mls_group_id") != se.get("mls_group_id")
                    or rc.get("mls_epoch") != se.get("mls_epoch")):
                v.add("LINT-NDE-04",
                      "recipient_confirmation MLS session != se.mls_group_id/mls_epoch")
            # R12-01: the proof is about THIS group state — the field the
            # confirmation already carries, bound as the S3 arm's is.
            if rc.get("mls_state") != se.get("mls_state"):
                v.add("LINT-NDE-04",
                      "recipient_confirmation.mls_state != se.mls_state")
            if rc.get("acceptance_policy_ref") != se.get("acceptance_policy_ref"):
                v.add("LINT-NDE-05",
                      "recipient_confirmation.acceptance_policy_ref != se.acceptance_policy_ref")
        # The recipient-recomputed hash MUST differ from the sender/SE hash the
        # NDE carries — equality would contradict the mismatch claim (the I-D (Canonicalisation and Payload Hashing)).
        if rc.get("payload_hash") == nde.get("payload_hash"):
            v.add("LINT-NDE-06",
                  "recipient_confirmation.payload_hash must differ from the NDE (sender) payload_hash")
    if reason == "payload-validation-failed":
        # LINT-NDE-08 (R23-01): the outcome for a post-decryption validation
        # failure, which is NOT a mismatch. A `mismatch` confirmation asserts a
        # comparison that was MADE and carries the differing digest; under
        # Mode C the declared payload_hash is the digest of the MANIFEST, so a
        # recipient whose received parts are wrong recomputes the same value the
        # sender declared, and LINT-NDE-06 refuses the NDE it would have to
        # build. The failure was detectable and unreportable — the defect
        # SBM-ADR-0014 names for an unusable salt, in the live path.
        vfr = nde.get("recipient_validation_failure") or {}
        _check_wallet_sig(v, vfr, "recipient_validation_failure")
        if nde.get("recipient_confirmation") is not None:
            v.add("LINT-NDE-08",
                  "an NDE carries a recipient_confirmation OR a "
                  "recipient_validation_failure, never both: one asserts a comparison "
                  "that was made, the other that none could be")
        if vfr.get("failure") not in RECIPIENT_VALIDATION_FAILURES:
            v.add("LINT-NDE-08",
                  f"recipient_validation_failure.failure {vfr.get('failure')!r} is not a "
                  "registered cause (registries/reason-codes.json "
                  "`recipient_validation_failures`)")
        for part in vfr.get("parts") or []:
            if part.get("failure") not in RECIPIENT_VALIDATION_FAILURES:
                v.add("LINT-NDE-08",
                      f"part {part.get('part_id')!r}: failure {part.get('failure')!r} is "
                      "not a registered cause")
            # `observed` is present exactly where a comparison WAS made. A
            # digest on a part that was absent would assert a computation over
            # octets nobody received.
            if part.get("failure") == "part-digest-mismatch":
                if not part.get("observed") or not part.get("declared"):
                    v.add("LINT-NDE-08",
                          f"part {part.get('part_id')!r}: a digest mismatch names both the "
                          "declared and the observed digest, or it is not a comparison")
                elif part["observed"] == part["declared"]:
                    v.add("LINT-NDE-08",
                          f"part {part.get('part_id')!r}: observed == declared, which "
                          "contradicts the mismatch claimed for it")
            elif part.get("observed") is not None:
                v.add("LINT-NDE-08",
                      f"part {part.get('part_id')!r}: an observed digest is carried for "
                      f"{part.get('failure')!r}, where no comparison was made")
        if vfr.get("message_id") != nde.get("message_id"):
            v.add("LINT-NDE-08", "recipient_validation_failure.message_id != NDE message_id")
        if se is not None:
            if vfr.get("declared_payload_hash") != se.get("payload_hash"):
                v.add("LINT-NDE-08",
                      "recipient_validation_failure.declared_payload_hash != se.payload_hash "
                      "— the assertion must name the commitment it was checking")
            if (vfr.get("mls_group_id") != se.get("mls_group_id")
                    or vfr.get("mls_epoch") != se.get("mls_epoch")):
                v.add("LINT-NDE-08",
                      "recipient_validation_failure MLS session != se.mls_group_id/mls_epoch")
            if vfr.get("mls_state") != se.get("mls_state"):
                v.add("LINT-NDE-08", "recipient_validation_failure.mls_state != se.mls_state")
            if vfr.get("acceptance_policy_ref") != se.get("acceptance_policy_ref"):
                v.add("LINT-NDE-08",
                      "recipient_validation_failure.acceptance_policy_ref != "
                      "se.acceptance_policy_ref")
    if reason == "uid-merged":
        ru = nde.get("redirect_uid")
        if not (isinstance(ru, str) and UID_RE.match(ru)):
            v.add("LINT-NDE-02", "reason=uid-merged requires a well-formed redirect_uid")
    # LINT-NDE-07 (N3): the NDE reason binds to its EN 319 522-1 event (TS clause 8.1).
    allowed = NDE_REASON_EVENT.get(reason)
    if allowed is not None and nde.get("event") not in allowed:
        v.add("LINT-NDE-07",
              f"reason {reason!r} requires event in {sorted(allowed)}, got {nde.get('event')!r}")
    # LINT-NDE-W1 (X-25, safe generic processing): a well-formed but UNREGISTERED
    # reason is accepted structurally, preserved verbatim and treated as a generic
    # non-delivery — a WARNING, not a violation. Registering the code (and its
    # event binding) in registries/reason-codes.json is a registry action.
    if (isinstance(reason, str) and reason not in REGISTERED_NDE_REASONS
            and REASON_LEXICAL.match(reason)):
        v.add("LINT-NDE-W1",
              f"reason {reason!r} is not a REGISTERED reason code — accepted and "
              "preserved verbatim; treat as a generic non-delivery "
              "(registries/reason-codes.json; the I-D, IANA Considerations)")


def lint_re(v, re_obj):
    _check_evidence_seal(v, re_obj)
    lint_re_semantics(v, re_obj)


def lint_re_semantics(v, re_obj):
    """Every RE rule but the seal — called by the retained linter and by the
    issuing path, which holds a member refusal's RE to it before sealing
    (R12-X1), exactly as a mismatch's NDE is held to `lint_nde_semantics`."""
    if re_obj.get("refusal_kind") == "member":
        _rc = re_obj.get("refusal_confirmation") or {}
        check_auth_assurance(v, re_obj.get("auth_context"), "re-member-refusal",
                             arm="wallet-signed" if _rc.get("wallet_signature_b64")
                             else "session")
    # LINT-RE-01 (X-29, evidence 2.3): kind/reason/proof coherence. The former
    # defect: an RE was an RDP-only assertion — nothing distinguished "the user
    # refused" from "our policy refused", and a provider could claim a user act
    # with no user proof. Now: a member refusal claims refused-by-user AND
    # carries the member's own confirmation whose content matches the refused
    # message; a policy refusal never claims a user act. Fail-closed.
    kind, reason = re_obj.get("refusal_kind"), re_obj.get("reason")
    reason_kind = RE_REASON_KIND.get(reason)
    rc = re_obj.get("refusal_confirmation")
    if kind == "member":
        if reason != "refused-by-user":
            v.add("LINT-RE-01",
                  f"refusal_kind 'member' claims a user act — reason must be "
                  f"'refused-by-user', got {reason!r}")
        if not isinstance(rc, dict):
            v.add("LINT-RE-01",
                  "refusal_kind 'member' without a recipient-produced "
                  "refusal_confirmation is an RDP-only assertion of a user act "
                  "— rejected (X-29)")
        else:
            for field, want in (("mid", re_obj.get("mid")),
                                ("message_id", re_obj.get("message_id")),
                                ("payload_hash", re_obj.get("payload_hash"))):
                if rc.get(field) != want:
                    v.add("LINT-RE-01",
                          f"refusal_confirmation.{field} does not match the RE "
                          f"({rc.get(field)!r} != {want!r}) — the proof must cover "
                          "the refused message")
    elif kind == "organisation-policy":
        if reason_kind == "member":
            v.add("LINT-RE-01",
                  f"refusal_kind 'organisation-policy' must not carry the "
                  f"member-kind reason {reason!r} — no user act is claimed")
        if rc is not None or re_obj.get("mid"):
            v.add("LINT-RE-01",
                  "an organisation-policy refusal names no refusing member and "
                  "carries no member confirmation (X-29)")
    if kind == "member" and reason_kind not in (None, "member"):
        v.add("LINT-RE-01",
              f"reason {reason!r} is registry-bound to refusal_kind "
              f"{reason_kind!r}, not 'member'")


def lint_ce(v, ce, se=None):
    _check_evidence_seal(v, ce)
    # LINT-CE-01 (X-24, evidence 2.5): a CE attests ONLY bytes its issuer
    # legitimately observes — the ciphertext framing. Shape coherence both
    # directions (after-commitments matched to the transformation kind), and
    # where the message's SE is available the input commitment MUST be the
    # SE's transmitted-octet commitment (the F-02 chain extended to the one
    # actor that legitimately re-frames). Fail-closed.
    kind = ce.get("transformation")
    if kind == "re-packaging":
        if not ce.get("envelope_hash_after"):
            v.add("LINT-CE-01",
                  "re-packaging CE without envelope_hash_after — the output "
                  "bytes are unattested (X-24)")
        if ce.get("part_envelope_hashes"):
            v.add("LINT-CE-01",
                  "re-packaging CE carrying part_envelope_hashes — wrong-kind "
                  "commitment (X-24)")
    elif kind == "chunking":
        parts = ce.get("part_envelope_hashes")
        if not (isinstance(parts, list) and len(parts) >= 2):
            v.add("LINT-CE-01",
                  "chunking CE without part_envelope_hashes (>= 2 parts) — "
                  "the emitted parts are unattested (X-24)")
        if ce.get("envelope_hash_after"):
            v.add("LINT-CE-01",
                  "chunking CE carrying envelope_hash_after — wrong-kind "
                  "commitment (X-24)")
    if not ce.get("envelope_hash_before"):
        v.add("LINT-CE-01",
              "CE without envelope_hash_before — the input bytes are "
              "unattested (X-24)")
    elif se is not None and se.get("envelope_hash") is not None \
            and ce.get("envelope_hash_before") != se.get("envelope_hash"):
        v.add("LINT-CE-01",
              "CE envelope_hash_before != se.envelope_hash — the attested "
              "input is not the transmitted message (X-24)")


def lint_relay(v, r):
    """Finding 1 (twentieth review): a four-corner relay hop's sealed evidence
    (RelayEvidence-v1; profile-2, TS clause 4.1, FC-1). Packaging checks mirror
    the other evidence objects; the two relay-specific invariants are the typed
    B.2 reason and the two-provider hop."""
    _check_evidence_seal(v, r)
    event, reason = r.get("event"), r.get("reason")
    # LINT-RLY-01: a B.2 RelayRejection carries a typed rejection reason;
    # a B.1 RelayAcceptance carries none.
    if event == "B.2-RelayRejection":
        if reason not in RELAY_B2_REASONS:
            v.add("LINT-RLY-01",
                  f"B.2-RelayRejection reason {reason!r} is not a typed relay-rejection "
                  f"reason {sorted(RELAY_B2_REASONS)}")
    elif event == "B.1-RelayAcceptance":
        if reason is not None:
            v.add("LINT-RLY-01",
                  "B.1-RelayAcceptance must not carry a rejection reason")
    # LINT-RLY-02: a relay hop is between two DISTINCT providers — both RDP
    # identifiers are present and not equal.
    s, rc = r.get("sending_rdp_id"), r.get("receiving_rdp_id")
    if not s or not rc:
        v.add("LINT-RLY-02",
              "relay evidence must name both sending_rdp_id and receiving_rdp_id")
    elif s == rc:
        v.add("LINT-RLY-02",
              f"sending_rdp_id == receiving_rdp_id ({s!r}) — a relay hop is between "
              "two distinct providers")


STATE_RECORD_FIELDS = {"state", "event", "at", "mid", "device_id"}


def lint_ep(v, ep):
    _check_evidence_seal(v, ep, "LINT-PKG-02")  # covers token + imprint via the seal container
    if "qualified_timestamp" not in (ep.get("seal") or {}):
        v.add("LINT-EP-03", "EP seal missing qualified_timestamp")
    # W8: states[] are non-operative state records — they MUST carry only the
    # allowed fields and no delivery-establishing claim (e.g. delivered_at,
    # s3_attestation, qualified_timestamp, a seal).
    for i, s in enumerate(ep.get("states") or []):
        extra = set(s) - STATE_RECORD_FIELDS
        if extra:
            v.add("LINT-EP-04",
                  f"states[{i}] has non-state-record fields {sorted(extra)} "
                  f"(state records establish no delivery and carry no Article 43(2) effect)")
    mid = ep.get("message_id")
    se = ep.get("se") or {}
    if se.get("message_id") != mid:
        v.add("LINT-EP-01", "se.message_id != EP message_id")
    se_scope = se.get("scope_ref")
    for i, o in enumerate(ep.get("outcomes", [])):
        if o.get("message_id") != mid:
            v.add("LINT-EP-01", f"outcomes[{i}].message_id != EP message_id")
        # LINT-EP-05 (N9): scope_ref coherence — a scoped outcome (SE/DE) shares
        # the enclosed SE's scope; a package cannot span two confidentiality scopes.
        if o.get("scope_ref") is not None and o.get("scope_ref") != se_scope:
            v.add("LINT-EP-05",
                  f"outcomes[{i}].scope_ref {o.get('scope_ref')!r} != se.scope_ref {se_scope!r}")
    # X-04/D5 (2.2): disputes[] — same message binding; each GCM linted with the
    # enclosed SE as context (echoes the disputed sealed commitment).
    for i, gcm in enumerate(ep.get("disputes") or []):
        if gcm.get("message_id") != mid:
            v.add("LINT-EP-01", f"disputes[{i}].message_id != EP message_id")
        lint_gcm(v, gcm, se=ep.get("se"))
    chain_ids = {c.get("rdp_id") for c in ep.get("rdp_chain", [])}
    seen = set()
    if se.get("rdp_id"):
        seen.add(se["rdp_id"])
    for o in ep.get("outcomes", []):
        if o.get("rdp_id"):
            seen.add(o["rdp_id"])
    missing = seen - chain_ids
    if missing:
        v.add("LINT-EP-02", f"rdp_chain does not cover rdp_ids {sorted(missing)}")
    # LINT-EP-06 (finding 2, twentieth review): the OPTIONAL per-hop relay-evidence
    # reference (profile-2 four-corner, FC-2) binds the hop's sealed B.x object to
    # THIS package — its message_id equals the EP message_id, and the seal digest is
    # well-formed. The shape (event enum, digest pattern) is schema-enforced; this
    # is the cross-field binding the schema cannot express.
    for i, c in enumerate(ep.get("rdp_chain", [])):
        ev = c.get("evidence")
        if not isinstance(ev, dict):
            continue
        if ev.get("message_id") != mid:
            v.add("LINT-EP-06",
                  f"rdp_chain[{i}].evidence.message_id {ev.get('message_id')!r} "
                  f"!= EP message_id {mid!r} (a per-hop relay-evidence reference "
                  "must bind this package)")
        if ev.get("event") not in ("B.1-RelayAcceptance", "B.2-RelayRejection"):
            v.add("LINT-EP-06",
                  f"rdp_chain[{i}].evidence.event {ev.get('event')!r} is not a "
                  "B.x relay event")
        dig = (ev.get("seal_digest") or {}).get("hex")
        if not (isinstance(dig, str) and len(dig) == 64
                and all(ch in "0123456789abcdef" for ch in dig)):
            v.add("LINT-EP-06",
                  f"rdp_chain[{i}].evidence.seal_digest.hex is not lowercase 64-hex")
    # LINT-EP-07 (finding R4, twenty-fourth review): outcome finality. Each of
    # DE-v1 / NDE-v1 / RE-v1 is a TERMINAL outcome; an EP carries at most ONE for
    # its message. A DE and a terminal NDE/RE together (or two terminals) is a
    # contradictory finality the state machine forbids — supplementary evidence
    # lives in changes/states, not as a second terminal outcome.
    terminals = [o for o in ep.get("outcomes", [])
                 if o.get("type") in ("DE-v1", "NDE-v1", "RE-v1")]
    if len(terminals) > 1:
        kinds = [o.get("type") for o in terminals]
        v.add("LINT-EP-07",
              f"EP carries {len(terminals)} terminal outcomes {kinds} for one message "
              "— at most one is allowed (a DE and a terminal NDE/RE are contradictory); "
              "supplementary evidence belongs in changes/states (finding R4)")
    # recurse for the enclosed objects' own rules (DE-04 needs the se context)
    lint_se(v, se)
    for o in ep.get("outcomes", []):
        lint_object(v, o, se=se)
    # LINT-EP-08 (X-31): every nested change/dispute binds THIS package's
    # message — outcomes and the SE were already bound; changes were not,
    # and the shipped federated fixture carried a foreign message's CE.
    for k in ("changes", "disputes"):
        for c in ep.get(k) or []:
            if c.get("message_id") != ep.get("message_id"):
                v.add("LINT-EP-08",
                      f"{k[:-1]} {c.get('type')} message_id "
                      f"{c.get('message_id')!r} != the EP's "
                      f"{ep.get('message_id')!r} — a package never carries "
                      "another message's evidence (X-31)")
    for c in ep.get("changes") or []:
        lint_ce(v, c, se=ep.get("se"))


def reveal_binding(conf, se):
    """R12-02 — what a reveal confirmation is ABOUT, stated once: the SE's
    message, recipient, transmitted octets and the grade commitment it opens.
    Called by `lint_gcm` on a retained dispute and by the issuing path before a
    reveal is recorded. Returns the problems as messages (LINT-GCM-01)."""
    out = []
    for field in ("message_id", "recipient_uid", "envelope_hash", "grade_commitment"):
        if conf.get(field) != se.get(field):
            out.append(f"reveal_confirmation.{field} != se.{field} — a reveal "
                       "must open the commitment of the message it disputes")
    return out


def lint_gcm(v, gcm, se=None):
    """X-04/D5 (evidence 2.2): grade-commitment-mismatch dispute evidence.
    LINT-GCM-01 — structural coherence: the reveal is well-formed and the GCM
    echoes the disputed sealed commitment; within an EP the GCM's message and
    commitment MUST be the SE's (the ORG-side declared-grade verification is
    bundle-level, LINT-BND-26). A GCM never retracts a DE: it is supplementary
    dispute evidence carried in the EP's disputes[], rebuttal-only (D5;
    TODO(legal) — the Article 43(2) clause awaits counsel)."""
    check_auth_assurance(v, gcm.get("auth_context"), "gcm-dispute")  # X-27
    # LINT-GCM-02 (DR-03): the dispute's own coherence, checked as TYPED
    # violations — never as exceptions escaping into the validator.
    ac_mid = (gcm.get("auth_context") or {}).get("mid")
    if ac_mid is not None and gcm.get("mid") != ac_mid:
        v.add("LINT-GCM-02",
              f"GCM mid {gcm.get('mid')!r} != auth_context.mid {ac_mid!r} — the "
              "disputing member and the authenticated member must be one (DR-03)")
    if not gcm.get("envelope_hash"):
        v.add("LINT-GCM-02",
              "GCM without envelope_hash — a dispute binds to the disputed "
              "OCTETS, not merely to a message_id (DR-03)")
    _salt = ((gcm.get("reveal") or {}).get("salt"))
    if isinstance(_salt, str) and not re.fullmatch(r"[a-f0-9]{32}", _salt):
        v.add("LINT-GCM-02",
              f"GCM reveal.salt must be exactly 32 lowercase hex characters "
              f"(16 bytes), got {len(_salt)} character(s) (DR-03)")
    _conf = gcm.get("reveal_confirmation")
    if isinstance(_conf, dict):
        _check_wallet_sig(v, _conf, "reveal_confirmation")
        if se is not None:
            for msg in reveal_binding(_conf, se):
                v.add("LINT-GCM-01", msg)
    _check_evidence_seal(v, gcm)
    rev = gcm.get("reveal")
    if not (isinstance(rev, dict) and isinstance(rev.get("salt"), str)
            and isinstance(rev.get("content_class"), str)):
        v.add("LINT-GCM-01", "GCM reveal missing or malformed (salt, content_class)")
        return
    try:
        bytes.fromhex(rev["salt"])
    except ValueError:
        v.add("LINT-GCM-01", "GCM reveal.salt is not hex")
    if se is not None:
        if gcm.get("message_id") != se.get("message_id"):
            v.add("LINT-GCM-01", "GCM message_id != se.message_id")
        if gcm.get("grade_commitment") != se.get("grade_commitment"):
            v.add("LINT-GCM-01",
                  "GCM grade_commitment does not echo the SE's sealed commitment "
                  "— the dispute must reference the disputed value")


def lint_object(v, obj, se=None):
    t = obj.get("type")
    if t == "SE-v1":
        lint_se(v, obj)
    elif t == "DE-v1":
        lint_de(v, obj, se=se)
    elif t == "NDE-v1":
        lint_nde(v, obj, se=se)
    elif t == "RE-v1":
        lint_re(v, obj)
    elif t == "CE-v1":
        lint_ce(v, obj)
    elif t == "EP-v1":
        lint_ep(v, obj)
    elif t == "RelayEvidence-v1":
        lint_relay(v, obj)
    elif t == "GCM-v1":
        lint_gcm(v, obj, se=se)
    else:
        v.add("LINT-000", f"unknown or missing evidence type: {t!r}")


# Published demo Ed25519 public keys (base64), for --verify-demo (N6). Real
# deployments verify against the Trusted-List trust material, not these keys.
DEMO_PUBKEYS_B64 = {
    "demo": "peni1HM+ZD1qbhm3SeKDlR5WTB3k87OcVWEWhqDd2oo=",         # rdp evidence seal
    "wallet-demo": "3xTEmmS8LjSde84g5A/YFOMo/DSsL2ju6SMLPpd9uEQ=",  # recipient wallet
}


def _demo_pub_b64(seed):
    """The deterministic demo public key for a seed label. X-32: wallet keys
    are per-device (seed 'wallet:<mid>:<device_id>'), so a signature verifies
    against exactly one device anchor; the fixed table covers the rdp seal."""
    if seed in DEMO_PUBKEYS_B64:
        return DEMO_PUBKEYS_B64[seed]
    from nacl.signing import SigningKey
    return base64.b64encode(
        bytes(SigningKey(hashlib.sha256(seed.encode()).digest()).verify_key)
    ).decode("ascii")


def _verify_cose(v, b64, seed, label):
    """--verify-demo: the COSE_Sign1 Ed25519 signature verifies against the demo key."""
    if not _b64_ok(b64) or not _HAVE_CBOR:
        return
    try:
        from nacl.signing import VerifyKey
    except Exception:  # pragma: no cover
        return  # pynacl absent; --verify-demo is best-effort
    try:
        cose = cbor2.loads(base64.b64decode(b64))
        protected, _u, payload, sig = cose
        to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
        VerifyKey(base64.b64decode(_demo_pub_b64(seed))).verify(to_sign, sig)
    except Exception:
        v.add("LINT-VERIFY-01",
              f"{label}: COSE signature does not verify against the demo {seed!r} key")


def _verify_demo_pass(v, obj):
    t = obj.get("type")
    _verify_cose(v, (obj.get("seal") or {}).get("cose_b64"),
                 "demo", f"{t} seal")
    for key in ("s3_attestation", "recipient_confirmation",
                "sender_confirmation", "refusal_confirmation"):
        conf = obj.get(key) or {}
        if conf.get("wallet_signature_b64"):
            _verify_cose(v, conf["wallet_signature_b64"],
                         f"wallet:{conf.get('mid', '')}:{conf.get('device_id', '')}",
                         f"{t} {key}.wallet_signature_b64")
    for q in obj.get("quorum") or []:
        if isinstance(q, dict) and q.get("wallet_signature_b64"):
            _verify_cose(v, q["wallet_signature_b64"],
                         f"wallet:{q.get('mid', '')}:{q.get('device_id', '')}",
                         f"{t} quorum[{q.get('mid')}].wallet_signature_b64")
    if isinstance(obj.get("se"), dict):
        _verify_demo_pass(v, obj["se"])
    for k in ("outcomes", "changes"):
        for it in obj.get(k) or []:
            _verify_demo_pass(v, it)


def _signer_identity(doc):
    """The identity that SEALED this evidence object (CF-6, twenty-first review).

    Every evidence object except one names its issuer in `rdp_id`. A
    `RelayEvidence-v1` does not: its issuer is the **recipient-side** RDP that
    accepts or refuses the relayed message and seals the hop — `receiving_rdp_id`
    (TS clause 4.1, FC-1; the schema's own words). Returning None for it would
    SILENTLY SKIP the LINT-TRUST-02 identity binding, because `check_trust` gates
    that comparison on `identity is not None` — so a relay hop could be attributed
    to an RDP the federation has never heard of and still pass the fail-closed
    trust mode. Per-hop evidence exists to prove which provider did what at which
    hop; this is the check that makes it answer.

    The EVIDENCE PACKAGE has the same gap, and it is the more consequential one:
    an EP carries NO `rdp_id` at all (the schema admits no such field), so its
    identity was None too and the binding was skipped for the aggregate dispute
    artefact itself — the object a verifier or a court actually reads. The EP is
    composed and sealed by the designated EP authority: the sender-side RDP that
    issued the SE and performs submission gating (TS clause 4.1; the EP schema's
    "default: RDP(out)"). So its signer is `se.rdp_id` — taken from the enclosed
    SE rather than from `rdp_chain[0]`, whose ordering is not normatively fixed.
    """
    t = doc.get("type")
    if t == "RelayEvidence-v1":
        return doc.get("receiving_rdp_id")
    if t == "EP-v1":
        return (doc.get("se") or {}).get("rdp_id")
    return doc.get("rdp_id")


def _relay_peer_trust(v, doc, store):
    """LINT-TRUST-04 (CF-6, twenty-first review): a RelayEvidence-v1's
    `sending_rdp_id` is a CLAIM about a federation peer — the provider that
    relayed the message to the issuer. That peer is NOT the signer, so it must
    **not** be checked against the *signer's* identity list (LINT-TRUST-02) — that
    is a different party. The meaningful check is MEMBERSHIP: the named peer must
    be a provider the federation knows. This makes FC-3 peer authentication
    (Trusted Lists + the federation membership register, TS clause 4.1)
    machine-checkable at lint time rather than only on the wire.

    Store-dependent, so it lives in the LINT-TRUST-* family: LINT-RLY-02 must keep
    working WITHOUT a trust store, and making a rule's meaning depend on the
    invocation mode is precisely the silent divergence this cycle removes.
    """
    if doc.get("type") != "RelayEvidence-v1":
        return
    peer = doc.get("sending_rdp_id")
    if peer is None:
        return  # a missing peer is already LINT-RLY-02
    known = set()
    for entry in (store.get("entries") or {}).values():
        if entry.get("role") == "evidence-rdp":
            known.update(entry.get("identities") or [])
    if known and peer not in known:
        v.add("LINT-TRUST-04",
              f"relay sending_rdp_id {peer!r} does not resolve to a known "
              f"evidence-rdp identity in the trust store {sorted(known)} — a hop "
              "may not name a relaying peer the federation has never heard of "
              "(FC-3 peer authentication)")


def lint(doc, profile="pilot", verify_demo=False, trust_store=None):
    """Return a list of (rule_id, message) violations for one evidence document.
    Modes (N6): default = schema/semantic + COSE payload binding + timestamp
    imprint; verify_demo = also cryptographically verify each COSE signature
    against the published demo keys (LINT-VERIFY-01); profile='production' adds
    the LINT-PROD-01..03 identity checks (X7); trust_store = a loaded demo
    store — the seal must resolve to it, verify against its key, and match its
    identity/validity constraints (LINT-TRUST-01..03, P10), and for relay evidence
    the named relaying peer must resolve to a known provider (LINT-TRUST-04)."""
    v = Violations()
    if isinstance(doc, dict) and "sm_artifact_b64" in doc and "projection" in doc:
        # LINT-PKG-11 (N1): the wire projection MUST equal decode(payload) exactly
        # before it is trusted; then reconstruct from the authoritative bytes.
        for rule, msg in projection_equals_decode(doc):
            v.add(rule, msg)
        # LINT-PKG-12 (N2): the decoded body MUST validate against its
        # authoritative JSON Schema (CDDL = structural outer bound only).
        for rule, msg in validate_body(doc["projection"]):
            v.add(rule, msg)
        doc = reconstruct(doc)
    elif flat_projection(doc) is not None:
        # R11-09: the FLAT form (body + `seal`) is accepted too, and only the
        # wrapper had its body Schema-validated — an SE without `sent_at`
        # lost its LINT-PKG-12 in this form. Every accepted form now
        # normalises to the same projection and validates it.
        for rule, msg in validate_body(flat_projection(doc)):
            v.add(rule, msg)
    for p, reason in find_unsafe_numbers(doc):
        v.add("LINT-PKG-09", f"{reason} at {p}")
    # LINT-HASH-01: every digest descriptor in the reconstructed document, not
    # only the ones a type-specific rule happens to read. A hash_mode outside
    # the profile is refused here as well as by the Schema, because a verifier
    # meeting one cannot recompute the digest at all.
    for rule, msg in hash_mode_violations(doc):
        v.add(rule, msg)
    lint_object(v, doc)
    if verify_demo:
        _verify_demo_pass(v, doc)
    if profile == "production":
        _production_pass(v, doc)
    if trust_store is not None:
        seal = (doc.get("seal") or {}).get("cose_b64")
        for rule, msg in check_trust(doc, seal, trust_store, "evidence-rdp",
                                     _signer_identity(doc)):
            v.add(rule, msg)
        _relay_peer_trust(v, doc, trust_store)
    return v.items


def main(argv):
    files, opts = parse_common_flags(argv)
    dev_mode = opts["dev_mode"]
    verify_demo = opts["verify_demo"]
    profile = opts["profile"]
    trust_store = opts["trust_store"]
    if opts["unknown"] or not files:
        for a in opts["unknown"]:
            print(f"[ERR ] unknown flag: {a}", file=sys.stderr)
        print("usage: evidence_lint.py [--dev-mode] [--verify-demo] "
              "[--profile pilot|production] [--trust-store PATH] <sample.json> [...]\n"
              "  Modes (§9.4): default = schema + semantic + COSE payload binding + timestamp imprint;\n"
              "  --verify-demo = also cryptographically verify each seal against the published DEMO keys\n"
              "    (LINT-VERIFY-01) — real deployments verify against the Trusted-List trust material;\n"
              "  --profile production = structural identity/TSA prechecks (LINT-PROD-01..03), NOT legal\n"
              "    qualification validation (no QSealC chain / SCD / Trusted List / TSA verification).\n"
              "  --trust-store PATH = fail-closed demo-store verification (LINT-TRUST-01..03): the seal's"
              " kid must\n    resolve to the store, verify against its key, and match its identity/validity"
              " constraints.", file=sys.stderr)
        return 2
    store = None
    if trust_store is not None:
        print(f"[notice] --trust-store {trust_store!r}: DEMO-grade store (kid -> key/identity/"
              "validity, LINT-TRUST-01..03, fail-closed). Production trust-path validation "
              "(QSealC chain, EU Trusted Lists, TSA chain) remains a production-verifier "
              "obligation — README, production verification roadmap.")
        try:
            store = load_trust_store(trust_store)
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
    # W3: cbor2 is REQUIRED for a conformance result. Without it the COSE
    # structural/alg checks (LINT-PKG-01/02/05) cannot run, so lint-clean would
    # be meaningless. Hard-fail unless the operator explicitly opts into the
    # degraded, non-conformance mode.
    if not _HAVE_CBOR and not dev_mode:
        print("[ERROR] cbor2 is not installed — the COSE structural/algorithm checks "
              "(LINT-PKG-01/02/05) cannot run, so protocol conformance CANNOT be "
              "established.\n"
              "        Install the test environment: pip install -r scripts/requirements.txt\n"
              "        (To run the DEGRADED, non-conformance lint anyway, pass --dev-mode.)",
              file=sys.stderr)
        return 2
    if not _HAVE_CBOR:
        print("[notice] --dev-mode: cbor2 is absent; running a DEGRADED lint with the "
              "COSE checks (LINT-PKG-01/02/05) SKIPPED. This is NOT a conformance result.")
    if profile == "production":
        print("[notice] --profile production is a STRUCTURAL precheck, NOT legal qualification "
              "validation: it does not verify the QSealC chain, SCD certification, Trusted List "
              "status, or the TSA chain (§9.4).")
    total = 0
    for f in files:
        try:
            raw_sample = load_ijson(open(f, encoding="utf-8").read())
            doc = reconstruct(raw_sample)
        except DuplicateKeyError as exc:
            print(f"[FAIL] {f}: LINT-PKG-10 {exc}")
            total += 1
            continue
        except Exception as exc:
            print(f"[ERR ] {f}: cannot read/parse ({exc})")
            total += 1
            continue
        if doc.get("type") not in EVIDENCE_DOC_TYPES:
            print(f"[skip] {f} (not an evidence document: {doc.get('type')!r})")
            continue
        # Pass the WRAPPER so lint() runs LINT-PKG-11 (projection ≡ decode(payload))
        # before reconstructing from the authoritative bytes.
        issues = lint(raw_sample, profile=profile, verify_demo=verify_demo, trust_store=store)
        # X-25: "-W" rules are WARNINGS (safe generic processing) — printed,
        # never counted as violations (the bundle_lint LINT-BND-W convention).
        warnings = [(r, m) for r, m in issues if r.split("-")[-1].startswith("W")]
        issues = [(r, m) for r, m in issues if not r.split("-")[-1].startswith("W")]
        for rule, msg in warnings:
            print(f"[warn] {f}: {rule}: {msg}")
        if issues:
            total += len(issues)
            for rule, msg in issues:
                print(f"[FAIL] {f}: {rule}: {msg}")
        else:
            print(f"[OK  ] {f} ✓")
    print(f"{'FAIL' if total else 'OK'}: {total} violation(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
