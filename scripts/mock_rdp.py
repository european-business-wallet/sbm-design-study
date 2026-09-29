#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Mock RDP server (demo) — SM-MLS-1.0 / evidence v2.0.

Produces demo SE/DE/EP evidence objects per the Secure Business Messaging Profile
(evidence objects and COSE packaging: Internet-Draft draft-sbm-mls-erd; evidence version 2.0).
Not a production implementation. COSE signing uses either PyNaCl (if
REAL_SIGN=1 and PyNaCl is installed) or a deterministic HMAC placeholder.

The v2.0 evidence includes, in addition to the MLS session binding
(transport, mls_group_id, mls_epoch, auth_method) and payload_hash:
  - profile (pilot | production) — §9.3 conformance profile
  - qualified_timestamp (Regulation (EU) No 910/2014, Article 44(1)(f)) — demo token
  - event (EN 319 522-1 clause 6), evidence_id (G01), policy_id (R01)
  - recipient_auth_method on DE (REQ-QERDS-5.2.2-03A)
"""

from flask import Flask, request, jsonify, Response
import os, json, base64, copy, hashlib, datetime, hmac, secrets, sys, uuid, warnings, pathlib

# scripts/ is not a package; make the shared modules importable whether this
# module is run directly or loaded via importlib by tests/regen.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cbor2  # noqa: E402  — deterministic CBOR for the authoritative body (M4)
# R8-01: the SE output gate runs twice in `submit()` — once on the candidate
# before the DS is contacted, once on the object about to be sealed — so the
# validator is imported once here rather than at each call site.
from lint_cli import (validate_body, validate_delivery_receipt,  # noqa: E402
                      validate_contract_object, instant, TimestampError,
                      load_registry as lint_cli_load_registry)
import mls_wire  # noqa: E402  — the published KeyPackage reference (R9-X1)

app = Flask(__name__)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- Minimal CBOR encoder (enough for COSE_Sign1 demo) ----------------------

def _cbor_mt_val(mt, val):
    if val < 24:
        return bytes([(mt << 5) | val])
    elif val < 256:
        return bytes([(mt << 5) | 24, val & 0xFF])
    elif val < 65536:
        return bytes([(mt << 5) | 25, (val >> 8) & 0xFF, val & 0xFF])
    elif val < 4294967296:
        return bytes([(mt << 5) | 26]) + (val.to_bytes(4, 'big'))
    else:
        return bytes([(mt << 5) | 27]) + (val.to_bytes(8, 'big'))


def _cbor_any(x):
    if isinstance(x, int):
        if x >= 0:
            return _cbor_mt_val(0, x)
        return _cbor_mt_val(1, -1 - x)  # CBOR negative integer (major type 1)
    if isinstance(x, bytes):
        return _cbor_mt_val(2, len(x)) + x
    if isinstance(x, str):
        bs = x.encode('utf-8')
        return _cbor_mt_val(3, len(bs)) + bs
    if isinstance(x, list):
        out = _cbor_mt_val(4, len(x))
        for it in x:
            out += _cbor_any(it)
        return out
    if isinstance(x, dict):
        out = _cbor_mt_val(5, len(x))
        for k, v in x.items():
            out += _cbor_any(k) + _cbor_any(v)
        return out
    raise TypeError("unsupported type")


def demo_seed_bytes(seed: str) -> bytes:
    """Deterministic 32-byte Ed25519 seed from a demo seed label (DEMO ONLY)."""
    return hashlib.sha256(seed.encode("utf-8")).digest()


def demo_public_key_b64(seed: str) -> str:
    """Base64 Ed25519 public key for a demo seed label — published in the README
    so the sample signatures are verifiable. Requires pynacl."""
    from nacl.signing import SigningKey
    return base64.b64encode(bytes(SigningKey(demo_seed_bytes(seed)).verify_key)).decode("ascii")


def cose_sign(payload_bytes: bytes, kid: str = "rdp", seed: str = "demo", extra_ph=None) -> bytes:
    ph = {1: -8, 4: kid.encode('utf-8')}  # alg=EdDSA, kid
    if extra_ph:
        ph.update(extra_ph)  # e.g. {33: <x5chain DER>} for production identity binding

    def _map(d):
        out = _cbor_mt_val(5, len(d))
        for k, v in d.items():
            # CBOR-encode every value: the kid (label 4) is raw bytes and MUST
            # become a CBOR byte string, else the protected header is malformed
            # and its alg cannot be decoded (LINT-PKG-05).
            out += _cbor_any(k) + _cbor_any(v)
        return out

    protected_b = _map(ph)
    sig_structure = ["Signature1", protected_b, b"", payload_bytes]
    to_sign = _cbor_any(sig_structure)

    # Real Ed25519 is the DEFAULT (X2). REAL_SIGN=0 selects the HMAC dev
    # fallback, which is a STRUCTURAL DEMO ONLY and NOT cryptographically valid.
    # Real Ed25519 is the DEFAULT (X2). A missing PyNaCl when real signing is
    # wanted MUST fail loudly (M6) — never silently degrade to the placeholder,
    # which would emit structurally-valid-but-cryptographically-invalid samples.
    want_real = os.environ.get("REAL_SIGN", "1") != "0"
    if want_real:
        try:
            from nacl.signing import SigningKey
        except Exception as exc:
            raise RuntimeError(
                "real signing requested but pynacl is not installed — install "
                "scripts/requirements.txt or set REAL_SIGN=0 for the structural "
                "dev fallback") from exc
        sig = SigningKey(demo_seed_bytes(seed)).sign(to_sign).signature
    else:
        # REAL_SIGN=0: explicit HMAC dev fallback — structurally well-formed but
        # NOT a cryptographically valid signature.
        warnings.warn(
            "REAL_SIGN=0: emitting the HMAC placeholder — structurally well-formed "
            "but NOT a cryptographically valid signature (dev only).",
            stacklevel=2)
        key = hashlib.sha256(seed.encode("utf-8")).digest()
        mac = hmac.new(key, to_sign, hashlib.sha256).digest()
        sig = (mac + mac)[:64]

    cose = [protected_b, {}, payload_bytes, sig]
    return _cbor_any(cose)


def _dcbor(obj) -> bytes:
    """Deterministic CBOR (RFC 8949 §4.2) of a body/projection (M4)."""
    return cbor2.dumps(obj, canonical=True)


def seal_cose(body: dict, kid: str = "rdp", seed=None, extra_ph=None) -> bytes:
    """The authoritative seal (M4/T1): a COSE_Sign1 whose payload is dCBOR(body).
    The body is encoded once, deterministically, and those bytes ARE the artefact."""
    payload = _dcbor(body)
    return cose_sign(payload, kid=kid, seed=seed or os.environ.get("KEY_SEED", "demo"),
                     extra_ph=extra_ph)


def evidence_artifact(body: dict, kid: str = "rdp", seed=None, extra_ph=None) -> dict:
    """A standalone evidence artefact (M4): the authoritative bytes are
    dCBOR([cose_sign1, qualified_timestamp]); the projection is the body verbatim
    (decode(cose payload) == projection)."""
    cose = seal_cose(body, kid=kid, seed=seed, extra_ph=extra_ph)
    qts = _qts_over_cose(cose, _stamp_instant(body))
    artifact = _dcbor([cose, qts])
    return {"sm_artifact_b64": base64.b64encode(artifact).decode("ascii"),
            "projection": body}


def discovery_artifact(body: dict, kid: str = "entity-admin", seed=None) -> dict:
    """A discovery artefact (M4): the authoritative bytes are the COSE_Sign1 alone
    (discovery documents carry no qualified timestamp)."""
    cose = seal_cose(body, kid=kid,
                     seed=seed or os.environ.get("ENTITY_ADMIN_SEED", "entity-admin-demo"))
    return {"sm_artifact_b64": base64.b64encode(cose).decode("ascii"),
            "projection": body}


def ep_artifact(ep_fields: dict, se_art: dict, outcome_arts: list,
                change_arts=None, dispute_arts=None, composed_at=None) -> dict:
    """An Evidence Package artefact (M4): the EP body EMBEDS each sub-object as its
    sub-ARTEFACT bytes (a CBOR bstr) so every issuer's seal is preserved for
    multi-party attribution; the projection nests the readable sub-bodies."""
    body = dict(ep_fields)
    body["se"] = base64.b64decode(se_art["sm_artifact_b64"])
    body["outcomes"] = [base64.b64decode(o["sm_artifact_b64"]) for o in outcome_arts]
    if change_arts:
        body["changes"] = [base64.b64decode(c["sm_artifact_b64"]) for c in change_arts]
    if dispute_arts:  # X-04/D5 (2.2)
        body["disputes"] = [base64.b64decode(d["sm_artifact_b64"]) for d in dispute_arts]
    cose = seal_cose(body)
    projection = dict(ep_fields)
    projection["se"] = se_art["projection"]
    projection["outcomes"] = [o["projection"] for o in outcome_arts]
    if change_arts:
        projection["changes"] = [c["projection"] for c in change_arts]
    if dispute_arts:
        # The body embedded the dispute artefacts and the projection did not, so
        # a package carrying one sealed a document its readable form denied
        # (LINT-PKG-11). Invisible until the cross-representation gate demanded
        # a vector for `disputes`: the branch above does both, this one did half.
        projection["disputes"] = [d["projection"] for d in dispute_arts]
    # R10-X5: composition IS the sealing, so the timestamp's genTime is the
    # composer's act instant. Default: the latest act the package encloses —
    # a package cannot be composed before the last thing it records.
    qts = _qts_over_cose(cose, composed_at or _stamp_instant(projection))
    artifact = _dcbor([cose, qts])
    return {"sm_artifact_b64": base64.b64encode(artifact).decode("ascii"),
            "projection": projection}


# R3-01 housekeeping: the evidence version was written out FOUR times in this
# file. `regen_samples` had the same constant, and its sibling discovery table
# had already caused a silent revert in round 2. Derived from versions.json —
# the manifest R-01 exists to be the single source of.
EVIDENCE_VERSION = json.loads(
    (pathlib.Path(__file__).resolve().parents[1] / "versions.json")
    .read_text(encoding="utf-8"))["dimensions"]["evidence"]["value"]


class SubmissionRejected(Exception):
    """DR-02: a typed intake rejection raised BEFORE any evidence is sealed.
    Carries the registry reason so the surface can return it verbatim."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


_SUBMISSION_LEDGER = {}   # message_id -> envelope digest of the accepted octets



def _org_body_digest(org):
    """The ORG's authoritative content digest (§8.3, LINT-BND-10): SHA-256 over
    dCBOR of the body the discovery seal covers."""
    body = {k: v for k, v in org.items() if k != "doc_cose_b64"}
    return hashlib.sha256(_dcbor(body)).hexdigest()


def _check_policy_against_discovery(meta, org):
    """R5-01: RECOMPUTE the acceptance-policy selection and refuse to seal over
    a disagreement — the obligation the wallet-RDP contract states and this
    function had no BW-ORG with which to meet.

    Three checks, in the order a provider can actually perform them:
      1. the reference pins THIS entity's published policy document (digest);
      2. that version was already in force at `sent_at` (LINT-BND-33's rule at
         intake, where refusing is still possible);
      3. the selected KEY equals what `select_policy_key` computes.

    The wallet's copy is a commitment; the RDP's computation is the authority.
    """
    from lint_cli import (select_policy_key, ForeignAddress, instant,
                          TimestampError)
    ref = meta.get("acceptance_policy_ref")
    if not isinstance(ref, dict):
        raise SubmissionRejected(
            "policy-ref-missing",
            "the submission carries no acceptance_policy_ref, so the policy "
            "the sender signed cannot be compared with the published one "
            "(R5-01); the D4 tuple REQUIRES the field")
    if not isinstance(org, dict) or not org:
        raise SubmissionRejected(
            "policy-unresolvable",
            "no BW-ORG was supplied to intake, so the acceptance policy cannot "
            "be recomputed. Fail closed: skipping the check when the material "
            "is absent is exactly how an unproven property became a silent "
            "pass (R5-01)")

    if ref.get("doc_digest", {}).get("hex") != _org_body_digest(org):
        raise SubmissionRejected(
            "policy-digest-mismatch",
            "acceptance_policy_ref pins a BW-ORG body that is not the "
            "recipient's published document — the sender signed a policy this "
            "provider cannot produce (R5-01, §8.3/LINT-BND-10)")
    if ref.get("policy_version") != org.get("policy_version"):
        raise SubmissionRejected(
            "policy-digest-mismatch",
            f"acceptance_policy_ref names policy_version "
            f"{ref.get('policy_version')!r} but the pinned body is "
            f"{org.get('policy_version')!r} (R5-01)")

    sent = meta.get("sent_at")
    try:
        if sent and instant(org.get("valid_from"), field="valid_from") > \
                instant(sent, field="sent_at"):
            raise SubmissionRejected(
                "policy-not-in-force",
                f"BW-ORG {org.get('policy_version')!r} takes force at "
                f"{org.get('valid_from')} — after sent_at {sent}. Evidence "
                "must not be evaluated under rules that did not yet exist when "
                "the act took place (R5-01, LINT-BND-33 at intake)")
    except TimestampError as e:
        raise SubmissionRejected("policy-not-in-force", f"{e} (R5-01)")

    try:
        computed = select_policy_key(org, meta.get("scope_ref"),
                                     meta.get("recipient_addr"))
    except ForeignAddress as e:
        raise SubmissionRejected("unaddressed-submission", f"{e} (R4-01)")
    except KeyError as e:
        raise SubmissionRejected("no-matching-scope", f"{e} (X-12)")
    if ref.get("policy_key") != computed:
        raise SubmissionRejected(
            "policy-key-mismatch",
            f"the submission claims acceptance policy {ref.get('policy_key')!r} "
            f"and the published BW-ORG selects {computed!r} for this address "
            "and scope — the RDP's recomputation is the authority, and a "
            "disagreement is refused BEFORE any evidence exists (R5-01)")


def _check_sender_confirmation(meta, members, computed):
    """R5-01: validate the sender's D4 confirmation at intake.

    The copied fields must equal the submission's own values, and the signature
    must verify against the sending device's PUBLISHED confirmation key — the
    LINT-DE-19 / LINT-BND-28 semantics the contract already claimed happen
    here. The field list is `lint_cli.D4_COPIED_FIELDS`, shared rather than
    restated (R3-01), so the tuple cannot drift between intake and the
    verifier.

    `computed` carries the commitments RDP(out) DERIVED from the octets it
    actually received — `envelope_hash` and `mls_state`. Those two D4 fields are
    compared against THOSE, not against the submission's own copies: comparing a
    sender-supplied confirmation with a sender-supplied metadata field compares
    two statements by the same party and proves nothing. Checked this way, the
    confirmation proves the sender signed the tuple describing the bytes that
    were actually submitted — which is DR-02's pattern applied to the D4 tuple.

    LIMIT, stated rather than implied: the roster resolution here is of the
    material the PROVIDER holds at intake. Historical act-time resolution
    against a retained member history is the verifier's job (LINT-BND-28,
    R3-03) and is not duplicated — a second implementation of an act-time
    window is precisely what invariant 3 forbids.
    """
    from lint_cli import D4_COPIED_FIELDS, verify_cose_signature, \
        SignatureVerificationError
    sc = meta.get("sender_confirmation")
    if sc is None:
        if meta.get("origin_proof") == "sender-signed":
            raise SubmissionRejected(
                "sender-confirmation-missing",
                "origin_proof is 'sender-signed' and no sender_confirmation is "
                "present — the opposable posture REQUIRES the sender's own "
                "signature (R5-01, INTF-1b)")
        return
    for field in D4_COPIED_FIELDS:
        want = computed.get(field, meta.get(field))
        if sc.get(field) != want:
            derived = field in computed
            raise SubmissionRejected(
                "sender-confirmation-mismatch",
                f"sender_confirmation.{field} does not equal "
                + ("the value RDP(out) computed from the submitted octets"
                   if derived else "the submission's own value")
                + " — the sender signed a different tuple than the one "
                  "submitted (R5-01, LINT-DE-19)")
    if not members:
        raise SubmissionRejected(
            "sender-confirmation-unverifiable",
            "no member roster was supplied to intake, so the sending device's "
            "published confirmation key cannot be resolved and the signature "
            "cannot be verified. Fail closed (R5-01)")
    mid, device_id = sc.get("mid"), sc.get("device_id")
    member = next((m for m in members if m.get("mid") == mid), None)
    device = next((d for d in (member or {}).get("devices") or []
                   if d.get("device_id") == device_id), None)
    key = (device or {}).get("confirmation_key")
    if not key:
        raise SubmissionRejected(
            "sender-confirmation-unverifiable",
            f"no published confirmation_key for ({mid!r}, {device_id!r}) — a "
            "signature with no resolvable key proves nothing (R5-01, INTF-1a)")
    try:
        verify_cose_signature(sc.get("wallet_signature_b64") or "", key)
    except SignatureVerificationError as e:
        raise SubmissionRejected(
            "sender-confirmation-invalid",
            f"the sender_confirmation does not verify against the published "
            f"confirmation key of ({mid!r}, {device_id!r}): {e} (R5-01)")


def accept_submission(meta, retained_group_context=None, *,
                      principal="urn:sbm:rdp:demo-out", org=None, members=None,
                      server_clock=None):
    """DR-02/R2-M2 — the ATOMIC submission gate (wallet-RDP contract 1.1.0).

    RDP(out) COMPUTES the transport commitment from the octets it actually
    receives, so what it later seals into SE is true by construction. Returns
    the RDP-computed {envelope_hash, mls_state}; raises SubmissionRejected —
    before any evidence exists — when the submission is not attestable.

    Before this gate, `POST /submissions` carried a wallet-CLAIMED digest and
    no bytes, while the bytes reached the Delivery Service by a separate call
    with no normative binding: RDP(out) could only copy the assertion, and a
    different message could be delivered under the same metadata.

    R5-01 (Blocker) — `org` and `members`, and why they had to be added.
    The published contract says RDP(out) "RECOMPUTES the selection
    (`lint_cli.select_policy_key`) and REJECTS a disagreeing submission with a
    typed reason BEFORE sealing", "validates the sender_confirmation", and
    "checks that the pinned policy version was in force at `sent_at`". This
    function received NO BW-ORG, NO member roster and NO confirmation key, so
    it was structurally incapable of any of the three: not a missing call, a
    missing INPUT. On addresses it checked `isinstance(str)` and non-empty.

    A contract describing behaviour the reference implementation cannot perform
    is worse than one describing none, because implementers calibrate against
    the reference. The discovery inputs are therefore REQUIRED for those checks
    and their absence is itself a typed rejection — fail closed, never "skip
    the check when the material is missing", which is how R4-02's silent
    downgrade worked.
    """
    import mls_wire
    # ---- R7-01: the PUBLISHED REQUEST CONTRACT, first, before anything ----
    # Nine of sixteen contract-required fields used to produce a SEALED SE
    # that fails its own authoritative Schema, because the path between the
    # request contract and the evidence Schema ran neither. This runs the
    # request contract, derived from wallet-rdp-openapi.yaml rather than
    # restated, at the first line — before any commitment is computed and
    # before any ledger is touched.
    from lint_cli import validate_submission_metadata, SubmissionInvalid
    try:
        validate_submission_metadata(meta)
    except SubmissionInvalid as e:
        # R7-01 requirement 2: map the Schema failure to a registered typed
        # reason WITHOUT collapsing the semantic ones. A missing address is a
        # contract violation AND the R3-01 case, and `unaddressed-submission`
        # tells a client something `submission-incomplete` does not — that the
        # message did not say what it is addressed to, which is the specific
        # failure R3-01 exists to make visible. Detected at the same first
        # line; answered with the sharper reason where one exists.
        #
        # R8-01: decided on `e.fields`, which is DATA. This used to substring-
        # match `e.detail`, and once the whole Schema ran, a `oneOf` failure
        # rendered the entire instance into that message — so every address in
        # the submission looked like the offending field and an unrelated
        # defect was answered `unaddressed-submission`.
        for field in ("recipient_addr", "sender_addr"):
            if field in e.fields and not str(meta.get(field) or "").strip():
                raise SubmissionRejected(
                    "unaddressed-submission",
                    f"no {field}: every message is explicitly entity-, role- "
                    "or member-addressed, and the address is inside the tuple "
                    "the sender signs (R3-01)")
        # R8-01 requirement 2, same shape: the contract expresses "a
        # sender-signed submission carries the D4 tuple" as a `oneOf`, so the
        # executed Schema now catches an absent tuple that only
        # `_check_sender_confirmation` used to reach. The registered reason
        # survives the move — a client that omitted the tuple must not be told
        # only that its request failed a combinator.
        if meta.get("origin_proof") == "sender-signed" \
                and meta.get("sender_confirmation") is None:
            raise SubmissionRejected(
                "sender-confirmation-missing",
                "origin_proof is 'sender-signed' and the submission carries no "
                "`sender_confirmation`: the published request contract and the "
                "SE Schema both require the D4 tuple for this origin proof "
                "(R3-01/R8-01)")
        raise SubmissionRejected(e.reason, e.detail)

    # R3-01/R3-T1: the addressing gate comes FIRST, before any commitment is
    # computed. A submission that does not say what it is addressed to cannot
    # have its acceptance policy selected, and 'default' is not a safe guess —
    # it is the weaker policy the omission used to reach silently.
    for field in ("recipient_addr", "sender_addr"):
        value = meta.get(field)
        if not isinstance(value, str) or not value.strip():
            raise SubmissionRejected(
                "unaddressed-submission",
                f"no {field}: every message is explicitly entity-, role- or "
                "member-addressed, and the address is inside the tuple the "
                "sender signs (R3-01)")

    # ---- R7-04: the issuing identity is canonical, or there is no
    # namespace to be idempotent within. Checked before any ledger key is
    # formed from it, at every entry point rather than only at the DS.
    from lint_cli import require_rdp_id, RdpIdentityError
    try:
        require_rdp_id(principal, context="the authenticated issuing RDP")
    except RdpIdentityError as e:
        raise SubmissionRejected(e.reason, e.detail)

    # ---- R6-01: the identity tuple must be COHERENT ----------------------
    # R5-01 verified each statement; nothing compared them, so a re-signed
    # tuple naming two different legal entities was accepted and SEALED. This
    # runs before any commitment is computed and before any ledger is touched
    # (required change 7): a submission that cannot be attributed is refused
    # without the provider doing work on it or leaving a trace to reconcile.
    from lint_cli import check_identity_coherence, check_scope_in_force
    for reason, detail in (
            check_identity_coherence(meta, org=org, members=members,
                                     at=meta.get("sent_at"))
            + check_scope_in_force(org, meta.get("scope_ref"),
                                   at=meta.get("sent_at"))):
        raise SubmissionRejected(reason, detail)

    # ---- R10-08 / X-22: the expiry is VALIDATED here, with the other
    # pre-commitment gates — before any commitment is computed, any ledger moves
    # or the Delivery Service is contacted. Intake ran none of these rules:
    # correctly signed submissions with a zero, reversed or 31-day TTL, or a
    # `sent_at` a day ahead of this RDP's clock, were sealed and moved all
    # three ledgers, and the violation surfaced only when the SEALED SE was
    # linted afterwards — too late by construction. The clock is THIS RDP's
    # own (a real one reads its clock; tests pass a fixed one); the maximum is
    # the RECIPIENT's declared one.
    from lint_cli import expiry_problems
    for reason, detail in expiry_problems(
            meta.get("sent_at"), meta.get("expires_at"),
            max_ttl=(org or {}).get("max_ttl"),
            clock=server_clock or now_iso()):
        raise SubmissionRejected(reason, detail)

    # ---- R5-01: what the contract says intake does, done here ------------
    # The policy half runs FIRST, before any commitment is computed: a
    # submission whose governing policy is not the published one is refused
    # without the provider doing work on it. The confirmation half runs below,
    # once the octets have been hashed, because two of the signed fields must
    # be compared with what RDP(out) DERIVED rather than with what the sender
    # asserted twice.
    _check_policy_against_discovery(meta, org)

    raw = meta.get("mls_message_b64")
    if not raw:
        raise SubmissionRejected(
            "malformed-envelope",
            "no mls_message_b64 — the transmitted octets travel WITH the "
            "submission (DR-02); RDP(out) does not attest bytes it has not seen")
    try:
        octets = base64.b64decode(raw, validate=True)
    except Exception:
        raise SubmissionRejected("malformed-envelope",
                                 "mls_message_b64 is not valid base64")
    computed = mls_wire.envelope_hash(octets)

    claimed = meta.get("envelope_hash")
    if claimed is not None and claimed != computed:
        raise SubmissionRejected(
            "envelope-hash-mismatch",
            f"the submitted octets hash to {computed['hex'][:16]}…, not to the "
            f"supplied {str(claimed.get('hex'))[:16]}… — RDP(out) attests what "
            "it received")

    # Idempotency binds message_id to THESE octets (INTF-4 extended to bytes).
    # R4-05: keyed by (issuing RDP, message_id). A provider's ledger is its
    # own; this process stands in for several, and conflating them would let
    # one provider's binding block or displace another's.

    # mls_state: hash the RETAINED GroupContext, never a sender claim (R2-M2).
    if retained_group_context is None:
        retained_group_context = mls_wire.demo_group_context(
            meta["mls_group_id"], meta["mls_epoch"],
            scope_id=(meta.get("scope_ref") or {}).get("scope_id", "default"),
            scope_version=(meta.get("scope_ref") or {}).get("version", "1"))
    state = mls_wire.mls_state_hash(retained_group_context)
    claimed_state = meta.get("mls_state")
    if claimed_state is not None and claimed_state != state:
        raise SubmissionRejected(
            "mls-group-invalid",
            "the supplied mls_state does not match the retained GroupContext "
            "for this (group, epoch) — SE records an RDP-verified state (DR-02)")

    mid_key = (principal, meta.get("message_id"))
    # R6-01 point 8: the reservation binds the COMPLETE immutable submission
    # identity, not the envelope digest alone. It used to record only the
    # octets, so the same ciphertext resubmitted under a different recipient,
    # payload commitment, scope or policy reference was not a collision — the
    # path returned the previously sealed SE and the changed metadata went
    # unreported. INTF-4's handle is the message, and the message is more than
    # its bytes.
    identity = {
        "envelope_hash": computed["hex"],
        "mls_state": state.get("hex"),
        "recipient_uid": meta.get("recipient_uid"),
        "recipient_addr": meta.get("recipient_addr"),
        "sender_uid": meta.get("sender_uid"),
        "payload_hash": meta.get("payload_hash"),
        "scope_ref": meta.get("scope_ref"),
        "acceptance_policy_ref": meta.get("acceptance_policy_ref"),
    }
    prior = _SUBMISSION_LEDGER.get(mid_key)
    if prior is not None and prior != identity:
        differing = sorted(k for k in identity
                           if prior.get(k) != identity.get(k)) or ["octets"]
        raise SubmissionRejected(
            "duplicate-message-id",
            f"message_id {mid_key!r} was accepted for a different submission — "
            f"{differing} differ. Reusing the handle for another message is a "
            "collision, not a retry (R6-01/INTF-4)")

    # R5-01: now that the commitments are RDP-derived, the sender's D4 tuple
    # can be checked against them rather than against the sender's own copies.
    _check_sender_confirmation(meta, members,
                               {"envelope_hash": computed, "mls_state": state})

    _SUBMISSION_LEDGER[mid_key] = identity
    return {"envelope_hash": computed, "mls_state": state}


# R9-01: a sentinel rather than `None`, so "the caller omitted it" and "the
# caller sent null" are the same answer instead of two code paths.
class _Required:
    def __repr__(self):
        return "<required>"


_REQUIRED = _Required()


class AckRejected(Exception):
    """DR-10: a typed rejection of an acknowledged handover, raised before any
    receipt exists (401 on the DS contract)."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


_ACK_LEDGER = {}   # (issuing_rdp_id, message_id, recipient_uid) -> the FIRST receipt


# R7-02/R7-X3 — THE DELIVERY ITEM. The DS owns this; no caller shapes it.
#
# The finding: `receipt_ack()` signed its arguments. It resolved nothing, so a
# valid signed receipt existed for a message the DS had never accepted, with an
# `issuing_rdp_id` the caller chose as a keyword argument. The signature was
# real and the state transition never happened.
#
# States, and each is a transition the DS OBSERVED:
#   accepted    the issuing RDP submitted octets (POST /messages)
#   queued      staged for one exact recipient DEVICE
#   transferred handed to that device in an authenticated session
#   acknowledged the device acknowledged; exactly one receipt exists
#
# A receipt may only be issued for an item in `transferred`. Anything else —
# unknown, still queued, wrong device, wrong session, wrong digest — is refused
# BEFORE anything is signed, because a signature over a refusal is still a
# signature somebody can present.
# R8-X2 — the key is PER DEVICE. One accepted message fans out to every
# enrolled device of the recipient, and each device's item is its own row.
# Before this, one mutable slot represented both the fan-out and the
# one-event-per-recipient receipt rule: re-queueing an ACKNOWLEDGED item for a
# second recipient overwrote the first and produced a second valid receipt.
# R9-02 requirement 4 / R9-X3 — THE ROUTING AUTHORITY, and it is published.
#
# Delivery items were created by the PRIVATE `queue_delivery()` helper, whose
# first caller chose `recipient_uid`, `mid` and `device_id` out of nothing the
# protocol defined. `POST /messages` supplies only group and message data and
# the acceptance record identifies no recipient, so two conforming Delivery
# Services would fan one accepted message out to different devices — and a test
# could only reach the flow by calling the private helper itself.
#
# The authority is the DS's OWN observation of group establishment: a device
# that was invited into a group (`POST /welcome`) and did not refuse
# (`POST /welcome/{id}/refusal`) is a member of it. Nothing else is consulted,
# and nothing is taken from the submission request — a client-supplied target
# list would have to be checked against this state anyway, so it would add a
# spoofing surface without adding information (the R4-U3 reasoning).
# R11-01 — A PRINCIPAL IS A TUPLE. MIDs are entity-scoped and device labels
# are member-scoped (umbrella §3): `F1N2C3D4P` may name a member of FR and a
# member of DE, and `dev-01` names a device of both members of one entity in
# the shipped samples. The Delivery Service keyed and authorised on the bare
# labels, and the published schemes bound a credential to a bare `mid` or
# `device_id`, so a FR device collected a DE device's message and the DS
# signed a receipt attributing that delivery to DE; a DE member collected and
# acknowledged a FR creator's outcome; and two members of one entity with a
# `dev-01` each could not even be invited. The labels are not redefined as
# global — every key and every comparison takes the whole tuple instead, and
# the tuple comes from the AUTHENTICATED credential, never from a request.
PRINCIPAL_FIELDS = {"member": ("uid", "mid"),
                    "device": ("uid", "mid", "device_id")}


def principal_of(credential, kind):
    """The principal a credential authenticates, as the tuple PRINCIPAL_FIELDS
    names — or None when the credential is of another kind or omits any part
    of it. A credential that names a device but not its member and entity does
    not identify a device: the label alone is shared (R11-01)."""
    if not isinstance(credential, dict) or credential.get("kind") != kind:
        return None
    vals = tuple(credential.get(f) for f in PRINCIPAL_FIELDS[kind])
    if not all(isinstance(v, str) and v.strip() for v in vals):
        return None
    return vals


_FAN_OUT = {}          # (issuing_rdp_id, message_id) -> the roster AT ACCEPTANCE (R10-04)


def group_roster(mls_group_id, at=None):
    """The devices the DS observed joining this group, as data a fan-out can
    iterate and a test can assert against.

    R11-07 — DERIVED FROM THE INVITATIONS, each owning its own claim. This was
    a set of devices: every deposit added the device, and any refusal
    discarded it. So a device invited twice into one group — which burn-and-
    re-reserve (R10-X2) produces as a matter of course — was removed by the
    refusal of an OLDER invitation after it had acknowledged the NEWER one,
    and received nothing again. A device is now routed while at least one
    LIVE invitation places it in the group: one it acknowledged (joined), or
    one still open and, at the DS clock `at`, not yet expired (R11-06). A
    refusal or an expiry withdraws only its own invitation's claim."""
    from lint_cli import instant
    # R12-X3: the group's FOUNDER — the device that created it, which MLS
    # never adds through a Welcome — is routed for the group's life.
    out = {_FOUNDERS[mls_group_id]} if mls_group_id in _FOUNDERS else set()
    for e in _INVITATIONS.values():
        if e["invitation"]["mls_group_id"] != mls_group_id:
            continue
        if e["state"] == "joined" or (
                e["state"] == "open" and (
                    at is None or instant(at) <= instant(e["invitation"]["expires_at"]))):
            out.add(e["invited"])
    return sorted(out)


_DELIVERY_ITEMS = {}   # (issuing_rdp_id, message_id, uid, mid, device_id) -> the item

# R8-02 requirement 6 — the state machine is MONOTONIC. A transition may only
# move forward, so an acknowledged item can never silently become queued again.
_DELIVERY_STATES = ("queued", "transferred", "acknowledged")


class DeliveryStateError(Exception):
    """An acknowledgement that does not correspond to an observed transfer."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _require_session(session_binding):
    """R8-02 requirement 5: a WELL-FORMED authenticated session, checked before
    any state moves.

    `transfer_delivery(session_binding=None)` used to succeed, and the null
    then passed the acknowledgement comparison (`None != None` is false) and
    the resolution guard (`if session_binding is not None`). The DS signed a
    receipt carrying `session_binding: null` — invalid under its own published
    `DeliveryReceipt`, which requires an object with `kind` and `digest` — and
    marked the item acknowledged. Three consecutive checks, all fail-open on
    the same absent value.
    """
    if not isinstance(session_binding, dict):
        raise DeliveryStateError(
            "delivery-session-invalid",
            "the transfer carries no authenticated session object; a receipt "
            "attests a handover IN a session, and 'no session' cannot be "
            "signed as one (R8-02)")
    missing = [f for f in ("kind", "digest")
               if not isinstance(session_binding.get(f), str)
               or not session_binding[f].strip()]
    if missing:
        raise DeliveryStateError(
            "delivery-session-invalid",
            f"the session binding omits {missing}; the published "
            "`DeliveryReceipt` requires an object with `kind` and `digest`, so "
            "a partial one would be signed into an invalid receipt (R8-02)")
    return session_binding


def _collection_token(issuing_rdp_id, message_id, principal, session_binding):
    """R8-X1: the idempotent handle returned with the octets.

    Derived from the transfer's own identity rather than minted at random, so a
    retry after a lost response yields the SAME token by construction — there
    is no stored counter to diverge, and a duplicate delivery event cannot be
    created by asking twice.
    """
    material = "|".join([issuing_rdp_id, message_id, *principal,
                         session_binding["kind"], session_binding["digest"]])
    return "dt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def queue_delivery(issuing_rdp_id, message_id, *, recipient_uid, mid,
                   device_id):
    """Stage an ACCEPTED message for one exact recipient device.

    R8-02 requirements 1 and 2 — THE BYTE BINDING IS CARRIED BY REFERENCE.
    This used to take `octets` and hash them into a new `message_digest`,
    without ever comparing them with the acceptance record's `envelope_hash`.
    `receipt_ack()` then compared the acknowledged bytes against that
    replacement faithfully, so the DS signed a rigorous statement about the
    wrong binding: accept bytes A, queue bytes B, and the receipt attested
    `sha256(B)`.

    The parameter is GONE rather than validated. A queue request that cannot
    express a different binding cannot install one, and there is no second
    comparison to keep in step with the first.

    R8-02 requirement 3 — the item is IMMUTABLE. An identical request returns
    the existing item unchanged, whatever state it has reached; a conflicting
    one is refused.
    """
    from lint_cli import require_rdp_id
    require_rdp_id(issuing_rdp_id, context="the issuing RDP")
    accepted = _DS_LEDGER.get((issuing_rdp_id, message_id))
    if accepted is None:
        raise DeliveryStateError(
            "delivery-item-unknown",
            f"{(issuing_rdp_id, message_id)!r} was never accepted at the "
            "Delivery Service, so there is nothing to queue — a receipt for it "
            "would attest a transfer of octets the DS never received (R7-02)")
    # R11-01 — THE KEY IS THE WHOLE PRINCIPAL. It was (issuing RDP, message,
    # device_id), so two devices sharing a label — across entities, or across
    # members of one entity — were one row, and the second fan-out target hit
    # the immutability check as `delivery-recipient-conflict` on every
    # attempt. With the entity and member in the key, an item's recipient
    # cannot change because it is part of what the item IS; the per-field
    # comparison that used to stand here is deleted (standing rule 3).
    #
    # R10-X3 — EACH ITEM IS BOUND TO ITS OWN MEMBER. This pinned every sibling
    # to the FIRST item's (recipient, member), on the premise that "an
    # accepted message has one recipient entity and one member". The bilateral
    # group holds members of BOTH entities, so an ordinary two-member recipient
    # made the first submission fail `delivery-recipient-conflict` halfway
    # through fan-out, the identical retry succeed, and one member lose the
    # message for good — which member, decided by the lexical order of MIDs
    # (R10-04). The pin defended against a second recipient "taking its own
    # row"; the public surface cannot express that at all, because items come
    # only from the roster the DS observed (`_fan_out`), never from a request
    # naming a recipient. What must hold is IMMUTABILITY: an existing item
    # never changes recipient or member. That is checked per item, below.
    key = (issuing_rdp_id, message_id, recipient_uid, mid, device_id)
    prior = _DELIVERY_ITEMS.get(key)
    if prior is not None:
        # Idempotent, and the state is PRESERVED (R8-02 requirement 6): an
        # identical re-queue never walks an acknowledged item back to queued.
        return dict(prior)
    _DELIVERY_ITEMS[key] = {
        "state": "queued", "recipient_uid": recipient_uid, "mid": mid,
        "device_id": device_id, "issuing_rdp_id": issuing_rdp_id,
        "message_id": message_id,
        # BY REFERENCE from the acceptance record (R8-02 requirement 1).
        "message_digest": copy.deepcopy(accepted["envelope_hash"]),
        "session_binding": None, "collection_token": None,
    }
    return dict(_DELIVERY_ITEMS[key])


def transfer_delivery(issuing_rdp_id, message_id, *, principal,
                      session_binding):
    """The DS hands the octets to the device in an authenticated session.

    This is the observation a receipt attests. It is recorded HERE, by the
    server, from the authenticated session — not asserted later by whoever
    calls the acknowledgement.

    R8-X1: returns an idempotent collection token. A lost response retried in
    the same session converges on the same token and the same delivery event.

    R9-X2 — RECLAIM SUPERSEDES CONFLICT. `delivery-session-conflict` is DELETED,
    not softened. It refused a re-transfer in a different authenticated
    session on the reasoning that an observed handover must not be moved; the
    effect was that losing a session stranded the item for ever, because
    nothing could ever bind it to a new one. Measured, the ordinary mobile
    lifecycle reached it — collect, do not acknowledge, a second message
    arrives, reconnect — and in one arrival order it left the device's whole
    queue collectable by nobody, including the sessions that owned the items.

    The same DEVICE may therefore re-collect any unacknowledged item of its own
    in any authenticated session. The binding moves to the new session and the
    token is reissued, because the token names a transfer and this is a new
    one. What the earlier rule was protecting is protected elsewhere and
    better: `_ACK_LEDGER` is keyed by recipient, so there is still exactly ONE
    signed delivery event, and it attests the session it was acknowledged in
    rather than an earlier one nobody used. An ACKNOWLEDGED item is never
    re-transferred — that is monotonic (R8-02 requirement 6) and unchanged.
    """
    _require_session(session_binding)
    key = (issuing_rdp_id, message_id, *principal)
    item = _DELIVERY_ITEMS.get(key)
    if item is None:
        raise DeliveryStateError(
            "delivery-item-unknown",
            f"no queued delivery item for {key!r} — a sibling device must not "
            "take another's delivery (R7-02/R8-X2)")
    if item["state"] == "acknowledged":
        return dict(item)             # terminal: the event already exists
    if item["state"] == "transferred" and item["session_binding"] == session_binding:
        return dict(item)             # idempotent: the same delivery event
    item["state"] = "transferred"
    item["session_binding"] = copy.deepcopy(session_binding)
    item["collection_token"] = _collection_token(
        issuing_rdp_id, message_id, principal, session_binding)
    return dict(item)


def collect_messages(*, credential, session_binding):
    """R8-03 — THE PUBLIC TRANSFER BOUNDARY (`GET /messages`).

    The finding: `queue_delivery()` and `transfer_delivery()` were private
    helpers, and `delivery-service-openapi.yaml` published no operation through
    which a device obtains a queued application message or the DS records the
    authenticated transfer. The `transferred` state the signed receipt depends
    on was therefore not reproducible from the contract — a test could drive
    the Python helper, but a client generated from the published API could not
    reach the flow at all, and two conforming services could disagree about
    whether a message had been delivered.

    The device identity is SERVER-DERIVED from the credential (R8-03
    requirement 2). There is no `device_id` parameter, because a parameter that
    can name a device is a parameter that can name the wrong one — the same
    reason `GET /welcome` takes none.

    Returning the octets IS the transition (R8-X1): each item is `transferred`
    when this returns, and carries the idempotent collection token. Calling
    again in the same session returns the same items with the same tokens.
    """
    principal = principal_of(credential, "device")
    if principal is None:
        raise DeliveryStateError(
            "device-auth-required",
            "collecting a queued message takes possession of bytes addressed "
            "to ONE enrolled device, identified by its entity, member and "
            "label; an entity- or member-level credential covers many, and a "
            "bare device label names a device of every member that uses it "
            "(R8-03/R11-01)")
    _require_session(session_binding)
    if credential.get("session") != session_binding["digest"]:
        raise DeliveryStateError(
            "delivery-session-invalid",
            "the credential is not bound to the session the transfer would be "
            "recorded in (R8-03)")

    # R9-02 requirements 1 and 2 — SELECT, PREFLIGHT, THEN TRANSITION.
    #
    # This loop used to call the mutating `transfer_delivery()` one item at a
    # time. An early item committed, a later one raised, and the caller got an
    # error and no bytes — a failed READ with durable, invisible WRITE effects.
    # Selection is now separated from mutation: every selected item is checked
    # first, and if any cannot transition the call raises having written
    # NOTHING.
    selected = []
    for key in sorted(_DELIVERY_ITEMS):
        rdp, mid_, owner = key[0], key[1], key[2:]
        if owner != principal:
            continue              # never another device's, never distinguishable
        item = _DELIVERY_ITEMS[key]
        if item["state"] == "acknowledged":
            continue              # terminal; the event exists
        selected.append((rdp, mid_))

    for rdp, mid_ in selected:     # preflight: no write happens in this pass
        if (rdp, mid_) not in _DS_LEDGER or (rdp, mid_) not in _DS_OCTETS:
            raise DeliveryStateError(
                "delivery-item-unknown",
                f"item {(rdp, mid_, *principal)!r} has no accepted octets to "
                "hand over; the whole collection is refused rather than "
                "returning a subset the caller cannot tell is partial (R9-02)")

    out = []
    for rdp, mid_ in selected:
        transferred = transfer_delivery(rdp, mid_, principal=principal,
                                        session_binding=session_binding)
        accepted = _DS_LEDGER[(rdp, mid_)]
        out.append({
            "issuing_rdp_id": rdp, "message_id": mid_,
            "mls_group_id": accepted["mls_group_id"],
            "mls_message_b64": _DS_OCTETS[(rdp, mid_)],
            "message_digest": copy.deepcopy(transferred["message_digest"]),
            "collection_token": transferred["collection_token"],
            "state": transferred["state"],
        })
    return {"items": out}


def resolve_transferred(issuing_rdp_id, message_id, *, principal,
                        session_binding):
    """The item a receipt may attest, or a typed refusal. Nothing is signed
    until this returns."""
    _require_session(session_binding)
    key = (issuing_rdp_id, message_id, *principal)
    item = _DELIVERY_ITEMS.get(key)
    if item is None:
        raise DeliveryStateError(
            "delivery-item-unknown",
            f"no delivery item for {key!r}: the DS never accepted, queued or "
            "transferred this message to this device, so there is no transfer "
            "to attest (R7-02)")
    if item["state"] == "queued":
        raise DeliveryStateError(
            "delivery-not-transferred",
            f"item {key!r} is queued and has not been handed to a device — a "
            "receipt would attest a transfer that has not happened (R7-02)")
    # R8-02: UNCONDITIONAL. This used to be guarded by
    # `if session_binding is not None`, so the one caller that supplied nothing
    # skipped the comparison entirely — absence read as agreement.
    if item["session_binding"] != session_binding:
        raise DeliveryStateError(
            "delivery-wrong-session",
            f"item {key!r} was transferred in a different authenticated "
            "session than the one acknowledging it (R7-02)")
    return item


def receipt_ack(message_id, device_id, *, credential,
                session_binding, octets, server_clock, client_acked_at=None,
                ds_kid="ds-demo-2026", issuing_rdp_id="urn:sbm:rdp:demo-out",
                collection_token=_REQUIRED):
    """DR-10 — the Delivery Service's acknowledged handover (DS contract 1.2.0).

    The DS OBSERVES the event instant. `client_acked_at` is retained as
    non-authoritative diagnostic metadata and never determines `server_time`:
    before this gate the contract took a client `acked_at` and defined
    `delivered_at = acked_at`, so a device — or a compromised entity session —
    could acknowledge after expiry while backdating into the valid window,
    defeating the X-21 deadline and the authenticated-S2 proof resting on it.

    `credential` must be DEVICE-bound (`{"kind": "device", "uid": …, "mid": …,
    "device_id": …, "session": …}`). An entity- or member-level credential
    satisfies the DS's generic scheme but NOT this operation: the S2 event
    asserts that a particular DEVICE received the bytes.

    R11-01 — WHO RECEIVED IS THE AUTHENTICATED PRINCIPAL. This took
    `recipient_uid` and `mid` as arguments the published `ReceiptAckRequest`
    does not carry, compared them with the item and signed the item's values;
    the credential was checked only for its `device_id`. So a FR device
    labelled `DEV-1` collected a DE device's message and acknowledged it, and
    the DS signed a receipt attributing delivery to DE. The arguments are
    DELETED (invariant 7): the entity and member come from the credential, the
    item is looked up by the whole principal, and the receipt names exactly
    the principal that was authenticated.

    `server_clock` is injected rather than read from the wall clock so the
    demo stays deterministic and a test can drive the instant; in a deployment
    it is the DS's own trusted clock.

    R6-03 points 1 and 6 — THE NAMESPACE, which the submission layer already
    promised. `/messages` and the DS ledger key on `(issuing RDP, message_id)`
    (R4-U3), and it disappeared downstream: the ack path exposed a bare
    `message_id`, the receipt carried no `issuing_rdp_id`, and the ack ledger
    was keyed by `(message_id, recipient_uid)`. Two providers using the same
    per-provider identifier collided in the receipt layer AFTER the submission
    layer had explicitly guaranteed they would not — the second ack returned
    the first provider's byte-identical receipt even when the ciphertext
    differed, which is denial of delivery evidence, or cross-provider receipt
    reuse where the bytes match. The identity is SIGNED, so it cannot be
    re-labelled after the fact.

    Returns the signed receipt. The FIRST ack per (issuing RDP, message_id,
    recipient entity) is THE event: duplicates return that same receipt,
    including its `server_time`.
    """
    principal = principal_of(credential, "device")
    if principal is None:
        raise AckRejected(
            "device-auth-required",
            "the acknowledged handover requires DEVICE-bound authentication "
            "naming the device's entity and member; a "
            f"{(credential or {}).get('kind')!r} credential, or a bare device "
            "label, cannot create a device handover (DR-10/R11-01)")
    if principal[2] != device_id:
        raise AckRejected(
            "device-auth-required",
            "the credential is bound to a different device than the one "
            "claiming to have received the bytes (DR-10)")
    # R8-02: the session must EXIST and be well-formed before it is compared.
    # `credential.get("session") != (session_binding or {}).get("digest")` was
    # `None != None` for a null session — the comparison passed because both
    # sides were absent, which is agreement about nothing.
    try:
        _require_session(session_binding)
    except DeliveryStateError as e:
        raise AckRejected(e.reason, e.detail)
    if credential.get("session") != session_binding.get("digest"):
        raise AckRejected(
            "session-replay",
            "the acknowledgement was presented outside the session it was "
            "issued in — the ack is session-bound (F-09/DR-10)")

    # R9-01 requirement 1: the token is REQUIRED, and absence is rejected here —
    # before the item is looked up and long before anything is mutated. The
    # sentinel default exists so that a caller which simply omits the argument
    # fails the same way as one that sends null, rather than being silently
    # served by a different code path.
    # R9-01 requirement 1: ABSENCE first, and with its own reason. "You did not
    # send it" and "what you sent is not a token" are different answers and a
    # client acts on them differently.
    if collection_token is _REQUIRED or collection_token is None:
        raise AckRejected(
            "collection-token-required",
            "the acknowledgement carries no `collection_token`. The published "
            "request declares it REQUIRED: it is the capability the transfer "
            "issued, and it is the only evidence that this acknowledgement "
            "resolves that exact handover rather than any message the caller "
            "can name (R9-01)")

    # R9-01 requirement 5: the reference validates its OWN call against the
    # published request Schema, so the two cannot describe different protocols
    # again. This is exactly what a generated client would put on the wire.
    problems = validate_contract_object(
        "delivery-service-openapi.yaml", "ReceiptAckRequest",
        {"device_id": device_id, "collection_token": collection_token,
         **({} if client_acked_at is None
            else {"client_acked_at": client_acked_at})})
    if problems:
        raise AckRejected(
            "acknowledgement-malformed",
            f"the acknowledgement does not satisfy the published "
            f"`ReceiptAckRequest`: {problems[:2]} (R9-01)")

    # R7-02 requirements 2 and 3: RESOLVE the server-owned item, and take the
    # attested facts FROM IT. Nothing here is signed on the caller's say-so.
    # `receipt_ack` used to sign its own arguments, so a receipt existed for a
    # message the DS had never accepted, under an `issuing_rdp_id` the caller
    # picked. The resolution happens BEFORE any signing: a signature over a
    # refusal is still a signature somebody can present.
    try:
        item = resolve_transferred(issuing_rdp_id, message_id,
                                   principal=principal,
                                   session_binding=session_binding)
    except DeliveryStateError as e:
        raise AckRejected(e.reason, e.detail)

    # R8-03 requirement 6: the acknowledgement REFERENCES the transfer handle
    # produced by the public boundary. Without it a device names a message and
    # the DS infers which transfer was meant; with it the device names THE
    # transfer, so an acknowledgement cannot be built by a caller that never
    # collected anything.
    #
    # R9-01: the comparison is UNCONDITIONAL. It was guarded by
    # `if collection_token is not None`, so omitting the argument skipped it
    # entirely — `None` as a hidden compatibility path around a value the
    # published request declares REQUIRED. Every other shape was already
    # refused (empty string, wrong value); only absence failed open, which
    # preserved compatibility with precisely the pre-token flow the token was
    # introduced to retire. Absence is now rejected ABOVE, before the item is
    # resolved or anything is mutated.
    #
    # `compare_digest` because the token is a bearer capability: presenting it
    # is the whole proof, so how long a wrong guess takes must not describe how
    # nearly right it was.
    if not hmac.compare_digest(str(collection_token),
                               str(item["collection_token"])):
        raise AckRejected(
            "delivery-token-mismatch",
            "the acknowledgement quotes a collection token that is not this "
            "transfer's — a receipt may only attest the handover the device "
            "actually collected (R8-03)")
    # R8-02: `stored_digest` is the ACCEPTANCE record's `envelope_hash`,
    # carried by reference through the delivery item. The comparison below was
    # always rigorous; what it compared against used to be a replacement the
    # queue computed from its own caller's bytes.
    stored_digest = item["message_digest"]
    caller_digest = {"format": "mls10-message",
                     "hex": hashlib.sha256(octets).hexdigest()}
    if stored_digest != caller_digest:
        raise AckRejected(
            "delivery-digest-mismatch",
            "the octets acknowledged are not the octets the DS accepted — the "
            "receipt would attest a handover of different bytes (R7-02/R8-02)")
    # Everything the receipt asserts now comes from the STORED item.
    recipient_uid = item["recipient_uid"]
    mid = item["mid"]
    session_binding = item["session_binding"]

    key = (issuing_rdp_id, message_id, recipient_uid)
    first = _ACK_LEDGER.get(key)
    if first is not None:
        # R10-09: the FIRST acknowledgement is the one recipient-level legal
        # event, and it is returned unchanged — but THIS device has just
        # acknowledged its own copy, with every check above passed, and its
        # transport item must terminate too. This returned before marking it,
        # so after two devices both acknowledged, the second still held a
        # `transferred` item it would collect for ever.
        item["state"] = "acknowledged"
        return first

    receipt = {
        "message_id": message_id,
        # R6-03: SIGNED, so the namespace cannot be re-labelled afterwards.
        "issuing_rdp_id": issuing_rdp_id,
        "recipient_uid": recipient_uid,
        "mid": mid,
        "device_id": device_id,
        "session_binding": session_binding,
        # THE authoritative instant — observed here, not supplied.
        "server_time": server_clock,
        # R7-02: the digest the DS RECORDED at transfer, not one recomputed
        # from whatever the acknowledging caller supplied.
        "message_digest": stored_digest,
    }
    if client_acked_at is not None:
        receipt["client_acked_at"] = client_acked_at      # diagnostics only
    # R3-04: the receipt NAMES its verifying key. Without a kid, "verify
    # against the DS's published key" had no referent at all.
    receipt["ds_kid"] = ds_kid
    receipt["ds_alg"] = "EdDSA"
    # R8-02 requirement 5 — VALIDATED AGAINST ITS PUBLISHED SCHEMA BEFORE IT IS
    # SIGNED. Nothing checked the generated receipt at all, so a null session
    # was signed into an object invalid on the wire and the item was marked
    # acknowledged. A signature cannot be withdrawn once issued, so the check
    # belongs before `seal_cose`, not after it. Validated WITHOUT the signature
    # field, because that is the object the signature is taken over.
    problems = validate_delivery_receipt(receipt, unsigned=True)
    if problems:
        raise AckRejected(
            "receipt-schema-invalid",
            f"the receipt this acknowledgement would sign does not satisfy the "
            f"published `DeliveryReceipt`: {problems[:3]} — nothing is signed "
            "and the item is not acknowledged (R8-02)")
    receipt["ds_signature"] = base64.b64encode(
        seal_cose({k: v for k, v in receipt.items()}, kid=ds_kid, seed="ds")
    ).decode()
    # ...and the COMPLETE object, before it becomes the ledger's answer to
    # every future acknowledgement of this event.
    problems = validate_delivery_receipt(receipt, unsigned=False)
    if problems:
        raise AckRejected(
            "receipt-schema-invalid",
            f"the signed receipt does not satisfy the published "
            f"`DeliveryReceipt`: {problems[:3]} — it is not stored and the "
            "item is not acknowledged (R8-02)")
    item["state"] = "acknowledged"
    _ACK_LEDGER[key] = receipt
    return receipt


# --- R3-07: the cross-service transaction -----------------------------------
#
# DR-02 fixed WHAT RDP(out) attests; it did not say WHEN. `POST /submissions`
# and `POST /messages` were independent operations with no ordering, no durable
# state, no recovery and no response proof — so an implementation could seal SE
# before the DS accepted anything, deliver bytes with no recoverable SE, or let
# the two ledgers bind one message_id to different octets.
#
# The observable invariant, which these functions exist to make testable:
# ONE message_id, ONE byte binding, AT MOST ONE SE, AT MOST ONE DELIVERY.

_DS_LEDGER = {}          # message_id -> acceptance record (the DS's own)
# R8-03: the DS retains the accepted OCTETS so it can hand them to the device
# at `GET /messages`. They are held beside the acceptance record rather than
# inside it, because `AcceptanceRecord` is a published object with
# `unevaluatedProperties: false` and adding a field to it here would be a
# second, unpublished shape travelling under a contracted name.
_DS_OCTETS = {}          # (issuing_rdp_id, message_id) -> mls_message_b64
_SE_LEDGER = {}          # message_id -> the sealed SE (RDP(out)'s own)


class TransportRejected(Exception):
    """R3-07: the DS refused the octets under this message_id."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# R12-X2 — WHO MAY FORWARD. The RDPs this Delivery Service accepts forwarded
# submissions from: the recipient-side RDP(s) it serves. Configuration, like the
# trust store; empty means no forwarding is accepted (fail closed).
DS_FORWARDERS = set()
DS_TRUST_STORE = pathlib.Path(__file__).resolve().parents[1] / "samples" / \
    "trust-store.demo.json"


def _proven_origin(origin, message_id, mls_group_id, digest):
    """R12-X2 — the originating namespace a forwarded submission claims, PROVEN
    by the origin's own sealed SE: the seal verifies against the origin's
    published evidence key, and the SE names this origin, this `message_id`,
    this group and the digest of these octets. Returns the origin, or raises."""
    import importlib.util as _ilu
    from lint_cli import load_trust_store, reconstruct
    art = (origin or {}).get("se")
    claim = (origin or {}).get("origin_rdp_id")
    spec = _ilu.spec_from_file_location(
        "_evlint_fwd", pathlib.Path(__file__).resolve().parent / "evidence_lint.py")
    ev = _ilu.module_from_spec(spec); spec.loader.exec_module(ev)
    try:
        found = ev.lint(art, verify_demo=True,
                        trust_store=load_trust_store(str(DS_TRUST_STORE)))
        se = reconstruct(art)
    except Exception as e:                      # an unreadable proof proves nothing
        raise TransportRejected("origin-unproven",
                                f"the forwarded SE cannot be evaluated: {e} (R12-X2)")
    if found:
        raise TransportRejected(
            "origin-unproven",
            f"the forwarded SE does not verify as the origin's sealed evidence: "
            f"{sorted({r for r, _ in found})} (R12-X2)")
    wrong = [f for f, want in (("type", "SE-v1"), ("rdp_id", claim),
                               ("message_id", message_id),
                               ("mls_group_id", mls_group_id),
                               ("envelope_hash", digest)) if se.get(f) != want]
    if wrong:
        raise TransportRejected(
            "origin-unproven",
            f"the forwarded SE does not bind this submission: {wrong} differ — "
            "an origin claim is proven only by the origin's SE for THESE octets "
            "under THIS message_id (R12-X2)")
    return claim


def ds_accept_message(message_id, mls_group_id, mls_message_b64,
                      accepted_at="2026-04-04T10:15:01Z", *, principal=None,
                      origin=None):
    """Step 2: the DS accepts the octets and says so, in terms that bind.

    IDEMPOTENT by (ISSUING RDP, message_id), and the digest is computed HERE —
    a DS that echoed the submitter's digest would confirm the submitter's claim
    rather than its own receipt, which is DR-02's defect one layer down.

    R4-05/R4-U3 — THE NAMESPACE. The I-D and TS define the global handle as
    `(issuing-RDP identity, message_id)`, and this keyed idempotency by BARE
    message_id: two providers submitting the same ULID collided, and one
    provider could see or displace another's binding. The issuing identity is
    DERIVED FROM THE AUTHENTICATED PRINCIPAL, not carried in the request — a
    client-supplied field would have to be checked against the principal
    anyway, so it would add a spoofing surface without adding information.

    `principal` is what the deployment's authentication established (mTLS
    subject, token subject). It is REQUIRED: an unauthenticated submission has
    no namespace to be idempotent within.

    R12-03 / R12-X2 — FORWARDING. In the four-corner case the recipient-side
    RDP hands the relayed octets to ITS Delivery Service under its own
    credential, and the namespace was derived from that credential alone: the
    acceptance named RDP(in) as the issuer, items and receipts carried the
    wrong handle, and two origins reusing a local `message_id` collided at the
    common DS (`duplicate-message-id`). A forwarded submission now states its
    `origin` — the originating provider and that provider's sealed SE — and
    the DS keys on the ORIGIN namespace once the SE proves it
    (`_proven_origin`), recording the forwarder beside it. The submitter must
    be a forwarder this DS serves (`DS_FORWARDERS`). An origin string without
    its proof is refused: that would trade the collision for spoofing.
    """
    # R7-04 requirement 4: a non-canonical principal is refused here, before
    # any ledger key is formed from it. `ds_accept_message(principal=
    # "not-a-canonical-rdp")` used to be accepted and STORED as the key.
    from lint_cli import require_rdp_id, RdpIdentityError
    if principal:
        try:
            require_rdp_id(principal, context="the authenticated issuing RDP")
        except RdpIdentityError as e:
            raise TransportRejected(e.reason, e.detail)
    if not principal:
        raise TransportRejected(
            "unauthenticated",
            "the Delivery Service derives the idempotency namespace from the "
            "authenticated issuing RDP, so an unauthenticated submission has "
            "no namespace to be idempotent within (R4-05/R4-U3)")
    # R12-X2: the published request, executed — the body was an inline Schema
    # nothing validated against, which is how an origin could never be stated.
    request = {"message_id": message_id, "mls_group_id": mls_group_id,
               "mls_message_b64": mls_message_b64,
               **({} if origin is None else {"origin": origin})}
    problems = validate_contract_object("delivery-service-openapi.yaml",
                                        "MessageSubmission", request)
    if problems:
        raise TransportRejected(
            "submission-malformed",
            f"the submission does not satisfy the published `MessageSubmission`: "
            f"{problems[:2]}")
    octets = base64.b64decode(mls_message_b64, validate=True)
    digest = {"format": "mls10-message", "hex": hashlib.sha256(octets).hexdigest()}
    forwarder = None
    if origin is not None:
        if principal not in DS_FORWARDERS:
            raise TransportRejected(
                "forwarder-not-authorised",
                f"{principal!r} is not an RDP this Delivery Service accepts "
                "forwarded submissions from (R12-X2)")
        forwarder, principal = principal, _proven_origin(
            origin, message_id, mls_group_id, digest)
    key = (principal, message_id)
    prior = _DS_LEDGER.get(key)
    if prior is not None:
        if prior["envelope_hash"] != digest:
            raise TransportRejected(
                "duplicate-message-id",
                f"message_id {message_id!r} is already bound at the Delivery "
                f"Service, for issuing RDP {principal!r}, to different octets — "
                "the two ledgers must not diverge (R3-07)")
        if prior["mls_group_id"] != mls_group_id:
            raise TransportRejected(
                "duplicate-message-id",
                f"message_id {message_id!r} is already bound to group "
                f"{prior['mls_group_id']!r}; a retry naming another group is a "
                "different submission, not the same one again")
        # R10-04: RESUME before replying. This returned the stored record
        # without completing the fan-out, so a first attempt that failed after
        # storing its acceptance left the retry "accepted" and some devices
        # with no item, for ever. Resumption reads the SNAPSHOT taken at
        # acceptance, so a device that joined in between still does not
        # retroactively receive the message (R9-X3), and it is idempotent per
        # device, so nothing is created twice.
        _fan_out(principal, message_id,
                 _FAN_OUT.setdefault(key, group_roster(prior["mls_group_id"],
                                                       at=prior["accepted_at"])))
        return dict(prior)                      # the SAME record, replayable
    record = {"message_id": message_id, "issuing_rdp_id": principal,
              "mls_group_id": mls_group_id,
              "envelope_hash": digest, "accepted_at": accepted_at,
              **({} if forwarder is None else {"forwarding_rdp_id": forwarder})}
    # R8-05 requirement 4: the server-DERIVED record is validated against its
    # own published contract before it is stored or returned. `issuing_rdp_id`
    # was an unconstrained string here, so the one field that decides the
    # idempotency namespace had no value space at the boundary that mints it.
    problems = validate_contract_object("delivery-service-openapi.yaml",
                                        "AcceptanceRecord", record)
    if problems:
        raise TransportRejected(
            "acceptance-record-invalid",
            f"the acceptance record this submission would return does not "
            f"satisfy the published `AcceptanceRecord`: {problems[:3]} — "
            "nothing is stored (R8-05)")
    # R9-X3 / R10-04: the recipient set is fixed HERE, once, from what the DS
    # observed — and stored, so that a retry resumes the same set rather than
    # reading a roster that has moved since.
    _FAN_OUT[key] = group_roster(mls_group_id, at=accepted_at)
    _DS_LEDGER[key] = record
    _DS_OCTETS[key] = mls_message_b64          # R8-03: handed to the device
    _fan_out(principal, message_id, _FAN_OUT[key])
    return dict(record)


def _fan_out(issuing_rdp_id, message_id, targets):
    """R9-X3 / R10-X3 — one delivery item per device the DS observed joining
    the group, at acceptance: `targets` is that snapshot, `(recipient_uid,
    mid, device_id)` triples of BOTH entities, each item bound to its own
    member. Sender-side copies are transport items: the DS cannot tell them
    apart and does not try — the RDP issuing a DE binds the receipt to the
    SE's addressee (`delivered_at_from_receipt`'s expected context), so a
    receipt for another entity's device never becomes delivery evidence.

    IDEMPOTENT per `(issuing_rdp_id, message_id, uid, mid, device_id)` — the
    device's whole principal (R11-01) — so a resumed fan-out creates nothing
    twice. A device that joins after acceptance does
    not receive an already-accepted message; one that refuses afterwards keeps
    the item it was owed."""
    for uid, mid_, device_id in targets:
        queue_delivery(issuing_rdp_id, message_id, recipient_uid=uid,
                       mid=mid_, device_id=device_id)


def _se_candidate(meta, accepted, principal):
    """The COMPLETE SE this submission would seal.

    R8-01 requirement 3: built as one object so it can be validated before the
    remote side effect and again before sealing, rather than being assembled
    inline at the only point where refusing it is already too late.
    """
    body = {
        "type": "SE-v1",
        "version": EVIDENCE_VERSION,
        "profile": "pilot",
        "message_id": meta["message_id"],
        "event": "A.1-SubmissionAcceptance",
        "evidence_id": _evidence_id(),
        "policy_id": POLICY_ID,
        "rdp_id": principal,
        "transport": "SM-MLS-1.0",
    }
    # Everything the wallet supplied, verbatim — the SE records the
    # submission, it does not reinterpret it.
    for field in ("sender_uid", "sender_addr", "recipient_uid",
                  "recipient_addr", "scope_ref", "payload_hash",
                  "mls_group_id", "mls_epoch", "auth_method",
                  "auth_context", "sent_at", "expires_at", "origin_proof",
                  "acceptance_policy_ref", "grade_commitment",
                  "mandate_ref", "manifest"):
        if meta.get(field) is not None:
            body[field] = meta[field]
    # ...and the commitments RDP(out) COMPUTED (DR-02), never copied.
    body["envelope_hash"] = accepted["envelope_hash"]
    body["mls_state"] = accepted["mls_state"]
    if meta.get("sender_confirmation") is not None:
        body["sender_confirmation"] = meta["sender_confirmation"]
    # R4-05 point 6: `ds_accepted_at` is NOT added to the SE. It was an
    # UNDECLARED field on a purported evidence object — standardising it would
    # need a version bump and a defined meaning, and it has neither. The
    # acceptance instant stays in the DS record, where it belongs.
    return body


def submit(meta, *, fail_at=None, retained_group_context=None,
           principal="urn:sbm:rdp:demo-out", org=None, members=None,
           server_clock=None):
    """R3-07: the WHOLE transaction, in the normative order.

    reserve -> DS acceptance -> seal. `fail_at` injects an interruption at one
    of the three points the review names, so recovery is exercised rather than
    described:

      "before-acceptance"  the DS never saw the bytes
      "after-acceptance"   accepted, but the seal did not happen
      "after-sealing"      sealed, but the client never got the response

    Returns the SEALED SE ARTEFACT — `{sm_artifact_b64, projection}`.

    R4-05: it used to return the submission metadata plus a few computed
    fields, stored in a dict and CALLED a "sealed SE". It carried no
    `type: SE-v1`, so `validate_body()` treated it as an unknown type and
    skipped Schema validation entirely; there was no COSE seal and no
    evidence_id, policy_id, event or transport. The conformance path did not
    construct the object it claimed to produce, and nothing noticed because the
    tests drove this helper rather than the published surfaces.

    `principal` is the AUTHENTICATED issuing RDP (R4-U3): the DS namespace is
    derived from it, so two providers using the same message_id do not collide.

    `org` and `members` are the recipient's published discovery documents
    (R5-01). Intake recomputes the acceptance policy against them and refuses a
    disagreeing submission before anything is sealed.
    """
    # Step 1 — validate and DURABLY RESERVE the (message_id, digest) binding.
    # R5-01: the discovery material the contract's obligations need. A real
    # RDP always holds the recipient's published documents; passing them is
    # what makes the recompute-and-refuse rule performable rather than merely
    # written down.
    accepted = accept_submission(meta, retained_group_context,
                                 principal=principal, org=org, members=members,
                                 server_clock=server_clock)
    mid = meta["message_id"]

    # R8-01 requirement 3 / R8-X4 — the COMPLETE candidate SE, constructed and
    # validated BEFORE the DS is contacted.
    #
    # The finding: the output gate ran after `accept_submission()` had written
    # `_SUBMISSION_LEDGER` and `ds_accept_message()` had written `_DS_LEDGER`,
    # while its own error text said "nothing is sealed and no ledger moves". A
    # malformed value therefore produced a durable reservation AND a real
    # remote acceptance record for a message no evidence could ever be sealed
    # for. Nothing in the SE waits on the DS — every field is request-derived
    # or RDP(out)-computed — so the candidate can be built here, and a
    # candidate that cannot be sealed is refused before the side effect rather
    # than after it. That is what makes the atomicity claim true instead of
    # merely reworded.
    prior = _SE_LEDGER.get((principal, mid))
    body = None
    if prior is None:
        body = _se_candidate(meta, accepted, principal)
        problems = validate_body(body) or []
        if problems:
            raise SubmissionRejected(
                "evidence-schema-invalid",
                f"the SE this submission would seal does not satisfy its own "
                f"Schema: {problems[:3]} — refused BEFORE the Delivery Service "
                "was contacted, so no transport acceptance and no SE exist "
                "(R8-01)")

    if fail_at == "before-acceptance":
        raise TransportRejected("interrupted", "before DS acceptance (test)")

    # Step 2 — the DS accepts the SAME octets and returns a record that binds.
    record = ds_accept_message(mid, meta["mls_group_id"],
                               meta["mls_message_b64"], principal=principal)
    if record["envelope_hash"] != accepted["envelope_hash"]:
        raise TransportRejected(
            "envelope-hash-mismatch",
            "the Delivery Service accepted different octets than RDP(out) "
            "committed to — no SE (R3-07)")

    if fail_at == "after-acceptance":
        raise TransportRejected("interrupted", "after DS acceptance (test)")

    # Step 3 — ONLY NOW may SE be sealed, and only with the confirmed
    # commitment. An SE sealed earlier attests a transport acceptance that had
    # not happened and might never happen.
    if prior is None:
        # R8-01 requirement 3, second half: validate the FINAL object again,
        # immediately before sealing. No DS-derived field is added to the SE
        # (R4-05 point 6 keeps `ds_accepted_at` in the DS record), so this
        # re-validates the exact object about to be sealed rather than a
        # changed one — the point is that nothing is signed unvalidated, not
        # that something was added.
        problems = validate_body(body) or []
        if problems:
            raise SubmissionRejected(
                "evidence-schema-invalid",
                f"the SE about to be sealed does not satisfy its own Schema: "
                f"{problems[:3]} — nothing is sealed (R8-01)")
        prior = evidence_artifact(body)
        _SE_LEDGER[(principal, mid)] = prior

    if fail_at == "after-sealing":
        raise TransportRejected("interrupted", "after sealing (test)")
    return copy.deepcopy(prior)


_WELCOME_QUEUE = {}          # (uid, mid, device_id) -> [queue item]  (R11-01)
_WELCOME_SEQ = [0]


class WelcomeAccessDenied(Exception):
    """R3-06: a Welcome operation that is not the authenticated device's.

    Deliberately ONE exception for "unknown", "already acknowledged" and
    "belongs to another device": distinguishing them would tell a caller
    whether some OTHER device has a Welcome pending, which is a queue-existence
    oracle over another device's state.
    """

    reason = "not-found"


# R8-04 requirement 3 — THE RESERVATION / KEYPACKAGE LEDGER.
#
# `reservation_id` and `keypackage_ref` were REQUIRED at deposit and read
# nowhere, because no reservation state existed in this module at all. The
# contract publishes the whole lifecycle (`POST /keypackages/{uid}/reservations`
# -> `POST /reservations/{id}/commit`), so an invitation naming an uncommitted
# reservation or an invented package reference was retained as though it had
# been checked. A required field nobody reads is a field that says nothing.
_RESERVATIONS = {}     # reservation_id -> {creator, cipher_suite, targets, state}
_ACKED_OUTCOMES = {}   # outcome_id -> the creator (uid, mid) that acknowledged it
_ACKED_WELCOMES = {}   # welcome_id -> the device (uid, mid, device_id) that did (R10-09)

# X-25: the registry owns the vocabulary; this reads it rather than restating it.
GROUP_ESTABLISHMENT_REASONS = frozenset(
    lint_cli_load_registry("reason-codes.json")["group_establishment_reasons"]
) - {"$comment"}


class ReservationError(Exception):
    """A reservation that cannot support the invitation naming it."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# R9-03/R9-X1 — the reservation is a PUBLIC transaction now.
#
# Three things were wrong at once and they compounded. The reference took a
# CLIENT-supplied `reservation_id` while the contract described it as
# server-assigned and exposed `Idempotency-Key`; it returned its own internal
# dictionary, which the published `Reservation` rejects four ways; and neither
# the request nor the response carried `keypackage_ref`, which the very next
# request requires. So a conforming client could not complete the flow and the
# reference could not serve as an oracle for it.
_RESERVATION_SEQ = [0]
_IDEMPOTENCY = {}      # ((uid, mid) creator, Idempotency-Key) -> reservation_id
RESERVATION_TTL_SECONDS = 300      # the contract's RECOMMENDED reservation TTL
DEMO_POOL_PER_SUITE = 8            # what the demo pool holds per suite


def _plus_seconds(iso, seconds):
    """An instant `seconds` later, in the same `Z` form the samples use.

    R9-04's parser (`lint_cli.instant`) already existed and was already
    RFC 3339-correct; the invitation path simply never called it and compared
    strings instead. Arithmetic on instants is done here so the reservation TTL
    cannot inherit that mistake.
    """
    return (instant(iso) + datetime.timedelta(seconds=seconds)) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")


def _demo_keypackage(uid, mid, device_id, cipher_suite):
    """Stand-in KeyPackage bytes for one device under one suite.

    The DEMO stands in for a real KeyPackage pool; what must be real is that
    the reference derived from these bytes is derived the published way, which
    is what a client checks."""
    # R11-01: the ENTITY is part of which device this is. Without it, the
    # same MID and label under two entities produced byte-identical packages
    # and therefore one `keypackage_ref` for two devices.
    # G1: the package carries the LEAF SIGNATURE KEY. A pre-join refusal is
    # verified against it by the Delivery Service, which holds the package —
    # no discovery document and no wallet key, because the device has joined
    # nothing yet. Without the key in here the DS could only check possession
    # of `keypackage_ref`, which is a hash of these public bytes and is held by
    # the creator and the DS alike: the two parties best placed to forge a
    # refusal attributed to the device.
    return ("demo-keypackage:" + "|".join([
        uid, mid, device_id, cipher_suite,
        demo_public_key_b64(f"leaf:{mid}:{device_id}")])).encode()


def _leaf_key_of(keypackage_ref, cipher_suite=None):
    """The leaf signature key carried by the RETAINED package that
    `keypackage_ref` names (G1 / R30-PUB-02).

    This is the whole point of the pre-join proof: the Delivery Service verifies
    a refusal against the key of the exact package the invitation consumed,
    because a device that has joined nothing has no discovery document and no
    wallet key to be checked against.

    `refuse_welcome` used to compute `demo_public_key_b64(f"leaf:{mid}:{did}")`
    instead — the same label the fixture generator uses, so the two agreed for
    every shipped package and nothing noticed. A package carrying a DIFFERENT
    valid key made the inversion plain: a refusal signed with the key the
    package actually carried was REJECTED, and one signed with a key that was
    not in the package at all was ACCEPTED. The reference followed the
    identity, and the error message said it had followed the package.

    The reference recomputes the ref over the retained bytes before trusting
    them, so a stored package that no longer hashes to the name it is filed
    under yields no key rather than the wrong one.
    """
    for reservation in _RESERVATIONS.values():
        for target in reservation.get("targets") or []:
            if target.get("keypackage_ref") != keypackage_ref:
                continue
            package = base64.b64decode(target["keypackage_b64"])
            suite = cipher_suite or reservation.get("cipher_suite")
            if mls_wire.keypackage_ref(package, cipher_suite=suite) != keypackage_ref:
                return None
            fields = package.decode("utf-8").split("|")
            return base64.b64decode(fields[-1]) if len(fields) >= 5 else None
    return None


def _reservation_response(r):
    """The PUBLIC `Reservation` — built from the record, never the record.

    R9-04's serializer rule arrives early here because R9-03 needs it: the
    internal row carries `creator`, `uid`, `targets` and `state`, all of which
    the closed public object rejects, and it lacks `expires_at`, `keypackages`
    and `committed`, all of which the public object requires.
    """
    return {
        "reservation_id": r["reservation_id"],
        "cipher_suite": r["cipher_suite"],
        "expires_at": r["expires_at"],
        "committed": r["state"] == "committed",
        "keypackages": [
            {"mid": t["mid"], "device_id": t["device_id"],
             "cipher_suite": r["cipher_suite"],
             "keypackage_b64": t["keypackage_b64"],
             "keypackage_ref": t["keypackage_ref"]}
            for t in r["targets"]],
    }


def keypackage_availability(uid, *, credential):
    """`GET /keypackages/{uid}` — per-suite availability for one entity.

    R9-B6: this operation was PUBLISHED with no reference behind it, so an
    implementer had nothing to calibrate against and the response-conformance
    sweep could not drive it. The DS genuinely knows this: the pool it holds,
    less what committed reservations have consumed.
    """
    _creator_of(credential)
    import mls_suite
    consumed = {}
    for r in _RESERVATIONS.values():
        if r["uid"] != uid or r["state"] != "committed":
            continue
        consumed[r["cipher_suite"]] = consumed.get(r["cipher_suite"], 0) + \
            len(r["targets"])
    return {"suites": [{"cipher_suite": suite,
                        "available": max(0, DEMO_POOL_PER_SUITE
                                         - consumed.get(suite, 0))}
                       for suite in mls_suite.PREFERENCE]}


def reserve_keypackages(uid, *, credential, cipher_suite, targets,
                        idempotency_key, now="2026-04-04T09:00:00Z"):
    """`POST /keypackages/{uid}/reservations` — reserve one usable KeyPackage
    per selected (mid, device_id).

    R9-03 requirement 3 — ONE idempotency model, and it is the contract's:
    the reservation id is SERVER-ASSIGNED, and the client's replay handle is
    the REQUIRED `Idempotency-Key` header. Replaying the same key returns the
    same reservation; reusing it for different content is a conflict.

    Requirement 2: every reserved target carries its `keypackage_ref`,
    derived the published way (RFC 9420 §5.2) from the bytes returned beside
    it, so the client can check the DS's arithmetic rather than trust it.
    """
    creator = _creator_of(credential)
    if not isinstance(idempotency_key, str) or len(idempotency_key) < 16:
        raise ReservationError(
            "idempotency-key-required",
            "`Idempotency-Key` is REQUIRED and at least 16 characters: without "
            "it a retried reservation opens a second one and the packages of "
            "the first are held until they expire (R9-03)")
    seen = set()
    for t in targets:
        pair = (t["mid"], t["device_id"])
        if pair in seen:
            raise ReservationError("keypackage-target-duplicate",
                                   f"device {pair!r} named twice (DR-08)")
        seen.add(pair)

    key = (creator, idempotency_key)
    prior_id = _IDEMPOTENCY.get(key)
    # A key pointing at a reservation that no longer exists is a DANGLING
    # entry, not a replay: the reservation expired, was released, or was
    # purged. Treat it as absent and mint a new one rather than raising —
    # found by a probe against my own Batch-1 code, where the two maps could
    # go out of sync and the operation crashed instead of answering.
    prior = _RESERVATIONS.get(prior_id) if prior_id is not None else None
    if prior is not None:
        # R10-06: the ENTITY is part of the request a key names. This compared
        # suite and targets but not `uid`, so the same key, targets and suite
        # under another entity returned the FIRST entity's reservation — its
        # id, its packages — to a request about somebody else. Not an
        # idempotency slip: a cross-entity leak.
        same = (prior["uid"] == uid and
                prior["cipher_suite"] == cipher_suite and
                [(t["mid"], t["device_id"]) for t in prior["targets"]] ==
                [(t["mid"], t["device_id"]) for t in targets])
        if not same:
            raise ReservationError(
                "reservation-conflict",
                f"`Idempotency-Key` {idempotency_key!r} was used for a "
                "different reservation. A replay converges; a different "
                "request under one key is a conflict (R9-03)")
        return _reservation_response(prior)

    _RESERVATION_SEQ[0] += 1
    reservation_id = f"res-{_RESERVATION_SEQ[0]:04d}"
    resolved = []
    for t in targets:
        kp = _demo_keypackage(uid, t["mid"], t["device_id"], cipher_suite)
        resolved.append({
            "mid": t["mid"], "device_id": t["device_id"],
            "keypackage_b64": base64.b64encode(kp).decode(),
            "keypackage_ref": mls_wire.keypackage_ref(kp,
                                                      cipher_suite=cipher_suite),
        })
    _RESERVATIONS[reservation_id] = {
        "reservation_id": reservation_id, "creator": creator, "uid": uid,
        "cipher_suite": cipher_suite, "targets": resolved, "state": "reserved",
        "expires_at": _plus_seconds(now, RESERVATION_TTL_SECONDS)}
    _IDEMPOTENCY[key] = reservation_id
    return _reservation_response(_RESERVATIONS[reservation_id])


def _reservation_of(reservation_id, creator, *, at):
    r = _RESERVATIONS.get(reservation_id)
    if r is None or r["creator"] != creator:
        raise ReservationError(
            "reservation-unknown",
            "unknown or belonging to another holder — uniformly "
            "indistinguishable")
    # R9-03 requirement 7: the TTL is enforced, not merely published. An
    # expired reservation's packages are back in the pool, so committing it
    # would consume packages the DS has already offered to somebody else.
    if r["state"] == "reserved" and instant(at) > instant(r["expires_at"]):
        raise ReservationError(
            "reservation-expired",
            f"reservation {reservation_id!r} expired at {r['expires_at']} and "
            "its packages returned to the pool; re-reserve (R9-03)")
    return r


def commit_reservation(reservation_id, *, credential,
                       now="2026-04-04T09:01:00Z"):
    """`POST /reservations/{id}/commit` — mark the packages consumed. ATOMIC
    over every target (DR-08) and idempotent."""
    r = _reservation_of(reservation_id, _creator_of(credential), at=now)
    if r["state"] == "released":
        raise ReservationError(
            "reservation-unknown",
            "unknown or belonging to another holder — uniformly "
            "indistinguishable")
    r["state"] = "committed"
    return _reservation_response(r)


def release_reservation(reservation_id, *, credential,
                        now="2026-04-04T09:01:00Z"):
    """`DELETE /reservations/{reservation_id}` — return every unused package.

    R10-X2 — BURN AND RE-RESERVE. Packages are CONSUMED at commit, whatever
    happens next. Release applies only BEFORE commit, when nothing has left
    the DS: every package returns to the pool together. After commit a failed
    or partial Welcome deposit releases nothing — the creator reserves afresh.
    The contract used to tell the creator to release a committed reservation
    when a deposit failed, which was unreachable (deposit REQUIRES commit, and
    this refused) and, taken literally, worse: it would have returned a
    package whose Welcome might already have escaped to a device, making a
    single-use package usable twice (R10-06).

    Releasing a reservation that has EXPIRED, or was already released, is the
    204 the contract promises: its packages are already back in the pool, and
    a lost release response must converge on retry. This raised
    `reservation-expired` instead (R10-06).
    """
    r = _RESERVATIONS.get(reservation_id)
    creator = _creator_of(credential)
    if r is None or r["creator"] != creator:
        raise ReservationError(
            "reservation-unknown",
            "unknown or belonging to another holder — uniformly "
            "indistinguishable")
    if r["state"] == "committed":
        raise ReservationError(
            "reservation-committed",
            f"reservation {reservation_id!r} is committed: its packages are "
            "consumed and do not return to the pool. A group that failed after "
            "commit is retried with a NEW reservation (R10-X2)")
    r["state"] = "released"        # idempotent: released or expired alike
    return None                    # 204: there is nothing to say


def resolve_committed_target(reservation_id, *, keypackage_ref, device_id,
                             creator):
    """The exact consumed KeyPackage for this device, or a typed refusal.

    R8-04 requirement 3: an invitation may only be created against a COMMITTED
    reservation held by the same creator, naming THIS device, and quoting the
    package reference that reservation actually consumed for it.

    R11-01: the target is found by the PACKAGE, which is unique, and then held
    to the device label — not found by the label, which two members of one
    entity may share. Found by label, the second member's deposit met the
    first member's package and was refused as `keypackage-not-consumed`, so
    the shipped topology (two members, each with a `dev-01`) could not be
    invited at all.
    """
    r = _RESERVATIONS.get(reservation_id)
    if r is None or r["creator"] != creator:
        raise InvitationError(
            "reservation-unknown",
            f"reservation {reservation_id!r} is unknown or belongs to another "
            "creator, so nothing binds this invitation to a KeyPackage the DS "
            "actually issued (R8-04)")
    if r["state"] != "committed":
        raise InvitationError(
            "reservation-not-committed",
            f"reservation {reservation_id!r} is {r['state']!r}: a Welcome "
            "deposited against an uncommitted reservation names packages that "
            "may still return to the pool (R8-04)")
    labelled = [t for t in r["targets"] if t["device_id"] == device_id]
    if not labelled:
        raise InvitationError(
            "keypackage-target-unrequested",
            f"device {device_id!r} is not a target of reservation "
            f"{reservation_id!r}, so no package was consumed for it (R8-04)")
    for t in labelled:
        if t.get("keypackage_ref") == keypackage_ref:
            # `uid` travels with the target: R9-X3 needs the recipient ENTITY
            # to record group membership, and the reservation is where the
            # DS learned it.
            return {"cipher_suite": r["cipher_suite"], "uid": r["uid"], **t}
    raise InvitationError(
        "keypackage-not-consumed",
        f"the invitation names KeyPackage {keypackage_ref!r} for device "
        f"{device_id!r}, but that reservation consumed no such package for "
        "it (R8-04)")


def published_device_floor(members, device):
    """R8-04 requirement 5 — the floor a device ACTUALLY publishes.

    A device MAY publish a floor above the mandatory `mls-suite-floor/v1`
    (BW-MEMBER 2.2 `min_cipher_suite`); it may never publish a lower one, so
    the answer is the stronger of the two. Returns None when the supplied
    discovery material does not describe the device — which is refused rather
    than defaulted, because "I could not check" and "it checks out" are
    different answers.

    R11-01: `device` is the (uid, mid, device_id) principal. This matched the
    label across every member supplied, so of two members each publishing a
    `dev-01` the first one's floor answered for both.
    """
    import mls_suite
    uid, mid, device_id = device
    for m in (members or []):
        if m.get("uid") != uid or m.get("mid") != mid:
            continue
        for d in (m.get("devices") or []):
            if d.get("device_id") != device_id:
                continue
            own = d.get("min_cipher_suite")
            if not own:
                return mls_suite.FLOOR
            rank = {s: i for i, s in enumerate(mls_suite.PREFERENCE)}
            if own not in rank:
                return own
            return own if rank[own] <= rank[mls_suite.FLOOR] else mls_suite.FLOOR
    return None


def validate_invitation_deposit(deposit):
    """The published `InvitationDeposit`, EXECUTED (R8-04 requirement 1)."""
    from lint_cli import request_schema
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "InvitationDeposit")
    return [("$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]"
                           for p in e.path), e.message[:160])
            for e in sorted(validator.iter_errors(deposit),
                            key=lambda e: list(e.path))]


_INVITATIONS = {}      # (creator (uid, mid), invitation_id) -> the record — R12-08
_PACKAGE_DEPOSITS = {} # (reservation_id, keypackage_ref) -> the invitation that consumed it — R12-07
_FOUNDERS = {}         # mls_group_id -> the founding device (uid, mid, device_id) — R12-X3
_OUTCOMES = {}         # outcome_id -> the typed pre-join outcome, for its creator
_OUTCOME_SEQ = [0]


class InvitationError(Exception):
    """A refusal or collection that does not correspond to a retained
    invitation. Uniform, so the queue is not an existence oracle."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _creator_of(credential):
    """R8-X3 / R8-04 requirement 2 — the creator is a MEMBER, exactly.

    R7-X2 settled that the creator is a member at deposit, collection and
    acknowledgement. The code then accepted `member`, `entity` OR `device` at
    deposit and did no kind check at all at collection, so a device credential
    carrying a `uid` could create and consume member-owned outcomes. That was
    not an open design question — it was a settled decision the code had not
    been brought to.

    A member-bound credential carries a `mid`. An entity-bound token carries a
    `uid` and covers every member of that entity; a device credential covers
    one device. Neither IS the creator, and neither may stand in for it.

    R11-01: the creator is `(uid, mid)`. It was the bare `mid`, which is
    unique only within an entity, so a DE member sharing a FR creator's MID
    collected and acknowledged the FR creator's outcomes, committed its
    reservation, and got it back by reusing its `Idempotency-Key`.
    """
    if not isinstance(credential, dict) or credential.get("kind") != "member":
        raise WelcomeAccessDenied(
            "this operation is MEMBER-bound (R7-X2/R8-X3): an entity-level "
            f"token covers every member of the entity and a device credential "
            f"covers one device; a {(credential or {}).get('kind')!r} "
            "credential is neither the creator nor able to stand in for it")
    who = principal_of(credential, "member")
    if who is None:
        raise WelcomeAccessDenied(
            "the member credential does not name its entity and `mid`, so "
            "there is no creator identity to own the resulting outcomes — a "
            "MID is unique only within its entity (R8-X3/R11-01)")
    return who


def _invitation_window(deposit):
    """R8-04 requirement 4: `created_at < expires_at`, checked before anything
    is retained. An invitation whose window is empty or inverted can never be
    refused in time, so retaining it creates a record no refusal can satisfy."""
    # R9-04 requirement 1 — INSTANTS, not strings.
    #
    # These were compared with `>=` on the raw values, and lexical order is not
    # chronological order once offsets are allowed — which the OpenAPI
    # `format: date-time` does allow. `2026-04-04T08:00:00-02:00` is 10:00Z and
    # sorts BEFORE `2026-04-04T09:00:00Z`, so a window that is chronologically
    # inverted was accepted as ordered and the invitation was born expired.
    #
    # `lint_cli.instant` already existed, was already RFC 3339-correct, and was
    # already used elsewhere in this repository. This path simply never called
    # it. That is the sharper form of the finding: not a missing capability,
    # an unused one.
    try:
        created, expires = (instant(deposit["created_at"], field="created_at"),
                            instant(deposit["expires_at"], field="expires_at"))
    except TimestampError as e:
        raise InvitationError(
            "invitation-window-invalid",
            f"{e}: an instant that cannot be parsed cannot bound a window "
            "(R9-04)")
    if created >= expires:
        raise InvitationError(
            "invitation-window-invalid",
            f"created_at {deposit['created_at']!r} ({created.isoformat()}) is "
            f"not before expires_at {deposit['expires_at']!r} "
            f"({expires.isoformat()}): the invitation would be born expired "
            "and no refusal could ever be in window (R8-04/R9-04)")


# R9-04 requirements 3, 4 and 5 — RESPONSE DTOs, and they are validated.
#
# The reference returned its own internal rows. `deposit_welcome` added
# `invitation_id`, the Welcome queue carried it too, and collected outcomes
# carried `creator` AND `invitation_id` — all rejected by the closed public
# objects. A generated client that correctly refuses unknown properties would
# have rejected the reference's SUCCESSFUL responses, so the nominal flow was
# not wire-interoperable even with everything else fixed.
#
# `invitation_id` stays INTERNAL (requirement 4). It correlates a device's
# queue with the creator's queue, nothing in the published flow needs it — an
# outcome already carries `welcome_id` and `outcome_id` — and adding it would
# be a privacy-model change, not a serializer convenience.


def _public(schema_name, obj, *, fields):
    """Project an internal record onto its published shape, then CHECK it.

    Two steps on purpose. Projecting alone would drift the moment a field is
    added to the record; validating alone would let a field the Schema happens
    to allow leak through. Doing both means the response is exactly what is
    published, and says so."""
    out = {k: copy.deepcopy(v) for k, v in obj.items() if k in fields}
    problems = validate_contract_object("delivery-service-openapi.yaml",
                                        schema_name, out)
    if problems:
        raise InvitationError(
            "response-schema-invalid",
            f"the generated {schema_name} does not satisfy its published "
            f"Schema: {problems[:3]} — it is not returned (R9-04)")
    return out


def deposit_welcome(deposit, *, credential, queued_at="2026-04-04T10:00:00Z"):
    """R3-06/R7-03/R8-04 — deposit a Welcome WITH its invitation record.

    R8-04 requirement 1: the argument IS the published `InvitationDeposit`
    request. It used to be `(recipient_device, welcome_b64, invitation=...)`
    with its own required-field tuple that omitted the first two — so the
    reference's own happy path was a request the published Schema REJECTED,
    and an implementer following the contract would have had its fixtures
    refused. The request object is validated against the contract here, so
    there is no second shape and no second required list to keep in step.

    R8-04 requirement 3: the invitation is bound to a COMMITTED reservation and
    to the exact KeyPackage consumed for the target device. `reservation_id`
    and `keypackage_ref` were required at deposit and read nowhere, so an
    arbitrary uncommitted reservation and an invented package reference were
    retained as though they had been checked.
    """
    creator = _creator_of(credential)
    problems = validate_invitation_deposit(deposit)
    if problems:
        raise InvitationError(
            "invitation-incomplete",
            f"the deposit does not satisfy the published `InvitationDeposit`: "
            f"{problems[:3]} — each field is something a refusal must be "
            "checkable against, so an unusable record is refused rather than "
            "retained (R7-03/R8-04)")
    _invitation_window(deposit)
    try:
        base64.b64decode(deposit["welcome_b64"], validate=True)
    except Exception:
        raise InvitationError(
            "welcome-malformed",
            "`welcome_b64` is not valid base64, so the DS would queue bytes no "
            "device can parse and the invitation could never be acted on "
            "(R8-04)")

    # R8-04 requirements 3 and 6 — the reservation and the exact KeyPackage.
    device = deposit["recipient_device"]
    target = resolve_committed_target(deposit["reservation_id"],
                                      keypackage_ref=deposit["keypackage_ref"],
                                      device_id=device, creator=creator)
    if deposit["offered_suite"] != target["cipher_suite"]:
        raise InvitationError(
            "invitation-suite-mismatch",
            f"the invitation offers {deposit['offered_suite']!r} while the "
            f"committed reservation consumed a {target['cipher_suite']!r} "
            "KeyPackage — the suite a refusal is checked against must be the "
            "one actually reserved (R8-04)")

    inv_id = deposit["invitation_id"]
    # R12-08 — THE HANDLE IS THE CREATOR'S. `invitation_id` is chosen by the
    # creator and nothing makes it globally unique, yet the ledger was keyed
    # on the bare value: a second creator, with its own reservation, choosing
    # `invitation-1` got `invitation-conflict` from somebody else's
    # invitation. It is scoped by the creator principal now (invariant 10).
    inv_key = (creator, inv_id)
    prior = _INVITATIONS.get(inv_key)
    if prior is not None:
        # A lost 202 converges: the same invitation_id with the same content
        # returns the same queue item rather than creating a second one.
        if prior["invitation"] != deposit:
            raise InvitationError(
                "invitation-conflict",
                f"invitation {inv_id!r} already exists with different content "
                "(R7-03)")
        return _public("WelcomeQueued", prior,
                       fields=("welcome_id", "recipient_device"))
    # R12-07 — ONE PACKAGE, ONE INVITATION. The reservation proved the package
    # was committed, and nothing bound its consumption to a deposit: one
    # committed package authorised two different invitations into two groups,
    # both queued and both routed. The exact retry above still converges.
    package = (deposit["reservation_id"], deposit["keypackage_ref"])
    if _PACKAGE_DEPOSITS.get(package, inv_key) != inv_key:
        raise InvitationError(
            "keypackage-already-deposited",
            f"KeyPackage {deposit['keypackage_ref']!r} of reservation "
            f"{deposit['reservation_id']!r} was consumed by another invitation; "
            "a single-use package authorises one Welcome — reserve afresh "
            "(R12-07, R10-X2)")
    _WELCOME_SEQ[0] += 1
    item = {"welcome_id": f"wel-{_WELCOME_SEQ[0]:04d}",
            "recipient_device": device,
            "welcome_b64": deposit["welcome_b64"], "queued_at": queued_at,
            # R10-05: what the invited device is told to CHECK, delivered to
            # it. Round 9 defined the commitment and assigned the check to this
            # device, and this item — the only thing it receives — carried
            # neither the value nor the suite it is computed under.
            "group_info_commitment": deposit["group_info_commitment"],
            "offered_suite": deposit["offered_suite"],
            # G1: the DS issues a single-use nonce WITH the Welcome. A refusal
            # signs it, and the DS accepts it once. The invitation window alone
            # bounds how long a captured refusal stays usable; a nonce makes
            # replaying one impossible rather than merely late.
            "refusal_nonce": _refusal_nonce(),
            "invitation_key": inv_key}
    # R11-01: the invited device IS (entity, member, label), resolved from the
    # package the reservation consumed — the deposit's `recipient_device` is
    # only the label, and two members may share one.
    invited = (target["uid"], target["mid"], device)
    _WELCOME_QUEUE.setdefault(invited, []).append(item)
    _PACKAGE_DEPOSITS[package] = inv_key
    _INVITATIONS[inv_key] = {
        "invitation": copy.deepcopy(deposit), "welcome_id": item["welcome_id"],
        # G1: retained here as well as on the queued item, because the item
        # leaves the queue when the device collects it and the refusal may
        # follow afterwards.
        "refusal_nonce": item["refusal_nonce"],
        "recipient_device": device, "invited": invited, "creator": creator,
        "state": "open",
        "member": (target["uid"], target["mid"])}
    # R9-X3: the DS OBSERVED this device being invited into this group. That
    # observation is the routing authority — the invitation record above IS
    # it, and `group_roster` reads it (R11-07).
    return _public("WelcomeQueued", item,
                   fields=("welcome_id", "recipient_device"))


_REFUSAL_NONCE_SEQ = [0]
_SPENT_REFUSAL_NONCES = set()


def _refusal_nonce():
    """A Welcome's single-use refusal nonce (DEMO: a counter; production takes
    it from a CSPRNG). Issued by the Delivery Service with the Welcome and
    spent by the refusal that signs it."""
    _REFUSAL_NONCE_SEQ[0] += 1
    return f"rn-{_REFUSAL_NONCE_SEQ[0]:012d}"


def welcome_refusal_proof(welcome_id, *, credential, reason, offered_suite,
                          required_floor=None, nonce=None):
    """What a REFUSING DEVICE produces — the client half of G1's proof.

    Here so that a caller cannot assemble the signed content its own way: the
    device and the Delivery Service must sign and verify the same bytes, and
    two builders is how they come to differ. The demo signs with the
    deterministic leaf seed; a real device holds the private half of the leaf
    key its KeyPackage published and signs with that.

    The nonce is the one the Welcome arrived with, and the CALLER supplies it
    from the queue item `GET /welcome` returned. It is not defaulted, and — since
    R30-PUB-01 — it is not looked up either.

    It used to be. This docstring said "it is not defaulted" while the code
    below read the value out of `_WELCOME_QUEUE` and `_INVITATIONS` when the
    caller passed none, which is the service's private state: a device on the
    other side of the boundary has no such access. So the reference demonstrated
    a flow that nobody holding the contract could execute, and the false
    sentence in this docstring is what let it look finished. The lookup is gone;
    a caller without the nonce must fetch its queue, which is where the value
    now is.
    """
    device = _device_of(credential)
    if not nonce:
        raise InvitationError(
            "refusal-proof-required",
            "no nonce: a refusal signs the value the Delivery Service issued "
            "with the Welcome, and this builder will not read it out of the "
            "service's own state — take it from the `refusal_nonce` of the "
            "queue item `GET /welcome` returned for this Welcome")
    # R32: the package reference comes from the DEVICE's own credential — it
    # holds the package it was invited with. This read `_INVITATIONS` first and
    # fell back to the credential, so a client that genuinely had no access to
    # the service's tables still appeared to work here, which is the same
    # illusion the nonce lookup created and the reason that one was missed.
    kp_ref = credential.get("keypackage_ref")
    if not kp_ref:
        raise InvitationError(
            "refusal-proof-required",
            "the credential does not name the KeyPackage this device was "
            "invited with; a refusal signs that reference, and this builder "
            "will not look it up in the service's records")
    seed = demo_seed_bytes(f"leaf:{device[1]}:{device[2]}")
    return {"nonce": nonce,
            "signature_b64": mls_wire.sign_welcome_refusal(
                seed, welcome_id=welcome_id, keypackage_ref=kp_ref,
                offered_suite=offered_suite, required_floor=required_floor,
                reason=reason, nonce=nonce)}


def _refusal_key(welcome_id, device, reason, offered_suite, required_floor):
    """R8-04 requirement 7: the idempotency key of a terminal refusal. The same
    device repeating the same request after a lost 204 must get the same
    success; a DIFFERENT request for the same Welcome must fail deterministically
    rather than being answered as though it were the first one."""
    return (welcome_id, device, reason, offered_suite, required_floor)


def refuse_welcome(welcome_id, *, credential, reason, offered_suite,
                   required_floor=None, refused_at="2026-04-04T10:05:00Z",
                   members=None, refusal_proof=None):
    """R5-V2/R6-W2/R7-03/R8-04 — the pre-join refusal, VALIDATED.

    The refusing device never instantiates the offered suite. R7-03 made the DS
    compare `offered_suite` with the record. R8-04 closes the rest: the refusal
    must be IN WINDOW, its `reason` must be one the registry defines, its
    `required_floor` must be the floor the device actually publishes, and the
    refusing credential must hold the KeyPackage this invitation consumed —
    not merely name the right `device_id`. Every one of those was retained
    verbatim from the caller, so a target could publish a false floor, invent a
    reason and refuse long after expiry.

    Uniform 404-equivalent for unknown, expired and another device's item: the
    queue must not be an existence oracle over another device's state.
    """
    device = _device_of(credential)          # (uid, mid, device_id) — R11-01
    entry = next((e for e in _INVITATIONS.values()
                  if e["welcome_id"] == welcome_id), None)
    if entry is None or entry["invited"] != device:
        raise InvitationError(
            "invitation-unknown",
            "unknown, already handled, expired, or belonging to another "
            "device — uniformly indistinguishable (R7-03)")
    inv = entry["invitation"]

    # R8-04 requirement 7 — the TERMINAL result, before the state check, so a
    # lost 204 converges instead of being answered `invitation-unknown`.
    key = _refusal_key(welcome_id, device, reason, offered_suite,
                       required_floor)
    if entry["state"] == "refused":
        if entry.get("refusal_key") == key:
            return _public("RefusalAccepted", entry,      # the same success
                           fields=("outcome_id",))
        raise InvitationError(
            "invitation-conflict",
            "this Welcome was already refused with a different reason, suite "
            "or floor. A retry converges; a different request is a conflict "
            "and must not silently replace the terminal result (R8-04)")
    if entry["state"] != "open":
        raise InvitationError(
            "invitation-unknown",
            "unknown, already handled, expired, or belonging to another "
            "device — uniformly indistinguishable (R7-03)")

    # R8-04 requirement 6: the credential must hold THIS invitation's package.
    if credential.get("keypackage_ref") != inv["keypackage_ref"]:
        raise InvitationError(
            "invitation-unknown",
            "unknown, already handled, expired, or belonging to another "
            "device — uniformly indistinguishable (R7-03)")

    # R10-05: the published request, EXECUTED — as `ReceiptAckRequest` and
    # `InvitationDeposit` already are. It was inline and could not be
    # referenced, so the reason/suite/floor rules below were the only ones
    # applied, while the published body (including which reasons may carry a
    # floor) went unchecked.
    # G1: the proof travels IN the request, so the published shape carries it
    # and this validation executes it. It used to be a keyword the reference
    # checked by hand while `WelcomeRefusalRequest` had no field for it at all
    # — the contract and the reference describing different operations, which
    # is the defect this repository keeps finding one surface at a time.
    #
    # R30-PUB-05: this ran AFTER the proof's fields were read, so a proof
    # missing `signature_b64` raised a bare KeyError — an untyped escape from a
    # function whose every other refusal is a typed `InvitationError`. The
    # identity checks above still come first, because they are what keeps the
    # queue from being an existence oracle; the SHAPE of the request is settled
    # here, before anything indexes into it.
    request = {"reason": reason, "offered_suite": offered_suite,
               **({} if refusal_proof is None else {"refusal_proof": refusal_proof}),
               **({} if required_floor is None else {"required_floor": required_floor})}
    # R32-RES-02: the REASON is settled first, because the shape check below used
    # to be conditional on it — so an unregistered reason skipped the shape check
    # and fell through to the proof's fields, where a missing `signature_b64`
    # raised a bare KeyError. Two invalid things in one request must still give a
    # typed answer about one of them.
    # R33-OBS-01: the membership test came first, so a reason that is not even a
    # string — a list, an object — raised `TypeError: unhashable` before anything
    # could refuse it. The published Schema rejects both, so this is the
    # in-process helper rather than an exposed endpoint; it is still the one
    # shape of malformed input that escaped untyped after the R32 pass.
    if not isinstance(reason, str) or reason not in GROUP_ESTABLISHMENT_REASONS:
        raise InvitationError(
            "refusal-reason-unknown",
            f"{reason!r} is not a registered group-establishment outcome "
            f"({sorted(GROUP_ESTABLISHMENT_REASONS)}). The reason is enumerated "
            "so a creator can act on it; a free-text value retained verbatim is "
            "an attacker-chosen string in the creator's queue (R8-04)")
    problems = validate_contract_object("delivery-service-openapi.yaml",
                                        "WelcomeRefusalRequest", request)
    if problems:
        raise InvitationError(
            "refusal-request-invalid",
            f"the refusal does not satisfy the published "
            f"`WelcomeRefusalRequest`: {problems[:2]} (R10-05)")
    # And the suite it CLAIMS is checked against the record before any of it is
    # used: the key resolution below recomputes the package reference, and a
    # suite the registry does not know made that raise a ValueError out of the
    # hash-function lookup — an untyped escape introduced by the R30-PUB-02 fix.
    if offered_suite != inv["offered_suite"]:
        raise InvitationError(
            "invitation-suite-mismatch",
            f"the refusal says it was offered {offered_suite!r}; this "
            f"invitation offered {inv['offered_suite']!r}. The DS validates "
            "the claim against the record rather than echoing it (R7-03)")

    # G1 — THE PRE-JOIN PROOF. Holding `keypackage_ref` proves nothing: it is a
    # hash of the package's PUBLIC bytes, returned to the creator by the
    # reservation and held by the Delivery Service, so the two parties best
    # placed to forge a refusal attributed to this device both hold it. The
    # proof is a signature under the KeyPackage's LEAF SIGNATURE KEY, whose
    # private half only the device has, over a typed domain-separated content
    # carrying the DS's single-use nonce — RFC 9420 §5.1.2 `SignWithLabel`,
    # label `SBMWelcomeRefusal`, verified against the key the package carries.
    # A pre-join device has joined nothing, so no discovery document and no
    # wallet key can be involved.
    proof = refusal_proof or {}
    queued = next((w for w in _WELCOME_QUEUE.get(device, [])
                   if w["welcome_id"] == welcome_id), None)
    expected_nonce = (queued or {}).get("refusal_nonce") or entry.get("refusal_nonce")
    # A MISSING proof is not refused here: the published `WelcomeRefusalRequest`
    # requires the field, and it is executed below — one authority for the
    # request's shape rather than a hand check beside it. What is checked here
    # is what a Schema cannot express: that the nonce is THIS Welcome's, that it
    # has not been spent, and that the signature verifies.
    if not proof:
        pass
    elif proof.get("nonce") != expected_nonce:
        raise InvitationError(
            "refusal-proof-invalid",
            "the refusal does not carry the nonce this Welcome was issued with")
    elif proof["nonce"] in _SPENT_REFUSAL_NONCES:
        raise InvitationError(
            "refusal-proof-replayed",
            "this nonce has already been spent; a refusal is usable once")
    # The package's identity is fixed by the reservation that created it, so the
    # reference is recomputed under the RETAINED suite — never under a value the
    # request supplied, which is the caller's claim about it.
    leaf_pub = _leaf_key_of(inv["keypackage_ref"])
    if proof and leaf_pub is None:
        raise InvitationError(
            "refusal-proof-invalid",
            "the KeyPackage this invitation consumed is not retrievable, or no "
            "longer hashes to the reference it is filed under, so there is no "
            "leaf signature key to verify the refusal against")
    if proof and not mls_wire.verify_welcome_refusal(
            leaf_pub, proof["signature_b64"],
            welcome_id=welcome_id, keypackage_ref=inv["keypackage_ref"],
            offered_suite=offered_suite, required_floor=required_floor,
            reason=reason, nonce=proof["nonce"]):
        raise InvitationError(
            "refusal-proof-invalid",
            "the signature does not verify against the leaf signature key this "
            "invitation's KeyPackage carries, over the refusal's own content")
    # NOT spent here. A refusal the DS rejects for any other reason — an
    # unresolvable floor, an out-of-window instant, an unregistered reason —
    # must leave the device able to try again: burning the nonce on a
    # recoverable error would give a device one attempt and no way to correct
    # it. It is spent where the outcome is recorded, below.

    # R8-04 requirement 4: IN WINDOW. `expires_at` was retained and never read,
    # so a refusal arriving at any later time created an outcome.
    # R9-04 requirements 1 and 2 — INSTANTS, and the window is CLOSED at both
    # ends: a refusal exactly at `created_at` or exactly at `expires_at` is IN
    # window. One rule, stated in the contract, applied at both boundaries.
    # Compared at the precision the values carry, truncated to microseconds by
    # the shared parser rather than rounded, so no value moves toward the
    # window it is being tested against.
    try:
        at = instant(refused_at, field="refused_at")
        lo = instant(inv["created_at"], field="created_at")
        hi = instant(inv["expires_at"], field="expires_at")
    except TimestampError:
        raise InvitationError(
            "invitation-unknown",
            "unknown, already handled, expired, or belonging to another "
            "device — uniformly indistinguishable (R7-03)")
    if not (lo <= at <= hi):
        raise InvitationError(
            "invitation-unknown",
            "unknown, already handled, expired, or belonging to another "
            "device — uniformly indistinguishable (R7-03)")

    # R10-05: the published request, EXECUTED — as `ReceiptAckRequest` and
    # `InvitationDeposit` already are. It was inline and could not be
    # referenced, so the reason/suite/floor rules below were the only ones
    # applied, while the published body (including which reasons may carry a
    # floor) went unchecked.
    # G1: the proof travels IN the request, so the published shape carries it
    # and this validation executes it. It used to be a keyword the reference
    # checked by hand while `WelcomeRefusalRequest` had no field for it at all
    # — the contract and the reference describing different operations, which
    # is the defect this repository keeps finding one surface at a time.
    # R10-05: a GroupInfo mismatch is not a cipher-suite refusal, and does not
    # pretend to be one. The device recomputed the commitment it read from its
    # WelcomeQueue item and it did not match; no floor is involved, so none
    # may be claimed. The DS cannot verify the claim — it cannot parse a
    # Welcome encrypted to the device — and records it for the creator,
    # authenticated by the KeyPackage credential like every refusal.
    # (That no floor may accompany it is the published request's rule, and
    # was refused above as `refusal-request-invalid`; a second statement of it
    # here was unreachable and has been deleted.)
    if reason == "group-info-mismatch":
        published = None
    else:
        published = _resolved_floor(members, device, required_floor)

    entry["state"] = "refused"
    entry["refusal_key"] = key
    # R9-X3/R11-07: it declined THIS invitation, which therefore no longer
    # places the device in the group; any other live invitation still does.
    # R11-06: and the item leaves the device's queue in the same step. The
    # contract promised the dequeue; the reference changed three ledgers and
    # left the Welcome collectable — and acknowledgeable, as if fresh.
    queue = _WELCOME_QUEUE.get(device, [])
    queue[:] = [i for i in queue if i["welcome_id"] != welcome_id]
    _OUTCOME_SEQ[0] += 1
    outcome_id = f"out-{_OUTCOME_SEQ[0]:04d}"
    entry["outcome_id"] = outcome_id
    # G1: the nonce is spent HERE — the refusal is accepted and terminal, so a
    # captured copy of it can never be used again. An exact retry converges on
    # the stored outcome above, before this point, which is why replay
    # protection and idempotency do not fight each other.
    _SPENT_REFUSAL_NONCES.add((refusal_proof or {}).get("nonce"))
    _OUTCOMES[outcome_id] = {
        "outcome_id": outcome_id, "welcome_id": welcome_id,
        "invitation_id": inv["invitation_id"],
        "mls_group_id": inv["mls_group_id"],
        # R11-01: WHICH device refused is the whole principal. The outcome
        # named the label only, so a creator whose invitees were two members
        # each with a `dev-01` could not tell which of them refused.
        "recipient_uid": device[0], "mid": device[1], "device_id": device[2],
        "reason": reason, "offered_suite": inv["offered_suite"],
        "refused_at": refused_at, "creator": entry["creator"]}
    if published is not None:
        # RESOLVED, not copied: what the creator reads is what discovery says.
        _OUTCOMES[outcome_id]["required_floor"] = published
    # R9-X4: 201 with a PUBLISHED body. The reference returned this value under
    # a contract that promised `204 No Content`, so a generated client received
    # nothing while the repository's own tests read it from the return value —
    # R9-03's shape a second time.
    return _public("RefusalAccepted", _OUTCOMES[outcome_id],
                   fields=("outcome_id",))


def _resolved_floor(members, device, required_floor):
    """R8-04 requirement 5: the floor is RESOLVED from published discovery, not
    believed. A target could otherwise publish one floor and claim another."""
    published = published_device_floor(members, device)
    if published is None:
        raise InvitationError(
            "refusal-floor-unresolvable",
            f"the floor device {device!r} publishes cannot be resolved from "
            "the supplied discovery material, so `required_floor` cannot be "
            "checked and the refusal would be an unverifiable assertion "
            "(R8-04)")
    if required_floor != published:
        raise InvitationError(
            "refusal-floor-mismatch",
            f"the refusal claims a floor of {required_floor!r}; device "
            f"{device!r} publishes {published!r}. The creator is told to verify "
            "the claim against published discovery, so the DS checks the same "
            "thing rather than forwarding whatever it was sent (R8-04)")
    return published


def register_founder(mls_group_id, *, credential):
    """`POST /groups/{group_id}/founder` — R12-04 / R12-X3.

    MLS begins a group with its creator; nothing adds the creator through a
    Welcome. Routing was derived from Welcomes alone, so the device that
    formed the group was never routed: invited, the counterparty replied, and
    the creator collected nothing. The creating device now registers itself,
    DEVICE-authenticated, as the group's founding member.

    Once per group; the same device repeating it converges (204). It must be a
    device of the creator that deposited an invitation into the group, so a
    group id cannot be claimed by someone who never formed it — an unknown
    group and another creator's group answer alike, as every other lookup
    here does. Later MLS membership changes after formation are on the review
    agenda, not guessed at here."""
    device = _device_of(credential)
    formed = any(e["invitation"]["mls_group_id"] == mls_group_id
                 and e["creator"] == device[:2] for e in _INVITATIONS.values())
    if not formed:
        raise InvitationError(
            "group-unknown",
            "unknown, or formed by another creator — uniformly "
            "indistinguishable (R12-X3)")
    prior = _FOUNDERS.get(mls_group_id)
    if prior is not None and prior != device:
        raise InvitationError(
            "founder-conflict",
            f"group {mls_group_id!r} already has its founding device; a group "
            "has one creator (R12-X3)")
    _FOUNDERS[mls_group_id] = device
    return None                    # 204


def collect_outcomes(*, credential, max_items=20):
    """R6-W2/R7-X2/R8-X3: the CREATOR collects, as a MEMBER, and sees only its
    own. This accepted any mapping carrying a `mid` OR a `uid` and performed no
    kind check, so a device credential returned the creator's outcomes."""
    who = _creator_of(credential)
    return [_public("GroupEstablishmentOutcome", o,
                    fields=("outcome_id", "welcome_id", "mls_group_id",
                            "recipient_uid", "mid", "device_id", "reason",
                            "offered_suite", "required_floor", "refused_at"))
            # R10-09: FILTER, THEN PAGINATE. This sliced the global queue
            # first and filtered second, so twenty earlier outcomes belonging
            # to other creators filled the page and a creator with a pending
            # outcome received [] for ever. Authorisation decides what a caller
            # may see; pagination only decides how much of it at once.
            for o in [o for o in _OUTCOMES.values()
                      if o["creator"] == who][:max_items]]


def ack_outcome(outcome_id, *, credential):
    """Explicit per-item acknowledgement, IDEMPOTENT for the creator that owns
    it (R7-03 requirement 6, aligned with the refusal's 204 rule): a repeat by
    the same creator succeeds, so a lost response converges.

    R8-04 requirement 8: an EXACT authenticated creator is required even when
    the item has already been deleted. `entry is None` used to return success
    before any identity check, so an unknown id acknowledged by nobody at all
    returned `{"acknowledged": True}` — the 404 description says "already
    acknowledged", and the reference made that true for every id in existence.
    The acknowledgement is remembered, so "already acknowledged BY YOU" and
    "never existed" stay distinguishable to the DS and indistinguishable to
    everyone else.
    """
    who = _creator_of(credential)
    entry = _OUTCOMES.get(outcome_id)
    if entry is None:
        if _ACKED_OUTCOMES.get(outcome_id) == who:
            return None                # 204, idempotent, for its owner
        raise InvitationError(
            "outcome-unknown",
            "unknown or belonging to another creator — uniformly "
            "indistinguishable (R7-03)")
    if entry["creator"] != who:
        raise InvitationError(
            "outcome-unknown",
            "unknown or belonging to another creator — uniformly "
            "indistinguishable (R7-03)")
    del _OUTCOMES[outcome_id]
    _ACKED_OUTCOMES[outcome_id] = who
    # R9-X4: 204 means no content, and now that is true. `{"acknowledged":
    # true}` carried nothing the status code does not.
    return None


def _device_of(credential):
    """The authenticated device as (uid, mid, device_id) — R11-01. The bare
    label was returned, so any device of any member using it owned the queue."""
    who = principal_of(credential, "device")
    if who is None:
        raise WelcomeAccessDenied(
            "collecting a Welcome requires DEVICE-bound authentication naming "
            "the device's entity and member: it hands over the group secrets "
            "of ONE device, an entity- or member-level credential covers many, "
            "and a bare label names a device of every member using it "
            "(R3-06/R11-01)")
    return who


def _live(item, at):
    """R11-06: an item is served only while its invitation's window is open
    at the DS clock. The contract said an expired Welcome is not served, and
    burn-and-re-reserve relies on an abandoned one expiring; collection read
    no clock at all, so a Welcome expired in April was still served in 2099."""
    from lint_cli import instant
    inv = _INVITATIONS[item["invitation_key"]]["invitation"]
    return instant(at) <= instant(inv["expires_at"])


def collect_welcomes(*, credential, at="2026-04-04T10:05:00Z"):
    """R3-06: the queue of the AUTHENTICATED device — there is no parameter
    naming a device, because a parameter that can name one can be got wrong.
    Fetching does NOT dequeue, so a lost response is retried harmlessly and
    concurrent fetches agree. `at` is the DS's own clock (injected, as
    `accepted_at` and `refused_at` are); an item past its window is not
    served (R11-06)."""
    device = _device_of(credential)
    queue = {"device_id": device[2],
             # R30-PUB-01: `refusal_nonce` is DELIVERED. The proof was required
             # and this value was withheld, so the published flow could not be
             # executed from the published contract — and the reference's own
             # helper hid it by reading the service's private queue.
             "welcomes": [{k: v for k, v in i.items()
                           if k in ("welcome_id", "recipient_device",
                                    "welcome_b64", "queued_at",
                                    "group_info_commitment", "offered_suite",
                                    "refusal_nonce")}
                          for i in _WELCOME_QUEUE.get(device, [])
                          if _live(i, at)]}
    problems = validate_contract_object("delivery-service-openapi.yaml",
                                        "WelcomeQueue", queue)
    if problems:
        raise WelcomeAccessDenied(
            f"the generated WelcomeQueue does not satisfy its published "
            f"Schema: {problems[:3]} — it is not returned (R9-04)")
    return queue


def ack_welcome(welcome_id, *, credential, at="2026-04-04T10:05:00Z"):
    """R3-06: explicit per-item acknowledgement, idempotent. Another device's
    item is indistinguishable from an unknown one.

    R11-07: acknowledging is JOINING — the invitation becomes `joined`, which
    keeps the device routed whatever becomes of any other invitation, and a
    joined invitation can no longer be refused. R11-06: an item that is not
    served (refused, expired at the DS clock `at`) cannot be acknowledged."""
    device = _device_of(credential)
    queue = _WELCOME_QUEUE.get(device, [])
    for i, item in enumerate(queue):
        if item["welcome_id"] == welcome_id and _live(item, at):
            queue.pop(i)
            _INVITATIONS[item["invitation_key"]]["state"] = "joined"
            _ACKED_WELCOMES[welcome_id] = device
            return None
    # R10-09: the contract promises 204 on a repeat, so a lost response
    # converges. This removed the item and then answered the retry with the
    # failure, whose text even said "already acknowledged". Completion is now
    # remembered, OWNER-BOUND as for outcomes: the device that acknowledged
    # gets its 204 again; anybody else still cannot tell the item existed.
    if _ACKED_WELCOMES.get(welcome_id) == device:
        return None
    raise WelcomeAccessDenied("unknown, or another device's")


def delivered_at_from_receipt(receipt, submitted_envelope_hash, med=None,
                              *, expect=None):
    """DR-10 + R3-04 — verify the DS receipt against the DS operator's
    published key, and return the S2 instant FROM THE SIGNED PAYLOAD.

    R11-04: that instant is `delivered_at` at the AVAILABILITY grade only. This
    docstring said "what RDP(out) MUST do before issuing the DE … take
    `delivered_at`" at every grade, as the DS contract did; at the
    verification and acceptance grades the receipt proves S2 and the delivery
    instant is the completing confirmation (`delivery_decision`).

    R5-03/R5-V4: this used to be a second implementation of the receipt check.
    R4-03 fixed `bundle_lint` and left this path behind, so the two disagreed
    about what a receipt proves — the retained verifier compared the asserted
    fields with the signed payload, while this one verified the signature and
    then returned the OUTER `server_time`. Moving that field on the outer
    object left the signature perfectly valid and made the live path report a
    delivery instant nobody had signed. There is ONE implementation now
    (`lint_cli.verify_ds_receipt`), and the instant returned is the SIGNED one.

    The digest check stays here rather than moving into the shared helper: it
    compares the receipt with THIS submission's commitment (the value RDP(out)
    computed at intake, DR-02), which is caller context, not a property of the
    receipt.
    """
    from lint_cli import verify_ds_receipt, ReceiptVerificationError
    if med is None:
        raise AckRejected(
            "receipt-unverifiable",
            "no BW-MED supplied, so the DS receipt key cannot be resolved and "
            "the signature cannot be verified against anything (R4-03)")
    # R6-03: the act being processed is STATED. Without it a valid receipt for
    # message A was accepted while handling message B whenever the ciphertext
    # digest matched — the function had no parameter with which to notice, so
    # cross-message, cross-recipient and cross-session replay were all
    # indistinguishable from a correct delivery.
    if expect is None:
        raise AckRejected(
            "receipt-context-missing",
            "no expected delivery context was supplied, so this receipt could "
            "be a valid one for another act. Fail closed (R6-03)")
    try:
        signed = verify_ds_receipt(receipt, med, expect=expect)
    except ReceiptVerificationError as e:
        raise AckRejected(e.reason, e.detail)

    if signed.get("message_digest") != submitted_envelope_hash:
        raise AckRejected(
            "receipt-unverifiable",
            "the DS receipt attests a different message than the one "
            "submitted — no DE (DR-10, the digest binds the receipt to the "
            "octets RDP(out) committed to)")
    delivered_at = signed.get("server_time")
    if not delivered_at:
        raise AckRejected(
            "receipt-unverifiable",
            "the signed payload carries no server_time, so there is no "
            "attested delivery instant to record (R5-03)")
    return delivered_at


def delivery_decision(se, grade, *, s2_at=None, state=None):
    """R11-04 / R11-X2 — which instant dates the delivery, and was it in time.

    ONE decision for the three grades, so the issuer and the retained verifier
    cannot make opposite deadline decisions on one trace:

      availability              the S2 instant — the VERIFIED receipt's
                                `server_time` (`delivered_at_from_receipt`);
      verification, acceptance  the instant RDP(in) observed the confirmation
                                that completed the policy (`confirmation_state`)
                                — never the S2 receipt, whatever it says.

    Timeliness is `lint_cli.in_time`, the rule LINT-BND-22 applies: a tie is
    delivered. Returns {"outcome": "delivered" | "expired" | "mismatch" |
    "validation-failed" | "refused" | "pending", "delivered_at": instant or None}. `expired` means the event
    happened, late; `pending` that it has not happened (yet)."""
    from lint_cli import in_time
    if grade == "availability":
        at = s2_at
    elif grade in ("verification", "acceptance"):
        if state and state.get("state") in ("mismatch", "refused"):
            # R12-X1: a verified refusal ends the message as a mismatch does
            return {"outcome": state["state"], "delivered_at": None}
        at = state.get("at") if state and state.get("state") == "satisfied" else None
    else:
        raise ValueError(f"unknown delivery grade {grade!r}")
    if at is None:
        return {"outcome": "pending", "delivered_at": None}
    if in_time(at, se["expires_at"]):
        return {"outcome": "delivered", "delivered_at": at}
    return {"outcome": "expired", "delivered_at": None}


def _sender_confirmation(se: dict, mid: str, device_id: str) -> dict:
    """X-03/D4 (2.3): the sender-wallet-signed submission tuple — every copied
    field taken verbatim from the SE body (LINT-DE-19), signed like every
    wallet confirmation (demo wallet key; production: the sender member's
    device key anchored in BW-MEMBER confirmation_key, INTF-1b)."""
    sc = {"mid": mid, "device_id": device_id}
    # R3-01: the ADDRESSES are in the signed set — they select the acceptance
    # policy, so leaving them out let the governing policy be changed without
    # invalidating this signature. The field list is lint_cli.D4_COPIED_FIELDS,
    # shared with regen_samples and LINT-DE-19: it used to be three copies.
    from lint_cli import D4_COPIED_FIELDS
    for field in D4_COPIED_FIELDS:
        sc[field] = se[field]
    sc["wallet_signature_b64"] = _wallet_sign(sc)
    return sc


def _wallet_sign(confirmation: dict) -> str:
    """Recipient wallet advanced electronic signature (the I-D (Canonicalisation and Payload Hashing), W5): a
    COSE_Sign1 over the deterministic-CBOR encoding of the FULL confirmation
    object with the
    wallet_signature_b64 field removed — the same signed-payload construction as
    the RDP seal, but under the recipient wallet's key (demo kid='wallet'). Alg is
    EdDSA(-8), within the LINT-PKG-05 allowlist."""
    payload = {k: v for k, v in confirmation.items() if k != "wallet_signature_b64"}
    b = _dcbor(payload)   # M4: the signed bytes are the dCBOR encoding
    # X-32: ONE key per (mid, device_id) — the demo seed derives from the
    # confirmation's own identity, so a signature verifies against exactly
    # one published device anchor (WALLET_SEED overrides for attacker
    # fixtures; production uses the device's provisioned key).
    seed = os.environ.get("WALLET_SEED") or \
        f"wallet:{confirmation.get('mid', '')}:{confirmation.get('device_id', '')}"
    return base64.b64encode(cose_sign(b, kid="wallet", seed=seed)).decode("ascii")


def _leaf_binding(uid: str, mid: str, device_id: str):
    """F-04 demo signed device binding: the entity seal key (demo kid
    'entity-admin', the QSealC stand-in) binds this device's MLS leaf signature
    key to (uid, mid, device_id). Returns (signature_key_hash, mls_leaf_binding
    dict). The demo leaf key is deterministic per (mid, device_id); production
    carries the device's real MLS leaf key + a QSealC-issued binding."""
    leaf_pub_b64 = demo_public_key_b64(f"leaf:{mid}:{device_id}")
    skh = hashlib.sha256(base64.b64decode(leaf_pub_b64)).hexdigest()
    content = {"uid": uid, "mid": mid, "device_id": device_id,
               "leaf_sig_pubkey_b64": leaf_pub_b64}
    cose = cose_sign(_dcbor(content), kid="entity-admin",
                     seed=os.environ.get("ENTITY_ADMIN_SEED", "entity-admin-demo"))
    return skh, {"leaf_sig_pubkey_b64": leaf_pub_b64,
                 "binding_cose_b64": base64.b64encode(cose).decode("ascii")}


def _qts_over_cose(cose_bytes: bytes, gen_time: str) -> dict:
    """Demo qualified timestamp (Regulation (EU) No 910/2014, Article 42) over the
    evidence seal: message imprint = SHA-256 of the inner COSE_Sign1 bytes (M4;
    seal first, then timestamp the seal — a sibling in the artefact envelope).
    Placeholder token — a real RDP obtains an RFC 3161 token from a qualified TSA.

    R10-X5: the token now carries its `genTime`, as a real one does —
    `SEQUENCE { OCTET STRING(32) imprint, GeneralizedTime genTime }`. It used to
    carry the imprint only, so the instant a seal was made was unobtainable in
    the pilot, and with it the instant an Evidence Package was COMPOSED — the
    act whose provider must be admitted at that instant. `gen_time` is REQUIRED:
    a stand-in that could stamp a seal without saying when is how the time went
    missing the first time. Read back by `lint_cli.parse_demo_qts`."""
    from lint_cli import instant as _inst
    at = _inst(gen_time, field="gen_time").astimezone(datetime.timezone.utc)
    imprint = hashlib.sha256(cose_bytes).digest()           # 32 bytes
    gt = at.strftime("%Y%m%d%H%M%SZ").encode("ascii")       # 15 bytes
    body = b"\x04\x20" + imprint + b"\x18" + bytes([len(gt)]) + gt
    der = b"\x30" + bytes([len(body)]) + body               # DER SEQUENCE
    return {
        "format": "rfc3161",
        "token_b64": base64.b64encode(der).decode("ascii"),
        "tsa_id": os.environ.get("QTSA_ID", "QTSA:MockEU:TS-01"),
    }


def _stamp_instant(body):
    """When the demo TSA stamps a seal: the latest instant the sealed body
    declares, so a seal is never timestamped before an act it records. Uses
    the chronological comparison R10-12 put back into `_latest_declared_instant`."""
    from lint_cli import _latest_declared_instant, instant, TimestampError
    at = _latest_declared_instant(body)
    try:
        instant(at)
        return at
    except (TimestampError, TypeError):
        # A body with no READABLE instant is invalid by construction — the
        # negative fixtures build exactly such bodies to prove the linters
        # refuse them. The stand-in TSA stamps those at a fixed demo instant
        # so they can still be sealed: the linters refuse the BODY, and the
        # stamp is not what is under test. Never reached by a valid body.
        return "2026-01-01T00:00:00Z"


def _demo_mls_group_id() -> str:
    """Generate a demo MLS group id (base64url of 16 random bytes)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")


POLICY_ID = os.environ.get("RDP_POLICY_ID", "https://rdp.example.eu/policy/qerds/1")


def _evidence_id() -> str:
    """EN 319 522-2 component G01 — unique per evidence. RFC 9562-valid
    UUID-URN syntax (F13): 32 unhyphenated hex chars are NOT a urn:uuid."""
    return "urn:uuid:" + str(uuid.uuid4())


_ORG_DIGEST_CACHE: dict = {}


def _org_doc() -> dict:
    """The BW-ORG document the demo acceptance_policy_ref points at.
    Defaults to samples/sample-BW-ORG.json; ORG_DOC overrides (the scoped
    samples use samples/sample-BW-ORG-scoped.json)."""
    path = os.environ.get("ORG_DOC", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "samples", "sample-BW-ORG.json"))
    if path not in _ORG_DIGEST_CACHE:
        with open(path, encoding="utf-8") as f:
            org = json.load(f)
        if isinstance(org, dict) and "sm_artifact_b64" in org and "projection" in org:
            org = org["projection"]  # M4: read the projection body
        payload = {k: v for k, v in org.items() if k not in ("doc_cose_b64", "seal")}
        _ORG_DIGEST_CACHE[path] = (org.get("policy_version"),
                                   hashlib.sha256(_dcbor(payload)).hexdigest())
    return _ORG_DIGEST_CACHE[path]


def _demo_policy_ref() -> dict:
    """Demo acceptance_policy_ref (BW-ORG policy version fixed at SE issuance;
    §8.3). doc_digest is the REAL SHA-256 digest of the referenced ORG
    document's signed payload — the document minus doc_cose_b64, encoded as
    deterministic CBOR, exactly the bytes the discovery seal covers — never a
    placeholder (F7, LINT-BND-10). Those are transmitted octets, so the mode is
    `raw-sha256`."""
    policy_version, digest_hex = _org_doc()
    return {
        "policy_version": os.environ.get("POLICY_VERSION", policy_version),
        # F-08 (2.4): the demo message is entity-addressed in the default
        # scope, so the deterministic selection yields the reserved key.
        "policy_key": os.environ.get("POLICY_KEY", "default"),
        "doc_digest": {
            "alg": "SHA-256",
            "hex": digest_hex,
            "hash_mode": "raw-sha256",
        },
    }


def _demo_scope_ref() -> dict:
    """Demo scope_ref (confidentiality-scope descriptor id+version in force at
    submission; D6, spec §8.3a). Defaults to the reserved 'default' scope;
    SCOPE_ID / SCOPE_VERSION override it for scoped samples."""
    return {
        "scope_id": os.environ.get("SCOPE_ID", "default"),
        "version": os.environ.get("SCOPE_VERSION", "1"),
    }


def _normalize_payload_hash(ph_in) -> dict:
    """Accept several input shapes and normalise to the {alg, hex, hash_mode} shape."""
    if not isinstance(ph_in, dict):
        return {
            "alg": "SHA-256",
            "hex": hashlib.sha256(b"").hexdigest(),
            "hash_mode": "raw-sha256"
        }
    alg = ph_in.get("alg", "SHA-256")
    # Accept either 'hex' or legacy 'value'
    hx = ph_in.get("hex") or ph_in.get("value") or hashlib.sha256(b"").hexdigest()
    hash_mode = ph_in.get("hash_mode", "raw-sha256")
    return {"alg": alg, "hex": hx.lower(), "hash_mode": hash_mode}


# --- Routes -----------------------------------------------------------------

@app.get("/.well-known/rdp")
def well_known():
    base = request.host_url.rstrip("/")
    return jsonify({
        "version": EVIDENCE_VERSION,
        "send": base + "/send",
        "evidence": base + "/evidence/{message_id}"
    })


def _envelope_hash(message_id, mls_group_id, mls_epoch):
    """envelope_hash (R-02/D3, evidence 2.2): SHA-256 over the REAL TLS-serialized
    MLSMessage octets (RFC 9420 wire object; scripts/mls_wire.py) — no synthetic
    string. Deterministic in the demo so an SE and its confirmation — sharing
    (message_id, mls_group_id, mls_epoch) — commit to the SAME value; a
    production RDP hashes the actual octets it hands to / receives from
    transport."""
    import mls_wire
    return mls_wire.envelope_hash(
        mls_wire.demo_mls_message(message_id, mls_group_id, mls_epoch))


def _mls_state(mls_group_id, mls_epoch, scope_id="default", scope_version="1"):
    """mls_state (R-02/F-03/D3, evidence 2.2): SHA-256 over the REAL
    TLS-serialized GroupContext octets (RFC 9420 §8.1) — ONE value pinning
    cipher suite, protocol version, tree/transcript hashes AND extensions
    together. F-05: the extensions carry the sbm_scope extension, so the
    commitment pins the group's scope binding too — a scoped group's state
    can never be mistaken for the default group's."""
    import mls_wire
    return mls_wire.mls_state_hash(
        mls_wire.demo_group_context(mls_group_id, mls_epoch,
                                    scope_id=scope_id,
                                    scope_version=scope_version))


class ConfirmationRejected(Exception):
    """R10-07: a typed refusal of a delivered recipient confirmation (the
    wallet-RDP `POST /confirmations` 422/409), raised before anything is
    sealed."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# R11-X1 — A CONFIRMATION IS ONE MEMBER'S ACT. R10-07 keyed confirmations on
# the message, which is right for one member and made `quorum:2` and `all`
# unreachable through the published request: the second member's valid `s3`
# was refused `confirmation-conflict`. Acts are now keyed per member of the
# ORIGINATING message namespace; the message's aggregate state is separate.
_CONFIRMATION_ACTS = {}    # (issuing_rdp_id, message_id, uid, mid[, "reveal"]) -> the act
_CONFIRMATION_STATE = {}   # (issuing_rdp_id, message_id) -> the aggregate


def confirmation_state(issuing_rdp_id, message_id):
    """The aggregate the acts produced: `open`, `satisfied` (S4 reached — at
    the instant RDP(in) observed the completing act, R11-X2) or `mismatch`
    (terminal: a verified mismatch proof ended the message)."""
    return copy.deepcopy(_CONFIRMATION_STATE.get((issuing_rdp_id, message_id)))


def _selected_policy(se, org, members):
    """The policy the SE pinned, and who may satisfy it: (policy, eligible
    MIDs). The ORG must be the version the SE's `acceptance_policy_ref`
    pins — a verifier would hold the DE to that version, so the issuer
    evaluates against it too (§8.3)."""
    from lint_cli import POLICY_RE
    ref = se.get("acceptance_policy_ref") or {}
    if not org or _org_body_digest(org) != (ref.get("doc_digest") or {}).get("hex"):
        raise ConfirmationRejected(
            "confirmation-policy-unresolvable",
            "the BW-ORG supplied is not the version the SE pins, so the policy "
            "this confirmation would count toward is not known (R11-02)")
    key = ref.get("policy_key")
    pol = (org.get("acceptance_policy") or {}).get(key)
    if not (isinstance(pol, str) and POLICY_RE.match(pol)) \
            or pol.startswith("device-class:"):
        raise ConfirmationRejected(
            "confirmation-policy-unresolvable",
            f"acceptance_policy[{key!r}] = {pol!r} is not a policy this "
            "reference evaluates (any-one | quorum:<n> | all)")
    active = [m for m in members or []
              if m.get("uid") == se.get("recipient_uid")
              and m.get("status") == "active"]
    if key == "default":
        eligible = active
    elif key in (org.get("roles") or []):
        eligible = [m for m in active if key in (m.get("roles") or [])]
    else:
        raise ConfirmationRejected(
            "confirmation-policy-unresolvable",
            f"policy key {key!r} names neither a role nor `default`")
    return pol, sorted({m["mid"] for m in eligible})


def _policy_satisfied(pol, counted, eligible):
    if pol == "any-one":
        return len(counted) >= 1
    if pol == "all":
        return bool(eligible) and set(eligible) <= set(counted)
    return len(counted) >= int(pol.split(":", 1)[1])      # quorum:<n>


def deliver_confirmation(request, *, credential, se, rdp_id, observed_at,
                         members=None, org=None):
    """`POST /confirmations` on RDP(in) — R10-07, rebuilt in round 11.

    The mismatch branch (R10-07) stands: a verified mismatch proof is the only
    way an NDE `payload-hash-mismatch` comes to exist. What round 11 found in
    this handler, and what it now does, in order:

      1. The request, against the PUBLISHED `ConfirmationDelivery`, executed.
      2. WHO — before anything stored is served (R11-03). The authenticated
         principal is a member `(uid, mid)` or device `(uid, mid, device_id)`
         of the SE's recipient entity, and it is the member (and device, where
         one is named) the confirmation names. The idempotent early return used
         to run BEFORE this, so replaying an accepted request under another
         principal returned the issued NDE.
      3. WHICH MESSAGE — `(issuing_rdp_id, message_id)`, the originating
         namespace. The request carried a bare `message_id`, so equal local ids
         from two originating providers were one message here (R11-02).
      4. ONE ACT PER MEMBER (R11-X1). An exact retry returns what the first
         returned; the same member making a different claim is a conflict.
         Distinct members no longer collide.
      5. INTF-2 — the member is an ACTIVE published member of the recipient
         entity holding an ack-capable device, the named one where named
         (`lint_cli.ack_capable_problem`, the rule the retained verifier runs).
         This handler took no member input at all: a session confirmation from
         a MID nobody published produced a sealed NDE.
      6. INTF-1a — a wallet signature is bound to the confirmation
         (`evidence_lint.wallet_signature_binding`) AND verified against the
         named device's PUBLISHED key (`lint_cli.verify_cose_signature`, the
         verifier's own boundary). Only the first half ran: a flipped signature
         byte produced a sealed NDE that the evidence linter then refused.
      7. INTF-3 — the confirmation's policy reference is the SE's.
      8. THE AGGREGATE. `s3` from a member eligible under the SE's selected
         policy counts once; the policy is satisfied — S4 — at the instant
         THIS RDP observed the completing act (R11-X2). A verified `mismatch`
         from a member of the recipient entity is terminal: the digest is
         message-wide, so it ends the message with the NDE. Acts after a
         terminal outcome are retained and change nothing; a mismatch after S4
         is dispute material, not an NDE. `refusal` and `reveal` are recorded
         and do not count.

    Nothing is stored or sealed until every check has passed. Returns the
    sealed NDE for a terminal mismatch, else None (the wallet sees 202). DE
    issuance stays on the receipt-/state-driven path.
    """
    import copy as _copy
    import importlib.util as _ilu
    from lint_cli import (ack_capable_problem, verify_cose_signature,
                          SignatureVerificationError)
    problems = validate_contract_object("wallet-rdp-openapi.yaml",
                                        "ConfirmationDelivery", request)
    if problems:
        raise ConfirmationRejected(
            "confirmation-malformed",
            f"the request does not satisfy the published "
            f"`ConfirmationDelivery`: {problems[:2]} (R10-07)")
    kind, conf = request["confirmation_kind"], request["confirmation"]

    # 2. WHO — authorisation first (R11-03).
    who = principal_of(credential, "device") or principal_of(credential, "member")
    if who is None or who[0] != se.get("recipient_uid") \
            or who[1] != conf.get("mid") \
            or (conf.get("device_id") is not None
                and (len(who) < 3 or who[2] != conf["device_id"])):
        raise ConfirmationRejected(
            "confirmation-not-member-bound",
            "the authenticated principal is not the confirming member of the "
            "message's recipient entity (and device, where one is named): "
            "INTF-1 requires the session to resolve to the member whose act "
            "this is (TS clause 6, R11-01)")

    # 3. WHICH MESSAGE — the originating namespace (R11-02).
    handle = (request["issuing_rdp_id"], request["message_id"])
    if handle != (se.get("rdp_id"), se.get("message_id")) \
            or conf.get("message_id") != se.get("message_id"):
        raise ConfirmationRejected(
            "confirmation-message-mismatch",
            "the confirmation, the request and the submission name different "
            "messages; a confirmation is about ONE message of ONE originating "
            "provider")

    # 4. ONE ACT PER MEMBER — only now may a stored answer be served.
    # A REVEAL IS NOT THAT ACT (R12-X1). `s3`, `mismatch` and `refusal` are the
    # member's one claim about delivery; a reveal is dispute material about the
    # grade and claims nothing about delivery. It shared the member's slot, so
    # a member who had refused or confirmed a message could never reveal on
    # it — refused `confirmation-conflict`, although R12-X1 accepts a reveal
    # whatever came before. The round-12 closure fixture found it: B1's test
    # had a different member reveal.
    act = handle + who[:2] + (("reveal",) if kind == "reveal" else ())
    prior = _CONFIRMATION_ACTS.get(act)
    if prior is not None:
        if prior["request"] != request:
            raise ConfirmationRejected(
                "confirmation-conflict",
                f"member {who[1]!r} already made a different confirmation for "
                f"{handle!r}; the first stands (R11-X1)")
        return _copy.deepcopy(prior["issued"])

    # R12-02 — EACH KIND ITS OWN RULES. Only `s3` and `mismatch` carry a
    # `verified_at` and an `acceptance_policy_ref`; a refusal is dated by
    # `refused_at` and a reveal by `read_at`, and their Schemas forbid the S3
    # fields. The time check and INTF-3 ran for every kind, so the shipped,
    # genuinely signed refusal and reveal were refused for a field they may not
    # carry.
    rules = CONFIRMATION_KINDS[kind]

    # 5. INTF-2.
    member = next((m for m in members or [] if m.get("uid") == who[0]
                   and m.get("mid") == who[1]), None)
    why = ("member is not published by the recipient entity" if member is None
           else f"member status is {member.get('status')!r}, not active"
           if member.get("status") != "active"
           # declining is not acknowledging: a refusing member must be active,
           # not ack-capable — the verifier's own rule (LINT-BND-29)
           else ack_capable_problem(member.get("devices") or [],
                                    conf.get("device_id")) if rules["ack"]
           else None)
    if why:
        raise ConfirmationRejected(
            "confirmation-member-ineligible",
            f"{who[1]!r} cannot confirm for {who[0]!r}: {why} (TS clause 6 "
            "INTF-2)")

    spec = _ilu.spec_from_file_location(
        "_evlint", pathlib.Path(__file__).resolve().parent / "evidence_lint.py")
    _ev = _ilu.module_from_spec(spec); spec.loader.exec_module(_ev)

    # 6. INTF-1a — bound AND verified, against the device's PUBLISHED key.
    if conf.get("wallet_signature_b64") is not None:
        bound = _ev.wallet_signature_binding(conf)
        device = next((d for d in member.get("devices") or []
                       if d.get("device_id") == conf.get("device_id")), {})
        try:
            if bound:
                raise SignatureVerificationError(
                    f"the signature does not bind this confirmation: {bound[:1]}")
            verify_cose_signature(conf["wallet_signature_b64"],
                                  device.get("confirmation_key"))
        except SignatureVerificationError as e:
            raise ConfirmationRejected(
                "confirmation-signature-invalid",
                f"the wallet signature of {who[1]!r}/{conf.get('device_id')!r} "
                f"does not verify against that device's published "
                f"confirmation_key: {e} (TS clause 6 INTF-1a)")

    # 7a. R11-X2, per kind: the act's own instant cannot follow RDP(in)'s
    # receipt of it.
    from lint_cli import instant, TimestampError
    when = rules["time"]
    try:
        future = instant(conf.get(when), field=when) > \
            instant(observed_at, field="observed_at")
    except TimestampError as e:
        raise ConfirmationRejected(
            "confirmation-time-invalid",
            f"the confirmation's {when} cannot be read: {e} (R11-04)")
    if future:
        raise ConfirmationRejected(
            "confirmation-time-invalid",
            f"{when} {conf.get(when)} is after RDP(in) received the "
            f"confirmation at {observed_at}; an act cannot be dated after its "
            "own receipt (R11-X2)")

    # 7. INTF-3 — for the kinds that carry a policy reference.
    if rules["policy_ref"] and \
            conf.get("acceptance_policy_ref") != se.get("acceptance_policy_ref"):
        raise ConfirmationRejected(
            "confirmation-policy-mismatch",
            "the confirmation's acceptance_policy_ref is not the SE's (TS "
            "clause 6 INTF-3)")

    # 7b. R12-01 — WHAT THE ACT IS ABOUT, before it is stored or counted, and
    # whatever state the message is in: the evidence it would rest on is built
    # and held to the retained verifier's own rules. An S3 was counted after
    # its signer was checked and its content never was, so two members'
    # authentic statements about ANOTHER message satisfied the quorum here
    # while LINT-DE-02/04/16 refused the result afterwards.
    candidate, found = None, []
    if kind == "s3":
        v = _ev.Violations()
        _ev.lint_s3_binding(v, conf, {k: se.get(k) for k in (
            "message_id", "payload_hash", "acceptance_policy_ref")}, se)
        found = [r for r, _m in v.items]
    elif kind == "mismatch":
        candidate = {"type": "NDE-v1", "version": EVIDENCE_VERSION,
                     "profile": "pilot", "event": "D.2-ContentConsignmentFailure",
                     "reason": "payload-hash-mismatch",
                     "evidence_id": _evidence_id(),
                     "message_id": se["message_id"],
                     "recipient_uid": se["recipient_uid"], "rdp_id": rdp_id,
                     "policy_id": se["policy_id"],
                     "payload_hash": se["payload_hash"], "observed_at": observed_at,
                     "recipient_confirmation": _copy.deepcopy(conf)}
        v = _ev.Violations()
        _ev.lint_nde_semantics(v, candidate, se=se)   # every NDE rule but the seal
        found = [r for r, _m in validate_body(candidate)] + [r for r, _m in v.items]
    elif kind == "validation-failure":
        # R23-01: the outcome a detected Mode C content failure had nowhere to
        # go. It carries NO payload_hash of the recipient's: under Mode C the
        # declared value is the digest of the manifest, so an honest
        # recomputation equals the sender's and LINT-NDE-06 refuses the NDE a
        # mismatch would have to be.
        candidate = {"type": "NDE-v1", "version": EVIDENCE_VERSION,
                     "profile": "pilot", "event": "D.2-ContentConsignmentFailure",
                     "reason": "payload-validation-failed",
                     "evidence_id": _evidence_id(),
                     "message_id": se["message_id"],
                     "recipient_uid": se["recipient_uid"], "rdp_id": rdp_id,
                     "policy_id": se["policy_id"],
                     "payload_hash": se["payload_hash"], "observed_at": observed_at,
                     "recipient_validation_failure": _copy.deepcopy(conf)}
        v = _ev.Violations()
        _ev.lint_nde_semantics(v, candidate, se=se)   # every NDE rule but the seal
        found = [r for r, _m in validate_body(candidate)] + [r for r, _m in v.items]
    elif kind == "refusal":
        candidate = {"type": "RE-v1", "version": EVIDENCE_VERSION,
                     "profile": "pilot", "event": "C.4-ConsignmentRejection",
                     "evidence_id": _evidence_id(),
                     "message_id": se["message_id"],
                     "recipient_uid": se["recipient_uid"], "rdp_id": rdp_id,
                     "policy_id": se["policy_id"], "refusal_kind": "member",
                     "reason": "refused-by-user", "mid": who[1],
                     "scope_ref": _copy.deepcopy(conf.get("scope_ref")
                                                 or se.get("scope_ref")),
                     "payload_hash": se["payload_hash"],
                     "refused_at": conf["refused_at"],
                     "refusal_confirmation": _copy.deepcopy(conf)}
        # How the RDP authenticated the refusing member is a fact of the
        # SESSION, taken from the authenticated credential as the principal
        # is — never from the request. A credential that does not say
        # (`method`, `loa`) leaves the RE without the context its Schema
        # requires, and the refusal is not recorded.
        # A member refusal is the MEMBER's act (the assurance table admits
        # `member` for it), whether the session was bound to the member or
        # to one of its devices.
        candidate["auth_context"] = {
            "identity": "member", "mid": who[1],
            **{f: credential[f] for f in ("method", "loa") if credential.get(f)}}
        v = _ev.Violations()
        _ev.lint_re_semantics(v, candidate)           # every RE rule but the seal
        found = [r for r, _m in validate_body(candidate)] + [r for r, _m in v.items]
    else:                                              # reveal
        found = ["LINT-GCM-01"] if _ev.reveal_binding(conf, se) else []
    if found:
        raise ConfirmationRejected(
            "confirmation-rejected",
            f"the {kind} is not about this message: the evidence it would rest "
            f"on fails {sorted(set(found))} — nothing is stored or sealed "
            "(R12-01/R12-02)")

    # 8. THE AGGREGATE — R11-X1 and R12-X1. `s3` counts; a verified `mismatch`,
    # `validation-failure` or `refusal` is terminal and issues its evidence; a
    # `reveal` changes nothing. Acts after a terminal outcome are retained and
    # change nothing.
    pol, eligible = _selected_policy(se, org, members)
    state = _CONFIRMATION_STATE.get(handle) or {
        "state": "open", "at": None, "counted": [], "policy": pol}
    issued = None
    if state["state"] == "open":
        if kind in ("mismatch", "refusal", "validation-failure"):
            issued = evidence_artifact(candidate, kid="rdp")
            state = dict(state, state=rules["terminal"], at=observed_at)
        elif kind == "s3" and who[1] in eligible:
            counted = state["counted"] + [who[1]]
            state = dict(state, counted=counted)
            if _policy_satisfied(pol, counted, eligible):
                state = dict(state, state="satisfied", at=observed_at)
    _CONFIRMATION_STATE[handle] = state
    _CONFIRMATION_ACTS[act] = {"request": _copy.deepcopy(request),
                               "issued": _copy.deepcopy(issued),
                               "kind": kind, "observed_at": observed_at}
    return issued


# R12-X1 — each confirmation kind's time field, eligibility and effect. The
# `ack` column is INTF-2's device half; `policy_ref` says whether the kind
# carries INTF-3's reference; `terminal` names the state a verified act of
# that kind ends the message in.
CONFIRMATION_KINDS = {
    "s3":       {"time": "verified_at", "ack": True,  "policy_ref": True,  "terminal": None},
    "mismatch": {"time": "verified_at", "ack": True,  "policy_ref": True,  "terminal": "mismatch"},
    # R23-01. Terminal like a mismatch and for the same reason — the failure is
    # message-wide — but a DIFFERENT claim: a mismatch asserts a comparison that
    # was made, this asserts that none could be.
    "validation-failure": {"time": "verified_at", "ack": True, "policy_ref": True,
                           "terminal": "validation-failed"},
    "refusal":  {"time": "refused_at",  "ack": False, "policy_ref": False, "terminal": "refused"},
    "reveal":   {"time": "read_at",     "ack": False, "policy_ref": False, "terminal": None},
}


def make_evidence(data: dict) -> dict:
    """Build a demo Evidence Package with object-level sealed SE/DE and an EP seal.
    Pure (no Flask request context) so it is unit-testable."""
    from_uid = data.get("from_uid")
    to_uid = data.get("to_uid")
    payload_hash = _normalize_payload_hash(data.get("payload_hash"))
    mls_group_id = data.get("mls_group_id") or _demo_mls_group_id()
    mls_epoch = str(int(data.get("mls_epoch", 0)))  # I-JSON: uint64 epoch as a decimal string (M1)
    auth_method = data.get("auth_method", "mls-x509")
    if auth_method not in (
        "mls-x509", "mls-uid-qeaa", "mls-x509+oidc4vp", "mls-uid-qeaa+oidc4vp",
        "two-factor", "wallet-eid-high", "wallet-eid-substantial",
        "mtls-ncp", "ncp-signature", "cab-confirmed",
    ):
        auth_method = "mls-x509"
    recipient_auth_method = data.get("recipient_auth_method", "wallet-eid-high")
    if recipient_auth_method not in (
        "mfa", "wallet-eid-high", "wallet-eid-substantial", "qes-qseal-cert", "cab-confirmed",
    ):
        recipient_auth_method = "wallet-eid-high"

    msg_id = data.get("message_id") or (
        "msg-" + hashlib.sha1((str(from_uid) + str(to_uid) + now_iso()).encode()).hexdigest()[:12]
    )
    rdp_id = os.environ.get("RDP_ID", "urn:sbm:rdp:mockeu-001")
    env_hash = _envelope_hash(msg_id, mls_group_id, mls_epoch)   # finding 2 (2.1)
    mstate = _mls_state(mls_group_id, mls_epoch)                 # finding 3 (2.1)

    sent = now_iso()
    # R1 (finding): expires_at is the authenticated absolute deadline the wallet
    # computes as sent_at + ttl (the envelope ttl, default 3 days here) and supplies
    # with the submission metadata; the RDP echoes it into the SE.
    ttl_s = int(data.get("ttl", 259200))
    expires = (datetime.datetime.fromisoformat(sent.replace("Z", "+00:00"))
               + datetime.timedelta(seconds=ttl_s)).replace(
                   microsecond=0).isoformat().replace("+00:00", "Z")
    se = {
        "type": "SE-v1",
        "version": EVIDENCE_VERSION,
        "profile": "pilot",
        "message_id": msg_id,
        "event": "A.1-SubmissionAcceptance",
        "evidence_id": _evidence_id(),
        "policy_id": POLICY_ID,
        "acceptance_policy_ref": _demo_policy_ref(),
        "scope_ref": _demo_scope_ref(),
        "sender_uid": from_uid,
        # R3-01: explicit addressing. The demo chain is entity-addressed, and
        # that is now WRITTEN DOWN rather than reached by omitting the field.
        "sender_addr": f"bw:uid:{from_uid}",
        "recipient_uid": to_uid,
        "recipient_addr": f"bw:uid:{to_uid}",
        "transport": "SM-MLS-1.0",
        "mls_group_id": mls_group_id,
        "mls_epoch": mls_epoch,
        "auth_method": auth_method,
        "auth_context": {
            "identity": "entity",
            "method": auth_method,
            "loa": "substantial"
        },
        "payload_hash": payload_hash,
        "envelope_hash": env_hash,
        "mls_state": mstate,
        "sent_at": sent,
        "expires_at": expires,
        "rdp_id": rdp_id,
        # X-03/D4 (2.3): the default posture is sender-signed — the demo sender
        # member's wallet signs the full submission tuple (incl. the byte-exact
        # commitments); provider-attested is the explicitly-narrowed fallback.
        "origin_proof": "sender-signed"
    }
    se["sender_confirmation"] = _sender_confirmation(se, data.get("sender_mid", "A1B2C3D4R"),
                                                     data.get("sender_device_id", "dev-01"))
    # M4: build the authoritative artefact (COSE over dCBOR(body) + qts).
    se_art = evidence_artifact(se)

    de = {
        "type": "DE-v1",
        "version": EVIDENCE_VERSION,
        "profile": "pilot",
        "message_id": msg_id,
        "event": "E.1-ContentHandover",
        "evidence_id": _evidence_id(),
        "policy_id": POLICY_ID,
        "acceptance_policy_ref": _demo_policy_ref(),
        "scope_ref": _demo_scope_ref(),
        "recipient_uid": to_uid,
        "delivered_at": now_iso(),
        "rdp_id": rdp_id,
        "recipient_auth_method": recipient_auth_method,
        "acceptance_policy_kind": "any-one",
        "delivery_grade": "verification",
        "integrity_basis": "recipient-verified-digest",
        "auth_context": {
            "identity": "member",
            "method": recipient_auth_method,
            "loa": "very-high"
        },
        "s3_attestation": {
            "mid": data.get("mid", "A1B2C3D4R"),
            "hash_verified": True,
            "verified_at": now_iso(),
            "message_id": msg_id,
            "mls_group_id": mls_group_id,
            "mls_epoch": mls_epoch,
            "mls_state": mstate,
            "envelope_hash": env_hash,
            "acceptance_policy_ref": _demo_policy_ref(),
            "payload_hash": payload_hash,
            "result": "match",
            "session_authenticated": True,
            # X-05 (2.3): the demo session confirmation retains its verifiable
            # binding — a bare boolean cannot claim member-grade proof
            # (LINT-DE-20); a real provider digests the actual session token.
            "session_binding": {
                "kind": "token-digest",
                "digest": hashlib.sha256(
                    f"demo-session-token:{msg_id}".encode()).hexdigest()
            }
        },
        "payload_hash": payload_hash
    }
    de_art = evidence_artifact(de)

    # M4: the EP body embeds the sub-ARTEFACTS (bstr); its projection nests the
    # sub-bodies. The EP's own seal covers the bundle-of-artefacts.
    ep_fields = {
        "type": "EP-v1",
        "version": EVIDENCE_VERSION,
        "message_id": msg_id,
        "rdp_chain": [{"rdp_id": rdp_id, "timestamp": now_iso()}],
    }
    return ep_artifact(ep_fields, se_art, [de_art])


@app.post("/send")
def send():
    data = request.get_json(force=True) or {}
    ep = make_evidence(data)
    # `make_evidence` returns the sealed ARTEFACT — {sm_artifact_b64, projection}
    # — since the octet-authoritative inversion, so the identifier is read from
    # the projection. Reading it from the artefact raised KeyError and returned
    # 500 for the request the README's own quickstart prints; the two sibling
    # handlers below were already written for the artefact shape, which is why
    # only this one broke. `tests/test_readme_quickstart.py` runs that sequence.
    msg_id = ep["projection"]["message_id"]
    app.config.setdefault("EVID", {})[msg_id] = ep
    base = request.host_url.rstrip("/")
    return jsonify({
        "message_id": msg_id,
        "evidence_url": base + "/evidence/" + msg_id,
        "evidence_cbor_url": base + "/evidence/" + msg_id + ".cbor"
    })


@app.get("/evidence/<msg_id>")
def evidence(msg_id):
    ep = app.config.get("EVID", {}).get(msg_id)
    if not ep:
        return jsonify({"error": "not found"}), 404
    return jsonify(ep)


@app.get("/evidence/<msg_id>.cbor")
def evidence_cbor(msg_id):
    ep = app.config.get("EVID", {}).get(msg_id)
    if not ep:
        return jsonify({"error": "not found"}), 404
    # M4: the authoritative artefact is the CBOR dCBOR([cose, qts]).
    b64 = ep.get("sm_artifact_b64")
    raw = base64.b64decode(b64) if b64 else b""
    return Response(raw, mimetype="application/cbor")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
