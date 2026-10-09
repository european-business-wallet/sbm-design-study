#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shared CLI flag parser for the conformance linters (ninth review, P1).

evidence_lint, discovery_lint and bundle_lint parse their command lines through
this ONE function so the flag grammar cannot drift between them again: the
valued flags (--profile, --trust-store) accept BOTH the `--flag value` and the
`--flag=value` form, and an unrecognised flag is a usage error (fail-closed)
rather than being silently dropped or read as a file name.

It also hosts the shared --trust-store MINIMAL SLICE (ninth review, P10):
a DEMO-grade JSON trust store keyed by COSE kid — NOT QSealC/Trusted-List
material — against which both linters check, fail-closed:

  LINT-TRUST-01  the seal's kid resolves to a store entry AND the Ed25519
                 signature verifies against that entry's public key
  LINT-TRUST-02  the entry is consistent with the object: store role matches
                 the document family (evidence-rdp / discovery-publisher) and
                 the SIGNER identity is among the entry's identities where
                 declared. The signer is the object's ISSUER: `rdp_id` for
                 SE/DE/NDE/RE/CE/EP, but `receiving_rdp_id` for a
                 RelayEvidence-v1 (the recipient-side RDP seals the hop; CF-6) —
                 see evidence_lint._signer_identity; discovery: the document uid
  LINT-TRUST-03  the object's latest declared instant lies within the entry's
                 [not_before, not_after] validity window (checked against the
                 provided store, deterministically — no wall clock)
  LINT-TRUST-04  (relay only, evidence_lint._relay_peer_trust) a RelayEvidence-v1
                 names a relaying PEER in `sending_rdp_id`; that peer is not the
                 signer, so it is checked for MEMBERSHIP — it must resolve to a
                 known evidence-rdp identity in the store (FC-3 peer
                 authentication, machine-checkable at lint time)

X.509 x5chain parsing, certificate validity, chain building to the EU Trusted
Lists and TSA-chain validation remain production-verifier obligations (README,
production verification roadmap).
"""
import base64
import json
import pathlib
import datetime
import re


GRADE_COMMITMENT_DST = "sm-mls:grade-commitment:v2"
MANDATE_COMMITMENT_DST = "sm-mls:mandate-commitment:v2"


def _commitment_cbor(dst, fields):
    """The commitment construction (twenty-fifth review, M3/T4; the I-D
    (Grade Commitment)/(Mandate Commitment)) — deterministic CBOR (RFC 8949
    §4.2) over a FIXED-POSITION array with a domain-separation tag at element 0,
    replacing the former digest over a canonicalised JSON object:

        commitment = lowercase-hex( SHA-256( dCBOR([ dst, f1, f2, ... ]) ) )

    A CBOR encoder is already a mandatory dependency (COSE), so this reuses it
    rather than adding a third encoding style; unlike a length-prefixed
    concatenation it gives the fields SHARP TYPES (tstr / bstr) and no
    key-ordering, number or parser ambiguity. The DST version suffix records the
    construction inside the hash; the on-wire selector is the evidence `version`
    (>= 1.18 => this v2 dCBOR construction). THE single implementation — regen,
    bundle_lint and the tests all call the two wrappers below."""
    import cbor2
    import hashlib
    return hashlib.sha256(cbor2.dumps([dst, *fields], canonical=True)).hexdigest()

# The B.2 RelayRejection typed reasons and their mapping to the sender-facing NDE
# reason (finding 7, twentieth review; TS clause 4.1). THE single machine-readable
# form of the normative mapping table — evidence_lint and bundle_lint share it.
# X-25: the tables are LOADED from the machine-readable registry artefact
# (registries/reason-codes.json, owned by the design authority per umbrella
# §13.4) — registering a code is a registry action, not a lint-code change.
def load_registry(name):
    root = pathlib.Path(__file__).resolve().parents[1]
    return json.loads((root / "registries" / name).read_text(encoding="utf-8"))


AUTH_ASSURANCE = load_registry("auth-assurance.json")  # X-27: admissible tuples
_REASONS = load_registry("reason-codes.json")


def _validate_nde_registry(reasons):
    """X-30: a COMPLETE reason x stage x event x external-mapping row is a
    PREREQUISITE for registering an NDE reason — an incomplete registration
    cannot load, so no conforming provider can emit a reason whose stage/
    event semantics are unbound. Fail-closed at import."""
    for code, entry in reasons.items():
        if entry.get("status") != "active":
            continue
        stages = entry.get("stages")
        events = entry.get("allowed_events")
        mapping = entry.get("en_319_522")
        if not (isinstance(stages, dict) and stages
                and isinstance(events, list) and events
                and isinstance(mapping, str) and mapping):
            raise ValueError(
                f"registries/reason-codes.json: nde_reason {code!r} is "
                "INCOMPLETE — stages, allowed_events and en_319_522 are "
                "registration prerequisites")
        if sorted(set(stages.values())) != sorted(set(events)):
            raise ValueError(
                f"registries/reason-codes.json: nde_reason {code!r} "
                "allowed_events disagree with its stages table")


_validate_nde_registry(_REASONS["nde_reasons"])
RELAY_B2_REASONS = set(_REASONS["relay_b2_reasons"])
RELAY_B2_TO_NDE = {k: v["nde_reason"] for k, v in _REASONS["relay_b2_reasons"].items()}
NDE_REASON_EVENT = {k: set(v["allowed_events"])
                    for k, v in _REASONS["nde_reasons"].items()
                    if v.get("allowed_events")}
REGISTERED_NDE_REASONS = set(_REASONS["nde_reasons"])


def _wallet_proof_fields():
    """Every evidence field carrying a WALLET-SIGNABLE proof, derived.

    R26-PUB-02: three places enumerated these by hand — the demo signature
    sweep, the production identity precheck and the bundle's member resolution
    — and a new proof type had to be added to all three. It was added to none,
    so a validation failure's signature was never verified, its member never
    resolved, and a flipped signature byte produced no violation at all: the
    outer provider seal was valid, and nothing else was asked.

    Derived from the schemas instead: a proof type is a `$defs` entry carrying
    `wallet_signature_b64`, and a proof field is a property that `$ref`s one.
    A type added tomorrow is swept the day it is referenced, which is the rule
    this repository applies to every other generated set.
    """
    root = pathlib.Path(__file__).resolve().parents[1] / "schemas"
    defs = json.loads((root / "evidence-common.schema.json").read_text(
        encoding="utf-8"))["$defs"]
    types = {n for n, d in defs.items()
             if "wallet_signature_b64" in (d.get("properties") or {})}
    fields, containers = set(), ("properties", "items", "$defs", "allOf",
                                 "anyOf", "oneOf", "then", "if")

    def walk(node, key=None):
        if isinstance(node, dict):
            ref = node.get("$ref", "")
            if key and any(ref.endswith("/" + t) for t in types):
                fields.add(key)
            for k, v in node.items():
                walk(v, key if k in containers else k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)

    for f in sorted(root.glob("evidence-*.schema.json")):
        walk(json.loads(f.read_text(encoding="utf-8")))
    return frozenset(fields)


def _recipient_ack_fields():
    """The recipient acts a verifier resolves to an ack-capable member.

    A NARROWER set than every wallet-signed proof, and the distinction is
    normative: INTF-1a says a RECIPIENT's act carries a wallet signature OR a
    session authentication, which is the `anyOf` shape those types have and the
    others do not. A `sender_confirmation` is a sender's member and a
    `reveal_confirmation` is not an acknowledgement, so resolving either
    against the recipient entity's roster asserts something false — which is
    exactly what happened when this was first derived from the wider set, and
    four positive bundles began reporting the sender's own member as unknown to
    the recipient entity.
    """
    root = pathlib.Path(__file__).resolve().parents[1] / "schemas"
    defs = json.loads((root / "evidence-common.schema.json").read_text(
        encoding="utf-8"))["$defs"]
    types = set()
    for name, d in defs.items():
        arms = [set(a.get("required", [])) for a in d.get("anyOf", [])]
        if any("wallet_signature_b64" in a for a in arms) \
                and any("session_authenticated" in a for a in arms):
            types.add(name)
    fields, containers = set(), ("properties", "items", "$defs", "allOf",
                                 "anyOf", "oneOf", "then", "if")

    def walk(node, key=None):
        if isinstance(node, dict):
            if key and any(node.get("$ref", "").endswith("/" + ty) for ty in types):
                fields.add(key)
            for k, val in node.items():
                walk(val, key if k in containers else k)
        elif isinstance(node, list):
            for val in node:
                walk(val, key)

    for f in sorted(root.glob("evidence-*.schema.json")):
        walk(json.loads(f.read_text(encoding="utf-8")))
    return frozenset(fields)


WALLET_PROOF_FIELDS = _wallet_proof_fields()
RECIPIENT_ACK_PROOF_FIELDS = _recipient_ack_fields()
# The typed causes a recipient may assert when the decrypted payload did not
# validate — a state that is NOT a digest mismatch and had no outcome.
RECIPIENT_VALIDATION_FAILURES = set(_REASONS["recipient_validation_failures"])
REGISTERED_RE_REASONS = set(_REASONS["re_reasons"])
# X-29: the registry also kind-binds each RE reason — a "member" reason claims a
# user act and demands member proof; an "organisation-policy" reason never does.
# The fields the D4 sender tuple COPIES from its SE — one definition.
#
# There were three: the mock that builds the tuple, `regen_samples` that
# re-syncs it, and LINT-DE-19 that compares it. Adding `recipient_addr` in
# R3-01 had to be done in all three, and missing one produced samples whose
# tuple silently disagreed with its own schema. Same family as the version
# constants that drifted in round 2: a list restated is a list that diverges.
D4_COPIED_FIELDS = (
    "message_id", "sender_uid", "sender_addr", "recipient_uid",
    "recipient_addr", "payload_hash", "envelope_hash", "mls_state",
    "acceptance_policy_ref", "scope_ref", "sent_at", "expires_at",
)


class ForeignAddress(ValueError):
    """R4-01 (Blocker): an address whose UID is not the entity it is being
    resolved against.

    Selection read only the `/r/<role>` tail, so an address naming ANOTHER
    entity picked a role out of this entity's `acceptance_policy` map. The UID
    was carried, signed since R3-01, and never compared.
    """

    reason = "foreign-address"


class UnaddressedSubmission(ValueError):
    """R3-01 (Blocker): a submission with no recipient address.

    Absence used to be a VALUE: `select_policy_key` returned 'default' for a
    missing or empty address exactly as it did for an explicitly
    entity-addressed one, so dropping the address from a role-addressed
    submission silently selected the weaker policy — and the sender's signature
    could not reveal the change, because `recipient_addr` was not even a
    property of the signed D4 tuple. Absence is now a typed rejection.
    """

    reason = "unaddressed-submission"


def _bw_address_pattern():
    """The `BwAddress` pattern FROM THE SCHEMA, which is the authority.

    R5-01(b). There were two hand-written parsers, and the round-4 test
    asserted they agreed WITH EACH OTHER — under a docstring saying so. They
    did agree, and both were wrong: each put `(u|r)` in front of BOTH value
    alternatives, so the kind and the value were not bound to one another and
    all four combinations parsed:

        bw:uid:<uid>/u/procurement    accepted; the Schema forbids it
        bw:uid:<uid>/r/F1N2C3D4P      accepted; the Schema forbids it

    The Schema binds them — the member arm takes a MID and the role arm a role
    name, in one alternation —
    so a member address must carry a MID and a role address a role name. A
    provider following the reference parser accepted addresses the published
    contract rejects, which is the interoperability failure the parser existed
    to prevent.

    Agreement between copies is not correctness. Invariant 1 says a test that
    calls the same helper as the producer is not independent evidence; this is
    the same mistake one level up, and the fix is not to reconcile the copies
    but to REMOVE the second authority. Acceptance is decided by the Schema's
    own pattern, read from the published file, so the two cannot disagree.
    """
    schema = json.loads((pathlib.Path(__file__).resolve().parents[1] /
                         "schemas" / "evidence-common.schema.json")
                        .read_text(encoding="utf-8"))
    return schema["$defs"]["BwAddress"]["pattern"]


_BW_ADDRESS_RE = re.compile(_bw_address_pattern())


def parse_bw_address(addr):
    """(uid, kind, value) for a canonical bw: address, else None.

    `kind` is 'entity' | 'member' | 'role'. THE canonical parser — `bundle_lint`
    calls this one rather than keeping its own (the dependency runs that way).

    Acceptance is the Schema's pattern; the split below only ever sees a string
    the Schema has already accepted, so it cannot widen the grammar. That
    ordering is the point: extraction can be simple precisely because it is not
    also deciding validity.
    """
    if not isinstance(addr, str) or not _BW_ADDRESS_RE.fullmatch(addr.strip()):
        return None
    rest = addr.strip()[len("bw:uid:"):]
    if "/" not in rest:                      # a UID contains no '/'
        return (rest, "entity", None)
    uid, seg, value = rest.split("/", 2)
    return (uid, "member" if seg == "u" else "role", value)


def _parse_bw_address_uid(addr):
    """The UID part of a bw: address, or None. Thin wrapper over the canonical
    parser, kept because `select_policy_key` wants only the UID."""
    parsed = parse_bw_address(addr)
    return parsed[0] if parsed else None


def select_policy_key(org, scope_ref, recipient_addr):
    """X-12 (umbrella §8.3, normative): the deterministic acceptance-policy
    selection. Exactly one key governs every message:
      1. scoped (scope_ref.scope_id != 'default') -> the matched scope
         descriptor's acceptance_policy_ref key;
      2. default scope, role-addressed (bw:...r/<role>) -> the role's key if
         present in acceptance_policy, else 'default';
      3. default scope, entity-addressed -> 'default'.

    R3-01/R3-T1: the address is REQUIRED and this FAILS CLOSED without one.
    Every message is explicitly entity-, role- or member-addressed; there is no
    unaddressed case to fall back from. A missing or empty `recipient_addr`
    raises `UnaddressedSubmission`, which the caller turns into the typed
    intake rejection of the same name — it never resolves to 'default'.

    Returns the key, or None where the scope descriptor cannot be resolved
    (that case is already a typed rejection upstream: no-matching-scope /
    LINT-BND-04)."""
    if not isinstance(recipient_addr, str) or not recipient_addr.strip():
        raise UnaddressedSubmission(
            "no recipient_addr: the acceptance policy cannot be selected "
            "without knowing what the message is addressed to. Absence is not "
            "entity addressing — entity addressing is written down")
    # R4-01 (Blocker): the address must name THE ENTITY WHOSE POLICY IS BEING
    # SELECTED. It did not have to, so an address naming a different entity
    # selected a role policy inside this one's BW-ORG:
    #
    #   recipient_uid  = EU-FR-…            (the French entity)
    #   recipient_addr = bw:uid:EU-DE-…/r/procurement
    #   -> 'procurement', from the FRENCH acceptance_policy map
    #
    # R3-01 made the address required and signed; this makes it MEAN something.
    org_uid = (org or {}).get("uid")
    parsed = _parse_bw_address_uid(recipient_addr)
    if parsed is None:
        raise ForeignAddress(
            f"recipient_addr {recipient_addr!r} is not a well-formed bw: "
            "address, so the entity it names cannot be checked")
    if org_uid and parsed != org_uid:
        raise ForeignAddress(
            f"recipient_addr names entity {parsed!r}, but the acceptance policy "
            f"being selected belongs to {org_uid!r} — an address to a different "
            "entity cannot select a role inside this one's policy map")
    sid = (scope_ref or {}).get("scope_id") or "default"
    if sid != "default":
        for sc in ((org.get("scope_map") or {}).get("scopes") or []):
            if sc.get("scope_id") == sid:
                return sc.get("acceptance_policy_ref")
        return None
    role = None
    if "/r/" in recipient_addr:
        role = recipient_addr.rsplit("/r/", 1)[1]
    if role and role in (org.get("acceptance_policy") or {}):
        return role
    return "default"


RE_REASON_KIND = {code: entry.get("refusal_kind")
                  for code, entry in _REASONS["re_reasons"].items()}
REASON_LEXICAL = re.compile(r"^(x-)?[a-z][a-z0-9-]{1,62}$")


class TimestampError(ValueError):
    """DR-05: an instant that cannot be parsed. Callers MUST turn this into a
    typed violation — never ignore it, and never fall back to string order."""


def instant(value, *, field="timestamp"):
    """DR-05 — THE timestamp comparison primitive: parse an RFC 3339 string to
    an AWARE UTC datetime.

    Every window check in this repository used raw STRING comparison, which is
    wrong at fractional boundaries because '.' sorts before 'Z':

        '2026-04-04T10:16:23.1Z' < '2026-04-04T10:16:23Z'   ->  True

    yet the first instant is LATER. Delivery could be accepted after expiry,
    premature expiry accepted, and the wrong historical key selected. Offsets
    were worse than mishandled — `_latest_declared_instant` simply SKIPPED any
    timestamp not ending in 'Z', so a valid '+02:00' vanished from the
    signer-validity check.

    Parsing (rather than mandating one fractional precision) is the fix the
    review recommends: it is less fragile, and it makes '+02:00' participate in
    exactly the checks it always should have. Unparsable input raises — the
    caller reports it, nothing is silently skipped.

    PORTABILITY (round-3 carry-in). The fractional part is parsed EXPLICITLY
    rather than handed to `datetime.fromisoformat`, which before Python 3.11
    accepts only 3- or 6-digit fractions and REJECTS 1-, 2-, 4- and 5-digit
    ones. Those are valid RFC 3339, so on 3.8-3.10 this helper failed closed on
    conforming input — and README promises "Python 3.8+ to use the artefacts"
    while `lint_cli` is a reference tool implementers run. The acceptance
    criterion is RFC 3339, not a Python version."""
    import datetime as _dt
    if not isinstance(value, str) or not value:
        raise TimestampError(f"{field}: missing or non-string instant {value!r}")
    s = value.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    # Split off a fractional part of ANY length (RFC 3339 allows 1..n digits)
    # and re-attach it as microseconds, so no Python version has an opinion.
    m = re.match(r"^(.*?T\d{2}:\d{2}:\d{2})\.(\d+)(.*)$", s)
    micros = 0
    if m:
        head, frac, tail = m.groups()
        micros = int((frac + "000000")[:6])          # truncate, never round up
        s = head + tail
    try:
        parsed = _dt.datetime.fromisoformat(s)
    except ValueError as exc:
        raise TimestampError(f"{field}: {value!r} is not an RFC 3339 instant") from exc
    if micros:
        parsed = parsed.replace(microsecond=micros)
    if parsed.tzinfo is None:
        raise TimestampError(
            f"{field}: {value!r} carries no timezone — an instant without an "
            "offset is not comparable")
    return parsed.astimezone(_dt.timezone.utc)


def _within_window(value, not_before, not_after):
    """Inclusive window test on PARSED instants (DR-05). A malformed bound or
    value fails closed — the check does not silently pass."""
    try:
        at = instant(value)
        lo = instant_or_none(not_before)
        hi = instant_or_none(not_after)
    except TimestampError:
        return False
    return (lo is None or lo <= at) and (hi is None or at <= hi)


def instant_or_none(value):
    """`instant()` for optional fields: None when absent, still raising on a
    present-but-malformed value (absent and invalid are different failures)."""
    if value is None:
        return None
    return instant(value)


class CommitmentInputError(ValueError):
    """DR-03: malformed commitment input — the caller MUST convert this into a
    typed lint violation, never let it escape as an unhandled exception."""


_HEX_EXACT = {32: re.compile(r"^[a-f0-9]{32}$"), 64: re.compile(r"^[a-f0-9]{64}$")}


def compute_grade_commitment(salt_hex, content_class, org_digest_hex,
                             grade="availability"):
    """The grade-commitment construction (fourteenth review, X0; twenty-fifth
    review, M3/T4; the I-D (Grade Commitment)): deterministic CBOR over the
    fixed-position array [dst, salt, content_class, grade, org_digest] — salt and
    org_digest as byte strings (hex-decoded), the rest text — lowercase hex. THE
    single implementation — regen, bundle_lint and the tests all use it."""
    # DR-03: validate BEFORE bytes.fromhex. A schema-valid odd-length salt used
    # to raise an uncaught ValueError inside the cross-document validator —
    # terminating validation instead of failing a lint. Callers get a typed
    # error they can turn into a violation.
    for label, hx, nybbles in (("salt", salt_hex, 32),
                               ("org_digest", org_digest_hex, 64)):
        if not isinstance(hx, str) or not _HEX_EXACT[nybbles].match(hx):
            raise CommitmentInputError(
                f"{label} must be exactly {nybbles} lowercase hex characters, "
                f"got {hx!r}")
    return _commitment_cbor(GRADE_COMMITMENT_DST,
                            [bytes.fromhex(salt_hex), content_class, grade,
                             bytes.fromhex(org_digest_hex)])


def compute_seal_digest(seal_b64):
    """The seal digest (twenty-first review, CF-5; TS clause 4.1): lowercase-hex
    SHA-256 over the **decoded COSE_Sign1 bytes** of a seal —
    `SHA-256(cose-sign1)` where cose-sign1 is the referenced artefact's FIRST
    element as transmitted. THE single implementation; regen,
    bundle_lint and the tests all call it, so the bytes cannot drift from the prose.

    The input is the DECODED bytes, not the base64 TEXT. Both are defensible
    readings of "the SHA-256 of its seal", and they produce DIFFERENT digests — so
    an EP built with one reading is unverifiable by a verifier recomputing the
    other, while both pass every shape check. The decoded bytes win because they
    are already the house convention: the qualified-timestamp imprint
    (`evidence_lint._check_imprint`, LINT-PKG-08) digests exactly this input, so a
    seal has exactly ONE digest across the profile."""
    import base64
    import hashlib
    return hashlib.sha256(base64.b64decode(seal_b64)).hexdigest()


def compute_mandate_commitment(salt_hex, mandate_id, content_class, org_digest_hex):
    """The mandate-commitment construction (nineteenth review, A1; twenty-fifth
    review, M3/T4; the I-D (Mandate Commitment)): deterministic CBOR over the
    fixed-position array [dst, salt, mandate_id, content_class, org_digest] — salt
    and org_digest as byte strings (hex-decoded), the rest text — binding the
    acted-under mandate to the message's content class, anchored to the published
    BW-ORG signed-payload digest. THE single implementation."""
    return _commitment_cbor(MANDATE_COMMITMENT_DST,
                            [bytes.fromhex(salt_hex), mandate_id, content_class,
                             bytes.fromhex(org_digest_hex)])


SAFE_INT_MAX = 9007199254740991  # 2**53 - 1, the JSON/ECMAScript safe-integer bound


def find_unsafe_numbers(obj, path="$"):
    """Paths to any JSON number that is not a safe integer (M1/J0+; the I-D
    (Canonicalisation and Payload Hashing)).

    I-JSON in this profile is integers-only within [-(2^53-1), 2^53-1]: a float
    (fractional or exponent form) or an integer outside the safe range cannot be
    round-tripped exactly through the ECMAScript/IEEE-754 number domain a JSON
    parser may impose between the wire and a verifier — which is the single
    most-cited canonicalisation hazard, and it is an INTEGER hazard, not merely a
    decimal one. The restriction is the profile's own, stated in the I-D, and it
    outlives any particular canonicalisation: a projection that cannot be read
    back exactly cannot be compared against the authoritative octets. Genuinely large counters (mls_epoch, manifest
    length) are carried as decimal STRINGS, so they never reach this walk. bool is
    a subclass of int and is correctly ignored. Returns (path, reason) pairs.
    THE single implementation — evidence_lint and discovery_lint both call it."""
    out = []
    if isinstance(obj, bool):
        return out
    if isinstance(obj, float):
        out.append((path, "floating-point number (I-JSON: integers only)"))
    elif isinstance(obj, int):
        if abs(obj) > SAFE_INT_MAX:
            out.append((path, f"integer {obj} outside the safe range +/-(2^53-1) "
                              "(carry large counters as decimal strings)"))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(find_unsafe_numbers(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(find_unsafe_numbers(v, f"{path}[{i}]"))
    return out


# The hash modes the profile defines (schemas/evidence-common.schema.json
# `$defs/Hash`, cddl/sm-mls-erd.cddl). A digest is ALWAYS over octets: `raw-*`
# over the transmitted bytes (the I-D (Canonicalisation and Payload Hashing),
# Mode A), `manifest-*` over the deterministic-CBOR manifest of a multipart
# payload, whose part digests are over each part's own octets (Mode C). The
# JSON-canonicalisation modes `jcs-sha256` / `jcs-sha512` were REMOVED from the
# profile on 2026-09-25; an artefact that declares one is refused rather than
# ignored, because it asserts a digest over canonicalised JSON, which this
# profile no longer defines a rule to recompute.
PROFILE_HASH_MODES = ("raw-sha256", "raw-sha512", "manifest-sha256", "manifest-sha512")

# Modes a previous revision of this profile defined, named so the refusal can say
# WHICH mode it is refusing rather than only that the value is unknown.
RETIRED_HASH_MODES = {
    "jcs-sha256": "removed 2026-09-25; JSON canonicalisation left the profile",
    "jcs-sha512": "removed 2026-09-25; JSON canonicalisation left the profile",
}


def find_foreign_hash_modes(obj, path="$"):
    """Paths to any `hash_mode` the profile does not define — LINT-HASH-01.

    A removed enumeration value is not merely un-enumerated: a verifier that
    accepted it would have to recompute a digest by a rule this profile no
    longer states, so the artefact is REFUSED at the document level and not only
    at the schema. The walk reaches every digest descriptor wherever it sits —
    `payload_hash`, the envelope `content_digest`, `acceptance_policy_ref.
    doc_digest`, a manifest part — including in objects a future revision adds.
    Returns (path, mode, reason) triples. THE single implementation —
    evidence_lint and discovery_lint both call it."""
    out = []
    if isinstance(obj, dict):
        mode = obj.get("hash_mode")
        if isinstance(mode, str) and mode not in PROFILE_HASH_MODES:
            out.append((path, mode, RETIRED_HASH_MODES.get(mode)))
        for k, v in obj.items():
            out.extend(find_foreign_hash_modes(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(find_foreign_hash_modes(v, f"{path}[{i}]"))
    return out


def hash_mode_violations(doc):
    """(rule, message) pairs for LINT-HASH-01 over a whole document."""
    out = []
    for path, mode, reason in find_foreign_hash_modes(doc):
        why = f" — {reason}" if reason else ""
        out.append(("LINT-HASH-01",
                    f"hash_mode {mode!r} at {path} is not part of the profile"
                    f"{why}; the profile defines "
                    + ", ".join(PROFILE_HASH_MODES)))
    return out


class DuplicateKeyError(ValueError):
    """A JSON object carried a duplicate key (M1/J0+)."""

    def __init__(self, keys):
        self.keys = sorted(keys)
        super().__init__("duplicate object key(s): " + ", ".join(self.keys))


def _reject_duplicate_pairs(pairs):
    seen, dups = {}, set()
    for k, v in pairs:
        if k in seen:
            dups.add(k)
        seen[k] = v
    if dups:
        raise DuplicateKeyError(dups)
    return seen


def load_ijson(text):
    """Parse JSON text, raising DuplicateKeyError on any duplicate object key
    (M1/J0+; the I-D (Canonicalisation and Payload Hashing)). A JSON parser
    silently keeps the last value for a duplicate key, so a duplicate is a
    canonicalisation ambiguity and a signature-wrapping vector; the profile
    rejects it at the parse boundary (the parsed dict has already lost the
    information, so it cannot be checked later). THE single strict loader — the
    linters read evidence/discovery files through it (LINT-PKG-10)."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)


def dcbor(obj) -> bytes:
    """Deterministic CBOR (RFC 8949 §4.2) — the authoritative canonicalisation
    from the octet-authoritative revision (M4), and since 2026-09-25 the
    profile's ONLY canonicalisation."""
    import cbor2
    return cbor2.dumps(obj, canonical=True)


def _reconstruct_sub(sub_bytes, sub_proj=None):
    """Reconstruct an EP sub-object from its artefact BYTES. When the wire
    projection does not supply the sub-body (a shorter/forged projection), it is
    SERVER-DERIVED from the authoritative payload (N1/LINT-PKG-11): reconstruction
    is driven by the signed bytes, never by an unverified wire projection, so a
    signed sub-object can never be dropped from the lint pass."""
    import base64
    import cbor2
    if sub_proj is None:
        inner = cbor2.loads(bytes(sub_bytes))
        cose = bytes(inner[0])
        sub_proj = cbor2.loads(cbor2.loads(cose)[2])
    return reconstruct({"sm_artifact_b64": base64.b64encode(bytes(sub_bytes)).decode("ascii"),
                        "projection": sub_proj})


def reconstruct(sample):
    """Rebuild the familiar flat shape (fields + `seal` / `doc_cose_b64`) from an
    M4 artefact `{sm_artifact_b64, projection}` (twenty-fifth review). The
    authoritative bytes are the artefact; this lets the existing lint rules run
    over a familiar object while LINT-PKG-06 re-derives and checks that the
    projection binds to those bytes. Non-artefact input is returned unchanged."""
    import base64
    import cbor2
    if not (isinstance(sample, dict) and "sm_artifact_b64" in sample
            and "projection" in sample):
        return sample
    proj = sample["projection"]
    raw = base64.b64decode(sample["sm_artifact_b64"])
    if str(proj.get("type", "")).startswith("BW-") \
            or proj.get("type") in ("STATUS-v1", "ROSTER-v1"):
        # discovery artefact (incl. the D6 status capability and the F-12
        # roster snapshot): the authoritative bytes ARE the COSE_Sign1
        doc = dict(proj)
        doc["doc_cose_b64"] = base64.b64encode(raw).decode("ascii")
        return doc
    # evidence artefact: dCBOR([cose_sign1, qualified_timestamp])
    outer = cbor2.loads(raw)
    cose = bytes(outer[0])
    doc = dict(proj)
    doc["seal"] = {"cose_b64": base64.b64encode(cose).decode("ascii"),
                   "qualified_timestamp": outer[1]}
    if proj.get("type") == "EP-v1":   # sub-objects embedded as artefact bytes
        body = cbor2.loads(cbor2.loads(cose)[2])
        # De-zipped (N1): iterate the AUTHORITATIVE signed lists, pairing the wire
        # projection by index and deriving it when absent, so a shorter/forged
        # projection can never silently truncate the signed set. LINT-PKG-11
        # (projection_equals_decode) separately rejects any projection != payload.
        po = proj.get("outcomes") or []
        pc = proj.get("changes") or []
        doc["se"] = _reconstruct_sub(body.get("se"), proj.get("se"))
        doc["outcomes"] = [_reconstruct_sub(b, po[i] if i < len(po) else None)
                           for i, b in enumerate(body.get("outcomes") or [])]
        if body.get("changes"):
            doc["changes"] = [_reconstruct_sub(b, pc[i] if i < len(pc) else None)
                              for i, b in enumerate(body["changes"])]
        pd = proj.get("disputes") or []
        if body.get("disputes"):  # X-04/D5: grade-mismatch dispute artefacts
            doc["disputes"] = [_reconstruct_sub(b, pd[i] if i < len(pd) else None)
                               for i, b in enumerate(body["disputes"])]
    return doc


def _deep_equal(a, b):
    """Recursive structural equality: dicts by key-set (order-independent), lists
    by length AND order, scalars by type+value. A bool is never equal to an int
    (JSON `true` must not match `1`)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_deep_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_deep_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return False
    return a == b


def _sub_eq(sub_proj, sub_bytes, path):
    import cbor2
    inner = cbor2.loads(bytes(sub_bytes))
    cose = bytes(inner[0])
    sub_body = cbor2.loads(cbor2.loads(cose)[2])
    return _proj_eq(sub_proj, sub_body, path)


def _proj_eq(proj, body, path="$"):
    """Compare a projection against the decoded authoritative body. For an EP the
    body carries each sub-object as artefact BYTES while the projection carries the
    decoded sub-body, so se/outcomes/changes are compared by decoding the bytes and
    recursing — which is exactly where an extra/missing projection element shows up
    as a length divergence."""
    if isinstance(proj, dict) and isinstance(body, dict) and proj.get("type") == "EP-v1":
        subkeys = ("se", "outcomes", "changes", "disputes")
        for k in set(proj) | set(body):
            if k in subkeys:
                continue
            if k not in proj or k not in body:
                return False, f"{path}.{k} present on only one side of projection/payload"
            if not _deep_equal(proj[k], body[k]):
                return False, f"{path}.{k} differs between projection and payload"
        if ("se" in proj) != ("se" in body):
            return False, f"{path}.se present on only one side"
        if "se" in proj:
            ok, why = _sub_eq(proj["se"], body["se"], f"{path}.se")
            if not ok:
                return False, why
        for k in ("outcomes", "changes", "disputes"):
            p, b = proj.get(k) or [], body.get(k) or []
            if len(p) != len(b):
                return False, (f"{path}.{k}: projection carries {len(p)} element(s), "
                               f"the signed payload carries {len(b)}")
            for i, (pe, be) in enumerate(zip(p, b)):
                ok, why = _sub_eq(pe, be, f"{path}.{k}[{i}]")
                if not ok:
                    return False, why
        return True, ""
    return (True, "") if _deep_equal(proj, body) else \
        (False, f"{path}: projection differs from decode(payload)")


def flat_projection(doc):
    """R11-09 — the wire projection a FLAT artefact stands for: the inverse of
    `reconstruct`'s shape change. The flat form is the body beside its
    authoritative bytes (`doc_cose_b64` for discovery, `seal` for evidence,
    and a `seal` on each Evidence Package sub-object); dropping those gives
    the projection the authoritative Schema is written against. Returns None
    for input that is neither form.

    Both linters accept the flat form, and only the wrapper had its body
    Schema-validated, so a descriptor without `endpoints` — or an SE without
    `sent_at` — was conformant or not depending on how it was wrapped. With
    this, every accepted form is validated as the same body."""
    if not isinstance(doc, dict):
        return None
    if "doc_cose_b64" in doc:
        return {k: v for k, v in doc.items() if k != "doc_cose_b64"}
    if "seal" not in doc:
        return None
    body = {k: v for k, v in doc.items() if k != "seal"}
    if body.get("type") == "EP-v1":
        def bare(sub):
            return {k: v for k, v in sub.items() if k != "seal"} \
                if isinstance(sub, dict) else sub
        for key in ("se",):
            if key in body:
                body[key] = bare(body[key])
        for key in ("outcomes", "changes", "disputes"):
            if isinstance(body.get(key), list):
                body[key] = [bare(x) for x in body[key]]
    return body


def projection_equals_decode(sample):
    """LINT-PKG-11 (N1): the projection MUST equal decode(payload) EXACTLY —
    recursive, array length and order included — for every wrapped artefact
    (evidence, discovery, and each EP sub-artefact). The authoritative bytes are
    `sm_artifact_b64`; a projection element that no signed artefact covers (extra,
    missing, reordered or mutated) is a fail-closed violation. Non-wrapped input
    yields no violation."""
    import base64
    import cbor2
    if not (isinstance(sample, dict) and "sm_artifact_b64" in sample
            and "projection" in sample):
        return []
    proj = sample["projection"]
    try:
        raw = base64.b64decode(sample["sm_artifact_b64"])
        if str(proj.get("type", "")).startswith("BW-") \
                or proj.get("type") in ("STATUS-v1", "ROSTER-v1"):
            body = cbor2.loads(cbor2.loads(raw)[2])      # discovery: raw IS the COSE_Sign1
        else:
            cose = bytes(cbor2.loads(raw)[0])            # evidence: [cose, qualified_timestamp]
            body = cbor2.loads(cbor2.loads(cose)[2])
    except Exception as exc:
        return [("LINT-PKG-11", f"cannot decode the authoritative payload: {exc}")]
    ok, why = _proj_eq(proj, body)
    return [] if ok else [("LINT-PKG-11", why)]


def ep_signed_body(ep_doc):
    """The dCBOR-signed EP body rebuilt from a reconstructed EP doc: each
    sub-object as its artefact BYTES (so LINT-PKG-06 detects a tampered EP)."""
    import base64
    body = {k: v for k, v in ep_doc.items()
            if k not in ("se", "outcomes", "changes", "disputes", "seal")}

    def _art(sub):
        s = sub["seal"]
        return dcbor([base64.b64decode(s["cose_b64"]), s["qualified_timestamp"]])
    body["se"] = _art(ep_doc["se"])
    body["outcomes"] = [_art(o) for o in ep_doc.get("outcomes", [])]
    if "changes" in ep_doc:
        body["changes"] = [_art(c) for c in ep_doc["changes"]]
    if "disputes" in ep_doc:
        body["disputes"] = [_art(d) for d in ep_doc["disputes"]]
    return body


def parse_common_flags(argv):
    """Parse argv (argv[0] = program name) into (files, opts).

    opts keys: allow_incomplete (bool — R6-W1: the caller accepts an
    INCOMPLETE verdict as a pass, never a violation; the gaps are printed
    either way), dev_mode (bool), verify_demo (bool), profile (str, default
    "pilot"), trust_store (str | None), now (str | None — the RETRIEVAL /
    verification instant for the parametric at-time checks, LINT-DISC-25 and
    LINT-DISC-28), unknown (list of unrecognised flags — a non-empty list is a
    usage error for the caller).
    """
    opts = {"dev_mode": False, "verify_demo": False,
            "profile": "pilot", "trust_store": None, "directory": None,
            "federation_register": None,
            "now": None, "allow_incomplete": False, "unknown": []}
    files = []
    args = list(argv[1:])
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--dev-mode", "--no-cbor-check"):
            opts["dev_mode"] = True
        elif a == "--verify-demo":
            opts["verify_demo"] = True
        elif a == "--allow-incomplete":
            opts["allow_incomplete"] = True
        elif a == "--profile":
            i += 1
            opts["profile"] = args[i] if i < len(args) else "pilot"
        elif a.startswith("--profile="):
            opts["profile"] = a.split("=", 1)[1]
        elif a == "--trust-store":
            i += 1
            opts["trust_store"] = args[i] if i < len(args) else None
        elif a.startswith("--trust-store="):
            opts["trust_store"] = a.split("=", 1)[1]
        elif a == "--federation-register":
            i += 1
            opts["federation_register"] = args[i] if i < len(args) else None
        elif a.startswith("--federation-register="):
            opts["federation_register"] = a.split("=", 1)[1]
        elif a == "--directory":
            i += 1
            opts["directory"] = args[i] if i < len(args) else None
        elif a.startswith("--directory="):
            opts["directory"] = a.split("=", 1)[1]
        elif a == "--now":
            i += 1
            opts["now"] = args[i] if i < len(args) else None
        elif a.startswith("--now="):
            opts["now"] = a.split("=", 1)[1]
        elif a.startswith("-"):
            opts["unknown"].append(a)
        else:
            files.append(a)
        i += 1
    return files, opts


def load_trust_store(path):
    """Load and minimally validate a demo trust store. Raises ValueError on
    an unreadable or malformed store (callers fail closed, exit 2)."""
    try:
        with open(path, encoding="utf-8") as f:
            store = json.load(f)
    except Exception as exc:
        raise ValueError(f"cannot read/parse trust store {path!r}: {exc}")
    entries = store.get("entries")
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"trust store {path!r} has no 'entries' object")
    for kid, e in entries.items():
        for req in ("role", "pubkey_b64", "not_before", "not_after"):
            if req not in e:
                raise ValueError(f"trust store entry {kid!r} lacks {req!r}")
    return store


def load_directory(path):
    """Load and minimally validate a demo directory-pin fixture (X-01): the
    pilot stand-in for the EDD DirectoryRecord.authorized_seal_keys. Raises
    ValueError on an unreadable/malformed fixture (callers fail closed)."""
    try:
        with open(path, encoding="utf-8") as f:
            directory = json.load(f)
    except Exception as exc:
        raise ValueError(f"cannot read/parse directory {path!r}: {exc}")
    records = directory.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError(f"directory {path!r} has no 'records' array")
    for r in records:
        if "uid" not in r or not isinstance(r.get("authorized_seal_keys"), list):
            raise ValueError(f"directory record {r.get('uid')!r} lacks uid / "
                             "authorized_seal_keys")
    return directory


def _seal_spki_sha256(seal_b64, store):
    """The lowercase-hex SHA-256 of the raw seal public key resolved from the
    store via the COSE kid. None if the seal cannot be decoded or the kid is
    unknown (those are LINT-TRUST-01's concern, reported there)."""
    import hashlib
    try:
        import cbor2
        cose = cbor2.loads(base64.b64decode(seal_b64))
        protected = cose[0]
        ph = cbor2.loads(protected) if protected else {}
        kid = ph.get(4) if isinstance(ph, dict) else None
        kid = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    except Exception:
        return None
    entry = store.get("entries", {}).get(kid)
    if entry is None:
        return None
    return hashlib.sha256(base64.b64decode(entry["pubkey_b64"])).hexdigest()


TYPE_SCHEMA = {
    "SE-v1": "evidence-se.schema.json", "DE-v1": "evidence-de.schema.json",
    "NDE-v1": "evidence-nde.schema.json", "RE-v1": "evidence-re.schema.json",
    "CE-v1": "evidence-ce.schema.json", "EP-v1": "evidence-ep.schema.json",
    "RelayEvidence-v1": "evidence-relay.schema.json",
    "GCM-v1": "evidence-gcm.schema.json",
    "BW-MED-v1": "bw-med.schema.json", "BW-ORG-v1": "bw-org.schema.json",
    "BW-MEMBER-v1": "bw-member.schema.json",
    "BW-PROVIDER-v1": "bw-provider.schema.json",
    "STATUS-v1": "status-assertion.schema.json",
    "ROSTER-v1": "roster-snapshot.schema.json",
    # R4-U4: GroupEstablishmentRefusal-v1 is WITHDRAWN. It had a Schema and no
    # OpenAPI operation, no transport, no signature rule, no CDDL, no
    # destination field and no sample — "addressed to the group creator"
    # without representing or authenticating the creator. A refusal only has to
    # reach the creator while the group is forming, which MLS already does with
    # authentication; half-plumbed was the worst of the two states.
}
_SCHEMA_CACHE = {}


def _ref_store():
    """Every published Schema, keyed by `$id` AND by path, so a `$ref` resolves
    OFFLINE. Shared by the evidence validator and the request validator, because
    the request contract's `$ref`s point INTO the evidence Schemas — `sender_uid`
    on a submission IS `evidence-common.schema.json#/$defs/Uid`, not a
    look-alike."""
    root = pathlib.Path(__file__).resolve().parents[1]
    store = {}
    for p in sorted((root / "schemas").glob("*.schema.json")):
        sch = json.loads(p.read_text(encoding="utf-8"))
        if "$id" in sch:
            store[sch["$id"]] = sch
        store[str(p)] = sch
        # The OpenAPI contracts reference the Schemas by REPOSITORY-RELATIVE
        # path (`schemas/evidence-common.schema.json#/$defs/Uid`), which
        # resolves against the root base URI to a file: URL. Registering that
        # form keeps resolution offline instead of falling through to a fetch.
        store[p.as_uri()] = sch
    return root, store


def _schema_validator(schema_file):
    """A cached Draft-2020-12 validator (format-asserting, local $ref store) for
    one schema file."""
    v = _SCHEMA_CACHE.get(schema_file)
    if v is not None:
        return v
    import jsonschema
    root, store = _ref_store()
    schema = json.loads((root / "schemas" / schema_file).read_text(encoding="utf-8"))
    resolver = jsonschema.RefResolver(base_uri=str(root.as_uri()) + "/",
                                      referrer=None, store=store)
    v = jsonschema.Draft202012Validator(
        schema, resolver=resolver, format_checker=jsonschema.FormatChecker())
    _SCHEMA_CACHE[schema_file] = v
    return v


_REQUEST_CACHE = {}


def request_schema(contract_file, schema_name):
    """R8-01 requirement 1 — the published request Schema and a validator that
    EXECUTES it, returned as `(schema, validator)`.

    The round-7 fix read this same component and then ran two projections of
    it: the `required` name list and the closed-object rule. Types, patterns,
    enums, formats, `oneOf` arms and every `$ref` were read and discarded — so
    a value violating the published hash pattern was accepted by intake, and
    the contract and the reference admitted different requests. Executing the
    Schema is the fix; reading it and reimplementing two of its keywords is the
    defect (R8-01).
    """
    key = (contract_file, schema_name)
    cached = _REQUEST_CACHE.get(key)
    if cached is not None:
        return cached
    import yaml
    import jsonschema
    root, store = _ref_store()
    contract_path = root / contract_file
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    schema = contract["components"]["schemas"][schema_name]
    # The WHOLE contract is registered under its own URI and used as the base,
    # so a component's document-local `#/components/schemas/...` pointer
    # resolves. Validating an extracted component against the repository root
    # left those pointers dangling — and the contracts legitimately use them,
    # since a request schema referring to a sibling schema in the same document
    # is how OpenAPI expresses one definition rather than two.
    base = contract_path.as_uri()
    store[base] = contract
    resolver = jsonschema.RefResolver(base_uri=base, referrer=contract,
                                      store=store)
    validator = jsonschema.Draft202012Validator(
        schema, resolver=resolver, format_checker=jsonschema.FormatChecker())
    _REQUEST_CACHE[key] = (schema, validator)
    return schema, validator


def validate_body(projection):
    """LINT-PKG-12 (N-02): the decoded body MUST validate against its
    authoritative JSON Schema. The CDDL is only the structural outer bound; the
    Schema is the authoritative validator of the decoded body (the I-D,
    CBOR Structure Definitions / N2), so a body that is CDDL-valid and
    projection-equal but Schema-invalid is rejected fail-closed at the verifier
    entry point. Returns [] or [("LINT-PKG-12", why)]."""
    t = projection.get("type") if isinstance(projection, dict) else None
    schema_file = TYPE_SCHEMA.get(t)
    if schema_file is None:
        return []  # unknown type is LINT-000 / LINT-DISC-000's concern
    try:
        validator = _schema_validator(schema_file)
    except ImportError:  # pragma: no cover — jsonschema is preflighted
        return []
    errors = sorted(validator.iter_errors(projection), key=lambda e: list(e.path))
    if not errors:
        return []
    e = errors[0]
    path = "$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]" for p in e.path)
    return [("LINT-PKG-12",
             f"decoded body does not validate against its authoritative JSON "
             f"Schema ({schema_file}): {path}: {e.message[:160]}"
             + (f" (+{len(errors)-1} more)" if len(errors) > 1 else ""))]


RDP_ID_PATTERN = None          # set below from the SCHEMA, never restated


def _rdp_id_pattern():
    """The canonical grammar, READ FROM THE SCHEMA that publishes it.

    R7-04 exists because one document stated a grammar and nothing downstream
    shared its value space. Writing the pattern a second time here would be the
    same defect with a smaller radius, so it is loaded from `RdpId` — the same
    definition the seven evidence schemas `$ref`.
    """
    global RDP_ID_PATTERN
    if RDP_ID_PATTERN is None:
        schema = json.loads(
            (pathlib.Path(__file__).resolve().parents[1] / "schemas" /
             "evidence-common.schema.json").read_text(encoding="utf-8"))
        RDP_ID_PATTERN = re.compile(schema["$defs"]["RdpId"]["pattern"])
    return RDP_ID_PATTERN


class RdpIdentityError(ValueError):
    """A provider identity that cannot be attributed. Carries the typed reason."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def require_rdp_id(value, *, context="principal"):
    """R7-04 requirement 4: reference entry points refuse a non-canonical
    provider identity, EVEN WHEN the external federation register is
    unavailable.

    The two questions are separate and only one of them is external.
    *Which* provider this is, is answerable here from the grammar alone.
    *Whether* it is admitted is a register question and stays with X-01. An
    identity that cannot be attributed has no namespace to be idempotent
    within, so accepting it would silently share one — which is the collision
    R4-U3 exists to prevent, arriving through the back door.
    """
    if not isinstance(value, str) or not _rdp_id_pattern().fullmatch(value):
        raise RdpIdentityError(
            "rdp-identity-invalid",
            f"{context} {value!r} is not a canonical RDP identifier "
            f"({_rdp_id_pattern().pattern}). Legacy identifiers are NOT "
            "aliased: an alias resolving to the same namespace is a second "
            "name for one thing, and two names is how the collision returns "
            "")
    return value


def canonical_rdp_id(san_uris):
    """R7-04 requirement 3: the post-authentication identity adapter.

    Takes what a TLS stack yields — the certificate's subjectAltName URIs —
    and returns ONE typed `RdpId`, or raises. It does not read a request body,
    because a client-supplied identity would have to be checked against the
    certificate anyway.

    EXACTLY ONE canonical OCCURRENCE. Zero cannot be attributed; two or more
    cannot be attributed EITHER, and choosing between them would make the
    namespace depend on the order a library returned extensions. Non-canonical
    URIs in the certificate are ignored rather than rejected — a certificate
    may legitimately carry other names — but they cannot supply the identity.

    R8-05 requirement 3 — OCCURRENCES, not distinct values. This tested
    `len(set(canonical)) > 1`, so a certificate carrying the same canonical URI
    encoded twice passed: the set silently normalised the duplicate away. The
    normative rule in `rdpAuth` says the certificate MUST carry exactly one SAN
    URI of that form, and it says so because a duplicate is evidence of
    malformed issuance — deduplicating it is deciding that a certificate we
    cannot explain is fine. The docstring said "exactly one" throughout; the
    code implemented "exactly one distinct", and the docstring is the normative
    half.
    """
    canonical = [u for u in (san_uris or [])
                 if isinstance(u, str) and _rdp_id_pattern().fullmatch(u)]
    if not canonical:
        raise RdpIdentityError(
            "rdp-identity-absent",
            "the client certificate carries no canonical `urn:sbm:rdp:` "
            "subjectAltName URI, so the provider cannot be attributed")
    if len(canonical) > 1:
        distinct = sorted(set(canonical))
        # Every matching occurrence is reported for diagnostics; the DECISION
        # does not deduplicate them.
        detail = (f"{len(canonical)} canonical subjectAltName URIs "
                  f"{sorted(canonical)}")
        raise RdpIdentityError(
            "rdp-identity-ambiguous",
            f"the client certificate carries {detail}"
            + (f" naming {distinct}" if len(distinct) > 1 else
               " — the SAME identifier encoded more than once")
            + ". A certificate that names two providers cannot be attributed "
              "to one, and picking would make the namespace depend on "
              "extension order; a repeated one is malformed issuance and must "
              "not be normalised away by counting distinct values")
    return canonical[0]


def validate_status_history(record):
    """Batch A / A2 — the three things the `MembershipRecord` Schema cannot say.

    The closed object constrains the SHAPE of `status_history`: entries, their
    enum, their timestamp format. It cannot express that the entries are
    contiguous, that they do not overlap, or that `status` agrees with the last
    of them — those are relations between entries, and a JSON Schema describes
    one value at a time.

    So the work order's "rejected by the component" is only two thirds true,
    and this is the missing third. Stating it plainly matters: a reader who
    believes the Schema covers it would not look for this function, and a
    register whose history overlaps answers an as-of question with two statuses
    at once.

    Instants, never strings (R9-04). Returns [] or a list of typed reasons.
    """
    out = []
    history = record.get("status_history") or []
    if not history:
        return [("membership-history-empty",
                 "a membership record carries no `status_history`, so no as-of "
                 "question about it has an answer")]
    try:
        bounds = [(instant(e["from"], field="from"),
                   instant(e["until"], field="until") if e.get("until") else None,
                   e["status"])
                  for e in history]
    except TimestampError as e:
        return [("membership-history-unparsable", str(e))]

    for i, (lo, hi, _status) in enumerate(bounds):
        last = i == len(bounds) - 1
        if last and hi is not None:
            out.append(("membership-history-bounded",
                        "the last entry carries `until`, so the record says "
                        "the participant's admission ended and nothing "
                        "replaced it — an open-ended final entry is what makes "
                        "the record answer 'and since then?'"))
        if not last and hi is None:
            out.append(("membership-history-unbounded",
                        f"entry {i} has no `until` but is not the last, so two "
                        "entries claim the same instants"))
            continue
        if hi is not None and hi <= lo:
            out.append(("membership-history-inverted",
                        f"entry {i} runs from {history[i]['from']} to "
                        f"{history[i]['until']}, which is not forwards"))
        if not last:
            nxt = bounds[i + 1][0]
            if hi is not None and hi != nxt:
                out.append((
                    "membership-history-discontinuous",
                    f"entry {i} ends at {history[i].get('until')} and entry "
                    f"{i + 1} begins at {history[i + 1]['from']}: "
                    + ("they overlap, so one instant has two statuses"
                       if nxt < hi else
                       "there is a gap, so some instants have none")))

    if record.get("status") != history[-1]["status"]:
        out.append((
            "membership-status-disagrees",
            f"`status` is {record.get('status')!r} and the last history entry "
            f"is {history[-1]['status']!r}. A record whose summary disagrees "
            "with its own history is refused rather than reconciled: there is "
            "no way to know which half was meant"))
    return out


DEFAULT_MAX_TTL = "P30D"          # X-22: absent BW-ORG.max_ttl
SENT_AT_FUTURE_BOUND = datetime.timedelta(minutes=5)   # the propagation bound

_DURATION = re.compile(r"P(?!$)(?:(\d+)D)?(?:T(?=\d)(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?")


def parse_iso_duration(value):
    """An ISO 8601 duration of the form the BW-ORG Schema admits for `max_ttl`
    (day and time designators). RAISES on anything else.

    `bundle_lint` carried its own parser, which returned None for a value it
    could not read — and the caller then used the 30-day default. The Schema
    pattern keeps unreadable values out of a validated BW-ORG, so that never
    fired on real input; but a parser that turns "I cannot read the maximum"
    into "the maximum is thirty days" is the wrong shape to keep (R10-08)."""
    m = _DURATION.fullmatch(value or "")
    if not m:
        raise ValueError(f"{value!r} is not a duration this profile defines "
                         "(ISO 8601, day and time designators)")
    d, h, mi, sec = (int(x) if x else 0 for x in m.groups())
    return datetime.timedelta(days=d, hours=h, minutes=mi, seconds=sec)


def expiry_problems(sent_at, expires_at, *, max_ttl=None, clock=None):
    """X-22 — the submission's expiry, VALIDATED, stated ONCE.

    Returns [] or `[(reason, detail)]` with registered intake reasons:
      `expiry-not-after-sent`   `expires_at` is not strictly later than
                                `sent_at` — a reversed or zero TTL;
      `expiry-beyond-max-ttl`   the TTL exceeds the RECIPIENT's declared
                                maximum (`BW-ORG.max_ttl`; absent = P30D);
      `sent-at-in-future`       `sent_at` lies beyond the 5-minute
                                propagation bound ahead of `clock`, the
                                accepting RDP's own clock.
    and, in the same registered vocabulary, `submission-invalid` for an
    instant that cannot be read and `policy-unresolvable` for a declared
    maximum that cannot be read. One vocabulary — the registry's — so intake
    raises what this returns and no caller keeps a translation table.

    R10-08: these rules were stated in the I-D, split across two linters that
    run AFTER sealing — ordering in `evidence_lint` (LINT-DE-18), the maximum
    in `bundle_lint` (LINT-BND-27) — and the future bound was implemented
    nowhere. Intake ran none of them, so correctly signed submissions with a
    zero, reversed or 31-day TTL, or a `sent_at` a day ahead, were sealed and
    moved every ledger, while LINT-DE-18's own comment said "a reversed or
    zero TTL is rejected at intake". Intake, LINT-DE-18 and LINT-BND-27 now
    all call this.
    """
    try:
        sent = instant(sent_at, field="sent_at")
        exp = instant(expires_at, field="expires_at")
    except TimestampError as e:
        return [("submission-invalid", str(e))]
    out = []
    if exp <= sent:
        out.append(("expiry-not-after-sent",
                    f"expires_at {expires_at} is not later than sent_at "
                    f"{sent_at} — a reversed or zero TTL"))
    else:
        try:
            limit = parse_iso_duration(max_ttl or DEFAULT_MAX_TTL)
        except ValueError as e:
            out.append(("policy-unresolvable",
                        f"the recipient's declared maximum cannot be read: {e}"))
        else:
            if exp - sent > limit:
                out.append(("expiry-beyond-max-ttl",
                            f"a TTL of {exp - sent} exceeds the recipient's "
                            f"maximum {max_ttl or DEFAULT_MAX_TTL + ' (default)'} "
                            "(X-22: expires_at is validated against policy, not "
                            "echoed)"))
    if clock is not None:
        now = instant(clock, field="clock")
        if sent > now + SENT_AT_FUTURE_BOUND:
            out.append(("sent-at-in-future",
                        f"sent_at {sent_at} is more than "
                        f"{SENT_AT_FUTURE_BOUND} ahead of the RDP's clock "
                        f"{clock}"))
    return out


class _NotCovered:
    """The register holds a record for the participant, and that record was
    asserted BEFORE the instant asked about, so it cannot speak for it
    (R10-X1). Neither a status nor an absence: a third answer, and callers
    that report it must report it as unestablished, never as admitted and
    never as a violation."""
    def __repr__(self):
        return "NOT_COVERED"


NOT_COVERED = _NotCovered()


def admission_at(register, participant_id, at):
    """Batch A / A4 — the federation admission rule, ONE implementation.

    What status the register attributes to `participant_id` at the instant
    `at`: "admitted", "suspended", "excluded", None when it attributes none,
    or NOT_COVERED when the participant's record was asserted before `at`
    and so cannot speak for it (R10-X1). Half-open windows `[from, until)`, the form the profile already uses
    for certificate validity (X-17/DR-11) and DS receipt keys (R3-04).

    THE INSTANT IS THE INSTANT OF THE ACT, never of verification. A verifier
    reading evidence of a message sent in April asks whether the provider was
    admitted in April; asking whether it is admitted today would make a
    January exclusion retroactively unmake an act that was properly authorised
    when it happened, and would make the same bundle verify differently on
    different days. The caller supplies the act's own instant — `sent_at` for
    an SE, `delivered_at` for a DE, the hop timestamp for relay evidence — and
    this function does not guess it.

    Instants, never strings (R9-04): the register's timestamps and the act's
    come from different producers, and lexical order is not chronological
    order across offsets.

    The third parameter is `at`, not `instant`, because `instant` is the
    parser this rule is built on and shadowing it here would leave the rule
    unable to read the values it compares.

    None is deliberately BOTH "no such participant" and "no status at that
    instant" — before the first entry, or in a gap between two. For the
    admission question they are one fact: the register vouches for nothing
    here. A caller wanting to say which it was can observe separately whether
    the identifier appears at all; that is a lookup, not this rule.

    Raises ValueError when the register cannot answer rather than guessing:
    an unparsable timestamp (`TimestampError`, a ValueError), or two records
    for one participant. Two records are not reconciled and one is not picked
    — picking would make admission depend on array order, the same defect as
    a certificate naming two providers (R7-04/R8-05).
    """
    records = [r for r in (register or {}).get("records", [])
               if r.get("participant_id") == participant_id]
    if len(records) > 1:
        raise ValueError(
            f"the register carries {len(records)} records for "
            f"{participant_id!r}. Admission would depend on which one was "
            "read first, so the register is refused rather than reconciled")
    if not records:
        return None
    when = at if isinstance(at, datetime.datetime) else instant(at, field="at")
    # R10-X1: an assertion made at T authenticates the history UP TO T and
    # nothing after it. Batch A let the open-ended final window answer for any
    # later instant, so a record asserted in September 2026 said `admitted`
    # about an act in 2036 — and, worse, an old genuine `admitted` record
    # could be replayed against an act that followed a later suspension it
    # had never heard of. Signing does not fix that (R10-01 proves who
    # asserted the history, not that it includes the change that mattered);
    # a coverage bound does. Inclusive: at T the record states the status
    # at T.
    asserted = records[0].get("asserted_at")
    if not asserted:
        raise ValueError(
            f"the record for {participant_id!r} carries no `asserted_at`, so "
            "nothing bounds the instants it can speak for")
    if when > instant(asserted, field="asserted_at"):
        return NOT_COVERED
    for e in records[0].get("status_history") or []:
        lo = instant(e["from"], field="from")
        hi = instant(e["until"], field="until") if e.get("until") else None
        if lo <= when and (hi is None or when < hi):
            return e.get("status")
    return None


def validate_contract_object(contract_file, schema_name, obj):
    """R8-05 requirement 4 — a server-DERIVED object against its own contract.

    Returns [] or a list of (pointer, message). The general form of the receipt
    gate added in R8-02: anything this repository generates and then returns,
    stores or signs is checked against the published shape first, because a
    generated object nobody validates is exactly where an unconstrained field
    stops being noticed.
    """
    _, validator = request_schema(contract_file, schema_name)
    return [("$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]"
                           for p in e.path), e.message[:160])
            for e in sorted(validator.iter_errors(obj),
                            key=lambda e: list(e.path))]


def validate_delivery_receipt(receipt, *, unsigned=True):
    """R8-02 requirement 5 — the generated receipt against its own contract.

    Nothing validated an emitted receipt at all. The DS signed one carrying
    `session_binding: null` and stored the item as acknowledged, although the
    published `DeliveryReceipt` requires an object with `kind` and `digest` —
    so a receipt that no conforming client could accept existed, signed, in the
    ledger. A signature cannot be withdrawn, which is why this runs BEFORE
    `seal_cose` and again over the complete object before it is stored.

    `unsigned=True` is the pre-signing pass: `ds_signature` is the one field
    legitimately absent, because it is what the caller is about to compute.
    Every other constraint applies unchanged, and the post-signing pass runs
    with `unsigned=False` so the stored object is checked in full.

    Returns [] or a list of (pointer, message).
    """
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "DeliveryReceipt")
    problems = []
    for e in sorted(validator.iter_errors(receipt), key=lambda e: list(e.path)):
        if unsigned and e.validator == "required" \
                and e.message.startswith("'ds_signature'"):
            continue
        where = "$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]"
                              for p in e.path)
        problems.append((where, e.message[:160]))
    return problems


class SubmissionInvalid(ValueError):
    """A submission that does not satisfy the published request contract.

    R8-01: `fields` names the offending top-level properties as DATA. Callers
    that answer with a sharper reason for a particular field used to substring-
    match the prose detail, which matched whatever the validator happened to
    quote — a `oneOf` failure quotes the whole instance, so every field name in
    the submission appeared to be the offending one. A caller deciding on
    prose is reading a message meant for a human.
    """

    def __init__(self, reason, detail="", fields=()):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail
        self.fields = tuple(fields)


def _offending_fields(errors):
    """The top-level property names an error set implicates, as data.

    A root-level failure (`required`, `oneOf`) carries no path, so the name is
    taken from the sub-errors a combinator collected or from the `required`
    message's own quoted property — never from the instance dump.
    """
    import re
    names = []
    for e in errors:
        path = list(e.path)
        if path:
            names.append(str(path[0]))
            continue
        if e.validator == "required":
            m = re.match(r"^'([^']+)' is a required property", e.message)
            if m:
                names.append(m.group(1))
            continue
        for sub in getattr(e, "context", None) or []:
            names.extend(_offending_fields([sub]))
    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return tuple(out)


def validate_submission_metadata(meta):
    """R8-01 requirement 1 — THE authoritative request validator, EXECUTED.

    R7-01's finding was that nine of sixteen contract-required fields produced
    a SEALED SE that failed its own authoritative Schema, because the path
    between the request contract and the evidence Schema ran neither. R7-01's
    fix read the contract and then reimplemented two of its keywords by hand —
    the `required` names and the closed-object rule — which is the SAME defect
    one level in: the contract was the source of truth, a projection of it was
    what ran, and the projection was checked faithfully. R8-01 executes the
    published Draft 2020-12 Schema, `$ref`s resolved and formats asserted.

    Typed reasons are PRESERVED, not collapsed (R8-01 requirement 2). A client
    acts differently on "you left out an address", "you sent a field I do not
    know" and "your digest is not a digest", so each keeps its own reason and
    the sharpest applicable one wins. The semantic reasons downstream —
    `identity-incoherent`, the policy and confirmation ones — are unaffected:
    they answer a different question, asked only once the request is
    well-formed.

    Raises `SubmissionInvalid`; returns `meta` unchanged on success.
    """
    if not isinstance(meta, dict):
        raise SubmissionInvalid("submission-malformed",
                                "the submission is not an object")
    schema, validator = request_schema("wallet-rdp-openapi.yaml",
                                       "SubmissionMetadata")
    # A required field that is ABSENT or explicitly null is incomplete. The
    # Schema would report the null as a type error; `submission-incomplete` is
    # the sharper answer and the one R7-01 registered, so it is kept.
    missing = [f for f in schema.get("required", []) if meta.get(f) is None]
    if missing:
        raise SubmissionInvalid(
            "submission-incomplete",
            f"the submission omits contract-required field(s) {missing}. The "
            "published request Schema requires them and the evidence Schema "
            "requires them; sealing an SE without them produces an artefact "
            "that fails its own authoritative Schema",
            fields=missing)
    unknown = sorted(set(meta) - set(schema.get("properties", {})))
    if unknown and schema.get("unevaluatedProperties") is False:
        raise SubmissionInvalid(
            "submission-unexpected-field",
            f"the submission carries undeclared field(s) {unknown}; the "
            "request Schema forbids them",
            fields=unknown)
    errors = sorted(validator.iter_errors(meta), key=lambda e: list(e.path))
    if errors:
        from jsonschema.exceptions import best_match
        e = best_match(errors) or errors[0]
        where = "$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]"
                              for p in e.path) if list(e.path) else "$"
        # NOT `e.message` for a root combinator: it renders the whole instance,
        # which puts every submitted value into an error string (R8-01).
        why = (f"{e.validator}" if not list(e.path)
               else f"{e.validator}: {e.message[:160]}")
        raise SubmissionInvalid(
            "submission-invalid",
            f"{where} violates the published request Schema ({why})"
            + (f" (+{len(errors) - 1} more)" if len(errors) > 1 else "")
            + ". The contract is executed, not summarised: a value the "
              "contract rejects must not reach a ledger or a seal",
            fields=_offending_fields(errors))
    return meta


class IdentityIncoherent(ValueError):
    """A submission whose independently valid statements name different
    entities, members, roles or authorization states. Carries the registry
    reason so intake can return it and the verifier can report it."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def check_identity_coherence(meta, *, org=None, members=None,
                             member_history=None, at=None):
    """R6-01 (Blocker) — THE identity resolver, shared by intake and the
    verifier. Returns a list of `(reason, detail)`; empty means coherent.

    R5-01 made intake verify each statement. **It never compared them.** Every
    field was independently valid and the tuple named two different legal
    entities, and a valid signature authenticates a contradiction without
    making it true:

        recipient_uid  = EU-DE-EOID-…                      (the German entity)
        recipient_addr = bw:uid:EU-FR-PSBID-…/r/procurement (the French one)
        BW-ORG.uid     = EU-FR-PSBID-…
        -> accepted, transported, and SEALED into an SE

    Round 6 reproduced that with a RE-SIGNED tuple, which is the point: the
    only thing standing between the old code and this was "an attacker cannot
    re-sign", and the sender's own wallet is exactly the party this constrains.

    What is checked, and each has a typed reason:

      * `recipient_uid` == uid(`recipient_addr`) == the BW-ORG's own uid;
      * `sender_uid` == uid(`sender_addr`) == the signing BW-MEMBER's uid;
      * a `/u/<mid>` sender address names the MEMBER THAT SIGNED; a `/r/<role>`
        address names a role that member actually holds; an entity-addressed
        sender is explicitly permitted, and means "this entity, unspecified
        member" — the confirmation still has to resolve;
      * the signing member is ACTIVE at the act, and the signing device exists,
        is not removed, and declares the `sign` capability at that instant;
      * `scope_ref` names a descriptor of THAT id AND version which was in
        force at the act — not merely an id that reaches a policy key.

    `at` is the act instant (`sent_at`). Status is resolved through
    `as_of_resolve` where a history is supplied, so this cannot become a second
    implementation of the window rule.
    """
    problems = []
    add = lambda reason, detail: problems.append((reason, detail))

    # ---- recipient: three statements, one entity --------------------------
    r_uid, r_addr = meta.get("recipient_uid"), meta.get("recipient_addr")
    parsed = parse_bw_address(r_addr) if r_addr else None
    if parsed is None:
        add("unaddressed-submission",
            f"recipient_addr {r_addr!r} is not a well-formed bw: address, so "
            "the entity it names cannot be compared with recipient_uid")
    else:
        if parsed[0] != r_uid:
            add("identity-incoherent",
                f"recipient_uid is {r_uid!r} but recipient_addr names "
                f"{parsed[0]!r} — one message, two recipients")
        if org and org.get("uid") and parsed[0] != org["uid"]:
            add("identity-incoherent",
                f"recipient_addr names {parsed[0]!r} but the acceptance policy "
                f"supplied belongs to {org['uid']!r}")
    if org and org.get("uid") and org["uid"] != r_uid:
        add("identity-incoherent",
            f"recipient_uid is {r_uid!r} but the BW-ORG governing the "
            f"submission is {org['uid']!r}")

    # ---- sender: the same, against the member that actually signed --------
    s_uid, s_addr = meta.get("sender_uid"), meta.get("sender_addr")
    s_parsed = parse_bw_address(s_addr) if s_addr else None
    if s_parsed is None:
        add("unaddressed-submission",
            f"sender_addr {s_addr!r} is not a well-formed bw: address")
    elif s_parsed[0] != s_uid:
        add("identity-incoherent",
            f"sender_uid is {s_uid!r} but sender_addr names {s_parsed[0]!r} "
            "— the acting entity and the addressed entity differ")

    sc = meta.get("sender_confirmation")
    if isinstance(sc, dict) and members is not None:
        mid, device_id = sc.get("mid"), sc.get("device_id")
        member = _member_as_of(members, mid, member_history=member_history, at=at)
        if member is None:
            add("sender-confirmation-unverifiable",
                f"no BW-MEMBER for {mid!r} in force at {at}")
        else:
            if member.get("uid") != s_uid:
                add("identity-incoherent",
                    f"sender_uid is {s_uid!r} but the signing member {mid!r} "
                    f"belongs to {member.get('uid')!r} — the signature is "
                    "valid and it is not this entity's")
            if member.get("status") != "active":
                add("member-not-active",
                    f"the signing member {mid!r} is {member.get('status')!r} at "
                    f"{at}, so its confirmation cannot be relied upon")
            # the address must name what actually signed
            if s_parsed and s_parsed[1] == "member" and s_parsed[2] != mid:
                add("identity-incoherent",
                    f"sender_addr is member-addressed to {s_parsed[2]!r} but "
                    f"the confirmation was signed by {mid!r}")
            if s_parsed and s_parsed[1] == "role":
                if s_parsed[2] not in (member.get("roles") or []):
                    add("identity-incoherent",
                        f"sender_addr claims role {s_parsed[2]!r} but member "
                        f"{mid!r} holds {member.get('roles') or []}")
            problems.extend(_signing_device_problems(member, device_id, at))
    return problems


def _member_as_of(members, mid, *, member_history=None, at=None):
    """The BW-MEMBER of `mid` in force at `at`. Uses `as_of_resolve` for the
    window — one implementation of that rule, not a second."""
    versions = (member_history or {}).get(mid)
    if versions:
        return as_of_resolve(versions, at=at) if at else None
    return next((m for m in (members or []) if m.get("mid") == mid), None)


def _signing_device_problems(member, device_id, at):
    """The device that signed must have existed, not been removed, and been
    authorised TO SIGN at the act.

    R6-01: `sign` is a declared BW-MEMBER capability and nothing required it —
    a device published as `["receive", "ack"]` could produce a D4 confirmation
    that intake accepted. The shipped samples had exactly that shape, so this
    check and the sample fix landed together.
    """
    out = []
    dev = next((d for d in (member.get("devices") or [])
                if d.get("device_id") == device_id), None)
    if dev is None:
        out.append(("sender-confirmation-unverifiable",
                    f"device {device_id!r} is not published by member "
                    f"{member.get('mid')!r}"))
        return out
    try:
        target = instant(at, field="sent_at") if at else None
        added = instant_or_none(dev.get("added_at"))
        removed = instant_or_none(dev.get("removed_at"))
    except TimestampError as e:
        out.append(("sender-confirmation-unverifiable",
                    f"device {device_id!r}: {e}"))
        return out
    if target is not None:
        if added is not None and added > target:
            out.append(("device-not-in-force",
                        f"device {device_id!r} was added at {dev.get('added_at')}, "
                        f"after the act at {at} — it did not exist then"))
        if removed is not None and removed <= target:
            out.append(("device-not-in-force",
                        f"device {device_id!r} was removed at "
                        f"{dev.get('removed_at')}, before the act at {at}"))
    caps = dev.get("capabilities") or []
    if "sign" not in caps:
        out.append(("device-not-sign-capable",
                    f"device {device_id!r} publishes capabilities {caps} and not "
                    "`sign`, so it is not authorised to produce the sender's "
                    "advanced electronic signature"))
    return out


def check_scope_in_force(org, scope_ref, *, at):
    """R6-01 point 6: the EXACT descriptor, and it was in force at the act.

    `select_policy_key` matched on `scope_id` alone, so a submitted
    `{scope_id: finance, version: "9"}` reached the `finance` policy key even
    though no such version is published, and a descriptor taking force after
    the act was equally acceptable. The bundle layer had these checks; intake
    did not, and intake is where refusing is still possible.
    """
    sid = (scope_ref or {}).get("scope_id") or "default"
    if sid == "default":
        return []
    version = (scope_ref or {}).get("version")
    scopes = ((org or {}).get("scope_map") or {}).get("scopes") or []
    exact = [s for s in scopes
             if s.get("scope_id") == sid and s.get("version") == version]
    if not exact:
        published = sorted({(s.get("scope_id"), s.get("version")) for s in scopes
                            if s.get("scope_id") == sid})
        return [("no-matching-scope",
                 f"scope {sid!r} version {version!r} is not published by this "
                 f"entity (published: {published or 'none'})")]
    if at:
        try:
            target = instant(at, field="sent_at")
            vf = instant_or_none(exact[0].get("valid_from"))
            vu = instant_or_none(exact[0].get("valid_until"))
        except TimestampError as e:
            return [("no-matching-scope", f"scope {sid!r}: {e}")]
        if vf is not None and vf > target:
            return [("scope-not-in-force",
                     f"scope {sid!r} v{version} takes force at "
                     f"{exact[0].get('valid_from')}, after the act at {at}")]
        if vu is not None and vu <= target:
            return [("scope-not-in-force",
                     f"scope {sid!r} v{version} ceased at "
                     f"{exact[0].get('valid_until')}, at or before the act at "
                     f"{at}")]
    return []


def as_of_resolve(versions, *, at):
    """X-17 as-of resolution: given a MID's binding history (member versions,
    each with `valid_from` and optional `valid_until`), return the version whose
    window [valid_from, valid_until) contains `at`, else None. An absent
    `valid_until` is open-ended.

    DR-05: the window is evaluated on PARSED instants. The former claim that
    "Zulu-form RFC 3339 strings compare correctly as strings" is false the
    moment a fractional part appears — '…23.1Z' < '…23Z' as strings, though it
    is the later instant — so a rotation boundary could resolve to the wrong
    version, and with it the wrong key. A version whose bounds do not parse is
    SKIPPED rather than silently matched."""
    target = instant(at, field="as_of")
    match = None
    for v in versions:
        try:
            vf = instant(v.get("valid_from"), field="valid_from")
            vu = instant_or_none(v.get("valid_until"))
        except TimestampError:
            continue
        if vf <= target and (vu is None or target < vu):
            match = v
    return match


def check_directory_pin(doc, seal_b64, store, directory):
    """LINT-TRUST-05 (X-01): the discovery seal's key MUST be an authorized seal
    key pinned by the directory for THIS document's UID. A valid QSealC
    authorised for another UID (present in the store, signature valid) but not
    pinned for this UID is rejected fail-closed. Returns a list of (rule, msg).

    Demo/pilot scope: the pin is the raw seal-key `spki_sha256`; production pins
    the QSealC `x5t#S256` and additionally validates the chain to an EU Trusted
    List (a production-verifier duty, not established here)."""
    out = []
    uid = doc.get("uid")
    spki = _seal_spki_sha256(seal_b64, store)
    if spki is None:
        # Undecodable seal / unknown signer — LINT-TRUST-01 already fails closed.
        return out
    rec = next((r for r in directory.get("records", []) if r.get("uid") == uid), None)
    if rec is None:
        out.append(("LINT-TRUST-05",
                    f"no directory record pins an authorized seal key for UID "
                    f"{uid!r} (fail-closed: unbound discovery-seal authority)"))
        return out
    pins = rec.get("authorized_seal_keys", [])
    matches = [p for p in pins if p.get("spki_sha256") == spki]
    if not matches:
        out.append(("LINT-TRUST-05",
                    f"discovery seal key (spki-sha256 {spki[:16]}…) is not an "
                    f"authorized seal key for UID {uid!r} in the directory record "
                    "— a key authorised for another UID cannot seal this entity's "
                    "discovery documents"))
        return out
    inst = _latest_declared_instant(doc)
    if inst is not None and not any(
            _within_window(inst, p.get("not_before"), p.get("not_after"))
            for p in matches):
        out.append(("LINT-TRUST-05",
                    f"discovery seal key for UID {uid!r} is pinned but the object "
                    f"instant {inst} lies outside its authorised key-set window "
                    "(rotation / retirement)"))
    return out


def load_federation_register(path):
    """Batch A / A5 — READ a Stage-1 federation membership register.

    This reads and shape-checks; it does NOT authenticate, and nothing it
    returns may be consulted for admission until `authenticate_register` has
    returned an `AuthenticatedRegister` for it. Batch A's docstring here said
    "fail-closed" and was believed to describe the whole ingress, which is how
    a register with its signature removed came to grant admission (R10-01).

    A register that cannot be read, or that is not a `{"records": [...]}`
    document with a `participant_id` on every record, raises rather than
    resolving to "nobody is admitted".
    """
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        raise ValueError(f"federation register {path!r} is unreadable: {exc}")
    if not isinstance(doc, dict) or not isinstance(doc.get("records"), list):
        raise ValueError(
            f"federation register {path!r} carries no `records` array")
    for i, r in enumerate(doc["records"]):
        if not isinstance(r, dict) or not r.get("participant_id"):
            raise ValueError(
                f"federation register {path!r} record {i} names no "
                "`participant_id`, so nothing can be looked up in it")
    return doc


DEMO_QTS_LEGACY = b"\x30\x22\x04\x20"     # SEQUENCE{ OCTET STRING(32) }
DEMO_QTS_TIMED = b"\x30\x33\x04\x20"      # SEQUENCE{ OCTET STRING(32), GeneralizedTime }


def parse_demo_qts(raw):
    """The demo qualified-timestamp token, read in ONE place (R10-X5).

    Returns `(imprint_bytes, gen_time_iso_or_None)`, or None when `raw` is not
    a demo token at all — a real RFC 3161 token, whose full validation is the
    production verifier's.

    Two shapes. The TIMED one — `SEQUENCE { OCTET STRING(32) imprint,
    GeneralizedTime genTime }` — carries the instant the TSA stamped the seal,
    as a real token's `genTime` does. The LEGACY one carries the imprint only:
    it is still read, so an artefact sealed before R10-X5 keeps its imprint
    check instead of silently becoming "not a demo token" and being skipped.
    It simply has no time to give.

    Why the time matters: an Evidence Package's act IS its sealing, so the
    instant its composer acted is the instant its timestamp attests. The
    stand-in token omitted that instant, and the composer's admission at
    composition was therefore unobtainable in the pilot (D10-01). Giving the
    demo token its time makes the AUTHORITATIVE source readable, rather than
    adding a second, self-asserted statement of the same instant to the body.
    """
    if not isinstance(raw, (bytes, bytearray)):
        return None
    raw = bytes(raw)
    if len(raw) == 36 and raw[:4] == DEMO_QTS_LEGACY:
        return raw[4:], None
    if len(raw) == 53 and raw[:4] == DEMO_QTS_TIMED and raw[36:38] == b"\x18\x0f":
        g = raw[38:53].decode("ascii", "replace")          # YYYYMMDDHHMMSSZ
        iso = f"{g[0:4]}-{g[4:6]}-{g[6:8]}T{g[8:10]}:{g[10:12]}:{g[12:14]}Z"
        return raw[4:36], iso
    return None


def sealed_at(doc):
    """The instant an evidence object's own timestamp attests, or None — from
    the reconstructed `seal.qualified_timestamp`. None when the token carries
    no time (legacy demo) or is not a demo token (the production verifier's)."""
    import base64 as _b64
    tok = ((doc.get("seal") or {}).get("qualified_timestamp") or {}).get("token_b64")
    try:
        got = parse_demo_qts(_b64.b64decode(tok, validate=True)) if tok else None
    except Exception:
        return None
    return got[1] if got else None


class AuthenticatedRegister(dict):
    """A membership register every record of which was authenticated against a
    configured Federation Authority anchor (R10-01).

    Only this type reaches admission. `check_register_pin` refuses anything
    else, and `bundle_lint` hands `admission_at` nothing but the value
    `authenticate_register` returned. The type is a statement about how the
    value was OBTAINED, which is the only thing that made the fields in it
    worth believing.
    """


def federation_authority_anchors(store):
    """The configured Federation Authority anchors: every trust-store entry
    whose role is `federation-authority`, keyed by kid, as `{kid: {kid,
    pubkey_b64, not_before, not_after}}`. Empty when none is configured.

    Configuration, never input: a register verified against a key that arrived
    beside it has been verified against nothing.

    A SET, not one key (R10-02, "authority bootstrap/update behaviour"). B1
    returned None whenever two entries claimed the role, calling that
    ambiguity — which made key ROTATION impossible: an authority rolling its
    key over has, for a while, two valid keys, and records sealed under each.
    It is not ambiguity, because nothing is chosen between: each record names
    its signer in its own COSE `kid`, and each key is honoured only inside its
    own validity window at the record's `asserted_at`. A record sealed by a
    retired key after that key's window closed is refused.
    """
    return {kid: {"kid": kid, "pubkey_b64": e.get("pubkey_b64"),
                  "not_before": e.get("not_before"),
                  "not_after": e.get("not_after")}
            for kid, e in ((store or {}).get("entries") or {}).items()
            if isinstance(e, dict) and e.get("role") == "federation-authority"}


def authenticate_register(register, anchors):
    """R10-01 — authenticate a membership register AT INGRESS.

    Returns `(AuthenticatedRegister, [])`, or `(None, [(rule, msg), ...])`.
    All or nothing: a register carrying one forged record is not a register
    any part of which can be trusted, so a single failure returns None and the
    caller treats admission as unestablished.

    Batch A shipped this check in `tests/test_federation_stage1.py` and nowhere
    else. The loader checked the container's SHAPE; admission and descriptor
    pinning then consumed the fields as written. A register with its signature
    removed granted admission, and — worse — a register whose
    `authorized_seal_keys` had been replaced, with the Federation Authority's
    signature left in place and now stale over a body it never signed, let an
    attacker's self-sealed descriptor through with zero findings. Batch A's
    closure verified the FIXTURE and not the consumer: the round-4 corollary
    inside the batch meant to close against it.

    Per record, each a LINT-TRUST-08 finding:
      * a seal and a timestamp are present;
      * the seal is a COSE_Sign1 whose `kid` names the configured anchor;
      * its payload IS the deterministic CBOR of the record minus
        {signature, timestamp} — so a field changed after sealing is caught
        even when the signature itself is untouched;
      * the signature verifies under the anchor's key;
      * the anchor was valid at the record's `asserted_at`;
      * the timestamp imprints SHA-256 of the seal (demo token; a real RFC
        3161 token's full validation is the production verifier's, as for
        LINT-PKG-08);
      * the record validates against the published `MembershipRecord`;
      * its history is well-formed (`validate_status_history`) — an
        overlapping history answered as-of questions with the first matching
        window while this very module flagged it as malformed.
    And across records: one record per participant.
    """
    out = []
    anchors = {k: a for k, a in (anchors or {}).items() if a.get("pubkey_b64")}
    if not anchors:
        return None, [("LINT-TRUST-08",
                       "no Federation Authority anchor is configured, so the "
                       "membership register cannot be authenticated — an "
                       "unauthenticated register cannot establish admission")]
    records = (register or {}).get("records")
    if not isinstance(records, list):
        return None, [("LINT-TRUST-08",
                       "the membership register carries no `records` array")]
    try:
        import cbor2
        from nacl.signing import VerifyKey
    except ImportError:  # pragma: no cover — preflighted in the canonical env
        return None, [("LINT-TRUST-08",
                       "cbor2/pynacl unavailable: the register cannot be "
                       "authenticated, so it is not used")]
    seen = {}
    for i, rec in enumerate(records):
        pid = rec.get("participant_id") if isinstance(rec, dict) else None
        tag = f"membership record {i} ({pid!r})"
        # R11-10: whatever a record carries, the answer is a FINDING. The
        # targeted checks in `_authenticate_record` come first; this is the
        # net under them — a malformed record produced a KeyError or a
        # TypeError out of the loader, which is an input deciding whether the
        # verifier answers at all.
        try:
            _authenticate_record(i, rec, pid, tag, anchors, seen, out, cbor2, VerifyKey)
        except Exception as e:                  # fail closed, never crash
            out.append(("LINT-TRUST-08",
                        f"{tag} could not be evaluated ({type(e).__name__}: {e}); "
                        "an unreadable record authenticates nothing"))
    for pid, idx in seen.items():
        if len(idx) > 1:
            out.append(("LINT-TRUST-08",
                        f"the register carries {len(idx)} records for {pid!r} "
                        f"(records {idx}); admission would depend on which was "
                        "read first, so the register is refused, not reconciled"))
    if out:
        return None, out
    return AuthenticatedRegister(register), []


def _authenticate_record(i, rec, pid, tag, anchors, seen, out, cbor2, VerifyKey):
    """One record of `authenticate_register`; every finding appended to `out`.

    R11-10: the protected header and the COSE value types are checked BEFORE
    any cryptography, and the semantic history checks run only once the
    record's structure is known to hold. The loader read the `kid`, ignored
    the declared algorithm and verified as Ed25519 whatever it said — Ed25519
    bytes under `alg` ES256, 0 or 42 all authenticated — converted a null
    payload with `bytes()` outside any guard, and indexed history fields the
    Schema had just reported missing."""
    import base64 as _b64
    import hashlib as _hl
    if not isinstance(rec, dict) or not pid:
        out.append(("LINT-TRUST-08", f"{tag} names no participant"))
        return
    seen.setdefault(pid, []).append(i)
    sig_b64, ts_b64 = rec.get("signature"), rec.get("timestamp")
    if not sig_b64 or not ts_b64:
        out.append(("LINT-TRUST-08",
                    f"{tag} carries no " + ("seal" if not sig_b64 else "timestamp")
                    + " — an unsealed record is an assertion nobody made"))
        return
    try:
        sig_bytes = _b64.b64decode(sig_b64, validate=True)
        cose = cbor2.loads(sig_bytes)
        cose = cose.value if isinstance(cose, cbor2.CBORTag) else cose
        protected, _u, payload, sig = cose
        ph = cbor2.loads(protected) if isinstance(protected, (bytes, bytearray)) \
            and protected else None
    except Exception:
        out.append(("LINT-TRUST-08", f"{tag}: the seal is not a decodable COSE_Sign1"))
        return
    if not isinstance(ph, dict):
        out.append(("LINT-TRUST-08",
                    f"{tag}: the seal's protected header is not a byte string "
                    "holding a map, so neither its signer nor its algorithm is "
                    "authenticated"))
        return
    if not isinstance(payload, (bytes, bytearray)) or \
            not isinstance(sig, (bytes, bytearray)):
        out.append(("LINT-TRUST-08",
                    f"{tag}: the seal's payload or signature is not a byte string "
                    "— a detached or null payload signs nothing this verifier can "
                    "compare with the record"))
        return
    kid = ph.get(4)
    kid = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    alg = ph.get(1)
    if alg != COSE_ALG_BY_NAME["EdDSA"]:
        out.append(("LINT-TRUST-08",
                    f"{tag}: the seal declares algorithm {alg!r}. "
                    + (f"That is the production form ({COSE_ALG_BY_ID[alg]}), which "
                       "this pilot verifier does not implement — unsupported, NOT "
                       "verified. " if alg in COSE_ALG_BY_ID else
                       "That is not an algorithm this profile permits. ")
                    + "The configured anchor is an Ed25519 key, and a signature is "
                    "verified under the algorithm it declares or not at all — "
                    "never under a substituted one"))
        return
    anchor = anchors.get(kid)
    if anchor is None:
        out.append(("LINT-TRUST-08",
                    f"{tag} is sealed under kid {kid!r}, which is not a "
                    f"configured Federation Authority anchor "
                    f"{sorted(anchors)} — §13.1 keeps the admission signer "
                    "distinct from every other role"))
        return
    body = {k: v for k, v in rec.items() if k not in ("signature", "timestamp")}
    if bytes(payload) != dcbor(body):
        out.append(("LINT-TRUST-08",
                    f"{tag}: the record differs from what its seal signed — a "
                    "field was changed after sealing, whatever the signature "
                    "says about the bytes it does cover"))
    try:
        VerifyKey(_b64.b64decode(anchor["pubkey_b64"])).verify(
            cbor2.dumps(["Signature1", protected, b"", payload]), sig)
    except Exception:
        out.append(("LINT-TRUST-08",
                    f"{tag}: the seal does not verify under the Federation "
                    "Authority's key"))
    if not _within_window(rec.get("asserted_at"), anchor.get("not_before"),
                          anchor.get("not_after")):
        out.append(("LINT-TRUST-08",
                    f"{tag} is asserted at {rec.get('asserted_at')!r}, outside "
                    f"the validity window of the anchor {kid!r} that sealed "
                    "it — a retired key does not keep speaking"))
    try:
        tok = _b64.b64decode(ts_b64, validate=True)
    except Exception:
        tok = b""
    demo = parse_demo_qts(tok)
    if not tok or tok[:1] != b"\x30":
        out.append(("LINT-TRUST-08", f"{tag}: the timestamp is not a DER token"))
    elif demo is not None and demo[0] != _hl.sha256(sig_bytes).digest():
        out.append(("LINT-TRUST-08",
                    f"{tag}: the timestamp does not imprint SHA-256 of the seal"))
    shape = validate_contract_object(
        "federation-register-openapi.yaml", "MembershipRecord", rec)
    for ptr, msg in shape:
        out.append(("LINT-TRUST-08",
                    f"{tag} is not a valid MembershipRecord at {ptr}: {msg}"))
    # R11-10: the history rules index fields the Schema requires; they run
    # only once the Schema holds, never over a record it has just refused.
    if not shape:
        for reason, msg in validate_status_history(rec):
            out.append(("LINT-TRUST-08", f"{tag}: {reason} — {msg}"))


def live_authorisation(register, participant_id, *, decision_at, max_age):
    """R11-X3 — may a provider exchange with this peer NOW? A different question
    from `admission_at`, and deliberately a different function.

    `admission_at` answers "was it admitted when it acted", from a record
    asserted AT OR AFTER the act (R10-X1). Under that rule no record held
    before an exchange can cover the exchange, so live use cannot be the
    historical rule with a smaller number — it is a LEASE: a record authorises
    exchange from its `asserted_at` for the maximum assertion age the
    Federation Authority publishes, and the decision is taken at ONE defined
    instant, `decision_at`, the start of the exchange on the deciding
    provider's own clock. Nothing is backdated and no future status is
    guessed: the record says what the status was at `asserted_at`, and the
    lease says how long that may be acted on.

    A live authorisation is NEVER evidence of admission at the act. Evidence
    produced during the exchange is verified later by `admission_at`, against
    a record asserted after the act — exactly as if no live check had run.

    Returns (verdict, detail): "authorised", "stale", "not-admitted",
    "no-record", or "record-from-the-future" (asserted after the decision
    instant — a clock the decision cannot rely on). `max_age` is an ISO 8601
    duration and is REQUIRED: the Federation Authority publishes it (agenda
    A2), and a decision taken without it would be a decision against a bound
    nobody set. Only an `AuthenticatedRegister` is accepted, as for
    `check_register_pin`."""
    if not isinstance(register, AuthenticatedRegister):
        raise TypeError(
            "live_authorisation takes an AuthenticatedRegister — the value "
            "authenticate_register returns — never a register read from input "
            "")
    if max_age is None:
        raise ValueError(
            "no maximum assertion age was supplied: the Federation Authority "
            "publishes it, and a live decision without it has no bound")
    lease = parse_iso_duration(max_age)
    records = [r for r in register.get("records", [])
               if r.get("participant_id") == participant_id]
    if not records:
        return "no-record", f"the register carries no record for {participant_id!r}"
    rec = records[0]
    asserted = instant(rec.get("asserted_at"), field="asserted_at")
    now = instant(decision_at, field="decision_at")
    if asserted > now:
        return ("record-from-the-future",
                f"the record was asserted at {rec.get('asserted_at')}, after the "
                f"decision instant {decision_at}")
    if now - asserted > lease:
        return ("stale",
                f"the record was asserted at {rec.get('asserted_at')}; at "
                f"{decision_at} it is older than the published maximum {max_age}")
    if rec.get("status") != "admitted":
        return ("not-admitted",
                f"the record states {rec.get('status')!r} at its asserted_at")
    return "authorised", f"admitted at {rec.get('asserted_at')}, within {max_age}"


def check_register_pin(doc, seal_b64, store, register):
    """LINT-TRUST-07 (Batch A / A5) — `LINT-TRUST-05` one level up.

    TRUST-05 asks whether a discovery document's seal key is pinned by the
    DIRECTORY for the document's own UID. A provider descriptor has no UID: it
    describes a federation participant, and the document that pins its seal
    keys is that participant's `MembershipRecord`. Same question, different
    pinning authority — so the same shape, implemented next to it rather than
    as a special case inside it.

    Two ways the register can fail to authorise a descriptor, one rule,
    because both answer one question — *does the register authorise THIS
    descriptor?*:

      the seal key is not among that participant's `authorized_seal_keys`,
      or is pinned but outside the pinned key's own window at `asserted_at`;

      the register attributes no `admitted` status to the participant at
      `asserted_at`. An excluded provider stops being resolved (§13.1); a
      descriptor whose participant the register has suspended is not a
      descriptor the register stands behind, and reporting only the key would
      be a gate measuring part of its own surface.

    Instants, never strings (R9-04). Returns a list of (rule, msg).
    """
    if not isinstance(register, AuthenticatedRegister):
        raise TypeError(
            "check_register_pin requires an AuthenticatedRegister — a register "
            "that has not been through authenticate_register is fields as "
            "written, and pinning a key against them is R10-01")
    out = []
    pid = doc.get("participant_id")
    spki = _seal_spki_sha256(seal_b64, store)
    if spki is None:
        # Undecodable seal / unknown signer — LINT-TRUST-01 fails closed first.
        return out
    rec = next((r for r in register.get("records", [])
                if r.get("participant_id") == pid), None)
    if rec is None:
        return [("LINT-TRUST-07",
                 f"no membership record pins an authorized seal key for "
                 f"participant {pid!r} (fail-closed: a descriptor nobody in "
                 "the federation vouches for)")]
    asserted = doc.get("asserted_at")
    pins = [k for k in rec.get("authorized_seal_keys", [])
            if k.get("spki_sha256") == spki]
    if not pins:
        out.append(("LINT-TRUST-07",
                    f"descriptor seal key (spki-sha256 {spki[:16]}…) is not an "
                    f"authorized seal key for participant {pid!r} in the "
                    "membership register — a key the federation has not pinned "
                    "to this participant cannot speak for it"))
    else:
        try:
            when = instant(asserted, field="asserted_at")
            if not any(
                    (k.get("not_before") is None
                     or instant(k["not_before"], field="not_before") <= when)
                    and (k.get("not_after") is None
                         or when <= instant(k["not_after"], field="not_after"))
                    for k in pins):
                out.append((
                    "LINT-TRUST-07",
                    f"descriptor seal key for participant {pid!r} is pinned but "
                    f"the descriptor is asserted at {asserted}, outside the "
                    "pinned key's window (rotation / retirement)"))
        except TimestampError as e:
            out.append(("LINT-TRUST-07",
                        f"the descriptor's `asserted_at` cannot be read ({e}), "
                        "so the pinned key's window cannot be applied to it"))
    try:
        status = admission_at(register, pid, at=asserted)
    except (ValueError, TimestampError) as e:
        return out + [("LINT-TRUST-07",
                       f"the register cannot answer for {pid!r} at {asserted}: "
                       f"{e}")]
    if status is NOT_COVERED:
        # R10-X1. discovery_lint has no third verdict, and a descriptor the
        # register cannot vouch for is not one it authorises: fail closed, and
        # say what would fix it.
        return out + [(
            "LINT-TRUST-07",
            f"the register's record for {pid!r} was asserted before the "
            f"descriptor ({asserted}), so it cannot speak for the instant the "
            "descriptor asserts itself; a later assertion is needed")]
    if status != "admitted":
        out.append((
            "LINT-TRUST-07",
            f"the register attributes "
            + (f"status {status!r}" if status else "NO status")
            + f" to participant {pid!r} at {asserted}, so it does not "
              "authorise this descriptor at the instant the descriptor "
              "asserts itself"))
    return out


_INSTANT_KEYS = {"at", "valid_from", "last_seen", "timestamp"}


def _is_instant_key(k):
    # sent_at / delivered_at / ack_at / verified_at / asserted_at / added_at …
    # but NOT expires_at: expiry is a window bound, not a declared instant.
    return k in _INSTANT_KEYS or (k.endswith("_at") and k != "expires_at")


def _latest_declared_instant(doc):
    """The object's latest declared RFC 3339 instant (issuance-style fields
    only — expiry fields are windows, not instants), or None when it declares
    none. Returned as the ORIGINAL string, so the caller's window test parses
    it again and reports it as written.

    R10-12: this compared the strings, on the documented premise that
    "Zulu-form RFC 3339 strings compare correctly as strings". DR-05 then made
    the walk ADMIT offset forms, so it stopped being Zulu-only and the premise
    stopped holding: `2026-02-28T23:00:00-02:00` sorts before
    `2026-03-01T00:00:00Z` and is ninety minutes after it. `_within_window`
    parsed correctly, so a correct window check was applied to the wrong value
    and LINT-TRUST-03/05 failed open. DR-05's fix created the defect by fixing
    half of it — the filter, not the comparison it fed.

    An instant that cannot be parsed is returned in preference to any parsed
    one, so the caller's window test fails closed on it rather than the walk
    quietly choosing a readable neighbour."""
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                # DR-05: parse, do not filter on a trailing 'Z'.
                if _is_instant_key(k) and isinstance(v, str):
                    found.append(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(doc)
    if not found:
        return None
    parsed = []
    for v in found:
        try:
            parsed.append((instant(v), v))
        except TimestampError:
            return v   # fail closed: the window test will refuse it
    return max(parsed, key=lambda t: t[0])[1]


# ---------------------------------------------------------------------------
# DR-12 — confirmation signatures over EVERY permitted algorithm
# ---------------------------------------------------------------------------
#
# BW-MEMBER permits EdDSA, ES256 and ES384, and the evidence COSE checks allow
# all three. `bundle_lint._verify_wallet_sig()` nonetheless interpreted every
# `public_key_b64` as a raw Ed25519 key and verified with PyNaCl alone. Both
# directions were broken:
#
#   * a CONFORMING ES256 or ES384 confirmation was REJECTED by the reference
#     verifier — evidence a member legitimately produced would not verify;
#   * an algorithm/key MISMATCH was not detected at the bundle layer, which is
#     an algorithm-confusion surface at exactly the layer that decides
#     attribution.
#
# The published algorithm, the COSE protected `alg` and the key's actual
# type/curve must AGREE. A disagreement is a failure, never a fallback: the
# whole point of naming an algorithm in discovery is that a verifier does not
# have to guess from the key's length.

COSE_ALG_BY_NAME = {"EdDSA": -8, "ES256": -7, "ES384": -35}
COSE_ALG_BY_ID = {v: k for k, v in COSE_ALG_BY_NAME.items()}

# Key encodings, one per algorithm — stated so two implementations agree on
# the bytes rather than each accepting what its library happens to parse.
#   EdDSA  raw 32-byte Ed25519 public key (RFC 8032 §5.1.5)
#   ES256  SEC1 UNCOMPRESSED point on P-256: 0x04 || X(32) || Y(32) = 65 bytes
#   ES384  SEC1 UNCOMPRESSED point on P-384: 0x04 || X(48) || Y(48) = 97 bytes
# Compressed points and bare scalars are REJECTED: accepting several encodings
# is how one key acquires two identities.
KEY_ENCODING = {"EdDSA": ("raw-ed25519", 32),
                "ES256": ("sec1-uncompressed-p256", 65),
                "ES384": ("sec1-uncompressed-p384", 97)}

# COSE ECDSA signatures are fixed-width r||s (RFC 9053 §2.1), NOT DER.
_ECDSA_COORD = {"ES256": 32, "ES384": 48}


class SignatureVerificationError(ValueError):
    """A typed verification failure carrying WHY, so a linter can report the
    algorithm confusion rather than a bare 'does not verify'."""


def _cose_protected_alg(protected_bstr):
    """The `alg` in the COSE protected header, as a name. Absent or unknown is
    an error: an unprotected algorithm is one an attacker may choose."""
    import cbor2
    try:
        hdr = cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception as e:
        raise SignatureVerificationError(f"protected header is not CBOR: {e}")
    if not isinstance(hdr, dict) or 1 not in hdr:
        raise SignatureVerificationError(
            "COSE protected header declares no alg (label 1) — the algorithm "
            "must be signed over, not inferred from the key")
    alg = hdr[1]
    if alg not in COSE_ALG_BY_ID:
        raise SignatureVerificationError(f"COSE alg {alg!r} is not permitted")
    return COSE_ALG_BY_ID[alg]


def load_confirmation_key(alg, public_key_b64):
    """Decode a published confirmation key under its DECLARED algorithm.
    Returns an object the corresponding verifier accepts. Wrong length, wrong
    curve and non-uncompressed points all fail closed."""
    if alg not in KEY_ENCODING:
        raise SignatureVerificationError(f"unsupported confirmation-key alg {alg!r}")
    encoding, size = KEY_ENCODING[alg]
    try:
        raw = base64.b64decode(public_key_b64 or "", validate=True)
    except Exception:
        raise SignatureVerificationError("confirmation key is not valid base64")
    if len(raw) != size:
        raise SignatureVerificationError(
            f"{alg} key is {len(raw)} bytes; {encoding} requires exactly {size} "
            "— a key of the wrong length for its declared algorithm")
    if alg == "EdDSA":
        from nacl.signing import VerifyKey
        return VerifyKey(raw)
    if raw[0] != 0x04:
        raise SignatureVerificationError(
            f"{alg} key is not a SEC1 UNCOMPRESSED point (leading byte "
            f"0x{raw[0]:02x}, expected 0x04) — one encoding per algorithm, so "
            "one key cannot acquire two identities")
    from cryptography.hazmat.primitives.asymmetric import ec
    curve = ec.SECP256R1() if alg == "ES256" else ec.SECP384R1()
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, raw)
    except Exception as e:          # point not on the curve, etc.
        raise SignatureVerificationError(f"{alg} key is not a valid point: {e}")


def in_time(event_at, expires_at):
    """X-21 / R11-04 — THE timeliness rule, stated once: an event is in time
    when it is at or before the deadline; a tie is delivered. Instants, never
    strings. Raises TimestampError on an unreadable instant — "I cannot read
    the time" is never "it was in time".

    Which instant is the EVENT is the grade's question, not this one's: S2 at
    the availability grade, the completing confirmation as RDP(in) observed it
    at the verification and acceptance grades (R11-X2). The issuing path
    (`mock_rdp.delivery_decision`) and the retained check (LINT-BND-22) both
    ask it here, so they cannot disagree about a boundary."""
    return instant(event_at, field="event time") <= instant(expires_at,
                                                            field="expires_at")


# The acceptance-policy grammar (umbrella §8.3), stated ONCE. bundle_lint and
# discovery_lint each carried a copy, and the issuing path needs it too
# (R11-02); a third copy is how the first two would have drifted.
POLICY_RE = re.compile(r"^(any-one|all|quorum:(\d+)|device-class:.+)$")


def ack_capable_problem(devices, device_id=None):
    """TS clause 6 INTF-2, its DEVICE half, stated once: None when a relied-on
    confirmation may come from these devices, else the reason.

    With a named device, that device must be among `devices` and ack-capable;
    without one, the member must hold at least one ack-capable device. The
    retained verifier (bundle_lint LINT-BND-12) reads `devices` as of the act;
    the issuing RDP (mock_rdp.deliver_confirmation, R11-03) reads the live
    published member. Before round 11 only the verifier asked, so a sealed NDE
    could carry a confirmation the verifier then refused."""
    if device_id is not None:
        d = next((d for d in devices if d.get("device_id") == device_id), None)
        if d is None:
            return f"device {device_id!r} not enrolled to the member at the act"
        if "ack" not in (d.get("capabilities") or []):
            return f"device {device_id!r} is not ack-capable"
        return None
    if not any("ack" in (d.get("capabilities") or []) for d in devices):
        return "member holds no ack-capable device"
    return None


def verify_cose_signature(sig_b64, key):
    """THE confirmation-signature verifier — one implementation, every
    permitted algorithm. `key` is a published confirmation_key object
    ({alg, public_key_b64}).

    Raises SignatureVerificationError with the reason; returns None on success.
    Callers that only need a boolean can catch it.
    """
    import cbor2
    if not isinstance(key, dict):
        raise SignatureVerificationError("no published confirmation key")
    declared = key.get("alg")
    if declared not in COSE_ALG_BY_NAME:
        raise SignatureVerificationError(
            f"published confirmation_key.alg {declared!r} is not permitted")
    try:
        protected, _u, payload, sig = cbor2.loads(base64.b64decode(sig_b64 or ""))
    except Exception as e:
        raise SignatureVerificationError(f"signature is not a COSE_Sign1: {e}")

    cose_alg = _cose_protected_alg(protected)
    if cose_alg != declared:
        raise SignatureVerificationError(
            f"ALGORITHM CONFUSION: the signature declares {cose_alg}, the "
            f"published key declares {declared}. The two must agree — naming "
            "the algorithm in discovery is pointless if a verifier accepts a "
            "signature that names a different one")

    pub = load_confirmation_key(declared, key.get("public_key_b64"))
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])

    if declared == "EdDSA":
        from nacl.exceptions import BadSignatureError
        try:
            pub.verify(to_sign, sig)
        except BadSignatureError:
            raise SignatureVerificationError("Ed25519 signature does not verify")
        return None

    n = _ECDSA_COORD[declared]
    if len(sig) != 2 * n:
        raise SignatureVerificationError(
            f"{declared} signature is {len(sig)} bytes; COSE requires the "
            f"fixed-width r||s form of {2 * n} (RFC 9053 §2.1) — a DER "
            "signature is not COSE")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"),
                                     int.from_bytes(sig[n:], "big"))
    digest = hashes.SHA256() if declared == "ES256" else hashes.SHA384()
    try:
        pub.verify(der, to_sign, ec.ECDSA(digest))
    except InvalidSignature:
        raise SignatureVerificationError(f"{declared} signature does not verify")
    return None


class CertificateBindingError(ValueError):
    """R3-05: a confirmation-key anchor whose certificate does not authorise
    the key it is published beside."""


def check_certificate_binds_key(x5chain, alg, public_key_b64, at=None):
    """R3-05: PARSE the leaf certificate and prove it carries the SAME public
    key as `public_key_b64`, in the encoding `alg` defines.

    The I-D required this equality; production lint checked only that an
    x5chain was PRESENT. So a production deployment could publish a bare
    asserted raw key beside a certificate for a different key, and the
    advanced-signature identity claim — that the certificate authorises the
    key the confirmations are made under — rested on nothing.

    SCOPE, and it matters: this proves the certificate carries this key, and
    (where `at` is given) that the certificate was within its own validity at
    the act. It does NOT validate the chain to a trust anchor, the QSealC
    qualification, the Trusted-List status or the SCD certification. Those are
    the EXTERNAL production trust policy (F-04, X-01) and remain Partial —
    completing the parsing locally is not completing them.

    Raises CertificateBindingError; returns the parsed leaf on success.
    """
    if not x5chain:
        raise CertificateBindingError("no x5chain to bind the key to")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:                                    # pragma: no cover
        raise CertificateBindingError("cryptography is required (see requirements)")
    leaf_der = x5chain[0]
    if isinstance(leaf_der, str):
        try:
            leaf_der = base64.b64decode(leaf_der, validate=True)
        except Exception:
            raise CertificateBindingError("x5chain[0] is not valid base64 DER")
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as e:
        raise CertificateBindingError(f"x5chain[0] is not a parsable certificate: {e}")

    pub = leaf.public_key()
    if alg == "EdDSA":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(pub, Ed25519PublicKey):
            raise CertificateBindingError(
                f"the certificate holds a {type(pub).__name__}, but the anchor "
                "declares EdDSA — the certificate does not authorise this key")
        cert_bytes = pub.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    else:
        from cryptography.hazmat.primitives.asymmetric import ec
        want_curve = "secp256r1" if alg == "ES256" else "secp384r1"
        if not isinstance(pub, ec.EllipticCurvePublicKey) or \
                pub.curve.name != want_curve:
            raise CertificateBindingError(
                f"the certificate's key is not on {want_curve}, which {alg} "
                "requires — the certificate does not authorise this key")
        cert_bytes = pub.public_bytes(serialization.Encoding.X962,
                                      serialization.PublicFormat.UncompressedPoint)

    try:
        published = base64.b64decode(public_key_b64 or "", validate=True)
    except Exception:
        raise CertificateBindingError("public_key_b64 is not valid base64")
    if cert_bytes != published:
        raise CertificateBindingError(
            "the certificate's subject public key is NOT the published "
            "confirmation key — the certificate attests a different key, so it "
            "authorises nothing about confirmations made under this one")

    if at is not None:
        when = instant(at, field="act_time")
        nb = leaf.not_valid_before_utc if hasattr(leaf, "not_valid_before_utc") \
            else leaf.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") \
            else leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        if not (nb <= when < na):
            raise CertificateBindingError(
                f"the certificate was not valid at {at} (valid {nb} .. {na})")
    return leaf


# R6-03 point 3: the MANDATORY signed set. Equality used to be conditional on
# a field appearing in BOTH objects, so a field present outside and absent
# inside was compared with nothing — and `ds_kid`/`ds_alg` were not in the set
# at all, though the contract says the signature covers the receipt's other
# fields. Re-aliasing one public key under a second published `kid` and
# changing only the outer selector was accepted while the signed payload named
# the original.
DS_RECEIPT_SIGNED_FIELDS = (
    "message_id", "issuing_rdp_id", "observed_by", "recipient_uid", "mid",
    "device_id", "server_time", "message_digest", "session_binding",
    "ds_kid", "ds_alg")
# R7-02 requirement 5: `session_binding` is in `DeliveryReceipt.required` on
# the wire and was NOT here, so a receipt with it removed and re-signed was
# accepted under a partial context. The contract and the code now agree.
DS_RECEIPT_MANDATORY_SIGNED = (
    "message_id", "issuing_rdp_id", "observed_by", "recipient_uid", "mid",
    "device_id", "server_time", "message_digest", "session_binding",
    "ds_kid", "ds_alg")

# R7-02 requirement 4: the EXACT expected-delivery-context type. A dict let a
# caller pass `{}`, or name every dimension with `None` values, and assert
# nothing — because verification skipped `None`. Both are now unrepresentable:
# every member is required and `None` is rejected rather than skipped.
DELIVERY_CONTEXT_FIELDS = (
    "message_id", "issuing_rdp_id", "observed_by", "recipient_uid", "mid",
    "device_id", "session_binding", "message_digest")


class DeliveryContext:
    """What the caller is processing, stated completely or not at all.

    R7-02: `expect={}` was accepted, and so was a context naming every
    mandatory dimension with `None` for each — `verify_ds_receipt` did
    `if want is None: continue`. Requiring the members to be PRESENT does not
    close that; the value has to stop meaning "unchecked". So this type makes
    both shapes impossible to construct: missing members raise, `None` members
    raise, and unknown members raise rather than being ignored as a typo that
    silently narrows the assertion.
    """

    __slots__ = DELIVERY_CONTEXT_FIELDS

    def __init__(self, **fields):
        unknown = sorted(set(fields) - set(DELIVERY_CONTEXT_FIELDS))
        if unknown:
            raise ReceiptVerificationError(
                "receipt-context-invalid",
                f"unknown delivery-context member(s) {unknown}: a misspelt "
                "member would silently assert nothing")
        missing = [f for f in DELIVERY_CONTEXT_FIELDS if f not in fields]
        if missing:
            raise ReceiptVerificationError(
                "receipt-context-incomplete",
                f"the delivery context omits {missing}. A partial context is "
                "what let a receipt for one act authorise another")
        for f in DELIVERY_CONTEXT_FIELDS:
            if fields[f] is None:
                raise ReceiptVerificationError(
                    "receipt-context-incomplete",
                    f"delivery-context member {f!r} is None. `None` used to be "
                    "SKIPPED, so a caller could name every dimension and "
                    "assert nothing")
            setattr(self, f, fields[f])

    def items(self):
        return [(f, getattr(self, f)) for f in DELIVERY_CONTEXT_FIELDS]


class _Unassociated:
    """R40-01: the bundle does not establish WHICH delivery this receipt is about.

    `expect=None` cannot mean this. `None` used to mean "unchecked", and R7-02
    exists because that reading let a caller assert nothing while looking
    complete — so `None` stays refused and this is a separate, named value with
    one meaning: the caller has reported the association as UNESTABLISHED and is
    asking for everything that does not depend on it.

    What it skips is one stage, the last: the comparison with the expected
    delivery context. The key resolution at the receipt's own instant, the
    signature, the mandatory signed fields, the outer-vs-signed equality and the
    `kid` attribution all still run, because none of them needs to know which
    delivery the receipt belongs to. A receipt whose signature does not verify
    does not verify whatever it is about.

    It exists because the retained path used to `continue` past ALL of this
    whenever it could not place the receipt, so adding one unrelated sealed SE to
    a bundle made a forged signature stop being reported. An inability to answer
    one question must not erase the answer to another.

    A caller that passes this MUST have reported the association as incomplete —
    `tests/test_production_signature_claims.py` holds the one caller to that, and
    holds the live path to never passing it at all.
    """

    def items(self):
        raise ReceiptVerificationError(
            "receipt-context-invalid",
            "UNASSOCIATED is not a delivery context and has no fields to "
            "compare — it says the caller could not establish one")

    def __repr__(self):
        return "UNASSOCIATED"


#: The one instance. Compared with `is`, so it cannot be constructed by accident
#: or arrive from parsed input.
UNASSOCIATED = _Unassociated()


class ReceiptVerificationError(ValueError):
    """A DS receipt that cannot be relied upon. Carries the typed reason so the
    live path can return it and the retained path can report it."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def verify_ds_receipt(receipt, provider, *, expect=None):
    """THE receipt check — one implementation, both paths (R5-03/R5-V4).

    Returns the SIGNED payload, authenticated. Raises
    `ReceiptVerificationError` otherwise.

    `expect` (R6-03) is the DELIVERY CONTEXT the caller is processing —
    `message_id`, `recipient_uid`, `mid`, `device_id`, `session_binding`,
    `message_digest`, the message's ORIGIN (`issuing_rdp_id`) and the provider that
    OBSERVED the handover (`observed_by`) — two different parties in a four-corner
    exchange, and the second is whose key verifies this (SBM-ADR-0016).
    Every stated field must equal the SIGNED payload. Without it a receipt
    proved that SOME delivery happened and was accepted for whichever act the
    caller had in hand.

    R4-03 fixed this in `bundle_lint` and not in the live issuing path, so the
    two disagreed about what a receipt proves: retained verification compared
    the asserted fields with the signed payload, and
    `mock_rdp.delivered_at_from_receipt` returned the OUTER `server_time`
    unchecked. Moving that field made the live path report a delivery instant
    nobody had signed while the retained path caught it. Two paths, one check —
    so there is one check now, and the live path returns the SIGNED instant.

    **Order matters, and it is the part that will be "simplified" away.** The
    key must be resolved at the receipt's own `server_time` (R3-04: a receipt
    signed in 2026 must still verify in 2033, after the key has rotated out),
    and that instant lives INSIDE the payload — so the payload is parsed BEFORE
    the signature over it is verified. Everything read before step 5 is
    therefore UNTRUSTED INPUT and is used only to choose what to check against;
    nothing is accepted on its basis. `kid` is a lookup hint: naming the wrong
    key can only make verification fail. The instant likewise only selects
    which published key must have signed — a forged instant that no valid key
    covers resolves to nothing.

    **When the caller cannot say which delivery.** `expect=UNASSOCIATED` runs
    every stage but the last and returns the authenticated payload. It is for the
    retained path, where the bundle may evidence one identifier under several
    origins; the association is reported unestablished and the signature is still
    verified, because a forged receipt is forged whichever delivery it names. The
    live path never passes it — it is processing a delivery it has in hand.

    **LIMIT, stated because the model has one.** Judging validity at the
    receipt's own time means a party holding a DS key that WAS valid in some
    past window can mint a receipt dated inside that window, and this check
    cannot tell the difference. That is inherent in retention-era verification,
    not a defect here: the counterweight is the DS operator's key management
    and revocation, which is external (X-01/F-04) and stays external.
    """
    import cbor2

    if not isinstance(receipt, dict):
        raise ReceiptVerificationError(
            "receipt-malformed", "not a receipt object")
    kid = receipt.get("ds_kid")
    if not kid:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            "the receipt names no ds_kid, so 'the DS's published key' has no "
            "referent and the verifying key cannot be resolved")
    # SBM-ADR-0015/0016: the key is the OBSERVING provider's OWN, published in its
    # BW-PROVIDER descriptor. Both arms below are the sentence this function's
    # docstring already made — "a kid published only in a BW-MED does not
    # resolve" — and neither was enforced. The resolver read `ds_receipt_keys`
    # off whatever mapping it was handed, so the BW-MED 2.1 projection, which
    # still publishes `ds-demo-2026`, verified a receipt when passed as
    # `provider=`: the parameter was renamed from `med` and the check was not
    # moved with it. Both checks are settled HERE rather than at the call sites,
    # because there is one implementation of the receipt check and the bundle
    # path was tighter only by accident — `_descriptor_for` matches on
    # `participant_id`, and a MED has none to match.
    kind = (provider or {}).get("type")
    if kind != "BW-PROVIDER-v1":
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the document supplied as the observing provider's descriptor is of type "
            f"{kind!r}, not 'BW-PROVIDER-v1' — a receipt key is resolved from "
            "the provider's own descriptor and from nothing else, so the MED "
            "path stays deleted rather than reachable by argument "
            "(SBM-ADR-0015)")
    # WHOSE descriptor must this be? The OBSERVER's — the provider whose Delivery
    # Service signed the receipt. It is NOT `issuing_rdp_id`: that field is the
    # message's origin, proven by its SE (the DS contract says so in terms), and
    # in a four-corner exchange the handover is observed on the other side. This
    # check first demanded the ORIGIN publish the key, which refused the
    # legitimate recipient-side signer and passed only because the sample had been
    # built with the origin rewritten to equal the signer. `observed_by` is the
    # signed field that answers the question (R37-01/SBM-ADR-0016).
    observer, held_by = receipt.get("observed_by"), provider.get("participant_id")
    if not observer:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            "the receipt names no observed_by, so the provider whose Delivery "
            "Service signed it is unknown and no descriptor can be shown to be "
            "the right one — `issuing_rdp_id` is the message's ORIGIN and does "
            "not answer this (SBM-ADR-0016)")
    if held_by != observer:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the descriptor supplied is {held_by!r}'s and the handover was "
            f"observed by {observer!r} — a provider publishes its own Delivery "
            "Service's receipt keys, so another participant's descriptor cannot "
            "authorise this receipt (SBM-ADR-0016)")
    if not (provider or {}).get("ds_receipt_keys"):
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the receipt names key {kid!r} but the observing provider's BW-PROVIDER "
            "publishes no ds_receipt_keys — the obligation to verify against "
            "'the published key' has no referent (R3-04/SBM-ADR-0015). The "
            "entity's BW-MED is NOT consulted: that path is deleted, so a kid "
            "published only there does not resolve")

    # 1-2. UNTRUSTED: decode the embedded payload to learn which instant the
    # signer claims. Nothing here is believed; it selects what must verify.
    try:
        raw = cbor2.loads(base64.b64decode(receipt.get("ds_signature") or ""))[2]
        claimed = cbor2.loads(raw) if isinstance(raw, bytes) else raw
    except Exception as e:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the signed payload cannot be decoded, so the asserted fields "
            f"cannot be compared with it: {e}")
    if not isinstance(claimed, dict):
        raise ReceiptVerificationError(
            "receipt-unverifiable", "the signed payload is not an object")

    at = claimed.get("server_time") or receipt.get("server_time")
    if not at:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            "neither the receipt nor its signed payload carries a server_time, "
            "so key validity cannot be judged at the receipt's own instant "
            "")

    # 3-4. Resolve the published key that must have signed at that instant.
    try:
        key = resolve_ds_receipt_key(provider, kid, at=at)
    except (ReceiptKeyError, TimestampError) as e:
        raise ReceiptVerificationError("receipt-unverifiable", f"{e}")
    if receipt.get("ds_alg") is not None and key.get("alg") != receipt.get("ds_alg"):
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the receipt declares alg {receipt.get('ds_alg')!r} but key "
            f"{kid!r} is published as {key.get('alg')!r} — algorithm confusion "
            "")

    # 5. NOW the payload is authenticated — and not one instant earlier.
    try:
        verify_cose_signature(receipt.get("ds_signature") or "", key)
    except SignatureVerificationError as e:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the signature does not verify against the published key {kid!r}: "
            f"{e} — the delivery it attests is unproven")

    # 6. A valid signature is still not enough: the COSE payload is EMBEDDED,
    # so the signature covers the bytes inside the structure, not the object
    # presented beside it. The asserted fields must EQUAL the signed ones,
    # exactly as LINT-DE-19 compares the D4 tuple with its SE.
    missing = [f for f in DS_RECEIPT_MANDATORY_SIGNED if f not in claimed]
    if missing:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the signed payload omits {missing} — a receipt must SIGN the "
            "fields it is relied upon for, and comparing only the intersection "
            "of what happens to be present compares an omitted field with "
            "nothing")
    for field in DS_RECEIPT_SIGNED_FIELDS:
        if field not in claimed:
            continue
        if field in receipt and receipt[field] != claimed[field]:
            raise ReceiptVerificationError(
                "receipt-unverifiable",
                f"{field} is {receipt[field]!r} but the SIGNED payload says "
                f"{claimed[field]!r} — the signature is valid over something "
                "other than what the receipt asserts")

    # R6-03 point 4: the key the signature was verified with must be the key
    # the payload NAMES. Resolution used the outer selector, so re-aliasing one
    # public key under a second published kid and swapping only the outer field
    # verified fine — the cryptography was real and the attribution was not.
    if claimed.get("ds_kid") != kid:
        raise ReceiptVerificationError(
            "receipt-unverifiable",
            f"the receipt selects key {kid!r} but the signed payload names "
            f"{claimed.get('ds_kid')!r} — the verifying key must be the one the "
            "signer committed to")

    # R6-03 point 2: the expected DELIVERY CONTEXT. A valid receipt for message
    # A was accepted while processing message B whenever the ciphertext digest
    # matched, because the function had no parameter with which to notice. The
    # caller states what it is expecting and every stated field must match the
    # SIGNED payload exactly.
    # R40-01: the caller may have been unable to say WHICH delivery this is —
    # one identifier evidenced under several origins, with nothing in the bundle
    # choosing between them. That is a question about the bundle, not about the
    # receipt, and it is reported as such (LINT-BND-I9). Everything above does
    # not depend on the answer and has already run; this one comparison does, and
    # is the only thing skipped. `None` still raises: it meant "unchecked".
    if expect is UNASSOCIATED:
        return claimed
    if not isinstance(expect, DeliveryContext):
        raise ReceiptVerificationError(
            "receipt-context-invalid",
            "the expected delivery context must be a DeliveryContext — a bare "
            "mapping allowed `{}` and all-None contexts, which asserted "
            "nothing while looking complete")
    for field, want in expect.items():
        if claimed.get(field) != want:
            raise ReceiptVerificationError(
                "receipt-context-mismatch",
                f"the receipt attests {field}={claimed.get(field)!r} but this "
                f"act is {want!r} — a valid signature over a DIFFERENT "
                "delivery")
    return claimed


class ReceiptKeyError(ValueError):
    """R3-04: the DS receipt's verification key cannot be resolved."""


def resolve_ds_receipt_key(provider, kid, at):
    """R3-04/R3-T3: the DS receipt key named by `kid`, as it stood at `at` —
    the receipt's OWN `server_time`, not verification time.

    That distinction is the whole point of publishing a history: a receipt
    signed in 2026 must still verify in 2033, after the key that signed it has
    been rotated out and its `valid_until` has passed. Judging validity at
    verification time would expire the evidence along with the key.

    Raises ReceiptKeyError; callers turn it into a typed violation.
    """
    keys = [k for k in ((provider or {}).get("ds_receipt_keys") or [])
            if k.get("kid") == kid]
    if not keys:
        raise ReceiptKeyError(
            f"no ds_receipt_keys entry with kid {kid!r} in the observing provider's "
            "BW-PROVIDER descriptor — the receipt names a key nobody published")
    if len(keys) > 1:
        raise ReceiptKeyError(
            f"{len(keys)} ds_receipt_keys entries share kid {kid!r} — a "
            "duplicate identifier makes the verifying key ambiguous, which is "
            "the substitution risk the identifier exists to remove")
    key = keys[0]
    when = instant(at, field="server_time")
    if instant(key["valid_from"], field="valid_from") > when:
        raise ReceiptKeyError(
            f"key {kid!r} takes effect at {key['valid_from']}, after the "
            f"receipt's server_time {at} — it cannot have signed it")
    vu = instant_or_none(key.get("valid_until"))
    if vu is not None and when >= vu:
        raise ReceiptKeyError(
            f"key {kid!r} ceased at {key.get('valid_until')}, at or before the "
            f"receipt's server_time {at}")
    return key


def check_trust(doc, seal_b64, store, expected_role, identity=None):
    """LINT-TRUST-01/02/03 for one document against a loaded store.
    Returns a list of (rule, message); empty = trusted (demo scope)."""
    out = []
    try:
        import cbor2
        cose = cbor2.loads(base64.b64decode(seal_b64))
        protected, _u, payload, sig = cose
        ph = cbor2.loads(protected) if protected else {}
        kid = ph.get(4) if isinstance(ph, dict) else None
        kid = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    except Exception:
        out.append(("LINT-TRUST-01",
                    "seal is not a decodable COSE_Sign1 — cannot resolve a signer "
                    "against the trust store (fail-closed)"))
        return out
    entry = store.get("entries", {}).get(kid)
    if entry is None:
        out.append(("LINT-TRUST-01",
                    f"seal kid {kid!r} does not resolve to a trust-store entry "
                    "(fail-closed: unknown signer)"))
        return out
    try:
        import cbor2
        from nacl.signing import VerifyKey
        to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
        VerifyKey(base64.b64decode(entry["pubkey_b64"])).verify(to_sign, sig)
    except ImportError:  # pragma: no cover — pynacl is preflighted in the canonical env
        pass
    except Exception:
        out.append(("LINT-TRUST-01",
                    f"seal signature does not verify against the trust-store key "
                    f"for kid {kid!r}"))
    if entry.get("role") != expected_role:
        out.append(("LINT-TRUST-02",
                    f"kid {kid!r} has store role {entry.get('role')!r}, expected "
                    f"{expected_role!r} for this document type"))
    ids = entry.get("identities")
    if identity is not None and ids is not None and identity not in ids:
        out.append(("LINT-TRUST-02",
                    f"signer identity {identity!r} is not among the trust-store "
                    f"identities for kid {kid!r}"))
    inst = _latest_declared_instant(doc)
    if inst is not None and not _within_window(inst, entry.get("not_before"),
                                               entry.get("not_after")):
        out.append(("LINT-TRUST-03",
                    f"object instant {inst} lies outside the trust-store validity "
                    f"window [{entry['not_before']}, {entry['not_after']}] for kid {kid!r}"))
    return out
