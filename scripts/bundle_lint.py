#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-document bundle validator (N2) — the pilot/test-event tool.

Checks the *coherence* of a discovery bundle (one BW-MED + one BW-ORG + a set of
BW-MEMBER documents + optional evidence) that per-document linters cannot see:

  LINT-BND-01  MED mls.scopes_supported <=> ORG publishes a scope_map
  LINT-BND-02  every scope role is held by >= 1 active MEMBER
  LINT-BND-03  member device capabilities satisfy the scopes referencing them
               (a scope role's holders can 'receive'; the scope has an 'ack'-capable member)
  LINT-BND-04  every acceptance_policy_ref resolves — scope refs to a policy key,
               evidence refs to the ORG policy_version in force
  LINT-BND-05  evidence scope_ref (id+version) resolves against the ORG scope map
               (the implicit default scope is fixed at version "1", §8.3a)
  LINT-BND-10  evidence acceptance_policy_ref.doc_digest equals the SHA-256
               of the ORG's signed payload (document minus doc_cose_b64, §8.3)
  LINT-BND-11  an availability-grade DE requires the referenced ORG to declare
               the availability grade for at least one content class (§8.3b);
               with a reveal fixture (manifest grade_reveals, X0) the FULL
               commitment verification runs: recompute + class-declared check
  LINT-BND-12  a recipient confirmation (and, under quorum/all, each acking
               member) resolves to an active, ack-capable BW-MEMBER of the
               recipient entity (TS clause 6 INTF-2, S2)
  LINT-BND-13  message_id is globally unique per issuing environment: across the
               evidence set no message_id maps to two recipients or two payloads
               (the I-D Error Handling and Retries; TS clause 6 INTF-4, S4)
  LINT-BND-14  a system acting identity (auth_context.identity=system) names an
               acting MID that, where it is a member of this entity, is an active
               member_type=system member (Annex R, A1)
  LINT-BND-15  an agent-sent SE's mandate_ref matches the acting system member's
               standing mandate (issuer+id) and is in validity at sent_at
               (Annex R, A2); with a mandate-reveal fixture (manifest
               mandate_reveals, A1) the FULL commitment verification runs:
               recompute + revealed content_class IN the mandate scope
  LINT-BND-16  a human_acceptance scope excludes system members from its
               acceptance eligible set; an all-system eligible set is
               unsatisfiable (Annex R, A3, §8.3)
  LINT-BND-17  a recoverability=records scope's records_role is staffed by >= 1
               active member, so the records leaf resolves (F16, §8.3a)
  LINT-BND-18  a system member's acknowledgement does not satisfy a
               human_acceptance scope — agents verify (S3) but do not legally
               accept (S4) a human-gated class (Annex R, A8, §8.3)
  LINT-BND-19  a B.2 RelayRejection and the sender-facing NDE for the same
               message_id agree on the reason per the TS clause 4.1 B.2->NDE
               mapping (finding 7): a typed relay rejection must not collapse to
               a single sender-facing reason
  LINT-BND-22  outcomes are temporally coherent with SE.expires_at (finding R1):
               an `expired` NDE is not premature (observed_at >= expires_at) and a
               non-availability DE does not post-date expires_at — the authenticated
               deadline, the ttl itself being envelope-only and unverifiable
  LINT-BND-28  where the bundle's entity IS the sender (SE sender_uid ==
               entity_uid, X-03/D4), the sender_confirmation resolves: the
               signing mid is an ACTIVE member of the sender entity and the
               wallet signature verifies against that member's published
               confirmation_key anchor per (mid, device_id) — the LINT-BND-21
               mirror on the sender side (INTF-1b)
  LINT-BND-32  confirmation-key uniqueness across the bundle's member set
               (X-32): the same confirmation public key on two device records
               — across devices, members or entities — collapses device-bound
               assurance and makes attribution ambiguous; rejected
  LINT-BND-31  a sender NDE translating a B.2 RelayRejection carries the
               RELAY-stage event B.3-RelayFailure (X-28): the rejection
               happened after the sender-side A.1, so an A.2 (pre-submission)
               event would make the EP's timeline read as accepted-then-
               rejected-before-submission — chronologically invalid
  LINT-BND-30  the evidence names the EXACT policy selected (F-08, evidence
               2.4): where the message's SE and the pinned ORG are both in the
               bundle, acceptance_policy_ref.policy_key equals the recomputed
               umbrella §8.3 deterministic selection, exists in the ORG's map,
               and a confirmed DE's acceptance_policy_kind equals the kind of
               the keyed policy — two keys in one BW-ORG can never produce
               indistinguishable evidence
  LINT-BND-29  a member refusal (RE-v1, refusal_kind "member", X-29) resolves:
               the refusing mid is an ACTIVE member of the recipient entity, and a
               wallet-signed refusal_confirmation verifies against the SAME
               published confirmation_key anchor as an acceptance — resolved per
               (mid, device_id) from BW-MEMBER. Refusing needs no ack capability
               (declining is not acknowledging) but it does need membership
  LINT-BND-21  a wallet-signed recipient confirmation verifies against the
               confirming device's PUBLISHED confirmation_key anchor, resolved per
               (mid, device_id) from BW-MEMBER (finding D): the reference-verifier
               check at lint time. Fail-closed on no device_id, no resolvable
               anchor, or a signature that does not verify — an RDP-minted
               confirmation under a foreign key (finding F) fails here
  LINT-BND-20  an EP's rdp_chain[].evidence.seal_digest is RECOMPUTED against the
               referenced B.x object when that object is in the same bundle
               (CF-5): SHA-256 over the DECODED COSE_Sign1 bytes of its seal.
               evidence_lint sees one object at a time and can only check the hex
               is well-formed, so any 64-hex string survives there — this is where
               the reference is actually BOUND to an object
  LINT-BND-I1  INCOMPLETE (R5-02): no policy history, so MAXIMALITY IS
               UNPROVEN — the pinned version is shown to have been in force,
               not to have been the latest (R4-02).
  LINT-BND-W1  WARNING (non-fatal): an acceptance policy uses device-class:,
               which MUST NOT be used in baseline-profile deployments — it
               requires the MWAP and device attestation (§8.3, V5)
  LINT-BND-06  MED/ORG/MEMBER UID coherence with the bundle entity
  LINT-BND-07  acceptance_policy grammar: any-one | all | quorum:<n, n>=1> | device-class:<c>
  LINT-BND-08  quorum:n / any-one satisfiable: >= n (resp. 1) DISTINCT active,
               ack-capable members eligible (umbrella par. 8.3 — the counting
               unit is the member/party, never the device)
  LINT-BND-09  'all' satisfiable: non-empty eligible set, every member ack-capable

Usage:
    python scripts/bundle_lint.py samples/bundle.default.manifest.json samples/bundle.scoped.manifest.json
Exit 0 = clean, 1 = at least one violation, 2 = usage / read error.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lint_cli as lc  # noqa: E402  — R26-PUB-02: the derived wallet-proof field set
from lint_cli import (parse_common_flags, compute_grade_commitment,  # noqa: E402  — shared (P1/X0)
                      instant, instant_or_none,  # noqa: E402  — DR-05 parsed instants
                      TimestampError,  # noqa: E402
                      CommitmentInputError,  # noqa: E402  — DR-03 typed input error
                      as_of_resolve,  # noqa: E402  — R4: ONE as-of implementation
                      admission_at,  # noqa: E402  — A4: ONE admission rule
                      load_federation_register,  # noqa: E402  — A5
                      authenticate_register,  # noqa: E402  — R10-01
                      federation_authority_anchors,  # noqa: E402  — R10-01/02
                      NOT_COVERED,  # noqa: E402  — R10-X1
                      expiry_problems,  # noqa: E402  — R10-08 ONE X-22 rule
                      sealed_at,  # noqa: E402  — R10-X5
                      load_trust_store,  # noqa: E402  — R10-01 anchor
                      select_policy_key,  # noqa: E402  — shared selection (X-12/F-08)
                      UnaddressedSubmission,  # noqa: E402  — R3-01 fail-closed
                      ForeignAddress,  # noqa: E402  — R4-01 fail-closed
                      parse_bw_address,  # noqa: E402  — R5-01 ONE parser
                      resolve_ds_receipt_key, ReceiptKeyError,  # noqa: E402  — R4-03
                      verify_ds_receipt,  # noqa: E402  — R5-03 ONE receipt check
                      DeliveryContext,  # noqa: E402  — R7-02 exact context
                      DELIVERY_CONTEXT_FIELDS,  # noqa: E402
                      check_identity_coherence,  # noqa: E402  — R6-01 SHARED
                      check_scope_in_force,  # noqa: E402  — R6-01
                      ReceiptVerificationError,  # noqa: E402
                      check_certificate_binds_key,  # noqa: E402  — R4-04
                      CertificateBindingError,  # noqa: E402
                      compute_mandate_commitment,  # noqa: E402  — shared (A1)
                      compute_seal_digest,  # noqa: E402  — shared seal digest (CF-5)
                      RELAY_B2_TO_NDE,  # noqa: E402  — shared relay->NDE map (finding 7)
                      verify_cose_signature,  # noqa: E402  — DR-12 multi-alg
                      SignatureVerificationError,  # noqa: E402
                      reconstruct, dcbor)  # noqa: E402  — M4 artefact decode
import base64  # noqa: E402
import cbor2  # noqa: E402  — R4-03: compare the SIGNED payload
import hashlib  # noqa: E402


def _verify_wallet_sig(sig_b64, key):
    """Verify a wallet-confirmation COSE_Sign1 against the PUBLISHED
    confirmation key — the reference-verifier check at lint time (finding D,
    LINT-BND-21). Returns None on success, else the REASON.

    DR-12: this used to interpret every key as raw Ed25519 and verify with
    PyNaCl alone, though BW-MEMBER permits EdDSA, ES256 and ES384. A conforming
    ES256 confirmation was rejected, and an algorithm/key mismatch went
    undetected — algorithm confusion at the layer that decides attribution. The
    dispatch, the encodings and the three-way agreement between the COSE alg,
    the published alg and the key's actual curve now live in ONE shared
    implementation (lint_cli.verify_cose_signature); this wrapper only adapts
    it to the linter's boolean-ish call sites and preserves the reason.

    `key` is the confirmation_key OBJECT — not the bare public bytes — because
    the algorithm is part of what must be checked.
    """
    try:
        verify_cose_signature(sig_b64, key)
        return None
    except SignatureVerificationError as e:
        return str(e)
    except Exception as e:                      # fail closed, never silently
        return f"signature could not be evaluated: {e}"


def _lt(a, b, add=None, field="instant"):
    """DR-05: parsed strict-less-than. A malformed instant is REPORTED (via
    `add`) and treated as a failure of the check, never as a passing string
    comparison."""
    try:
        return instant(a, field=field) < instant(b, field=field)
    except TimestampError as exc:
        if add:
            add("LINT-BND-22", f"unparsable instant in a window check: {exc}")
        return False


def _gt(a, b, add=None, field="instant"):
    """DR-05: parsed strict-greater-than (see `_lt`)."""
    try:
        return instant(a, field=field) > instant(b, field=field)
    except TimestampError as exc:
        if add:
            add("LINT-BND-22", f"unparsable instant in a window check: {exc}")
        return False


def _within(value, lo, hi):
    """DR-05: inclusive window on parsed instants; malformed fails closed."""
    try:
        at = instant(value)
        return ((lo is None or instant(lo) <= at)
                and (hi is None or at <= instant(hi)))
    except TimestampError:
        return False


def _load(path):
    with open(path, encoding="utf-8") as f:
        return reconstruct(json.load(f))   # M4: decode the artefact to the flat shape


from lint_cli import POLICY_RE, ack_capable_problem, in_time  # noqa: E402  — R11-02/03/04: stated once


def lint_bundle(manifest, base, fa_anchors=None):
    """Load the bundle's documents from disk and check their coherence. An
    OPTIONAL manifest key `grade_reveals` names a reveal fixture (X0): a JSON
    file whose `reveals` list maps message_id -> (salt, content_class),
    enabling FULL grade-commitment verification in LINT-BND-11. OPTIONAL
    `member_history` (mid -> [member files]) and `roster` (a ROSTER-v1
    snapshot) enable the DR-11 act-time resolution, LINT-BND-34."""
    reveals = {}
    if manifest.get("grade_reveals"):
        data = _load(os.path.join(base, manifest["grade_reveals"]))
        reveals = {r["message_id"]: r for r in data.get("reveals", [])}
    mandate_reveals = {}
    if manifest.get("mandate_reveals"):
        data = _load(os.path.join(base, manifest["mandate_reveals"]))
        mandate_reveals = {r["message_id"]: r for r in data.get("reveals", [])}
    # DR-11: OPTIONAL `member_history` (mid -> [BW-MEMBER versions, each with
    # valid_from and an optional valid_until]) and `roster` (the ROSTER-v1
    # snapshot covering the evidence epoch). Without them a bundle behaves as
    # before; with them, confirmations are resolved as they stood at the act.
    member_history = None
    if manifest.get("member_history"):
        member_history = {mid: [_load(os.path.join(base, f)) for f in files]
                          for mid, files in manifest["member_history"].items()}
    roster = _load(os.path.join(base, manifest["roster"])) \
        if manifest.get("roster") else None
    # R3-02: the ordered BW-ORG chain, oldest first or any order (it is sorted).
    policy_history = [_load(os.path.join(base, f))
                      for f in (manifest.get("policy_history") or [])] or None
    # R4-03: OPTIONAL retained DS receipts, {message_id: file}.
    receipts = {mid: _load(os.path.join(base, f))
                for mid, f in (manifest.get("receipts") or {}).items()} or None
    # R5-05: OPTIONAL retained GroupContext octets. R4-06 built the semantic
    # verifier, added `group_contexts` to check_bundle and NEVER PASSED IT
    # HERE, and no manifest carried the material — so the rule was reachable
    # only from a hand-built unit test, which is the exact integration failure
    # round 4 existed to eliminate, committed in the batch that eliminated it.
    #
    # The file lists {mls_group_id, mls_epoch, group_context_b64}; the bytes
    # are the retained GroupContext whose hash the evidence already pins as
    # `mls_state` (F-03), so supplying them adds no new trust — it lets the
    # DECISION they encode be recomputed rather than merely committed to.
    # R6-01: the counterparty roster, so the sender-side tuple is decidable.
    counterparty_members = [_load(os.path.join(base, m))
                            for m in (manifest.get("counterparty_members") or [])] or None
    # R6-05: the material the semantic recomputation needs. Without these the
    # strongest-usable arm cannot run and the bundle says so (LINT-BND-I5)
    # instead of reporting a clean verdict it did not reach.
    # R12-X4: the inputs each group's suite decision was taken on — its
    # members and per-device package availability — retained as ONE object
    # per formation, which the decision commits to by digest. This replaces
    # the separate `package_suites` table, which was keyed by (mid, device_id)
    # and bound to nothing, and let the members be whatever was current.
    fi_doc = manifest.get("formation_inputs")
    formation_inputs = (_load(os.path.join(base, fi_doc)).get("formations", [])
                        if fi_doc else None)
    reg_file = manifest.get("suite_registry")
    suite_registry = _load(os.path.join(base, reg_file)) if reg_file else None
    # A5: the federation membership register, a Stage-1 file. Loaded through
    # `lint_cli.load_federation_register` so a malformed register raises here
    # rather than resolving to "nobody is admitted" — which would look like a
    # fail-closed run while actually having no input at all.
    fed_file = manifest.get("federation_register")
    federation_register = (load_federation_register(os.path.join(base, fed_file))
                           if fed_file else None)
    group_contexts = None
    gc_file = manifest.get("group_contexts")
    if gc_file:
        doc = _load(os.path.join(base, gc_file))
        group_contexts = {
            (c["mls_group_id"], c["mls_epoch"]):
                base64.b64decode(c["group_context_b64"], validate=True)
            for c in doc.get("contexts", [])}
    return check_bundle(
        manifest.get("entity_uid"),
        _load(os.path.join(base, manifest["med"])),
        _load(os.path.join(base, manifest["org"])),
        [_load(os.path.join(base, m)) for m in manifest.get("members", [])],
        [_load(os.path.join(base, e)) for e in manifest.get("evidence", [])],
        reveals=reveals,
        mandate_reveals=mandate_reveals,
        member_history=member_history,
        roster=roster,
        policy_history=policy_history,
        receipts=receipts,
        group_contexts=group_contexts,
        counterparty_members=counterparty_members,
        formation_inputs=formation_inputs,
        suite_registry=suite_registry,
        federation_register=federation_register,
        fa_anchors=fa_anchors,
    )


def _parse_bw_address(addr):
    """The canonical parser, called rather than re-spelled (R5-01).

    This module used to carry its own regex, and round 4 asserted the two
    agreed with each other. They did; both were wrong in the same way, because
    neither was ever compared with the Schema. One authority now:
    `lint_cli.parse_bw_address`, whose acceptance IS the published
    `BwAddress` pattern. Invariant 3 — the superseded spelling is deleted, not
    left reachable.
    """
    return parse_bw_address(addr)


def is_warning(rule):
    """R4: ONE definition of what counts as ADVISORY.

    `main()` split warnings off with a `startswith` and every other caller —
    tests included — compared the whole list against `[]`, so adding a warning
    broke callers that only ever meant violations. Two spellings of one rule is
    the R4 family; this is the single one.
    """
    return rule.startswith("LINT-BND-W")


def is_incomplete(rule):
    """R5-02/R5-V1 — the THIRD verdict, and the reason it had to exist.

    The retired maximality warning (the W2 slot) said, in the tool's own words,
    that MAXIMALITY IS NOT PROVEN
    — the property that decides which policy governs a message, and therefore
    the legally decisive one — and `main()` then printed `[OK] ✓` and returned
    0. Four shipped positive bundles did exactly that, and `make conformance`
    was green over all of them.

    Stating an unproven property is honest engineering. Reporting SUCCESS while
    stating it is the defect: a release bar that passes an incomplete
    verification teaches every downstream reader that the gap does not matter.

    So incompleteness is neither a warning nor a violation. Nothing is WRONG
    with the evidence — the verifier could not establish a required property
    from the material it was given, which is a different claim and deserves a
    different word. The I-prefixed rule ids are that class: they do not print
    `[OK]`, and they do not exit 0.

    R4-U1 built the typed outcome and left this half open in as many words:
    *"requiring the full chain inside every bundle is a separate decision
    nobody has taken."* R5-V1 takes it.
    """
    return rule.startswith("LINT-BND-I")


def violations(issues):
    """The fatal subset of check_bundle's output."""
    return [(r, m) for r, m in issues
            if not is_warning(r) and not is_incomplete(r)]


def warnings_of(issues):
    return [(r, m) for r, m in issues if is_warning(r)]


def incomplete_of(issues):
    return [(r, m) for r, m in issues if is_incomplete(r)]


# R7-05: the optional RETAINED MATERIAL a complete verification consumes. It
# is declared once, here, and both the signature below and the
# required-properties table are checked against it — so a new input cannot be
# added to one and forgotten in the other.
RETAINED_MATERIAL_INPUTS = (
    "policy_history", "receipts", "group_contexts", "counterparty_members",
    "formation_inputs", "suite_registry", "federation_register",
    # R23-01/A15: the input that WOULD establish that a CE's output
    # commitments are the transformation of its input. No bundle carries one,
    # because no operation is defined to produce it — the output commitment is
    # typed `mls10-message`, a COMPLETE MLSMessage, which a fragment is not.
    # Named here rather than left unnameable, so the gap is reported through
    # the same machinery as every other unestablished property, and so a
    # definition has somewhere to arrive.
    "transformation_traces")


# Batch A / A5 — the ACT's own instant, per evidence type. Admission is asked
# about the moment the provider acted (umbrella §13.1), so the rule needs to
# know which field carries that moment for each object.
#
# This map is knowledge, not derivation: nothing in a Schema says that DE's act
# happened at `delivered_at`. What IS derived is the set of fields that name a
# provider (below) and the set of types this map must cover — a test compares
# it against the evidence Schemas on disk, so a new evidence type cannot arrive
# without either an entry here or a deliberate exclusion. And a provider found
# with no instant in scope is a VIOLATION, not a skip: the one failure mode a
# hand-written map has is silence, and this closes it.
ACT_INSTANT = {
    "SE-v1": "sent_at",
    "DE-v1": "delivered_at",
    "NDE-v1": "observed_at",
    "RE-v1": "refused_at",
    "CE-v1": "changed_at",
    "GCM-v1": "read_at",
    "RelayEvidence-v1": "hop_at",
}
# EP-v1 RECORDS other acts — each `rdp_chain[]` entry and embedded object
# carries the instant of the act it records — and IS an act itself: its
# composer seals it at the instant its own timestamp attests (R10-X5). That
# instant is not a body field, so it is not in the map above; the TRUST-06
# loop reads it from the package's timestamp. This comment used to say EP
# "has no instant of its own", which is how the composer went unchecked.
ACT_INSTANT_COMPOSED = {"EP-v1"}


def _provider_id_fields():
    """The field names that name a provider, DERIVED from the evidence Schemas.

    The work order's list was `rdp_id`, the EP's composing `se.rdp_id`, and
    relay's `sending_rdp_id` / `receiving_rdp_id`. Hand-writing it here is the
    defect R8-05 found one level down: the round-7 gate looked only at
    top-level `rdp_id` and reported three occurrences where there were six.
    The executable inventory already walks every published Schema for exactly
    these fields, so the set comes from there and a field added to a Schema is
    covered the day it lands.
    """
    import rdp_identity_inventory as _inv
    return {ptr.rsplit(".", 1)[-1]
            for src, ptr, _decl in _inv.inventory()
            if src.startswith("schemas/evidence-")}


def _provider_acts(obj, inherited=None, where="", fields=None):
    """Yield (participant_id, instant, where) for every provider an evidence
    object names, each paired with the instant of ITS OWN act."""
    fields = fields if fields is not None else _provider_id_fields()
    if isinstance(obj, dict):
        t = obj.get("type")
        at = inherited
        if isinstance(t, str) and t in ACT_INSTANT:
            at = obj.get(ACT_INSTANT[t]) or inherited
        elif "timestamp" in obj and any(k in fields for k in obj):
            # An EP `rdp_chain[]` entry: a composing act with its own instant.
            at = obj["timestamp"]
        for k, v in obj.items():
            if k in fields and isinstance(v, str):
                yield v, at, f"{where}.{k}".lstrip(".")
            else:
                yield from _provider_acts(v, at, f"{where}.{k}".lstrip("."),
                                          fields)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _provider_acts(v, inherited, f"{where}[{i}]", fields)


def check_bundle(entity, med, org, members, evidence, reveals=None,
                 mandate_reveals=None, member_history=None, roster=None,
                 policy_history=None, receipts=None,
                 group_contexts=None, counterparty_members=None,
                 formation_inputs=None, suite_registry=None,
                 federation_register=None, fa_anchors=None,
                 transformation_traces=None, provider_descriptors=None):
    """Return a list of (rule, message) violations for a loaded bundle.

    `member_history` (DR-11, optional): {mid: [BW-MEMBER versions]}, each
    version carrying `valid_from` and an optional `valid_until`. Where it is
    absent for a mid, the bundle's single current version is used — so a
    bundle assembled the old way behaves as before, while the act-time and
    `added_at` checks still run against it.

    `roster` (DR-11, optional): the ROSTER-v1 snapshot covering the evidence
    epoch. Where supplied, the version selected for an act is checked against
    the snapshot's `member_doc_digest`, so the history cannot disagree with
    the signed roster.

    `counterparty_members` (R6-01, optional): the SENDER entity's BW-MEMBER
    documents. A recipient-side bundle carries the recipient's roster, so the
    sender-side half of the identity tuple — `sender_uid` == the signing
    member's uid, the address kind bound to what signed, the device authorised
    to sign at the act — is undecidable without them. Retaining them is what
    lets a 2033 verifier check the sender's side at all; without them the rule
    reports INCOMPLETE rather than passing.

    `group_contexts` (R4-06, optional): retained GroupContext bytes,
    {(mls_group_id, mls_epoch): bytes}. Where supplied, the pinned
    cipher-suite decision is RECOMPUTED rather than read — hashing the context
    proves the bytes were retained, not that the decision they encode was
    valid.

    `receipts` (R4-03, optional): retained DS delivery receipts, {message_id:
    receipt}. Where supplied, each is resolved against the DS operator's
    published `ds_receipt_keys` and VERIFIED against the resolved key — the
    verifier reaches its own verdict instead of taking RDP(out)'s word that it
    checked at issuance. Before R4-03 nothing outside the mock consumed the
    resolver at all.

    `policy_history` (R3-02, optional): the ordered BW-ORG chain. Where
    supplied it establishes LINKAGE and IN-FORCE-AT-THE-ACT — the chain is
    unbroken back to a first publication and the pinned version's window
    contains `sent_at`.

    It does NOT establish maximality (R6-02/R6-W1): a hidden successor is
    indistinguishable from none from inside the bundle, so that stays with
    X-33 and the verdict is INCOMPLETE rather than a pass.

    *This paragraph previously said "without it the pinned version's own
    `valid_until` is still enforced". That was impossible from the moment
    R4-U1 removed `valid_until` as a stored field — there was nothing to
    enforce. R5-07 corrected the same sentence in the umbrella and left this
    copy, which is why round 6 found it: a correction applied where it was
    demonstrated rather than everywhere the claim was made.*
    """
    out = []
    def add(rule, msg):
        out.append((rule, msg))

    # LINT-BND-06: UID coherence.
    named = [("MED", med), ("ORG", org)] + [("MEMBER", m) for m in members]
    for name, doc in named:
        if doc.get("uid") != entity:
            add("LINT-BND-06", f"{name} uid {doc.get('uid')!r} != bundle entity {entity!r}")

    # LINT-BND-01: MED capability <=> ORG scope_map presence.
    supported = bool((med.get("mls") or {}).get("scopes_supported"))
    has_map = isinstance(org.get("scope_map"), dict)
    if supported != has_map:
        add("LINT-BND-01",
            f"MED scopes_supported={supported} but ORG scope_map present={has_map}")

    scopes = ((org.get("scope_map") or {}).get("scopes")) or []
    policy = org.get("acceptance_policy") or {}
    # R3-03, the survivor and WHY it is intentional. `active` is the CURRENT
    # membership, and it stays — but only for SATISFIABILITY (LINT-BND-02/08/09:
    # can this organisation's own policy still be met by the people it has
    # today?). That is legitimately a question about the present. ATTRIBUTION —
    # who made this confirmation, and were they entitled to — is a question
    # about the ACT, and no attribution rule may read this list. The four that
    # did are migrated; see `_active_at`.
    active = [m for m in members if m.get("status") == "active"]

    def holders(role):
        return [m for m in active if role in (m.get("roles") or [])]

    def has_cap(m, cap):
        return any(cap in (d.get("capabilities") or []) for d in (m.get("devices") or []))

    # LINT-BND-02 / -03: scope roles covered by active members with adequate capabilities.
    for sc in scopes:
        sid = sc.get("scope_id")
        scope_members = []
        for role in sc.get("roles") or []:
            hs = holders(role)
            scope_members += hs
            if not hs:
                add("LINT-BND-02", f"scope {sid!r} role {role!r} is held by no active member")
            elif not any(has_cap(m, "receive") for m in hs):
                add("LINT-BND-03",
                    f"scope {sid!r} role {role!r}: no active member device can 'receive'")
        if scope_members and not any(has_cap(m, "ack") for m in scope_members):
            add("LINT-BND-03", f"scope {sid!r}: no member device can 'ack' (acceptance impossible)")
        # LINT-BND-04 (documents): the scope's acceptance_policy_ref is a policy key.
        apr = sc.get("acceptance_policy_ref")
        if apr is not None and apr not in policy:
            add("LINT-BND-04",
                f"scope {sid!r} acceptance_policy_ref {apr!r} is not an acceptance_policy key")
        # LINT-BND-17 (F16, §8.3a): a recoverability=records scope's records_role
        # must be staffed by >= 1 active member, so the records leaf resolves.
        if sc.get("recoverability") == "records":
            rr = sc.get("records_role")
            if rr and not holders(rr):
                add("LINT-BND-17",
                    f"scope {sid!r} is recoverability=records but its records_role "
                    f"{rr!r} is held by no active member — the records leaf does not "
                    "resolve (§8.3a, F16)")

    # LINT-BND-07/08/09: acceptance-policy satisfiability (umbrella par. 8.3).
    # Counting unit = the DISTINCT active member (a party), not the device: a
    # member with several ack-capable devices counts once. Eligible set = the
    # scope's role holders for a scope-referenced policy; the role's holders
    # for a policy key naming an organisation-level role.
    def check_policy(ctx, name, pol, eligible):
        m = POLICY_RE.match(pol) if isinstance(pol, str) else None
        if not m:
            add("LINT-BND-07",
                f"{ctx}: acceptance_policy {name!r} = {pol!r} is not "
                "any-one | all | quorum:<n> | device-class:<class>")
            return
        distinct = list({mm.get("mid"): mm for mm in eligible}.values())
        ackers = [mm for mm in distinct if has_cap(mm, "ack")]
        if pol.startswith("quorum:"):
            n = int(m.group(2))
            if n < 1:
                add("LINT-BND-07", f"{ctx}: {pol!r} is malformed (quorum n must be >= 1)")
            elif len(ackers) < n:
                add("LINT-BND-08",
                    f"{ctx}: {pol!r} unsatisfiable — {len(ackers)} distinct active, "
                    f"ack-capable member(s) eligible, {n} required")
        elif pol == "any-one":
            if not ackers:
                add("LINT-BND-08",
                    f"{ctx}: 'any-one' unsatisfiable — no active, ack-capable "
                    "member is eligible")
        elif pol == "all":
            if not distinct:
                add("LINT-BND-09",
                    f"{ctx}: 'all' over an empty eligible set is ambiguous — rejected")
            else:
                lacking = [mm.get("mid") for mm in distinct if not has_cap(mm, "ack")]
                if lacking:
                    add("LINT-BND-09",
                        f"{ctx}: 'all' unreachable — eligible member(s) {lacking} "
                        "have no ack-capable device")
        # device-class:<class>: grammar-recognised; the baseline-profile
        # prohibition (§8.3, V5) is warned once per policy key in the
        # top-level loop (LINT-BND-W1).

    def eligible_for(wanted):
        return [mm for mm in active
                if any(r in (mm.get("roles") or []) for r in wanted)]

    org_roles = org.get("roles") or []
    for key, pol in (policy.items() if isinstance(policy, dict) else []):
        # V5 (§8.3): device-class is prohibited in baseline-profile deployments
        # (requires the MWAP + device attestation). The linter cannot know the
        # deployment profile, so this is a WARNING; main() does not count it.
        if isinstance(pol, str) and pol.startswith("device-class:"):
            add("LINT-BND-W1",
                f"acceptance_policy[{key!r}] uses device-class: — MUST NOT be used "
                "in baseline-profile deployments; requires the MWAP "
                "(docs/wallet-assurance-profile.md) and device attestation (§8.3)")
        if key in org_roles:
            check_policy(f"acceptance_policy[{key!r}]", key, pol, eligible_for([key]))
        elif key == "default":
            # X-12 (BW-ORG 2.4): the reserved default key governs
            # entity-addressed default-scope messages — its eligible set is
            # the ENTIRE active membership, and it must be satisfiable like
            # any other key (LINT-BND-07..09).
            check_policy("acceptance_policy['default']", key, pol, active)
        elif not (isinstance(pol, str) and POLICY_RE.match(pol)):
            add("LINT-BND-07",
                f"acceptance_policy[{key!r}] = {pol!r} is not "
                "any-one | all | quorum:<n> | device-class:<class>")
    for sc in scopes:
        apr = sc.get("acceptance_policy_ref")
        if apr is not None and apr in policy:
            eligible = eligible_for(sc.get("roles") or [])
            # LINT-BND-16 (A3, Annex R): a human-acceptance scope excludes system
            # members from its eligible set (§8.3) — an agent's ack does not
            # satisfy a human-gated class. If every eligible member is a system
            # member the policy is unsatisfiable.
            if sc.get("human_acceptance"):
                humans = [mm for mm in eligible if mm.get("member_type") != "system"]
                if eligible and not humans:
                    add("LINT-BND-16",
                        f"scope {sc.get('scope_id')!r} is human_acceptance but every "
                        "eligible member is a system member — a human-gated policy "
                        "is unsatisfiable by agents alone (Annex R, A3)")
                eligible = humans
            check_policy(f"scope {sc.get('scope_id')!r}", apr, policy[apr], eligible)

    # LINT-BND-04 / -05 / -10 (evidence addressed to this entity as recipient).
    orgpv = org.get("policy_version")
    org_payload = {k: v for k, v in org.items() if k != "doc_cose_b64"}
    org_digest = hashlib.sha256(dcbor(org_payload)).hexdigest()  # M4: over the dCBOR octets

    # LINT-BND-23 (X-17): MID non-reuse. A MID that is retained indefinitely in
    # sealed evidence is a permanent attribution key; reassigning it to a member
    # with a different authorisation chain would silently re-attribute old
    # confirmations. Within a UID a MID MUST NOT be bound to two different
    # accountability.authorisation_ref values. Checked across ALL members in the
    # bundle (any status), which also surfaces the duplicate-MID case the current
    # `by_mid` map would otherwise silently collapse.
    _mid_authz = {}
    for m in members:
        mid = m.get("mid")
        if mid is None:
            continue
        authz = (m.get("accountability") or {}).get("authorisation_ref")
        if mid in _mid_authz and _mid_authz[mid] != authz:
            add("LINT-BND-23",
                f"MID {mid!r} is bound to two different "
                f"accountability.authorisation_ref ({_mid_authz[mid]!r} and "
                f"{authz!r}) — a MID MUST NOT be reassigned to a different "
                f"member/authorisation chain within a UID (X-17)")
        else:
            _mid_authz.setdefault(mid, authz)

    # R3-03: the CURRENT-status map is GONE. DR-11 added the act-time resolver
    # beside it; four gates kept reading it and went on deciding attribution
    # from today's roster. `all_by_mid` plus an explicit status check at the
    # act replaces every use — see `_active_at`. Deleting it is what makes the
    # fix hold: an unused wrong path is one refactor away from being used.
    all_by_mid = {m.get("mid"): m for m in members}

    # LINT-BND-34 (DR-11, X-17): resolve the member version and the device key
    # AS THEY STOOD AT THE ACT, not as they stand now. INTF-2 has required this
    # since X-17 and `as_of_resolve` implemented it, but nothing CALLED it from
    # here: `by_mid` was built from members whose CURRENT status is active and
    # the signatures were verified against their CURRENT device keys. Two
    # opposite errors followed. A confirmation that was valid when it was made
    # was rejected once the member retired — evidence decaying with the roster.
    # And a signature under a key ADDED AFTER the claimed act was accepted,
    # which is the dangerous direction: it lets a key minted today validate a
    # confirmation dated yesterday.
    _seen_history_errors = set()

    def _history_error(key, rule, msg):
        """Report a history defect once per (mid, defect) rather than once per
        signature checked against it."""
        if key in _seen_history_errors:
            return
        _seen_history_errors.add(key)
        add(rule, msg)

    def _member_at(mid, act_time, context):
        """The BW-MEMBER version of `mid` in force at `act_time`, or None.

        Rejects rather than guesses: overlapping windows, a history that does
        not cover the act, and an unparsable instant are all LINT-BND-34 —
        picking by manifest order would silently choose an attacker-favourable
        version."""
        versions = (member_history or {}).get(mid)
        if not versions:
            return all_by_mid.get(mid)          # single current version
        if act_time is None:
            _history_error((mid, "no-act-time"), "LINT-BND-34",
                           f"{context}: {mid!r} carries a version history but the "
                           "act has no resolvable time — the version in force "
                           "cannot be determined (DR-11)")
            return None
        try:
            # R4 meta-finding: DELEGATE to as_of_resolve rather than repeat its
            # window test. DR-11's finding was that that helper had no caller;
            # the round-2 fix reimplemented it here, so the defect was routed
            # around instead of removed and one normative rule had two
            # implementations. `as_of_resolve` returns the LAST covering
            # version, so ambiguity is detected by counting covers separately.
            instant(act_time, field="act_time")      # fail closed on a bad act
            covering = [v for v in versions
                        if as_of_resolve([v], at=act_time) is not None]
        except TimestampError as e:
            _history_error((mid, "unparsable"), "LINT-BND-34",
                           f"{context}: {mid!r} history cannot be resolved: {e} (DR-11)")
            return None
        if len(covering) > 1:
            _history_error((mid, "overlap"), "LINT-BND-34",
                           f"{context}: {len(covering)} versions of {mid!r} claim to be "
                           f"in force at {act_time} — an ambiguous history is rejected, "
                           "not resolved by manifest order (DR-11)")
            return None
        if not covering:
            _history_error((mid, "gap"), "LINT-BND-34",
                           f"{context}: no version of {mid!r} was in force at "
                           f"{act_time} — the history does not cover the act (DR-11)")
            return None
        chosen = covering[0]
        if roster is not None:
            entry = next((r for r in (roster.get("members") or [])
                          if r.get("mid") == mid), None)
            if entry is not None and entry.get("member_doc_digest"):
                got = hashlib.sha256(dcbor(
                    {k: v for k, v in chosen.items()
                     if k not in ("doc_cose_b64", "valid_from", "valid_until")}
                )).hexdigest()
                if got != entry["member_doc_digest"]:
                    _history_error((mid, "roster"), "LINT-BND-34",
                                   f"{context}: the version of {mid!r} selected for "
                                   f"{act_time} does not match the signed ROSTER "
                                   "snapshot's member_doc_digest — the history "
                                   "disagrees with the roster (DR-11)")
                    return None
        return chosen

    def _device_at(member, device_id, act_time, context, mid):
        """The device record as it stood at `act_time`. A device whose
        `added_at` is AFTER the act did not exist then, and one removed before
        it no longer did — in both cases the key cannot anchor the act."""
        dev = next((d for d in ((member or {}).get("devices") or [])
                    if d.get("device_id") == device_id), None)
        if dev is None or act_time is None:
            return dev
        try:
            at = instant(act_time, field="act_time")
            added = instant_or_none(dev.get("added_at"))
            removed = instant_or_none(dev.get("removed_at"))
        except TimestampError as e:
            add("LINT-BND-34", f"{context}: {mid!r}/{device_id!r} device window "
                               f"cannot be evaluated: {e} (DR-11)")
            return None
        if added is not None and added > at:
            add("LINT-BND-34",
                f"{context}: device {device_id!r} of {mid!r} was added at "
                f"{dev.get('added_at')}, AFTER the act at {act_time} — a key "
                "minted after the fact cannot anchor it (DR-11)")
            return None
        if removed is not None and removed <= at:
            add("LINT-BND-34",
                f"{context}: device {device_id!r} of {mid!r} was removed at "
                f"{dev.get('removed_at')}, at or before the act at {act_time} "
                "(DR-11)")
            return None
        return dev

    def _act_time(ev, conf=None):
        """The instant of the act a confirmation attests, per object type
        (DR-11). The confirmation's own signed instant governs where it has
        one — the enclosing artefact may be sealed later (DR-06)."""
        for src in (conf or {}, ev or {}):
            for field in ("verified_at", "read_at", "refused_at", "acked_at",
                          "delivered_at", "observed_at", "sent_at"):
                if src.get(field):
                    return src[field]
        s3 = (ev or {}).get("s3_attestation") or {}
        return s3.get("verified_at")

    def _active_at(mid, act_time, context):
        """R3-03: did `mid` resolve to an ACTIVE member of this entity AT THE
        ACT? Returns None when it did, else the reason.

        This replaces `mid not in by_mid`, which asked whether the member is
        active NOW. DR-11 added `_member_at()` beside those gates instead of
        replacing them, so four of them survived and kept deciding
        attribution from the current roster: a confirmation valid when it was
        made became unattributable the moment the member retired, and — at
        the LINT-BND-18 site, in the opposite direction — a retired member
        vanished from the map entirely and its acknowledgement stopped being
        checked at all.
        """
        m = _member_at(mid, act_time, context) if act_time else all_by_mid.get(mid)
        if m is None:
            return "unknown"
        if m.get("status") != "active":
            return "not active at the act"
        return None

    # LINT-BND-39 (R4-04): the confirming device's certificate was valid AT THE
    # ACT, checked where the act is known.
    #
    # `check_certificate_binds_key(..., at=)` existed since R3-05 and the one
    # production call omitted `at`, so the validity-at-the-act half was
    # reachable only from its own test. Discovery lint cannot supply the act —
    # it sees a document, not an event — which is why this belongs here.
    def _bnd39(mid, device_id, act_time, context):
        m = _member_at(mid, act_time, context)
        dev = _device_at(m, device_id, act_time, context, mid)
        ck = (dev or {}).get("confirmation_key") or {}
        chain = ck.get("x5chain")
        if not chain or not act_time:
            # No certificate published, or no act instant: LINT-DISC-31 owns
            # the production requirement that one exist, and an act with no
            # time is already reported by LINT-BND-34.
            return
        try:
            check_certificate_binds_key(chain, ck.get("alg"),
                                        ck.get("public_key_b64"), at=act_time)
        except CertificateBindingError as e:
            add("LINT-BND-39",
                f"{context}: the confirming device's certificate does not hold "
                f"at the act ({act_time}): {e} (R4-04)")

    def _anchor_at(mid, device_id, act_time, context):
        """The published confirmation KEY OBJECT of (mid, device_id) as it
        stood at the act — THE resolution every wallet-signature check uses.

        DR-12: the whole object, not `public_key_b64`. The declared algorithm
        is half of what a verifier must check, and returning only the bytes is
        what made the linter guess Ed25519 for every key."""
        m = _member_at(mid, act_time, context)
        dev = _device_at(m, device_id, act_time, context, mid)
        # R4-04: every anchor resolution also checks the certificate's own
        # window at the act, so the check rides the path that already knows
        # WHEN — rather than sitting in a helper nothing calls with `at`.
        _bnd39(mid, device_id, act_time, context)
        return (dev or {}).get("confirmation_key")



    # LINT-BND-32 (X-32): one confirmation key per (mid, device_id) — a key
    # appearing on two device records anywhere in the member set makes a
    # signature resolve to more than one device/security class. Fail-closed.
    _ck_owner = {}
    for m in members:
        for dev in m.get("devices") or []:
            pk = ((dev.get("confirmation_key") or {}).get("public_key_b64"))
            if not pk:
                continue
            owner = (m.get("mid"), dev.get("device_id"))
            if pk in _ck_owner and _ck_owner[pk] != owner:
                add("LINT-BND-32",
                    f"confirmation_key shared by {_ck_owner[pk]!r} and "
                    f"{owner!r} — one key per device; cross-context reuse "
                    "makes attribution ambiguous (X-32)")
            _ck_owner[pk] = owner

    def _resolves_acker(mid, device_id=None, act_time=None):
        """None if mid resolved, AT THE ACT, to an active member of this entity
        with an ack-capable device (matching device_id when given); else a
        reason string — TS clause 6 INTF-2 (LINT-BND-12).

        DR-11: resolution is as-of the act. Before that this read the
        CURRENT-status map, so a confirmation that was perfectly valid when it
        was made became unresolvable the moment the member retired — evidence
        decaying with the roster. Where no history is supplied the bundle's
        single version is used and the behaviour is unchanged.

        R3-03: the no-act-time fallback goes through `all_by_mid` and an
        EXPLICIT status check rather than the pre-filtered active map. Same
        verdict, but it distinguishes "unknown" from "not active", and it
        leaves the active map with no consumers at all — which is the point:
        a superseded structure that is merely unused is one refactor away from
        being used again.
        """
        why = _active_at(mid, act_time, f"acker {mid!r}")
        if why:
            return why
        m = _member_at(mid, act_time, f"acker {mid!r}") if act_time \
            else all_by_mid.get(mid)
        devs = m.get("devices") or []
        if device_id is not None and act_time:
            # the device as it stood at the act; the RULE is the shared one
            # the issuing RDP also runs (R11-03)
            d = _device_at(m, device_id, act_time, f"acker {mid!r}", mid)
            devs = [d] if d is not None else []
        return ack_capable_problem(devs, device_id)

    # LINT-BND-28 (X-03/D4, evidence 2.3): the sender-side mirror of BND-21 —
    # runs BEFORE the recipient guard below, because an SE's recipient_uid is
    # the OTHER entity precisely when this bundle IS the sender's. Where
    # sender_uid == entity, the sender_confirmation's mid must be an ACTIVE
    # member of THIS roster and its wallet signature must verify against that
    # member's published confirmation_key anchor per (mid, device_id) — so a
    # provider cannot mint "the sender authorised these bytes" under its own
    # key. Fail-closed.
    for ev in evidence:
        if ev.get("type") != "SE-v1" or ev.get("sender_uid") != entity:
            continue
        sc = ev.get("sender_confirmation")
        if not isinstance(sc, dict):
            continue
        smid, sdid = sc.get("mid"), sc.get("device_id")
        if (why := _active_at(smid, ev.get("sent_at"),
                              f"sender_confirmation {smid!r}")):
            add("LINT-BND-28",
                f"sender_confirmation mid {smid!r} did not resolve to an active "
                f"member of the sender entity {entity!r} AT THE SUBMISSION "
                f"({why}) — X-03/D4, resolved as-of per DR-11/R3-03")
            continue
        # DR-11: the anchor as it stood at the SUBMISSION, not now.
        spub = _anchor_at(smid, sdid, ev.get("sent_at"),
                          f"SE sender_confirmation {smid!r}/{sdid!r}")
        if not spub:
            add("LINT-BND-28",
                f"sender_confirmation by {smid!r}/{sdid!r} has no resolvable "
                "confirmation_key anchor — nowhere to verify the sender "
                "signature (X-03/D4)")
        elif (why := _verify_wallet_sig(sc.get("wallet_signature_b64") or "", spub)):
            add("LINT-BND-28",
                f"sender_confirmation wallet_signature_b64 does not verify "
                f"against the published confirmation key of {smid!r}/{sdid!r} — "
                "the submission was not authorised by that member's device "
                f"(X-03/D4): {why}")
    def _descriptor_for(rdp_id):
        """The BW-PROVIDER descriptor of one provider, by `participant_id`.

        `issuing_rdp_id` and `participant_id` are the same value space
        (`urn:sbm:rdp:…`), so the receipt names its own key's publisher.
        """
        for descriptor in (provider_descriptors or []):
            if isinstance(descriptor, dict) and descriptor.get("participant_id") == rdp_id:
                return descriptor
        return None

    def _check_published_key(ev, field, conf):
        """LINT-BND-21 for ONE proof: its signature against the published
        confirmation_key anchor of the device it names, resolved at its own act.

        One helper rather than an inline block, because the inline block was
        what went wrong: it read a loop variable after the loop and silently
        checked whichever proof happened to be last. A helper takes the proof it
        is meant to check as an argument, so a caller cannot pass the wrong one
        by forgetting to.
        """
        if not conf.get("wallet_signature_b64"):
            return                      # session-authenticated: nothing to verify
        mid, did = conf.get("mid"), conf.get("device_id")
        if not did:
            add("LINT-BND-21",
                f"{ev.get('type')} {field} by {mid!r} is wallet-signed but carries "
                "no device_id — the confirmation key is resolved per "
                "(mid, device_id) (finding D)")
            return
        # DR-11: the key as it stood at the act, not now.
        pub = _anchor_at(mid, did, _act_time(ev, conf),
                         f"{ev.get('type')} {field} {mid!r}/{did!r}")
        if not pub:
            add("LINT-BND-21",
                f"{ev.get('type')} {field} by {mid!r}/{did!r} has no resolvable "
                "confirmation_key anchor — nowhere to verify the wallet signature "
                "(finding D)")
        elif (why := _verify_wallet_sig(conf["wallet_signature_b64"], pub)):
            add("LINT-BND-21",
                f"{ev.get('type')} {field} wallet_signature_b64 does not verify "
                f"against the published confirmation key of {mid!r}/{did!r} — the "
                "proof was not produced by that member's device "
                f"(INTF-1/S1): {why}")

    # X-31: the confirmation checks sweep NESTED objects too — an EP's
    # outcomes carry the same s3/quorum/refusal confirmations as top-level
    # evidence, and the shipped federated fixture proved a foreign-member s3
    # could hide inside a package unchecked. Expand the sweep list with every
    # EP's nested outcomes (identity, roster and anchor checks run identically).
    _sweep = []
    for ev in evidence:
        _sweep.append(ev)
        if ev.get("type") == "EP-v1":
            _sweep.extend(o for o in ev.get("outcomes") or []
                          if isinstance(o, dict))
    for ev in _sweep:
        if ev.get("recipient_uid") and ev["recipient_uid"] != entity:
            continue  # scope/policy belong to that message's recipient entity, not this bundle
        # LINT-BND-12 (S2, TS clause 6 INTF-2): the recipient confirmation — and,
        # under a quorum/all acceptance, every acking member — must resolve to an
        # active, ack-capable BW-MEMBER of the recipient entity. A confirmation from
        # an unknown, retired, suspended or non-ack member does not satisfy any
        # acceptance policy (including any-one).
        for _key in sorted(lc.RECIPIENT_ACK_PROOF_FIELDS):
            conf = ev.get(_key)
            if not isinstance(conf, dict):
                continue
            if conf.get("mid"):
                why = _resolves_acker(conf.get("mid"), conf.get("device_id"),
                                      _act_time(ev, conf))
                if why:
                    add("LINT-BND-12",
                        f"{ev.get('type')} {_key} mid {conf.get('mid')!r} does not "
                        f"resolve to an active, ack-capable member of {entity!r} ({why}) "
                        "— TS clause 6 INTF-2")
            # LINT-BND-21 (finding D, twenty-second review; R27-PUB-02): where the
            # proof carries a wallet advanced electronic signature, that signature
            # MUST verify against the signing device's PUBLISHED confirmation_key
            # anchor — resolved per (mid, device_id) from BW-MEMBER, exactly as the
            # reference wallet verifier does. This is what makes INTF-1/S1 real: a
            # confirmation minted by an RDP under a foreign key (finding F) does NOT
            # verify against the member's OWN published key. Fail-closed.
            #
            # It runs HERE, once per selected proof. It used to run after this loop
            # on whatever `conf` the last iteration had left behind, and since
            # `s3_attestation` sorts last, every NDE carrying a
            # `recipient_confirmation` or a `recipient_validation_failure` and no
            # s3 attestation reached the check with `conf` as None and was not
            # verified at all. A forged recipient proof naming a known, active
            # member passed LINT-BND-12 and nothing else objected. That was a
            # regression: before the derived-set loop the line read
            # `conf = ev.get("s3_attestation") or ev.get("recipient_confirmation")`,
            # so the mismatch confirmation WAS checked; the new type never was.
            _check_published_key(ev, _key, conf)
        for acker in (ev.get("quorum") or []):
            if isinstance(acker, dict) and acker.get("mid"):
                # X-05: a wallet-signed entry names its device — resolve the
                # pair; a provider entry resolves the member alone.
                why = _resolves_acker(acker.get("mid"), acker.get("device_id"),
                                      _act_time(ev, acker))
                if why:
                    add("LINT-BND-12",
                        f"{ev.get('type')} quorum acker {acker.get('mid')!r} does not "
                        f"resolve to an active, ack-capable member of {entity!r} ({why}) "
                        "— TS clause 6 INTF-2")
                # LINT-BND-21 extended (X-05, evidence 2.3): a wallet-signed
                # quorum entry is an independently portable per-member proof —
                # verified against THAT member's published confirmation_key
                # anchor per (mid, device_id), exactly like the s3 signed arm.
                if acker.get("attestation") == "wallet-signed":
                    qmid, qdid = acker.get("mid"), acker.get("device_id")
                    # DR-11: resolved as of THIS acker's own act time.
                    qpub = _anchor_at(qmid, qdid, _act_time(ev, acker),
                                      f"quorum entry {qmid!r}/{qdid!r}")
                    if not qpub:
                        add("LINT-BND-21",
                            f"wallet-signed quorum entry by {qmid!r}/{qdid!r} has no "
                            "resolvable confirmation_key anchor — nowhere to verify "
                            "the portable proof (X-05)")
                    elif (why := _verify_wallet_sig(
                            acker.get("wallet_signature_b64") or "", qpub)):
                        add("LINT-BND-21",
                            f"wallet-signed quorum entry signature by {qmid!r}/{qdid!r} "
                            "does not verify against the published confirmation key — "
                            "the acknowledgement was not produced by that member's "
                            f"device (X-05): {why}")
        # LINT-BND-29 (X-29, evidence 2.3): a member refusal is an attributable
        # act. The refusing mid must resolve to an ACTIVE member of the recipient
        # entity (no ack capability needed — declining is not acknowledging), and
        # where the refusal_confirmation carries a wallet advanced electronic
        # signature it MUST verify against the member's published confirmation_key
        # anchor per (mid, device_id) — the same finding-D machinery as an
        # acceptance, so a provider cannot mint "the user refused" under its own
        # key. Fail-closed.
        if ev.get("type") == "RE-v1" and ev.get("refusal_kind") == "member":
            rmid = ev.get("mid")
            if (why := _active_at(rmid, _act_time(ev, ev.get("refusal_confirmation")),
                                  f"RE refusing mid {rmid!r}")):
                add("LINT-BND-29",
                    f"RE refusing mid {rmid!r} did not resolve to an active "
                    f"member of {entity!r} AT THE REFUSAL ({why}) — an "
                    "unattributable member refusal (X-29, as-of per R3-03)")
            rc = ev.get("refusal_confirmation")
            if isinstance(rc, dict) and rc.get("wallet_signature_b64"):
                did = rc.get("device_id")
                if not did:
                    add("LINT-BND-29",
                        f"refusal_confirmation by {rmid!r} is wallet-signed but "
                        "carries no device_id — the confirmation key is resolved "
                        "per (mid, device_id)")
                else:
                    # DR-11: the key as it stood at the REFUSAL.
                    pub2 = _anchor_at(rmid, did, _act_time(ev, rc),
                                      f"refusal_confirmation {rmid!r}/{did!r}")
                    if not pub2:
                        add("LINT-BND-29",
                            f"refusal_confirmation by {rmid!r}/{did!r} has no "
                            "resolvable confirmation_key anchor — nowhere to "
                            "verify the wallet signature")
                    elif (why := _verify_wallet_sig(rc["wallet_signature_b64"], pub2)):
                        add("LINT-BND-29",
                            f"refusal_confirmation wallet_signature_b64 does not "
                            f"verify against the published confirmation key of "
                            f"{rmid!r}/{did!r} — the refusal was not produced by "
                            f"that member's device (X-29): {why}")
        # LINT-BND-18 (A8, Annex R / §8.3): a system member may reach S3 (decrypt +
        # verify) but is excluded from acceptance in a human_acceptance scope — an
        # agent's acknowledgement never satisfies a human-gated class.
        sref = ev.get("scope_ref")
        if isinstance(sref, dict):
            sc = next((s for s in scopes if s.get("scope_id") == sref.get("scope_id")), None)
            if sc and sc.get("human_acceptance"):
                ack_mids = [conf.get("mid")] if isinstance(conf, dict) else []
                ack_mids += [a.get("mid") for a in (ev.get("quorum") or []) if isinstance(a, dict)]
                for amid in filter(None, ack_mids):
                    # R3-03: resolved AT THE ACT. Read from the current-status
                    # map, this failed OPEN in the opposite direction to the
                    # other three: a member who had since retired was absent
                    # from `by_mid`, so `am` was None and a SYSTEM member's
                    # acknowledgement in a human_acceptance scope was never
                    # checked at all.
                    am = _member_at(amid, _act_time(ev, conf),
                                    f"human_acceptance acker {amid!r}") \
                        or all_by_mid.get(amid) or {}
                    if am.get("member_type") == "system":
                        add("LINT-BND-18",
                            f"{ev.get('type')} acknowledgement by system member "
                            f"{amid!r} does not satisfy the human_acceptance scope "
                            f"{sref.get('scope_id')!r} — agents may verify (S3) but not "
                            "legally accept (S4) a human-gated class (Annex R, A8, §8.3)")
        apref = ev.get("acceptance_policy_ref")
        if isinstance(apref, dict) and apref.get("policy_version") != orgpv:
            add("LINT-BND-04",
                f"{ev.get('type')} acceptance_policy_ref.policy_version "
                f"{apref.get('policy_version')!r} != ORG policy_version {orgpv!r}")
        elif isinstance(apref, dict):
            # LINT-BND-10 (F7): doc_digest binds the evidence to the published
            # ORG content — SHA-256 of the ORG's authoritative bytes (the COSE
            # payload = dCBOR of the document minus doc_cose_b64; §8.3, M4),
            # reseal-stable. hash_mode is `raw-sha256` (a raw hash of those bytes).
            dd = apref.get("doc_digest") or {}
            if dd.get("hex") != org_digest or dd.get("hash_mode") != "raw-sha256":
                add("LINT-BND-10",
                    f"{ev.get('type')} acceptance_policy_ref.doc_digest does not match "
                    f"the ORG signed payload (raw-SHA-256 {org_digest[:16]}…, "
                    "hash_mode raw-sha256) — §8.3")
        # LINT-BND-11 (V0 + X0, §8.3b): availability-grade delivery is never
        # implicit — the recipient's signed ORG must declare it. Evidence does
        # not carry the content class (privacy). With a reveal fixture for the
        # message (X0), the FULL grade-commitment verification runs: recompute
        # the commitment against the ORG signed-payload digest, compare, and
        # check the revealed class maps to availability. Without one, the
        # floor remains: the ORG declares availability for at least one class.
        if ev.get("delivery_grade") == "availability":
            dg = org.get("delivery_grades") or {}
            r = (reveals or {}).get(ev.get("message_id"))
            if r is not None:
                expected = compute_grade_commitment(
                    r.get("salt"), r.get("content_class"), org_digest)
                if ev.get("grade_commitment") != expected:
                    add("LINT-BND-11",
                        f"{ev.get('type')} grade_commitment does not match the reveal "
                        f"(salt, {r.get('content_class')!r}) against ORG policy_version "
                        f"{orgpv!r} — the I-D (Grade Commitment) construction")
                if dg.get(r.get("content_class")) != "availability":
                    add("LINT-BND-11",
                        f"revealed content class {r.get('content_class')!r} is not "
                        f"declared availability-grade in ORG policy_version {orgpv!r} "
                        "(§8.3b — availability is never implicit)")
            elif "availability" not in dg.values():
                add("LINT-BND-11",
                    f"{ev.get('type')} is availability-grade but ORG policy_version "
                    f"{orgpv!r} declares no availability-grade content class "
                    "(§8.3b — availability is never implicit)")
        sr = ev.get("scope_ref")
        if isinstance(sr, dict):
            if sr.get("scope_id") == "default":
                # §8.3a: the implicit default scope has no descriptor — its
                # version is fixed at "1" and never redeclared (F6).
                if sr.get("version") != "1":
                    add("LINT-BND-05",
                        f"{ev.get('type')} scope_ref default/{sr.get('version')!r} — the "
                        "implicit default scope is fixed at descriptor version '1' (§8.3a)")
            elif not any(s.get("scope_id") == sr.get("scope_id")
                         and s.get("version") == sr.get("version") for s in scopes):
                add("LINT-BND-05",
                    f"{ev.get('type')} scope_ref {sr.get('scope_id')!r}/{sr.get('version')!r} "
                    "does not resolve against the ORG scope map")

    # LINT-BND-13 (S4, the I-D Error Handling and Retries; TS clause 6 INTF-4):
    # message_id is globally unique per issuing environment — the same message_id
    # must not map to two recipients or two payloads across the evidence set. This
    # is a coherence check over the objects at hand; the authoritative rejection
    # of a colliding submission is a Delivery-Service-intake duty (duplicate-
    # message-id / A.2). Runs over ALL evidence, not just this entity's.
    # LINT-BND-14 (A1, Annex R): evidence recording a system acting identity
    # (auth_context.identity=system) names the acting agent's MID; where that MID
    # belongs to this bundle's entity it MUST be an active member_type=system
    # member. A system acting identity resolving to a person (or an inactive)
    # member of the entity is rejected. (Where the acting MID is not in this
    # entity's roster — e.g. a peer entity's sending agent — resolution is
    # verifier-side and skipped here.)
    roster = {m.get("mid"): m for m in members}
    for ev in evidence:
        ac = ev.get("auth_context") or {}
        if ac.get("identity") != "system":
            continue
        amid = ac.get("mid")
        m = roster.get(amid)
        if m is not None and (m.get("status") != "active"
                              or m.get("member_type") != "system"):
            add("LINT-BND-14",
                f"{ev.get('type')} auth_context.identity=system names mid {amid!r}, "
                f"not an active system member of {entity!r} "
                f"(status={m.get('status')!r}, member_type={m.get('member_type')!r}) "
                "— Annex R (A1)")
        # LINT-BND-15 (A2, Annex R): the mandate the agent acted under (SE
        # mandate_ref) is the acting member's standing mandate (BW-MEMBER
        # mandate_ref, same issuer+id) and is in validity at the SE sent_at.
        # (Scope-covers-content_class is verifier-side / mandate-commitment
        # reveal — the content class is not carried in evidence.)
        mref = ev.get("mandate_ref")
        if ev.get("type") == "SE-v1" and isinstance(mref, dict) and m is not None:
            standing = m.get("mandate_ref") or {}
            if (mref.get("issuer") != standing.get("issuer")
                    or mref.get("id") != standing.get("id")):
                add("LINT-BND-15",
                    f"SE mandate_ref (issuer/id) does not match the standing "
                    f"mandate of system member {amid!r} — Annex R (A2)")
            else:
                sent = ev.get("sent_at")
                if sent is not None and not (
                        _within(sent, standing.get("valid_from"),
                                standing.get("valid_until"))):
                    add("LINT-BND-15",
                        f"SE acted under mandate {mref.get('id')!r} outside its "
                        f"validity window at sent_at {sent!r} — Annex R (A2)")
                # A1 (nineteenth review): with a mandate-reveal fixture, run the
                # FULL commitment verification — recompute against the SE's ORG
                # digest and check the revealed content_class is IN the mandate
                # scope (out-of-scope reveal = provable agent overreach).
                r = (mandate_reveals or {}).get(ev.get("message_id"))
                mc = mref.get("mandate_commitment")
                if r is not None and mc is not None:
                    od = ((ev.get("acceptance_policy_ref") or {}).get("doc_digest") or {}).get("hex")
                    expected = compute_mandate_commitment(
                        r.get("salt"), mref.get("id"), r.get("content_class"), od)
                    if mc != expected:
                        add("LINT-BND-15",
                            f"SE mandate_commitment does not match the reveal "
                            f"(salt, {r.get('content_class')!r}) — the I-D (Mandate Commitment)")
                    elif r.get("content_class") not in (standing.get("scope") or []):
                        add("LINT-BND-15",
                            f"revealed content class {r.get('content_class')!r} is not in the "
                            f"mandate scope of {amid!r} — agent overreach (A1)")

    seen = {}
    for ev in evidence:
        mid = ev.get("message_id")
        if not mid:
            continue
        rid = ev.get("recipient_uid")
        ph = json.dumps(ev.get("payload_hash"), sort_keys=True) if ev.get("payload_hash") else None
        prev = seen.get(mid)
        if prev is None:
            seen[mid] = (rid, ph)
        else:
            if rid is not None and prev[0] is not None and rid != prev[0]:
                add("LINT-BND-13",
                    f"message_id {mid!r} maps to two recipients ({prev[0]!r}, {rid!r}) "
                    "— message_id must be globally unique per issuing environment (S4)")
            if ph is not None and prev[1] is not None and ph != prev[1]:
                add("LINT-BND-13",
                    f"message_id {mid!r} maps to two payload_hash values "
                    "— message_id must be globally unique per issuing environment (S4)")

    # LINT-BND-19 (finding 7, twentieth review; TS clause 4.1): where a bundle
    # carries both a recipient-side B.2 RelayRejection and the sender-facing NDE
    # for the same message_id, the NDE reason is the mapping of the B.2 reason —
    # a typed relay rejection must not collapse to a single sender-facing reason.
    nde_by_mid = {ev.get("message_id"): ev for ev in evidence
                  if ev.get("type") == "NDE-v1"}
    for ev in evidence:
        if ev.get("type") != "RelayEvidence-v1" or ev.get("event") != "B.2-RelayRejection":
            continue
        nde = nde_by_mid.get(ev.get("message_id"))
        if nde is None:
            continue
        expected = RELAY_B2_TO_NDE.get(ev.get("reason"))
        if expected is not None and nde.get("reason") != expected:
            add("LINT-BND-19",
                f"B.2 RelayRejection reason {ev.get('reason')!r} for message "
                f"{ev.get('message_id')!r} maps to sender NDE reason {expected!r}, but the "
                f"NDE carries {nde.get('reason')!r} — TS clause 4.1 B.2->NDE mapping")
        # LINT-BND-31 (X-28): the translated NDE is a RELAY-stage outcome —
        # after the sender-side A.1 acceptance — so its event MUST be
        # B.3-RelayFailure. An A.2-SubmissionRejection here would make the
        # same submission read as both accepted (A.1/SE) and rejected before
        # submission when the EP is read alone. Fail-closed.
        if nde.get("event") != "B.3-RelayFailure":
            add("LINT-BND-31",
                f"sender NDE translating the B.2 RelayRejection for message "
                f"{ev.get('message_id')!r} carries event {nde.get('event')!r} "
                "— a relay-stage rejection is B.3-RelayFailure, never a "
                "pre-submission A.2 (X-28; TS clause 4.1)")

    # LINT-BND-20 (CF-5, twenty-first review): where a bundle carries an EP whose
    # rdp_chain[].evidence references a B.x object PRESENT IN THE SAME BUNDLE, the
    # seal_digest is RECOMPUTED and compared. This turns a shape check into a
    # BINDING check: evidence_lint's LINT-EP-06 sees one object at a time and can
    # only verify that the hex is well-formed, so ANY 64-hex string survives it —
    # the digest could point at nothing. The input is the DECODED COSE_Sign1 bytes
    # (TS clause 4.1; lint_cli.compute_seal_digest, the single implementation).
    relay_by_ref = {(r.get("message_id"), r.get("event")): r for r in evidence
                    if r.get("type") == "RelayEvidence-v1"}
    for ev in evidence:
        if ev.get("type") != "EP-v1":
            continue
        for i, hop in enumerate(ev.get("rdp_chain") or []):
            ref = hop.get("evidence")
            if not isinstance(ref, dict):
                continue
            target = relay_by_ref.get((ref.get("message_id"), ref.get("event")))
            if target is None:
                continue  # the referenced object is not in this bundle — nothing to bind against
            expected = compute_seal_digest((target.get("seal") or {}).get("cose_b64"))
            got = (ref.get("seal_digest") or {}).get("hex")
            if got != expected:
                add("LINT-BND-20",
                    f"EP rdp_chain[{i}].evidence.seal_digest.hex {got!r} does not match the "
                    f"referenced {ref.get('event')} object's seal: expected {expected!r} = "
                    "SHA-256 over the DECODED COSE_Sign1 bytes of its seal.cose_b64 "
                    "(TS clause 4.1 — the digest input is the decoded bytes, not the base64 text)")

    # LINT-BND-22 (finding R1, twenty-fourth review): outcomes are temporally
    # coherent with the SE's AUTHENTICATED deadline SE.expires_at. An `expired`
    # NDE must not be premature — its observation instant is at or after
    # expires_at (the message actually expired by then); a DE must not post-date
    # expires_at, EXCEPT at the availability grade, whose DE for an
    # authenticated-S2 event within ttl stays valid once issued (I-D state model).
    # The `ttl` itself lives only in the E2EE envelope, so this is the only
    # place the deadline is verifiable — hence the bind to SE.expires_at.
    def _check_expiry(se, out):
        exp = (se or {}).get("expires_at")
        if not exp:
            return
        t = out.get("type")
        if t == "NDE-v1" and out.get("reason") == "expired":
            obs = out.get("observed_at")
            if obs and _lt(obs, exp, add, "NDE.observed_at"):
                add("LINT-BND-22",
                    f"NDE `expired` for {out.get('message_id')!r} was observed at {obs} — "
                    f"BEFORE SE.expires_at {exp}: a premature expiry (the message had not "
                    "yet expired) — finding R1")
        elif t == "DE-v1":
            # X-21 + DR-06: delivered_at is the EVENT time at EVERY grade —
            # there is no availability exemption anywhere any more (DR-06 found
            # the I-D and the SE schema still stating one while this code
            # enforced the current rule, so two conforming implementations
            # could disagree about whether a delivery was legally timely). The
            # qualified timestamp remains the possibly-later SEALING time; a
            # tie (event == expiry instant) is delivered.
            dat = out.get("delivered_at")
            try:
                late = bool(dat) and not in_time(dat, exp)   # one rule (R11-04)
            except TimestampError as exc:
                add("LINT-BND-22", f"unparsable instant in a window check: {exc}")
                late = False
            if late:
                add("LINT-BND-22",
                    f"{out.get('delivery_grade')}-grade DE for {out.get('message_id')!r} "
                    f"delivered at {dat} — AFTER SE.expires_at {exp}: delivery past the "
                    "authenticated deadline (R1/X-21; the event time bounds every "
                    "grade, availability included)")
    se_by_mid = {e.get("message_id"): e for e in evidence if e.get("type") == "SE-v1"}

    # LINT-BND-40 (R4-06): the pinned cipher-suite decision is RECOMPUTED.
    #
    # R3-08 put the decision into `sbm_group_params` so `mls_state` would
    # commit to it, and the only decoder lived inside a test — so the bytes
    # were pinned and the DECISION THEY ENCODE was never checked. Hashing the
    # GroupContext proves those bytes were retained; a creator could commit a
    # self-consistent but false or downgraded record and a verifier would
    # validate the hash rather than the selection rule.
    #
    # `group_contexts` is the retained material, {(group_id, epoch): bytes} —
    # the same F-03 reads the DS already serves.
    def _bnd40():
        if not group_contexts:
            return
        import mls_wire
        from mls_suite import verify_group_params

        # R6-05 class 2 — SUBSTITUTION. The map key was taken on trust: the
        # context's OWN group id and epoch were never decoded and compared, and
        # the bytes were never hashed against the evidence commitment. A valid
        # context from a foreign group, filed under this key, produced no
        # finding at all — the evidence committed to one state while the
        # verifier semantically inspected another.
        # The epoch is a STRING in evidence and an int in a manifest map, so
        # both sides are normalised. Comparing them raw made a legitimate
        # bundle report a missing context on a type difference — a check that
        # fires on the wrong thing gets suppressed, and a suppressed check is
        # worse than none.
        def _key(gid, epoch):
            try:
                return (gid, int(epoch))
            except (TypeError, ValueError):
                return (gid, epoch)

        committed = {}
        for ev in evidence:
            st = ev.get("mls_state")
            if isinstance(st, dict) and ev.get("mls_group_id"):
                committed.setdefault(
                    _key(ev["mls_group_id"], ev.get("mls_epoch")), set()
                ).add(st.get("hex"))
        contexts = {_key(g, e): v for (g, e), v in group_contexts.items()}
        for key, hexes in committed.items():
            if key not in contexts:
                add("LINT-BND-40",
                    f"evidence commits to MLS state for {key[0]}/{key[1]} and "
                    "no retained GroupContext is supplied for it — the state "
                    "the evidence names cannot be inspected (R6-05)")
        for key, gc in contexts.items():
            if key not in committed:
                add("LINT-BND-40",
                    f"a GroupContext is supplied for {key[0]}/{key[1]}, which "
                    "no evidence in this bundle commits to — an extra context "
                    "is either the wrong bundle or an attempt to be inspected "
                    "in place of the real one (R6-05)")
                continue
            actual = hashlib.sha256(gc).hexdigest()
            if actual not in committed[key]:
                add("LINT-BND-40",
                    f"the GroupContext supplied for {key[0]}/{key[1]} hashes to "
                    f"{actual[:16]}…, which is not the mls_state the evidence "
                    f"commits to ({sorted(committed[key])[0][:16]}…) — a "
                    "substituted context (R6-05)")
                continue
            try:
                parsed_key = mls_wire.parse_group_context(gc)
            except Exception:
                continue          # decoded again below, reported there
            # The wire carries the group id as OCTETS, so the key is decoded
            # with the canonical helper rather than compared as a string — a
            # second spelling of that encoding is how this family starts.
            inner_g = parsed_key.get("group_id")
            inner_e = parsed_key.get("epoch")
            try:
                want_g = mls_wire._b64url_decode(key[0])
            except Exception:
                want_g = None
            if inner_g is not None and want_g is not None and \
                    (inner_g != want_g or int(inner_e) != int(key[1])):
                add("LINT-BND-40",
                    f"the GroupContext filed under {key[0]}/{key[1]} decodes to "
                    f"a different group/epoch — the map key is not the "
                    "context's own identity (R6-05)")

        # R12-X4: the formations this bundle retains, by the digest a
        # decision commits to.
        formations = {mls_wire.formation_inputs_digest(f): f
                      for f in (formation_inputs or [])}
        for (gid, epoch), gc in contexts.items():
            try:
                parsed = mls_wire.parse_group_context(gc)
                params = mls_wire.group_params_from(parsed["extensions"])
                if params is None:
                    add("LINT-BND-40",
                        f"the retained GroupContext for {gid}/{epoch} carries no "
                        "sbm_group_params — the cipher-suite decision it was "
                        "supposed to pin is absent (R4-06/R3-08)")
                    continue
            except mls_wire.GroupParamsError as e:
                add("LINT-BND-40",
                    f"the retained GroupContext for {gid}/{epoch}: {e} (R4-06)")
                continue
            # R6-05 class 3: the recomputation gets EVERY input it needs, or
            # says it could not do it. `_bnd40` passed only the current roster,
            # so the strongest-usable arm never ran from the CLI — round 6
            # reproduced a downgrade that direct verification caught and the
            # bundle path did not.
            if suite_registry is None:
                # R10-11: without the RETAINED registry revision the decision
                # cannot be recomputed as it was taken — recomputing it against
                # today's registry is how evolution would invalidate a correct
                # historical decision. The `suite-registry` required property
                # already reports this as unestablished (LINT-BND-I5).
                continue
            # R11-X4 — decode under the revision the group PINNED. This decoded
            # through TODAY's map before the retained revision was consulted,
            # so a revision-1 group was refused as "not in the profile's
            # vector" while direct verification under revision 1 passed it.
            rev = str(suite_registry.get("registry_version"))
            if str(params.get("floor_version")) != rev:
                add("LINT-BND-I5",
                    f"the group {gid}/{epoch} pins registry revision "
                    f"{params.get('floor_version')!r}; the retained registry "
                    f"supplied is revision {rev!r}, so the decision cannot be "
                    "recomputed as it was taken — supply that revision (R11-X4)")
                continue
            # R12-X4 — recompute ONLY from the inputs the decision is bound to.
            # A v1 record binds none: it is not recomputed from current data,
            # which is how a later capability change used to rewrite a
            # historical verdict in either direction (R12-06).
            if params.get("params_version") != 2:
                add("LINT-BND-I5",
                    f"the group {gid}/{epoch} pins its decision in sbm_group_params "
                    "v1, which binds neither the entity of its raises nor the "
                    "inputs it was taken on — it cannot be recomputed as it was "
                    "taken, and is not recomputed from current data (R12-X4)")
                continue
            formation = formations.get(params.get("inputs_digest"))
            if formation is None:
                add("LINT-BND-I5",
                    f"the group {gid}/{epoch} was decided on inputs with digest "
                    f"{str(params.get('inputs_digest'))[:16]}…, and no retained "
                    "formation matches it — the decision is not recomputed from "
                    "anything else (R12-X4)")
                continue
            suite_name = mls_wire.wire_map(suite_registry).get(parsed["cipher_suite"])
            if suite_name is None:
                if not suite_registry.get("code_points"):
                    add("LINT-BND-I5",
                        f"registry revision {rev!r} published no wire values, so "
                        f"the GroupContext for {gid}/{epoch} running "
                        f"{parsed['cipher_suite']:#06x} — not an IANA allocation "
                        "— cannot be decoded as it stood: unverifiable, not "
                        "decoded by today's map (R11-X4)")
                else:
                    add("LINT-BND-40",
                        f"the GroupContext for {gid}/{epoch} runs cipher suite "
                        f"{parsed['cipher_suite']:#06x}, which registry revision "
                        f"{rev!r} does not define (R4-06/R11-X4)")
                continue
            for problem in verify_group_params(
                    params, cipher_suite_name=suite_name,
                    formation=formation, registry=suite_registry):
                add("LINT-BND-40",
                    f"group {gid}/{epoch}: {problem} (R4-06)")

    _bnd40()

    # LINT-BND-38 (R4-03): a retained DS receipt is resolved and VERIFIED here.
    #
    # R3-04 published the keys and mock_rdp resolved them — and then verified
    # the signature by re-deriving the demo key from `kid` and a hard-coded
    # seed, so the resolved public key was never used and substituting it
    # changed nothing. `bundle_lint` did not call the resolver at all, so no
    # verifier outside the issuing provider ever checked a receipt. Discovery
    # that no verification consumes is decoration.
    # ---- R6-05: the DECLARED required properties, iterated ---------------
    #
    # Round 5 built the three-verdict model so a required-but-unestablished
    # property could not pass, and wired it to ONE of the two it was built for.
    # The set a green verdict depends on now lives in
    # docs/required-properties.json and is walked here, so adding a property
    # fails closed until it is wired instead of being silently unguarded.
    _locals = locals()

    def _required_registry():
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "docs", "required-properties.json")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    class RequiredPropertyConfigError(Exception):
        """R7-05 requirement 2: an unknown id, input, precondition kind or gap
        rule is a FATAL configuration error, never a `continue`.

        The round-6 design failed OPEN — a hard-coded `applies` map returned
        None for any id it did not know, so an injected property was skipped in
        silence and the verifier's output was byte-identical. Failing closed on
        an unrecognised declaration is the whole fix: a declaration nobody can
        evaluate must stop the verification, not be assumed inapplicable.
        """

    # R7-05: the retained-material inputs, taken from THIS CALL rather than
    # restated — a hand-written list beside the signature is one more thing to
    # keep in step, and the finding is about exactly that kind of second copy.
    # `receipts` belongs here too; omitting it made a legitimate declaration
    # look like a configuration error.
    _SUPPLIED = {name: _locals[name] for name in RETAINED_MATERIAL_INPUTS}

    def _precondition_holds(prop):
        """The `when` vocabulary, exhaustively mapped. Anything else raises."""
        when = prop.get("when")
        if not isinstance(when, dict) or "kind" not in when:
            raise RequiredPropertyConfigError(
                f"required property {prop.get('id')!r} declares no executable "
                "`when` precondition (R7-05)")
        kind = when["kind"]
        if kind == "always":
            return True
        if kind == "evidence_has_field":
            field = when.get("field")
            if not field:
                raise RequiredPropertyConfigError(
                    f"{prop['id']!r}: `evidence_has_field` names no field")
            return any(e.get(field) for e in evidence)
        if kind == "evidence_or_nested_has_field":
            # An Evidence Package carries its CEs in `changes[]` and its
            # outcomes in `outcomes[]`, so a property whose trigger is a field
            # of a SUB-artefact is invisible to the check above. Reporting a
            # gap for a loose CE and not for the same CE inside a package would
            # be reporting by the accident of packaging. A separate kind rather
            # than a widening of `evidence_has_field`, because that one is the
            # trigger for three other properties and quietly changing what they
            # fire on is not this row's business.
            field = when.get("field")
            if not field:
                raise RequiredPropertyConfigError(
                    f"{prop['id']!r}: `evidence_or_nested_has_field` names no field")

            def _reaches(obj):
                if isinstance(obj, dict):
                    if obj.get(field):
                        return True
                    return any(_reaches(v) for k, v in obj.items()
                               if k in ("changes", "outcomes", "se", "evidence"))
                if isinstance(obj, list):
                    return any(_reaches(v) for v in obj)
                return False
            return any(_reaches(e) for e in evidence)
        if kind == "any_input":
            names = when.get("inputs") or []
            unknown = [n for n in names if n not in _SUPPLIED]
            if unknown:
                raise RequiredPropertyConfigError(
                    f"{prop['id']!r}: `any_input` names unknown input(s) "
                    f"{unknown} (R7-05)")
            return any(_SUPPLIED.get(n) for n in names)
        raise RequiredPropertyConfigError(
            f"{prop['id']!r}: unknown precondition kind {kind!r}. The "
            "vocabulary is closed and unmapped kinds are fatal, because the "
            "previous design treated an unknown declaration as 'does not "
            "apply' and skipped it in silence (R7-05)")

    # R8-06 requirement 2 — the CLOSED STRATEGY VOCABULARY. Behaviour is
    # selected by a declared key, never by the identifier of the rule a row
    # would emit. `_gaps()` used to end in two branches keyed on `gap_rule`
    # (`== "LINT-BND-I1"`, `== "LINT-BND-I2"`), so ANY future row choosing one
    # of those identifiers was skipped whatever its semantics — one declaration
    # produced five different outcomes depending only on which rule it named.
    _STRATEGIES = ("report_gap", "delegated")

    # Rows whose property another check owns. Verified at the END of this
    # function rather than trusted here: a delegation nobody confirms is the
    # same shape as the branch it replaces.
    _delegated = []

    # R9-05 — THE ESTABLISHMENT REGISTER, keyed by required-property ID.
    #
    # R8-06 confirmed a delegation by asking whether any id from the row's
    # `delegated_to` list appeared anywhere in the global emitted-rule set. The
    # emitting rule did not have to be reporting on THIS property, THIS input
    # or THIS row — so pointing a row at `LINT-BND-I3`, which the ordinary
    # bundle emits for X-33 maximality, established it for free. A future
    # security property could be declared mandatory, have no evidence input,
    # and still pass, because an unrelated check happened to use the same rule
    # identifier.
    #
    # A delegate now RECORDS what it established, by property id and with the
    # instance it decided from. Coincidence cannot produce that signal:
    # a silent delegate, a crashing one, one that did not apply, and one
    # reporting on a different property all leave the register empty for this
    # row, and all four fail closed the same way.
    _established = {}

    def establish(property_id, detail):
        """Record that THIS property was decided, for THIS instance."""
        declared = {p.get("id") for p in _required_registry()["properties"]}
        if property_id not in declared:
            raise RequiredPropertyConfigError(
                f"a check reported establishing {property_id!r}, which is not "
                f"a declared required property {sorted(declared)}. An "
                "establishment signal nobody declared is a claim about a "
                "property that does not exist (R9-05)")
        _established.setdefault(property_id, []).append(detail)

    def _gaps():
        cat_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "docs", "lint-catalogue.json")
        with open(cat_path, encoding="utf-8") as fh:
            catalogued = {r["id"] for r in json.load(fh)["rules"]}
        registry = _required_registry()
        props = registry["properties"]

        # R8-06 requirement 3: an EXACT mandatory set, and unique ids. Deleting
        # a row, duplicating one or renaming one is fatal — the registry could
        # previously lose a property as quietly as it gained one.
        ids = [p.get("id") for p in props]
        duplicated = sorted({i for i in ids if ids.count(i) > 1})
        if duplicated:
            raise RequiredPropertyConfigError(
                f"required properties declare duplicate id(s) {duplicated}: a "
                "second row under one id makes the set unreadable (R8-06)")
        mandatory = registry.get("mandatory")
        if not mandatory:
            raise RequiredPropertyConfigError(
                "the required-property registry declares no `mandatory` set, "
                "so a row could be deleted without anything noticing (R8-06)")
        if set(ids) != set(mandatory):
            missing = sorted(set(mandatory) - set(ids))
            extra = sorted(set(ids) - set(mandatory))
            raise RequiredPropertyConfigError(
                f"the required-property set does not match the declared "
                f"mandatory set — missing {missing}, undeclared {extra}. "
                "Adding a property means declaring it mandatory or recording a "
                "migration; removing one may not be silent (R8-06)")

        for prop in props:
            for field in ("id", "input", "gap_rule", "establishes", "strategy"):
                if not prop.get(field):
                    raise RequiredPropertyConfigError(
                        f"a required property declares no {field!r} (R7-05)")
            if prop["input"] not in _SUPPLIED:
                raise RequiredPropertyConfigError(
                    f"required property {prop['id']!r} names input "
                    f"{prop['input']!r}, which check_bundle does not accept — "
                    "a declaration the verifier cannot act on (R7-05)")
            if prop["gap_rule"] not in catalogued:
                raise RequiredPropertyConfigError(
                    f"required property {prop['id']!r} names gap rule "
                    f"{prop['gap_rule']!r}, which is not catalogued (R7-05)")
            if prop["strategy"] not in _STRATEGIES:
                raise RequiredPropertyConfigError(
                    f"required property {prop['id']!r} declares strategy "
                    f"{prop['strategy']!r}; the vocabulary is closed "
                    f"({list(_STRATEGIES)}) and an unmapped strategy is fatal "
                    "rather than a skip (R8-06)")
            if prop["strategy"] == "delegated":
                owners = prop.get("delegated_to") or []
                unknown = [r for r in owners if r not in catalogued]
                if not owners or unknown:
                    raise RequiredPropertyConfigError(
                        f"required property {prop['id']!r} is delegated but "
                        f"names {owners or 'no'} owning rule(s)"
                        + (f", of which {unknown} are not catalogued" if unknown
                           else "")
                        + " — delegation must say WHO establishes the property "
                          "(R8-06)")
            if not _precondition_holds(prop):
                continue
            if _SUPPLIED.get(prop["input"]):
                continue
            if prop["strategy"] == "delegated":
                _delegated.append(prop)
                continue
            add(prop["gap_rule"],
                f"{prop['establishes']} — NOT ESTABLISHED: the bundle carries "
                f"no `{prop['input']}` (R6-05)")

    def _verify_delegations():
        """R8-06 requirement 1/2, corrected by R9-05 — the delegation is
        confirmed by a PROPERTY-SPECIFIC result, not by a rule identifier
        appearing somewhere in the output.

        R8-06 asked whether any id from `delegated_to` was in the global
        emitted set. That set is global: the emitting rule did not have to be
        reporting on this property at all, so a row could delegate to a common
        rule and be established by an unrelated occurrence of it.

        The delegate must have called `establish()` for THIS row's id. A
        delegate that was silent, crashed, did not apply, or decided a
        different property leaves the register empty and the row emits its own
        gap — one failure mode, closed.
        """
        for prop in _delegated:
            if not _established.get(prop["id"]):
                add(prop["gap_rule"],
                    f"{prop['establishes']} — NOT ESTABLISHED: the bundle "
                    f"carries no `{prop['input']}`, and {prop['delegated_to']} "
                    "— declared to establish it — recorded no result for this "
                    "property (R8-06/R9-05)")

    _gaps()

    # LINT-BND-41 (R6-01): the SAME identity resolver intake uses, over
    # retained evidence. Requirement 1 of the finding is "one canonical intake
    # identity resolver, SHARED with bundle validation" — sharing is the point,
    # because R6-01 exists at all through a check that lived on one side of a
    # boundary. A verifier holding an SE years later must reach the same
    # verdict the provider should have reached at intake.
    def _bnd41():
        for ev in evidence:
            if ev.get("type") != "SE-v1":
                continue
            # The SENDER's roster is the SENDER entity's discovery document, and
            # a recipient-side bundle carries the recipient's. Where the signing
            # member is not among the supplied members, the sender-side half is
            # UNDECIDABLE from this material — so it is reported INCOMPLETE
            # (R5-02's third verdict), never passed over and never failed as
            # though the member were absent from its own entity's roster.
            sc = ev.get("sender_confirmation")
            mid = sc.get("mid") if isinstance(sc, dict) else None
            roster = list(members or []) + list(counterparty_members or [])
            known = any(m.get("mid") == mid for m in roster) or \
                bool((member_history or {}).get(mid))
            if not known:
                roster = None
            # R9-05: `_bnd41` OWNS `counterparty-roster`, and records the SE
            # it decided it from — whether the tuple checked out or is reported
            # INCOMPLETE. Deciding it is the establishment; the verdict is
            # what the rules below report.
            if isinstance(sc, dict):
                establish("counterparty-roster",
                          f"SE-v1 {ev.get('message_id')!r} signed by {mid!r}")
            if isinstance(sc, dict) and not known:
                add("LINT-BND-I2",
                    f"SE-v1 {ev.get('message_id')!r} is signed by member "
                    f"{mid!r} of {ev.get('sender_uid')!r}, whose BW-MEMBER this "
                    "bundle does not carry — the sender-side identity tuple "
                    "cannot be checked from this material (R6-01)")
            for reason, detail in check_identity_coherence(
                    ev, org=org, members=roster, member_history=member_history,
                    at=ev.get("sent_at")):
                add("LINT-BND-41", f"SE-v1 {ev.get('message_id')!r}: {detail}")
            for reason, detail in check_scope_in_force(
                    org, ev.get("scope_ref"), at=ev.get("sent_at")):
                add("LINT-BND-41", f"SE-v1 {ev.get('message_id')!r}: {detail}")

    _bnd41()

    def _bnd38():
        # LINT-BND-38 (R4-03, R5-03): a retained DS receipt is verified by the
        # SHARED implementation. This rule used to carry its own copy of the
        # resolve-verify-compare sequence while mock_rdp carried another, and
        # the two drifted exactly as invariant 3 predicts: R4-03's payload
        # comparison landed here and not there, so the live path reported an
        # instant nobody had signed while this one caught it.
        if not receipts:
            return
        # R6-03 point 5: each retained receipt is LINKED to the evidence it
        # substantiates. The manifest key was never compared with the signed
        # `message_id`, so a receipt filed under any key was verified in
        # isolation and proved a delivery that might belong to another act.
        by_message = {}
        for ev in evidence:
            if ev.get("message_id"):
                by_message.setdefault(ev["message_id"], []).append(ev)
        for message_id, receipt in receipts.items():
            if not isinstance(receipt, dict):
                continue      # not a receipt object; nothing to resolve
            supported = by_message.get(message_id) or []
            if not supported:
                add("LINT-BND-38",
                    f"a DS receipt is filed under {message_id!r}, which no "
                    "evidence in this bundle names — a receipt substantiates a "
                    "delivery, and there is none here to substantiate (R6-03)")
                continue
            # R7-02 requirement 6: bind the retained receipt to the exact
            # SE/DE it substantiates, INCLUDING the issuing-RDP namespace and
            # the full signed delivery context — not only the manifest key.
            # The partial context this built before ({message_id} plus
            # sometimes recipient_uid) asserted a fraction of what the receipt
            # claims, so a receipt could be correct about the message and wrong
            # about everything else.
            se = next((e for e in supported if e.get("type") == "SE-v1"), None)
            missing = [f for f in DELIVERY_CONTEXT_FIELDS
                       if receipt.get(f) is None]
            if missing:
                add("LINT-BND-38",
                    f"DS receipt for {message_id!r} omits {missing}, so the "
                    "delivery context it attests cannot be stated in full "
                    "(R7-02)")
                continue
            expect = DeliveryContext(
                message_id=message_id,
                issuing_rdp_id=receipt["issuing_rdp_id"],
                recipient_uid=(se or {}).get("recipient_uid")
                or receipt["recipient_uid"],
                mid=receipt["mid"], device_id=receipt["device_id"],
                session_binding=receipt["session_binding"],
                message_digest=receipt["message_digest"])
            # SBM-ADR-0015: the receipt key is the ISSUING RDP's, published in
            # its BW-PROVIDER descriptor and pinned by its membership record.
            # It used to be read from the entity's BW-MED, because the Delivery
            # Service was a second provider and the customer's signed document
            # was the only thing already retained for the evidence period. With
            # one provider role the key is the RDP's own, and the MED path is
            # DELETED rather than kept as a fallback — a `kid` published only in
            # a BW-MED does not resolve.
            descriptor = _descriptor_for(receipt.get("issuing_rdp_id"))
            if descriptor is None:
                add("LINT-BND-I8",
                    f"DS receipt for {message_id!r}: no BW-PROVIDER descriptor "
                    f"for the issuing RDP {receipt.get('issuing_rdp_id')!r} was "
                    "supplied, so the key that signed it cannot be resolved and "
                    "the handover rests on the DE's assertion alone "
                    "(SBM-ADR-0015)")
                continue
            try:
                verify_ds_receipt(receipt, descriptor, expect=expect)
            except ReceiptVerificationError as e:
                add("LINT-BND-38",
                    f"DS receipt for {message_id!r}: {e.detail}")

    _bnd38()

    # LINT-BND-35 (R3-02/R3-T2): the pinned policy version was the LATEST one
    # in force at the act, not merely one that was in force.
    #
    # LINT-BND-33 receives only the single BW-ORG the bundle pins, so it can
    # check `valid_from <= sent_at` and nothing else: with no upper bound, no
    # successor and no history, MAXIMALITY is unprovable, and an old superseded
    # policy carrying a valid signature and a valid `valid_from` passed. The
    # R2-M6 prohibition on publishing a future version as current does not help
    # — it constrains the future, and this is a claim about the past.
    #
    # R3-T2 chose a signed chain over an `as_of` endpoint deliberately:
    # maximality becomes a LOCAL property of the retained artefacts, so
    # verifying a 2026 act in 2033 does not depend on a service still being
    # online and still honest.
    def _bnd35(ev, se_ctx):
        apr = ev.get("acceptance_policy_ref")
        if not (isinstance(apr, dict)
                and (apr.get("doc_digest") or {}).get("hex") == org_digest):
            return
        src = se_ctx if se_ctx is not None else (
            ev if ev.get("type") == "SE-v1" else None)
        sent = (src or {}).get("sent_at")
        if not sent:
            return

        # R4-U1: a published BW-ORG is IMMUTABLE. Its window is
        # [valid_from, successor.valid_from) — DERIVED from the chain, never
        # stored — so closing v1 is v2's job and v1's pinned digest stays valid
        # forever. R4-02 reproduced the deadlock the stored field created:
        # leaving v1 unbounded made this rule reject it, and bounding it changed
        # its digest so the evidence that pinned it stopped resolving. Both
        # branches were closed for the ORDINARY publication.
        if not policy_history:
            # R4-02: this was a bare `return`, so an absent history silently
            # downgraded verification to "in force at some point" — and the
            # umbrella claimed omitting the history was not a way around
            # maximality, which was false for exactly the normal case. Absence
            # is now a stated OUTCOME: what is unproven is said to be unproven.
            # R5-02/R5-V1: this was the W2 warning, which main() printed
            # and did not count — so the verifier said MAXIMALITY IS NOT PROVEN
            # and returned `[OK] ✓`, exit 0, on all four shipped positive
            # bundles. Round 4 wrote that "requiring the full chain inside every
            # bundle is a separate decision nobody has taken"; R5-V1 has taken
            # it. INCOMPLETE is not success: no [OK], and a non-zero exit.
            add("LINT-BND-I1",
                f"{ev.get('type')} pins BW-ORG {org.get('policy_version')!r} and "
                f"the bundle carries no policy history, so MAXIMALITY IS NOT "
                f"PROVEN: this verification shows the version was in force at "
                f"{sent}, not that it was the latest such version. Supply the "
                "signed chain to prove it (R4-02)")
            return

        # R9-05: this rule OWNS `policy-chain`, and it says so for THIS act.
        # The delegation used to be confirmed by `LINT-BND-35` appearing
        # anywhere in the output — including for a completely different act, or
        # for an ordering failure that decided nothing.
        establish("policy-chain",
                  f"{ev.get('type')} {ev.get('message_id')!r} at {sent}")

        try:
            chain = sorted(policy_history,
                           key=lambda v: instant(v.get("valid_from"),
                                                 field="valid_from"))
        except TimestampError as e:
            add("LINT-BND-35", f"policy history cannot be ordered: {e} (R3-02)")
            return

        # R6-02/R6-W1: a PREFIX is not a history. Round 5 made the ABSENT
        # history a typed gap and left truncation untouched, so supplying only
        # the current document passed clean — the fix had been applied to the
        # reproduction (`[]`) rather than to the class.
        #
        # What is locally checkable is the backward link each document already
        # carries: every `supersedes` must resolve to another document in the
        # supplied set, and the earliest must be a first publication with none.
        # A fragment presented as a history is a FAIL, not a gap: the claimant
        # chose what to show, and the documents themselves say something is
        # missing.
        #
        # NOT cowork's proposed rule ("the head must be the BW-ORG the manifest
        # carries as `org`"), which was checked and cannot fire: LINT-BND-10
        # already forces that org to BE the pinned document, so the rule
        # compares the pinned version with itself.
        have = {v.get("policy_version") for v in chain}
        for v in chain:
            sup = v.get("supersedes")
            if isinstance(sup, dict) and sup.get("policy_version") not in have:
                add("LINT-BND-35",
                    f"BW-ORG {v.get('policy_version')!r} names predecessor "
                    f"{sup.get('policy_version')!r}, which the supplied history "
                    "does not contain — this is a PREFIX, not the chain. The "
                    "document itself says a version is missing (R6-02)")
                return
        roots = [v for v in chain if not isinstance(v.get("supersedes"), dict)]
        if len(roots) != 1:
            add("LINT-BND-35",
                f"the supplied history has {len(roots)} first publications "
                "(documents with no `supersedes`); a chain has exactly one, so "
                "this is either a fragment or two chains spliced (R6-02)")
            return

        seen_from = set()
        for i, v in enumerate(chain):
            vf = v.get("valid_from")
            if vf in seen_from:
                add("LINT-BND-35",
                    f"two BW-ORG versions claim valid_from {vf} — a duplicate "
                    "boundary makes the version in force at that instant "
                    "ambiguous (R3-02)")
                return
            seen_from.add(vf)
            if v.get("valid_until"):
                add("LINT-BND-35",
                    f"BW-ORG {v.get('policy_version')!r} stores a valid_until — "
                    "the window's upper bound is DERIVED from the successor's "
                    "valid_from (R4-U1). Storing it means the document must be "
                    "rewritten when a successor appears, which changes the "
                    "digest evidence already pinned to it")
                return
            if i + 1 < len(chain):
                nxt = chain[i + 1]
                sup = nxt.get("supersedes") or {}
                if sup.get("policy_version") != v.get("policy_version"):
                    add("LINT-BND-35",
                        f"BW-ORG {nxt.get('policy_version')!r} does not name "
                        f"{v.get('policy_version')!r} as its predecessor — the "
                        "chain is not linked, so a version could be dropped "
                        "from the history unnoticed (R3-02)")
                    return
                want = hashlib.sha256(dcbor(
                    {k: val for k, val in v.items() if k != "doc_cose_b64"}
                )).hexdigest()
                if ((sup.get("doc_digest") or {}).get("hex")) != want:
                    add("LINT-BND-35",
                        f"BW-ORG {nxt.get('policy_version')!r} names a "
                        "predecessor digest that is not its predecessor's "
                        "content — an equivocated history (R3-02). Note this "
                        "detects a fork only when BOTH documents are observed; "
                        "it does not prevent equivocation (X-33)")
                    return

        # The window of chain[i] is [valid_from(i), valid_from(i+1)) — derived.
        try:
            at = instant(sent, field="sent_at")
            bounds = [instant(v.get("valid_from"), field="valid_from")
                      for v in chain]
        except TimestampError as e:
            add("LINT-BND-35", f"policy history cannot be evaluated: {e}")
            return
        eligible = [v for i, v in enumerate(chain)
                    if bounds[i] <= at
                    and (i + 1 == len(chain) or at < bounds[i + 1])]
        if not eligible:
            add("LINT-BND-35",
                f"no BW-ORG version in the history was in force at {sent} "
                "(R3-02)")
            return
        latest = eligible[-1]
        # R6-W1: and even when it matches, MAXIMALITY IS NOT PROVEN.
        #
        # The truncation that defeats maximality is a hidden SUCCESSOR, not a
        # dropped predecessor. If the entity published v2 before the act and
        # the claimant supplies [v0, v1], every backward link resolves, the
        # chain is structurally perfect, and this rule concludes v1 was latest.
        # A complete chain and a successor-truncated chain are BYTE-IDENTICAL
        # from inside the bundle.
        #
        # So round 5's `[OK]` asserted a property no local material can
        # establish. R5-V1 fixed the absence case and left the claim itself
        # overstated; R6-W1 stops making it. What a retained chain proves is
        # LINKAGE and IN-FORCE-AT-THE-ACT. Excluding a later successor needs an
        # authenticated head — a log — and that is X-33.
        add("LINT-BND-I3",
            f"{ev.get('type')} pins BW-ORG {org.get('policy_version')!r} and "
            f"the supplied chain shows it in force at {sent} and unbroken back "
            "to a first publication. MAXIMALITY IS STILL NOT PROVEN: nothing "
            "in a retained prefix can exclude a successor the claimant did not "
            "supply, and a complete chain is indistinguishable from a truncated "
            "one from inside the bundle. Excluding one needs an authenticated "
            "head (X-33) (R6-02/R6-W1)")
        if latest.get("policy_version") != org.get("policy_version"):
            add("LINT-BND-35",
                f"{ev.get('type')} pins BW-ORG "
                f"{org.get('policy_version')!r}, but the version in force at "
                f"{sent} was {latest.get('policy_version')!r} — pinning an "
                "earlier version applies rules that had already been "
                "superseded (R3-02)")

    # LINT-BND-33 (DR-04): the pinned version was IN FORCE at the act. X-12
    # made selection deterministic and F-08 made the selected KEY recomputable,
    # but neither bounded the version in TIME: the shipped chains pinned a
    # BW-ORG taking force 2026-06-01 for a message sent 2026-04-04, and the
    # scoped chain a scope taking force 2026-07-01 for the same message — and
    # the bundles were lint-clean. Evidence could be evaluated under rules that
    # did not yet exist when the act took place, which is the one thing a
    # policy version is supposed to prevent. Both arms are checked: the ORG's
    # own valid_from, and (for a scoped message) the SCOPE entry's, since a
    # scope can be introduced into an already-in-force ORG. Parsed instants
    # (DR-05); a tie is in force.
    def _bnd33(ev, se_ctx):
        apr = ev.get("acceptance_policy_ref")
        if not (isinstance(apr, dict)
                and (apr.get("doc_digest") or {}).get("hex") == org_digest):
            return
        src = se_ctx if se_ctx is not None else (
            ev if ev.get("type") == "SE-v1" else None)
        sent = (src or {}).get("sent_at")
        if not sent:
            return
        vf = org.get("valid_from")
        if vf and _gt(vf, sent, add, "BW-ORG.valid_from"):
            add("LINT-BND-33",
                f"{ev.get('type')} pins a BW-ORG in force from {vf}, but the "
                f"message was sent at {sent}: the acceptance policy did not yet "
                "exist when the message was sent — evidence cannot be evaluated "
                "under rules that post-date the act (DR-04, umbrella §8.3)")
        sref = (src or {}).get("scope_ref") or {}
        sid, sver = sref.get("scope_id"), sref.get("scope_version") or sref.get("version")
        if sid and sid != "default":
            entries = ((org.get("scope_map") or {}).get("scopes") or [])
            match = [s for s in entries if s.get("scope_id") == sid
                     and (sver is None or str(s.get("version")) == str(sver))]
            for s in match:
                svf = s.get("valid_from")
                if svf and _gt(svf, sent, add, f"scope[{sid}].valid_from"):
                    add("LINT-BND-33",
                        f"{ev.get('type')} is scoped to {sid!r} v{s.get('version')}, "
                        f"in force from {svf}, but the message was sent at {sent}: "
                        "the scope did not yet exist when the message was sent "
                        "(DR-04, umbrella §8.3)")

    # LINT-BND-30 (F-08, evidence 2.4): the selected policy key is recomputable
    # and recomputed. For every evidence object whose acceptance_policy_ref
    # pins THIS org (doc_digest == the org's digest): (a) policy_key must
    # exist in the org's acceptance_policy map; (b) where the message's SE is
    # in the bundle, policy_key must equal the deterministic selection
    # recomputed from (scope_ref, recipient_addr, org) — the reference
    # algorithm lint_cli.select_policy_key (umbrella §8.3); (c) a DE carrying
    # acceptance_policy_kind must carry the kind of the keyed policy. A DE/RE
    # echoes its SE's ref, so the SE's selection governs the whole chain.
    def _bnd30(ev, se_ctx):
        apr = ev.get("acceptance_policy_ref")
        if not (isinstance(apr, dict)
                and (apr.get("doc_digest") or {}).get("hex") == org_digest):
            return
        pk = apr.get("policy_key")
        policy = org.get("acceptance_policy") or {}
        if pk not in policy:
            add("LINT-BND-30",
                f"{ev.get('type')} acceptance_policy_ref.policy_key {pk!r} does "
                "not exist in the pinned BW-ORG's acceptance_policy map (F-08)")
            return
        src = se_ctx if se_ctx is not None else (
            ev if ev.get("type") == "SE-v1" else None)
        if src is not None:
            # R3-01: an unaddressed SE is a violation HERE too, not merely at
            # intake — a bundle is verified long after the RDP that accepted
            # it, and a verifier must reach the same verdict.
            try:
                want = select_policy_key(org, src.get("scope_ref"),
                                         src.get("recipient_addr"))
            except UnaddressedSubmission as e:
                add("LINT-BND-30",
                    f"{ev.get('type')} carries no recipient_addr, so the "
                    f"deterministic §8.3 selection cannot be recomputed: {e} "
                    "(R3-01)")
                return
            except ForeignAddress as e:
                # R4-01: a typed violation, never an escaping exception. An
                # uncaught error in a verifier is worse than a missed check —
                # it terminates validation and everything after it goes
                # unexamined, which is DR-03's lesson.
                add("LINT-BND-24",
                    f"{ev.get('type')}: the §8.3 selection cannot be "
                    f"recomputed: {e}")
                return
            if want is not None and pk != want:
                add("LINT-BND-30",
                    f"{ev.get('type')} policy_key {pk!r} != {want!r}, the "
                    "deterministic selection recomputed from the SE's "
                    "(scope_ref, recipient_addr) and the pinned ORG "
                    "(umbrella §8.3; F-08)")
        kind = ev.get("acceptance_policy_kind")
        if kind:
            pol = policy.get(pk) or ""
            want_kind = "quorum" if pol.startswith("quorum:") else \
                        "device-class" if pol.startswith("device-class:") else pol
            if kind != want_kind:
                add("LINT-BND-30",
                    f"{ev.get('type')} acceptance_policy_kind {kind!r} != "
                    f"{want_kind!r}, the kind of acceptance_policy[{pk!r}] = "
                    f"{pol!r} in the pinned ORG (F-08)")

    for ev in evidence:
        if ev.get("type") == "EP-v1":
            ep_se = ev.get("se")
            if isinstance(ep_se, dict):
                _bnd30(ep_se, ep_se)
                _bnd33(ep_se, ep_se)
                _bnd35(ep_se, ep_se)
            for o in ev.get("outcomes", []):
                if isinstance(o, dict):
                    _bnd30(o, ep_se if isinstance(ep_se, dict) else None)
                    _bnd33(o, ep_se if isinstance(ep_se, dict) else None)
                    _bnd35(o, ep_se if isinstance(ep_se, dict) else None)
        else:
            _bnd30(ev, se_by_mid.get(ev.get("message_id")))
            _bnd33(ev, se_by_mid.get(ev.get("message_id")))
            _bnd35(ev, se_by_mid.get(ev.get("message_id")))
    for ev in evidence:
        if ev.get("type") in ("DE-v1", "NDE-v1"):
            _check_expiry(se_by_mid.get(ev.get("message_id")), ev)
        elif ev.get("type") == "EP-v1":  # an EP carries its own SE + outcomes
            for o in ev.get("outcomes", []):
                _check_expiry(ev.get("se"), o)

    # LINT-BND-25 (F-02, evidence 2.2): the transmitted-octet chain — a relay
    # hop's envelope_hash MUST equal the SE's for the same message_id (a
    # substituted ciphertext under the same metadata fails at every hop).
    _se_env = {}
    for ev in evidence:
        if ev.get("type") == "SE-v1" and ev.get("envelope_hash"):
            _se_env[ev.get("message_id")] = ev["envelope_hash"]
        elif ev.get("type") == "EP-v1" and (ev.get("se") or {}).get("envelope_hash"):
            _se_env[ev["se"].get("message_id")] = ev["se"]["envelope_hash"]
    for ev in evidence:
        if ev.get("type") != "RelayEvidence-v1":
            continue
        se_val = _se_env.get(ev.get("message_id"))
        if se_val is not None and ev.get("envelope_hash") != se_val:
            add("LINT-BND-25",
                f"relay hop for {ev.get('message_id')!r} attests a different "
                "envelope_hash than the SE — substituted ciphertext under the "
                "same metadata (F-02)")

    # LINT-BND-26 (X-04/D5/DR-03, evidence 2.7): grade-commitment-mismatch
    # verification — REWRITTEN. The former rule accepted a dispute whenever the
    # recomputed commitment DIFFERED from the sealed one; difference is
    # manufacturable (invent a salt), so any recipient provider could rebut ANY
    # availability-grade DE. Commitment inequality alone now proves NOTHING.
    #
    # A dispute is valid only when BOTH hold:
    #   (a) PROOF OF ATTRIBUTION — the recipient's reveal_confirmation verifies
    #       against the confirming device's published confirmation_key as it
    #       stood at read_at (the as-of read; INTF-1/1a/2), and its signed tuple
    #       matches the disputed evidence; and
    #   (b) MISMATCH — the recomputation differs from the sealed commitment, OR
    #       it matches but the revealed class is not availability-declared.
    # (b) alone is what the attacker manufactures; (a) is what makes the claim
    # someone's. Honest scope: (a) proves an ATTRIBUTABLE RECIPIENT ASSERTION,
    # not objective extraction from the ciphertext (R2-M1).
    _gcms = [ev for ev in evidence if ev.get("type") == "GCM-v1"]
    for ev in evidence:
        if ev.get("type") == "EP-v1":
            _gcms.extend(ev.get("disputes") or [])
    _sealed_gc = {}
    for ev in evidence:
        if ev.get("type") == "SE-v1" and ev.get("grade_commitment"):
            _sealed_gc[ev.get("message_id")] = ev["grade_commitment"]
        elif ev.get("type") == "EP-v1" and (ev.get("se") or {}).get("grade_commitment"):
            _sealed_gc[ev["se"].get("message_id")] = ev["se"]["grade_commitment"]
    for g in _gcms:
        pv = (g.get("acceptance_policy_ref") or {}).get("policy_version")
        r = g.get("reveal") or {}
        if pv != orgpv or not r:
            continue  # pinned to a different ORG version — not this bundle's to verify
        sealed = _sealed_gc.get(g.get("message_id"), g.get("grade_commitment"))
        if g.get("grade_commitment") != sealed:
            add("LINT-BND-26",
                f"GCM for {g.get('message_id')!r} does not echo the sealed "
                "grade_commitment of its SE/DE — the dispute must reference the "
                "disputed value (D5)")
            continue
        # (a) PROOF OF ATTRIBUTION — without it the dispute is inert, whatever
        # the arithmetic says. This is the DR-03 fix: the former rule reached
        # the recompute directly and accepted inequality as proof.
        conf = g.get("reveal_confirmation")
        if not isinstance(conf, dict):
            add("LINT-BND-26",
                f"GCM for {g.get('message_id')!r} carries NO recipient "
                "reveal_confirmation — commitment inequality alone proves "
                "nothing and is manufacturable by inventing a salt (DR-03)")
            continue
        cmid, cdid = conf.get("mid"), conf.get("device_id")
        # DR-11: as-of resolution — the key valid at read_at, not the current
        # one. This comment made that claim before DR-11; the code did not.
        cpub = _anchor_at(cmid, cdid, _act_time(g, conf),
                          f"GCM reveal_confirmation {cmid!r}/{cdid!r}")
        if (why := _active_at(cmid, _act_time(g, conf),
                              f"GCM reveal_confirmation {cmid!r}")):
            add("LINT-BND-26",
                f"GCM reveal_confirmation by {cmid!r} did not resolve to an "
                f"active member of {entity!r} AT read_at ({why}) — an "
                "unattributable dispute (DR-03, as-of per R3-03)")
            continue
        if not cpub:
            add("LINT-BND-26",
                f"GCM reveal_confirmation by {cmid!r}/{cdid!r} has no resolvable "
                "confirmation_key anchor as of read_at (DR-03)")
            continue
        if (why := _verify_wallet_sig(conf.get("wallet_signature_b64") or "", cpub)):
            add("LINT-BND-26",
                f"GCM reveal_confirmation signature does not verify against the "
                f"published confirmation key of {cmid!r}/{cdid!r} — the dispute "
                f"was not produced by that member's device (DR-03): {why}")
            continue
        # the signed tuple must describe THIS dispute
        for field, want in (("message_id", g.get("message_id")),
                            ("envelope_hash", g.get("envelope_hash")),
                            ("grade_commitment", g.get("grade_commitment")),
                            ("salt", r.get("salt")),
                            ("content_class", r.get("content_class")),
                            ("read_at", g.get("read_at")),
                            ("recipient_uid", g.get("recipient_uid")),
                            ("mid", g.get("mid"))):
            if conf.get(field) != want:
                add("LINT-BND-26",
                    f"GCM reveal_confirmation.{field} does not match the dispute "
                    f"({conf.get(field)!r} != {want!r}) — the signed tuple must "
                    "cover the disputed values (DR-03)")
                break
        else:
            # (b) MISMATCH — evaluated only now that the claim is attributable
            try:
                recomputed = compute_grade_commitment(
                    r["salt"], r["content_class"], org_digest)
            except CommitmentInputError as exc:
                add("LINT-BND-26",
                    f"GCM for {g.get('message_id')!r} has malformed commitment "
                    f"input: {exc} (DR-03 — a typed violation, never an "
                    "uncaught exception in the validator)")
                continue
            declared = (org.get("delivery_grades") or {}).get(r["content_class"])
            if recomputed == g.get("grade_commitment") and declared == "availability":
                add("LINT-BND-26",
                    f"GCM for {g.get('message_id')!r} is VOID: the reveal matches "
                    f"the sealed commitment and {r['content_class']!r} IS "
                    "availability-declared — no mismatch is proven; the "
                    "availability DE stands (D5)")

    # LINT-BND-27 (X-22): the sender-computed TTL is bounded by the recipient's
    # declared maximum (BW-ORG max_ttl, ISO 8601 duration; absent => the profile
    # default P30D). Checked for every SE addressed to this entity.
    # R10-08: the ONE X-22 validator, which intake runs before sealing. This
    # carried a private duration parser that returned None for a value it
    # could not read, and the caller then used the 30-day default — "I cannot
    # read the maximum" became "the maximum is thirty days".
    for ev in evidence:
        ses = []
        if ev.get("type") == "SE-v1":
            ses.append(ev)
        elif ev.get("type") == "EP-v1" and ev.get("se"):
            ses.append(ev["se"])
        for se_ in ses:
            if se_.get("recipient_uid") != entity:
                # Safe to skip: LINT-BND-27 bounds the TTL against THIS
                # entity's declared maximum, and an SE addressed elsewhere is
                # governed by that entity's own maximum, not ours. Contrast
                # LINT-BND-24 below, where a foreign UID is the defect itself
                # (R4-01) rather than someone else's business.
                continue
            sent, exp = se_.get("sent_at"), se_.get("expires_at")
            if not (sent and exp):
                continue
            for reason, detail in expiry_problems(sent, exp,
                                                  max_ttl=org.get("max_ttl")):
                if reason == "expiry-beyond-max-ttl":
                    add("LINT-BND-27",
                        f"SE for {se_.get('message_id')!r}: {detail}")
                elif reason in ("submission-invalid", "policy-unresolvable"):
                    add("LINT-BND-27",
                        f"SE for {se_.get('message_id')!r}: TTL cannot be "
                        f"evaluated: {detail} (DR-05)")
                # ordering is LINT-DE-18's concern

    # LINT-BND-24 (X-16): a bw: address that names a role or member MUST RESOLVE.
    # A recipient_addr .../r/<role> addressed to this entity must name a declared
    # role (every address resolves); .../u/<MID> must name a member. Schema
    # tightening already guarantees every DECLARED role is addressable; this closes
    # the other direction — an address to an undeclared role/member is rejected.
    addressable_roles = set(org.get("roles") or [])
    addressable_roles |= set((org.get("acceptance_policy") or {}).keys())
    for sc in scopes:
        addressable_roles |= set(sc.get("roles") or [])
        if sc.get("records_role"):
            addressable_roles.add(sc["records_role"])
    member_mids = {m.get("mid") for m in members}
    _addr_objs = list(evidence) + [ev.get("se") for ev in evidence
                                   if ev.get("type") == "EP-v1" and ev.get("se")]

    # LINT-BND-37 (R4-01): the SENDER side, which was ABSENT — `sender_addr`
    # appeared zero times in this file. An address is only as good as its
    # binding to the identity it claims, and the recipient arm having one while
    # the sender arm had none is the asymmetry the finding names.
    for ev in _addr_objs:
        saddr, suid = ev.get("sender_addr"), ev.get("sender_uid")
        if not isinstance(saddr, str) or not suid:
            continue        # absence is R3-01's typed rejection, not this rule
        sparsed = _parse_bw_address(saddr)
        if sparsed is None:
            add("LINT-BND-37",
                f"{ev.get('type')} sender_addr {saddr!r} is not a well-formed "
                "bw: address (R4-01/X-16)")
            continue
        if sparsed[0] != suid:
            add("LINT-BND-37",
                f"{ev.get('type')} sender_addr names entity {sparsed[0]!r} but "
                f"sender_uid is {suid!r} — the acting address must belong to the "
                "acting entity, or the signed act names someone it is not "
                "(R4-01)")
            continue
        # Where THIS bundle is the sender's, the role/member must resolve on
        # this roster too — the mirror of the recipient arm above.
        if suid == entity:
            if sparsed[1] == "role" and sparsed[2] not in addressable_roles:
                add("LINT-BND-37",
                    f"{ev.get('type')} sender_addr names role {sparsed[2]!r}, "
                    f"not a declared role of {entity!r} (R4-01)")
            elif sparsed[1] == "member" and sparsed[2] not in member_mids:
                add("LINT-BND-37",
                    f"{ev.get('type')} sender_addr names member {sparsed[2]!r}, "
                    f"not a member of {entity!r} (R4-01)")
    for ev in _addr_objs:
        addr = ev.get("recipient_addr")
        if not isinstance(addr, str):
            continue
        parsed = _parse_bw_address(addr)
        if parsed is None:
            add("LINT-BND-24", f"{ev.get('type')} recipient_addr {addr!r} is not a "
                "well-formed bw: address (X-16)")
            continue
        uid, kind, val = parsed
        # R4-01 (Blocker): this WAS `continue  # not this bundle's org`. The
        # comment was true and irrelevant: the object being checked is THIS
        # bundle's evidence, addressed to THIS entity, so an address naming
        # another entity is not someone else's business — it is the defect.
        # Selection read only the /r/<role> tail, so a foreign address picked a
        # role out of this entity's policy map.
        target_uid = ev.get("recipient_uid")
        if uid != (target_uid or entity):
            add("LINT-BND-24",
                f"{ev.get('type')} recipient_addr names entity {uid!r} but the "
                f"object is addressed to {target_uid or entity!r} — the address "
                "and the evidence must name the SAME entity, or the address can "
                "select a policy inside an entity it does not belong to (R4-01)")
            continue
        if uid != entity:
            # Coherent with its own recipient_uid but not this bundle's entity:
            # LINT-BND-06/04 own that mismatch, and the role/member resolution
            # below is meaningless against another entity's roster.
            continue
        if kind == "role" and val not in addressable_roles:
            add("LINT-BND-24", f"{ev.get('type')} recipient_addr names role {val!r}, "
                f"not a declared role of {entity!r} — an address MUST resolve to a "
                "declared role (X-16)")
        elif kind == "member" and val not in member_mids:
            add("LINT-BND-24", f"{ev.get('type')} recipient_addr names member {val!r}, "
                f"not a published member of {entity!r} (X-16)")
    # ---- LINT-TRUST-06 (Batch A / A5) — federation admission at the act ----
    #
    # The bundle establishes that an issuer sealed this evidence. It does not
    # establish that the issuer was ADMITTED to the federation when it acted —
    # umbrella §13.1 makes that an independent gate, and until this rule the
    # specification ordered a verifier to check something nothing checked.
    #
    # The register is a SEPARATE INPUT. Its absence is the declared
    # `federation-admission` gap (INCOMPLETE, exit 3), emitted by `_gaps()`
    # from the registry row — not here, because a rule that also owned its own
    # absence would be deciding when it applies.
    #
    # R10-01: the register is AUTHENTICATED before a single status is read,
    # against an anchor that is configuration (`--trust-store`), never part of
    # the bundle — a register verified against a key that arrived beside it
    # has been verified against nothing. A register that fails authentication
    # is a violation (LINT-TRUST-08); a register nobody can authenticate,
    # because no anchor is configured, leaves admission unestablished and says
    # so as the same property's gap.
    register = None
    if federation_register is not None:
        if not fa_anchors:
            add("LINT-BND-I6",
                "that every provider named in the bundle was admitted to the "
                "federation at the instant of its act — NOT ESTABLISHED: a "
                "register was supplied, but no Federation Authority anchor is "
                "configured (--trust-store), so its authenticity cannot be "
                "established and it was not consulted (R10-01)")
        else:
            register, _reg_issues = authenticate_register(
                federation_register, fa_anchors)
            for rule, msg in _reg_issues:
                add(rule, msg)
    def _resolve(label, pid, at):
        """One provider, one act instant: the admission rule, reported."""
        try:
            status = admission_at(register, pid, at=at)
        except (ValueError, TimestampError) as exc:
            add("LINT-TRUST-06",
                f"{label}: the register cannot answer for {pid!r} at {at}: {exc}")
            return
        if status == "admitted":
            return
        if status is NOT_COVERED:
            # R10-X1: the record was asserted before this act, so it cannot
            # speak for it. Unestablished — the same property's gap, never
            # `admitted` and never a violation. A later assertion closes it.
            add("LINT-BND-I6",
                f"that every provider named in the bundle was admitted to the "
                f"federation at the instant of its act — NOT ESTABLISHED for "
                f"{label}: provider {pid!r} acted at {at}, after the register's "
                "assertion for it, which cannot speak for a later instant (R10-X1)")
            return
        if status is None:
            add("LINT-TRUST-06",
                f"{label} names provider {pid!r}, to which the register "
                f"attributes no status at {at} — the provider is unknown to the "
                "federation, or acted before it was admitted. Silence is not "
                "admission (§13.1)")
        else:
            add("LINT-TRUST-06",
                f"{label} names provider {pid!r}, which the register records as "
                f"{status!r} at {at}, the instant of the act itself (§13.1)")

    if register is not None:
        _fields = _provider_id_fields()
        for ev in evidence:
            for pid, at, where in _provider_acts(ev, fields=_fields):
                label = f"{ev.get('type')} {where}"
                if at is None:
                    add("LINT-TRUST-06",
                        f"{label} names provider {pid!r} but no act instant is "
                        "in scope for it, so admission cannot be evaluated at "
                        "the moment of the act. An evidence type this verifier "
                        "cannot date is one it must not vouch for "
                        "(bundle_lint.ACT_INSTANT)")
                    continue
                _resolve(label, pid, at)
            if ev.get("type") in ACT_INSTANT_COMPOSED:
                # R10-X5 / D10-01 — the COMPOSER is a provider too, and
                # composing IS an act: sealing a package that attests
                # everyone else's acts. The chain entries and nested objects
                # above are the acts the package RECORDS; this is the act of
                # making it, by the sender-side RDP (the EP signer is bound to
                # `se.rdp_id`, TS clause 4.1), at the instant its own
                # timestamp attests. It had no instant of its own here, so a
                # composer suspended between the last relay hop and the
                # sealing composed a package this verifier accepted.
                composer = (ev.get("se") or {}).get("rdp_id")
                composed = sealed_at(ev)
                label = f"{ev.get('type')} composition (sealed by se.rdp_id)"
                if not composer:
                    add("LINT-TRUST-06",
                        f"{label}: the package names no composer, so whose "
                        "admission to check cannot be determined")
                elif composed is None:
                    add("LINT-BND-I6",
                        f"that every provider named in the bundle was admitted "
                        f"to the federation at the instant of its act — NOT "
                        f"ESTABLISHED for {label}: the package's timestamp "
                        "carries no readable instant, so the moment of "
                        "composition cannot be read (R10-X5)")
                else:
                    _resolve(label, composer, composed)

    # R8-06: the delegated properties are settled LAST, once every rule
    # that might own one has had its say.
    _verify_delegations()
    return out


def main(argv):
    args, opts = parse_common_flags(argv)
    if opts["unknown"] or not args:
        for a in opts["unknown"]:
            print(f"[ERR ] unknown flag: {a}", file=sys.stderr)
        print("usage: bundle_lint.py <bundle.manifest.json> [...]", file=sys.stderr)
        return 2
    # R10-01: the Federation Authority anchor is CONFIGURATION, taken from the
    # trust store, never from the bundle being verified.
    fa_anchors = None
    if opts["trust_store"] is not None:
        try:
            fa_anchors = federation_authority_anchors(
                load_trust_store(opts["trust_store"]))
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
    total = unproven = 0
    for f in args:
        try:
            manifest = _load(f)
        except Exception as exc:
            print(f"[ERR ] {f}: cannot read/parse ({exc})")
            total += 1
            continue
        issues = lint_bundle(manifest, os.path.dirname(os.path.abspath(f)),
                             fa_anchors=fa_anchors)
        warnings = warnings_of(issues)
        gaps = incomplete_of(issues)
        issues = violations(issues)
        for rule, msg in warnings:
            print(f"[WARN] {f}: {rule}: {msg}")
        for rule, msg in gaps:
            print(f"[GAP ] {f}: {rule}: {msg}")
        if issues:
            total += len(issues)
            for rule, msg in issues:
                print(f"[FAIL] {f}: {rule}: {msg}")
        elif gaps:
            # R5-02: NOT `[OK]`. The evidence may be perfectly sound; the
            # verifier could not establish a required property from what it was
            # given, and saying "ok" to that is how a stated gap becomes an
            # ignored one.
            unproven += len(gaps)
            print(f"[GAP ] {f}: verification INCOMPLETE — {len(gaps)} required "
                  "property could not be established from the retained material")
        else:
            print(f"[OK  ] {f} ✓")
    if total:
        print(f"FAIL: {total} violation(s)")
        return 1
    if unproven and opts.get("allow_incomplete"):
        # R6-W1: this bar accepts INCOMPLETE and never accepts violations. The
        # gaps are printed either way — the flag changes the exit code, not
        # what the verifier says. `make conformance` passes the flag because
        # the shipped bundles cannot prove maximality and no local material
        # could make them; a deployment that has an authenticated head should
        # not pass it.
        print(f"INCOMPLETE (accepted): 0 violation(s), {unproven} unproven "
              "required property/properties — see [GAP] above")
        return 0
    if unproven:
        print(f"INCOMPLETE: 0 violation(s), {unproven} unproven required "
              "property/properties — not a pass")
        return 3
    print("OK: 0 violation(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
