#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Semantic conformance validator for the discovery documents (X8): BW-MED-v1,
BW-ORG-v1, BW-MEMBER-v1. The discovery side was previously unlinted while the
evidence side had `evidence_lint`; this closes that gap with the same
conventions (stable `LINT-DISC-NN` rule ids, deterministic-CBOR payload binding,
a hard `cbor2` requirement).

Usage:
    python scripts/discovery_lint.py samples/sample-BW-*.json
Exit 0 = clean, 1 = at least one violation, 2 = usage / missing cbor2.
"""
import base64
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lint_cli import (parse_common_flags, load_trust_store, check_trust,  # noqa: E402  — shared (P1/P10)
                      load_directory, check_directory_pin,
                      load_federation_register, check_register_pin,
                      authenticate_register, federation_authority_anchors,
                      find_unsafe_numbers, hash_mode_violations, load_ijson, DuplicateKeyError,
                      reconstruct, dcbor, projection_equals_decode, validate_body)
import id_grammar  # noqa: E402  — X-02: the single UID/MID check-symbol algorithm

DISCOVERY_TYPES = {"BW-MED-v1", "BW-ORG-v1", "BW-MEMBER-v1",
                   "BW-PROVIDER-v1"}
# A3: closed to `rdp`, matching the register's `role` enum and the descriptor
# Schema. It stays closed: SBM-ADR-0015 made `rdp` the ONE provider role — the
# Registered Delivery Provider operates the Delivery Service as part of the
# qualified service it is supervised for — so there is no second role to admit.
# This comment said `msp` was coming, which was true of 17 September 2026 and
# withdrawn on 6 October; the enum it describes never moved.
PROVIDER_ROLES = {"rdp"}
COSE_ALG_ALLOWLIST = {-8, -7, -35}
UID_RE = re.compile(
    r"^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$")
MID_RE = re.compile(r"^[0-9A-HJ-NP-TV-Z]{9}$")
from lint_cli import POLICY_RE  # noqa: E402  — the grammar, stated once (R11-02)
from lint_cli import flat_projection  # noqa: E402  — R11-09
RECOVERABILITY = {"strict", "records"}
# Two-tier content-class registry (X-25): tier 1 is LOADED from the
# machine-readable registry artefact (registries/content-classes.json, owned by
# the design authority per umbrella §13.4) — promoting a class is a registry
# action, not a lint-code release. Entity-defined private classes carry the
# x- prefix (the same private-use convention as the reason-code registry).
from lint_cli import load_registry  # noqa: E402
STANDARD_CONTENT_CLASSES = set(load_registry("content-classes.json")["tier1"])
# Lint is stricter than the schema's lexical pattern: a private class must
# have a non-empty name after the x- prefix ("x-" alone is rejected here).
CONTENT_CLASS_RE = re.compile(r"^(x-[a-z0-9][a-z0-9-]{0,61}|(?!x-)[a-z][a-z0-9-]{0,62})$")
SCOPE_REQUIRED = ("scope_id", "version", "valid_from", "roles",
                  "content_classes", "recoverability", "acceptance_policy_ref")

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


def _check_doc_seal(v, doc):
    """LINT-DISC-01/02: doc_cose_b64 is a COSE_Sign1 in the alg allowlist whose
    payload equals the deterministic-CBOR encoding of the document (minus
    doc_cose_b64)."""
    b64 = doc.get("doc_cose_b64")
    if not _b64_ok(b64):
        v.add("LINT-DISC-01", "doc_cose_b64 is not valid Base64")
        return
    if not _HAVE_CBOR:
        return
    try:
        cose = cbor2.loads(base64.b64decode(b64))
    except Exception:
        v.add("LINT-DISC-01", "doc_cose_b64 does not decode to CBOR")
        return
    if not (isinstance(cose, list) and len(cose) == 4):
        v.add("LINT-DISC-01", "doc_cose_b64 is not a 4-element COSE_Sign1 array")
        return
    try:
        ph = cbor2.loads(cose[0]) if cose[0] else {}
        alg = ph.get(1) if isinstance(ph, dict) else None
    except Exception:
        alg = None
    if alg not in COSE_ALG_ALLOWLIST:
        v.add("LINT-DISC-02", f"doc_cose_b64 COSE alg {alg!r} not in the allowlist")
    payload = cose[2]
    if not isinstance(payload, (bytes, bytearray)):
        # Parity with evidence_lint LINT-PKG-06: a detached / non-byte payload
        # means the seal does not embed the document, so the binding is
        # unverifiable. Do not silently skip it (M2).
        v.add("LINT-DISC-07", "doc_cose_b64 COSE payload is detached (not embedded)")
        return
    expected = dcbor({k: val for k, val in doc.items() if k != "doc_cose_b64"})
    if bytes(payload) != expected:
        v.add("LINT-DISC-01",
              "doc_cose_b64 payload does not match the canonical document (stale/tampered)")


def _check_uid(v, doc):
    uid = doc.get("uid")
    if not (isinstance(uid, str) and UID_RE.match(uid)):
        v.add("LINT-DISC-03", f"uid is not a well-formed EU UID: {uid!r}")
    elif not id_grammar.uid_valid_checksum(uid):  # X-02: enforce the RS check symbols
        v.add("LINT-DISC-03", f"uid {uid!r} has an invalid check symbol (C1C2) — "
              "the GF(2^5) Reed-Solomon check does not verify")


def _check_scope_map(v, doc):
    """Confidentiality-scope semantics (spec §8.3a). The scope_map is OPTIONAL;
    when present:
    - each descriptor complete; recoverability strict|records, no default (08, D2);
    - any fallback == 'default' (09, D4);
    - scope_id unique within scopes (10);
    - each content_class routes to at most one scope — deterministic (11);
    - acceptance_policy_ref references an existing acceptance_policy key (12);
    - every scope role exists in the organisation-level roles (13);
    - scope_id 'default' is RESERVED and MUST NOT be declared (14);
    - content-class registry discipline: an unprefixed class must be a
      STANDARD registry class; private classes carry the x- prefix (16, Q5)."""
    sm = doc.get("scope_map")
    if sm is None:
        return  # default-scope only (backwards compatible)
    # LINT-DISC-19 (F14, §8.3a): a scoped entity MUST advertise a member-
    # enumeration surface (BW-ORG member_endpoint → edd-resolver GET
    # /uid/{uid}/members) so a counterparty can resolve the scope-eligible
    # member/device set and a verifier can map group leaves to members and roles.
    if not doc.get("member_endpoint"):
        v.add("LINT-DISC-19",
              "BW-ORG publishes a scope_map but no member_endpoint — the scope's "
              "eligible member/device set and roster leaves are unresolvable "
              "cross-provider (§8.3a, F14)")
    scopes = sm.get("scopes") if isinstance(sm, dict) else None
    if not isinstance(scopes, list) or not scopes:
        v.add("LINT-DISC-08", "scope_map.scopes must be a non-empty list")
        return
    org_roles = set(doc.get("roles") or [])
    policy_keys = set((doc.get("acceptance_policy") or {}).keys())
    seen_ids, seen_classes = set(), {}
    for i, sc in enumerate(scopes):
        if not isinstance(sc, dict):
            v.add("LINT-DISC-08", f"scope_map.scopes[{i}] is not an object")
            continue
        for f in SCOPE_REQUIRED:
            if f not in sc:
                v.add("LINT-DISC-08", f"scope_map.scopes[{i}] missing {f}")
        if sc.get("recoverability") not in RECOVERABILITY:
            v.add("LINT-DISC-08",
                  f"scope_map.scopes[{i}] recoverability {sc.get('recoverability')!r} "
                  "not in {strict, records}")
        # LINT-DISC-21 (F16, §8.3a): the records leaf is declared per scope via
        # records_role — REQUIRED where recoverability=records, FORBIDDEN where
        # strict; a declared org role that is NOT one of the scope's own roles
        # (the records function recovers, it is not an acceptance party, SCOPE-8).
        rec = sc.get("recoverability")
        rr = sc.get("records_role")
        if rec == "records":
            if not rr:
                v.add("LINT-DISC-21",
                      f"scope_map.scopes[{i}] recoverability=records requires a "
                      "records_role naming the records leaf (§8.3a, F16)")
            else:
                if rr not in org_roles:
                    v.add("LINT-DISC-21",
                          f"scope_map.scopes[{i}] records_role {rr!r} is not an "
                          "organisation-level role")
                if rr in (sc.get("roles") or []):
                    v.add("LINT-DISC-21",
                          f"scope_map.scopes[{i}] records_role {rr!r} is also a scope "
                          "role — the records function recovers, it is not an "
                          "acceptance party (§8.3a, SCOPE-8)")
        elif rec == "strict" and rr is not None:
            v.add("LINT-DISC-21",
                  f"scope_map.scopes[{i}] recoverability=strict must not declare a "
                  "records_role (a strict scope has no records leaf, §8.3a)")
        if "fallback" in sc and sc.get("fallback") != "default":
            v.add("LINT-DISC-09",
                  f"scope_map.scopes[{i}] fallback must be 'default' when present")
        sid = sc.get("scope_id")
        if sid == "default":
            v.add("LINT-DISC-14",
                  f"scope_map.scopes[{i}] scope_id 'default' is reserved (implicit scope)")
        if sid in seen_ids:
            v.add("LINT-DISC-10", f"scope_map has a duplicate scope_id {sid!r}")
        elif sid is not None:
            seen_ids.add(sid)
        for cc in sc.get("content_classes") or []:
            if not (isinstance(cc, str) and CONTENT_CLASS_RE.match(cc)):
                v.add("LINT-DISC-16",
                      f"scope_map.scopes[{i}] content_class {cc!r} is not "
                      "lowercase-kebab (optionally x- prefixed)")
            elif not cc.startswith("x-") and cc not in STANDARD_CONTENT_CLASSES:
                v.add("LINT-DISC-16",
                      f"scope_map.scopes[{i}] content_class {cc!r} is neither a "
                      "standard registry class nor x- prefixed (private classes "
                      "MUST carry the x- namespace prefix)")
            if cc in seen_classes and seen_classes[cc] != sid:
                v.add("LINT-DISC-11",
                      f"content_class {cc!r} maps to more than one scope "
                      f"({seen_classes[cc]!r} and {sid!r})")
            else:
                seen_classes.setdefault(cc, sid)
        apr = sc.get("acceptance_policy_ref")
        if apr is not None and apr not in policy_keys:
            v.add("LINT-DISC-12",
                  f"scope_map.scopes[{i}] acceptance_policy_ref {apr!r} is not an "
                  "acceptance_policy key")
        for r in sc.get("roles") or []:
            if r not in org_roles:
                v.add("LINT-DISC-13",
                      f"scope_map.scopes[{i}] role {r!r} is not an organisation-level role")
    if "fallback" in sm and sm.get("fallback") != "default":
        v.add("LINT-DISC-09", "scope_map.fallback must be 'default' when present")


def lint_med(v, d):
    _check_uid(v, d)
    _check_doc_seal(v, d)
    mls = d.get("mls") or {}
    if not isinstance(mls.get("cipher_suites"), list) or not mls["cipher_suites"]:
        v.add("LINT-DISC-05", "BW-MED mls.cipher_suites must be a non-empty list")
    # SBM-ADR-0015 (BW-MED 2.2): the routing and KeyPackage endpoints are the
    # RDP's, under `rdp`, not under `mls` — `mls` describes the group's
    # cryptographic parameters, not who serves them. The `msp` field is
    # withdrawn with the role; its content is `rdp.delivery_service`.
    rdp = d.get("rdp") or {}
    for url_field in ("delivery_service", "keypackage_url", "ds_url"):
        u = rdp.get(url_field)
        if not (isinstance(u, str) and u.startswith("https://")):
            v.add("LINT-DISC-05", f"BW-MED rdp.{url_field} must be an https URL")
    if "msp" in d:
        v.add("LINT-DISC-05",
              "BW-MED carries `msp`, withdrawn in 2.2: there is one provider role "
              "and the Delivery Service is the RDP's (SBM-ADR-0015)")
    if "ds_receipt_keys" in d:
        v.add("LINT-DISC-05",
              "BW-MED carries `ds_receipt_keys`, withdrawn in 2.2: a provider's "
              "receipt key is published in its own BW-PROVIDER descriptor, and the "
              "BW-MED path is deleted rather than kept as a fallback "
              "(SBM-ADR-0015)")
    if not d.get("expires_at"):
        v.add("LINT-DISC-05", "BW-MED must declare expires_at (freshness bound)")
    ss = mls.get("scopes_supported")
    if ss is not None and not isinstance(ss, bool):
        v.add("LINT-DISC-05", "BW-MED mls.scopes_supported must be a boolean when present")


def lint_org(v, d, now=None):
    _check_uid(v, d)
    _check_doc_seal(v, d)
    # Acceptance-policy versioning (spec §8.3): signed + versioned.
    if not d.get("policy_version"):
        v.add("LINT-DISC-04", "BW-ORG must carry policy_version")
    if not d.get("valid_from"):
        v.add("LINT-DISC-04", "BW-ORG must carry valid_from")
    ap = d.get("acceptance_policy")
    if not isinstance(ap, dict) or not ap:
        v.add("LINT-DISC-04", "BW-ORG acceptance_policy must be a non-empty object")
        # LINT-DISC-24 (X-12, BW-ORG 2.4): no policy map at all also means no
        # `default` key — an entity-addressed default-scope message would
        # select nothing. Fail-closed.
        v.add("LINT-DISC-24",
              "BW-ORG carries no acceptance_policy — the REQUIRED reserved "
              "'default' key is missing, so entity-addressed default-scope "
              "messages select no policy (X-12, umbrella §8.3)")
    else:
        # LINT-DISC-24 (X-12, BW-ORG 2.4): the reserved `default` key is
        # REQUIRED — it is the deterministic selection for entity-addressed
        # default-scope messages (umbrella §8.3); without it that case
        # selects no policy. Its eligible set is the entire active membership
        # (satisfiability is bundle-level, LINT-BND-08/09).
        if "default" not in ap:
            v.add("LINT-DISC-24",
                  "BW-ORG acceptance_policy has no 'default' key — "
                  "entity-addressed default-scope messages select no policy "
                  "(X-12, umbrella §8.3)")
        for role, pol in ap.items():
            if not (isinstance(pol, str) and POLICY_RE.match(pol)):
                v.add("LINT-DISC-04",
                      f"BW-ORG acceptance_policy[{role!r}] is not a valid policy: {pol!r}")
    _check_scope_map(v, d)
    _check_delivery_grades(v, d)
    _check_in_force(v, d, now)


def _check_in_force(v, d, now=None):
    """LINT-DISC-28 (DR-04, R2-M6): a BW-ORG served AS CURRENT must already be
    IN FORCE. R2-M6 settled the question DR-04 raised — pre-publication of a
    future policy at the current-document endpoint is PROHIBITED, rather than
    permitted with an `as_of` retrieval API. A relying party fetching the
    current document has no way to know a version is not yet effective, and
    would evaluate an act under rules that do not yet bind. Publish the future
    version when it takes force; announce it out of band.

    Parametric on the verification `now`, following the LINT-DISC-25 pattern:
    the check is about what a party retrieving the document TODAY may rely on,
    so it is meaningless without a retrieval time, and an archived version
    legitimately has a valid_from in the past of its own service window. Where
    `now` is absent the static shape checks still run. Fail-closed on an
    unparsable instant."""
    if now is None:
        return
    from lint_cli import instant as _inst, TimestampError as _TSErr
    vf = d.get("valid_from")
    if not vf:
        return                                    # LINT-DISC-04 already reports
    try:
        if _inst(vf, field="valid_from") > _inst(now, field="now"):
            v.add("LINT-DISC-28",
                  f"BW-ORG served as current takes force at {vf}, which is "
                  f"AFTER the retrieval time {now}: publishing a not-yet-"
                  "effective policy as the current document lets a relying "
                  "party evaluate an act under rules that do not yet bind "
                  "(DR-04/R2-M6 — pre-publication as current is prohibited)")
    except _TSErr as e:
        v.add("LINT-DISC-28", f"BW-ORG in-force check cannot be evaluated: {e}")


def _check_device_suites(v, doc, dev, i):
    """LINT-DISC-29 (DR-08, BW-MEMBER 2.2): every addressable device publishes
    the cipher suites its KeyPackages are served for, and that list MUST
    contain the mandatory baseline.

    The normative selector has always required per-device capability sets, but
    nothing published them: the tests supplied synthetic arrays, so a creator
    could not execute the algorithm from discovery at all. Requiring the
    baseline is what preserves the invariant the selector rests on — "the
    baseline is always in the intersection, so a selection always exists".
    Without it a single device could make every group unformable, which is
    indistinguishable from a denial of service."""
    from mls_suite import BASELINE
    suites = dev.get("cipher_suites")
    did = dev.get("device_id", f"#{i}")
    if not suites:
        v.add("LINT-DISC-29",
              f"device {did!r} publishes no cipher_suites — the suite selector "
              "cannot be executed for it from discovery (DR-08, BW-MEMBER 2.2)")
        return
    if BASELINE not in suites:
        v.add("LINT-DISC-29",
              f"device {did!r} cipher_suites omits the REQUIRED baseline "
              f"{BASELINE} — every implementation supports it, and the "
              "selector's guarantee that a selection always exists depends on "
              "it being in every intersection")
    if len(set(suites)) != len(suites):
        v.add("LINT-DISC-29",
              f"device {did!r} cipher_suites repeats a suite — the set is what "
              "the intersection is taken over")


def _check_device_floor(v, doc, dev, i):
    """LINT-DISC-30 (DR-15/R2-M5): a device's published floor may only RAISE
    the mandatory one.

    The mandatory `mls-suite-floor/v1` binds every conforming deployment, so
    this field is a raise and nothing else. A weaker value is not a weaker
    policy the federation honours — it is non-conformant, and accepting it
    would reintroduce exactly what R2-M5 removed: a participant choosing its
    own protection level, unverifiably. The raise must also be a suite the
    device actually publishes, since demanding one it cannot use makes every
    group unformable, which is a denial of service wearing a policy's
    clothes."""
    from mls_suite import FLOOR, FLOOR_ID, PREFERENCE, PREFERENCE_ID
    raised = dev.get("min_cipher_suite")
    if not raised:
        return
    did = dev.get("device_id", f"#{i}")
    rank = {s: n for n, s in enumerate(PREFERENCE)}     # 0 = strongest
    if raised not in rank:
        v.add("LINT-DISC-30",
              f"device {did!r} min_cipher_suite {raised!r} is not in "
              f"{PREFERENCE_ID} — an unordered floor cannot be compared")
        return
    if rank[raised] > rank[FLOOR]:
        v.add("LINT-DISC-30",
              f"device {did!r} min_cipher_suite {raised!r} is WEAKER than the "
              f"mandatory {FLOOR_ID} ({FLOOR}) — the published floor may only "
              "RAISE the mandatory one")
    if raised not in (dev.get("cipher_suites") or []):
        v.add("LINT-DISC-30",
              f"device {did!r} demands {raised!r} but does not publish it in "
              "cipher_suites — every group would be unformable for this device")


def _check_leaf_binding(v, doc, dev, i):
    """LINT-DISC-23 (F-04): the device's signed mls_leaf_binding. (i) the RFC
    9420 rule that the credential key IS the LeafNode signature key —
    signature_key_hash == SHA-256(leaf_sig_pubkey_b64); (ii) the binding COSE
    payload binds exactly THIS device's (uid, mid, device_id, leaf key); and
    (iii, demo/pilot) the binding signature verifies against the entity seal key
    (kid 'entity-admin'). OPTIONAL in pilot: absent => no check. The production
    certificate profile / QSealC-chain validation is a production-verifier duty."""
    b = dev.get("mls_leaf_binding")
    if not isinstance(b, dict):
        return
    lpk = b.get("leaf_sig_pubkey_b64")
    ref = dev.get("mls_leaf_node_ref") or {}
    try:
        computed = hashlib.sha256(base64.b64decode(lpk)).hexdigest()
    except Exception:
        v.add("LINT-DISC-23",
              f"BW-MEMBER devices[{i}].mls_leaf_binding.leaf_sig_pubkey_b64 is "
              "not base64-decodable")
        return
    if ref.get("signature_key_hash") != computed:
        v.add("LINT-DISC-23",
              f"BW-MEMBER devices[{i}]: mls_leaf_node_ref.signature_key_hash != "
              "SHA-256(mls_leaf_binding.leaf_sig_pubkey_b64) — the MLS LeafNode "
              "signature key is not the bound credential key (RFC 9420)")
    if not _HAVE_CBOR:
        return
    import cbor2
    from lint_cli import dcbor
    try:
        cose = cbor2.loads(base64.b64decode(b.get("binding_cose_b64", "")))
        protected, _u, payload, sig = cose
        ph = cbor2.loads(protected) if protected else {}
        kid = ph.get(4) if isinstance(ph, dict) else None
        kid = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    except Exception:
        v.add("LINT-DISC-23",
              f"BW-MEMBER devices[{i}].mls_leaf_binding.binding_cose_b64 is not a "
              "decodable COSE_Sign1")
        return
    expected = dcbor({"uid": doc.get("uid"), "mid": doc.get("mid"),
                      "device_id": dev.get("device_id"),
                      "leaf_sig_pubkey_b64": lpk})
    if payload != expected:
        v.add("LINT-DISC-23",
              f"BW-MEMBER devices[{i}] mls_leaf_binding does not bind this "
              "device's (uid, mid, device_id, leaf key) — content mismatch")
        return
    # (iii) demo/pilot signature verification against the entity seal key.
    if kid == EXPECTED_DISCOVERY_KID:
        try:
            from nacl.signing import VerifyKey
            to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
            # The ENTITY key, not the document signer: a leaf binding is the
            # entity authorising a device (F-04). It stays a constant here
            # because this branch has already established the signer IS the
            # entity — `_expected_demo_signer` answers a different question.
            VerifyKey(base64.b64decode(ENTITY_ADMIN_PUBKEY_B64)).verify(to_sign, sig)
        except ImportError:  # pragma: no cover — pynacl preflighted in the canonical env
            pass
        except Exception:
            v.add("LINT-DISC-23",
                  f"BW-MEMBER devices[{i}] mls_leaf_binding signature does not "
                  "verify against the entity seal key — the binding was not "
                  "authorised by the entity")


def lint_member(v, d):
    # LINT-DISC-27 (X-32): one confirmation key per device — two devices of
    # this member sharing a key collapse device-bound assurance and make
    # attribution ambiguous. Cross-member duplicates are bundle-level
    # (LINT-BND-32). Fail-closed.
    _seen_ck = {}
    for dev in d.get("devices") or []:
        pk = ((dev.get("confirmation_key") or {}).get("public_key_b64"))
        if pk:
            if pk in _seen_ck:
                v.add("LINT-DISC-27",
                      f"devices {_seen_ck[pk]!r} and {dev.get('device_id')!r} "
                      "publish the SAME confirmation_key — one key per device "
                      "(X-32)")
            _seen_ck[pk] = dev.get("device_id")
    _check_uid(v, d)
    _check_doc_seal(v, d)
    if not (isinstance(d.get("mid"), str) and MID_RE.match(d["mid"])):
        v.add("LINT-DISC-06", f"BW-MEMBER mid is not a well-formed MID: {d.get('mid')!r}")
    elif not id_grammar.mid_valid_checksum(d["mid"]):  # X-02: enforce the RS check symbol
        v.add("LINT-DISC-06", f"BW-MEMBER mid {d['mid']!r} has an invalid check symbol "
              "— the GF(2^5) Reed-Solomon check does not verify")
    devices = d.get("devices")
    if not isinstance(devices, list) or not devices:
        v.add("LINT-DISC-06", "BW-MEMBER must list at least one device")
    else:
        for i, dev in enumerate(devices):
            if "mls_leaf_node_ref" not in dev:
                v.add("LINT-DISC-06", f"BW-MEMBER devices[{i}] missing mls_leaf_node_ref")
            # LINT-DISC-22 (finding D, twenty-second review): an ack/sign-capable
            # device MUST publish a well-formed confirmation_key anchor — the key
            # against which its wallet advanced electronic signature on a recipient
            # confirmation is resolved and verified (TS clause 6 INTF-1(a)). The
            # mls_leaf_node_ref carries only a HASH of the LEAF key, which can
            # neither verify a signature nor is it the confirmation key. Schema
            # if/then enforces PRESENCE for ack/sign devices; this checks the anchor
            # is usable: the public key decodes and the alg is a permitted COSE alg.
            caps = dev.get("capabilities") or []
            if "ack" in caps or "sign" in caps:
                ck = dev.get("confirmation_key")
                if not isinstance(ck, dict):
                    v.add("LINT-DISC-22",
                          f"BW-MEMBER devices[{i}] is ack/sign-capable but has no "
                          "confirmation_key anchor (finding D — nowhere to resolve "
                          "its wallet confirmation signature)")
                else:
                    pk = ck.get("public_key_b64")
                    if not (isinstance(pk, str) and _b64_ok(pk)):
                        v.add("LINT-DISC-22",
                              f"BW-MEMBER devices[{i}].confirmation_key.public_key_b64 "
                              "is not base64-decodable — a verifier cannot resolve a "
                              "usable key")
                    if ck.get("alg") not in ("EdDSA", "ES256", "ES384"):
                        v.add("LINT-DISC-22",
                              f"BW-MEMBER devices[{i}].confirmation_key.alg "
                              f"{ck.get('alg')!r} is not a permitted COSE algorithm")
            _check_leaf_binding(v, d, dev, i)
            _check_device_suites(v, d, dev, i)
            _check_device_floor(v, d, dev, i)
    # LINT-DISC-20 (A2, Annex R): a system member acts under a scoped mandate, so
    # a counterparty can check its authority before treating its messages as
    # binding — a member_type=system binding MUST carry a mandate_ref.
    if d.get("member_type") == "system" and not d.get("mandate_ref"):
        v.add("LINT-DISC-20",
              "BW-MEMBER member_type=system without a mandate_ref — a system "
              "member's scoped authority must be published (Annex R, A2)")


EXPECTED_DISCOVERY_KID = "entity-admin"
DEMO_KIDS = {"rdp", "entity-admin", "wallet", "demo"}
DEMO_URL_MARKERS = ("example.eu", "example.fr", "example.com", "example.org")


def _production_confirmation_keys(v, doc):
    """LINT-DISC-31 (R3-05, --profile production): in production, a device's
    confirmation-key anchor MUST carry an x5chain, and that certificate MUST
    hold the SAME public key.

    The I-D required the equality and the prose required the chain; the schema
    required neither, and production lint checked only that SOME x5chain
    identity was present on the document seal. A production deployment could
    therefore publish a bare asserted raw key — the advanced-signature identity
    claim rested on an assertion.

    SCOPE, stated because it would otherwise be over-read: this proves the
    certificate carries this key. It does NOT validate the chain to a trust
    anchor, the QSealC qualification or the Trusted-List status — that is the
    external production trust policy (F-04, X-01), which stays Partial.
    """
    from lint_cli import check_certificate_binds_key, CertificateBindingError
    for i, dev in enumerate(doc.get("devices") or []):
        did = dev.get("device_id", f"#{i}")
        ck = dev.get("confirmation_key") or {}
        if not ck:
            continue
        chain = ck.get("x5chain")
        if not chain:
            v.add("LINT-DISC-31",
                  f"device {did!r} publishes a confirmation_key with no x5chain "
                  "— in the production profile the key must be authorised by a "
                  "certificate, not asserted")
            continue
        try:
            check_certificate_binds_key(chain, ck.get("alg"),
                                        ck.get("public_key_b64"))
        except CertificateBindingError as e:
            v.add("LINT-DISC-31",
                  f"device {did!r} confirmation_key: {e}")


def _production_check(v, doc):
    """LINT-DISC-P-01/02/03 (--profile production), mirroring evidence LINT-PROD:
    the discovery seal MUST embed a verifier-resolvable QSealC identity (x5chain/
    x5t, P-01); MUST NOT be attributed to the RDP evidence signer — discovery
    documents are entity-published (P-02); and MUST NOT carry demo COSE kids or
    demo/example URLs (P-03). STRUCTURAL precheck, NOT legal qualification
    validation: it does not verify the QSealC chain, SCD certification, Trusted
    List status, or the entity's authority."""
    b64 = doc.get("doc_cose_b64")
    if not _HAVE_CBOR or not _b64_ok(b64):
        return
    try:
        cose = cbor2.loads(base64.b64decode(b64))
        ph = cbor2.loads(cose[0]) if cose[0] else {}
    except Exception:
        return
    if not (isinstance(ph, dict) and (33 in ph or 34 in ph)):  # x5chain / x5t
        v.add("LINT-DISC-P-01",
              "production discovery seal must embed a verifier-resolvable QSealC "
              "identity (COSE x5chain/x5t)")
    kid = ph.get(4) if isinstance(ph, dict) else None
    kid_s = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    if kid_s == "rdp":
        v.add("LINT-DISC-P-02",
              "discovery document sealed by the RDP evidence signer; discovery "
              "documents are entity-published (signer-type mismatch)")
    elif kid_s in DEMO_KIDS:
        v.add("LINT-DISC-P-03", f"demo COSE kid {kid_s!r} in production discovery document")
    blob = json.dumps(doc)
    for m in DEMO_URL_MARKERS:
        if m in blob:
            v.add("LINT-DISC-P-03", f"demo/example URL ({m}) in production discovery document")
            break


ENTITY_ADMIN_PUBKEY_B64 = "FmS2pIFL/WZQpTPR0ppF3jYkqzPf/TRBq1aLTHRZg/o="  # demo only


def _expected_demo_signer(doc):
    """(kid, public key) the demo seal of THIS document type must carry.

    Batch A / A3: this was one constant, `EXPECTED_DISCOVERY_KID`, because
    every discovery document was an ENTITY's and the entity's
    wallet-administration function signed all of them. A provider descriptor is
    not an entity document — it is the provider speaking for itself, sealed by
    a key the membership register pins to that participant — so the expected
    signer became a function of the type rather than a property of the class.

    Keeping the constant and exempting the new type would have said "every
    discovery document is entity-signed, except the ones that are not", which
    is the shape of a rule that has stopped being one.
    """
    import mock_rdp as _m
    if doc.get("type") == "BW-PROVIDER-v1":
        pid = (doc.get("participant_id") or "").rsplit(":", 1)[-1]
        kid = doc.get("kid")
        return kid, _m.demo_public_key_b64(f"{pid}-descriptor-demo")
    return EXPECTED_DISCOVERY_KID, ENTITY_ADMIN_PUBKEY_B64


def _check_demo_signer(v, doc):
    """LINT-DISC-15 (--verify-demo): the discovery seal's COSE kid must match the
    normative signer FOR THIS DOCUMENT TYPE — an entity document is sealed by the
    entity's wallet-administration function ('entity-admin'), NOT the RDP
    evidence signer ('rdp') (N4); a provider descriptor is sealed by the
    participant itself (A3) — and the Ed25519 signature must verify against that
    signer's published DEMO key (real deployments verify against the
    Trusted-List trust material)."""
    expected_kid, expected_pub = _expected_demo_signer(doc)
    b64 = doc.get("doc_cose_b64")
    if not _HAVE_CBOR or not _b64_ok(b64):
        return
    try:
        cose = cbor2.loads(base64.b64decode(b64))
        ph = cbor2.loads(cose[0]) if cose[0] else {}
        kid = ph.get(4) if isinstance(ph, dict) else None
    except Exception:
        return
    kid_s = kid.decode("utf-8", "replace") if isinstance(kid, (bytes, bytearray)) else kid
    if kid_s != expected_kid:
        v.add("LINT-DISC-15",
              f"discovery doc sealed with kid {kid_s!r}, expected "
              f"{expected_kid!r} (the normative signer for {doc.get('type')!r})")
    try:
        from nacl.signing import VerifyKey
        protected, _u, payload, sig = cose
        to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
        VerifyKey(base64.b64decode(expected_pub)).verify(to_sign, sig)
    except ImportError:  # pragma: no cover
        pass  # pynacl absent; --verify-demo signature check is best-effort
    except Exception:
        v.add("LINT-DISC-15",
              f"discovery seal signature does not verify against the "
              f"{expected_kid!r} demo key")


DELIVERY_GRADES = {"availability", "verification", "acceptance"}


def _check_delivery_grades(v, doc):
    """V0 (thirteenth review, spec §8.3b): the optional per-content-class
    delivery-grade declaration.
    - LINT-DISC-17: the map is well-formed — content-class keys, grade values.
    - LINT-DISC-18: a declared verification/acceptance grade is coherent with
      the acceptance policy of the scope its class routes to (quorum/all =>
      acceptance; any-one/device-class => verification). availability composes
      with any scope (the scope bounds who decrypts; the grade sets when
      delivery operates), and default-scope classes have no static policy
      binding — both are checked at issuance by the RDP instead."""
    dg = doc.get("delivery_grades")
    if dg is None:
        return
    if not isinstance(dg, dict) or not dg:
        v.add("LINT-DISC-17", "delivery_grades must be a non-empty object")
        return
    for cls, grade in dg.items():
        if not isinstance(cls, str) or not CONTENT_CLASS_RE.match(cls):
            v.add("LINT-DISC-17",
                  f"delivery_grades key {cls!r} is not a well-formed content class")
        if grade not in DELIVERY_GRADES:
            v.add("LINT-DISC-17",
                  f"delivery_grades[{cls!r}] = {grade!r} not in {sorted(DELIVERY_GRADES)}")
    scopes = (doc.get("scope_map") or {}).get("scopes") or []
    policy = doc.get("acceptance_policy") or {}
    for sc in scopes:
        pol = policy.get(sc.get("acceptance_policy_ref"))
        if not isinstance(pol, str):
            continue
        implied = "acceptance" if (pol == "all" or pol.startswith("quorum:")) else "verification"
        for cls in (sc.get("content_classes") or []):
            g = dg.get(cls)
            if g in ("verification", "acceptance") and g != implied:
                v.add("LINT-DISC-18",
                      f"content class {cls!r} declared {g}-grade but routes to scope "
                      f"{sc.get('scope_id')!r} whose policy {pol!r} implies {implied}-grade (§8.3b)")


def lint(doc, verify_demo=False, profile="pilot", trust_store=None, directory=None,
         now=None, federation_register=None):
    v = Violations()
    if isinstance(doc, dict) and "sm_artifact_b64" in doc and "projection" in doc:
        # LINT-PKG-11 (N1): the wire projection MUST equal decode(payload) exactly.
        for rule, msg in projection_equals_decode(doc):
            v.add(rule, msg)
        # LINT-PKG-12 (N2): the decoded body MUST validate against its
        # authoritative JSON Schema — the CDDL is only the structural outer bound.
        for rule, msg in validate_body(doc["projection"]):
            v.add(rule, msg)
        doc = reconstruct(doc)
    elif isinstance(doc, dict) and "doc_cose_b64" in doc:
        # R11-09: the FLAT form — the body beside its `doc_cose_b64` — is
        # accepted as well, and the authoritative Schema ran only for the
        # wrapper. A descriptor without `endpoints`, genuinely re-sealed,
        # passed `--verify-demo` with zero findings in this form while the
        # identical signed body got LINT-PKG-12 in the other; so did a
        # BW-MEMBER without `status`. Every accepted form now normalises to
        # the body and validates it — the verdict must not depend on wrapping.
        for rule, msg in validate_body(flat_projection(doc)):
            v.add(rule, msg)
    for p, reason in find_unsafe_numbers(doc):
        # Parity with evidence_lint LINT-PKG-09 (M1/J0+: I-JSON safe integers).
        v.add("LINT-PKG-09", f"{reason} at {p}")
    # Parity with evidence_lint LINT-HASH-01: a published ORG document pins the
    # acceptance policy every SE will cite, so a hash_mode outside the profile
    # is refused at the source as well as in the evidence that references it.
    for rule, msg in hash_mode_violations(doc):
        v.add(rule, msg)
    t = doc.get("type")
    if t == "BW-MED-v1":
        lint_med(v, doc)
    elif t == "BW-ORG-v1":
        lint_org(v, doc, now=now)
    elif t == "BW-MEMBER-v1":
        lint_member(v, doc)
    elif t == "STATUS-v1":
        lint_status(v, doc, directory=directory, now=now)
    elif t == "ROSTER-v1":
        lint_roster(v, doc)
    elif t == "BW-PROVIDER-v1":
        lint_provider(v, doc, now=now)
    else:
        v.add("LINT-DISC-000", f"not a discovery document: {t!r}")
        return v.items
    if verify_demo:
        _check_demo_signer(v, doc)
    if profile == "production":
        _production_check(v, doc)
        if t == "BW-MEMBER-v1":
            _production_confirmation_keys(v, doc)
    if trust_store is not None:
        for rule, msg in check_trust(doc, doc.get("doc_cose_b64"), trust_store,
                                     "discovery-publisher",
                                     # A5: an entity document is identified by
                                     # its UID; a provider descriptor by its
                                     # `participant_id`. Passing only `uid`
                                     # here left LINT-TRUST-02's identity arm
                                     # SKIPPED for descriptors — a gate
                                     # reporting on part of its own surface.
                                     identity=(doc.get("uid")
                                               or doc.get("participant_id"))):
            v.add(rule, msg)
        if directory is not None:
            # LINT-TRUST-05 (X-01): the seal key must be pinned by the directory
            # for THIS document's UID (a key authorised for another UID cannot
            # seal here). Needs the store to resolve the kid to a public key.
            for rule, msg in check_directory_pin(doc, doc.get("doc_cose_b64"),
                                                 trust_store, directory):
                v.add(rule, msg)
        if federation_register is not None and t == "BW-PROVIDER-v1":
            # R10-01: AUTHENTICATE FIRST. The register arrives as input; only
            # the anchor is configuration. Batch A consulted it as written, so
            # a register with its signature removed — or with a participant's
            # pinned keys replaced under a now-stale Federation Authority
            # signature — authorised an attacker's descriptor. Nothing below
            # sees anything but the value `authenticate_register` returns.
            register, issues = authenticate_register(
                federation_register, federation_authority_anchors(trust_store))
            for rule, msg in issues:
                v.add(rule, msg)
            if register is not None:
                # LINT-TRUST-07 (A5): the seal key must be one the MEMBERSHIP
                # REGISTER pins to this participant. Needs the store for the
                # same reason TRUST-05 does: to resolve the kid to a key.
                for rule, msg in check_register_pin(doc, doc.get("doc_cose_b64"),
                                                    trust_store, register):
                    v.add(rule, msg)
    elif federation_register is not None and t == "BW-PROVIDER-v1":
        # R10-01: a register with no store to take the anchor from is a
        # register nobody can authenticate. It used to be ignored in silence
        # here, which reads as "checked" to a caller who passed it.
        v.add("LINT-TRUST-08",
              "a membership register was supplied with no trust store, so no "
              "Federation Authority anchor is configured and the register "
              "cannot be authenticated; it was not consulted")
    return v.items


def lint_status(v, d, directory=None, now=None):
    """LINT-DISC-25 (D6, F-10/X-07): the signed short-lived status capability.
    STATIC checks always: the validity WINDOW is bounded (expires_at −
    issued_at ≤ the 5-minute suspension-propagation bound and > 0), a merged
    status carries its redirect, the replay guard is a ULID. Where a
    `directory` is supplied, the seal key must be one of the REGISTRY's own
    pinned keys (`registry_seal_keys` — the D6 anchor; an ENTITY's key, even
    a validly pinned one, cannot issue status). Where `now` is supplied
    (verification time), the assertion must be within its validity — the
    at-time freshness check is parametric because an archived assertion is
    not "invalid", it is EXPIRED FOR RELIANCE: an RDP may rely on it only
    inside the window (umbrella §5.7). Fail-closed."""
    _check_doc_seal(v, d)
    issued, expires = d.get("issued_at"), d.get("expires_at")
    if issued and expires:
        from datetime import timedelta
        from lint_cli import instant as _inst, TimestampError as _TSErr
        try:
            t0 = _inst(issued, field="issued_at")     # DR-05: the shared parser
            t1 = _inst(expires, field="expires_at")
            if t1 <= t0:
                v.add("LINT-DISC-25",
                      f"status assertion validity is empty or reversed "
                      f"({issued} .. {expires})")
            elif (t1 - t0) > timedelta(minutes=5):
                v.add("LINT-DISC-25",
                      f"status assertion validity {t1 - t0} exceeds the "
                      "5-minute suspension-propagation bound — the bound is "
                      "what makes the concealment window bounded (D6)")
            if now is not None:
                tn = _inst(now, field="now")
                if not (t0 <= tn < t1):
                    v.add("LINT-DISC-25",
                          f"status assertion is not valid at {now} "
                          f"(validity {issued} .. {expires}) — an RDP MUST "
                          "fail closed outside the window (umbrella §5.7)")
        except _TSErr:
            v.add("LINT-DISC-25", "status assertion timestamps unparseable")
    if d.get("status") == "merged" and not d.get("redirect_uid"):
        v.add("LINT-DISC-25", "merged status assertion without redirect_uid")
    if directory is not None:
        import base64 as _b64
        import hashlib as _hl
        pinned = {k.get("spki_sha256")
                  for k in (directory.get("registry_seal_keys") or [])}
        if not pinned:
            v.add("LINT-DISC-25",
                  "directory pins no registry_seal_keys — nowhere to anchor "
                  "the status capability (D6)")
            return
        ok = False
        try:
            import cbor2 as _c2
            from nacl.signing import VerifyKey
            from mock_rdp import demo_public_key_b64 as _dpk
            # Demo scope: the registry key is the demo 'edd-registry-demo'
            # key; production resolves the pinned x5t#S256 via the Trusted
            # List (production-verifier duty). Verify seal AND pin together.
            pub = _b64.b64decode(_dpk("edd-registry-demo"))
            if _hl.sha256(pub).hexdigest() in pinned:
                cose = _c2.loads(_b64.b64decode(d.get("doc_cose_b64") or ""))
                to_sign = _c2.dumps(["Signature1", cose[0], b"", cose[2]])
                VerifyKey(pub).verify(to_sign, cose[3])
                ok = True
        except Exception:
            ok = False
        if not ok:
            v.add("LINT-DISC-25",
                  "status assertion seal does not verify against any pinned "
                  "registry_seal_keys entry — only the EDD core registry "
                  "issues status (D6)")


def lint_provider(v, doc, now=None):
    """Batch A / A3 — structural rules for the provider's own descriptor.

    LINT-DISC-32  the validity window is forwards and, where a verification
                  instant is given, the descriptor is in force at it. Compared
                  as INSTANTS (R9-04): the profile closed a defect where a
                  lexically ordered window was chronologically inverted, and a
                  document carrying `asserted_at` and `expires_at` is exactly
                  where it would come back.

    LINT-DISC-33  the roles it claims are roles this version defines.

    The seal-key pin — that `kid` is one the membership register authorises
    for this participant — is a TRUST rule, not a structural one: it needs the
    register, which is an input rather than part of the document, so it does
    not live here. A5 adds it beside the rule that does the same job one level
    down, and names it there. Naming it here before it exists would put a rule
    identifier in prose that the catalogue does not carry, which is the phantom
    the catalogue gate refuses — and it refused this, correctly.
    """
    from lint_cli import instant as _inst, TimestampError as _TSErr
    # R10-03: the COMMON artefact/seal requirements, as every other discovery
    # type runs them. This handler omitted the call, and the demo-signer and
    # production-precheck helpers both return early when no seal exists — so a
    # bare, unsealed projection passed `--verify-demo --profile production`
    # with zero findings while the same bare BW-MED got LINT-DISC-01. A new
    # document type inherits the class's obligations; it does not get to
    # opt out of them by omission.
    _check_doc_seal(v, doc)
    asserted, expires = doc.get("asserted_at"), doc.get("expires_at")
    lo = hi = None
    try:
        lo = _inst(asserted, field="asserted_at")
        hi = _inst(expires, field="expires_at")
    except _TSErr as e:
        v.add("LINT-DISC-32",
              f"the descriptor's validity window cannot be parsed: {e} — an "
              "instant that cannot be read cannot bound anything")
    if lo is not None and hi is not None:
        if hi <= lo:
            v.add("LINT-DISC-32",
                  f"the descriptor is asserted at {asserted} and expires at "
                  f"{expires}, which is not forwards: it would be stale before "
                  "it was published")
        elif now is not None:
            # R10-03: BOTH bounds, and an unreadable verification instant is a
            # finding. This checked only the upper bound, so a descriptor
            # asserted in 2026 passed a verification instant in 2025 — in force
            # before it existed — and a `now` that could not be parsed was
            # swallowed, turning "check at this instant" into "do not check".
            try:
                at = _inst(now, field="now")
            except _TSErr as e:
                v.add("LINT-DISC-32",
                      f"the verification instant cannot be parsed ({e}), so the "
                      "descriptor's window cannot be applied to it — refused "
                      "rather than skipped")
            else:
                if at < lo:
                    v.add("LINT-DISC-32",
                          f"the descriptor is asserted at {asserted} and the "
                          f"verification instant is {now}: it was not in force "
                          "before it was asserted")
                elif at > hi:
                    v.add("LINT-DISC-32",
                          f"the descriptor expired at {expires} and the "
                          f"verification instant is {now}: a stale descriptor "
                          "names endpoints nobody has reaffirmed")
    unknown = [r for r in (doc.get("roles") or []) if r not in PROVIDER_ROLES]
    if unknown:
        v.add("LINT-DISC-33",
              f"the descriptor claims role(s) {unknown}; this version defines "
              f"{sorted(PROVIDER_ROLES)}. A role nobody defines is a claim no "
              "verifier can act on")


def lint_roster(v, d, member_docs=None, expected_tree_hash=None):
    """LINT-DISC-26 (F-12): the signed atomic roster snapshot. STATIC always:
    shape (schema does most; fail-closed basics re-checked). With the
    entity's sealed BW-MEMBER docs supplied (`member_docs`: mid -> the
    sealed body's dCBOR SHA-256), BOTH directions are checked — a supplied
    ACTIVE member absent from the snapshot is an OMITTED MEMBER (the
    completeness the signature attests is false), and a snapshot digest
    matching no supplied doc is a MIXED-VERSION enumeration (a stale or
    unknown document version). With `expected_tree_hash` (the ratchet-tree
    hash inside the retained GroupContext the evidence mls_state commits
    to), tree_hash must match — the snapshot chains enumeration ↔ tree ↔
    evidence. Fail-closed."""
    _check_doc_seal(v, d)
    if not d.get("members"):
        v.add("LINT-DISC-26", "roster snapshot with no members")
        return
    mids = [m.get("mid") for m in d["members"]]
    if len(set(mids)) != len(mids):
        v.add("LINT-DISC-26", "roster snapshot lists a mid twice")
    if member_docs is not None:
        snap = {m.get("mid"): m.get("member_doc_digest") for m in d["members"]}
        for mid, digest in member_docs.items():
            if mid not in snap:
                v.add("LINT-DISC-26",
                      f"active member {mid!r} is OMITTED from the snapshot — "
                      "the completeness the signature attests is false")
            elif snap[mid] != digest:
                v.add("LINT-DISC-26",
                      f"snapshot pins a different document version for {mid!r} "
                      "than the sealed BW-MEMBER supplied — a mixed-version "
                      "enumeration")
        for mid in snap:
            if mid not in member_docs:
                v.add("LINT-DISC-26",
                      f"snapshot member {mid!r} matches no supplied sealed "
                      "BW-MEMBER")
    if expected_tree_hash is not None and d.get("tree_hash") != expected_tree_hash:
        v.add("LINT-DISC-26",
              "snapshot tree_hash does not equal the ratchet-tree hash the "
              "evidence mls_state commits to — the enumeration does not chain "
              "to the evidenced epoch")


def main(argv):
    args, opts = parse_common_flags(argv)
    dev_mode = opts["dev_mode"]
    verify_demo = opts["verify_demo"]
    profile = opts["profile"]
    trust_store = opts["trust_store"]
    directory_path = opts["directory"]
    register_path = opts["federation_register"]
    now = opts["now"]
    if opts["unknown"] or not args:
        for a in opts["unknown"]:
            print(f"[ERR ] unknown flag: {a}", file=sys.stderr)
        print("usage: discovery_lint.py [--dev-mode] [--verify-demo] "
              "[--profile pilot|production] <bw-doc.json> [...]\n"
              "  --verify-demo: check the seal's signer kid matches the document type (LINT-DISC-15).\n"
              "  --profile production: structural identity prechecks (LINT-DISC-P-01..03) — NOT legal "
              "qualification validation.\n"
              "  --trust-store PATH: fail-closed demo-store verification (LINT-TRUST-01..03).\n"
              "  --federation-register PATH: check a BW-PROVIDER seal key against the "
              "keys the membership register pins to that participant (LINT-TRUST-07); "
              "requires --trust-store.\n"
              "  --now RFC3339: retrieval/verification instant for the at-time checks "
              "(LINT-DISC-25 status freshness, LINT-DISC-28 in-force).",
              file=sys.stderr)
        return 2
    if profile == "production":
        print("[notice] --profile production is a STRUCTURAL precheck, NOT legal qualification "
              "validation: it does not verify the QSealC chain, SCD certification, Trusted List "
              "status, or the entity's authority.")
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
    directory = None
    if directory_path is not None:
        if store is None:
            print("[ERROR] --directory requires --trust-store (the pin resolves "
                  "the seal kid to a key via the store).", file=sys.stderr)
            return 2
        print(f"[notice] --directory {directory_path!r}: X-01 directory-pin check "
              "(LINT-TRUST-05) — the seal key must be authorised for the "
              "document's UID. Pilot pins the raw-key spki_sha256; production "
              "pins the QSealC x5t#S256 + Trusted-List chain (production verifier).")
        try:
            directory = load_directory(directory_path)
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
    register = None
    if register_path is not None:
        if store is None:
            print("[ERROR] --federation-register requires --trust-store (the "
                  "pin resolves the seal kid to a key via the store).",
                  file=sys.stderr)
            return 2
        print(f"[notice] --federation-register {register_path!r}: the seal key "
              "of a BW-PROVIDER descriptor must be pinned to that participant "
              "by the membership register, and the register must admit the "
              "participant at the descriptor's own `asserted_at` "
              "(LINT-TRUST-07). Admission is NOT qualification (umbrella "
              "§13.1): this establishes no Trusted-List status. Nor is it "
              "permission to USE the descriptor's endpoints today: it "
              "establishes that the descriptor was authorised when it was "
              "published. Whether to exchange with the provider now is a "
              "live decision, taken at the start of the exchange against a "
              "fresh record (lint_cli.live_authorisation, R11-X3).")
        try:
            register = load_federation_register(register_path)
        except ValueError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
    if not _HAVE_CBOR and not dev_mode:
        print("[ERROR] cbor2 is not installed — the doc_cose_b64 binding check "
              "(LINT-DISC-01/02) cannot run. Install: pip install -r scripts/requirements.txt "
              "(or pass --dev-mode for a degraded, non-conformance run).", file=sys.stderr)
        return 2
    total = 0
    for f in args:
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
        if doc.get("type") not in DISCOVERY_TYPES:
            print(f"[skip] {f} (not a discovery document: {doc.get('type')!r})")
            continue
        # Pass the WRAPPER so lint() runs LINT-PKG-11 (projection ≡ decode(payload)).
        issues = lint(raw_sample, verify_demo=verify_demo, profile=profile,
                      trust_store=store, directory=directory, now=now,
                      federation_register=register)
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
