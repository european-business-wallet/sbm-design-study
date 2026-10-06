#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate the evidence samples' cryptographic packaging with real (demo)
COSE seals and DER-structured qualified-timestamp tokens, using the mock RDP's
signing primitives (deterministic under KEY_SEED=demo).

Hand-authored semantic content — ids, events, reasons, manifests, wall-clock
timestamps — is preserved; only rdp_cose_b64 / ep_cose_b64 / qualified_timestamp
are recomputed, following the the I-D (Evidence Objects and COSE Packaging) sign-then-timestamp sequencing, so that
evidence_lint's structural checks (LINT-PKG-01/02/03) run over real COSE_Sign1
and DER token structures rather than human-readable placeholders.

Run after editing a sample's content:
    python scripts/regen_samples.py
"""
import base64
import importlib.util
import json
import os
import hashlib
import pathlib
import sys
import cbor2

os.environ.setdefault("KEY_SEED", "demo")
ROOT = pathlib.Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
mock = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mock)

EVIDENCE_TYPES = {"SE-v1", "DE-v1", "NDE-v1", "RE-v1", "CE-v1", "RelayEvidence-v1", "GCM-v1"}
def _dimension(name):
    import json as _json
    return _json.loads((ROOT / "versions.json").read_text(
        encoding="utf-8"))["dimensions"][name]["value"]


def _discovery_versions():
    import json as _json
    dims = _json.loads(
        (ROOT / "versions.json").read_text(encoding="utf-8"))["dimensions"]
    return {"BW-MED-v1": dims["discovery_bw_med"]["value"],
            "BW-ORG-v1": dims["discovery_bw_org"]["value"],
            "BW-MEMBER-v1": dims["discovery_bw_member"]["value"],
            "BW-PROVIDER-v1": dims["discovery_bw_provider"]["value"],
            "STATUS-v1": dims["status_assertion"]["value"],
            "ROSTER-v1": dims["roster_snapshot"]["value"]}


DISCOVERY_VERSIONS = _discovery_versions()


# Single stamp point (spec §9.3), DERIVED from versions.json rather than typed.
# The discovery table beside it was hand-written and silently pinned BW-MEMBER
# at 2.1 through a bump (fixed in round 2); this constant is the same shape of
# defect waiting to happen, so it reads the manifest R-01 exists to be.
EVIDENCE_VERSION = _dimension("evidence")
# Discovery documents version independently; the M4 inversion (drop doc_cose_b64
# from the body -> the artefact) is a shape change, so each bumps to 2.0.
#
# DERIVED from versions.json, not restated here. This table was hand-written
# and silently pinned BW-MEMBER at 2.1 while the schema, the CDDL, the README
# and the umbrella all moved to 2.2 — the regenerator would have quietly put
# the old number back into every sample on the next reseal. R-01 exists to
# stop exactly this, so the regenerator reads the same manifest the gate does.



def _content(d):
    """The working content of a sample: the projection body if it is already an
    M4 artefact `{sm_artifact_b64, projection}`, else the dict as-is. Makes regen
    idempotent once samples are inverted."""
    if isinstance(d, dict) and "sm_artifact_b64" in d and "projection" in d:
        return d["projection"]
    return d


def _migrate_body(obj):
    """An on-disk (pre-M4) evidence dict -> the M4 BODY: drop the seal wrapper,
    stamp `version` = 2.0, and recompute any nested wallet signature over dCBOR
    (the confirmation's own advanced e-signature; the outer seal then covers a
    consistent value). Assumes the field-level fixups already ran on `obj`."""
    body = {k: v for k, v in obj.items() if k != "seal"}
    body["version"] = EVIDENCE_VERSION
    # findings 2/3 (evidence 2.1): inject the MLS-binding commitments
    # deterministically so an SE and its confirmation — which share
    # (message_id, mls_group_id, mls_epoch) — commit to the SAME values.
    if body.get("type") == "SE-v1":
        body["envelope_hash"] = mock._envelope_hash(
            body["message_id"], body["mls_group_id"], body["mls_epoch"])
        _sref = body.get("scope_ref") or {}
        body["mls_state"] = mock._mls_state(
            body["mls_group_id"], body["mls_epoch"],
            scope_id=_sref.get("scope_id", "default"),
            scope_version=_sref.get("version", "1"))
    # F-02 (2.2): the availability DE and every relay hop carry the
    # transmitted-octet commitment too. All demo messages share the demo MLS
    # session (group Zzw1S4pWq9T5n7xYbXc2dQ, epoch 3), so the derivation chains
    # with the SE's value for the same message_id automatically.
    _DEMO_GROUP, _DEMO_EPOCH = "Zzw1S4pWq9T5n7xYbXc2dQ", "3"
    if body.get("type") == "GCM-v1":
        # DR-03 (2.7): the dispute binds to the disputed OCTETS and carries the
        # recipient's attributable proof — the tuple is synced from the dispute
        # then signed under the member's per-device key (X-32).
        body["envelope_hash"] = mock._envelope_hash(
            body["message_id"], _DEMO_GROUP, _DEMO_EPOCH)
        # X-04/D5: keep the demo GCM consistent across ORG reseals — the carried
        # (disputed) commitment recomputes from its own reveal + the pinned ORG.
        pv = (body.get("acceptance_policy_ref") or {}).get("policy_version")
        r = body.get("reveal") or {}
        if pv in ORG_DIGESTS and r:
            body["grade_commitment"] = lint_cli.compute_grade_commitment(
                r["salt"], r["content_class"], ORG_DIGESTS[pv])
            apr = body.get("acceptance_policy_ref")
            apr["doc_digest"] = {"alg": "SHA-256", "hex": ORG_DIGESTS[pv],
                                 "hash_mode": "raw-sha256"}
        rc = body.get("reveal_confirmation")
        if isinstance(rc, dict):
            rc.update({"message_id": body["message_id"],
                       "envelope_hash": body["envelope_hash"],
                       "grade_commitment": body["grade_commitment"],
                       "salt": body["reveal"]["salt"],
                       "content_class": body["reveal"]["content_class"],
                       "read_at": body["read_at"],
                       "recipient_uid": body["recipient_uid"],
                       "mid": body["mid"]})
            rc["wallet_signature_b64"] = mock._wallet_sign(rc)
    if body.get("type") == "DE-v1" and body.get("delivery_grade") == "availability":
        body["envelope_hash"] = mock._envelope_hash(
            body["message_id"], _DEMO_GROUP, _DEMO_EPOCH)
    if body.get("type") == "RelayEvidence-v1":
        body["envelope_hash"] = mock._envelope_hash(
            body["message_id"], _DEMO_GROUP, _DEMO_EPOCH)
    if body.get("type") == "CE-v1":         # X-24 (2.5): observable commitments
        body["envelope_hash_before"] = mock._envelope_hash(
            body["message_id"], _DEMO_GROUP, _DEMO_EPOCH)
        if body.get("transformation") == "chunking":
            import mls_wire as _w
            body["part_envelope_hashes"] = [
                _w.envelope_hash(f"demo-part:{body['message_id']}:{i}".encode())
                for i in (1, 2)]
            body.pop("envelope_hash_after", None)
        elif body.get("transformation") == "re-packaging":
            import mls_wire as _w
            body["envelope_hash_after"] = _w.envelope_hash(
                f"demo-repack:{body['message_id']}".encode())
            body.pop("part_envelope_hashes", None)
    sc = body.get("sender_confirmation")    # X-03/D4 (2.3): re-sync + re-sign
    if isinstance(sc, dict):                # the sender-signed submission tuple
        from lint_cli import D4_COPIED_FIELDS      # one definition (R3-01)
        for f in D4_COPIED_FIELDS:
            sc[f] = body[f]
        sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    for q in (body.get("quorum") or []):    # X-05 (2.3): re-sign portable quorum proofs
        if isinstance(q, dict) and "wallet_signature_b64" in q:
            q["wallet_signature_b64"] = mock._wallet_sign(q)
    rc = body.get("refusal_confirmation")   # X-29 (2.3): re-sign the refusal proof
    if isinstance(rc, dict) and "wallet_signature_b64" in rc:
        rc["wallet_signature_b64"] = mock._wallet_sign(rc)
    for key in ("s3_attestation", "recipient_confirmation"):
        conf = body.get(key)
        if isinstance(conf, dict):
            _csref = body.get("scope_ref") or {}
            conf["mls_state"] = mock._mls_state(
                conf["mls_group_id"], conf["mls_epoch"],
                scope_id=_csref.get("scope_id", "default"),
                scope_version=_csref.get("version", "1"))
            if key == "s3_attestation":
                conf["envelope_hash"] = mock._envelope_hash(
                    conf["message_id"], conf["mls_group_id"], conf["mls_epoch"])
            if "wallet_signature_b64" in conf:   # re-sign AFTER injecting the fields
                conf["wallet_signature_b64"] = mock._wallet_sign(conf)
    return body


def _ep_artifact_from(ep):
    """Build the EP artefact from an on-disk EP: each sub-object becomes its own
    artefact (embedded as bytes in the EP body), the EP fields the outer body."""
    se_body = _migrate_body(ep["se"])
    se_art = mock.evidence_artifact(se_body)
    outcome_arts = [mock.evidence_artifact(_migrate_body(o)) for o in ep.get("outcomes", [])]
    change_bodies = [_migrate_body(c) for c in ep.get("changes") or []]
    for cb in change_bodies:                 # X-24: a CE's input commitment is
        if cb.get("type") == "CE-v1":        # ITS message's SE envelope hash
            cb["envelope_hash_before"] = se_body["envelope_hash"]
    change_arts = [mock.evidence_artifact(cb) for cb in change_bodies]
    dispute_arts = [mock.evidence_artifact(_migrate_body(d)) for d in ep.get("disputes") or []]
    ep_fields = {k: v for k, v in ep.items()
                 if k not in ("se", "outcomes", "changes", "disputes", "seal")}
    ep_fields["version"] = EVIDENCE_VERSION
    return mock.ep_artifact(ep_fields, se_art, outcome_arts, change_arts or None,
                            dispute_arts or None)


ORG_SAMPLES = ("sample-BW-ORG.json", "sample-BW-ORG-scoped.json",
               "sample-BW-ORG-de.json", "sample-BW-ORG-prev.json",
               "sample-BW-ORG-scoped-prev.json")


def _org_digests():
    """policy_version -> doc_digest hex of the ORG's authoritative bytes (M4:
    SHA-256 of dCBOR(ORG body), the COSE payload; §8.3, LINT-BND-10). Computed
    over the MIGRATED body so it matches what regen seals; reseal-invariant.

    R5-02: resolved in DEPENDENCY ORDER, predecessors first. `supersedes` is
    part of the body, so a version's digest depends on its predecessor's — and
    computing them in file order stamped every evidence object with a digest
    taken before the chain link was filled in. A chain that cannot be resolved
    is a hard error rather than a silently stale value.
    """
    bodies = {}
    for name in ORG_SAMPLES:
        org = _content(json.loads((ROOT / "samples" / name).read_text(encoding="utf-8")))
        body = {k: v for k, v in org.items() if k != "doc_cose_b64"}
        body["version"] = DISCOVERY_VERSIONS.get(org.get("type"), body.get("version"))
        bodies[org["policy_version"]] = body
    out, pending = {}, dict(bodies)
    while pending:
        ready = [pv for pv, b in pending.items()
                 if not isinstance(b.get("supersedes"), dict)
                 or b["supersedes"].get("policy_version") in out]
        if not ready:
            raise SystemExit(
                "the BW-ORG chain does not resolve — a version supersedes one "
                f"no sample publishes: {sorted(pending)}")
        for pv in ready:
            body = pending.pop(pv)
            sup = body.get("supersedes")
            if isinstance(sup, dict):
                sup["doc_digest"] = {"alg": "SHA-256", "hash_mode": "raw-sha256",
                                     "hex": out[sup["policy_version"]]}
            out[pv] = hashlib.sha256(mock._dcbor(body)).hexdigest()
    return out


ORG_DIGESTS = _org_digests()


def fix_supersedes(body):
    """R5-02/R4-U1: the predecessor's CONTENT DIGEST, recomputed.

    `supersedes.doc_digest` is what makes the chain a chain — drop a version
    and the link stops matching. A hand-written digest is one more restated
    value, and every restated value in this repository has been found stale at
    least once, so it is derived here from the predecessor actually on disk.
    A `supersedes` naming a version no sample publishes is an error, not a
    silently unresolved reference.
    """
    sup = body.get("supersedes")
    if not isinstance(sup, dict):
        return
    pv = sup.get("policy_version")
    if pv not in ORG_DIGESTS:
        raise SystemExit(
            f"BW-ORG {body.get('policy_version')!r} supersedes {pv!r}, which no "
            "sample publishes — the chain would be unverifiable")
    sup["doc_digest"] = {"alg": "SHA-256", "hash_mode": "raw-sha256",
                         "hex": ORG_DIGESTS[pv]}

sys.path.insert(0, str(ROOT / "scripts"))
import lint_cli  # noqa: E402  — the single grade-commitment implementation (X0)


def _load_reveals(name="grade-reveal.demo.json"):
    p = ROOT / "samples" / name
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    return {r["message_id"]: r for r in data.get("reveals", [])}


REVEALS = _load_reveals()
MANDATE_REVEALS = _load_reveals("mandate-reveal.demo.json")


def _relay_seals():
    """(message_id, event) -> the published relay object's seal (CF-5).

    Each relay sample is RESEALED IN MEMORY here rather than read off disk, so the
    seal we digest is exactly the one regen will write — independent of the order
    in which samples are regenerated, and correct even if a relay sample's content
    was just edited (sealing is deterministic under KEY_SEED=demo)."""
    out = {}
    for p in sorted((ROOT / "samples").glob("sample-RELAY-*.json")):
        d = _content(json.loads(p.read_text(encoding="utf-8")))
        art = mock.evidence_artifact(_migrate_body(d))
        cose = cbor2.loads(base64.b64decode(art["sm_artifact_b64"]))[0]  # [cose, qts][0]
        out[(d["message_id"], d["event"])] = base64.b64encode(cose).decode("ascii")
    return out


RELAY_SEALS = _relay_seals()


def fix_seal_digests(ep):
    """CF-5 (twenty-first review): a federated EP's per-hop relay-evidence
    reference carries the REAL digest of the referenced object's seal — SHA-256
    over the DECODED COSE bytes (lint_cli.compute_seal_digest, the single
    implementation). Runs BEFORE the EP is resealed, so the EP's own seal covers
    the correct digest. This is what makes the sample a byte-level reference an
    implementer can self-check against, rather than prose."""
    for hop in ep.get("rdp_chain", []):
        ref = hop.get("evidence")
        if not isinstance(ref, dict):
            continue
        seal = RELAY_SEALS.get((ref.get("message_id"), ref.get("event")))
        if seal:
            ref["seal_digest"] = {"alg": "SHA-256",
                                  "hex": lint_cli.compute_seal_digest(seal)}


FIXTURES = ROOT / "samples" / "fixtures" / "multipart"


def fix_mismatch_digest(obj):
    """R16-01, swept: the recipient's recomputed digest in the mismatch
    demonstration is the digest of a fixture, not sixty-four f characters.

    `sample-NDE-mismatch.json` showed a recipient that decrypted and got a
    different digest, and carried `ffff…` as that digest — a value no verifier
    can reproduce, announcing that it had been typed. It is now SHA-256 over
    `samples/fixtures/mismatch/received.txt`, the plaintext as received, so the
    demonstration is reproducible and still differs from the declared value.
    Found by the shape scan this pass added, in a sample the review did not name.
    """
    rc = obj.get("recipient_confirmation")
    if not (isinstance(rc, dict) and rc.get("result") == "mismatch"):
        return
    ph = rc.get("payload_hash")
    if not isinstance(ph, dict) or ph.get("hash_mode") != "raw-sha256":
        return
    octets = (ROOT / "samples" / "fixtures" / "mismatch" / "received.txt").read_bytes()
    ph["hex"] = hashlib.sha256(octets).hexdigest()


def fix_manifest_digests(obj):
    """R16-01: every digest in a multipart sample is the digest of bytes that
    exist in this repository.

    The manifest's part digests and the outer `payload_hash` were hand-typed.
    They passed the Schema, the CDDL, the linter and the seal — the seal covers
    whatever body it is given — so an implementer reproducing the published
    vector got a different number with every gate green, which is the one state
    a conformance suite cannot report.

    Each part is now hashed from `samples/fixtures/multipart/<filename>`, its
    `length` is that fixture's decoded-octet count, and the outer digest is
    SHA-256/512 over the deterministic-CBOR encoding of the manifest the sample
    carries — a list of maps, as the CDDL defines it. Every copy of
    `payload_hash` in the object is set from the same computation, because a
    sender confirmation that echoed a stale one would be the same defect moved
    one field along.
    """
    manifest = obj.get("manifest")
    if not isinstance(manifest, list) or not manifest:
        return
    for part in manifest:
        name = part.get("filename")
        fixture = FIXTURES / name if name else None
        if not (fixture and fixture.exists()):
            raise SystemExit(
                f"manifest part {part.get('part_id')!r} names no fixture under "
                f"{FIXTURES.relative_to(ROOT)}: a published digest must be the digest "
                "of bytes this repository holds")
        octets = fixture.read_bytes()
        part["length"] = str(len(octets))
        alg = (part.get("digest") or {}).get("alg", "SHA-256")
        part["digest"] = {"alg": alg, "hash_mode": "raw-sha256" if alg == "SHA-256" else "raw-sha512",
                          "hex": (hashlib.sha256 if alg == "SHA-256" else hashlib.sha512)(octets).hexdigest()}
    outer = obj.get("payload_hash") or {}
    if not str(outer.get("hash_mode", "")).startswith("manifest-"):
        return
    body = lint_cli.dcbor(manifest)
    alg = outer.get("alg", "SHA-256")
    hexed = (hashlib.sha256 if alg == "SHA-256" else hashlib.sha512)(body).hexdigest()
    for holder in (obj, obj.get("sender_confirmation") or {},
                   obj.get("recipient_confirmation") or {}):
        ph = holder.get("payload_hash") if isinstance(holder, dict) else None
        if isinstance(ph, dict) and str(ph.get("hash_mode", "")).startswith("manifest-"):
            ph["hex"] = hexed


def fix_mandate_commitments(obj):
    """A1 (nineteenth review): recompute mandate_commitment for an opposable
    agent SE from the published demo mandate-reveal fixture and the referenced
    ORG's signed-payload digest. Runs BEFORE resealing."""
    if isinstance(obj, dict):
        mref = obj.get("mandate_ref")
        if (isinstance(mref, dict)
                and (obj.get("auth_context") or {}).get("identity") == "system"
                and mref.get("opposable", True) is not False):
            r = MANDATE_REVEALS.get(obj.get("message_id"))
            pv = (obj.get("acceptance_policy_ref") or {}).get("policy_version")
            if r and pv in ORG_DIGESTS:
                mref["mandate_commitment"] = lint_cli.compute_mandate_commitment(
                    r["salt"], mref["id"], r["content_class"], ORG_DIGESTS[pv])
        for v in obj.values():
            fix_mandate_commitments(v)
    elif isinstance(obj, list):
        for x in obj:
            fix_mandate_commitments(x)


def fix_grade_commitments(obj):
    """X0: recompute grade_commitment for availability-grade evidence from the
    published demo reveal fixture and the referenced ORG's signed-payload
    digest — reseal-stable, exactly like fix_policy_refs. Runs BEFORE
    resealing."""
    if isinstance(obj, dict):
        if obj.get("delivery_grade") == "availability":
            r = REVEALS.get(obj.get("message_id"))
            pv = (obj.get("acceptance_policy_ref") or {}).get("policy_version")
            if r and pv in ORG_DIGESTS:
                obj["grade_commitment"] = lint_cli.compute_grade_commitment(
                    r["salt"], r["content_class"], ORG_DIGESTS[pv])
        for v in obj.values():
            fix_grade_commitments(v)
    elif isinstance(obj, list):
        for x in obj:
            fix_grade_commitments(x)


def fix_policy_refs(obj):
    """F7: every acceptance_policy_ref.doc_digest (top-level, s3_attestation,
    recipient_confirmation, EP-nested) becomes the real digest of the ORG
    version it references. Runs BEFORE resealing, so wallet signatures and
    seals cover the corrected values."""
    if isinstance(obj, dict):
        apr = obj.get("acceptance_policy_ref")
        if isinstance(apr, dict) and apr.get("policy_version") in ORG_DIGESTS:
            apr["doc_digest"] = {"alg": "SHA-256",
                                 "hex": ORG_DIGESTS[apr["policy_version"]],
                                 "hash_mode": "raw-sha256"}
        for v in obj.values():
            fix_policy_refs(v)
    elif isinstance(obj, list):
        for x in obj:
            fix_policy_refs(x)


def _inject_leaf_bindings(body):
    """F-04 (evidence-independent, BW-MEMBER 2.1): give each device a signed
    mls_leaf_binding and set its mls_leaf_node_ref.signature_key_hash to the
    SHA-256 of the bound leaf key, so the RFC 9420 leaf-key == credential-key
    rule holds and LINT-DISC-23 verifies the entity-signed binding."""
    uid, mid = body.get("uid"), body.get("mid")
    for dev in body.get("devices", []):
        did = dev.get("device_id")
        skh, binding = mock._leaf_binding(uid, mid, did)
        dev.setdefault("mls_leaf_node_ref", {})["signature_key_hash"] = skh
        dev["mls_leaf_binding"] = binding


def regen(path):
    d = _content(json.loads(path.read_text(encoding="utf-8")))
    t = d.get("type")
    if t == "EP-v1":
        fix_policy_refs(d)
        fix_grade_commitments(d)
        fix_mandate_commitments(d)
        fix_seal_digests(d)
        fix_manifest_digests(d)
        for sub in [d.get("se")] + list(d.get("outcomes") or []) + list(d.get("changes") or []):
            if isinstance(sub, dict):
                fix_manifest_digests(sub)
                fix_mismatch_digest(sub)
        art = _ep_artifact_from(d)
    elif t in EVIDENCE_TYPES:
        fix_policy_refs(d)
        fix_grade_commitments(d)
        fix_mandate_commitments(d)
        fix_manifest_digests(d)
        fix_mismatch_digest(d)
        art = mock.evidence_artifact(_migrate_body(d))
    elif t in DISCOVERY_VERSIONS:  # BW-MED-v1 / BW-ORG-v1 / BW-MEMBER-v1
        body = {k: v for k, v in d.items() if k != "doc_cose_b64"}
        body["version"] = DISCOVERY_VERSIONS.get(t, body.get("version"))
        if t == "BW-ORG-v1":
            fix_supersedes(body)          # R5-02: the chain link is derived
        if t == "BW-MEMBER-v1":
            _inject_leaf_bindings(body)   # F-04: signed device bindings (2.1)
            # X-32: one confirmation key PER DEVICE — each anchor derives from
            # (mid, device_id), so no key is shared across devices, members,
            # entities or security classes.
            for dev in body.get("devices") or []:
                if isinstance(dev.get("confirmation_key"), dict):
                    dev["confirmation_key"]["public_key_b64"] = \
                        mock.demo_public_key_b64(
                            f"wallet:{body['mid']}:{dev['device_id']}")
        if t == "ROSTER-v1":
            # F-12: the snapshot's member_doc_digests pin the EXACT sealed
            # BW-MEMBER bodies on disk, and tree_hash is the demo epoch's
            # ratchet-tree hash — re-derived so the snapshot always chains.
            import hashlib as _hl
            import mls_wire as _w
            _docs = {}
            for name in ("sample-BW-MEMBER-fr.json", "sample-BW-MEMBER-fr2.json",
                         "sample-BW-MEMBER-records.json"):
                _m = json.loads((ROOT / "samples" / name).read_text())["projection"]
                _docs[_m["mid"]] = _hl.sha256(mock._dcbor(_m)).hexdigest()
            for entry in body.get("members", []):
                if entry.get("mid") in _docs:
                    entry["member_doc_digest"] = _docs[entry["mid"]]
            body["tree_hash"] = _w.demo_tree_hash(
                body["mls_group_id"], body["mls_epoch"]).hex()
        if t == "STATUS-v1":
            # D6: the status capability is sealed by the EDD CORE REGISTRY key,
            # never an entity's (directory registry_seal_keys pin, LINT-DISC-25).
            art = mock.discovery_artifact(body, kid="edd-registry",
                                          seed="edd-registry-demo")
        elif t == "BW-PROVIDER-v1":
            # Batch A / A3: sealed by the PARTICIPANT, with the key the
            # membership register pins to it — not by an entity, and not by the
            # design authority. The descriptor is the provider speaking for
            # itself, so a key belonging to anybody else would defeat the point
            # of having one. A5 adds the rule that CHECKS the pin; it is
            # named there rather than here, because a rule identifier in
            # prose that the catalogue does not carry is a phantom.
            short = body["participant_id"].rsplit(":", 1)[1]
            art = mock.discovery_artifact(body, kid=body["kid"],
                                          seed=f"{short}-descriptor-demo")
        else:
            art = mock.discovery_artifact(body)
    else:
        return False
    # M4: the sample is the authoritative artefact + its non-authoritative projection.
    path.write_text(json.dumps(art, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


# --- Batch A: the Stage-1 federation MEMBERSHIP register ---------------------
#
# Distinct from the Stage-1 DIRECTORY above, and deliberately so: §13.1 keeps
# the four instruments apart, and Annex P's Stage-1 row named the directory the
# "minimum viable federation registry", which is the collision A6 renames away.
# This one records ADMISSION.

FEDERATION_ADMITTED_FROM = "2026-01-01T00:00:00Z"
"""Earlier than every act in the shipped samples (the earliest is a DE at
2026-04-04T09:58:41Z) and the same instant the trust store already uses as the
`rdp` entry's `not_before` — so the two demonstration instruments agree rather
than merely not colliding. A later instant would fail the positive bar for a
reason that is the fixture's, not the code's."""


def emit_stage1_federation_register():
    """Batch A / A2: the Stage-1 membership register.

    Shape per `federation-register-openapi.yaml` `MembershipRecord`, each record
    sealed INDIVIDUALLY by the FEDERATION AUTHORITY (demo kid
    'federation-authority') over the dCBOR record minus {signature, timestamp},
    with the demo QTS token over the signature — the same construction the
    Stage-1 directory uses, under a different signer.

    THE SIGNER IS THE POINT. §13.1 gives the Federation Authority and the design
    authority different rows; a demonstration that signed both with one key
    would demonstrate the opposite of the independence it claims. The
    design-authority key MUST NOT verify a membership record, and
    `tests/test_federation_stage1.py` asserts exactly that.
    """
    seed = os.environ.get("FEDERATION_AUTHORITY_SEED",
                          "federation-authority-demo")

    def _keys(kid):
        # The descriptor seal key pinned to this participant (A3 uses it).
        pub = mock.demo_public_key_b64(f"{kid}-descriptor-demo")
        return [{"kid": f"{kid}-descriptor",
                 "spki_sha256": hashlib.sha256(
                     base64.b64decode(pub)).hexdigest(),
                 "not_before": FEDERATION_ADMITTED_FROM,
                 "not_after": "2027-06-30T23:59:59Z"}]

    participants = [
        # The two providers the shipped samples actually name. Admitted for the
        # whole window, so every shipped act resolves `admitted`.
        ("urn:sbm:rdp:mockeu-001",
         [{"status": "admitted", "from": FEDERATION_ADMITTED_FROM}]),
        ("urn:sbm:rdp:mockeu-002",
         [{"status": "admitted", "from": FEDERATION_ADMITTED_FROM}]),
        # A THIRD participant, named by no shipped sample, carrying the
        # suspension the as-of vectors need. It is a third identifier rather
        # than a window carved out of one of the two above, because a window
        # that must avoid every shipped act is a window shaped to pass — and
        # the next sample added would either break the bar or force the window
        # to move again.
        ("urn:sbm:rdp:mockeu-003",
         [{"status": "admitted", "from": FEDERATION_ADMITTED_FROM,
           "until": "2026-03-01T00:00:00Z"},
          {"status": "suspended", "from": "2026-03-01T00:00:00Z",
           "until": "2026-09-01T00:00:00Z"},
          {"status": "admitted", "from": "2026-09-01T00:00:00Z"}]),
    ]
    _emit_register(participants, _keys, seed,
                   "federation.stage1.demo.json",
                   "This DEMONSTRATES the mechanism and admits nobody to "
                   "anything.")

    # A5 — the NEGATIVE register. Same authority, same construction, one
    # difference: the provider that issues the shipped SE is SUSPENDED across
    # the window every shipped act falls in. It exists because the positive bar
    # cannot prove a rule fires; a fixture that only ever passes tells you the
    # rule ran, not that it decides anything.
    #
    # The suspension is moved onto an ACTING provider rather than evidence
    # being forged for `mockeu-003`: the rule under test resolves a provider
    # against a register, and either side can carry the negative. Changing the
    # register keeps the evidence byte-identical to the positive run, so a
    # failure can only be the register — which is what the fixture is for.
    suspended = [
        ("urn:sbm:rdp:mockeu-001",
         [{"status": "admitted", "from": FEDERATION_ADMITTED_FROM,
           "until": "2026-03-01T00:00:00Z"},
          {"status": "suspended", "from": "2026-03-01T00:00:00Z",
           "until": "2026-09-01T00:00:00Z"},
          {"status": "admitted", "from": "2026-09-01T00:00:00Z"}]),
        ("urn:sbm:rdp:mockeu-002",
         [{"status": "admitted", "from": FEDERATION_ADMITTED_FROM}]),
    ]
    _emit_register(suspended, _keys, seed,
                   "federation.suspended.demo.json",
                   "NEGATIVE fixture: `mockeu-001` is SUSPENDED across "
                   "[2026-03-01, 2026-09-01), the window every shipped act "
                   "falls in, so a bundle verified against this register MUST "
                   "report LINT-TRUST-06. Never used in the green path.")


def _emit_register(participants, _keys, seed, filename, note):
    """The Stage-1 register construction, written once and called twice (A5).

    The negative fixture differs from the shipped one by its PARTICIPANT LIST
    and nothing else. Copying the sealing code to produce it would let the two
    drift, and a negative fixture sealed differently from the positive one
    proves the rule rejects a different construction rather than a different
    admission state.
    """
    records = []
    for pid, history in participants:
        short = pid.rsplit(":", 1)[1]
        rec = {
            "participant_id": pid,
            "role": "rdp",
            "status": history[-1]["status"],
            "status_history": history,
            "authorized_seal_keys": _keys(short),
            "descriptor_url":
                f"https://{short}.example.eu/.well-known/bw/provider",
            "asserted_at": "2026-09-01T00:00:00Z",
        }
        payload = mock._dcbor(rec)
        sig_b64 = base64.b64encode(mock.cose_sign(
            payload, kid="federation-authority", seed=seed)).decode("ascii")
        rec["signature"] = sig_b64
        rec["timestamp"] = mock._qts_over_cose(
            base64.b64decode(sig_b64), rec["asserted_at"])["token_b64"]
        records.append(rec)
    out = {
        "_comment": "Stage-1 federation MEMBERSHIP register (umbrella §13.1): "
                    "MembershipRecord records per federation-register-openapi.yaml, "
                    "each sealed individually by the FEDERATION AUTHORITY (demo kid "
                    "'federation-authority', key published in trust-store.demo.json) "
                    "over the deterministic-CBOR record minus {signature, timestamp}; "
                    "timestamp = demo QTS token over the signature. The signer is NOT "
                    "the design authority: §13.1 makes them distinct roles. "
                    + note +
                    " DEMO material; regenerate via regen_samples.py — never "
                    "hand-edit.",
        "records": records,
    }
    (ROOT / "samples" / filename).write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"regenerated {filename}")


def emit_stage1_registry():
    """F10: the Stage-1 registry file convention (umbrella Annex P.1.1) —
    {"records": [DirectoryRecord…]} per the EDD resolver OpenAPI, each record
    sealed INDIVIDUALLY by the pilot's design authority (demo kid
    'design-authority') over the deterministic-CBOR (dCBOR) record minus
    {signature, timestamp}, with the demo QTS token over the signature
    (seal-then-timestamp sequencing, the I-D (Evidence Objects and COSE
    Packaging))."""
    seed = os.environ.get("DESIGN_AUTHORITY_SEED", "design-authority-demo")
    entities = [
        ("EU-DE-EOID-7K3D9W0Q2M5FW0", "QTSP:MockEU:001"),
        ("EU-FR-PSBID-ZYWVTSRQPNM8M4", "PubEAA:MockFR:001"),
    ]
    records = []
    for uid, issuer in entities:
        rec = {
            "uid": uid,
            "issuer_id": issuer,
            "status": "active",
            "asserted_at": "2026-06-01T08:00:00Z",
            "med_url": f"https://rdp.example.eu/.well-known/bw/med/{uid}",
        }
        payload = mock._dcbor(rec)  # M4: the signed bytes are the dCBOR encoding
        sig_b64 = base64.b64encode(mock.cose_sign(
            payload, kid="design-authority", seed=seed)).decode("ascii")
        rec["signature"] = sig_b64
        rec["timestamp"] = mock._qts_over_cose(base64.b64decode(sig_b64), rec["asserted_at"])["token_b64"]
        records.append(rec)
    out = {
        "_comment": "Stage-1 minimum-viable-federation registry (umbrella Annex "
                    "P.1.1): DirectoryRecord records per the EDD resolver OpenAPI, "
                    "each sealed individually by the pilot's design authority "
                    "(demo kid 'design-authority', key published in "
                    "trust-store.demo.json) over the deterministic-CBOR record minus "
                    "{signature, timestamp}; timestamp = demo QTS token over the "
                    "signature. DEMO material; regenerate via regen_samples.py — "
                    "never hand-edit.",
        "records": records,
    }
    # R5-05: the retained GroupContext octets a verifier is given. GENERATED,
    # never hand-written: the bytes must hash to the `mls_state` the evidence
    # already pins (F-03), so a transcribed blob would be one more restated
    # value — and this one would fail silently, since a wrong context simply
    # reports a mismatch nobody expected.
    #
    # ONE FILE PER BUNDLE WORLD, because (mls_group_id, mls_epoch) identifies
    # exactly one GroupContext: the default and scoped samples share a group
    # and epoch while carrying different scope extensions — impossible in a
    # real MLS group, and an artefact of their being alternative presentations
    # of one entity — so a single keyed file would silently drop one of them.
    import base64 as _b64
    import mls_wire as _w
    for _name, _out in (("sample-SE.json", "group-contexts.demo.json"),
                        ("sample-SE-scoped.json",
                         "group-contexts.scoped.demo.json")):
        _se = json.loads((ROOT / "samples" / _name).read_text())
        _se = _se.get("projection", _se)
        _scope = _se.get("scope_ref") or {}
        _gc = _w.demo_group_context(
            _se["mls_group_id"], _se["mls_epoch"],
            scope_id=_scope.get("scope_id", "default"),
            scope_version=_scope.get("version", "1"))
        if _w.mls_state_hash(_gc)["hex"] != _se["mls_state"]["hex"]:
            raise SystemExit(
                f"{_name}: the generated GroupContext does not hash to the "
                "mls_state the evidence pins — retaining bytes that do not "
                "match the commitment would prove nothing")
        (ROOT / "samples" / _out).write_text(json.dumps({
            "$comment": (
                "R5-05: retained GroupContext octets, keyed by (mls_group_id, "
                "mls_epoch). The evidence already pins each one's hash as "
                "mls_state (F-03), so retaining the bytes adds no trust — it "
                "lets LINT-BND-40 RECOMPUTE the cipher-suite decision they "
                "encode instead of merely confirming they were kept. "
                "Generated by scripts/regen_samples.py."),
            "contexts": [{"mls_group_id": _se["mls_group_id"],
                          "mls_epoch": _se["mls_epoch"],
                          "group_context_b64": _b64.b64encode(_gc).decode()}],
        }, indent=2, ensure_ascii=False) + "\n")
        print(f"regenerated {_out}")

    # R12-X4: the inputs the demo groups' suite decision was TAKEN ON —
    # retained as one object the decision commits to by digest
    # (`mls_wire.demo_formation_inputs`, the same function the demo
    # parameters are computed from, so the two cannot disagree). This replaces
    # `package-suites.demo.json`, an availability table keyed by
    # (mid, device_id) that bound to nothing and let the members be whatever
    # the bundle supplied today (R12-05, R12-06).
    _formation = _w.demo_formation_inputs()
    if _w.formation_inputs_digest(_formation) != _w.demo_group_params()["inputs_digest"]:
        raise SystemExit("the retained formation inputs are not the ones the "
                         "demo decision commits to")
    (ROOT / "samples" / "formation-inputs.demo.json").write_text(json.dumps({
        "$comment": (
            "R12-X4: the exact inputs each retained group's cipher-suite decision was taken on — "
            "its members (both entities) and each addressable device's KeyPackage availability. "
            "A decision commits to SHA-256(dCBOR(formation)) as `inputs_digest` in sbm_group_params "
            "v2; a verifier recomputes it only from a formation that matches, and never from "
            "current data. Generated by scripts/regen_samples.py."),
        "formations": [_formation]}, indent=2, ensure_ascii=False) + "\n")
    print("regenerated formation-inputs.demo.json")

    # R10-11: suite-registry.demo.json is NOT regenerated. It is the registry
    # AS IT STOOD when the demo groups were formed — the retained material a
    # bundle verifier recomputes their cipher-suite decision against — and
    # copying the live registry over it on every regen meant the first new
    # revision rewrote history: the demo groups re-pinned a vector that did not
    # exist when they were created. It is frozen at revision 1; the demo pins
    # read it (`mls_wire.demo_group_params`).

    (ROOT / "samples" / "registry.stage1.demo.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    n = 0
    for p in sorted((ROOT / "samples").glob("sample-*.json")):
        if regen(p):
            print("regenerated", p.name)
            n += 1
    emit_stage1_registry()
    emit_stage1_federation_register()
    print("regenerated registry.stage1.demo.json")
    print(f"{n} evidence samples regenerated")


if __name__ == "__main__":
    main()
