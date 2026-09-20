#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""R-02 / D3 — minimal RFC 9420 TLS-presentation serialization for the two wire
structs the evidence commitments hash:

  * MLSMessage (version mls10, wire_format mls_private_message) wrapping a
    PrivateMessage — the EXACT wire object handed to transport. The evidence
    `envelope_hash` is SHA-256 over these serialized octets (D3: the MLSMessage,
    not the PrivateMessage alone; format label "mls10-message").
  * GroupContext (RFC 9420 §8.1) — version, cipher_suite, group_id, epoch,
    tree_hash, confirmed_transcript_hash, extensions. The evidence `mls_state`
    is SHA-256 over these serialized octets (format label "mls10-group-context"):
    ONE value that pins cipher suite, protocol version, both hashes AND the
    extensions together (D3's replacement for the enumerated field pair).

Encoding follows RFC 9420 §2.1.2: variable-length vectors carry a QUIC-style
variable-length integer length prefix (RFC 9000 §16: 2-bit prefix, 1/2/4/8-byte
big-endian). Fixed-width integers are big-endian. This is deliberately a
serializer only (no parser): the reference tooling needs deterministic bytes to
hash, and the KAT pins them.

Demo fixtures: `demo_mls_message` / `demo_group_context` build deterministic
structs from the evidence-visible identifiers (message_id, group_id, epoch) so
an SE and its confirmation commit to the SAME values; a production provider
hashes the actual octets it transmits/holds (the I-D, Transmitted-octet
commitment).
"""
import base64
import hashlib
import struct

PROTOCOL_VERSION_MLS10 = 0x0001
WIRE_FORMAT_PRIVATE_MESSAGE = 0x0002
CONTENT_TYPE_APPLICATION = 0x01
CIPHER_SUITE_BASELINE = 0x0001  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

ENVELOPE_HASH_FORMAT = "mls10-message"
MLS_STATE_FORMAT = "mls10-group-context"

# F-05: the sbm_scope GroupContext extension. ExtensionType from the RFC 9420
# PRIVATE-USE range (0xF000-0xFFFF); the code-point strategy is stated in the
# I-D (private use now; IANA registration is the published intent on
# standardisation - additive, no wire change). Every SM-MLS group carries it
# (the reserved default scope included), members MUST advertise it in LeafNode
# capabilities, and GroupContext required_capabilities MUST include it.
SBM_SCOPE_EXTENSION_TYPE = 0xF53B
# RFC 9420 §12.4.3: the registered required_capabilities GroupContext extension.
# The I-D requires it to list sbm_scope, so a member that does not support the
# extension cannot join silently. It was never serialized before DR-01.
REQUIRED_CAPABILITIES_EXTENSION_TYPE = 0x0003
# R3-08/R3-T4: the sbm_group_params GroupContext extension, private use, one
# code point above sbm_scope so canonical ascending order is 0x0003, 0xF53B,
# 0xF53C. It pins the cipher-suite decision — the preference vector, the floor
# and its version, the effective floor, the selected suite, and the per-device
# raises that produced it.
#
# In a GroupContext BECAUSE `mls_state` already commits to the GroupContext, so
# the pin is evidence-visible for free — which is what the I-D claimed and what
# R3-08 found nothing represented. A separate signed artefact would have had to
# add its own commitment to the group state: rebuilding by hand what mls_state
# already does.
SBM_GROUP_PARAMS_EXTENSION_TYPE = 0xF53C      # v1: decoded for history, never produced
# R12-05 / R12-X4 — version 2 of the pinned decision. v1's DeviceRaise named
# (mid, device_id), which is unique only within an entity, and v1 bound nothing
# about the inputs the decision was taken on, so a verifier recomputed it from
# whatever members it was handed today. A new extension type, not an edit to
# v1: a retained v1 group keeps its bytes and its meaning.
SBM_GROUP_PARAMS_V2_EXTENSION_TYPE = 0xF53D
_SCOPE_ID_MAX = 64
_DESCRIPTOR_VERSION_MAX = 32
_ENTITY_UIDS_MAX = 16


def varint(n: int) -> bytes:
    """RFC 9000 §16 variable-length integer (the RFC 9420 §2.1.2 vector length)."""
    if n < 0x40:
        return struct.pack(">B", n)
    if n < 0x4000:
        return struct.pack(">H", 0x4000 | n)
    if n < 0x40000000:
        return struct.pack(">I", 0x80000000 | n)
    if n < 0x4000000000000000:
        return struct.pack(">Q", 0xC000000000000000 | n)
    raise ValueError("varint out of range")


def opaque_v(data: bytes) -> bytes:
    """opaque data<V> — varint length prefix + bytes."""
    return varint(len(data)) + bytes(data)


# --- R9-03/R9-X1: the canonical KeyPackage reference -------------------------
#
# `keypackage_ref` was REQUIRED by `InvitationDeposit` and produced by nothing.
# It occurred in the published surface exactly once — as that required property
# — and its description said what it BINDS rather than what it IS: zero
# occurrences in the Internet-Draft, the TS, the umbrella, the CDDL and every
# JSON Schema. A conforming client could not construct the request at all, and
# two implementations that each invented a rule ("hash the encoded bytes", "the
# MLS reference", "our database id") would reject each other while both
# following the prose.
#
# MLS already defines a reference for this exact object, so SBM does not invent
# a second one (the R7-X1 rule: two names for one thing is how the collision
# comes back).

_SUITE_HASH = {"SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512"}


def suite_hash_name(cipher_suite: str) -> str:
    """The hash function of an MLS cipher suite, read from its own name.

    RFC 9420 names carry it (`..._SHA256_...`), so this derives rather than
    restating a table that would drift from the registry.
    """
    for token, name in _SUITE_HASH.items():
        if f"_{token}_" in cipher_suite:
            return name
    raise ValueError(
        f"cannot determine the hash function of cipher suite {cipher_suite!r}; "
        "the MLS suite name must carry it (RFC 9420 §17.1)")


def ref_hash(label: bytes, value: bytes, *, hash_name: str) -> bytes:
    """RFC 9420 §5.2 RefHash.

        RefHashInput = struct {
            opaque label<V>;
            opaque value<V>;
        }
        RefHash(label, value) = Hash(RefHashInput)

    `Hash` is the cipher suite's hash function; both fields are
    length-prefixed, so the label cannot be confused with the value.
    """
    return hashlib.new(hash_name, opaque_v(label) + opaque_v(value)).digest()


KEYPACKAGE_REF_LABEL = b"MLS 1.0 KeyPackage Reference"


def keypackage_ref(keypackage: bytes, *, cipher_suite: str) -> str:
    """RFC 9420 §5.2 — `KeyPackageRef`, base64url without padding.

    The input is the ENCODED KeyPackage exactly as it appears on the wire (the
    bytes a reservation returns as `keypackage_b64`), and the hash is the one
    named by the reservation's own cipher suite. Both halves are stated
    normatively so that the same bytes and suite always derive the same value:
    the DS returns it for every reserved target AND a client can derive it
    itself, and the two must agree.
    """
    digest = ref_hash(KEYPACKAGE_REF_LABEL, bytes(keypackage),
                      hash_name=suite_hash_name(cipher_suite))
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


SBM_GROUP_INFO_COMMITMENT_LABEL = b"SBM 1.0 GroupInfo Commitment"


def group_info_commitment(group_info: bytes, *, cipher_suite: str) -> str:
    """R9-03 requirement 6 — the commitment to the GroupInfo a Welcome carries.

    Same construction as the KeyPackage reference, with its own label, so the
    two can never be confused and neither can be replayed as the other. The
    input is the encoded `GroupInfo` the Welcome delivers.

    WHO VALIDATES IT, stated because the field previously claimed a binding
    nobody could check: the DS cannot. A Welcome is encrypted to the invited
    device, so the DS retains and echoes this value without being able to parse
    what it commits to. The INVITED DEVICE recomputes it after decrypting the
    Welcome and refuses an invitation whose commitment does not match. The DS's
    role is to make the creator's claim immutable and quotable in the refusal,
    not to verify it.
    """
    digest = ref_hash(SBM_GROUP_INFO_COMMITMENT_LABEL, bytes(group_info),
                      hash_name=suite_hash_name(cipher_suite))
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def serialize_private_message(group_id: bytes, epoch: int,
                              authenticated_data: bytes,
                              encrypted_sender_data: bytes,
                              ciphertext: bytes) -> bytes:
    """PrivateMessage (RFC 9420 §6.3), content_type = application."""
    return (opaque_v(group_id)
            + struct.pack(">Q", epoch)
            + struct.pack(">B", CONTENT_TYPE_APPLICATION)
            + opaque_v(authenticated_data)
            + opaque_v(encrypted_sender_data)
            + opaque_v(ciphertext))


def serialize_mls_message(private_message: bytes) -> bytes:
    """MLSMessage (RFC 9420 §6): mls10 + wire_format(private_message) + body."""
    return (struct.pack(">H", PROTOCOL_VERSION_MLS10)
            + struct.pack(">H", WIRE_FORMAT_PRIVATE_MESSAGE)
            + private_message)


def serialize_group_context(cipher_suite: int, group_id: bytes, epoch: int,
                            tree_hash: bytes, confirmed_transcript_hash: bytes,
                            extensions=()) -> bytes:
    """GroupContext (RFC 9420 §8.1). `extensions` is a SEQUENCE OF
    (extension_type, extension_data) PAIRS — never pre-serialized vector bytes
    (DR-01: the former signature accepted already-vectored bytes and prefixed
    them again, emitting a GroupContext no conforming implementation produces).
    The vector is built by `serialize_extensions`, which owns the single
    prefix and enforces the canonical order."""
    return (struct.pack(">H", PROTOCOL_VERSION_MLS10)
            + struct.pack(">H", cipher_suite)
            + opaque_v(group_id)
            + struct.pack(">Q", epoch)
            + opaque_v(tree_hash)
            + opaque_v(confirmed_transcript_hash)
            + serialize_extensions(extensions))


def serialize_scope_extension(scope_id: str, descriptor_version: str,
                              entity_uids=(), bilateral: bool = True) -> bytes:
    """The SBMScopeExtension TLS struct (F-05):

        struct {
          opaque scope_id<V>;             /* UTF-8; 1..64 bytes */
          opaque descriptor_version<V>;   /* UTF-8; 1..32 bytes */
          opaque entity_uids<V>;          /* 0..16 UIDs, each opaque<V>;
                                             bytewise-ascending, no dups */
        } SBMScopeExtension;

    entity_uids MUST be EMPTY in this profile version (D1/F-07: bilateral
    only — a non-empty list is the multiparty marker and is rejected; the
    field survives for the specified future-study extension, buildable with
    bilateral=False for fixtures). The serializer REJECTS what the wire
    forbids - unordered or duplicate UIDs, oversize fields - so two
    conforming implementations cannot emit different bytes for one scope."""
    if bilateral and entity_uids:
        raise ValueError(
            "bilateral only (D1/F-07): entity_uids MUST be empty in this "
            "profile version — a non-empty list is the multiparty marker")
    sid = scope_id.encode("utf-8")
    ver = descriptor_version.encode("utf-8")
    if not 1 <= len(sid) <= _SCOPE_ID_MAX:
        raise ValueError("scope_id must be 1..64 UTF-8 bytes")
    if not 1 <= len(ver) <= _DESCRIPTOR_VERSION_MAX:
        raise ValueError("descriptor_version must be 1..32 UTF-8 bytes")
    uids = [u.encode("utf-8") if isinstance(u, str) else bytes(u)
            for u in entity_uids]
    if len(uids) > _ENTITY_UIDS_MAX:
        raise ValueError("entity_uids exceeds the 16-entry bound")
    if uids != sorted(uids):
        raise ValueError("entity_uids must be bytewise-ascending (canonical order)")
    if len(set(uids)) != len(uids):
        raise ValueError("duplicate entity UID")
    uid_vec = b"".join(opaque_v(u) for u in uids)
    return opaque_v(sid) + opaque_v(ver) + opaque_v(uid_vec)


def serialize_group_params(preference_vector_id: str, floor_id: str,
                           floor_version: str, effective_floor: str,
                           selected_suite: str, device_raises=()) -> bytes:
    """The SBMGroupParams TLS struct (R3-08):

        struct {
          opaque preference_vector_id<V>;   /* e.g. "mls-suite-preference/v2" */
          opaque floor_id<V>;               /* "mls-suite-floor/v1" */
          opaque floor_version<V>;          /* the registry revision */
          opaque effective_floor<V>;        /* the floor actually in force */
          opaque selected_suite<V>;         /* what the creator chose */
          DeviceRaise device_raises<V>;     /* who demanded more, and what */
        } SBMGroupParams;

        struct { opaque mid<V>; opaque device_id<V>; opaque suite<V>; }
        DeviceRaise;

    `effective_floor` is the mandatory floor RAISED by the strongest device
    raise, so a verifier reads the decision without re-deriving it — and
    `device_raises` says WHO raised it, so the derivation can be checked rather
    than trusted. Raises are in canonical (mid, device_id) order with
    duplicates rejected: without one, two conforming creators produce different
    `mls_state` for the same group, which is R2-M3's lesson.
    """
    raises = [(str(m), str(d), str(s)) for m, d, s in device_raises]
    if len(set((m, d) for m, d, _ in raises)) != len(raises):
        raise ValueError("duplicate (mid, device_id) in device_raises")
    if raises != sorted(raises):
        raise ValueError(
            "device_raises must be in ascending (mid, device_id) order "
            "(canonical form) — otherwise two creators emit different bytes")
    raise_vec = b"".join(
        opaque_v(m.encode("utf-8")) + opaque_v(d.encode("utf-8"))
        + opaque_v(s.encode("utf-8")) for m, d, s in raises)
    return (opaque_v(preference_vector_id.encode("utf-8"))
            + opaque_v(floor_id.encode("utf-8"))
            + opaque_v(floor_version.encode("utf-8"))
            + opaque_v(effective_floor.encode("utf-8"))
            + opaque_v(selected_suite.encode("utf-8"))
            + opaque_v(raise_vec))


def serialize_group_params_v2(preference_vector_id: str, floor_id: str,
                              floor_version: str, effective_floor: str,
                              selected_suite: str, device_raises=(),
                              formed_at: str = "", inputs_digest: str = "") -> bytes:
    """SBMGroupParams version 2 (R12-05, R12-X4):

        struct {
          opaque preference_vector_id<V>;
          opaque floor_id<V>;
          opaque floor_version<V>;
          opaque effective_floor<V>;
          opaque selected_suite<V>;
          DeviceRaise device_raises<V>;
          opaque formed_at<V>;       /* RFC 3339: when the decision was taken */
          opaque inputs_digest<V>;   /* SHA-256 hex over the formation inputs */
        } SBMGroupParamsV2;

        struct { opaque uid<V>; opaque mid<V>; opaque device_id<V>;
                 opaque suite<V>; } DeviceRaise;

    The raise names the device's WHOLE principal: two entities may both have
    member `F1N2C3D4P` with a `dev-01`, and v1 could neither encode both of
    their raises nor tell which one a raise belonged to. `inputs_digest`
    commits to the exact capabilities and package availability the decision
    was taken on (`formation_inputs_digest`), so a verifier recomputes from
    those or not at all. Raises are in canonical (uid, mid, device_id) order,
    duplicates rejected."""
    raises = [(str(u), str(m), str(d), str(x)) for u, m, d, x in device_raises]
    if len(set(r[:3] for r in raises)) != len(raises):
        raise ValueError("duplicate (uid, mid, device_id) in device_raises")
    if raises != sorted(raises):
        raise ValueError(
            "device_raises must be in ascending (uid, mid, device_id) order "
            "(canonical form) — otherwise two creators emit different bytes")
    raise_vec = b"".join(b"".join(opaque_v(f.encode("utf-8")) for f in r)
                         for r in raises)
    return (b"".join(opaque_v(v.encode("utf-8")) for v in (
                preference_vector_id, floor_id, floor_version, effective_floor,
                selected_suite))
            + opaque_v(raise_vec)
            + opaque_v(formed_at.encode("utf-8"))
            + opaque_v(inputs_digest.encode("utf-8")))


def formation_inputs(members, package_suites):
    """R12-X4 — the inputs a suite decision is taken on, in canonical form:
    the BW-MEMBER documents consulted (both entities), ordered by (uid, mid),
    and each addressable device's package availability, ordered by principal.
    `package_suites` maps (uid, mid, device_id) -> suites."""
    return {"members": sorted(members, key=lambda m: (m.get("uid", ""), m.get("mid", ""))),
            "package_suites": [{"uid": u, "mid": m, "device_id": d,
                                "suites": sorted(package_suites[(u, m, d)])}
                               for (u, m, d) in sorted(package_suites)]}


def formation_inputs_digest(inputs) -> str:
    """SHA-256 hex over the deterministic CBOR of `formation_inputs(...)`."""
    from lint_cli import dcbor
    return hashlib.sha256(dcbor(inputs)).hexdigest()


def sbm_group_params_extension(preference_vector_id, floor_id, floor_version,
                               effective_floor, selected_suite,
                               device_raises=(), formed_at=None,
                               inputs_digest=None, params_version=1):
    """The sbm_group_params extension as an (type, data) PAIR — version 2
    when the record says so (R12-X4), version 1 only to reproduce history."""
    if params_version == 2:
        return (SBM_GROUP_PARAMS_V2_EXTENSION_TYPE,
                serialize_group_params_v2(
                    preference_vector_id, floor_id, floor_version,
                    effective_floor, selected_suite,
                    [(r["uid"], r["mid"], r["device_id"], r["suite"])
                     if isinstance(r, dict) else tuple(r) for r in device_raises],
                    formed_at or "", inputs_digest or ""))
    return (SBM_GROUP_PARAMS_EXTENSION_TYPE,
            serialize_group_params(preference_vector_id, floor_id,
                                   floor_version, effective_floor,
                                   selected_suite, device_raises))


def serialize_extensions(extensions) -> bytes:
    """The RFC 9420 `Extension extensions<V>` vector: a <V>-prefixed sequence of
    (uint16 extension_type + opaque extension_data<V>).

    DR-01: this is the ONLY place a vector prefix is applied to an extension
    list. `serialize_group_context` takes the PAIRS, never pre-vectored bytes —
    the double-prefix defect (which made a conforming decoder read extension
    type 0x0ef5 instead of 0xF53B, silently, with no parse error to report) is
    now unrepresentable rather than merely fixed.

    Canonical form (R2-M3): ascending `extension_type`, duplicates rejected —
    without it two conforming implementations produce different `mls_state`
    for the same group."""
    pairs = list(extensions)
    types = [etype for etype, _ in pairs]
    if len(set(types)) != len(types):
        raise ValueError("duplicate extension_type in the extension list")
    if types != sorted(types):
        raise ValueError(
            "extensions must be in ascending extension_type order (canonical "
            "form, R2-M3) — got " + ", ".join(hex(x) for x in types))
    body = b"".join(struct.pack(">H", etype) + opaque_v(data)
                    for etype, data in pairs)
    return opaque_v(body)


def required_capabilities_extension(extension_types=(SBM_SCOPE_EXTENSION_TYPE,),
                                    proposal_types=(), credential_types=()):
    """RFC 9420 §12.4.3 required_capabilities, as an (type, data) PAIR:

        struct { ExtensionType extension_types<V>;
                 ProposalType  proposal_types<V>;
                 CredentialType credential_types<V>; } RequiredCapabilities;
    """
    def _u16_vec(values):
        return opaque_v(b"".join(struct.pack(">H", v) for v in values))
    return (REQUIRED_CAPABILITIES_EXTENSION_TYPE,
            _u16_vec(extension_types) + _u16_vec(proposal_types)
            + _u16_vec(credential_types))


def sbm_scope_extension(scope_id: str, descriptor_version: str,
                        entity_uids=(), bilateral: bool = True):
    """The sbm_scope extension as an (type, data) PAIR."""
    return (SBM_SCOPE_EXTENSION_TYPE,
            serialize_scope_extension(scope_id, descriptor_version,
                                      entity_uids, bilateral=bilateral))


def sm_mls_extensions(scope_id: str, descriptor_version: str, entity_uids=(),
                      group_params=None):
    """The extension PAIRS every SM-MLS GroupContext carries, in canonical
    ascending order: required_capabilities (0x0003) listing both private-use
    extensions, then sbm_scope (0xF53B), then sbm_group_params (0xF53C).

    R3-08: `group_params` is a dict of the serialize_group_params arguments.
    Where it is given, required_capabilities lists 0xF53C too — a member that
    cannot read the pinned decision must not join silently, exactly as for
    sbm_scope."""
    types = [SBM_SCOPE_EXTENSION_TYPE]
    exts = [sbm_scope_extension(scope_id, descriptor_version, entity_uids)]
    if group_params:
        ext = sbm_group_params_extension(**group_params)
        types.append(ext[0])
        exts.append(ext)
    return [required_capabilities_extension(extension_types=tuple(types))] + exts


def sbm_scope_extensions(scope_id: str, descriptor_version: str,
                         entity_uids=()) -> bytes:
    """DEPRECATED (DR-01): returns the serialized vector for the sbm_scope
    extension ALONE. Retained only for the F-05 byte-level tests that pin the
    single-extension encoding; it MUST NOT be passed to
    `serialize_group_context`, which now takes PAIRS — passing pre-vectored
    bytes is what produced the double length prefix."""
    return serialize_extensions([sbm_scope_extension(scope_id,
                                                     descriptor_version,
                                                     entity_uids)])


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# Deterministic DEMO fixtures (the evidence-visible identifiers -> real bytes)
# ---------------------------------------------------------------------------

def demo_mls_message(message_id: str, mls_group_id: str, mls_epoch) -> bytes:
    """The demo transmitted MLSMessage for a message: deterministic ciphertext /
    sender data derived from the identifiers, wrapped in the real wire struct."""
    gid = _b64url_decode(mls_group_id)
    epoch = int(mls_epoch)
    ct = hashlib.sha256(f"demo-ciphertext:{message_id}:{mls_group_id}:{mls_epoch}"
                        .encode()).digest() * 2  # 64 demo ciphertext bytes
    esd = hashlib.sha256(f"demo-sender-data:{message_id}".encode()).digest()
    pm = serialize_private_message(gid, epoch, b"", esd, ct)
    return serialize_mls_message(pm)


def demo_group_context(mls_group_id: str, mls_epoch,
                       cipher_suite: int = CIPHER_SUITE_BASELINE,
                       extensions=None,
                       scope_id: str = "default",
                       scope_version: str = "1") -> bytes:
    """The demo GroupContext for (group, epoch): deterministic tree/transcript
    hashes (the retained demo state a verifier resolves, F-03). F-05: unless
    explicit extension bytes are supplied, the context carries the REAL
    sbm_scope extension for (scope_id, scope_version) - so the demo mls_state
    commitments pin the scope binding exactly as production ones do.

    R3-08: and the REAL sbm_group_params, so the pinned cipher-suite decision
    is committed by mls_state too. The I-D said the selection and floor were
    pinned in group-establishment state; nothing represented them, and the
    conformance test asserted only that the sentence existed."""
    gid = _b64url_decode(mls_group_id)
    epoch = int(mls_epoch)
    th = hashlib.sha256(f"tree:{mls_group_id}:{mls_epoch}".encode()).digest()
    cth = hashlib.sha256(f"transcript:{mls_group_id}:{mls_epoch}".encode()).digest()
    if extensions is None:
        extensions = sm_mls_extensions(scope_id, scope_version,
                                       group_params=demo_group_params())
    return serialize_group_context(cipher_suite, gid, epoch, th, cth, extensions)


DEMO_FORMED_AT = "2026-04-01T09:00:00Z"
DEMO_FORMATION_MEMBERS = ("sample-BW-MEMBER-fr.json", "sample-BW-MEMBER-fr2.json")


def demo_formation_inputs():
    """R12-X4: the inputs the demo groups' decision was taken on — the two FR
    members the demo decision recomputes over, and each addressable device's
    package availability as its published capabilities give it. Derived from
    the sample files, never restated; `regen_samples` writes it out as the
    retained `formation-inputs.demo.json`."""
    import json as _json
    import pathlib as _pathlib
    import mls_suite as _ms
    root = _pathlib.Path(__file__).resolve().parents[1] / "samples"
    members = []
    for name in DEMO_FORMATION_MEMBERS:
        doc = _json.loads((root / name).read_text(encoding="utf-8"))
        members.append(doc.get("projection", doc))
    packages = {(m["uid"], m["mid"], d["device_id"]): d.get("cipher_suites") or []
                for m in members for d in _ms.addressable_devices(m)}
    return formation_inputs(members, packages)


def demo_group_params(selected_suite=None, device_raises=(), inputs=None,
                      formed_at=None):
    """R3-08: the pinned selection for the demo groups, read from a registry
    rather than restated — the drift family this repository keeps finding.

    R10-11: from the RETAINED revision the demo groups were formed under,
    `samples/suite-registry.demo.json`, not the live one. This read the LIVE
    registry, so the first registry revision after the demo groups were formed
    (R10-11's rename) re-pinned them: their GroupContexts named a vector that
    did not exist when they were created, `mls_state` changed, and thirteen
    evidence samples with it. A formed group is history. Pinning from the
    retained revision is also the consistent choice: it is exactly the record
    a bundle verifier recomputes the decision against."""
    import json as _json
    import pathlib as _pathlib
    reg = _json.loads(
        (_pathlib.Path(__file__).resolve().parents[1] / "samples" /
         "suite-registry.demo.json").read_text(encoding="utf-8"))
    floor = reg["floor"]["suite"]
    # R12-X4: version 2 — the raises name whole principals and the record
    # commits to the instant and the inputs it was decided on.
    return {"params_version": 2,
            "preference_vector_id": reg["preference_vector"]["id"],
            "floor_id": reg["floor"]["id"],
            "floor_version": str(reg["registry_version"]),
            "effective_floor": floor,
            "selected_suite": selected_suite or floor,
            "device_raises": device_raises,
            "formed_at": formed_at or DEMO_FORMED_AT,
            "inputs_digest": formation_inputs_digest(
                inputs if inputs is not None else demo_formation_inputs())}


def demo_tree_hash(mls_group_id: str, mls_epoch) -> bytes:
    """The demo ratchet-tree hash inside demo_group_context (linkage, F-03)."""
    return hashlib.sha256(f"tree:{mls_group_id}:{mls_epoch}".encode()).digest()


def envelope_hash(mls_message_octets: bytes) -> dict:
    """The evidence EnvelopeHash value over transmitted MLSMessage octets."""
    return {"format": ENVELOPE_HASH_FORMAT,
            "hex": hashlib.sha256(mls_message_octets).hexdigest()}


def mls_state_hash(group_context_octets: bytes) -> dict:
    """The evidence MlsStateHash value over serialized GroupContext octets."""
    return {"format": MLS_STATE_FORMAT,
            "hex": hashlib.sha256(group_context_octets).hexdigest()}


# ---------------------------------------------------------------------------
# R4-06 — the PRODUCTION decoder, and why one has to exist
# ---------------------------------------------------------------------------
#
# R3-08 put the cipher-suite decision into `sbm_group_params` so `mls_state`
# would commit to it. But the only decoder lived inside the KAT test, so the
# bytes were pinned and the DECISION THEY ENCODE was never recomputed: a
# creator could commit a self-consistent but false or downgraded record, and a
# verifier would check the hash rather than the selection rule. Hashing the
# GroupContext proves those bytes were retained — nothing more.
#
# The KAT keeps its own independent reader (a test that shares the producer's
# helper is not independent evidence); this one exists so PRODUCTION can read
# what production wrote.

class GroupParamsError(ValueError):
    """R4-06: a GroupContext extension whose group parameters cannot be read."""


def _read_varint(b, i):
    pre = b[i] >> 6
    if pre == 0:
        return b[i] & 0x3F, i + 1
    if pre == 1:
        return struct.unpack(">H", b[i:i + 2])[0] & 0x3FFF, i + 2
    if pre == 2:
        return struct.unpack(">I", b[i:i + 4])[0] & 0x3FFFFFFF, i + 4
    return struct.unpack(">Q", b[i:i + 8])[0] & 0x3FFFFFFFFFFFFFFF, i + 8


def _read_opaque(b, i):
    n, i = _read_varint(b, i)
    if i + n > len(b):
        raise GroupParamsError("truncated opaque field")
    return b[i:i + n], i + n


def parse_group_params_v2(data: bytes) -> dict:
    """Decode an SBMGroupParamsV2 body (R12-X4). Raises GroupParamsError."""
    try:
        i, out = 0, {"params_version": 2}
        for field in ("preference_vector_id", "floor_id", "floor_version",
                      "effective_floor", "selected_suite"):
            value, i = _read_opaque(data, i)
            out[field] = value.decode("utf-8")
        raise_vec, i = _read_opaque(data, i)
        formed_at, i = _read_opaque(data, i)
        digest, i = _read_opaque(data, i)
        if i != len(data):
            raise GroupParamsError("trailing bytes after sbm_group_params v2")
        raises, j = [], 0
        while j < len(raise_vec):
            fields = []
            for _ in range(4):
                value, j = _read_opaque(raise_vec, j)
                fields.append(value.decode("utf-8"))
            raises.append(dict(zip(("uid", "mid", "device_id", "suite"), fields)))
        out.update(device_raises=raises, formed_at=formed_at.decode("utf-8"),
                   inputs_digest=digest.decode("utf-8"))
        return out
    except GroupParamsError:
        raise
    except Exception as exc:
        raise GroupParamsError(f"sbm_group_params v2 is not decodable: {exc}") from exc


def group_params_from(extensions):
    """The pinned decision a GroupContext carries, whichever version: v2 where
    present, else v1 (marked `params_version` 1 — history, with no entity in
    its raises and no binding to its inputs), else None."""
    if SBM_GROUP_PARAMS_V2_EXTENSION_TYPE in extensions:
        return parse_group_params_v2(extensions[SBM_GROUP_PARAMS_V2_EXTENSION_TYPE])
    if SBM_GROUP_PARAMS_EXTENSION_TYPE in extensions:
        return dict(parse_group_params(extensions[SBM_GROUP_PARAMS_EXTENSION_TYPE]),
                    params_version=1)
    return None


def parse_group_params(data: bytes) -> dict:
    """Decode an `sbm_group_params` extension body into its five identifiers
    and its device raises. Raises GroupParamsError; never guesses."""
    try:
        i = 0
        out = {}
        for field in ("preference_vector_id", "floor_id", "floor_version",
                      "effective_floor", "selected_suite"):
            value, i = _read_opaque(data, i)
            out[field] = value.decode("utf-8")
        raise_vec, i = _read_opaque(data, i)
        if i != len(data):
            raise GroupParamsError("trailing bytes after sbm_group_params")
        raises, j = [], 0
        while j < len(raise_vec):
            mid, j = _read_opaque(raise_vec, j)
            did, j = _read_opaque(raise_vec, j)
            suite, j = _read_opaque(raise_vec, j)
            raises.append({"mid": mid.decode("utf-8"),
                           "device_id": did.decode("utf-8"),
                           "suite": suite.decode("utf-8")})
        out["device_raises"] = raises
        return out
    except GroupParamsError:
        raise
    except Exception as exc:
        raise GroupParamsError(f"sbm_group_params is not decodable: {exc}") from exc


def parse_group_context(gc: bytes) -> dict:
    """RFC 9420 §8.1, enough of it to reach the extensions and the SUITE.

    The cipher suite matters on its own: R4-06 requires `selected_suite` to
    equal the group's ACTUAL suite, and nothing compared them — a record could
    name one suite while the group ran on another.
    """
    try:
        i = 0
        version, cipher_suite = struct.unpack(">HH", gc[i:i + 4]); i += 4
        group_id, i = _read_opaque(gc, i)
        epoch = struct.unpack(">Q", gc[i:i + 8])[0]; i += 8
        _tree, i = _read_opaque(gc, i)
        _transcript, i = _read_opaque(gc, i)
        ext_body, i = _read_opaque(gc, i)
        if i != len(gc):
            raise GroupParamsError("trailing bytes after the GroupContext")
        exts, j = {}, 0
        while j < len(ext_body):
            etype = struct.unpack(">H", ext_body[j:j + 2])[0]; j += 2
            data, j = _read_opaque(ext_body, j)
            exts[etype] = data
        return {"version": version, "cipher_suite": cipher_suite,
                "group_id": group_id, "epoch": epoch, "extensions": exts}
    except GroupParamsError:
        raise
    except Exception as exc:
        raise GroupParamsError(f"GroupContext is not decodable: {exc}") from exc


def _suite_code_points():
    """R10-11: the wire value of each suite, READ from
    registries/cipher-suites.json rather than restated here. This was a
    literal map carrying `0x004D` for the post-quantum hybrid — a value IANA
    has not allocated to it, under a name its source does not use — and it
    was the only place either was written down."""
    import json as _json
    import pathlib as _pl
    reg = _json.loads((_pl.Path(__file__).resolve().parents[1] / "registries"
                       / "cipher-suites.json").read_text(encoding="utf-8"))
    return {int(v["value"], 16): name
            for name, v in reg["code_points"].items() if not name.startswith("$")}


CIPHER_SUITE_NAMES = _suite_code_points()


def _iana_code_points():
    """The values IANA has ALLOCATED. An allocation never changes, so it is
    the same fact under every registry revision — which is why a revision that
    published no wire map can still resolve these, and only these (R11-X4)."""
    import json as _json
    import pathlib as _pl
    reg = _json.loads((_pl.Path(__file__).resolve().parents[1] / "registries"
                       / "cipher-suites.json").read_text(encoding="utf-8"))
    return {int(v["value"], 16): name for name, v in reg["code_points"].items()
            if not name.startswith("$") and v.get("status") == "iana"}


IANA_CODE_POINTS = _iana_code_points()


def wire_map(registry):
    """R11-X4 — the code point -> suite name map of ONE registry revision:
    the revision a retained group was FORMED under, never today's.

    `CIPHER_SUITE_NAMES` is the live map, right for groups formed now and wrong
    for history: the bundle path decoded a retained GroupContext through it
    BEFORE consulting the retained revision, so the first registry evolution
    would strand every group of the previous one — the promised private-use to
    IANA migration included. A revision carrying `code_points` decodes by its
    own; a revision that published none (revision 1) resolves the IANA
    allocations only, since those never change, and nothing else: `0x004D`
    lived only in the reference's code and was never specified by any
    revision."""
    cps = (registry or {}).get("code_points")
    if cps:
        return {int(v["value"], 16): name for name, v in cps.items()
                if not name.startswith("$")}
    return dict(IANA_CODE_POINTS)
