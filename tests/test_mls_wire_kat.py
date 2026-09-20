# SPDX-License-Identifier: MIT
"""DR-01 — the GroupContext bytes, checked against RFC 9420, not against us.

Former defect (round-2 review, Blocker): `serialize_group_context()` applied
a vector prefix to an ALREADY-vectored extension list, so every emitted
GroupContext carried a DOUBLE length prefix. The failure mode was worse than
a parse error: a conforming decoder reaches clean end-of-input and reads
`extension_type = 0x0ef5` (the inner length byte swallowed into the uint16)
instead of `0xF53B` — it simply concludes the group carries no `sbm_scope`.
The claim that the scope binding is "evidence-visible" was false on the wire.
Second defect: `required_capabilities` was never serialized at all, so the
extension-support property the I-D claims was not enforced by the demo state.

Why the round-1 tests missed it, and the rule this file exists to obey: they
pinned the producer's own output through the producer's own helpers. The
producer, the fixtures and the tests shared one faulty serializer and agreed
perfectly while all being wrong. **A test that calls the same helper as the
producer is not independent evidence.**

Everything below is built from the RFC structure. This module does NOT import
`scripts/mls_wire.py`; it reads the SHIPPED samples and re-derives the bytes.
"""
import json
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parents[1]

SBM_SCOPE = 0xF53B
SBM_GROUP_PARAMS_V1 = 0xF53C       # R3-08 — history: never produced any more
SBM_GROUP_PARAMS = 0xF53D          # R12-X4 — version 2, what the shipped groups pin
DEMO_FORMED_AT = "2026-04-01T09:00:00Z"   # the documented demo formation instant
REQUIRED_CAPABILITIES = 0x0003


# --- an independent RFC 9420 reader ----------------------------------------

def _varint(b, i):
    """RFC 9000 §16 variable-length integer (RFC 9420 §2.1.2 vector length)."""
    pre = b[i] >> 6
    if pre == 0:
        return b[i] & 0x3F, i + 1
    if pre == 1:
        return struct.unpack(">H", b[i:i + 2])[0] & 0x3FFF, i + 2
    if pre == 2:
        return struct.unpack(">I", b[i:i + 4])[0] & 0x3FFFFFFF, i + 4
    return struct.unpack(">Q", b[i:i + 8])[0] & 0x3FFFFFFFFFFFFFFF, i + 8


def _opaque(b, i):
    n, i = _varint(b, i)
    return b[i:i + n], i + n


def _varint_enc(n):
    """RFC 9000 §16 encoder. The decoder above always existed; the ENCODER was
    faked with a single length byte, which is correct only below 64 — and
    R3-08's extension pushed the vector past that. A test helper that is right
    only for short inputs is a test helper that stops testing when the input
    grows."""
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack(">H", n | 0x4000)
    return struct.pack(">I", n | 0x80000000)


def _opaque_enc(data):
    return _varint_enc(len(data)) + data


def decode_group_context(b):
    """RFC 9420 §8.1, decoded field by field. Returns the parsed struct and
    the number of trailing bytes (which MUST be zero)."""
    i = 0
    version, cipher_suite = struct.unpack(">HH", b[i:i + 4]); i += 4
    group_id, i = _opaque(b, i)
    epoch = struct.unpack(">Q", b[i:i + 8])[0]; i += 8
    tree_hash, i = _opaque(b, i)
    confirmed_transcript_hash, i = _opaque(b, i)
    ext_body, i = _opaque(b, i)          # Extension extensions<V>
    exts, j = [], 0
    while j < len(ext_body):
        etype = struct.unpack(">H", ext_body[j:j + 2])[0]; j += 2
        data, j = _opaque(ext_body, j)
        exts.append((etype, data))
    return {"version": version, "cipher_suite": cipher_suite,
            "group_id": group_id, "epoch": epoch, "tree_hash": tree_hash,
            "confirmed_transcript_hash": confirmed_transcript_hash,
            "extensions": exts}, len(b) - i


def decode_required_capabilities(data):
    """RFC 9420 §12.4.3: three uint16 vectors."""
    i = 0
    out = []
    for _ in range(3):
        vec, i = _opaque(data, i)
        out.append([struct.unpack(">H", vec[k:k + 2])[0]
                    for k in range(0, len(vec), 2)])
    assert i == len(data), "trailing bytes in required_capabilities"
    return dict(zip(("extension_types", "proposal_types", "credential_types"), out))


def decode_sbm_group_params(data):
    """The pinned cipher-suite decision, version 2 (R12-X4), decoded from the
    RFC-style structure — five opaque fields, a vector of (uid, mid,
    device_id, suite) raises, the formation instant and the input digest."""
    i = 0
    out = {}
    for field in ("preference_vector_id", "floor_id", "floor_version",
                  "effective_floor", "selected_suite"):
        value, i = _opaque(data, i)
        out[field] = value.decode()
    raise_vec, i = _opaque(data, i)
    formed_at, i = _opaque(data, i)
    digest, i = _opaque(data, i)
    assert i == len(data), "trailing bytes in sbm_group_params"
    raises, j = [], 0
    while j < len(raise_vec):
        fields = []
        for _ in range(4):
            value, j = _opaque(raise_vec, j)
            fields.append(value.decode())
        raises.append(tuple(fields))
    out.update(device_raises=raises, formed_at=formed_at.decode(),
               inputs_digest=digest.decode())
    return out


def _formation_digest():
    """SHA-256 over the canonical CBOR of the RETAINED formation — computed
    here from the file a verifier holds, not through `mls_wire`."""
    import hashlib
    import cbor2
    doc = json.loads((ROOT / "samples" / "formation-inputs.demo.json").read_text())
    return hashlib.sha256(cbor2.dumps(doc["formations"][0], canonical=True)).hexdigest()


def decode_sbm_scope(data):
    i = 0
    scope_id, i = _opaque(data, i)
    version, i = _opaque(data, i)
    uid_vec, i = _opaque(data, i)
    assert i == len(data), "trailing bytes in sbm_scope"
    uids, j = [], 0
    while j < len(uid_vec):
        uid, j = _opaque(uid_vec, j)
        uids.append(uid)
    return {"scope_id": scope_id.decode(), "version": version.decode(),
            "entity_uids": uids}


# --- the KAT, constructed from the RFC structure ---------------------------

def _u16_vec(values):
    return _opaque_enc(b"".join(struct.pack(">H", v) for v in values))


def _group_params_data(registry):
    """R3-08, built from the REGISTRY and the RFC structure — never from
    `mls_wire`. If the producer and this file agreed because they shared a
    serializer, the agreement would prove nothing (DR-01's lesson)."""
    floor = registry["floor"]["suite"]
    fields = [registry["preference_vector"]["id"], registry["floor"]["id"],
              str(registry["registry_version"]), floor, floor]
    body = b"".join(_opaque_enc(f.encode()) for f in fields)
    return (body + _opaque_enc(b"")     # empty device_raises vector
            + _opaque_enc(DEMO_FORMED_AT.encode())
            + _opaque_enc(_formation_digest().encode()))


def _expected_extension_vector(registry):
    """The bytes RFC 9420 says an SM-MLS GroupContext extension field holds:
    required_capabilities(0x0003) listing both private-use types, then
    sbm_scope(0xF53B), then sbm_group_params(0xF53C) — ascending type order,
    ONE vector prefix."""
    rc_data = _u16_vec([SBM_SCOPE, SBM_GROUP_PARAMS]) + _u16_vec([]) + _u16_vec([])
    scope_data = _opaque_enc(b"default") + _opaque_enc(b"1") + _opaque_enc(b"")
    gp_data = _group_params_data(registry)
    body = (struct.pack(">H", REQUIRED_CAPABILITIES) + _opaque_enc(rc_data)
            + struct.pack(">H", SBM_SCOPE) + _opaque_enc(scope_data)
            + struct.pack(">H", SBM_GROUP_PARAMS) + _opaque_enc(gp_data))
    return _opaque_enc(body)


def _registry():
    """The registry revision the SHIPPED GroupContexts were formed under — the
    retained one. R10-11: this read the live registry, which was the same
    thing until the first registry evolution, and then described the shipped
    groups with a vector that did not exist when they were created."""
    return json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())


def test_kat_the_extension_vector_bytes():
    """Pinned hex, derived here from the RFC and the registry — not from the
    producer. R3-08 lengthened it: required_capabilities now lists both
    private-use types and sbm_group_params follows sbm_scope."""
    got = _expected_extension_vector(_registry()).hex()
    # R12-X4: required_capabilities lists sbm_group_params v2 (0xF53D), and
    # the v2 body is longer — it binds the formation instant and inputs.
    assert got.startswith("40fb00030704f53bf53d0000f53b0b0764656661756c74013100f53d")
    assert "6d6c732d73756974652d707265666572656e63652f7631" in got, \
        "the preference-vector id must be in the pinned bytes"


# --- every shipped GroupContext, decoded independently ---------------------

def _sample_group_contexts():
    """Rebuild the GroupContext for every (group, epoch, scope) the shipped
    evidence commits to, using the demo derivation rules stated in the I-D —
    tree/transcript hashes are SHA-256 over documented labels."""
    import hashlib
    import base64
    out = []
    for f in sorted((ROOT / "samples").glob("sample-*.json")):
        d = json.loads(f.read_text())
        proj = d.get("projection")
        if not isinstance(proj, dict):
            continue
        for body in [proj] + [proj.get("se")] + (proj.get("outcomes") or []):
            if not isinstance(body, dict):
                continue
            gid, epoch = body.get("mls_group_id"), body.get("mls_epoch")
            if not gid or epoch is None or not body.get("mls_state"):
                continue
            sref = body.get("scope_ref") or {}
            scope = sref.get("scope_id", "default")
            ver = sref.get("version", "1")
            raw_gid = base64.urlsafe_b64decode(gid + "=" * (-len(gid) % 4))
            th = hashlib.sha256(f"tree:{gid}:{epoch}".encode()).digest()
            cth = hashlib.sha256(f"transcript:{gid}:{epoch}".encode()).digest()
            rc_data = (_u16_vec([SBM_SCOPE, SBM_GROUP_PARAMS])
                       + _u16_vec([]) + _u16_vec([]))
            sd = (_opaque_enc(scope.encode()) + _opaque_enc(ver.encode())
                  + _opaque_enc(b""))
            gp = _group_params_data(_registry())
            ebody = (struct.pack(">H", REQUIRED_CAPABILITIES) + _opaque_enc(rc_data)
                     + struct.pack(">H", SBM_SCOPE) + _opaque_enc(sd)
                     + struct.pack(">H", SBM_GROUP_PARAMS) + _opaque_enc(gp))
            gc = (struct.pack(">HH", 0x0001, 0x0001)
                  + _opaque_enc(raw_gid)
                  + struct.pack(">Q", int(epoch))
                  + _opaque_enc(th) + _opaque_enc(cth)
                  + _opaque_enc(ebody))
            out.append((f.name, gc, body["mls_state"]))
    return out


def test_every_generated_group_context_decodes_to_exact_end_of_input():
    ctxs = _sample_group_contexts()
    assert ctxs, "no GroupContext-bearing samples found"
    for name, gc, _ in ctxs:
        parsed, trailing = decode_group_context(gc)
        assert trailing == 0, f"{name}: {trailing} trailing byte(s)"
        assert parsed["version"] == 0x0001, name


def test_the_extension_field_has_exactly_one_vector_prefix():
    """The defect verbatim: a second prefix made the first extension type
    decode as 0x0ef5. Now the first decoded type is a real one."""
    for name, gc, _ in _sample_group_contexts():
        parsed, _ = decode_group_context(gc)
        types = [t for t, _ in parsed["extensions"]]
        assert 0x0EF5 not in types, f"{name}: the double-prefix signature is back"
        assert types == sorted(types), f"{name}: extensions not ascending"


def test_the_decoded_set_contains_both_extensions():
    for name, gc, _ in _sample_group_contexts():
        parsed, _ = decode_group_context(gc)
        types = [t for t, _ in parsed["extensions"]]
        assert REQUIRED_CAPABILITIES in types, f"{name}: no required_capabilities"
        assert SBM_SCOPE in types, f"{name}: no sbm_scope"


def test_required_capabilities_lists_both_private_use_types():
    """A member that cannot read the pinned decision must not join silently,
    exactly as for the scope binding."""
    for name, gc, _ in _sample_group_contexts():
        parsed, _ = decode_group_context(gc)
        rc = dict(parsed["extensions"])[REQUIRED_CAPABILITIES]
        declared = decode_required_capabilities(rc)["extension_types"]
        assert SBM_SCOPE in declared, name
        assert SBM_GROUP_PARAMS in declared, name


def test_the_pinned_selection_is_committed_by_mls_state():
    """R3-08: the I-D said the selected suite and effective floor are pinned in
    group-establishment state, and NOTHING represented them — the conformance
    test asserted that the prose sentence existed. Decoded here from the bytes
    `mls_state` commits to, with an independent reader."""
    registry = _registry()
    for name, gc, _ in _sample_group_contexts():
        parsed, _ = decode_group_context(gc)
        params = decode_sbm_group_params(dict(parsed["extensions"])[SBM_GROUP_PARAMS])
        assert params["preference_vector_id"] == registry["preference_vector"]["id"], name
        assert params["floor_id"] == registry["floor"]["id"], name
        assert params["effective_floor"] == registry["floor"]["suite"], name
        assert params["selected_suite"] in registry["preference_vector"]["order"], name


def test_changing_the_pinned_selection_changes_the_commitment():
    """Evidence-visible means exactly this: alter the decision and the sealed
    mls_state no longer matches."""
    import hashlib
    name, gc, mls_state = _sample_group_contexts()[0]
    assert hashlib.sha256(gc).hexdigest() == mls_state["hex"], name
    tampered = gc.replace(b"mls-suite-floor/v1", b"mls-suite-floor/v9")
    assert tampered != gc
    assert hashlib.sha256(tampered).hexdigest() != mls_state["hex"]


def test_the_shipped_mls_state_commits_to_these_exact_bytes():
    """The evidence and an independent RFC derivation agree — the property
    that was false before DR-01."""
    import hashlib
    for name, gc, mls_state in _sample_group_contexts():
        assert mls_state["format"] == "mls10-group-context", name
        assert mls_state["hex"] == hashlib.sha256(gc).hexdigest(), \
            f"{name}: the sealed mls_state does not match an independently " \
            f"derived RFC 9420 GroupContext"


def test_deleting_either_extension_changes_the_commitment():
    """Removal is evidence-visible: drop either extension and the committed
    bytes differ, so `mls_state` no longer matches the sealed evidence."""
    import hashlib
    name, gc, mls_state = _sample_group_contexts()[0]
    parsed, _ = decode_group_context(gc)
    full = b"".join(struct.pack(">H", ty) + _opaque_enc(d)
                    for ty, d in parsed["extensions"])
    head = gc[:len(gc) - len(_opaque_enc(full))]
    for drop in (REQUIRED_CAPABILITIES, SBM_SCOPE, SBM_GROUP_PARAMS):
        kept = [(ty, d) for ty, d in parsed["extensions"] if ty != drop]
        body = b"".join(struct.pack(">H", ty) + _opaque_enc(d) for ty, d in kept)
        rebuilt = head + _opaque_enc(body)
        assert rebuilt != gc
        assert hashlib.sha256(rebuilt).hexdigest() != mls_state["hex"], \
            f"{name}: dropping {hex(drop)} left the commitment unchanged"


def test_the_committed_inputs_are_exactly_the_retained_formation():
    """R12-X4, independently: the digest the shipped decision commits to is
    SHA-256 over the canonical CBOR of the formation a verifier is handed —
    so recomputing from those inputs recomputes the decision as it was taken."""
    for name, gc, _ in _sample_group_contexts():
        parsed, _ = decode_group_context(gc)
        params = decode_sbm_group_params(dict(parsed["extensions"])[SBM_GROUP_PARAMS])
        assert params["inputs_digest"] == _formation_digest(), name
        assert params["formed_at"] == DEMO_FORMED_AT, name
        assert SBM_GROUP_PARAMS_V1 not in dict(parsed["extensions"]), name
