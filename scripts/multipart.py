#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""A14 — the layout of a multipart payload inside the envelope.

The manifest described the parts and bound them, and **no document said how a
recipient locates part N's octets**: no delimiter, no length-prefix framing, no
reference to an existing multipart format, and no statement that the parts were
concatenated in the manifest's order at the declared lengths. So two independent
implementations could satisfy every rule in the profile and fail to exchange one
multipart message, each verifying its manifest against its own framing.

The reason that went unnoticed for so long is worth keeping in view: under Mode C
`payload_hash` is the digest of the **manifest**, not of the plaintext, so every
check a provider or a verifier can run passes on one implementation's own bytes,
and a recipient that recomputed only `payload_hash` compared the manifest with
itself and checked nothing about the content it received.

The framing decided on 27 September 2026 (the I-D, *Application Envelope*; the
CDDL `payload-multipart`): the payload — the octets after the `0x00` separator in
the MLS application data — is the deterministic-CBOR encoding of an array of
`{part_id, octets}` maps, in byte-wise ascending `part_id` order, whose `part_id`
set equals the manifest's exactly. Keyed rather than positional, because a
fixed-position encoding is one silent reordering away from attributing a part's
octets to another part's descriptor — the same reason the manifest is a list of
maps and not a fixed array.

This module is the reference for it: `assemble` builds a payload, `parse` reads
one, and `verify_against_manifest` performs the recipient's obligation — each
part's digest recomputed from the octets RECEIVED and compared with the manifest,
then the manifest digest compared with `payload_hash`. Nothing here runs in a
linter, and that is not an omission: the payload is end-to-end encrypted and
absent from evidence, so no provider and no bundle verifier can check it. Only a
party holding the plaintext can, which is why the obligation is the recipient's.
"""
import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import lint_cli as lc  # noqa: E402

ALGS = {"SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512}


class MultipartError(ValueError):
    """A payload that is not the framing, or does not match its manifest."""


def canonical_order(part_ids):
    """Byte-wise ascending, which is the manifest's order (LINT-MAN-02).

    On UTF-8 bytes rather than on Python's string comparison: `part_id` is
    `^[A-Za-z0-9._-]{1,64}$`, so the two agree over the permitted alphabet
    today, and a widened alphabet would silently diverge.
    """
    return sorted(part_ids, key=lambda i: i.encode("utf-8"))


def assemble(parts):
    """{part_id: octets} -> the payload octets.

    Deterministic CBOR, so two senders with the same parts emit the same bytes:
    that is what makes `envelope_hash` independently recomputable over a
    multipart message at all.
    """
    if not parts:
        raise MultipartError("a multipart payload carries at least one part")
    return lc.dcbor([{"part_id": pid, "octets": parts[pid]}
                     for pid in canonical_order(parts)])


def parse(octets):
    """The payload octets -> [(part_id, octets)], or raise.

    Every deviation from the framing is refused here rather than tolerated,
    because a tolerated deviation is a second framing: a recipient that accepted
    an out-of-order array would interoperate with a sender no other recipient
    accepts.
    """
    import cbor2
    try:
        decoded = cbor2.loads(octets)
    except Exception as exc:                                   # pragma: no cover
        raise MultipartError(f"payload is not CBOR: {exc}") from exc
    if not isinstance(decoded, list) or not decoded:
        raise MultipartError("payload is not a non-empty array of part records")
    out = []
    for i, record in enumerate(decoded):
        if not isinstance(record, dict) or set(record) != {"part_id", "octets"}:
            raise MultipartError(
                f"part record {i} is not a map of exactly part_id and octets")
        pid, data = record["part_id"], record["octets"]
        if not isinstance(pid, str) or not isinstance(data, bytes):
            raise MultipartError(f"part record {i}: part_id must be text and octets bytes")
        out.append((pid, data))
    ids = [pid for pid, _ in out]
    if len(set(ids)) != len(ids):
        raise MultipartError(f"duplicate part_id in payload: {ids}")
    if ids != canonical_order(ids):
        raise MultipartError(
            f"payload is not in byte-wise ascending part_id order: {ids}")
    if lc.dcbor([{"part_id": p, "octets": d} for p, d in out]) != octets:
        raise MultipartError(
            "payload is not deterministic CBOR — a digest is a property of the "
            "bytes that travelled, so a re-serialisable encoding is not the framing")
    return out


def _digest(alg, data):
    try:
        return ALGS[alg](data).hexdigest()
    except KeyError:
        raise MultipartError(f"unsupported alg {alg!r}") from None


def verify_against_manifest(octets, manifest, payload_hash):
    """The recipient's obligation, in the order the I-D states it.

    Returns [] on a match, or a list of reasons. The order matters and is the
    point of the rule: the parts are checked against the octets RECEIVED first,
    and only then is the manifest digest compared with `payload_hash`. Doing it
    the other way round — which the earlier wording allowed — compares the
    manifest with itself and passes on any content whatsoever.
    """
    problems = []
    try:
        parts = dict(parse(octets))
    except MultipartError as exc:
        return [str(exc)]
    described = {p["part_id"]: p for p in manifest}
    for pid in sorted(set(described) - set(parts)):
        problems.append(f"part {pid!r} is described by the manifest and absent from the payload")
    for pid in sorted(set(parts) - set(described)):
        problems.append(f"part {pid!r} is in the payload and not described by the manifest")
    for pid in sorted(set(parts) & set(described)):
        part, data = described[pid], parts[pid]
        if part["length"] != str(len(data)):
            problems.append(f"part {pid!r}: manifest length {part['length']} != "
                            f"{len(data)} octets received")
        got = _digest(part["digest"]["alg"], data)
        if got != part["digest"]["hex"]:
            problems.append(f"part {pid!r}: digest over the octets received is {got}, "
                            f"the manifest declares {part['digest']['hex']}")
    if problems:
        return problems
    alg = payload_hash["alg"]
    if _digest(alg, lc.dcbor(manifest)) != payload_hash["hex"]:
        problems.append("the manifest's digest is not the declared payload_hash")
    return problems
