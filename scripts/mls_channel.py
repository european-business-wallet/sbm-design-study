#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""F-06 — deterministic channel identity and duplicate-group convergence.

Both entities can create a first-contact group concurrently; the suite
selector (N3) makes them pick the same cipher suite but says nothing about
GROUP IDENTITY. This module is the reference implementation of the I-D's
*Channel identity and convergence* rules:

  * `channel_id(entity_uids, scope_id)` — the logical channel key for a
    `(entity set, scope)`: SHA-256 over the deterministic-CBOR array
    `["sm-mls:channel:v1", [sorted UIDs], scope_id]`. Order-insensitive in
    the entity set, scope-sensitive, computable by both sides with no
    coordination. Two MLS groups whose rosters span the same entity set and
    whose sbm_scope extension (F-05) names the same scope_id ARE the same
    logical channel.
  * `surviving_group_id(a, b)` — the convergence tie-break for a duplicate:
    the group with the BYTEWISE-SMALLER `group_id` survives. A total order
    both sides evaluate locally and identically; no election protocol.

Migration is evidence-governed (the I-D): messages DELIVERED in the losing
group keep their evidence (the group existed; its state history is retained
per F-03); an accepted-but-undelivered message closes its chain with NDE
`mls-group-invalid` (consignment stage) — its SE's `mls_group_id` names the
superseded group — and the sender resubmits on the survivor as a NEW
submission (`duplicate-message-id` intake gating prevents double acceptance,
so nothing is delivered twice).
"""
import base64
import hashlib

import cbor2

CHANNEL_DST = "sm-mls:channel:v1"


def channel_id(entity_uids, scope_id: str) -> str:
    """The logical channel key (lowercase hex). D1/F-07 (bilateral only): a
    channel is between EXACTLY TWO distinct entities in this profile version
    — a three-or-more set raises (the multiparty prohibition's negative)."""
    uids = sorted(set(entity_uids))
    if len(uids) != 2:
        raise ValueError(
            "bilateral only (D1/F-07): a channel is between exactly two "
            "distinct entities in this profile version")
    if len(uids) != len(list(entity_uids)):
        raise ValueError("duplicate entity UID")
    payload = cbor2.dumps([CHANNEL_DST, uids, scope_id], canonical=True)
    return hashlib.sha256(payload).hexdigest()


def _gid_bytes(group_id) -> bytes:
    if isinstance(group_id, bytes):
        return group_id
    s = str(group_id)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def surviving_group_id(group_id_a, group_id_b):
    """The duplicate-group tie-break: bytewise-smaller group_id survives.
    Symmetric and deterministic — both creators compute the same survivor
    locally. Returns the SURVIVING group_id (as passed in)."""
    a, b = _gid_bytes(group_id_a), _gid_bytes(group_id_b)
    if a == b:
        raise ValueError("not a duplicate: identical group_id")
    return group_id_a if a < b else group_id_b
