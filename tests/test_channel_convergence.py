# SPDX-License-Identifier: MIT
"""F-06 — concurrent MLS group creation converges deterministically.

Former defect: both entities could create a first-contact group
concurrently and NO rule defined which group survives, how duplicates are
detected, or how pending messages migrate — the deterministic suite
selector (N3) solved suite agreement, not group identity.

Now (I-D, Channel identity and convergence): the logical channel key
`channel_id = SHA-256(dCBOR(["sm-mls:channel:v1", [sorted UIDs],
scope_id]))` identifies the `(entity set, scope)`; a second group for an
existing channel is a duplicate, and the group with the bytewise-smaller
`group_id` survives — a total order both sides compute locally. Migration
is evidence-governed: delivered messages keep their evidence; an
accepted-but-undelivered message closes with NDE `mls-group-invalid`
(the SE's `mls_group_id` names the superseded group) and is resubmitted
as a new chain on the survivor.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import mls_channel as ch  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")

DE_UID = "EU-DE-EOID-7K3D9W0Q2M5FW0"
FR_UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]


# ---------------------------------------------------------------------------
# Channel identity: order-insensitive, scope-sensitive, coordination-free
# ---------------------------------------------------------------------------

def test_both_sides_compute_the_same_channel_id():
    a = ch.channel_id([DE_UID, FR_UID], "default")
    b = ch.channel_id([FR_UID, DE_UID], "default")   # the other side's order
    assert a == b


def test_channel_id_is_scope_sensitive():
    assert ch.channel_id([DE_UID, FR_UID], "default") != \
        ch.channel_id([DE_UID, FR_UID], "finance")


def test_channel_id_rejects_degenerate_sets():
    with pytest.raises(ValueError):
        ch.channel_id([DE_UID], "default")
    with pytest.raises(ValueError):
        ch.channel_id([DE_UID, DE_UID, FR_UID], "default")


# ---------------------------------------------------------------------------
# Convergence: one survivor, computed identically by both creators
# ---------------------------------------------------------------------------

def test_simultaneous_open_converges_to_one_group():
    """The interop case: each side created a group; both apply the
    tie-break locally and agree — no election, no coordination."""
    gid_a = base64.urlsafe_b64encode(b"\x01" * 16).decode().rstrip("=")
    gid_b = base64.urlsafe_b64encode(b"\x02" * 16).decode().rstrip("=")
    assert ch.surviving_group_id(gid_a, gid_b) == gid_a
    assert ch.surviving_group_id(gid_b, gid_a) == gid_a   # symmetric


def test_the_tie_break_is_a_total_order_over_bytes():
    lo = base64.urlsafe_b64encode(b"\x00\xff" + b"\x00" * 14).decode().rstrip("=")
    hi = base64.urlsafe_b64encode(b"\x01\x00" + b"\x00" * 14).decode().rstrip("=")
    assert ch.surviving_group_id(hi, lo) == lo


def test_identical_group_ids_are_not_a_duplicate():
    gid = base64.urlsafe_b64encode(b"\x03" * 16).decode().rstrip("=")
    with pytest.raises(ValueError):
        ch.surviving_group_id(gid, gid)


# ---------------------------------------------------------------------------
# Migration: the superseded chain closes in evidence; nothing lost or doubled
# ---------------------------------------------------------------------------

def test_the_superseded_chain_closes_with_mls_group_invalid():
    """An accepted-but-undelivered message on the losing group: its SE names
    the superseded group (mls_group_id) and the NDE closes the chain at the
    consignment stage — valid per schema and the X-30 event table."""
    nde = copy.deepcopy(NDE)
    nde["message_id"] = SE["message_id"]        # the accepted message
    nde["reason"] = "mls-group-invalid"
    nde["event"] = "D.2-ContentConsignmentFailure"
    assert not lc.validate_body(nde)
    v = el.Violations()
    el.lint_nde(v, nde)
    assert not [m for r, m in v.items if r == "LINT-NDE-07"]
    assert SE["mls_group_id"], "the SE identifies the superseded group"


def test_the_resubmission_is_a_distinct_chain():
    """The survivor carries a NEW submission: a new message_id (the
    duplicate-message-id intake rule bars reusing the old one for the
    changed group), so no message can be delivered twice."""
    idd = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "resubmits on the surviving group as a NEW submission" in idd
    assert "no message is delivered twice" in idd
    assert "exactly one DE or NDE" in idd


def test_the_id_defines_the_channel_and_the_tie_break():
    idd = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "sm-mls:channel:v1" in idd
    assert "bytewise-smaller `group_id`" in idd
    assert "no election protocol" in idd
