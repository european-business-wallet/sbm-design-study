# SPDX-License-Identifier: MIT
"""F-03 — the exact MLS state, historically verifiable.

Former defect: group_id+epoch alone did not pin the ratchet tree/transcript, the
2.1 mls_state omitted the cipher suite and extensions, and no verification
procedure from evidence time existed. Evidence 2.2's MlsStateHash commits to the
whole TLS-serialized GroupContext; the provider retains the GroupContext + tree
(the demo fixtures are deterministically rebuildable), and the verifier's
procedure is: resolve GroupContext -> recompute hash == mls_state -> verify the
tree against the GroupContext's tree_hash.

Negative fixture: two forks sharing group_id+epoch produce DIFFERENT commitments
— their evidence is not interchangeable.
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_wire as w  # noqa: E402

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]


def test_verification_from_evidence_time_linkage():
    """The full procedure on a shipped confirmation: retained GroupContext ->
    hash equals the evidence mls_state -> the retained tree verifies against the
    GroupContext's tree_hash."""
    gid, epoch = SE["mls_group_id"], SE["mls_epoch"]
    # (1) resolve the retained historical GroupContext (demo: deterministic)
    gc = w.demo_group_context(gid, epoch)
    # (2) recompute the commitment == the evidence mls_state (SE and confirmation)
    expected = {"format": "mls10-group-context", "hex": hashlib.sha256(gc).hexdigest()}
    assert SE["mls_state"] == expected
    assert DE["s3_attestation"]["mls_state"] == expected
    # (3) the retained ratchet tree verifies against the GroupContext's tree_hash
    tree = w.demo_tree_hash(gid, epoch)
    assert tree in gc, "the GroupContext must embed the tree_hash it commits to"


def test_negative_two_forks_sharing_group_and_epoch_differ():
    """The acceptance criterion: forks with the same (group_id, epoch) but
    diverging state produce DIFFERENT mls_state commitments."""
    gid, epoch = SE["mls_group_id"], SE["mls_epoch"]
    gc_a = w.demo_group_context(gid, epoch)
    # fork B: same group_id+epoch, different tree (a diverged membership)
    gc_b = w.serialize_group_context(
        w.CIPHER_SUITE_BASELINE, w._b64url_decode(gid), int(epoch),
        hashlib.sha256(b"forked tree").digest(),
        hashlib.sha256(f"transcript:{gid}:{epoch}".encode()).digest())
    assert gc_a != gc_b
    assert w.mls_state_hash(gc_a) != w.mls_state_hash(gc_b), (
        "two forks sharing group_id+epoch must not be interchangeable")


def test_cipher_suite_and_extensions_are_inside_the_commitment():
    """F-03's residue: suite/extensions were outside the 2.1 pair — now any
    change to either changes the commitment."""
    gid, epoch = SE["mls_group_id"], SE["mls_epoch"]
    base = w.demo_group_context(gid, epoch)
    other_suite = w.demo_group_context(gid, epoch, cipher_suite=0x0002)
    # DR-01: extensions are PAIRS now, never pre-vectored bytes — passing
    # bytes is what produced the double length prefix.
    with_ext = w.demo_group_context(gid, epoch, extensions=[(0x0001, b"ab")])
    assert len({w.mls_state_hash(x)["hex"] for x in (base, other_suite, with_ext)}) == 3


def test_retention_duty_is_stated():
    idtxt = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "MLS state retention and historical verification" in idtxt
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    assert "MLS GroupContext and ratchet tree/GroupInfo" in umb
