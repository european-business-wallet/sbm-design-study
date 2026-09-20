# SPDX-License-Identifier: MIT
"""X-26 — sender multi-device continuity.

Former defect: for scoped (and default) groups a default-only sender
contributed ONLY the author leaf — the member's other active devices could
not decrypt the thread, contradicting multi-device recovery, and replies,
author-device loss and later device addition were unspecified.

Chosen model (approved): ALL active enrolled devices of the SENDING MEMBER
join the group (the member's continuity — not the whole entity). Loss of
the authoring device leaves the member's other devices with access; a
replacement joins via the existing device lifecycle; revocation via the
existing role-lifecycle Remove; sender-side leaves never count toward the
recipient's acceptance policy.
"""
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")

IDD = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()


def test_the_single_author_leaf_model_is_gone_and_forbidden():
    assert not re.search(r"only its (own )?author leaf", IDD, re.I)
    former = ("the sender contributes only its author leaf and there is "
              "nothing sender-side to gate")
    assert any(p.search(former) for p in dl.FORBIDDEN), \
        "doc_lint must forbid the single-author-leaf phrasing"


def test_all_member_devices_join_the_group():
    assert "all active enrolled devices of the sending member" in IDD.lower()


def test_author_device_loss_has_a_defined_recovery_outcome():
    assert "loss of the authoring device has a defined recovery outcome" in IDD.lower()
    assert "remaining devices retain access" in IDD
    assert "BW-MEMBER republication, then\nAdd + Commit" in IDD or \
        "BW-MEMBER republication" in IDD


def test_sender_leaves_never_count_toward_acceptance():
    assert "Sender-side leaves NEVER count toward the recipient's acceptance policy" in IDD
    assert "a sender device's\nacknowledgement satisfies nothing" in IDD or \
        "acknowledgement satisfies nothing" in IDD


def test_scoped_senders_stay_descriptor_gated():
    assert "additionally gated by its own scope descriptor" in IDD


def test_roster_transparency_still_verifies_sender_leaves():
    """The continuity model widens the sender's roster; the transparency
    duty (each entity's leaves verified against its own documents) stays."""
    assert "verified against its BW-MEMBER" in IDD or \
        "verified against **its own**" in IDD
