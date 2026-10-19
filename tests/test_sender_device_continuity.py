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
