# SPDX-License-Identifier: MIT
"""X-06 — merge lifecycle: atomic transitions, no transport rerouting.

Former defect: the state machine permitted `merged` only from `retired`
(operational mergers begin from live entities, and the intermediate retired
state had no redirect), and §4.4 said in-flight messages "SHOULD be rerouted
by the resolver" — invalid: a resolver never handles payloads, and a
PrivateMessage encrypted to the old group cannot be delivered to the
surviving entity's leaves or legally re-addressed without the sender.

Now: `active|suspended|retired → merged` are all permitted, each atomic with
the §5.6 redirect record published in the same signed act; the rerouting
sentence is deleted and doc_lint-FORBIDDEN; the in-flight outcome is NDE
`uid-merged` + `redirect_uid` (schema-REQUIRED), and only the sender
re-addresses via a new submission with a new SE.
"""
import copy
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")
el = _load("evidence_lint", "evidence_lint.py")

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]


# ---------------------------------------------------------------------------
# The state machine: a merger from any live state, never redirect-less
# ---------------------------------------------------------------------------

def test_merged_is_reachable_from_every_operational_state():
    assert "| active | merged |" in UMB
    assert "| suspended | merged |" in UMB
    assert "| retired | merged |" in UMB


def test_the_live_transitions_are_atomic_with_the_redirect():
    """No instant exists in which the UID is merged without its redirect."""
    row = next(line for line in UMB.splitlines()
               if line.startswith("| active | merged |"))
    assert "same signed act" in row


# ---------------------------------------------------------------------------
# No transport rerouting; the sender re-addresses
# ---------------------------------------------------------------------------

def test_the_rerouting_sentence_is_gone_and_forbidden():
    assert not re.search(r"rerouted? by the resolver", UMB, re.I)
    former = ("Messages addressed to the merged UID SHOULD be rerouted "
              "by the resolver if the redirect is active")
    assert any(p.search(former) for p in dl.FORBIDDEN), \
        "doc_lint must forbid the resolver-rerouting phrasing"


def test_only_the_sender_re_addresses():
    assert "new submission with a new SE" in UMB
    assert "Only an authorised sender changes the legal addressee" in UMB


# ---------------------------------------------------------------------------
# The in-flight outcome: NDE uid-merged + redirect, at any stage of the table
# ---------------------------------------------------------------------------

def test_uid_merged_nde_requires_the_redirect():
    bad = copy.deepcopy(NDE)
    bad["reason"] = "uid-merged"
    bad["event"] = "D.2-ContentConsignmentFailure"
    assert lc.validate_body(bad), "uid-merged without redirect_uid must fail schema"
    ok = copy.deepcopy(bad)
    ok["redirect_uid"] = "EU-DE-EOID-7K3D9W0Q2M5FW0"
    assert not lc.validate_body(ok)


def test_merger_timeline_every_stage_has_a_valid_outcome():
    """A merger discovered at intake, at relay or at consignment yields the
    same reason with the stage's event — no state lacks the redirect path."""
    for event in ("A.2-SubmissionRejection", "B.3-RelayFailure",
                  "D.2-ContentConsignmentFailure"):
        nde = copy.deepcopy(NDE)
        nde["reason"] = "uid-merged"
        nde["event"] = event
        nde["redirect_uid"] = "EU-DE-EOID-7K3D9W0Q2M5FW0"
        if event == "A.2-SubmissionRejection":
            # F-14 (2.6): the intake stage carries the SUBMISSION domain
            nde["submission_hash"] = nde.pop("payload_hash")
        assert not lc.validate_body(nde), event
        v = el.Violations()
        el.lint_nde(v, nde)
        assert not [m for r, m in v.items if r == "LINT-NDE-07"], event
