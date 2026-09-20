# SPDX-License-Identifier: MIT
"""X-08 — the OpenID4VP ceremony is out-of-band; the binding is the profile's.

Former defect: §10.2's numbered flow exchanged Authorization Request and VP
Token wallet-to-wallet BEFORE the MLS group existed — while the
architecture forbids direct P2P connections and recipients are
asynchronous/offline — with no carrier, correlation, timeout or replay
binding; the `+oidc4vp` auth_method suffix could claim a ceremony from any
session.

Chosen resolution (approved): the ceremony is deployment-specific
OUT-OF-BAND guidance (no transport defined; never over the messaging path;
skip-by-default), and the profile owns the BINDING — the OID4VP nonce MUST
include the F-06 channel_id of the authorised (entity pair, scope)
(computable before any group exists), the transcript MUST be retained under
the §4.3 duty, and only then may `+oidc4vp` be claimed. The suffixed
methods are registered in auth-assurance.json so LINT-AUTH-03 assesses
them.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
FLAT = " ".join(UMB.split()).replace("**", "").replace("`", "")
REG = json.loads((ROOT / "registries" / "auth-assurance.json").read_text())
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def test_the_p2p_flow_is_gone():
    """The former defect: a wallet-to-wallet exchange before the group."""
    assert "WU-S sends an OpenID4VP Authorization Request to WU-R" not in UMB
    assert "WU-R responds with a VP Token" not in UMB


def test_the_ceremony_is_out_of_band_and_skippable():
    assert "no OpenID4VP transport" in FLAT
    assert "never over the messaging path" in FLAT
    assert "skipping it is the default" in FLAT


def test_the_binding_is_channel_bound_and_retained():
    assert "MUST include the channel_id" in FLAT
    assert "computable before any MLS group exists" in FLAT
    assert "MUST retain the ceremony transcript" in FLAT
    assert "unsupported and MUST NOT be made" in FLAT


def test_negative_a_foreign_transcript_cannot_support_the_claim():
    assert ("A transcript whose nonce binds a different channel is a replay"
            in FLAT)


def test_the_suffixed_methods_are_registered_with_the_binding_note():
    for method in ("mls-x509+oidc4vp", "mls-uid-qeaa+oidc4vp", "mls-uid-qeaa"):
        assert method in REG["methods"], method
    note = REG["methods"]["mls-x509+oidc4vp"]["note"]
    assert "channel-bound" in note and "RETAINED transcript" in note
    assert "not LoA" in note, "the ceremony adds policy enforcement, not LoA"


def _auth03(body):
    v = el.Violations()
    el.lint_se(v, body)
    return ([m for r, m in v.items if r == "LINT-AUTH-03"],
            [m for r, m in v.items if r == "LINT-AUTH-W1"])


def test_lint_assesses_the_registered_methods():
    """An SE claiming the ceremony at an admissible LoA passes; above the
    method's ceiling it FAILS; and it is never 'unknown' (no W1)."""
    ok = copy.deepcopy(SE)
    ok["auth_method"] = "mls-x509+oidc4vp"
    ok["auth_context"]["method"] = "mls-x509+oidc4vp"
    bad3, warn = _auth03(ok)
    assert not bad3 and not warn, (bad3, warn)
    over = copy.deepcopy(ok)
    over["auth_context"]["loa"] = "very-high"   # above the registered ceiling
    bad3, _ = _auth03(over)
    assert bad3, "the ceremony does not elevate LoA above the base ceiling"
