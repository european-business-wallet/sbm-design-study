# SPDX-License-Identifier: MIT
"""D6 — F-10 + X-07: the signed short-lived status capability.

Former defects: (F-10) §5.7 permitted DE issuance on a last-active status
younger than 5 minutes and claimed such a confirmation "cannot conceal a
suspension" — logically false: a suspension immediately after the
confirmation, under partition, is concealed for the residual window.
(X-07) an EDD outage longer than the bound froze qualified delivery with no
deterministic outcome.

D6 (one mechanism, two findings): the EDD core registry issues STATUS-v1 —
a signed, SHORT-LIVED (≤ 5 min) per-UID status assertion sealed under the
registry's own pinned key. An RDP relies on a valid assertion (even
offline); a suspension stops new assertions; at expiry the RDP fails
closed. The false claim is REMOVED and the residual exposure stated openly:
a suspension hides for AT MOST the remaining validity of the last
assertion — bounded and disclosed. An outage longer than the validity has
one deterministic outcome (hold → expiry / recipient-unreachable), never a
freeze, never a stale-active DE.

The timeline below is the F-10 acceptance test: active assertion at T0,
suspension at T0+ε, partition — issuance is admissible only inside the
assertion's validity and fail-closed after.
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


dl = _load("discovery_lint", "discovery_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
ART = json.loads((ROOT / "samples" / "sample-STATUS.json").read_text())
DOC = lc.reconstruct(ART)
DIR = json.loads((ROOT / "samples" / "directory.demo.json").read_text())

# The demo assertion: issued 10:15:00Z, expires 10:20:00Z (5 minutes).
T_ISSUED, T_EXPIRES = DOC["issued_at"], DOC["expires_at"]


def _disc25(doc, directory=DIR, now=None):
    v = dl.Violations()
    dl.lint_status(v, doc, directory=directory, now=now)
    return [m for r, m in v.items if r == "LINT-DISC-25"]


def _resealed(body, kid="edd-registry", seed="edd-registry-demo"):
    return lc.reconstruct(mock.discovery_artifact(body, kid=kid, seed=seed))


# ---------------------------------------------------------------------------
# The capability object: schema + anchor
# ---------------------------------------------------------------------------

def test_the_demo_assertion_is_schema_valid_and_anchored():
    assert not lc.validate_body({k: v for k, v in DOC.items()
                                 if k != "doc_cose_b64"})
    assert not _disc25(copy.deepcopy(DOC)), _disc25(copy.deepcopy(DOC))


def test_negative_an_entity_key_cannot_issue_status():
    """Only the registry issues status: a seal under the entity-admin key —
    validly pinned for the entity's OWN documents — fails the registry pin."""
    body = {k: v for k, v in DOC.items() if k != "doc_cose_b64"}
    forged = _resealed(body, kid="entity-admin", seed="entity-admin-demo")
    assert _disc25(forged), "an entity-key status assertion must fail LINT-DISC-25"


def test_negative_an_overlong_validity_is_rejected():
    """The hard 5-minute bound IS the concealment bound — a longer window
    would silently widen the disclosed exposure."""
    body = {k: v for k, v in DOC.items() if k != "doc_cose_b64"}
    body["expires_at"] = "2026-04-04T11:15:00Z"   # one hour
    assert _disc25(_resealed(body))


def test_negative_merged_without_redirect_is_rejected():
    body = {k: v for k, v in DOC.items() if k != "doc_cose_b64"}
    body["status"] = "merged"
    assert lc.validate_body(copy.deepcopy(body)), "schema must require redirect_uid"
    assert _disc25(_resealed(body))


# ---------------------------------------------------------------------------
# The F-10 timeline: active → suspension → partition, bounded and disclosed
# ---------------------------------------------------------------------------

def test_timeline_issuance_is_admissible_only_within_the_validity():
    """T0 the assertion issues (active). T0+ε the suspension lands and the
    partition begins — no new assertion reaches the RDP. Reliance is
    admissible strictly inside [issued_at, expires_at) and NOWHERE after:
    the concealment window is exactly the assertion residue, ≤ 5 minutes."""
    within = "2026-04-04T10:17:30Z"     # suspension already active: concealed
    at_expiry = "2026-04-04T10:20:00Z"
    after = "2026-04-04T10:21:00Z"
    before = "2026-04-04T10:14:00Z"
    assert not _disc25(copy.deepcopy(DOC), now=within), \
        "inside the window the capability holds (the disclosed residue)"
    assert _disc25(copy.deepcopy(DOC), now=at_expiry), \
        "at expires_at the capability is gone — fail closed"
    assert _disc25(copy.deepcopy(DOC), now=after)
    assert _disc25(copy.deepcopy(DOC), now=before), \
        "not-yet-valid is as unreliable as expired"


def test_the_false_claim_is_gone_and_the_exposure_is_disclosed():
    assert "cannot conceal" not in UMB
    assert "Residual stale-status exposure (stated openly — D6)" in UMB
    assert "bounded and disclosed" in UMB


# ---------------------------------------------------------------------------
# The X-07 outage: deterministic and bounded, never a freeze
# ---------------------------------------------------------------------------

def test_an_outage_longer_than_the_validity_has_one_outcome():
    """Modeled: the registry goes dark at T0+1min; the assertion expires at
    T0+5min. Until expiry the RDP operates (bounded offline); after it,
    reliance fails closed — the prose defines the single outcome per case."""
    during_outage_valid = "2026-04-04T10:19:00Z"
    during_outage_expired = "2026-04-04T10:30:00Z"
    assert not _disc25(copy.deepcopy(DOC), now=during_outage_valid)
    assert _disc25(copy.deepcopy(DOC), now=during_outage_expired)
    assert "EDD outage semantics (deterministic and bounded)" in UMB
    assert "cannot freeze qualified delivery federation-wide" in UMB


def test_the_gate_is_capability_bounded_in_the_prose():
    assert "capability-bounded — D6" in UMB
    assert "valid (unexpired) signed status assertion" in UMB
