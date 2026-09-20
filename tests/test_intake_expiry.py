# SPDX-License-Identifier: MIT
"""Round 10 / B6 — R10-08: X-22 is enforced AT INTAKE, before anything moves.

The I-D requires intake to reject a non-positive TTL, a TTL above the
recipient's declared maximum (absent = P30D), and a `sent_at` more than five
minutes ahead of the RDP's clock. Intake ran none of these: correctly signed
submissions violating each were SEALED and moved the submission, DS and SE
ledgers to [1, 1, 1], and the violation surfaced only when the sealed SE was
linted afterwards. The review's instruction for these tests: "do not replace
these with tests that detect the violation only after sealing."

So every case goes through `submit`, and asserts the ledgers — refused cases
leave all three EMPTY, accepted boundary cases fill all three — with each
submission's sender confirmation re-signed over its own tuple, so the only
thing wrong with a refused one is its expiry.
"""
import copy
import hashlib
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import lint_cli as lc  # noqa: E402
import test_current_claims as tc  # noqa: E402
import test_intake_obligations as t  # noqa: E402

CLOCK = "2026-04-04T10:15:00Z"          # the accepting RDP's own clock
SENT = t.SE["sent_at"]                  # == CLOCK


def _plus(iso, **delta):
    import datetime
    return (lc.instant(iso) + datetime.timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _submit(org=None, **over):
    """A FRESH reference, so all three ledgers start empty."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    meta = t._meta(**over)
    try:
        m.submit(meta, org=org or t.ORG, members=t.MEMBERS, server_clock=CLOCK)
        outcome = "sealed"
    except m.SubmissionRejected as e:
        outcome = e.reason
    return outcome, [len(m._SUBMISSION_LEDGER), len(m._DS_LEDGER), len(m._SE_LEDGER)]


def _org_with_max(max_ttl):
    """A BW-ORG declaring `max_ttl`, and the policy reference that pins its
    REAL digest — so the maximum is the recipient's, correctly pinned."""
    org = dict(copy.deepcopy(t.ORG), max_ttl=max_ttl)
    ref = copy.deepcopy(t.SE["acceptance_policy_ref"])
    ref["doc_digest"] = {"alg": "SHA-256", "hash_mode": "raw-sha256",
                         "hex": hashlib.sha256(lc.dcbor(org)).hexdigest()}
    return org, ref


# ---------------------------------------------------------------------------
# The review's five cases — refused, nothing moved
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("over,reason", [
    ({"expires_at": SENT}, "expiry-not-after-sent"),
    ({"expires_at": _plus(SENT, seconds=-1)}, "expiry-not-after-sent"),
    ({"expires_at": _plus(SENT, days=31)}, "expiry-beyond-max-ttl"),
    ({"sent_at": _plus(CLOCK, hours=24), "expires_at": _plus(CLOCK, hours=48)},
     "sent-at-in-future"),
], ids=["expiry==sent", "expiry-1s", "ttl-31d-default", "sent-24h-ahead"])
def test_each_violation_is_refused_before_anything_moves(over, reason):
    outcome, ledgers = _submit(**over)
    assert outcome == reason
    assert ledgers == [0, 0, 0], "a refused submission moved a ledger"


def test_a_ttl_above_the_recipients_pinned_maximum_is_refused():
    """The fifth case, which Phase 1 did not re-run: a BW-ORG declaring
    `max_ttl: P1D`, correctly pinned. The control — the same pin, a one-day
    TTL — SEALS, so the refusal can only be the expiry rule."""
    org, ref = _org_with_max("P1D")
    assert _submit(org=org, acceptance_policy_ref=ref,
                   expires_at=_plus(SENT, days=1)) == ("sealed", [1, 1, 1])
    assert _submit(org=org, acceptance_policy_ref=ref,
                   expires_at=_plus(SENT, days=2)) == ("expiry-beyond-max-ttl", [0, 0, 0])


# ---------------------------------------------------------------------------
# Just inside, at, and just outside every bound
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("over,outcome", [
    ({"expires_at": _plus(SENT, seconds=1)}, "sealed"),                       # ordering: just inside
    ({"expires_at": _plus(SENT, days=30)}, "sealed"),                         # TTL: AT the default max
    ({"expires_at": _plus(SENT, days=30, seconds=1)}, "expiry-beyond-max-ttl"),
    ({"sent_at": _plus(CLOCK, minutes=5),
      "expires_at": _plus(CLOCK, days=1)}, "sealed"),                         # clock: AT the bound
    ({"sent_at": _plus(CLOCK, minutes=5, seconds=1),
      "expires_at": _plus(CLOCK, days=1)}, "sent-at-in-future"),
], ids=["ttl=1s", "ttl=P30D", "ttl=P30D+1s", "sent=clock+5m", "sent=clock+5m+1s"])
def test_the_bounds(over, outcome):
    got, ledgers = _submit(**over)
    assert got == outcome
    assert ledgers == ([1, 1, 1] if outcome == "sealed" else [0, 0, 0])


# ---------------------------------------------------------------------------
# One rule, three callers
# ---------------------------------------------------------------------------

def _retained(se_body, org=None):
    """What the two retained checks say about an SE: LINT-DE-18 from the
    evidence linter, LINT-BND-27 from the bundle linter."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("ev_b6", ROOT / "scripts" / "evidence_lint.py")
    ev = importlib.util.module_from_spec(spec); spec.loader.exec_module(ev)
    v = ev.Violations(); ev.lint_se(v, se_body)
    import bundle_lint as bl
    bnd = bl.check_bundle(se_body["recipient_uid"], {}, org or {}, [], [se_body])
    return ({r for r, _ in v.items} | {r for r, _ in bnd}) & {"LINT-DE-18", "LINT-BND-27"}


@pytest.mark.parametrize("over,intake,retained", [
    ({"expires_at": SENT}, "expiry-not-after-sent", {"LINT-DE-18"}),
    ({"expires_at": _plus(SENT, days=31)}, "expiry-beyond-max-ttl", {"LINT-BND-27"}),
    ({"expires_at": _plus(SENT, days=30)}, "sealed", set()),
], ids=["zero-ttl", "ttl-31d", "ttl-30d"])
def test_intake_and_the_retained_checks_agree(over, intake, retained):
    """One rule, three callers, the same verdict on the same input. A second
    statement of X-22 is how intake came to run none of it while the retained
    check's own comment said intake did."""
    assert _submit(**over)[0] == intake
    assert _retained(dict(t.SE, **over)) == retained


def test_the_bundle_check_refuses_an_unreadable_maximum_instead_of_defaulting():
    """The deleted private parser returned None for a maximum it could not
    read, and the caller used thirty days — so a ten-day TTL passed a
    recipient whose declared maximum was a week. Now it is reported."""
    ten_days = dict(t.SE, expires_at=_plus(SENT, days=10))
    assert _retained(ten_days, org={"max_ttl": "P1W"}) == {"LINT-BND-27"}


def test_an_unreadable_declared_maximum_is_refused_not_defaulted():
    """The deleted private parser turned "I cannot read the maximum" into "the
    maximum is thirty days". The shared one refuses."""
    assert lc.expiry_problems(SENT, _plus(SENT, days=1), max_ttl="P1W")[0][0] \
        == "policy-unresolvable"
    with pytest.raises(ValueError):
        lc.parse_iso_duration("P1W")
