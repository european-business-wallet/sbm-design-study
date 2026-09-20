# SPDX-License-Identifier: MIT
"""Round 11 / B3 — R11-04: each grade is dated by its own event.

The I-D dated delivery by S2 at the availability grade and by S3/S4 at the
verification and acceptance grades. The DS contract told every DE issuer to
copy the receipt's `server_time` — the S2 instant — whatever the grade; the
diagram and the reference helper taught the same; and the I-D itself said so
in its S2 paragraph. The review's counterexample: S2 at 10:00, expiry at 10:05,
the second quorum member confirming at 10:10. Following the contract yields a
timely DE; following the I-D cannot. And the retained verifier could not tell:
a DE dated before its own attestation and both quorum acknowledgements linted
clean, because no rule related `delivered_at` to the acts it dates.

R11-X2: at the verification and acceptance grades `delivered_at` is the
instant RDP(in) observed the confirmation that completed the policy. The
review's acceptance: "One trace contains separate S2, S3, quorum/S4, expiry and
seal times. Before/at/after-expiry decisions agree at all three grades; a
pre-expiry S2 cannot make a post-expiry S4 timely."
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_current_claims as tc  # noqa: E402

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
BASE_SE, ORG = _ld("sample-SE.json"), _ld("sample-BW-ORG.json")
MEMBERS = [_ld("sample-BW-MEMBER-fr.json"), _ld("sample-BW-MEMBER-fr2.json")]
S3, DE = _ld("sample-DE.json")["s3_attestation"], _ld("sample-DE.json")
FR, A, B = BASE_SE["recipient_uid"], "F1N2C3D4P", "F2X3Y4Z55"

# THE TRACE — every instant distinct.
SENT = "2026-04-04T10:15:00Z"
S2 = "2026-04-04T10:16:00Z"        # the DS observed the acknowledged handover
A_VERIFIED, A_SEEN = "2026-04-04T10:17:30Z", "2026-04-04T10:18:00Z"   # first member
EXPIRY = "2026-04-04T10:20:00Z"
B_VERIFIED, B_SEEN = "2026-04-04T10:24:30Z", "2026-04-04T10:25:00Z"   # completes quorum:2
SEALED = "2026-04-04T10:26:00Z"    # the DE's qualified timestamp — issuance, never the event


def _m():
    return tc._load("mock_rdp", "mock_rdp.py")


def _ev():
    spec = importlib.util.spec_from_file_location("ev_b3", ROOT / "scripts" / "evidence_lint.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _se(policy_key, expires=EXPIRY):
    se = copy.deepcopy(BASE_SE)
    se.update(sent_at=SENT, expires_at=expires,
              message_id=f"01HZR11B3CLOCK{policy_key.upper()[:6]:0<6}00000")
    se["acceptance_policy_ref"] = dict(se["acceptance_policy_ref"], policy_key=policy_key)
    return se


def _confirm(m, se, mid, verified, seen):
    conf = dict(copy.deepcopy(S3), mid=mid, verified_at=verified,
                message_id=se["message_id"],
                acceptance_policy_ref=copy.deepcopy(se["acceptance_policy_ref"]))
    return m.deliver_confirmation(
        {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
         "confirmation_kind": "s3", "confirmation": conf},
        credential={"kind": "member", "uid": FR, "mid": mid}, se=se,
        rdp_id="urn:sbm:rdp:mockeu-002", observed_at=seen,
        members=MEMBERS, org=ORG)


def _decide(m, se, grade):
    return m.delivery_decision(se, grade, s2_at=S2,
                               state=m.confirmation_state(se["rdp_id"], se["message_id"]))


# ---------------------------------------------------------------------------
# The issuer — one trace, three grades
# ---------------------------------------------------------------------------

def test_the_three_grades_are_dated_by_their_own_events():
    m = _m()
    avail = _se("invoices")                       # the grade does not depend on the key
    assert _decide(m, avail, "availability") == {"outcome": "delivered", "delivered_at": S2}

    verif = _se("invoices")                       # any-one over F2X3Y4Z55
    _confirm(m, verif, B, "2026-04-04T10:18:30Z", "2026-04-04T10:19:00Z")
    assert _decide(m, verif, "verification") == \
        {"outcome": "delivered", "delivered_at": "2026-04-04T10:19:00Z"}

    accept = _se("procurement")                   # quorum:2 — the review's counterexample
    _confirm(m, accept, A, A_VERIFIED, A_SEEN)
    assert _decide(m, accept, "acceptance")["outcome"] == "pending"
    _confirm(m, accept, B, B_VERIFIED, B_SEEN)
    assert _decide(m, accept, "acceptance") == {"outcome": "expired", "delivered_at": None}, \
        "a pre-expiry S2 made a post-expiry S4 timely"


@pytest.mark.parametrize("completing,outcome", [
    ("2026-04-04T10:19:59Z", "delivered"),
    (EXPIRY, "delivered"),                        # a tie is delivered
    ("2026-04-04T10:20:01Z", "expired"),
], ids=["before", "at", "after"])
def test_the_acceptance_boundary(completing, outcome):
    m = _m()
    se = _se("procurement")
    _confirm(m, se, A, A_VERIFIED, A_SEEN)
    _confirm(m, se, B, "2026-04-04T10:19:00Z", completing)
    assert _decide(m, se, "acceptance")["outcome"] == outcome


@pytest.mark.parametrize("s2,outcome", [
    ("2026-04-04T10:19:59Z", "delivered"), (EXPIRY, "delivered"),
    ("2026-04-04T10:20:01Z", "expired"),
], ids=["before", "at", "after"])
def test_the_availability_boundary(s2, outcome):
    m = _m()
    assert m.delivery_decision(_se("invoices"), "availability", s2_at=s2)["outcome"] == outcome


def test_a_confirmation_dated_after_its_own_receipt_is_refused():
    """`delivered_at` will be RDP(in)'s receipt; a wallet clock running ahead
    would make the DE date its delivery before the act it embeds."""
    m = _m()
    se = _se("invoices")
    with pytest.raises(m.ConfirmationRejected) as exc:
        _confirm(m, se, B, "2026-04-04T10:19:01Z", "2026-04-04T10:19:00Z")
    assert exc.value.reason == "confirmation-time-invalid"
    assert m._CONFIRMATION_ACTS == {} and m._CONFIRMATION_STATE == {}


# ---------------------------------------------------------------------------
# The retained verifier agrees
# ---------------------------------------------------------------------------

def _de(se, delivered_at):
    de = copy.deepcopy(DE)
    de.update(message_id=se["message_id"], delivered_at=delivered_at)
    de["s3_attestation"] = dict(de["s3_attestation"], verified_at=A_VERIFIED,
                                message_id=se["message_id"])
    de["quorum"] = [dict(q, ack_at=at, message_id=se["message_id"])
                    for q, at in zip(de["quorum"], (A_SEEN, B_SEEN))]
    return de


def _retained(se, de):
    ev = _ev(); v = ev.Violations(); ev.lint_de(v, de)
    import bundle_lint as bl
    bnd = bl.check_bundle(se["recipient_uid"], {}, {}, [], [se, de])
    return ({r for r, _ in v.items} | {r for r, _ in bnd}) & {"LINT-DE-21", "LINT-BND-22"}


def test_a_de_dated_by_the_s2_receipt_is_caught():
    """The review's counterexample as a retained DE: `delivered_at` copied
    from the S2 receipt, as the DS contract instructed, before both quorum
    acknowledgements. Before B3 this linted clean."""
    assert _retained(_se("procurement"), _de(_se("procurement"), S2)) == {"LINT-DE-21"}


def test_the_true_s4_instant_is_judged_late_as_the_issuer_judged_it():
    se = _se("procurement")
    assert _retained(se, _de(se, B_SEEN)) == {"LINT-BND-22"}
    in_time = _se("procurement", expires=B_SEEN)            # the deadline at S4 exactly
    assert _retained(in_time, _de(in_time, B_SEEN)) == set()


def test_the_sealing_instant_is_not_the_event():
    """A DE sealed after the deadline whose EVENT is in time is valid; the
    qualified timestamp is issuance, never delivery."""
    import lint_cli as lc
    se = _se("procurement", expires=B_SEEN)
    assert lc.instant(SEALED) > lc.instant(se["expires_at"])
    assert _retained(se, _de(se, B_SEEN)) == set()


def test_issuer_and_verifier_share_one_timeliness_rule():
    """LINT-BND-22 and `delivery_decision` both call `lint_cli.in_time`; the
    rule used to be a private comparison in the linter."""
    import lint_cli as lc
    assert lc.in_time(EXPIRY, EXPIRY) and not lc.in_time("2026-04-04T10:20:01Z", EXPIRY)
    assert lc.in_time("2026-04-04T12:20:00+02:00", EXPIRY), "an instant, not a string"
    with pytest.raises(lc.TimestampError):
        lc.in_time("not a time", EXPIRY)
