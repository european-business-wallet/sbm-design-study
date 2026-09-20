# SPDX-License-Identifier: MIT
"""DR-06 — one expiry rule, stated once, at every grade.

Former defect (round-2 review, High): the I-D's delivery-state section said an
availability DE "MAY post-date `expires_at` and is exempt from the post-dating
rule"; the later Timing section said the exemption was REMOVED and every grade
bounded. The SE schema description still carried the exemption, and a
`bundle_lint` comment still described the old rule while the code enforced the
new one. Two conforming implementations reading the same normative document
could reach opposite conclusions about whether a delivery was legally timely —
and the availability grade, the one grade with no recipient confirmation, is
exactly where the temporal guard carries the most weight.

The surviving rule is X-21's, and it turns on a distinction the removed text
blurred: the EVENT time is bounded (`event_time <= expires_at`, at every
grade); the SEALING time — the qualified timestamp, which is external to the
evidence body — is not. An in-time event sealed late is valid; a late event
sealed promptly is not.

These tests read the SHIPPED prose and schema text directly rather than
trusting the linter, because the defect was precisely that prose and code
disagreed while every code-level test passed.
"""
import copy
import importlib.util
import json
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


bl = _load("bundle_lint", "bundle_lint.py")

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]

ID_TEXT = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()


def _bnd22(evidence):
    issues = bl.check_bundle(SE["recipient_uid"], {}, {}, [], evidence)
    return [m for r, m in issues if r == "LINT-BND-22"]


def _availability_de(delivered_at):
    """The grade the removed exemption applied to: no S3 attestation, so no
    recipient confirmation stands behind the claim."""
    de = copy.deepcopy(DE)
    de["delivery_grade"] = "availability"
    de.pop("s3_attestation", None)
    de["delivered_at"] = delivered_at
    return de


# ---------------------------------------------------------------------------
# The rule, at the grade that used to be exempt
# ---------------------------------------------------------------------------

def test_a_post_expiry_availability_event_is_not_delivered():
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    issues = _bnd22([se, _availability_de("2026-04-07T10:15:01Z")])
    assert issues, "the availability grade must carry no exemption"
    assert "availability included" in issues[0]


def test_the_tie_is_delivered():
    """Equality is defined, not left to the implementer — X-21's rule."""
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    assert not _bnd22([se, _availability_de("2026-04-07T10:15:00Z")])


def test_an_in_time_event_sealed_after_expiry_is_still_delivered():
    """The distinction the removed text blurred. The sealing instant is the
    qualified timestamp, which is EXTERNAL to the evidence body — so the
    linter must have no path from any in-body field to a late-sealing
    rejection. Verified structurally: the only field LINT-BND-22 reads for a
    DE is the event time, and moving the sealing instant arbitrarily late
    cannot change the verdict because it is not in the body at all."""
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    in_time = _availability_de("2026-04-07T10:14:59.999Z")
    assert not _bnd22([se, in_time])
    # no in-body timestamp names the sealing act, at any grade
    for grade_de in (in_time, copy.deepcopy(DE)):
        assert not [k for k in grade_de
                    if re.search(r"seal|issued|qualified|tsa", k, re.I)], \
            "a sealing instant appeared in the evidence body — DR-06's " \
            "event/seal distinction would need re-checking"


def test_the_verification_grade_is_bounded_by_the_same_rule():
    """One rule means the arms are not written per grade."""
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    de = copy.deepcopy(DE)
    de["delivered_at"] = "2026-04-07T10:15:00.001Z"
    assert _bnd22([se, de])


# ---------------------------------------------------------------------------
# The prose and the schema say what the code does
# ---------------------------------------------------------------------------

def _normalise(s):
    return " ".join(s.replace("**", "").replace("`", "").split())


def test_no_normative_text_states_the_removed_exemption():
    body = _normalise(ID_TEXT)
    for phrase in ("exempt from the post-dating rule",
                   "MAY post-date expires_at",
                   "expiry does not apply"):
        assert phrase.lower() not in body.lower(), \
            f"the removed availability exemption is back in the I-D: {phrase!r}"


def test_the_id_states_the_event_seal_distinction_where_expiry_is_defined():
    """Not merely silent — the rule that replaced it is stated at the site the
    contradiction lived."""
    i = ID_TEXT.index("Expiry per grade.")
    para = _normalise(ID_TEXT[i:i + 1400])
    assert "event_time <= expires_at" in para
    assert "NO exemption" in para
    assert "sealing" in para.lower() and "tie" in para.lower()


def test_the_se_schema_description_agrees_with_the_id():
    desc = _normalise(json.loads(
        (ROOT / "schemas" / "evidence-se.schema.json").read_text()
    )["properties"]["expires_at"]["description"])
    assert "except at the availability grade" not in desc
    assert "EVENT time must not post-date expires_at AT ANY GRADE" in desc


def test_doc_lint_forbids_the_exemption_in_both_directions():
    """A guard, so the contradiction cannot be reintroduced by either half."""
    src = (ROOT / "scripts" / "doc_lint.py").read_text()
    assert "exempt from the post-dating rule" in src
    assert "MAY post-date" in src
