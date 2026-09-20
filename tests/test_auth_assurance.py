# SPDX-License-Identifier: MIT
"""X-27 — assurance-level requirements are enforceable.

Former defect: schemas permitted any loa (`substantial`, `n/a`, …) with no
object-specific floors anywhere; the reference SE used `substantial` beneath
a high-confidence claim; `method` was a free string nothing assessed. The
finding warns a naive scalar ordering would be unsafe — the required
assurance depends on the full method/combination.

Machinery (evidence 2.4): `registries/auth-assurance.json` is an explicit
admissible-TUPLE table — each REGISTERED method carries the LoA labels it
can truthfully claim, each evidence context (se-submission split by
origin_proof; de-confirmation split by wallet-signed vs session;
de-availability; re-member-refusal; gcm-dispute) its admissible
(identity, loa) tuples, with combined-factor ELEVATION stated where a wallet
signature admits a substantial session the session-only arm does not.
LINT-AUTH-03 enforces fail-closed; an unregistered well-formed method warns
(LINT-AUTH-W1) and is treated as unassessed.

TODO(legal): the adopted floors are the pilot profile's PROVISIONAL set —
which combinations satisfy which Regulation (EU) No 910/2014 obligations per
context awaits counsel review and is left OPEN; nothing here asserts legal
sufficiency.

Negative fixtures: a registered method claiming above its ceiling; a
provider-attested SE at substantial; a session-only acceptance DE at
substantial; a session-only member refusal at substantial; `n/a` in an
evidence context. Every reference evidence object demonstrates an allowed
tuple.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]
DEAV = json.load(open(ROOT / "samples" / "sample-DE-availability.json"))["projection"]
RE = json.load(open(ROOT / "samples" / "sample-RE.json"))["projection"]
GCM = json.load(open(ROOT / "samples" / "sample-GCM.json"))["projection"]


def _auth(fn, body, **kw):
    v = el.Violations()
    fn(v, body, **kw)
    return ([m for r, m in v.items if r == "LINT-AUTH-03"],
            [m for r, m in v.items if r == "LINT-AUTH-W1"])


# ---------------------------------------------------------------------------
# Every reference evidence object demonstrates an allowed tuple
# ---------------------------------------------------------------------------

def test_every_shipped_object_carries_an_admissible_tuple():
    for fn, body in ((el.lint_se, SE), (el.lint_de, DE), (el.lint_de, DEAV),
                     (el.lint_re, RE), (el.lint_gcm, GCM)):
        bad, warn = _auth(fn, copy.deepcopy(body))
        assert not bad, (body.get("type"), bad)
        assert not warn, (body.get("type"), warn)


def test_the_reference_se_is_admissible_only_because_it_is_sender_signed():
    """The finding's exhibit: mls-x509/substantial under a high-confidence
    claim. The sender-signed elevation row admits it; the provider-attested
    arm (leaning wholly on the session) does not."""
    ok = copy.deepcopy(SE)
    assert ok["auth_context"]["loa"] == "substantial"
    assert not _auth(el.lint_se, ok)[0]
    narrowed = copy.deepcopy(SE)
    narrowed["origin_proof"] = "provider-attested"
    narrowed.pop("sender_confirmation")
    assert _auth(el.lint_se, narrowed)[0], \
        "a provider-attested SE at substantial must fail LINT-AUTH-03"


# ---------------------------------------------------------------------------
# The method's own ceiling (no scalar ordering)
# ---------------------------------------------------------------------------

def test_negative_a_registered_method_cannot_claim_above_its_ceiling():
    bad = copy.deepcopy(SE)
    bad["auth_context"]["method"] = "password-otp"
    bad["auth_method"] = "password-otp"
    bad["auth_context"]["loa"] = "very-high"
    assert any("cannot claim loa" in m for m in _auth(el.lint_se, bad)[0])
    bad = copy.deepcopy(SE)
    bad["auth_context"]["loa"] = "very-high"   # mls-x509 caps at high
    assert any("cannot claim loa" in m for m in _auth(el.lint_se, bad)[0])


def test_negative_na_is_admissible_in_no_evidence_context():
    bad = copy.deepcopy(DE)
    bad["auth_context"]["loa"] = "n/a"
    assert _auth(el.lint_de, bad)[0]


# ---------------------------------------------------------------------------
# Context floors: the session-only arms require high+
# ---------------------------------------------------------------------------

def test_negative_session_only_acceptance_de_at_substantial_fails():
    bad = copy.deepcopy(DE)
    bad["s3_attestation"].pop("wallet_signature_b64", None)
    bad["s3_attestation"]["session_authenticated"] = True
    bad["auth_context"]["method"] = "password-otp"
    bad["recipient_auth_method"] = "password-otp"
    bad["auth_context"]["loa"] = "substantial"
    assert _auth(el.lint_de, bad)[0], \
        "a session-only confirmation DE at substantial must fail the floor"


def test_wallet_signed_confirmation_elevates_a_substantial_session():
    ok = copy.deepcopy(DE)   # s3 is wallet-signed in the walletsig... check arm
    ok["s3_attestation"]["wallet_signature_b64"] = "A" * 96
    ok["s3_attestation"].pop("session_authenticated", None)
    ok["auth_context"]["method"] = "password-otp"
    ok["recipient_auth_method"] = "password-otp"
    ok["auth_context"]["loa"] = "substantial"
    assert not _auth(el.lint_de, ok)[0], \
        "the wallet-signed arm admits a substantial session (elevation)"


def test_negative_session_only_member_refusal_at_substantial_fails():
    bad = copy.deepcopy(RE)
    rc = bad["refusal_confirmation"]
    rc.pop("wallet_signature_b64", None); rc.pop("device_id", None)
    rc["session_authenticated"] = True
    bad["auth_context"]["method"] = "password-otp"
    bad["auth_context"]["loa"] = "substantial"
    assert _auth(el.lint_re, bad)[0]


# ---------------------------------------------------------------------------
# Unregistered methods: accepted, warned, unassessed
# ---------------------------------------------------------------------------

def test_an_unregistered_method_warns_and_is_not_a_violation():
    odd = copy.deepcopy(SE)
    odd["auth_context"]["method"] = "x-carrier-pigeon-attest"
    odd["auth_method"] = "x-carrier-pigeon-attest"
    bad, warn = _auth(el.lint_se, odd)
    assert not bad, "an unregistered method must not hard-fail"
    assert warn and "unassessed" in warn[0].lower() or "UNASSESSED" in warn[0]


# ---------------------------------------------------------------------------
# The registry states its provisional status
# ---------------------------------------------------------------------------

def test_the_floors_are_marked_pilot_provisional_and_legal_open():
    reg = json.loads((ROOT / "registries" / "auth-assurance.json").read_text())
    c = reg["$comment"]
    assert "PILOT-PROVISIONAL" in c and "TODO(legal)" in c
