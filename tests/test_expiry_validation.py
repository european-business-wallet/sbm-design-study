# SPDX-License-Identifier: MIT
"""X-22 — expires_at is validated, not echoed.

Former defect: the sender computed expires_at from its own clock and the RDP
echoed it verbatim — no check ordered it after sent_at, bounded the TTL by
policy, or compared the envelope ttl with the committed expiry. Now:
LINT-DE-18 (ordering), LINT-BND-27 (TTL <= BW-ORG max_ttl, default P30D), and
the envelope-mismatch typed outcome `expiry-mismatch` — registered as a pure
REGISTRY ACTION (the X-25 machinery: no schema/CDDL/lint-code change).
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
bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def test_negative_reversed_expiry_is_rejected():
    """The reproduced defect: expires_at <= sent_at passed every check."""
    bad = copy.deepcopy(SE)
    bad["expires_at"] = bad["sent_at"]  # zero TTL
    rules = [r for r, _ in el.lint(mock.evidence_artifact(bad))]
    assert "LINT-DE-18" in rules, rules


def test_positive_ordered_expiry_passes():
    rules = [r for r, _ in el.lint(mock.evidence_artifact(copy.deepcopy(SE)))]
    assert "LINT-DE-18" not in rules


def _bundle_with_se(se):
    m = bl.reconstruct(json.loads(
        (ROOT / "samples" / "bundle.default.manifest.json").read_text()))
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], [_rc(x) for x in m["evidence"]] + [se]]


def test_negative_oversized_ttl_fails_the_default_p30d():
    se = copy.deepcopy(SE)
    se["message_id"] = "01HZ3TTLTEST0000000000001"
    se["sent_at"] = "2026-01-01T00:00:00Z"
    se["expires_at"] = "2026-03-01T00:00:00Z"  # 59 days > P30D default
    rules = [r for r, _ in bl.check_bundle(*_bundle_with_se(se))]
    assert "LINT-BND-27" in rules, rules


def test_positive_in_bound_ttl_passes():
    se = copy.deepcopy(SE)
    se["message_id"] = "01HZ3TTLTEST0000000000002"
    se["sent_at"] = "2026-01-01T00:00:00Z"
    se["expires_at"] = "2026-01-20T00:00:00Z"  # 19 days < P30D
    rules = [r for r, _ in bl.check_bundle(*_bundle_with_se(se))]
    assert "LINT-BND-27" not in rules, rules


def test_declared_max_ttl_overrides_the_default():
    entity, med, org, members, evidence = _bundle_with_se(
        dict(copy.deepcopy(SE), message_id="01HZ3TTLTEST0000000000003",
             sent_at="2026-01-01T00:00:00Z", expires_at="2026-01-05T00:00:00Z"))
    org = dict(org, max_ttl="P2D")  # stricter than the 4-day TTL above
    rules = [r for r, _ in bl.check_bundle(entity, med, org, members, evidence)]
    assert "LINT-BND-27" in rules, rules


def test_expiry_mismatch_is_a_pure_registry_action():
    """The X-25 machinery exercised for real: `expiry-mismatch` is REGISTERED
    (bound to D.2) with no schema/CDDL/lint-code change — an NDE carrying it is
    fully accepted with its event enforced."""
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    assert reg["nde_reasons"]["expiry-mismatch"]["allowed_events"] == [
        "D.2-ContentConsignmentFailure"]
    assert "expiry-mismatch" in lc.REGISTERED_NDE_REASONS
    nde = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]
    ok = dict(copy.deepcopy(nde), reason="expiry-mismatch",
              event="D.2-ContentConsignmentFailure")
    rules = [r for r, _ in el.lint(mock.evidence_artifact(ok))]
    assert "LINT-NDE-07" not in rules and "LINT-NDE-W1" not in rules, rules
    wrong = dict(copy.deepcopy(nde), reason="expiry-mismatch",
                 event="A.2-SubmissionRejection")
    rules = [r for r, _ in el.lint(mock.evidence_artifact(wrong))]
    assert "LINT-NDE-07" in rules, rules


def _de18(se):
    return [r for r, _ in el.lint(mock.evidence_artifact(se)) if r == "LINT-DE-18"]


def test_a_reversed_ttl_of_100ms_is_rejected():
    """X-22's acceptance asks for a SKEWED vector. Before DR-05 the ordering
    check compared strings through local variables, so a TTL reversed by
    100 ms read as ordered ('…00.100Z' <= '…00Z' as text) and the SE passed
    both the ordering rule and — because the same skip fired — the policy
    maximum."""
    se = copy.deepcopy(SE)
    se["sent_at"] = "2026-04-04T10:15:00.100Z"
    se["expires_at"] = "2026-04-04T10:15:00Z"          # 100 ms EARLIER
    # the trap: as TEXT the pair looks correctly ordered, because '.' sorts
    # before 'Z' — so the old check saw a valid TTL and skipped both rules.
    assert se["expires_at"] > se["sent_at"]
    assert _de18(se), "a TTL reversed by 100 ms must be rejected"


def test_an_unparsable_expiry_is_reported_not_skipped():
    se = copy.deepcopy(SE)
    se["expires_at"] = "whenever"
    assert _de18(se)
