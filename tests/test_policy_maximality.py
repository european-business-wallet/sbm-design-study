# SPDX-License-Identifier: MIT
"""R3-02 — the pinned policy version was the LATEST one in force at the act.

Former defect (round-3 review, High). Umbrella §8.3 requires the version in
force at `sent_at`: the latest whose `valid_from <= sent_at`. `LINT-BND-33`
receives only the single BW-ORG the bundle pins, so it could check
`valid_from <= sent_at` and nothing else — with no upper bound, no successor
and no history, **maximality was unprovable**. An old, superseded policy
carrying a valid signature and a valid `valid_from` passed, and evidence could
apply rules that were no longer in force.

R2-M6's prohibition on publishing a future version as "current" does not help:
it constrains the future, and this is a claim about the past.

**R3-T2 chose a signed chain over an `as_of` endpoint**, and the reason is what
these tests encode: maximality becomes a **local** property of the retained
artefacts — a verifier checks the window and the digest-linked successor and is
done — so verifying a 2026 act in 2033 does not depend on some service still
being online and still honest. That is exactly what an evidence-retention model
must not assume.

The four vectors below are the review's own.
"""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lint_cli import dcbor  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
DE = json.loads((ROOT / "samples" / "sample-DE.json").read_text())["projection"]
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]

T1 = "2026-01-01T00:00:00Z"
T2 = "2026-03-20T00:00:00Z"          # between the shipped valid_from and sent_at
SENT = SE["sent_at"]                  # 2026-04-04T10:15:00Z


def _digest(org):
    return hashlib.sha256(dcbor(
        {k: v for k, v in org.items() if k != "doc_cose_b64"})).hexdigest()


def _version(policy_version, valid_from, predecessor=None, **over):
    """R4-U1: a version is published with a START and nothing else. Its window
    ends where its successor begins, DERIVED from the chain.

    The old helper took `valid_until`, and every fixture built v1 with T2
    already filled in — a PRESCIENT PREDECESSOR, a document that could only
    exist in a world where the future was known. That is why no test caught
    R4-02: the transition being modelled was one that never happens.
    """
    v = copy.deepcopy(ORG)
    v["policy_version"] = policy_version
    v["valid_from"] = valid_from
    v.pop("valid_until", None)
    if predecessor is not None:
        v["supersedes"] = {"policy_version": predecessor["policy_version"],
                           "doc_digest": {"alg": "SHA-256",
                                          "hash_mode": "raw-sha256",
                                          "hex": _digest(predecessor)}}
    else:
        v.pop("supersedes", None)
    v.update(over)
    return v


def _all(org, history=None, sent=SENT):
    """Every LINT-BND-* issue, warnings included — some tests are about the
    warning itself."""
    se, de = copy.deepcopy(SE), copy.deepcopy(DE)
    se["sent_at"] = sent
    for ev in (se, de):
        for holder in (ev, ev.get("s3_attestation") or {}):
            apr = holder.get("acceptance_policy_ref")
            if isinstance(apr, dict) and isinstance(apr.get("doc_digest"), dict):
                apr["doc_digest"]["hex"] = _digest(org)
                apr["policy_version"] = org["policy_version"]
    return bl.check_bundle(SE["recipient_uid"], {}, org, [], [se, de],
                           policy_history=history)


def _run(org, history=None, sent=SENT):
    """Repin the evidence to `org` so the rule under test is the in-force one,
    not the digest precondition."""
    se, de = copy.deepcopy(SE), copy.deepcopy(DE)
    se["sent_at"] = sent
    for ev in (se, de):
        for holder in (ev, ev.get("s3_attestation") or {}):
            apr = holder.get("acceptance_policy_ref")
            if isinstance(apr, dict) and isinstance(apr.get("doc_digest"), dict):
                apr["doc_digest"]["hex"] = _digest(org)
                apr["policy_version"] = org["policy_version"]
    issues = bl.check_bundle(SE["recipient_uid"], {}, org, [], [se, de],
                             policy_history=history)
    return [m for r, m in issues if r == "LINT-BND-35"]


# ---------------------------------------------------------------------------
# The shipped bundle
# ---------------------------------------------------------------------------

def test_the_shipped_bundle_raises_no_maximality_violation():
    assert not _run(ORG)


# ---------------------------------------------------------------------------
# (a) The pinned version's own bound — enforced with NO history
# ---------------------------------------------------------------------------

def test_without_a_history_maximality_is_STATED_to_be_unproven():
    """R4-02/R4-U1. There is no stored end date any more, so a lone document
    cannot say it was superseded — and the honest answer is to say so. This was
    a bare early return: an absent history silently downgraded verification
    while the umbrella claimed omitting it was not a way around maximality,
    which was false for exactly the ordinary publication."""
    issues = [(r, m) for r, m in _all(ORG) if r.startswith("LINT-BND-")]
    unproven = [m for r, m in issues if r == "LINT-BND-I1"]
    assert unproven, "an unproven claim must be stated, not passed over"
    assert "MAXIMALITY IS NOT PROVEN" in unproven[0]
    assert not [r for r, _ in issues if r == "LINT-BND-35"], \
        "absence of a history is not itself a violation"
    # R5-02: and stating it is NOT SUCCESS. The rule was a warning that main()
    # printed and did not count, so the verifier said maximality was unproven
    # and returned `[OK] ✓`, exit 0. Both halves are asserted here because
    # renaming the rule without changing the verdict would leave the finding
    # open under a new id.
    only_i1 = [(r, m) for r, m in issues if r == "LINT-BND-I1"]
    assert bl.incomplete_of(only_i1) == only_i1
    assert bl.violations(only_i1) == [], \
        "an incompleteness is not a violation — nothing is wrong with the evidence"
    assert bl.warnings_of(only_i1) == [], \
        "and it is not an advisory warning, which is what let it report success"


def test_the_ordinary_publication_works_at_all():
    """R4-02 (Blocker): this is the case that was IMPOSSIBLE. v1 is published
    open-ended — correctly, it IS current — evidence pins its digest, then v2
    appears. Leaving v1 alone made the chain reject it; bounding it changed the
    digest that evidence had pinned. Both branches were closed."""
    v1 = _version("v1", T1)
    before = _digest(v1)
    v2 = _version("v2", "2026-06-01T00:00:00Z", predecessor=v1)
    assert _digest(v1) == before, "publishing a successor must not touch v1"
    # the act falls inside v1's window [T1, 2026-06-01)
    assert not _run(v1, history=[v1, v2]), "the ordinary transition must verify"
    assert _run(v1, history=[v1, v2], sent="2026-07-01T00:00:00Z"), \
        "after the successor takes force, v1 must no longer govern"


# ---------------------------------------------------------------------------
# (b) The review's four vectors, over a history
# ---------------------------------------------------------------------------

def test_an_act_after_t2_pinned_to_v1_fails():
    """Vector 1. v1 from T1, v2 from T2; the act is after T2 and pins v1."""
    v1 = _version("v1", T1)
    v2 = _version("v2", T2, predecessor=v1)
    issues = _run(v1, history=[v1, v2])
    assert issues
    assert "the version in force at" in issues[0] or "ceased" in issues[0]


def test_an_act_exactly_at_t2_selects_v2():
    """Vector 2, and the reason windows are HALF-OPEN: at the boundary instant
    exactly one version is in force, and it is the later one."""
    v1 = _version("v1", T1)
    v2 = _version("v2", T2, predecessor=v1)
    assert not _run(v2, history=[v1, v2], sent=T2)
    assert _run(v1, history=[v1, v2], sent=T2), \
        "at the boundary the EARLIER version must no longer govern"


def test_gaps_and_overlaps_are_impossible_by_construction():
    """R4-U1 removes two of the four defect classes rather than detecting them.
    A window ends exactly where its successor begins, so there is no instant
    that belongs to none (a gap) and none that belongs to two (an overlap) —
    they cannot be expressed. That is the argument for deriving the bound
    instead of storing it: a stored end date is a second statement of one fact,
    and two statements can disagree."""
    v1 = _version("v1", T1)
    v2 = _version("v2", T2, predecessor=v1)
    assert "valid_until" not in v1 and "valid_until" not in v2
    for at, expect in (("2026-02-01T00:00:00Z", "v1"),
                       (T2, "v2"),                       # the boundary instant
                       ("2026-05-01T00:00:00Z", "v2")):
        governing = v1 if expect == "v1" else v2
        assert not _run(governing, history=[v1, v2], sent=at), (at, expect)


def test_a_stored_valid_until_is_itself_rejected():
    """The field is gone from the schema; a document carrying one anyway is
    reintroducing the mutation R4-02 was about."""
    v1 = _version("v1", T1); v1["valid_until"] = T2
    v2 = _version("v2", T2, predecessor=v1)
    issues = _run(v1, history=[v1, v2], sent="2026-02-01T00:00:00Z")
    assert issues and "DERIVED from the successor" in issues[0]


@pytest.mark.parametrize("flaw", ["duplicate", "unlinked", "equivocated"])
def test_a_broken_history_fails_closed(flaw):
    """Vector 3. Each defect makes 'the version in force' either ambiguous or
    unknowable, so none may be resolved by guessing."""
    v1 = _version("v1", T1)
    v2 = _version("v2", T2, predecessor=v1)
    if flaw == "duplicate":
        v2["valid_from"] = T1                          # two claim one boundary
    elif flaw == "unlinked":
        v2.pop("supersedes")                           # a version could vanish
    elif flaw == "equivocated":
        v2["supersedes"]["doc_digest"]["hex"] = "f" * 64
    assert _run(v2, history=[v1, v2]), f"{flaw} was not rejected"


def test_a_historical_act_stays_verifiable_after_the_policy_changes():
    """Vector 4, and the point of the whole design: an act governed by v1 must
    remain verifiable once v2 is current — evidence must not decay when the
    policy moves on."""
    v1 = _version("v1", T1)
    v2 = _version("v2", T2, predecessor=v1)
    early = "2026-02-01T00:00:00Z"
    assert not _run(v1, history=[v1, v2], sent=early)


def test_maximality_holds_across_three_versions():
    v1 = _version("v1", T1)
    v2 = _version("v2", "2026-02-01T00:00:00Z", predecessor=v1)
    v3 = _version("v3", T2, predecessor=v2)
    hist = [v3, v1, v2]                    # order in the manifest is irrelevant
    assert not _run(v3, history=hist)
    assert _run(v2, history=hist), "a middle version must not govern a later act"
    assert not _run(v2, history=hist, sent="2026-02-15T00:00:00Z")


# ---------------------------------------------------------------------------
# The rule is reachable from the manifest, not only from Python
# ---------------------------------------------------------------------------

def test_the_manifest_can_carry_a_policy_history():
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert '"policy_history"' in src
    assert "policy_history=policy_history" in src


def test_the_schema_declares_the_chain_fields():
    org = json.loads((ROOT / "schemas" / "bw-org.schema.json").read_text())
    assert "valid_until" not in org["properties"], \
        "R4-U1: the end date is DERIVED from the successor, never stored — " \
        "storing it means rewriting a document that evidence has already pinned"
    sup = org["properties"]["supersedes"]
    assert set(sup["required"]) == {"policy_version", "doc_digest"}


# ---------------------------------------------------------------------------
# R5-02 — the release bar, which is where the finding actually lived
# ---------------------------------------------------------------------------

def _cli(manifest):
    """The CLI, exactly as a release gate invokes it."""
    import subprocess
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "bundle_lint.py"),
                        str(ROOT / "samples" / manifest)],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def test_a_bundle_with_no_chain_does_not_pass(tmp_path):
    """The finding verbatim: the verifier stated that the legally decisive
    property was unproven and returned `[OK] ✓`, exit 0, on all four shipped
    positive bundles — with `make conformance` green over them.

    Driven through the CLI rather than through check_bundle, because the defect
    was in the VERDICT, not in the rule: the rule was already correct and
    already said so."""
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    m.pop("policy_history")
    stripped = ROOT / "samples" / "bundle.__r5tmp.manifest.json"
    stripped.write_text(json.dumps(m))
    try:
        code, out = _cli(stripped.name)
    finally:
        stripped.unlink()
    assert "MAXIMALITY IS NOT PROVEN" in out
    assert "[OK  ]" not in out, "an incomplete verification must not report OK"
    assert code != 0, "an incomplete verification must not exit 0"
    assert code == 3 and "INCOMPLETE" in out


def test_every_shipped_positive_bundle_carries_a_complete_chain():
    """R5-V1's second half, CORRECTED by R6-W1.

    Round 5 asserted these bundles PROVE maximality. They do not, and no local
    material could: a complete chain and a successor-truncated chain are
    byte-identical from inside the bundle. What they do carry is a chain that
    is unbroken back to a first publication and shows the pinned version in
    force at the act — linkage, not maximality — so the honest verdict is
    INCOMPLETE with no violations, and the release bar accepts it explicitly
    rather than by mislabelling it."""
    for name in ("bundle.default", "bundle.federated", "bundle.scoped",
                 "bundle.walletsig"):
        code, out = _cli(f"{name}.manifest.json")
        assert code in (0, 3), f"{name}: {out}"
        assert "FAIL" not in out, f"{name} has violations: {out}"
        if "LINT-BND-I3" in out:
            assert "MAXIMALITY IS STILL NOT PROVEN" in out, name


def test_the_shipped_chains_are_real_chains():
    """A one-element history satisfies LINT-BND-35 trivially — it has nothing
    to link — so shipping `policy_history: [the org itself]` would have turned
    the bar green while proving exactly what it proved before. Each positive
    bundle carries a genuine predecessor, linked by content digest."""
    for name in ("bundle.default", "bundle.federated", "bundle.scoped",
                 "bundle.walletsig"):
        m = json.loads((ROOT / "samples" / f"{name}.manifest.json").read_text())
        chain = m["policy_history"]
        assert len(chain) >= 2, f"{name}: a chain of one links nothing"
        docs = [json.loads((ROOT / "samples" / f).read_text()) for f in chain]
        bodies = [d.get("projection", d) for d in docs]
        head = bodies[-1]
        sup = head.get("supersedes")
        assert sup, f"{name}: the head names no predecessor"
        assert sup["policy_version"] == bodies[-2]["policy_version"]
        want = hashlib.sha256(bl.dcbor(
            {k: v for k, v in bodies[-2].items() if k != "doc_cose_b64"})).hexdigest()
        assert sup["doc_digest"]["hex"] == want, \
            f"{name}: the chain link is not the predecessor's content"


# ---------------------------------------------------------------------------
# R6-02 / R6-W1 — the CLASS, not the reproduction
# ---------------------------------------------------------------------------

def _with_history(hist):
    m = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
    if hist is None:
        m.pop("policy_history")
    else:
        m["policy_history"] = hist
    t = ROOT / "samples" / "bundle.__r6test.manifest.json"
    t.write_text(json.dumps(m))
    try:
        return _cli(t.name)
    finally:
        t.unlink()


def test_a_truncated_prefix_is_a_VIOLATION_not_a_pass():
    """R6-02, and it is the first demonstrable cost of round 5's own caveat.
    R5-02's acceptance criterion read: *an act pinned to v1 fails when the
    claimant supplies `[]`, `[v1]`, or any other truncated prefix.* The `[]`
    case was fixed because it was the one demonstrated; `[v1]` passed clean.
    """
    code, out = _with_history(["sample-BW-ORG.json"])
    assert code == 1, out
    assert "this is a PREFIX, not the chain" in out


def test_a_history_missing_its_head_is_also_caught():
    code, out = _with_history(["sample-BW-ORG-prev.json"])
    assert code == 1, out


def test_two_first_publications_are_two_chains_spliced():
    code, out = _with_history(["sample-BW-ORG-prev.json",
                               "sample-BW-ORG-scoped-prev.json"])
    assert code == 1 and "first publications" in out, out


def test_a_COMPLETE_chain_still_does_not_prove_maximality():
    """R6-W1's substance, and the reason this is not merely 'one more input to
    the gap'. A hidden SUCCESSOR is what defeats maximality, and a complete
    chain is indistinguishable from a successor-truncated one from inside the
    bundle — so round 5's `[OK]` claimed more than the evidence supports."""
    code, out = _with_history(["sample-BW-ORG-prev.json", "sample-BW-ORG.json"])
    assert code == 3, out
    assert "LINT-BND-I3" in out
    assert "MAXIMALITY IS STILL NOT PROVEN" in out
    assert "authenticated head (X-33)" in out


def test_the_release_bar_accepts_gaps_and_never_violations():
    """`--allow-incomplete` changes the exit code, not the verdict: the [GAP]
    lines print either way, and a bundle with violations still fails."""
    import subprocess
    def run(manifest, *flags):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bundle_lint.py"), *flags,
             str(ROOT / "samples" / manifest)], capture_output=True, text=True)
    ok = run("bundle.default.manifest.json", "--allow-incomplete")
    assert ok.returncode == 0
    assert "[GAP ]" in ok.stdout, "the gap must still be reported"
    bad = run("bundle.negative.manifest.json", "--allow-incomplete")
    assert bad.returncode == 1, "the flag must never accept a violation"
