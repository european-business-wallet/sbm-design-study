# SPDX-License-Identifier: MIT
"""The integration invariant, mechanised — and REBUILT in round 5.

`CONTRIBUTING.md` invariant 2: *a helper only its own test calls is not
integrated*. Round 4 mechanised it here after the invariant was adopted in
round 3 and violated three times in round 4 (R4-03, R4-04, and `as_of_resolve`,
which had no caller at all).

**Round 5 found the instrument had the same shape as the defects it hunts.**
`docs/normative-helpers.json` recorded each helper's integration STATUS, and
two entries were false: `resolve_ds_receipt_key` and
`check_certificate_binds_key` still said `unintegrated`, with a reason opening
*"RED ON ARRIVAL"* — a description of round 4's STARTING state, never revised
after round 4's own Batch 3 wired both in. A registry whose entries can be
false is worse than no registry, because it is consulted instead of the code.

Three defects, three fixes, and the third is the one that matters most:

1. **The status was stored, so it could go stale.** It is DERIVED now, both
   directions, and the registry may not assert it.
2. **Reachability was "some module calls it".** It is computed from declared
   public entry points now: a helper called by a function nobody reaches is not
   integrated.
3. **The act-time check asserted `assert hits` — AT LEAST ONE caller.** One
   correct call site satisfied it for ever. Two real violations were hiding
   behind it: `mock_rdp.delivered_at_from_receipt` passed `at` POSITIONALLY —
   the same call site as R5-03 — and `discovery_lint` never passed it at all,
   which is the call site R4-04 was ABOUT. Round 4 fixed a different site,
   added `_bnd39` in `bundle_lint`, and the gate went green over the one the
   finding named. Coverage is over EVERY site now, and an exempt site is named
   individually with its reason.

Corollary earned here, beside the four in `CONTRIBUTING.md`: **a gate that
asserts *at least one* caller measures existence, not coverage.**

The fixtures below are not decoration. An analysis that silently returned
nothing would make every assertion in this file pass vacuously, which is the
failure mode of every gate this project has had to rebuild.
"""
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import helper_integration as hi  # noqa: E402

REGISTRY = json.loads((ROOT / "docs" / "normative-helpers.json").read_text())
HELPERS = REGISTRY["helpers"]
ENTRY_POINTS = REGISTRY["entry_points"]
BY_NAME = {h["name"]: h for h in HELPERS}

MODULES = hi.production_modules()
GRAPH = hi.call_graph(MODULES)


# ===========================================================================
# The instrument itself — proved to detect, before it is trusted
# ===========================================================================

FIXTURE = '''
def entry():
    wanted(1, at="x")
    orphaned_caller()

def unreachable():
    wanted(1, at="y")

def orphaned_caller():
    deep(2)

def sloppy():
    wanted(1, "positional")
'''


@pytest.fixture
def fake():
    return {"fixture.py": FIXTURE}


def test_the_analysis_finds_call_sites(fake):
    sites = hi.call_sites("wanted", fake)
    assert sorted(s.enclosing for s in sites) == ["entry", "sloppy", "unreachable"]


def test_the_analysis_attributes_a_call_to_its_enclosing_function(fake):
    site = hi.call_sites("deep", fake)[0]
    assert site.enclosing == "orphaned_caller"
    assert site.key == "fixture.py::orphaned_caller"


def test_reachability_excludes_a_function_nobody_reaches(fake):
    live = hi.reachable(["entry"], hi.call_graph(fake))
    assert "orphaned_caller" in live and "deep" in live
    assert "unreachable" not in live, \
        "a function with no path from an entry point must not count as reached"


def test_a_helper_called_only_from_dead_code_is_unintegrated(fake):
    status, sites = hi.classify(
        {"name": "wanted"}, graph=hi.call_graph(fake), modules=fake,
        entry_points=["no_such_entry_point"])
    assert sites, "the fixture must contain call sites, or this proves nothing"
    assert status == "unintegrated"


def test_EVERY_call_site_is_checked_not_merely_one(fake):
    """The round-4 defect, reproduced against the fixture: `entry` passes
    `at=` correctly and `sloppy` does not. A gate satisfied by one correct
    caller reports nothing here."""
    gaps = hi.missing_arguments(
        {"name": "wanted", "required_arguments": ["at"]}, modules=fake)
    assert sorted(s.enclosing for s, _ in gaps) == ["sloppy"], \
        "one correct caller must not launder an incorrect one"


def test_an_exemption_is_keyed_by_code_not_by_line(fake):
    gaps = hi.missing_arguments(
        {"name": "wanted", "required_arguments": ["at"],
         "argument_exemptions": {"fixture.py::sloppy": "reviewed"}}, modules=fake)
    assert gaps == []


# ===========================================================================
# The registry cannot assert what the code decides
# ===========================================================================

def test_the_registry_stores_no_status():
    """The finding itself. A stored classification is a claim that can become
    false while the gate keeps consulting it."""
    for h in HELPERS:
        assert "status" not in h, (
            f"{h['name']} stores a status. It is derived — round 5 found two "
            "stored ones false, describing a state round 4's own batches had "
            "already changed.")
    assert REGISTRY.get("registry_version") == "2"


def test_no_stale_arrival_note_survives():
    """Both false entries opened with 'RED ON ARRIVAL'. The phrase describes a
    moment, and a registry that records moments will be wrong at every later
    one."""
    # The HELPERS, not the file: the preamble QUOTES the phrase to record what
    # went wrong, which is evidence rather than a live claim — the same reason
    # docs/DESIGN_REVIEW_FINDINGS_HANDOFF.md is doc_lint-exempt.
    assert "RED ON ARRIVAL" not in json.dumps(HELPERS)
    assert "RED ON ARRIVAL" in json.dumps(REGISTRY.get("$comment", "")), \
        "the preamble should still record WHAT was false, as evidence"


@pytest.mark.parametrize("helper", HELPERS, ids=lambda h: h["name"])
def test_every_registered_helper_exists(helper):
    src = (SCRIPTS / helper["module"]).read_text()
    assert re.search(rf"^def {re.escape(helper['name'])}\(", src, re.M), \
        f"{helper['name']} is registered but not defined in {helper['module']}"


@pytest.mark.parametrize("helper", HELPERS, ids=lambda h: h["name"])
def test_every_helper_is_integrated_or_names_its_exemption(helper):
    """Invariant 2, derived. A helper with no reachable production caller must
    be recorded as a deliberate, reviewable decision — never as an omission
    nobody noticed for two rounds."""
    status, sites = hi.classify(helper, graph=GRAPH, modules=MODULES,
                                entry_points=ENTRY_POINTS)
    if status == "integrated":
        assert not helper.get("unintegrated_reason"), (
            f"{helper['name']} records a reason for being unintegrated and IS "
            "integrated — the registry contradicts the code")
        return
    reason = helper.get("unintegrated_reason", "")
    assert len(reason) > 80, (
        f"{helper['name']} has no reachable production caller "
        f"({len(sites)} call site(s), none reached from a public entry point). "
        "Wire it in, or record why not.")
    assert re.search(r"R\d-\d\d|DR-\d\d", reason), \
        f"{helper['name']}: the reason cites no finding"


@pytest.mark.parametrize(
    "helper", [h for h in HELPERS if h.get("required_arguments")],
    ids=lambda h: h["name"])
def test_every_call_site_passes_the_arguments_that_do_the_work(helper):
    """R4-04 generalised. The parameter existed and one accepting path omitted
    it; round 4 then checked that SOME caller passed it, which is why
    `discovery_lint` went on calling `check_certificate_binds_key` with no
    `at` for a whole round after the finding was declared closed."""
    gaps = hi.missing_arguments(helper, modules=MODULES)
    assert not gaps, "\n".join(
        f"{s.module}:{s.lineno} in {s.enclosing}() omits `{arg}` — exempt it by "
        f"key {s.key!r} with a reason, or pass it" for s, arg in gaps)


@pytest.mark.parametrize(
    "helper", [h for h in HELPERS if h.get("argument_exemptions")],
    ids=lambda h: h["name"])
def test_an_exemption_names_a_real_call_site_and_states_why(helper):
    """An exemption that no longer matches any code is the stored-status
    defect wearing a different hat: it would keep excusing something that
    moved."""
    live = {s.key for s in hi.call_sites(helper["name"], MODULES)}
    for key, reason in helper["argument_exemptions"].items():
        assert key in live, (
            f"{helper['name']}: exemption {key!r} matches no call site — "
            "delete it, or fix the key")
        assert len(reason) > 80 and re.search(r"R\d-\d\d|DR-\d\d", reason), \
            f"{helper['name']}: exemption {key!r} states no reviewable reason"


def test_the_registry_covers_the_helpers_that_need_covering():
    """EVERY production module, not just `lint_cli.py`.

    Round 4 scanned one file, so `verify_group_params` — R4-06's own helper,
    and the subject of R5-05 — was never required to be registered at all, and
    neither were the three mls_suite algorithms this scan found unwired. The
    round-4 version also carried a bare exclusion set,
    `- {"check_trust", "check_directory_pin"}`, with no reason recorded: a
    stored claim exempting code from a check, which is R5-07/3 in miniature.
    Both are now registered, and the exclusion set is gone.
    """
    missing = set()
    for src in MODULES.values():
        for d in re.findall(r"^def ([a-z][a-z0-9_]*)\(", src, re.M):
            if re.match(r"^(compute_|resolve_|select_|verify_|check_)", d) \
                    and d not in BY_NAME:
                missing.add(d)
    assert not missing, (
        f"normative-looking helpers absent from docs/normative-helpers.json: "
        f"{sorted(missing)} — register each with its rule, and either wire it "
        "in or record why not")


def test_every_declared_entry_point_exists():
    """A stale entry point makes helpers look unreachable and the gate FAIL,
    which is the safe direction — but a name that never existed is a typo
    silently narrowing the graph."""
    defined = set()
    for src in MODULES.values():
        defined |= set(re.findall(r"^def ([a-z_][a-z0-9_]*)\(", src, re.M))
    unknown = [e for e in ENTRY_POINTS if e not in defined]
    assert not unknown, f"declared entry points that no module defines: {unknown}"


# ===========================================================================
# One rule, one implementation
# ===========================================================================

def test_the_as_of_window_test_has_one_implementation():
    """DR-11's helper was uncalled because the round-2 fix REIMPLEMENTED its
    window test. Two copies of a normative rule drift, and the second is
    always the one nobody is looking at."""
    pattern = re.compile(r"vf\s*<=\s*\w+\s+and\s+\(vu is None or\s+\w+\s*<\s*vu\)")
    sites = []
    for mod, src in MODULES.items():
        for m in pattern.finditer(src):
            sites.append(f"{mod}:{src[:m.start()].count(chr(10)) + 1}")
    assert len(sites) <= 1, (
        f"the as-of window test is implemented more than once: {sites}")


# ===========================================================================
# A `continue` in a verifier is a decision not to check
# ===========================================================================

def test_every_IDENTITY_skip_in_a_verifier_says_why_it_is_safe():
    """R4-01's `LINT-BND-24` did `if uid != entity: continue` — the foreign UID
    skipped exactly where it should be flagged — and R3-03's fourth site was
    the same shape.

    NARROWED, and the reason is part of the check. The broad version fired 34
    times, almost all on ordinary loop filters; a check that fires 34 times
    gets suppressed, and a suppressed check is worse than none.

    LIMIT: this makes the decision VISIBLE, not correct. A comment satisfies it
    whether or not the reasoning holds — R4-01's own site carried
    `# addressed to a different entity — not this bundle's org`, which is true
    and irrelevant. The check surfaces such claims for review; only a reviewer
    can reject one.
    """
    identity = re.compile(
        r"\b(uid|entity|mid|sender_uid|recipient_uid|device_id|principal)\b"
        r"[^\n]*(!=|not in)|"
        r"(!=|not in)[^\n]*\b(uid|entity|mid|sender_uid|recipient_uid|device_id)\b")
    offenders = []
    for mod in ("bundle_lint.py", "evidence_lint.py", "discovery_lint.py"):
        lines = (SCRIPTS / mod).read_text().splitlines()
        for n, line in enumerate(lines, 1):
            if line.strip() != "continue":
                continue
            guard = lines[max(0, n - 3):n - 1]
            if not any(identity.search(g) for g in guard):
                continue
            if any(l.strip().startswith("#") for l in lines[max(0, n - 5):n]):
                continue
            offenders.append(f"{mod}:{n}  ({guard[-1].strip()[:60]})")
    assert not offenders, (
        "a `continue` that skips on an IDENTITY mismatch is a decision not to "
        "report the mismatch, and needs a comment saying why that is safe:\n  "
        + "\n  ".join(offenders))
