# SPDX-License-Identifier: MIT
"""X-20 — the normative lint catalogue is complete, faithful and traceable.

The catalogue (`docs/lint-catalogue.json`, rendered to `docs/lint-catalogue.md`)
is the normative definition of every `LINT-*` rule; the scripts are its reference
implementation. These gates ensure conformance semantics can no longer live only
in mutable Python:

  * completeness — every rule the tools emit is catalogued (no undocumented rule);
  * no phantoms — every catalogue id actually appears in the tools;
  * drift — the committed Markdown equals the freshly rendered Markdown;
  * traceability — the exact set of rules lacking a naming test is pinned in
    `coverage_gap`, so a regression in coverage is visible.

The negative fixtures reproduce X-20's former defect: a rule that exists only in
Python (emitted but uncatalogued) must FAIL the completeness gate.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_catalogue as lc  # noqa: E402


def test_catalogue_completeness_and_no_phantoms():
    data = lc.load()
    missing, phantom = lc.completeness(data)
    assert not missing, (
        "rules emitted by the reference tools but absent from the catalogue "
        f"(undocumented conformance rule — X-20): {missing}"
    )
    assert not phantom, f"catalogue ids that appear in no reference tool: {phantom}"


def test_markdown_is_not_stale():
    data = lc.load()
    rendered = lc.render_md(data)
    assert lc.MD.read_text(encoding="utf-8") == rendered, (
        "docs/lint-catalogue.md is stale — run `make lint-catalogue`"
    )


def test_every_rule_has_the_required_fields():
    data = lc.load()
    required = {"id", "input", "precondition", "predicate", "error",
                "profile", "owner_fn"}
    profiles = {"core", "production", "agent", "four-corner"}
    ids = set()
    for r in data["rules"]:
        assert required <= set(r), f"{r.get('id')} missing fields {required - set(r)}"
        assert r["profile"] in profiles, f"{r['id']} bad profile {r['profile']!r}"
        assert r["id"] not in ids, f"duplicate catalogue id {r['id']}"
        ids.add(r["id"])


def test_non_rule_tokens_are_not_catalogued():
    """The declared prefixes/placeholders must not collide with real rule ids."""
    data = lc.load()
    cat = set(lc.catalogue_ids(data))
    overlap = cat & set(data.get("non_rule_tokens", {}))
    assert not overlap, f"non_rule_tokens overlap real catalogue ids: {overlap}"


def test_coverage_gap_is_pinned_and_honest():
    """The exact set of rules with no naming test is recorded, so a coverage
    regression (a rule silently losing its test) surfaces as a diff."""
    data = lc.load()
    tmap = lc.test_map(set(lc.catalogue_ids(data)))
    untested = sorted(i for i in lc.catalogue_ids(data) if not tmap.get(i))
    assert untested == sorted(data.get("coverage_gap", [])), (
        "coverage_gap is out of date — the rules lacking a naming test are "
        f"{untested}; update docs/lint-catalogue.json (add tests to shrink it, "
        "or record a newly-untested rule)."
    )


# --- negative fixtures: the X-20 former defect (a rule only in Python) ---

def test_negative_undocumented_rule_fails(monkeypatch):
    data = lc.load()
    real = lc.emitted_ids()
    monkeypatch.setattr(lc, "emitted_ids", lambda: real | {"LINT-XYZ-99"})
    missing, _ = lc.completeness(data)
    assert "LINT-XYZ-99" in missing, (
        "a script emitting an uncatalogued rule must fail the completeness gate"
    )


def test_negative_phantom_catalogue_entry_fails():
    data = lc.load()
    data = dict(data)
    data["rules"] = list(data["rules"]) + [{
        "id": "LINT-NOPE-99", "input": "x", "precondition": "x",
        "predicate": "x", "error": "x", "profile": "core", "owner_fn": "x"}]
    _, phantom = lc.completeness(data)
    assert "LINT-NOPE-99" in phantom, (
        "a catalogue id present in no reference tool must be flagged as a phantom"
    )
