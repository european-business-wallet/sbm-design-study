# SPDX-License-Identifier: MIT
"""The retrievability gate, checked against the omissions it must detect.

`scripts/retrievability.py` binds `docs/retrievability.json` to three facts the
tree already states machine-readably, so no verification input can be added
without recording who keeps its material retrievable. A registry that only
described things would drift the day someone added an argument; these probes
assert the binding actually holds in each direction.

It earned its place on the first run, catching two things in the registry I had
just written by hand: a declared residual (`LINT-BND-I6`) that no row claimed,
and a row asserting that no operation publishes retained group context when
`GET /groups/{group_id}/context?epoch=` does exactly that. The second mattered
beyond a typo — A5's actual gap is that nothing publishes the BYTES that read
serves, which is the opposite shape from every other row, where the interface is
settled and only the custody after an exit is not.
"""
import copy
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import retrievability as retr  # noqa: E402


@pytest.fixture
def data():
    return retr.load()


# ---------------------------------------------------------------------------
# The live registry
# ---------------------------------------------------------------------------

def test_the_registry_is_complete_and_current(data):
    assert retr.check(data) == []


def test_the_rendered_document_is_current(data):
    assert retr.MD.read_text(encoding="utf-8") == retr.render_md(data)


# ---------------------------------------------------------------------------
# RETR-01 — a verifier input nobody described
# ---------------------------------------------------------------------------

def test_an_undescribed_verifier_input_is_caught(data, monkeypatch):
    """The drift that matters: someone adds an argument to `check_bundle` and
    says nothing about who serves what it reads."""
    monkeypatch.setattr(retr, "verifier_inputs",
                        lambda: ["evidence", "a_new_retained_thing"])
    findings = retr.check(data)
    assert any("a_new_retained_thing" in f and f.startswith("RETR-01") for f in findings), \
        findings


def test_a_row_that_does_not_say_whether_it_survives_an_exit_is_caught(data):
    broken = copy.deepcopy(data)
    broken["inputs"][0].pop("survives_provider_exit")
    findings = retr.check(broken)
    assert any("survives a provider exit" in f for f in findings), findings


@pytest.mark.parametrize("field", ["material", "operation", "served_by", "absent"])
def test_a_row_missing_any_required_statement_is_caught(data, field):
    broken = copy.deepcopy(data)
    broken["inputs"][0][field] = "   "
    assert any(f"`{field}`" in f for f in retr.check(broken)), field


# ---------------------------------------------------------------------------
# RETR-02 — a residual that names no owner
# ---------------------------------------------------------------------------

def test_a_residual_no_row_claims_is_caught(data, monkeypatch):
    """A `LINT-BND-I*` rule says the material to decide is absent. If no row
    claims it, nothing records whose material it was — which is the question."""
    monkeypatch.setattr(retr, "declared_residuals",
                        lambda: ["LINT-BND-I1", "LINT-BND-I99"])
    findings = retr.check(data)
    assert any("LINT-BND-I99" in f and f.startswith("RETR-02") for f in findings), findings


def test_every_declared_residual_is_a_real_catalogue_rule():
    """The other direction: the registry must not claim residuals that do not
    exist, or a typo would satisfy RETR-02 by naming nothing."""
    real = set(retr.declared_residuals())
    claimed = {r for row in retr.load()["inputs"] for r in row.get("residuals") or []}
    assert claimed <= real, sorted(claimed - real)
    assert real, "no residuals found at all — the catalogue reader is broken"


# ---------------------------------------------------------------------------
# RETR-03 — a published historical read nothing depends on
# ---------------------------------------------------------------------------

def test_a_published_as_of_read_no_row_depends_on_is_caught(data, monkeypatch):
    monkeypatch.setattr(retr, "historical_reads",
                        lambda: {"/some/new/history/{id}": ["as_of"]})
    findings = retr.check(data)
    assert any("/some/new/history/{id}" in f and f.startswith("RETR-03")
               for f in findings), findings


def test_the_reads_it_finds_are_the_ones_that_take_a_selector():
    """Grounding: the discovered set must include the three reads the custody
    question is actually about, and each by its selector rather than by name."""
    found = retr.historical_reads()
    assert "/.well-known/bw/member/{uid}/{mid}" in found
    assert "as_of" in found["/.well-known/bw/member/{uid}/{mid}"]
    assert "/participants/{participant_id}" in found
    assert "as_of" in found["/participants/{participant_id}"]
    assert "/.well-known/bw/org/{uid}" in found
    assert "doc_digest" in found["/.well-known/bw/org/{uid}"]


# ---------------------------------------------------------------------------
# The finding the registry exists to state
# ---------------------------------------------------------------------------

def test_exactly_one_historical_read_survives_a_provider_exit(data):
    """The shape of the gap, asserted so that closing it changes this test.

    The federation register's admission history is served by the Federation
    Authority — not by the provider that exits — which is why it survives. If a
    successor pointer is ever specified for the others, this assertion is the one
    that should fail and be updated.
    """
    rows = {r["input"]: r for r in data["inputs"]}
    assert rows["federation_register"]["survives_provider_exit"] is True
    for name in ("med", "org", "policy_history", "member_history",
                 "counterparty_members", "roster"):
        assert rows[name]["survives_provider_exit"] is False, name
    exposed = [r["input"] for r in data["inputs"] if not r["survives_provider_exit"]]
    assert len(exposed) >= 8, exposed


def test_the_evidence_itself_is_durable_and_the_material_to_check_it_is_not(data):
    """The asymmetry worth keeping in view: evidence has a second independent
    holder by design (each party's own copy), and most of what is needed to CHECK
    it has exactly one."""
    rows = {r["input"]: r for r in data["inputs"]}
    assert rows["evidence"]["survives_provider_exit"] is True
    assert rows["member_history"]["survives_provider_exit"] is False
