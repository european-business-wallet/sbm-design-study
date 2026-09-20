# SPDX-License-Identifier: MIT
"""R3-09 — the version gate reaches active claims, not just bound occurrences.

Former defect (round-3 review, Medium). Each entry in `versions.json` binds ONE
occurrence per file, so an active, reader-visible claim ELSEWHERE in the same
artefact was invisible. ICS row 191 — an **active conformance row**, not a
changelog row — stated the companion contracts at "(v1.0.0)" and "evidence-2.6"
against actual 2.0.0 and 2.7, and two contracts carried stale
"Contract v1.0.0" / "evidence 2.6" strings in their descriptions, while
`make versions` reported 74 bindings consistent.

This is DR-13 one artefact over: R-01's criterion is "no current prose
identifies an obsolete version", and prose the gate does not bind is prose that
drifts. DR-13 bound one paragraph; binding them one at a time is what left the
gap, so the answer is a SWEEP.

**The discriminator is grammatical, and a regex cannot guess it:**

    "the surfaces ARE published contracts (v1.0.0)"      <- a current claim
    "as-of BW-MEMBER reads (SINCE EDD contract v1.4.0)"  <- provenance

So provenance is **marked**, not inferred. Six ICS rows genuinely record when a
feature arrived and now say "since"; one was a stale current claim and was
corrected. History TABLES stay out of scope entirely — a changelog row
correctly records what was true then, and sweeping it would force us to falsify
the record.
"""
import importlib.util
import json
import pathlib
import shutil
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "version_manifest", ROOT / "scripts" / "version_manifest.py")
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)

MANIFEST = json.loads((ROOT / "versions.json").read_text())
TS = "etsi/TS-SBM-QERDS-Binding-v0.1.md"


@pytest.fixture
def tree(tmp_path):
    """A copy of the swept artefacts, so a test can break one."""
    for rel in MANIFEST["active_claim_sweep"]:
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dst)
    return tmp_path


def _sweep(tree):
    return vm.sweep_active_claims(tree, MANIFEST)


# ---------------------------------------------------------------------------
# The shipped tree
# ---------------------------------------------------------------------------

def test_no_active_claim_is_stale(tree):
    assert _sweep(tree) == []


def test_the_sweep_covers_every_published_contract():
    """A file absent from the list is a file nothing sweeps — the same shape of
    hole as a contract absent from the OpenAPI validator's list."""
    on_disk = {p.name for p in ROOT.glob("*openapi*.yaml")}
    swept = {pathlib.Path(rel).name for rel in MANIFEST["active_claim_sweep"]}
    assert on_disk <= swept, on_disk - swept
    assert TS in MANIFEST["active_claim_sweep"], "the ICS pro forma must be swept"


# ---------------------------------------------------------------------------
# The gate catches the defect it exists for — BOTH halves
# ---------------------------------------------------------------------------

def _never_current():
    """A version-shaped token no dimension currently carries.

    The probes below inject a "stale" value, and two of them hard-coded
    `1.0.0` — which stopped being stale the moment the federation register
    landed at exactly that version, so both probes asserted that the sweep
    catches something the sweep is right not to catch. A fixture that can
    collide with a real current value is a fixture that will, eventually.

    Derived, so it cannot collide again.
    """
    taken = {d["value"].lstrip("v") for d in MANIFEST["dimensions"].values()}
    for major in range(90, 100):
        token = f"{major}.0.0"
        if token not in taken:
            return token
    raise AssertionError("no non-current version token available")


NEVER_CURRENT = _never_current()


def test_the_original_row_191_is_caught(tree):
    """Reconstructed verbatim. The first version of this sweep caught only the
    `evidence-2.6` half: `contracts` (plural) slipped past the pattern, so half
    the defect would have shipped green a second time."""
    ts = tree / TS
    # The current values are READ, not restated: this probe pinned
    # "contracts (v2.1.0)" and silently stopped reproducing anything the moment
    # round 5 bumped the contracts to 3.0.0 — a test that pins a moving value
    # is the drift family it exists to catch.
    contracts = MANIFEST["dimensions"]["companion_contracts"]["value"]
    evidence = MANIFEST["dimensions"]["evidence"]["value"]
    text = ts.read_text()
    assert f"contracts (v{contracts})" in text and f"evidence-{evidence}" in text
    ts.write_text(text
                  .replace(f"contracts (v{contracts})",
                           f"contracts (v{NEVER_CURRENT})")
                  .replace(f"evidence-{evidence}", "evidence-2.6"))
    found = [token for _, _, token in _sweep(tree)]
    assert f"contracts (v{NEVER_CURRENT})" in found
    assert "evidence-2.6" in found


def test_a_stale_claim_in_a_contract_description_is_caught(tree):
    """The other half of the finding: `info.version` is bound, and a version
    restated in prose beside it is not."""
    wr = tree / "wallet-rdp-openapi.yaml"
    wr.write_text(wr.read_text().replace(
        "    internally. Authentication:",
        f"    internally. Contract v{NEVER_CURRENT}. Authentication:"))
    assert [t for _, _, t in _sweep(tree) if NEVER_CURRENT in t]


# ---------------------------------------------------------------------------
# ...and does not fire on what is legitimately history
# ---------------------------------------------------------------------------

def test_marked_provenance_is_not_flagged(tree):
    """Six ICS rows genuinely record when a feature arrived. Flagging them
    would push authors to delete the provenance, which is worse than the drift
    being prevented."""
    ts = tree / TS
    ts.write_text(ts.read_text() +
                  "\n| 999 | A feature that arrived earlier (since evidence 2.2) | [UMB] | §1 | A | none |\n")
    assert _sweep(tree) == []


@pytest.mark.parametrize("marker", ["since", "as of", "introduced in", "added in"])
def test_every_provenance_marker_is_honoured(tree, marker):
    ts = tree / TS
    ts.write_text(ts.read_text() +
                  f"\n| 998 | Something ({marker} EDD contract v1.4.0) | [UMB] | §1 | A | none |\n")
    assert _sweep(tree) == []


def test_the_revision_history_is_out_of_scope(tree):
    """A changelog row correctly records what was true THEN. Sweeping it would
    force the record to be falsified, so history tables are excluded by shape:
    their first cell is a TS version, an ICS row's is a number."""
    ts = tree / TS
    ts.write_text(ts.read_text() +
                  "\n| v0.01 | 2020-01-01 | contracts (v1.0.0), evidence 2.2 |\n")
    assert _sweep(tree) == []


def test_prose_outside_the_ics_table_is_not_swept(tree):
    """Narrative prose describing past states is not a conformance claim. The
    ICS pro forma is what an assessor reads as 'what this profile does now'."""
    ts = tree / TS
    ts.write_text(ts.read_text() +
                  "\nThe construction dates from evidence 2.2 and contract v1.4.0.\n")
    assert _sweep(tree) == []


# ---------------------------------------------------------------------------
# The gate is on the bar
# ---------------------------------------------------------------------------

def test_the_sweep_runs_in_the_versions_gate():
    src = (ROOT / "scripts" / "version_manifest.py").read_text()
    assert "sweep_active_claims(ROOT, manifest)" in src
    assert "return 1" in src.split("if stale:")[1][:400], \
        "a stale active claim must FAIL the gate, not merely be reported"
