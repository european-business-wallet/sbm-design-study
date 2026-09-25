# SPDX-License-Identifier: MIT
"""PT-01 — the JSON-canonicalisation hash modes are removed, and their removal
is a REFUSAL, not an omission.

`jcs-sha256` / `jcs-sha512` left the profile on 25 September 2026 with RFC 8785.
Dropping the two values from the schema enumeration would make an artefact that
declares one merely un-validatable; these tests pin the stronger property the
work order asks for — LINT-HASH-01 refuses it BY NAME, from the document
validators, with a message that says the mode is not part of the profile.

Two refusals, deliberately independent: the authoritative JSON Schema
(LINT-PKG-12) and the linter's own walk (LINT-HASH-01). A schema is a shape
check and would pass over a digest descriptor a future revision moves somewhere
new; the walk reaches every `hash_mode` wherever it sits.

The removal is breaking. A sender that emitted `jcs-sha256` now has its evidence
refused rather than ignored, which is the intended outcome: that digest was over
canonicalised JSON, and the profile no longer defines a rule to recompute it.
"""
import copy
import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_lint as el  # noqa: E402
import discovery_lint as dl  # noqa: E402
import lint_cli as lc  # noqa: E402

RETIRED = ("jcs-sha256", "jcs-sha512")
PROFILE = ("raw-sha256", "raw-sha512", "manifest-sha256", "manifest-sha512")


def _mock():
    spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # pragma: no cover — no flask in a minimal env
        pytest.skip(f"mock_rdp not importable ({exc})")
    return mod


# --- what the profile now defines -----------------------------------------

def test_the_schema_and_the_cddl_agree_on_the_four_modes():
    schema = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
    enum = schema["$defs"]["Hash"]["properties"]["hash_mode"]["enum"]
    assert enum == list(PROFILE), enum
    cddl = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    rule = re.search(r"hash_mode:(.*?),\n", cddl, re.S).group(1)
    assert set(re.findall(r'"([a-z0-9-]+)"', rule)) == set(PROFILE), rule


def test_no_shipped_sample_declares_a_mode_outside_the_profile():
    """Checked over the sealed artefact as well as the projection: a sample's
    authority is its bytes, and a mode could survive in one and not the other."""
    for path in sorted((ROOT / "samples").glob("*.json")):
        doc = json.loads(path.read_text())
        found = {m for _, m, _ in lc.find_foreign_hash_modes(doc)}
        assert not found, (path.name, found)
        if isinstance(doc, dict) and "sm_artifact_b64" in doc and "projection" in doc:
            whole = lc.reconstruct(doc)
            assert not lc.find_foreign_hash_modes(whole), path.name


# --- the refusal -----------------------------------------------------------

@pytest.mark.parametrize("mode", RETIRED)
def test_evidence_declaring_a_retired_mode_is_refused_by_name(mode):
    """LINT-HASH-01 on a genuinely sealed artefact — not on a loose dict, so the
    refusal is shown where a real submission would arrive."""
    mock = _mock()
    se = copy.deepcopy(json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"])
    se["payload_hash"] = {"alg": "SHA-256" if mode.endswith("256") else "SHA-512",
                          "hex": se["payload_hash"]["hex"] if mode.endswith("256") else "a" * 128,
                          "hash_mode": mode}
    verdict = el.lint(mock.evidence_artifact(se))
    hits = [m for r, m in verdict if r == "LINT-HASH-01"]
    assert len(hits) == 1, verdict
    assert mode in hits[0] and "not part of the profile" in hits[0], hits[0]
    assert "payload_hash" in hits[0], "the refusal must say WHERE the mode sits"
    # And independently: the authoritative Schema does not admit it either.
    assert "LINT-PKG-12" in [r for r, _ in verdict], verdict


def test_a_published_org_document_is_refused_at_the_source():
    """An ORG document pins the acceptance policy every SE will cite, so the
    mode is refused where it is PUBLISHED, not only where it is referenced."""
    org = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())
    body = copy.deepcopy(org["projection"])
    body["supersedes"]["doc_digest"]["hash_mode"] = "jcs-sha256"
    hits = [m for r, m in dl.lint(body) if r == "LINT-HASH-01"]
    assert len(hits) == 1 and "not part of the profile" in hits[0], hits


def test_the_walk_reaches_a_digest_wherever_it_sits():
    """The rule is a walk, not a field list: a nested manifest part descriptor
    and a policy reference are reached the same way `payload_hash` is."""
    doc = {"type": "SE-v1",
           "acceptance_policy_ref": {"doc_digest": {"hash_mode": "jcs-sha256"}},
           "manifest": [{"part_id": "1", "digest": {"hash_mode": "jcs-sha512"}}]}
    paths = {p for p, _, _ in lc.find_foreign_hash_modes(doc)}
    assert paths == {"$.acceptance_policy_ref.doc_digest", "$.manifest[0].digest"}


@pytest.mark.parametrize("mode", PROFILE)
def test_a_mode_the_profile_defines_is_not_refused(mode):
    """The rule refuses what left the profile, not everything it meets — a gate
    that failed on every mode would pass this suite and break the samples."""
    assert lc.find_foreign_hash_modes({"doc_digest": {"hash_mode": mode}}) == []


def test_an_unknown_mode_is_refused_without_being_named_as_retired():
    """A typo is refused too, but the message does not claim it was ever part of
    the profile — the catalogue distinguishes removed from never-defined."""
    (path, mode, reason), = lc.find_foreign_hash_modes({"d": {"hash_mode": "sha256"}})
    assert (path, mode, reason) == ("$.d", "sha256", None)
    msg = lc.hash_mode_violations({"d": {"hash_mode": "sha256"}})[0][1]
    assert "removed" not in msg and "not part of the profile" in msg


def test_every_defined_mode_is_mandatory_to_implement():
    """A11, decided 25 September 2026. The linter can refuse a mode outside the
    profile; it cannot prove a receiver implemented one. So the obligation is
    stated where the wire rules live, assessed through the TS ICS row, and held
    in place by the rule-ownership gate — which fails if the owner stops saying
    it. Without it the surviving modes reproduce the defect that removed A′:
    `manifest-*` needs a construction `raw-*` does not."""
    id_text = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "A receiver MUST implement\nevery `hash_mode`" in id_text or \
           "A receiver MUST implement every `hash_mode`" in id_text.replace("\n", " ")
    for mode in PROFILE:
        assert mode in id_text
    ts = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
    row = next((l for l in ts.splitlines() if l.startswith("| 192 |")), None)
    assert row and "mandatory to implement" in row and "[I-D]" in row, row
    family = json.loads((ROOT / "docs" / "rule-ownership.json").read_text())
    fam, = [f for f in family["families"] if f["id"] == "hash-mode-mandatory-to-implement"]
    assert fam["owner"] == "id" and "LINT-HASH-01" in fam["rule_ids"]


def test_the_rule_is_catalogued():
    """X-20: a conformance rule a tool emits and the catalogue does not carry is
    an undocumented rule. `make lint-catalogue` enforces it; this names it."""
    cat = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text())
    entry, = [r for r in cat["rules"] if r["id"] == "LINT-HASH-01"]
    assert entry["owner_fn"] == "find_foreign_hash_modes"
    for mode in RETIRED:
        assert mode in entry["predicate"]
