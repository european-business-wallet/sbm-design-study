# SPDX-License-Identifier: MIT
"""R16-04 — the gate that can see a change crossing a version dimension.

Two shape gates already existed and neither could see this. `schema_shapes.py`
compares a discovery schema's top-level property set; `contract_shapes.py`
compares a contract's paths, methods and security. Both read a file as written,
and **the dependency is not written in the file**: `wallet-rdp-openapi.yaml`
says `$ref: schemas/evidence-common.schema.json#/$defs/Hash`, so when the
JSON-canonicalisation modes left that `$defs` the contract stopped accepting
inputs it had accepted the day before, while `companion_contracts` stayed at
9.0.0 — a different version dimension from the file that changed.

This gate resolves the references and fingerprints what a validator sees. The
test that matters is the last one: the defect is reproduced by editing one file,
and the gate is required to name every dimension it reaches.
"""
import json
import pathlib
import shutil
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import resolved_shapes as rs  # noqa: E402

COPIED = ("schemas", "versions.json", "docs", "wallet-rdp-openapi.yaml",
          "delivery-service-openapi.yaml", "rdp-relay-openapi.yaml",
          "edd-resolver-openapi.yaml", "federation-register-openapi.yaml")


@pytest.fixture
def repo():
    """A copy carrying the artefacts and the manifest that binds them."""
    root = pathlib.Path(tempfile.mkdtemp())
    for rel in COPIED:
        src = ROOT / rel
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, root / rel) if src.is_dir() else shutil.copy(src, root / rel)
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _record(root):
    (root / "docs" / "resolved-shapes.json").write_text(
        json.dumps({"shapes": rs.current(root)}), encoding="utf-8")


def _narrow_the_shared_type(root, add=("jcs-sha256", "jcs-sha512")):
    """R16-04's own edit: one `$defs`, in one file, no version touched."""
    p = root / "schemas" / "evidence-common.schema.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    node = d["$defs"]["Hash"]["properties"]["hash_mode"]
    node["enum"] = list(node["enum"]) + list(add)
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")


# --- the tree as it stands --------------------------------------------------

def test_the_repository_matches_its_record():
    assert rs.drift() == []


def test_every_versioned_artefact_is_covered():
    """Driven by versions.json, so a new versioned artefact is covered the day
    it is bound rather than when someone remembers a second list."""
    covered = rs.artefacts()
    assert len(covered) >= 21, covered
    assert covered["wallet-rdp-openapi.yaml"] == "companion_contracts"
    assert covered["schemas/envelope.schema.json"] == "application_envelope"
    assert covered["schemas/evidence-common.schema.json"] == "evidence"


def test_each_contract_has_its_own_fingerprint():
    """The regression that matters most in this file. A first draft allow-listed
    JSON Schema keywords and dropped every key it did not recognise, which
    reduced all three OpenAPI documents to `{}` — the same fingerprint, the
    SHA-256 of nothing — and the gate reported them unchanged because it was
    comparing emptiness with emptiness."""
    prints = {c: rs.fingerprint(ROOT / c) for c in
              ("wallet-rdp-openapi.yaml", "rdp-relay-openapi.yaml",
               "delivery-service-openapi.yaml")}
    assert len(set(prints.values())) == 3, prints
    empty = rs.fingerprint.__globals__["hashlib"].sha256(b"{}").hexdigest()
    assert empty not in prints.values(), "a contract fingerprinted as nothing"


# --- the defect it was built for -------------------------------------------

def test_one_edited_file_is_reported_across_every_dimension_it_reaches(repo):
    """R16-04, reproduced. Editing `$defs/Hash` alone must be reported against
    the evidence schemas AND the envelope AND the contracts that `$ref` it."""
    _record(repo)
    _narrow_the_shared_type(repo)
    problems = dict(rs.drift(repo))
    dims = {rs.current(repo)[rel]["dimension"] for rel in problems}
    assert {"evidence", "application_envelope", "discovery_bw_org",
            "companion_contracts", "edd_openapi"} <= dims, dims
    assert "wallet-rdp-openapi.yaml" in problems, \
        "the contract is where R16-04 was reported, and it must be named"
    assert "schemas/envelope.schema.json" in problems


def test_the_message_says_what_a_reader_needs(repo):
    _record(repo)
    _narrow_the_shared_type(repo)
    problems = dict(rs.drift(repo))
    msg = problems["wallet-rdp-openapi.yaml"]
    assert "companion_contracts" in msg and "9.0.0" in msg
    assert "may be invalid" in msg, "it must say what changed for an input"
    assert "through a `$ref`" in msg, \
        "its own file is untouched; the message must say where the change came from"


def test_a_shape_that_moves_with_its_version_is_accepted(repo):
    """The gate must not force a version to stand still: a deliberate bump is
    exactly how a narrowing is published."""
    _record(repo)
    _narrow_the_shared_type(repo)
    manifest = json.loads((repo / "versions.json").read_text(encoding="utf-8"))
    for dim in ("evidence", "application_envelope", "discovery_bw_org",
                "companion_contracts", "edd_openapi"):
        v = manifest["dimensions"][dim]["value"]
        manifest["dimensions"][dim]["value"] = v + "-next"
    (repo / "versions.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert rs.drift(repo) == []


def test_prose_alone_does_not_fire(repo):
    """A reworded description changes no input's validity. A gate that fired on
    it would be switched off, and then it would catch nothing at all."""
    _record(repo)
    p = repo / "schemas" / "evidence-se.schema.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    d["description"] = "Reworded for this test, changing nothing a validator does."
    # Only the prose. A first draft of this test also wrote `d["$defs"] =
    # d.get("$defs", {})`, which ADDS a key where there was none — a structural
    # change, correctly reported, by a test claiming to change nothing.
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    assert rs.drift(repo) == []


def test_a_real_narrowing_fires_even_when_the_file_looks_untouched(repo):
    """The narrowing direction, not only the widening one: removing a value is
    what the profile's own versioning policy calls a shape change."""
    _record(repo)
    p = repo / "schemas" / "evidence-common.schema.json"
    d = json.loads(p.read_text(encoding="utf-8"))
    node = d["$defs"]["Hash"]["properties"]["hash_mode"]
    node["enum"] = [m for m in node["enum"] if not m.startswith("manifest-")]
    p.write_text(json.dumps(d, indent=2), encoding="utf-8")
    problems = dict(rs.drift(repo))
    assert "schemas/envelope.schema.json" in problems


def test_a_reference_cycle_terminates(repo):
    """A self-referential schema must be fingerprinted, not hung on."""
    p = repo / "schemas" / "cycle.schema.json"
    p.write_text(json.dumps({
        "$defs": {"Node": {"type": "object",
                           "properties": {"child": {"$ref": "#/$defs/Node"}}}},
        "$ref": "#/$defs/Node"}), encoding="utf-8")
    assert rs.fingerprint(p)


def test_a_new_versioned_artefact_must_be_recorded(repo):
    """Binding an artefact without recording its shape would leave it
    unwatched, so the gate says so rather than passing."""
    _record(repo)
    manifest = json.loads((repo / "versions.json").read_text(encoding="utf-8"))
    manifest["dimensions"]["evidence"]["bindings"].append(
        {"kind": "json", "file": "schemas/bw-med.schema.json", "path": "title"})
    (repo / "versions.json").write_text(json.dumps(manifest), encoding="utf-8")
    record = json.loads((repo / "docs" / "resolved-shapes.json").read_text(encoding="utf-8"))
    del record["shapes"]["schemas/bw-med.schema.json"]
    (repo / "docs" / "resolved-shapes.json").write_text(json.dumps(record), encoding="utf-8")
    problems = dict(rs.drift(repo))
    assert "schemas/bw-med.schema.json" in problems
    assert "no recorded shape" in problems["schemas/bw-med.schema.json"]
