# SPDX-License-Identifier: MIT
"""N2 (language equivalence): the CDDL is a structural OUTER BOUND; the JSON
Schema is AUTHORITATIVE for the decoded body. Proven three ways:

  (a) a negative corpus the authoritative body-Schema MUST reject;
  (b) the reproduced divergence — a minimal `{type, version}` BW-ORG body is
      CDDL-valid yet Schema-invalid: the boundary working as designed;
  (c) a coherence property over every positive sample: the projection equals
      `decode(payload)` (so CDDL-valid ∧ Schema-valid ∧ body≡projection hold
      together, and cannot describe different documents).
"""
import importlib.util
import json
import pathlib
import shutil

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
jsonschema = pytest.importorskip("jsonschema")
cbor2 = pytest.importorskip("cbor2")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lc = _load("lint_cli", "lint_cli.py")

_STORE = {}
for _p in (ROOT / "schemas").glob("*.schema.json"):
    _s = json.loads(_p.read_text(encoding="utf-8"))
    if "$id" in _s:
        _STORE[_s["$id"]] = _s
    _STORE[str(_p)] = _s
_RESOLVER = jsonschema.RefResolver(base_uri=str(ROOT.as_uri()) + "/schemas",
                                   referrer=None, store=_STORE)


def _validate(doc, schema_file):
    schema = json.loads((ROOT / "schemas" / schema_file).read_text(encoding="utf-8"))
    jsonschema.validate(instance=doc, schema=schema, resolver=_RESOLVER, format_checker=jsonschema.FormatChecker())


def _current(dimension):
    """R3-02 housekeeping: these versions were typed by hand, and BW-MEMBER's
    was left at 2.1 through the round-2 bump to 2.2 — so the negative fixture
    was rejected for the WRONG reason (a stale version const) and stopped
    testing what it exists to test, that an UNDER-SPECIFIED body is rejected.
    Derived from versions.json, like everything else that names a version."""
    return json.loads((ROOT / "versions.json").read_text(
        encoding="utf-8"))["dimensions"][dimension]["value"]


# ---- (a) the authoritative body Schema MUST reject these under-specified bodies
NEGATIVES = [
    ("bw-org.schema.json", {"type": "BW-ORG-v1", "version": _current("discovery_bw_org")}),
    ("bw-med.schema.json", {"type": "BW-MED-v1", "version": _current("discovery_bw_med")}),
    ("bw-member.schema.json", {"type": "BW-MEMBER-v1", "version": _current("discovery_bw_member")}),
]


@pytest.mark.parametrize("schema_file,doc", NEGATIVES)
def test_authoritative_body_schema_rejects(schema_file, doc):
    with pytest.raises(jsonschema.ValidationError):
        _validate(doc, schema_file)


# ---- (b) reproduced divergence: CDDL accepts (outer bound), Schema rejects
@pytest.mark.skipif(not shutil.which("cddl"), reason="the `cddl` tool is not installed")
def test_n2_minimal_org_is_cddl_valid_but_schema_invalid():
    cc = _load("cddl_check", "cddl_check.py")
    body = {"type": "BW-ORG-v1", "version": _current("discovery_bw_org")}
    assert cc._validate(cbor2.dumps(body, canonical=True), "bw-org-body", "minimal-org"), \
        "CDDL is a structural outer bound and admits {type, version}"
    with pytest.raises(jsonschema.ValidationError):
        _validate(body, "bw-org.schema.json")  # the authoritative body validator rejects it


# ---- (c) coherence over every positive sample: projection == decode(payload)
_SAMPLES = sorted((ROOT / "samples").glob("sample-*.json"))


@pytest.mark.parametrize("path", _SAMPLES, ids=lambda p: p.name)
def test_positive_projection_equals_decode(path):
    d = json.loads(path.read_text(encoding="utf-8"))
    if not (isinstance(d, dict) and "sm_artifact_b64" in d and "projection" in d):
        pytest.skip("not a wrapped artefact")
    assert lc.projection_equals_decode(d) == []
