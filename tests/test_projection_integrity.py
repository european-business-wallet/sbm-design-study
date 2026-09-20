# SPDX-License-Identifier: MIT
"""LINT-PKG-11 (N1, projection-integrity cycle): the wire projection MUST equal
`decode(payload)` EXACTLY — recursive, array length AND order included. A
projection element that no signed artefact covers (extra, missing, reordered or
mutated) is rejected fail-closed, on both linters.

Every case forges ONLY the projection, never the authoritative `sm_artifact_b64`,
so the signed payload is unchanged — precisely the attack LINT-PKG-11 closes: a
JSON consumer reading `projection` would otherwise see content in no signed
artefact. The `sample-EP.json` extra-outcome case is the independently reproduced
finding (distinct `evidence_id` dodges the schema's `uniqueItems`)."""
import copy
import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("evidence_lint", "evidence_lint.py")
dv = _load("discovery_lint", "discovery_lint.py")


def _sample(name):
    return json.loads((ROOT / "samples" / name).read_text(encoding="utf-8"))


def _rules(items):
    return [r for r, _ in items]


# ------------------------------------------------------------ positive control

def test_intact_projection_has_no_pkg11():
    assert "LINT-PKG-11" not in _rules(ev.lint(_sample("sample-EP.json")))
    assert "LINT-PKG-11" not in _rules(dv.lint(_sample("sample-BW-ORG.json")))


# ------------------------------------------------------------------ negatives

def test_pkg11_extra_projection_outcome():
    """The reproduced N1 case: an extra projection outcome (distinct evidence_id,
    dodging `uniqueItems`) that no signed sub-artefact covers."""
    d = _sample("sample-EP.json")
    forged = copy.deepcopy(d["projection"]["outcomes"][0])
    forged["evidence_id"] = forged["evidence_id"] + "-FORGED"
    forged["delivered_at"] = "2099-01-01T00:00:00Z"
    d["projection"]["outcomes"].append(forged)
    assert "LINT-PKG-11" in _rules(ev.lint(d))


def test_pkg11_missing_projection_outcome():
    d = _sample("sample-EP.json")
    d["projection"]["outcomes"] = []
    assert "LINT-PKG-11" in _rules(ev.lint(d))


def test_pkg11_reordered_projection_array():
    d = _sample("sample-EP.json")
    d["projection"]["states"] = list(reversed(d["projection"]["states"]))
    assert "LINT-PKG-11" in _rules(ev.lint(d))


def test_pkg11_mutated_projection_scalar():
    d = _sample("sample-EP.json")
    d["projection"]["outcomes"][0]["evidence_id"] += "-MUTATED"
    assert "LINT-PKG-11" in _rules(ev.lint(d))


def test_pkg11_discovery_mutated_projection_scalar():
    d = _sample("sample-BW-ORG.json")
    d["projection"]["display_name"] = "Totally Different Org"
    assert "LINT-PKG-11" in _rules(dv.lint(d))
