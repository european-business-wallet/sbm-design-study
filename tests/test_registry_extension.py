# SPDX-License-Identifier: MIT
"""X-25 — additive registries are actually additive; one owner per registry.

Former defect: §9.3 said a new NDE/RE reason is a registry action (no version
bump), yet the closed schema enums AND the closed CDDL reason sets rejected an
unknown code before the I-D's "preserve verbatim / treat as generic" ingest MUST
could apply — that MUST was unsatisfiable. The content-class tier-1 set was
frozen in Python. And the transport I-D claimed to BE the registry.

Now: the reason value spaces are pattern-open at schema+CDDL; the registered
sets + event bindings live in machine-readable registry artefacts
(registries/*.json, owned by umbrella §13.4) that the linters LOAD; an
unregistered well-formed code is accepted + preserved + WARNed (LINT-NDE-W1);
a registered code still enforces its bindings.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import evidence_lint as el  # noqa: E402
import discovery_lint as dl  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")
NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]


def _lint_art(body):
    return el.lint(mock.evidence_artifact(body))


def test_unknown_wellformed_reason_is_accepted_and_warned():
    """The acceptance criterion: a v2 verifier safely ingests and preserves an
    unknown additive reason without treating it as a known semantic."""
    bad = dict(NDE)
    bad["reason"] = "x-future-registered-ground"
    issues = _lint_art(bad)
    fails = [(r, m) for r, m in issues if not r.split("-")[-1].startswith("W")]
    warns = [(r, m) for r, m in issues if r.split("-")[-1].startswith("W")]
    assert not fails, f"an unknown well-formed reason must not FAIL: {fails}"
    assert any(r == "LINT-NDE-W1" for r, _ in warns), warns
    # schema layer: pattern-open accepts it
    assert lc.validate_body(bad) == []


def test_lexically_invalid_reason_is_rejected():
    bad = dict(NDE)
    bad["reason"] = "NOT-A-VALID-Reason!"
    assert lc.validate_body(bad), "the lexical bound must reject a malformed code"


def test_registered_reason_with_wrong_event_still_fails():
    """Opening the value space must NOT weaken registered semantics."""
    bad = dict(NDE)
    bad["reason"] = "expired"  # registered: requires C.5-AcceptanceRejectionExpiry
    bad["event"] = "A.2-SubmissionRejection"
    rules = [r for r, _ in _lint_art(bad)]
    assert "LINT-NDE-07" in rules, rules


def test_lint_tables_are_loaded_from_the_registry_artefacts():
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    expected_map = {k: set(v["allowed_events"]) for k, v in reg["nde_reasons"].items()
                    if v.get("allowed_events")}
    assert lc.NDE_REASON_EVENT == expected_map
    assert lc.RELAY_B2_REASONS == set(reg["relay_b2_reasons"])
    assert lc.RELAY_B2_TO_NDE == {k: v["nde_reason"]
                                  for k, v in reg["relay_b2_reasons"].items()}
    classes = json.loads((ROOT / "registries" / "content-classes.json").read_text())
    assert dl.STANDARD_CONTENT_CLASSES == set(classes["tier1"])


def test_registry_action_reaches_the_linter_without_code_change(tmp_path, monkeypatch):
    """Simulate a registration: add a code to the artefact -> the recognized set
    grows with NO lint-code change (the registry is the single source)."""
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    reg["nde_reasons"]["carrier-strike"] = {
        "allowed_events": ["D.2-ContentConsignmentFailure"], "status": "active"}
    monkeypatch.setattr(lc, "_REASONS", reg)
    recognized = set(reg["nde_reasons"])
    assert "carrier-strike" in recognized  # the registry action, no code change


def test_unknown_reason_passes_cddl_and_projection_equality():
    """The full stack: unknown reason -> CDDL-open + projection==payload +
    schema-pattern-open. (The former defect: CDDL's closed nde-reason set.)"""
    bad = dict(NDE)
    bad["reason"] = "x-future-registered-ground"
    art = mock.evidence_artifact(bad)
    assert lc.projection_equals_decode(art) == []
    cddl = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    assert "nde-reason = tstr" in cddl, "the CDDL reason set closed again"


def test_ownership_split_is_recorded():
    """X-34 residual: the I-D no longer claims to BE the registry; the umbrella
    owns the artefacts; the well-known registration moved to §8.1."""
    idtxt = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    assert "initially this document" not in idtxt
    assert "registries/reason-codes.json" in umb and "registries/content-classes.json" in umb
    assert "Well-Known URI suffix **`bw`**" in umb
    # the I-D registers no well-known URI and drops the undefined /.well-known/rdp
    assert "Well-Known URI suffixes `bw` and `rdp`" not in idtxt
