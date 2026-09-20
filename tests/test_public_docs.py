# SPDX-License-Identifier: MIT
"""Round 11 / B8 — D11-01..03: the public reading path agrees with what exists.

The review's acceptance for the walkthrough: "a reviewer following either
narrative or diagram produces the same request sequence, proof inputs,
outcomes and clocks as the APIs" — and a token scanner cannot establish that.
These tests check AGREEMENT rather than the presence of sentences: every
operation the walkthrough tells a reader to call exists, with that method, in
a published contract; the README's setup instructions are the preflight's own
list; and the version sweep now reads the reader-facing prose that was never
swept, so the stale claims D11-02 found cannot return unnoticed.
"""
import json
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import version_manifest as vm  # noqa: E402

CONTRACTS = ["wallet-rdp-openapi.yaml", "delivery-service-openapi.yaml",
             "rdp-relay-openapi.yaml", "edd-resolver-openapi.yaml",
             "federation-register-openapi.yaml"]


def _published():
    ops = set()
    for c in CONTRACTS:
        for path, methods in yaml.safe_load((ROOT / c).read_text())["paths"].items():
            ops |= {(m.upper(), path) for m in methods if m in ("get", "post", "delete", "put")}
    return ops


def test_every_operation_the_walkthrough_names_is_published():
    text = (ROOT / "docs" / "federated-flow-explainer.md").read_text()
    named = set(re.findall(r"`(GET|POST|DELETE|PUT) (/[^`\s]+)`", text))
    assert len(named) >= 10, f"the walkthrough names too few operations to be a sequence: {named}"
    missing = sorted(named - _published())
    assert not missing, f"the walkthrough tells a reader to call operations no contract publishes: {missing}"


def _diagram():
    return (ROOT / "docs" / "diagrams" / "federated-flow.mermaid").read_text()


def test_every_operation_the_diagram_names_is_published():
    """D12-01: the diagram drew an MSP-to-MSP relay no contract publishes, and
    a join without the acknowledgement that IS joining."""
    named = {(m, re.sub(r"\{[^}]+\}", "{x}", p)) for m, p in
             re.findall(r"\b(GET|POST|DELETE|PUT) (/[^\s·—()]+)", _diagram())}
    published = {(m, re.sub(r"\{[^}]+\}", "{x}", p)) for m, p in _published()}
    assert {("POST", "/relay/messages"), ("DELETE", "/welcome/{x}"),
            ("POST", "/messages")} <= named
    assert not sorted(named - published), sorted(named - published)


def test_the_rendered_diagram_is_the_source():
    """The SVG is what the walkthrough embeds; a source edited without a
    re-render teaches the old flow. Every message label must be in it."""
    import html
    svg = (ROOT / "docs" / "diagrams" / "federated-flow.svg").read_text()
    labels = re.findall(r"^\s*\w+\s*-{1,2}>>\s*\w+:\s*(.+?)\s*$", _diagram(), re.M)
    assert len(labels) > 30
    missing = [l for l in labels if html.escape(l, quote=False) not in svg and l not in svg]
    assert not missing, f"re-render the diagram (mmdc): {missing[:3]}"


def test_the_readme_setup_is_the_preflights_list():
    req = (ROOT / "scripts" / "requirements.txt").read_text()
    required_part, optional_part = req.split("# Optional", 1)
    pkg = re.compile(r"^([A-Za-z0-9_.-]+)\s*[<>=]", re.M)
    required, optional = set(pkg.findall(required_part)), set(pkg.findall(optional_part))
    readme = (ROOT / "README.md").read_text()
    req_line = next(l for l in readme.splitlines() if l.startswith("- **Required for the canonical"))
    opt_line = next(l for l in readme.splitlines() if l.startswith("- **Optional / demo-only**"))
    listed_req = set(re.findall(r"`([A-Za-z0-9_.-]+)`", req_line))
    listed_opt = set(re.findall(r"`([A-Za-z0-9_.-]+)`", opt_line))
    assert required <= listed_req, f"required by the preflight, not in the README: {sorted(required - listed_req)}"
    assert not (required & listed_opt), f"called optional, required by the preflight: {sorted(required & listed_opt)}"
    assert optional <= listed_opt


def test_the_readmes_second_preflight_list_is_the_preflights_own():
    """D12-02: the README states the preflight's list twice, and only the first
    was checked — the second still named five of the seven packages."""
    import check_env
    package = {"yaml": "pyyaml", "nacl": "pynacl",
               "openapi_spec_validator": "openapi-spec-validator"}
    checked = {package.get(m, m) for m in check_env.REQUIRED}
    line = next(l for l in (ROOT / "README.md").read_text().splitlines()
                if l.startswith("`make test` runs `scripts/check_env.py` first"))
    listed = set(re.findall(r"`([A-Za-z0-9_.-]+)`", line.split("if any of", 1)[1].split("is missing", 1)[0]))
    assert listed == checked, f"README {sorted(listed)} vs preflight {sorted(checked)}"


def test_the_reading_path_leaves_legal_effect_open():
    """The walkthrough said the Article 43(2) presumptions attach until round
    11; the evidence explainer until round 12; the agent explainer, the vision
    note and the README's feature list until the onboarding pass (DOC-02).
    Whether they attach is a legal question this study does not answer — so
    every sentence about it, in any active reader-facing document, states it
    as the question it is."""
    manifest = json.loads((ROOT / "versions.json").read_text())
    files = vm.prose_sweep_files(ROOT, manifest)
    assert "docs/agent-profile-explainer.md" in files and "README.md" in files
    for rel in files:
        text = (ROOT / rel).read_text()
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            if re.search(r"presumptions?\b.*\battach", sentence, re.I):
                assert "whether" in sentence.lower(), f"{rel}: {sentence.strip()[:160]}"


def test_the_prose_sweep_catches_an_unmarked_stale_version(tmp_path):
    manifest = json.loads((ROOT / "versions.json").read_text())
    (tmp_path / "README.md").write_text(
        "a network may run evidence 1.15 today\n"
        "scopes (introduced in evidence 1.15) are optional\n"
        f"the current evidence {manifest['dimensions']['evidence']['value']} is sealed\n")
    found = vm.sweep_active_prose(tmp_path, dict(manifest, active_prose_sweep=["README.md"]))
    assert [(n, tok) for _, n, tok in found] == [(1, "evidence 1.15")]


def test_the_reader_facing_prose_is_current():
    manifest = json.loads((ROOT / "versions.json").read_text())
    assert "README.md" in manifest["active_prose_sweep"]
    assert vm.sweep_active_prose(ROOT, manifest) == []
