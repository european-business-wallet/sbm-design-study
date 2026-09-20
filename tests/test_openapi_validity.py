# SPDX-License-Identifier: MIT
"""DR-09 — the published contracts are structurally valid, and a gate says so.

Former defect (round-2 review, High), independently reproduced with
`openapi-spec-validator 0.9.0`:

  * `rdp-relay-openapi.yaml` declared OpenAPI 3.0.3 and used security-scheme
    type `mutualTLS`, which exists only in 3.1;
  * `edd-resolver-openapi.yaml` placed `description` directly inside Media Type
    Objects, where 3.0.3 permits only schema / example(s) / encoding.

The companion tests only parsed the YAML and checked that `openapi` began with
`3.`, so a release stayed green while code generators and validators could
reject the normative contracts outright.

Fixed per **R2-M4**: all four contracts move to OpenAPI 3.1 — `mutualTLS` is
native there, and 3.1's JSON-Schema alignment is what lets the wallet-RDP
contract `$ref` the authoritative evidence schemas (DR-07) instead of
paraphrasing them. The media-type descriptions moved into their Schema Objects,
where they are legal in either version.

A gate alone is not evidence that the gate WORKS. The tests below therefore
also inject each defect the review found and assert the gate rejects it — the
standing invariant applied to tooling: a validator that has never failed is not
known to be able to fail.
"""
import copy
import importlib.util
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

spec = importlib.util.spec_from_file_location(
    "openapi_validate", ROOT / "scripts" / "openapi_validate.py")
ov = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ov)


def _spec(name):
    return yaml.safe_load((ROOT / name).read_text())


# ---------------------------------------------------------------------------
# The four contracts, as shipped
# ---------------------------------------------------------------------------

def test_every_published_contract_validates():
    for name in ov.CONTRACTS:
        assert not ov.validate(ROOT / name), name


def test_all_four_declare_openapi_31():
    """R2-M4. Not 'starts with 3.' — that is the check that let this ship."""
    for name in ov.CONTRACTS:
        assert _spec(name)["openapi"] == "3.1.0", name


def test_the_gate_covers_every_contract_in_the_repository():
    """A contract absent from the gate's list is a contract nothing validates."""
    on_disk = {p.name for p in ROOT.glob("*openapi*.yaml")}
    assert on_disk == set(ov.CONTRACTS), on_disk.symmetric_difference(ov.CONTRACTS)


# ---------------------------------------------------------------------------
# The gate rejects the exact defects the review found
# ---------------------------------------------------------------------------

def _validate_dict(spec_dict, tmp_path, name="probe.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(spec_dict, allow_unicode=True))
    return ov.validate(p)


def test_an_invalid_security_scheme_type_fails(tmp_path):
    """`mutualTLS` under a 3.0.3 declaration — the relay contract's defect."""
    s = _spec("rdp-relay-openapi.yaml")
    s["openapi"] = "3.0.3"
    assert any(v.get("type") == "mutualTLS"
               for v in s["components"]["securitySchemes"].values()), \
        "the fixture no longer contains the scheme this test is about"
    problems = _validate_dict(s, tmp_path)
    assert problems, "a 3.0.3 document using mutualTLS must be rejected"
    assert "mutualTLS" in problems[0]


def test_an_invalid_media_type_object_field_fails(tmp_path):
    """`description` inside a Media Type Object — the EDD contract's defect."""
    s = _spec("edd-resolver-openapi.yaml")
    s["openapi"] = "3.0.3"
    resp = s["paths"]["/.well-known/bw/med/{uid}"]["get"]["responses"]["200"]
    resp["content"]["application/cbor"]["description"] = "not legal here in 3.0.3"
    assert _validate_dict(s, tmp_path), \
        "a Media Type Object carrying `description` must be rejected under 3.0.3"


def test_a_bogus_schema_construct_fails(tmp_path):
    """The gate is not merely a YAML parser: a structurally wrong document
    fails even when it parses cleanly."""
    s = _spec("wallet-rdp-openapi.yaml")
    s["paths"]["/submissions"]["post"]["responses"] = "not an object"
    assert _validate_dict(s, tmp_path)


# ---------------------------------------------------------------------------
# Offline resolution
# ---------------------------------------------------------------------------

def test_every_external_ref_resolves_without_the_network(tmp_path):
    """The gate installs a guard that turns a remote fetch into an error rather
    than a hang or a silent pass; the shipped contracts must not need one."""
    ov._offline_guard()
    for name in ov.CONTRACTS:
        assert not ov.validate(ROOT / name), f"{name} needed the network"


def test_a_remote_ref_is_rejected_rather_than_fetched(tmp_path):
    ov._offline_guard()
    s = _spec("wallet-rdp-openapi.yaml")
    s["paths"]["/submissions"]["post"]["requestBody"]["content"][
        "application/json"]["schema"] = {"$ref": "https://example.invalid/x.json"}
    problems = _validate_dict(s, tmp_path)
    assert problems, "a remote $ref must not be silently accepted"


def test_local_refs_point_at_files_that_exist():
    """Offline resolution is only meaningful if the targets are in the tree."""
    import re
    for name in ov.CONTRACTS:
        text = (ROOT / name).read_text()
        for ref in re.findall(r"\$ref:\s*'?\"?(\./[^'\"\s}]+)", text):
            target = (ROOT / ref.split("#")[0]).resolve()
            assert target.exists(), f"{name}: dangling $ref {ref}"


# ---------------------------------------------------------------------------
# The gate is wired into the bar, not merely available
# ---------------------------------------------------------------------------

def test_the_gate_is_part_of_make_conformance():
    mk = (ROOT / "Makefile").read_text()
    line = next(l for l in mk.splitlines() if l.startswith("conformance:"))
    assert "openapi-validate" in line, "the validator is not on the release bar"
    lite = next(l for l in mk.splitlines() if l.startswith("conformance-lite:"))
    assert "openapi-validate" in lite, \
        "the lite bar skips the validator — it must not; the escape hatch is " \
        "for a missing Rust toolchain, not for contract validity"


def test_the_validator_is_a_pinned_required_dependency():
    req = (ROOT / "scripts" / "requirements.txt").read_text()
    assert "openapi-spec-validator" in req
    assert "openapi-spec-validator" not in req.split("# Optional")[-1], \
        "the validator must be REQUIRED — the review asked for it on the bar"
    env = (ROOT / "scripts" / "check_env.py").read_text()
    assert "openapi_spec_validator" in env
