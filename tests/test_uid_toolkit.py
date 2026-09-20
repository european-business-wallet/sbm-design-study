# SPDX-License-Identifier: MIT
"""The shipped UID toolkit — identifiers, and (DR-14) its discovery output.

DR-14 (round-2 review, Medium): this file tested UID/MID generation and
nothing else. The toolkit also emits BW-MED documents, and it emitted
`version: "1.1"` (current 2.0) with an in-object
`doc_cose_b64: "DEMO_UNSIGNED_PLACEHOLDER"` — the superseded, pre-M4 shape
where the signature sits inside the body it signs — plus a DNS-alias generator
for a discovery model the profile removed. The README RECOMMENDS this toolkit,
so the official quick-start produced an artefact the current specification
REJECTS and pointed implementers at an obsolete model. Five releases of drift
went unnoticed because nothing validated the output.

The DR-14 tests below check the generated ARTEFACT, not the generator's
source: what matters is what an implementer receives from the documented
command.
"""

import os, sys, pathlib, importlib.util, re, json, subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TK_PATH = ROOT / "scripts/eu_entity_uid_toolkit.py"

spec = importlib.util.spec_from_file_location("toolkit", str(TK_PATH))
toolkit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toolkit)

def test_mid_generate_and_validate():
    mid = toolkit.mid_generate()
    ok, errs = toolkit.mid_validate(mid)
    assert ok, f"MID should validate, got errors: {errs}"
    # flip last char to make it invalid
    bad = mid[:-1] + ("0" if mid[-1] != "0" else "1")
    ok, _ = toolkit.mid_validate(bad)
    assert not ok, "Corrupted MID must not validate"

def test_uid_generate_and_validate_randoms():
    # generate a few random EOID and PSBID
    for scheme in ("EOID","PSBID"):
        for cc in ("DE","FR","IT","ES"):
            uid = toolkit.uid_generate(cc, scheme)
            ok, errs = toolkit.uid_validate(uid)
            assert ok, f"UID {uid} should validate: {errs}"
            # tamper C2
            payloadc = uid.split("-")[3]
            tampered = uid[:-1] + ("0" if uid[-1] != "0" else "1")
            ok2, _ = toolkit.uid_validate(tampered)
            assert not ok2, "Tampered UID C2 must fail"

def test_address_and_label():
    uid = toolkit.uid_generate("DE", "EOID")
    addr = toolkit.build_bw_address(uid)
    assert addr.startswith("bw:uid:" + uid)
    mid = toolkit.mid_generate()
    addr_mid = toolkit.build_bw_address(uid, mid=mid)
    assert addr_mid.endswith("/u/" + mid)
    addr_role = toolkit.build_bw_address(uid, role="invoices")
    assert addr_role.endswith("/r/invoices")
    # label
    lab = toolkit.uid_label(uid, length=24)
    assert lab.startswith("h-")
    assert 2 < len(lab) <= 26  # h- + 24


# ===========================================================================
# DR-14 — the discovery output
# ===========================================================================

UID = "EU-DE-EOID-7K3D9W0Q2M5FW0"


def _run(*args):
    return subprocess.run([sys.executable, str(TK_PATH), *args],
                          capture_output=True, text=True, cwd=str(ROOT))


@pytest.fixture(scope="module")
def artefact():
    r = _run("med-stub", "--uid", UID, "--host", "msp.example.eu")
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def test_the_generated_artefact_passes_the_current_discovery_lint(artefact, tmp_path):
    """The review's first criterion. All three of its checks run in one
    command: the linter validates the schema (LINT-PKG-12) and projection
    equivalence (LINT-PKG-11) before any rule of its own."""
    p = tmp_path / "med.json"
    p.write_text(json.dumps(artefact))
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "discovery_lint.py"),
                        str(p)], capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_generated_version_comes_from_versions_json(artefact):
    """Not a literal. The toolkit pinned 1.1 while the schema, the CDDL and the
    samples had moved to 2.0 — R-01's defect in a file R-01's gate did not
    reach."""
    want = json.loads((ROOT / "versions.json").read_text())[
        "dimensions"]["discovery_bw_med"]["value"]
    assert artefact["projection"]["version"] == want
    src = TK_PATH.read_text()
    assert '"version": "1.1"' not in src
    assert '_current_version("discovery_bw_med")' in src


def test_the_output_is_the_m4_artefact_not_a_body_with_a_signature_field(artefact):
    """The octet-authoritative inversion: the seal IS the artefact and the
    projection is derived from it. A `doc_cose_b64` inside the body is the
    superseded shape — a signature field within the object it signs."""
    assert set(artefact) == {"sm_artifact_b64", "projection"}
    assert "doc_cose_b64" not in artefact["projection"]
    assert "DEMO_UNSIGNED_PLACEHOLDER" not in json.dumps(artefact)


def test_the_projection_equals_the_decoded_payload(artefact):
    """Checked directly, not only through the linter, because 'it seals with
    the same functions as sample generation' is the claim being made."""
    sys.path.insert(0, str(ROOT / "scripts"))
    from lint_cli import projection_equals_decode
    assert not list(projection_equals_decode(artefact))


def test_no_active_command_emits_a_removed_dns_discovery_path():
    r = _run("dns-zone", "--uid", UID, "--host", "msp.example.eu")
    assert r.returncode != 0, "a removed command must not succeed"
    assert "REMOVED" in r.stderr
    assert "TXT" not in r.stdout and "SRV" not in r.stdout


def test_the_quick_start_commands_execute():
    """The commands the README shows, run as shown."""
    assert _run("gen-uid", "--cc", "DE", "--scheme", "EOID").returncode == 0
    assert _run("val-uid", UID).returncode == 0
    assert _run("med-stub", "--uid", UID, "--host", "msp.example.eu").returncode == 0


def test_the_unsealed_body_is_also_the_current_shape():
    """A caller signing with its own key still gets the current body."""
    r = _run("med-stub", "--uid", UID, "--host", "msp.example.eu", "--no-seal")
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout)
    assert body["type"] == "BW-MED-v1"
    assert "doc_cose_b64" not in body and "sm_artifact_b64" not in body
    want = json.loads((ROOT / "versions.json").read_text())[
        "dimensions"]["discovery_bw_med"]["value"]
    assert body["version"] == want


def test_the_freshness_bound_is_present():
    """LINT-DISC-05. The stub omitted both instants, so the emitted document
    failed the current linter on a REQUIRED field, not merely on its version."""
    body = json.loads(_run("med-stub", "--uid", UID, "--no-seal").stdout)
    assert body["asserted_at"] < body["expires_at"]


def _readme():
    return " ".join((ROOT / "README.md").read_text()
                    .replace("**", "").replace("`", "").split())


def test_the_demo_seal_is_documented_as_a_demo():
    readme = _readme()
    assert "ephemeral key, not a QSealC" in readme
    assert "not a QSealC" in TK_PATH.read_text()


def test_the_readme_no_longer_teaches_the_removed_alias_layer():
    readme = _readme()
    assert "Removed: dns-zone" in readme
    assert "sealed M4 artefact" in readme
