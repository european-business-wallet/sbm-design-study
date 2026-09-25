# SPDX-License-Identifier: MIT
"""The README's quickstart is executed, not just printed.

`POST /send` read the message identifier from what `make_evidence` returns, and
that has been the sealed artefact — `{sm_artifact_b64, projection}` — since the
octet-authoritative inversion: the request the README prints returned 500. The
defect survived because no test ran the documented sequence.

So this test runs it: it takes the body **from the README**, posts it to the
mock, follows `evidence_url` and lints what comes back. The body is derived,
never copied beside the document, so the README and the endpoint cannot drift
apart without this failing — which is the half of the finding that matters.
"""
import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

flask = pytest.importorskip("flask")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def readme_quickstart():
    """The documented call: (method, path, body) read out of README.md."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"curl -X (?P<method>[A-Z]+) https?://[^/\s]+(?P<path>/\S*)"
                  r"(?P<rest>.*?)-d '(?P<body>\{.*?\})'", text, re.S)
    assert m, "README no longer shows a curl POST with a JSON body"
    return m.group("method"), m.group("path"), json.loads(m.group("body"))


def readme_follow_up_path():
    """The fetch the README tells the reader to make next."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"curl https?://[^/\s]+(/evidence/\S+)", text)
    assert m, "README no longer shows how to fetch the evidence"
    return m.group(1)


def test_the_readme_quickstart_runs_and_its_evidence_lints():
    method, path, body = readme_quickstart()
    assert (method, path) == ("POST", "/send")
    mock = _load("mock_rdp_readme", "mock_rdp.py")
    client = mock.app.test_client()

    posted = client.post(path, json=body)
    assert posted.status_code == 200, \
        f"the README's own request returns {posted.status_code}: {posted.data[:200]}"
    answer = posted.get_json()
    assert {"message_id", "evidence_url", "evidence_cbor_url"} <= set(answer)

    # follow `evidence_url`, as the README says to
    url = answer["evidence_url"]
    assert url.endswith("/evidence/" + answer["message_id"])
    assert readme_follow_up_path().startswith("/evidence/")
    fetched = client.get("/evidence/" + answer["message_id"])
    assert fetched.status_code == 200, "the evidence the response points at is not served"
    artefact = fetched.get_json()
    assert set(artefact) == {"sm_artifact_b64", "projection"}, \
        "the served evidence is not the sealed artefact"

    problems = _load("evidence_lint_readme", "evidence_lint.py").lint(artefact, verify_demo=True)
    assert problems == [], f"the evidence the quickstart produces does not lint: {problems}"

    raw = client.get("/evidence/" + answer["message_id"] + ".cbor")
    assert raw.status_code == 200 and raw.mimetype == "application/cbor" and raw.data


def test_the_documented_body_is_one_the_endpoint_accepts():
    """The drift half: a README body the endpoint would reject fails here, and
    a mode the profile no longer publishes never reaches the reader."""
    _, _, body = readme_quickstart()
    mode = (body.get("payload_hash") or {}).get("hash_mode")
    modes = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text()
                       )["$defs"]["Hash"]["properties"]["hash_mode"]["enum"]
    assert mode in modes, f"the README prints hash_mode {mode!r}, which the schema does not define"
