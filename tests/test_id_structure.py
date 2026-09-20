# SPDX-License-Identifier: MIT
"""Internet-Draft structure check (restructure cycle).

Keeps the I-D buildable without gating CI on kramdown-rfc/xml2rfc: verifies the
kramdown-rfc front matter and the required RFC 7322 sections are present.
"""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
DRAFT = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


build_id = _load("build_id", "build_id.py")


def test_draft_exists():
    assert DRAFT.is_file()


def test_draft_structure_is_valid():
    errors = build_id.structure_check(str(DRAFT))
    assert errors == [], f"I-D structure errors: {errors}"
