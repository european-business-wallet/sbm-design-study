# SPDX-License-Identifier: MIT
"""Findings 2 & 3 (evidence 2.1): SE and the recipient confirmation commit to the
exact transmitted MLS octets (`envelope_hash`) and to the RFC 9420 §8.1
GroupContext state (`mls_state` = SHA-256 of the TLS-serialized GroupContext, 2.2), not only
the plaintext digest and group_id+epoch. LINT-DE-16 binds the confirmation's
commitments to the SE's within an Evidence Package; presence is schema-required.

The negative fixtures tamper the confirmation's `envelope_hash` / `mls_state` so
they no longer match the SE — the delivered-ciphertext / group-state attestation
would then not be the one the sender's evidence bound."""
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


def _ep():
    return ev.reconstruct(json.loads((ROOT / "samples" / "sample-EP.json").read_text(encoding="utf-8")))


def _rules(v):
    return [r for r, _ in v.items]


def _lint_de(de, se):
    v = ev.Violations()
    ev.lint_de(v, de, se)
    return _rules(v)


def test_se_and_confirmation_carry_the_commitments():
    ep = _ep()
    se, s3 = ep["se"], ep["outcomes"][0]["s3_attestation"]
    assert "envelope_hash" in se and "mls_state" in se
    assert se["mls_state"].keys() == {"format", "hex"}  # 2.2: MlsStateHash
    assert se["mls_state"]["format"] == "mls10-group-context"
    assert s3["envelope_hash"] == se["envelope_hash"]      # bound
    assert s3["mls_state"] == se["mls_state"]


def test_intact_ep_has_no_de16():
    ep = _ep()
    assert "LINT-DE-16" not in _lint_de(ep["outcomes"][0], ep["se"])


def test_de16_envelope_hash_mismatch_bites():
    ep = _ep()
    de = copy.deepcopy(ep["outcomes"][0])
    de["s3_attestation"]["envelope_hash"] = dict(de["s3_attestation"]["envelope_hash"], hex="ab" * 32)
    assert "LINT-DE-16" in _lint_de(de, ep["se"])


def test_de16_mls_state_mismatch_bites():
    ep = _ep()
    de = copy.deepcopy(ep["outcomes"][0])
    de["s3_attestation"]["mls_state"]["hex"] = "ab" * 32  # tampered state commitment
    assert "LINT-DE-16" in _lint_de(de, ep["se"])
