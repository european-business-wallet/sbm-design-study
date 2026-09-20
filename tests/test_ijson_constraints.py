# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: 2026 Secure Business Messaging contributors
"""M1/J0+ (twenty-fifth review) — the I-JSON restricted data model.

Covers the two machine-checkable rules the schema cannot express:
  LINT-PKG-09  no float, no integer outside the safe range (2^53-1)
  LINT-PKG-10  duplicate object keys are rejected at the parse boundary
"""
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lint_cli = _load("lint_cli", "lint_cli.py")


# ── LINT-PKG-09: safe-integer / no-float walk ────────────────────────────────

def test_safe_integers_and_strings_pass():
    doc = {"mls_epoch": "18446744073709551615",  # uint64 max, as a decimal string
           "ttl": 4294967295, "n": 0, "neg": -5, "flag": True, "arr": [1, 2, 3]}
    assert lint_cli.find_unsafe_numbers(doc) == []


def test_float_is_flagged():
    hits = lint_cli.find_unsafe_numbers({"a": {"b": 1.0}})
    assert hits and hits[0][0] == "$.a.b" and "float" in hits[0][1]


def test_integer_above_safe_range_is_flagged():
    # 2^53 + 1 — the exact C1 defect (a uint64 value JCS cannot round-trip).
    hits = lint_cli.find_unsafe_numbers({"mls_epoch": 9007199254740993})
    assert hits and hits[0][0] == "$.mls_epoch" and "safe range" in hits[0][1]


def test_safe_boundary_is_allowed():
    assert lint_cli.find_unsafe_numbers({"x": lint_cli.SAFE_INT_MAX}) == []
    assert lint_cli.find_unsafe_numbers({"x": lint_cli.SAFE_INT_MAX + 1}) != []


# ── LINT-PKG-10: duplicate-key rejection ─────────────────────────────────────

def test_load_ijson_accepts_unique_keys():
    assert lint_cli.load_ijson('{"a": 1, "b": 2}') == {"a": 1, "b": 2}


def test_load_ijson_rejects_duplicate_keys():
    with pytest.raises(lint_cli.DuplicateKeyError) as exc:
        lint_cli.load_ijson('{"a": 1, "a": 2}')
    assert "a" in exc.value.keys


def test_load_ijson_rejects_duplicate_nested_keys():
    with pytest.raises(lint_cli.DuplicateKeyError):
        lint_cli.load_ijson('{"outer": {"k": 1, "k": 2}}')
