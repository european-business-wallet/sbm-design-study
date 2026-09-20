# SPDX-License-Identifier: MIT
"""RFC 8785 JCS conformance tests for scripts/jcs.py (X4).

Covers the RFC 8785 §3 concerns: object-key ordering by UTF-16 code units,
string escaping, ECMAScript number serialisation, and the §3.2.3 worked example.
"""
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


jcs = _load("jcs", "jcs.py")


@pytest.mark.parametrize("value,expected", [
    (333333333.33333329, "333333333.3333333"),
    (1e30, "1e+30"),
    (4.50, "4.5"),
    (2e-3, "0.002"),
    (1e-27, "1e-27"),
    (0, "0"),
    (-0.0, "0"),
    (42, "42"),
    (10.0, "10"),          # integer-valued float -> integer form
    (-5, "-5"),
])
def test_number_serialization(value, expected):
    assert jcs.canonicalize(value) == expected


def test_nan_infinity_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            jcs.canonicalize(bad)


def test_key_ordering_by_utf16():
    # Keys must be ordered by UTF-16 code units, not insertion order.
    # 'A'(0x41) < 'a'(0x61) < 'b'(0x62) < 'é'(0xE9) < '€'(0x20AC)
    obj = {"b": 1, "a": 2, "é": 3, "A": 4, "€": 5}
    assert jcs.canonicalize(obj) == '{"A":4,"a":2,"b":1,"é":3,"€":5}'


def test_string_escaping():
    s = "€$\nA'B\"\\/"   # € $ U+000F LF A ' B " backslash /
    # € and $ literal, U+000F -> , LF -> \n, " -> \", backslash -> \\, / literal
    assert jcs.canonicalize(s) == '"€$\\u000f\\nA\'B\\"\\\\/"'


def test_literals_and_structure():
    assert jcs.canonicalize([None, True, False]) == "[null,true,false]"
    assert jcs.canonicalize({}) == "{}"
    assert jcs.canonicalize([]) == "[]"


def test_rfc8785_worked_example():
    # RFC 8785 §3.2.3 input, built directly to avoid source-escaping ambiguity.
    s = "€" + "$" + "" + "\n" + "A'B" + "\"" + "\\" + "\\" + "\"" + "/"
    obj = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": s,
        "literals": [None, True, False],
    }
    out = jcs.canonicalize(obj)
    # keys reordered (literals < numbers < string), no whitespace, canonical numbers
    assert out.startswith(
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"')
    # value-preserving and idempotent
    assert json.loads(out) == obj
    assert jcs.canonicalize(json.loads(out)) == out
