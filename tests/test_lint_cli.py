# SPDX-License-Identifier: MIT
"""P1 (ninth review): the linters share ONE flag grammar (scripts/lint_cli.py).

Regression for the verified bug: `discovery_lint --profile production`
(space-separated form) leaked "production" into the file list and reported
"[ERR ] production: cannot read/parse"; only `--profile=production` worked.
Both forms must now work on BOTH linters (and bundle_lint must tolerate the
common flags), and an unknown flag is a usage error, not a silent no-op.
"""
import importlib.util
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lint_cli = _load("lint_cli", "lint_cli.py")


def _run(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        capture_output=True, text=True, cwd=ROOT)


# ---------------------------------------------------------------- unit level

def test_space_and_equals_forms_are_equivalent():
    for argv in (["x", "--profile", "production", "a.json"],
                 ["x", "--profile=production", "a.json"]):
        files, opts = lint_cli.parse_common_flags(argv)
        assert files == ["a.json"]
        assert opts["profile"] == "production"
        assert not opts["unknown"]
    for argv in (["x", "--trust-store", "ts.json", "a.json"],
                 ["x", "--trust-store=ts.json", "a.json"]):
        files, opts = lint_cli.parse_common_flags(argv)
        assert files == ["a.json"]
        assert opts["trust_store"] == "ts.json"


def test_boolean_flags_and_mixing():
    files, opts = lint_cli.parse_common_flags(
        ["x", "--dev-mode", "--verify-demo", "--profile", "production",
         "a.json", "b.json"])
    assert files == ["a.json", "b.json"]
    assert opts["dev_mode"] and opts["verify_demo"]
    assert opts["profile"] == "production"


def test_unknown_flag_is_flagged():
    _files, opts = lint_cli.parse_common_flags(["x", "--bogus", "a.json"])
    assert opts["unknown"] == ["--bogus"]


# ---------------------------------------------------- CLI level (regression)

@pytest.mark.parametrize("script,sample", [
    ("evidence_lint.py", "samples/sample-SE.json"),
    ("discovery_lint.py", "samples/sample-BW-MED.json"),
])
@pytest.mark.parametrize("form", [("--profile", "production"),
                                  ("--profile=production",)])
def test_profile_both_forms_on_both_linters(script, sample, form):
    r = _run(script, *form, sample)
    # The bug: the flag VALUE was read as a file.
    assert "production: cannot read/parse" not in r.stdout
    # The sample file itself was processed (clean or with LINT findings —
    # demo samples legitimately fail the production profile).
    assert sample in r.stdout
    assert r.returncode in (0, 1)


@pytest.mark.parametrize("script,sample", [
    ("evidence_lint.py", "samples/sample-SE.json"),
    ("discovery_lint.py", "samples/sample-BW-MED.json"),
])
@pytest.mark.parametrize("form", [("--trust-store", "samples/trust-store.demo.json"),
                                  ("--trust-store=samples/trust-store.demo.json",)])
def test_trust_store_both_forms_on_both_linters(script, sample, form):
    r = _run(script, *form, sample)
    # The P1 bug pattern: the flag VALUE must never be read as an input file.
    assert "trust-store.demo.json: cannot read/parse (" not in r.stdout
    assert sample in r.stdout
    assert r.returncode == 0, r.stdout + r.stderr


def test_bundle_lint_tolerates_common_flags():
    # R6-W1: the shipped bundles report INCOMPLETE (exit 3) because maximality
    # is not locally provable, so this asserts "no VIOLATIONS", which is what
    # the test was always about — and the flag that accepts a gap must still
    # produce exit 0.
    r = _run("bundle_lint.py", "--profile=production",
             "samples/bundle.scoped.manifest.json")
    assert r.returncode == 3, r.stdout
    assert "bundle.scoped.manifest.json" in r.stdout
    ok = _run("bundle_lint.py", "--profile=production", "--allow-incomplete",
              "samples/bundle.scoped.manifest.json")
    assert ok.returncode == 0, ok.stdout


@pytest.mark.parametrize("script", ["evidence_lint.py", "discovery_lint.py",
                                    "bundle_lint.py"])
def test_unknown_flag_is_a_usage_error(script):
    r = _run(script, "--bogus", "samples/sample-SE.json")
    assert r.returncode == 2
    assert "unknown flag: --bogus" in r.stderr
