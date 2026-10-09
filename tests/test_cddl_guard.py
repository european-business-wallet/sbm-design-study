# SPDX-License-Identifier: MIT
"""One guard for the optional `cddl` tool, and it is the only one.

Three test modules reached `cddl_check._check_body` with no guard at all, so on
a machine without the Rust tool six tests FAILED where the convention is to
skip. Two other modules each carried their own copy of
`skipif(shutil.which("cddl") is None)`. The convention existed and nothing held
anyone to it, which is how three modules departed from it one at a time.

So the convention is now a check, in two parts:

  * every call that EXECUTES the tool sits behind `cddl_tool.requires_cddl`,
    by a decorator on the test or by the module's `pytestmark`; and
  * no module writes its own `which("cddl")` guard, because that is the form
    that cannot see the failure below.

The failure below is the reason the guard probes instead of asking PATH. The
tool was installed on the maintainer's machine, found by `which`, and killed by
the kernel on exec — an x86_64 build on an arm64 host. `shutil.which` said yes,
every sample "failed to validate", and the gate reported *CDDL is not RFC
8610-conformant*: a verdict on this repository's own CDDL, from a binary that
never ran. A `which`-only guard passes there and the six tests fail exactly as
before, which is why this module tests the probe against a tool that is present
and broken, not only against one that is absent.
"""
import ast
import os
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cddl_check  # noqa: E402
import cddl_probe  # noqa: E402
import cddl_tool  # noqa: E402

#: The entry points of `cddl_check` that shell out to the tool.
TOOL_CALLS = {"_validate", "_check_body"}
OWN_GUARD = re.compile(r"""which\(\s*["']cddl["']\s*\)""")


def _module_guarded(tree):
    return any(isinstance(n, ast.Assign)
               and any(getattr(t, "id", None) == "pytestmark" for t in n.targets)
               and "requires_cddl" in ast.dump(n.value)
               for n in tree.body)


def _tool_calls(node):
    return [c for c in ast.walk(node)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
            and c.func.attr in TOOL_CALLS]


def guard_problems(source, name="<module>"):
    """[(where, why)] for every unguarded execution of the tool."""
    problems = []
    if OWN_GUARD.search(source):
        problems.append((name, "its own `which(\"cddl\")` guard — the one guard "
                               "is `cddl_tool.requires_cddl`, which probes"))
    tree = ast.parse(source)
    guarded = _module_guarded(tree)
    defs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for fn in defs:
        if not _tool_calls(fn) or guarded:
            continue
        if fn.name.startswith("test"):
            if any("requires_cddl" in ast.dump(d) for d in fn.decorator_list):
                continue
            problems.append((f"{name}:{fn.lineno} {fn.name}",
                             "executes the `cddl` tool with no `@requires_cddl`"))
        else:
            problems.append((f"{name}:{fn.lineno} {fn.name}",
                             "a helper executes the `cddl` tool, so the module "
                             "needs `pytestmark = requires_cddl`"))
    if not guarded and any(_tool_calls(n) for n in tree.body if n not in defs):
        problems.append((name, "executes the `cddl` tool at import time, unguarded"))
    return problems


def _modules():
    """Every test module but this one. This module is excluded on purpose and
    it is the only exclusion: its probe sources below are module text as DATA,
    and its one `_check_body` call runs with the probe's memo forced, so it
    never reaches the tool. Scanning itself would flag the fixtures that prove
    the scan works."""
    return [p for p in sorted((ROOT / "tests").glob("test_*.py"))
            if p.name != pathlib.Path(__file__).name]


def test_every_execution_of_the_tool_is_guarded():
    problems = []
    for path in _modules():
        problems += guard_problems(path.read_text(encoding="utf-8"),
                                   path.relative_to(ROOT).as_posix())
    assert problems == [], "\n".join(f"{w}: {why}" for w, why in problems)


def test_the_scan_is_not_looking_at_nothing():
    """The check above is vacuous if nothing in the suite executes the tool.
    These are the modules that do; a refactor that moves the calls behind a
    name this scan cannot see would empty it silently."""
    found = {p.name for p in _modules()
             if _tool_calls(ast.parse(p.read_text(encoding="utf-8")))}
    assert {"test_body_schema_authority.py", "test_constraint_matrix.py",
            "test_validation_failure_outcome.py",
            "test_language_equivalence.py"} <= found, found


@pytest.mark.parametrize("source,expected", [
    ("import cddl_check\n\n\ndef test_x():\n    cddl_check._check_body({}, 'x')\n",
     "no `@requires_cddl`"),
    ("import shutil, pytest\n"
     "pytestmark = pytest.mark.skipif(shutil.which('cddl') is None, reason='no cddl')\n"
     "def test_x():\n    cddl_check._check_body({}, 'x')\n",
     "its own `which(\"cddl\")` guard"),
    ("import cddl_check\n\n\ndef _probe():\n    cddl_check._validate(b'', 'r', 'l')\n"
     "\n\ndef test_x():\n    _probe()\n",
     "needs `pytestmark = requires_cddl`"),
])
def test_the_scan_catches_what_it_claims(source, expected):
    """Invariant 13: the probe builds its world. Each of these is a module that
    could be written tomorrow, and the scan must refuse it."""
    problems = guard_problems(source, "probe.py")
    assert problems, f"the scan accepted: {source!r}"
    assert any(expected in why for _, why in problems), problems


def test_the_guarded_modules_are_accepted():
    """The legitimate case: the five modules that need the tool are clean, so
    the refusals above are not the scan refusing everything."""
    for name in ("test_cddl_coherence.py", "test_language_equivalence.py",
                 "test_body_schema_authority.py", "test_constraint_matrix.py",
                 "test_validation_failure_outcome.py"):
        path = ROOT / "tests" / name
        assert guard_problems(path.read_text(encoding="utf-8"), name) == [], name


# ---- the probe itself: present-and-broken, not only absent ----

def _fake_cddl(tmp_path, body):
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    exe = d / "cddl"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(0o755)
    return d


def _reprobe(monkeypatch, path_dir):
    monkeypatch.setattr(cddl_probe, "_PROBED", [])
    monkeypatch.setenv("PATH", str(path_dir) if path_dir else "")
    return cddl_probe.unusable()


def test_an_absent_tool_is_named_as_absent(monkeypatch):
    reason = _reprobe(monkeypatch, None)
    assert reason and "not installed" in reason
    assert "cargo install cddl" in reason, "the reason must carry the fix"


def test_a_tool_that_runs_is_usable(tmp_path, monkeypatch):
    """The legitimate case first: a tool that answers `--version` is usable, and
    nothing is skipped for it."""
    assert _reprobe(monkeypatch, _fake_cddl(tmp_path, "echo 'cddl 0.10.7'\n")) is None


def test_a_tool_present_and_killed_is_not_reported_as_bad_cddl(tmp_path, monkeypatch):
    """The failure this file exists for. `shutil.which` finds this tool; it
    cannot run. The reason must say so, and must name the architecture, because
    the previous behaviour was to blame the repository's CDDL."""
    reason = _reprobe(monkeypatch, _fake_cddl(tmp_path, "kill -9 $$\n"))
    assert reason and "killed by signal 9" in reason, reason
    assert "architecture" in reason and "cargo install cddl --force" in reason
    assert "RFC 8610" not in reason and "conformant" not in reason


def test_a_tool_that_errors_is_reported_with_its_exit_status(tmp_path, monkeypatch):
    reason = _reprobe(monkeypatch, _fake_cddl(tmp_path, "echo 'boom' >&2\nexit 2\n"))
    assert reason and "exits 2" in reason and "boom" in reason, reason


def test_check_body_raises_the_typed_failure_rather_than_file_not_found(monkeypatch):
    """What the three unguarded modules saw was `FileNotFoundError` raised
    inside a test body, indistinguishable at a glance from a regression. The
    caller now gets a failure that says what it is."""
    monkeypatch.setattr(cddl_probe, "_PROBED", ["the tool is not installed (probe)"])
    with pytest.raises(cddl_check.CddlUnavailable, match="not installed"):
        cddl_check._check_body({"type": "SE-v1"}, "probe")


def test_the_gate_diagnoses_the_tool_and_still_fails_closed_in_ci(tmp_path):
    """`scripts/cddl_check.py` must blame the tool, not the CDDL — and must
    still refuse to skip when CI is set (N4/D7)."""
    broken = _fake_cddl(tmp_path, "kill -9 $$\n")
    env = dict(os.environ, PATH=f"{broken}:/usr/bin:/bin")
    env.pop("CI", None)
    r = subprocess.run([sys.executable, "scripts/cddl_check.py"], cwd=ROOT,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "killed by signal 9" in r.stdout, r.stdout
    assert "RFC 8610-conformant" not in r.stdout, \
        "a binary that never ran must not produce a verdict on the CDDL"

    r = subprocess.run([sys.executable, "scripts/cddl_check.py"], cwd=ROOT,
                       capture_output=True, text=True,
                       env=dict(env, CI="true"))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "MUST run in CI" in r.stdout


def test_the_marker_does_not_skip_under_ci():
    """The policy stated in CONTRIBUTING: optional locally, required in CI. A
    marker that skipped in CI would have moved five modules out of the
    non-divergence guarantee CI owes (N4/D7)."""
    src = (ROOT / "tests" / "cddl_tool.py").read_text(encoding="utf-8")
    assert "STRICT = bool(os.environ.get(\"CI\"))" in src
    assert "UNUSABLE is not None and not STRICT" in src
    if cddl_tool.UNUSABLE is None:
        assert not cddl_tool.requires_cddl.args[0], \
            "the tool runs here, so nothing may be skipped for it"
