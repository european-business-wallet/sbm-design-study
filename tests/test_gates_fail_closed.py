# SPDX-License-Identifier: MIT
"""N4 (D7): the declared non-divergence gates FAIL CLOSED, and CI runs them.

Before this cycle `make conformance` omitted doc-lint, cddl-check skipped when the
`cddl` tool was absent, and CI installed neither cddl nor ran the gate — so a
CDDL/Schema divergence passed CI green. These tests prove: (a) the conformance bar
now includes cddl-check AND doc-lint; (b) doc-lint fails closed on a reintroduced
token; (c) cddl-check fails closed (exit 1, not a silent skip) when the tool is
absent AND CI is set."""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_conformance_bar_includes_cddl_check_and_doc_lint():
    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    line = next(l for l in mk.splitlines() if l.startswith("conformance:"))
    assert "cddl-check" in line and "doc-lint" in line, line


def test_doc_lint_fails_closed_on_a_reintroduced_token():
    probe = ROOT / "docs" / "_gate_probe.md"
    probe.write_text("A COSE_Sign1 over the JCS-canonical object minus seal.\n", encoding="utf-8")
    try:
        r = subprocess.run([sys.executable, "scripts/doc_lint.py"], cwd=ROOT,
                           capture_output=True, text=True)
        assert r.returncode == 2, r.stdout + r.stderr
        assert "_gate_probe.md" in r.stdout
    finally:
        probe.unlink(missing_ok=True)


def test_cddl_check_fails_closed_in_ci_when_tool_absent():
    env = dict(os.environ, CI="true", PATH="/usr/bin:/bin")  # a PATH without the cddl tool
    r = subprocess.run([sys.executable, "scripts/cddl_check.py"], cwd=ROOT,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "MUST run in CI" in r.stdout


def test_make_cddl_check_fails_the_bar_locally_when_tool_absent():
    """N-04: the LOCAL skip must not report green. With `cddl` off PATH and CI
    unset, `make cddl-check` must exit NON-ZERO (previously the recipe rewrote the
    script's exit 3 to 0, so `make conformance` printed green without CDDL)."""
    env = dict(os.environ)
    env.pop("CI", None)
    # A PATH with python3 + make but WITHOUT the cddl tool (~/.cargo/bin excluded).
    env["PATH"] = os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"])
    r = subprocess.run(["make", "cddl-check"], cwd=ROOT,
                       capture_output=True, text=True, env=env)
    assert r.returncode != 0, (
        "make cddl-check reported success with cddl absent (N-04): "
        + r.stdout + r.stderr)


def test_conformance_requires_cddl_and_lite_tolerates_it():
    """The full bar depends on the strict cddl-check; conformance-lite on the
    skip-tolerant one."""
    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    conf = next(l for l in mk.splitlines() if l.startswith("conformance:"))
    lite = next(l for l in mk.splitlines() if l.startswith("conformance-lite:"))
    assert "cddl-check" in conf and "cddl-check-lite" not in conf, conf
    assert "cddl-check-lite" in lite, lite
    # the strict recipe must NOT convert exit 3 to success
    recipe = mk.split("\ncddl-check:\n", 1)[1].splitlines()[0]
    assert "exit 0" not in recipe, recipe
