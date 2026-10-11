#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Can the Rust `cddl` tool be used here, and if not, why.

Its own module, with no third-party imports, because three callers need the
answer and one of them is `scripts/check_env.py` — the dependency preflight,
which must still run and report in an environment where `cbor2` is missing.
The other two are the CDDL gate (`scripts/cddl_check.py`) and the test guard
(`tests/cddl_tool.py`).
"""
import re
import shutil
import subprocess


class CddlUnavailable(RuntimeError):
    """The `cddl` tool could not be executed AT ALL — absent, or present and
    unrunnable. Kept apart from a validation failure on purpose: a validation
    failure is a fact about this repository, this is a fact about the machine."""


_PROBED = []          # memo: empty = not probed, [None] = usable, [reason] = not


def unusable():
    """None when the tool runs, otherwise why it does not. Probed once.

    `shutil.which` alone is not enough, and the gap was not hypothetical: an
    x86_64 `cddl` on an arm64 machine is found on PATH and killed by the kernel
    on exec. Every sample then "failed to validate" and this gate printed
    `CDDL is not RFC 8610-conformant` — a verdict about the repository's own
    CDDL, reached by a binary that never ran. Six tests failed with it, and a
    session cannot tell that apart from a regression at a glance. So the probe
    EXECUTES the tool once and says what it found.
    """
    if not _PROBED:
        _PROBED.append(_probe())
    return _PROBED[0]


def _probe():
    exe = shutil.which("cddl")
    if exe is None:
        return ("the `cddl` tool is not installed — install it with "
                "`cargo install cddl --version 0.9.5 --locked`")
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True)
    except OSError as exc:
        return f"`cddl` at {exe} could not be executed: {exc}"
    if r.returncode < 0:
        return (f"`cddl` at {exe} was killed by signal {-r.returncode} on a bare "
                "`--version`; on Apple silicon this is usually a binary built "
                "for another architecture — rebuild it with "
                "`cargo install cddl --force`")
    if r.returncode != 0:
        first = ((r.stderr or r.stdout or "").strip().splitlines() or [""])[0]
        return (f"`cddl` at {exe} exits {r.returncode} on a bare `--version`"
                + (f": {first}" if first else ""))
    _VERSION.append(_parse_version(r.stdout or r.stderr or ""))
    return None


_VERSION = []
_SEMVER = re.compile(r"(\d+\.\d+\.\d+)")


def _parse_version(text):
    """The version `cddl --version` printed, or None if it printed none."""
    m = _SEMVER.search(text)
    return m.group(1) if m else None


def installed():
    """The version of the tool that actually ran, or None.

    The probe already executes `cddl --version`; this is what it said. It is
    separate from `unusable()` because a tool that runs is usable whatever
    version it is — whether it is the version this repository PINS is a
    different question, and `scripts/check_env.py` asks it.
    """
    if not _PROBED:
        unusable()
    return _VERSION[0] if _VERSION else None
