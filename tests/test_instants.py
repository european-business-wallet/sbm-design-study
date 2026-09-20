# SPDX-License-Identifier: MIT
"""DR-05 — RFC 3339 instants are parsed, never compared as strings.

Former defect (round-2 review, High; reproduced): every window check in the
repository compared timestamps as STRINGS, which is wrong at fractional
boundaries because '.' sorts before 'Z':

    '2026-04-04T10:16:23.1Z' < '2026-04-04T10:16:23Z'   ->  True

though the first instant is later. A DE delivered 100 ms after expiry
produced no LINT-BND-22 violation. Worse, `_latest_declared_instant()` did
not merely mishandle offsets — it SKIPPED any timestamp not ending in 'Z',
so a valid '2026-07-28T12:00:00+02:00' vanished from the signer-validity
check entirely.

Now: one shared `lint_cli.instant()` parses to an aware UTC datetime, every
linter uses it, and unparsable input raises `TimestampError` which callers
convert into violations — reject rather than ignore.

The five acceptance tests are the review's own; the sixth is the concrete
100 ms regression it named.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]


# ---------------------------------------------------------------------------
# The review's five acceptance tests
# ---------------------------------------------------------------------------

def test_exact_second_versus_fractional_orders_correctly():
    """The defect verbatim — string order reported the opposite."""
    later = lc.instant("2026-04-04T10:16:23.1Z")
    earlier = lc.instant("2026-04-04T10:16:23Z")
    assert later > earlier
    assert "2026-04-04T10:16:23.1Z" < "2026-04-04T10:16:23Z", \
        "the string comparison this replaces really was inverted"


def test_trailing_zero_fractions_compare_equal():
    assert lc.instant("2026-04-04T10:16:23.1Z") == \
        lc.instant("2026-04-04T10:16:23.10Z")


def test_equivalent_offset_and_zulu_instants_compare_equal():
    assert lc.instant("2026-07-28T12:00:00+02:00") == \
        lc.instant("2026-07-28T10:00:00Z")


def test_offset_timestamps_participate_in_window_checks():
    """They used to be SKIPPED, not mishandled — a silent hole."""
    assert lc._within_window("2026-07-28T12:00:00+02:00",
                             "2026-07-28T09:00:00Z", "2026-07-28T11:00:00Z")
    assert not lc._within_window("2026-07-28T12:00:00+02:00",
                                 "2026-07-28T11:00:00Z", "2026-07-28T11:30:00Z")


def test_malformed_instants_fail_closed():
    for bad in ("not-a-time", "", None, "2026-04-04T10:16:23"):   # last: no offset
        with pytest.raises(lc.TimestampError):
            lc.instant(bad)
    # and a window with a malformed bound does not silently pass
    assert not lc._within_window("2026-07-28T10:00:00Z", "nonsense", None)


# ---------------------------------------------------------------------------
# The concrete regression the review named
# ---------------------------------------------------------------------------

def _bnd22(evidence):
    issues = bl.check_bundle(SE["recipient_uid"], {}, {}, [], evidence)
    return [m for r, m in issues if r == "LINT-BND-22"]


def test_a_de_delivered_100ms_after_expiry_is_now_caught():
    """The review's reproduction: string order made '…00.100Z' look smaller
    than '…00Z', so a late delivery passed."""
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    de = copy.deepcopy(DE)
    de["delivered_at"] = "2026-04-07T10:15:00.100Z"       # 100 ms LATE
    assert de["delivered_at"] < se["expires_at"], "string order still inverted"
    assert _bnd22([se, de]), "a 100 ms late delivery must now be caught"


def test_the_tie_is_still_delivered():
    """X-21's rule survives the migration: event == expiry is delivered."""
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00Z"
    de = copy.deepcopy(DE)
    de["delivered_at"] = "2026-04-07T10:15:00.000Z"       # the same instant
    assert not _bnd22([se, de])


def test_a_premature_expired_nde_is_caught_across_the_fractional_boundary():
    nde = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]
    se = copy.deepcopy(SE)
    se["expires_at"] = "2026-04-07T10:15:00.500Z"
    bad = copy.deepcopy(nde)
    bad["message_id"] = se["message_id"]
    bad["reason"], bad["event"] = "expired", "C.5-AcceptanceRejectionExpiry"
    bad["observed_at"] = "2026-04-07T10:15:00.400Z"       # BEFORE expiry
    assert _bnd22([se, bad])


# ---------------------------------------------------------------------------
# The migration is complete
# ---------------------------------------------------------------------------

def test_as_of_resolution_uses_parsed_instants():
    """A rotation boundary at a fractional instant resolves to the right
    version — with string order it resolved to the wrong key."""
    versions = [
        {"tag": "old", "valid_from": "2026-01-01T00:00:00Z",
         "valid_until": "2026-04-04T10:16:23.5Z"},
        {"tag": "new", "valid_from": "2026-04-04T10:16:23.5Z"},
    ]
    assert lc.as_of_resolve(versions, at="2026-04-04T10:16:23.4Z")["tag"] == "old"
    assert lc.as_of_resolve(versions, at="2026-04-04T10:16:23.9Z")["tag"] == "new"
    # the exact string-order trap: '…23Z' is EARLIER than '…23.5Z'
    assert lc.as_of_resolve(versions, at="2026-04-04T10:16:23Z")["tag"] == "old"


TIME_FIELDS = ("expires_at", "observed_at", "delivered_at", "valid_from",
               "valid_until", "verified_at", "sent_at", "read_at", "refused_at",
               "not_before", "not_after", "issued_at", "added_at", "removed_at",
               "snapshot_at", "acked_at", "server_time")

LINTERS = ("bundle_lint.py", "lint_cli.py", "discovery_lint.py",
           "evidence_lint.py")


def test_no_linter_compares_two_timestamp_fields_as_strings():
    """A grep guard: the pattern that caused this must not come back."""
    import re
    pat = re.compile(
        r"(get\(\"(?:" + "|".join(TIME_FIELDS) + r")\"[^)]*\)\s*[<>]=?)")
    for name in LINTERS:
        src = (ROOT / "scripts" / name).read_text()
        hits = [ln for ln in src.splitlines()
                if pat.search(ln) and "instant" not in ln]
        assert not hits, f"{name}: string comparison of instants: {hits}"


def test_the_guard_also_catches_instants_compared_through_local_variables():
    """The first guard read only direct `.get("field") < …` comparisons, so
    two sites survived B1 by assigning to locals first:

        sent, exp = se.get("sent_at"), se.get("expires_at")
        if sent and exp and exp <= sent:      # <- string order, LINT-DE-18

    Both are fixed; this catches the shape rather than the spelling. Any
    variable that was ASSIGNED from a timestamp field must not then be
    compared with an ordering operator unless the line parses first.
    """
    import re
    assign = re.compile(
        r"(\w+(?:\s*,\s*\w+)*)\s*=\s*[^=\n]*\.get\(\"(?:"
        + "|".join(TIME_FIELDS) + r")\"")
    for name in LINTERS:
        src = (ROOT / "scripts" / name).read_text()
        tracked = set()
        for line in src.splitlines():
            # R4: reset at each function boundary. The tracked set used to
            # accumulate across the whole file, so a variable named `at`
            # assigned from a timestamp field in one function made every later
            # `at < x` suspicious in another — a false positive that would
            # eventually be silenced, taking the real check with it.
            if line.startswith(("def ", "    def ")):
                tracked = set()
            m = assign.search(line)
            if m:
                tracked.update(v.strip() for v in m.group(1).split(","))
            if not tracked or "instant" in line:
                continue
            for cmp_ in re.finditer(r"\b(\w+)\s*(<=|>=|<|>)\s*(\w+)\b", line):
                a, _, b = cmp_.groups()
                assert not (a in tracked and b in tracked), \
                    f"{name}: instants compared as strings via locals: {line.strip()!r}"


# ---------------------------------------------------------------------------
# Portability (round-3 carry-in from cowork's round-2 verification)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,micros", [
    ("2026-04-04T10:16:23Z", 0),
    ("2026-04-04T10:16:23.1Z", 100_000),
    ("2026-04-04T10:16:23.12Z", 120_000),
    ("2026-04-04T10:16:23.123Z", 123_000),
    ("2026-04-04T10:16:23.1234Z", 123_400),
    ("2026-04-04T10:16:23.12345Z", 123_450),
    ("2026-04-04T10:16:23.123456Z", 123_456),
    ("2026-07-28T12:00:00.5+02:00", 500_000),
])
def test_every_rfc3339_fractional_precision_parses(text, micros):
    """`datetime.fromisoformat` accepts only 3- and 6-digit fractions before
    Python 3.11 and REJECTS 1-, 2-, 4- and 5-digit ones — all valid RFC 3339.
    So on 3.8-3.10 this helper failed closed on CONFORMING input, while README
    promises "Python 3.8+ to use the artefacts" and `lint_cli` is a reference
    tool implementers run.

    This environment is 3.14, so the DEFECT cannot be executed here — what is
    verified is the FIX: the fraction is parsed explicitly, so no Python
    version has an opinion. The acceptance criterion is RFC 3339, not a
    version of Python.
    """
    assert lc.instant(text).microsecond == micros


def test_the_fraction_is_parsed_not_delegated():
    """Structural, because the behavioural test above passes on 3.11+ either
    way: the point is that the fraction never reaches `fromisoformat`."""
    src = (ROOT / "scripts" / "lint_cli.py").read_text()
    body = src[src.index("def instant("):src.index("def instant_or_none(")]
    # Compare the CODE, not the prose: the docstring names `fromisoformat`
    # while explaining why the fraction is kept away from it.
    code = body[body.index('"""', body.index('"""') + 3) + 3:]
    assert "microsecond=micros" in code
    assert code.index("re.match") < code.index("fromisoformat"), \
        "the fraction must be split off BEFORE fromisoformat sees the string"


def test_a_longer_fraction_truncates_rather_than_rounds():
    """Truncation, so an instant never moves FORWARD past a boundary it was
    inside — the direction that matters for expiry."""
    assert lc.instant("2026-04-04T10:16:23.9999999Z").microsecond == 999_999
