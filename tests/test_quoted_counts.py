# SPDX-License-Identifier: MIT
"""A generated number quoted in prose must still be the generated number.

`docs/project-counts.json` exists because three numbers — the review rounds, the
catalogue's rules, the conformance gates — were corrected by hand after every
round and were two rounds stale when round 6 arrived, inside the documents
describing a process built to eliminate exactly that. The generated file fixed
the documents that quote it *by reference*. It did nothing for the ones that
quote it *in words*, and the design study's export has three:

    brief/executive-brief.md   "a published catalogue of 158 rules"
    brief/executive-brief.md   "more than two thousand automated checks across twelve gates"
    README.md                  "`make conformance` runs twelve gates"

Those files are the export's OWN — `rebuild_export.py` copies them forward from
the previous edition rather than taking them from the source — so the numbers in
them survived every rebuild untouched, correct only because nobody had changed a
rule or a gate. That is the round count's failure mode with a different noun.

A count written in words is not wrong to write: "twelve gates" reads better than
a cross-reference, and a bound like "more than two thousand" is the honest shape
for a number that moves every commit. What was missing is the check. Exact
claims are compared to the generated value, and a bound is checked as a bound.

In the source there is no `brief/` and the README quotes no count, so the sweep
finds nothing and the rules are driven on fixtures instead.
"""
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COUNTS = ROOT / "docs" / "project-counts.json"

WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
         8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
         14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
         19: "nineteen", 20: "twenty"}


def _spellings(n):
    """How a document may legitimately write the number n."""
    out = {str(n)}
    if n in WORDS:
        out.add(WORDS[n])
    return out


def quoted_count_problems(root, counts):
    """[(where, problem)] — every prose count that no longer matches its source.

    Exact claims ("N rules", "N gates") must equal the generated value. A bound
    ("more than two thousand automated checks") must still hold; it is not
    required to be tight, because a test total moves with every commit and a
    document that chased it would be wrong more often than not.
    """
    problems = []
    files = [root / "README.md", *sorted((root / "brief").glob("*.md"))]
    # A NUMBER followed by the noun — never "the rules", "validation rules" or
    # "the same gates", which are prose about the things and claim no count.
    number = r"(\d+|" + "|".join(sorted(WORDS.values(), key=len, reverse=True)) + r")"
    exact = ((number + r"\s+rules\b", "lint_rules"),
             (number + r"\s+gates\b", "conformance_gates"))
    for path in files:
        if not path.exists():
            continue
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), 1):
            for pattern, key in exact:
                for m in re.finditer(pattern, line, re.IGNORECASE):
                    written = m.group(1).lower()
                    if written not in _spellings(counts[key]):
                        problems.append((f"{rel}:{n}", f"says {m.group(0)!r} where "
                                                       f"{key} is {counts[key]}"))
            if "more than two thousand automated checks" in line and counts["automated_checks"] <= 2000:
                problems.append((f"{rel}:{n}", f"claims more than two thousand automated "
                                               f"checks; there are {counts['automated_checks']}"))
    return problems


NUMBERED = (re.compile(r"^\*\*(\d+)\.", re.M),      # the source's long form
            re.compile(r"^(\d+)\. \*\*", re.M))       # the export's condensed form


def invariant_count_problems(root):
    """[(where, problem)] — a section that says how many rules it lists must
    list that many.

    `CONTRIBUTING.md` is the last document either repository still maintains by
    hand, and the export rewrites it in its own voice rather than carrying the
    source's. Its invariants section opened with "The eleven rules below" while
    listing twelve and closing with "all twelve" — self-contradictory for five
    editions, in the first sentence a contributor reads, because the edition
    that added a rule updated one sentence and not the other.

    This count has no entry in `project-counts.json` and needs none: the list is
    its own source of truth, so the check counts what is there and compares.
    Where a section states no number — the source's does not — there is nothing
    to check and nothing to keep in step.
    """
    path = root / "CONTRIBUTING.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    heading = re.search(r"^## Review invariants.*$", text, re.M)
    if not heading:
        return []
    end = text.find("\n## ", heading.end())
    section = text[heading.start():end if end > 0 else len(text)]
    listed = max((len({m for m in rx.findall(section)}) for rx in NUMBERED), default=0)
    if not listed:
        return []
    problems = []
    # Only a statement ABOUT THE LIST counts. "four rules kept deciding
    # attribution from today's roster", inside a rule's own narrative, is a
    # sentence about lint rules and not a claim about how many rules there are.
    n = r"(\d+|" + "|".join(WORDS.values()) + r")"
    stated = re.finditer(rf"\b{n}\s+(?:rules|invariants)\s+(?:below|here|above)\b"
                         rf"|run through all\s+{n}\b", section, re.IGNORECASE)
    for m in stated:
        written = (m.group(1) or m.group(2)).lower()
        if written not in _spellings(listed):
            line = section[:m.start()].count("\n") + text[:heading.start()].count("\n") + 1
            problems.append((f"CONTRIBUTING.md:{line}",
                             f"says {m.group(0)!r} where the section lists {listed}"))
    return problems


def test_the_invariants_section_counts_itself_correctly():
    assert invariant_count_problems(ROOT) == []


def test_a_section_that_states_the_wrong_number_is_caught(tmp_path):
    """The export's before-state, reproduced: a rule added, one sentence
    updated, the other left."""
    (tmp_path / "CONTRIBUTING.md").write_text(
        "## Review invariants (earned, not theoretical)\n\n"
        "The eleven rules below are what those reviews earned.\n\n"
        "1. **First.** Body.\n2. **Second.** Body.\n\n"
        "Two rules run through all twelve: a fixture with one of everything.\n\n"
        "## Provenance\n", encoding="utf-8")
    problems = invariant_count_problems(tmp_path)
    assert len(problems) == 2, problems
    assert all("section lists 2" in p for _, p in problems), problems


def test_a_section_that_states_no_number_needs_no_check(tmp_path):
    """The source's section states none, and must not be made to."""
    (tmp_path / "CONTRIBUTING.md").write_text(
        "## Review invariants (earned, not theoretical)\n\n"
        "These rules live here, and not only in a batch plan that gets archived.\n\n"
        "**1. A TEST THAT CALLS THE SAME HELPER.** Body.\n\n"
        "**2. A HELPER ONLY ITS OWN TEST CALLS.** Body.\n\n## Provenance\n",
        encoding="utf-8")
    assert invariant_count_problems(tmp_path) == []


def test_both_numbering_styles_are_counted(tmp_path):
    """The source writes `**1. TITLE**`, the export writes `1. **title**`."""
    for style in ("**{n}. RULE.** Body.\n\n", "{n}. **Rule.** Body.\n"):
        body = "".join(style.format(n=n) for n in (1, 2, 3))
        (tmp_path / "CONTRIBUTING.md").write_text(
            "## Review invariants\n\nThe three rules below.\n\n" + body + "\n## Provenance\n",
            encoding="utf-8")
        assert invariant_count_problems(tmp_path) == [], style


def test_the_repository_quotes_its_own_counts_correctly():
    assert quoted_count_problems(ROOT, json.loads(COUNTS.read_text())) == []


@pytest.fixture
def mini(tmp_path):
    (tmp_path / "brief").mkdir()
    (tmp_path / "README.md").write_text("`make conformance` runs twelve gates: the version\n",
                                        encoding="utf-8")
    (tmp_path / "brief" / "executive-brief.md").write_text(
        "a published catalogue of 158 rules enforced by semantic linters, and\n"
        "more than two thousand automated checks across twelve gates, all in CI\n",
        encoding="utf-8")
    return tmp_path, {"lint_rules": 158, "conformance_gates": 12, "automated_checks": 2094}


def test_a_matching_set_passes(mini):
    root, counts = mini
    assert quoted_count_problems(root, counts) == []


def test_a_rule_count_that_moved_is_caught(mini):
    root, counts = mini
    problems = quoted_count_problems(root, dict(counts, lint_rules=159))
    assert [w for w, _ in problems] == ["brief/executive-brief.md:1"], problems
    assert "lint_rules is 159" in problems[0][1]


def test_a_gate_count_that_moved_is_caught_in_both_files(mini):
    """The gate count is written in words, in two files, by two authors of the
    same sentence. A thirteenth gate has to reach both."""
    root, counts = mini
    problems = quoted_count_problems(root, dict(counts, conformance_gates=13))
    assert {w for w, _ in problems} == {"README.md:1", "brief/executive-brief.md:2"}, problems


def test_the_bound_is_checked_as_a_bound(mini):
    """"More than two thousand" is not required to be tight — only true."""
    root, counts = mini
    assert quoted_count_problems(root, dict(counts, automated_checks=2500)) == []
    problems = quoted_count_problems(root, dict(counts, automated_checks=1999))
    assert any("more than two thousand" in p for _, p in problems), problems


def test_prose_about_the_things_is_not_read_as_a_count(mini):
    """"the validation rules" and "the same gates" name the things; they claim
    no number, and the sweep must not read one into them. Both are real
    sentences from the source README, and both made this check fail until the
    pattern required a NUMBER rather than any word."""
    root, counts = mini
    (root / "README.md").write_text("And the validation rules, the same gates, all rules and "
                                    "no gates. It runs twelve gates.\n", encoding="utf-8")
    assert quoted_count_problems(root, counts) == []
