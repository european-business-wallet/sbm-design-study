#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Architecture decision records — index renderer and consistency checker.

`docs/adr/SBM-ADR-NNNN.md` are the records: one per architectural choice, an
identifier assigned once and never renumbered, a YAML front matter that carries
the fields the index is built from, and a body in a fixed order (context, the
requirement and constraint, the decision, the alternatives considered, the
trade-off, the consequences and residual limit, the status of the decision kept
apart from the status of its implementation, what it supersedes, the normative
owner). `docs/decisions-index.md` is GENERATED from those fields and is not a
second authority: it is never hand-edited.

This module:
  * `--render`  regenerates `docs/decisions-index.md`;
  * `--check` (default) verifies that every record is well-formed (identifier,
    filename, statuses, sections in order, agenda identifiers that exist,
    supersession references that resolve) and that the committed index equals
    the freshly rendered one.

Run: `make adr-index`. Enforced by `tests/test_adr_index.py`.
"""
import argparse
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADR_DIR = ROOT / "docs" / "adr"
INDEX = ROOT / "docs" / "decisions-index.md"
AGENDA = ROOT / "docs" / "REVIEW_AGENDA.md"

ID_RE = re.compile(r"^SBM-ADR-(\d{4})$")
DECISION_STATUSES = ("proposed", "accepted", "superseded")
IMPLEMENTATION_TAGS = ("specified", "in-reference", "planned", "not-implemented")
REQUIRED_FIELDS = ("id", "title", "label", "decision_status", "implementation_status",
                   "implementation", "choice", "alternative", "benefit", "cost",
                   "open_questions", "author_questions", "supersedes")
REQUIRED_SECTIONS = ["Context", "Requirement and constraint", "Decision",
                     "Alternatives considered", "Trade-off",
                     "Consequences and residual limit", "Status", "Supersedes",
                     "Normative owner"]
# `Why this choice` is where a record answers the SELECTION question — why this
# mechanism rather than another shape — as distinct from `Alternatives
# considered`, which weighs the options inside a shape already chosen. The
# distinction is the r23 review's: a reader of the architecture asks the first
# question before the second, and `SBM-ADR-0003` had the second and not the
# first. Optional, because most records inherit their mechanism from one that
# already made the choice.
OPTIONAL_SECTIONS = ["Why this choice", "Open questions", "Unanswered"]
AGENDA_ID_RE = re.compile(r"^(?:A\d+|G\d+|P\d+|L\d+)$")


def load():
    """[(path, front_matter_dict, body_text)] in identifier order."""
    out = []
    for p in sorted(ADR_DIR.glob("SBM-ADR-*.md")):
        text = p.read_text(encoding="utf-8")
        parts = text.split("---\n", 2)
        if len(parts) < 3:
            raise ValueError(f"{p.name}: no front matter")
        fm = yaml.safe_load(parts[1]) or {}
        out.append((p, fm, parts[2]))
    return out


def agenda_ids():
    text = AGENDA.read_text(encoding="utf-8")
    return set(re.findall(r"^\| ((?:A|G|P|L)\d+) \|", text, re.M))


#: The words the review agenda uses to mark a question it no longer carries.
#: `scripts/doc_lint.py` gates the agenda's own prose; this gates the records
#: that cite it.
CLOSED_MARKERS = ("RESOLVED", "CLOSED")


def closed_agenda_ids():
    """The agenda rows that record themselves as answered or withdrawn.

    `agenda_ids()` answers "is this a real row", which is what the existing rule
    asks — and a row stays on the agenda after it closes, so A6 and A9 remained
    valid `open_questions` three weeks after SBM-ADR-0015 withdrew one and
    answered the other. Existence is not openness.
    """
    out = set()
    for line in AGENDA.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| ((?:A|G|P|L)\d+) \|", line)
        if m and any(re.search(rf"\b{w}\b", line) for w in CLOSED_MARKERS):
            out.add(m.group(1))
    return out


def check(records=None):
    """[problem, ...] — empty when the records and the index are consistent."""
    records = load() if records is None else records
    problems = []
    ids = [fm.get("id") for _, fm, _ in records]
    numbers = []
    for p, fm, body in records:
        name = p.name
        for f in REQUIRED_FIELDS:
            if f not in fm:
                problems.append(f"{name}: front matter lacks `{f}`")
        ident = fm.get("id", "")
        m = ID_RE.match(str(ident))
        if not m:
            problems.append(f"{name}: id {ident!r} is not SBM-ADR-NNNN")
        else:
            numbers.append(int(m.group(1)))
            if p.stem != ident:
                problems.append(f"{name}: filename does not match id {ident}")
        if fm.get("decision_status") not in DECISION_STATUSES:
            problems.append(f"{name}: decision_status {fm.get('decision_status')!r} not in {DECISION_STATUSES}")
        tags = fm.get("implementation_status")
        if not isinstance(tags, list) or not tags or any(t not in IMPLEMENTATION_TAGS for t in tags):
            problems.append(f"{name}: implementation_status must be a non-empty list drawn from {IMPLEMENTATION_TAGS}")
        for key in ("open_questions", "author_questions", "supersedes"):
            if not isinstance(fm.get(key), list):
                problems.append(f"{name}: `{key}` must be a list")
        known = agenda_ids()
        closed = closed_agenda_ids()
        for q in fm.get("open_questions") or []:
            if not AGENDA_ID_RE.match(str(q)) or q not in known:
                problems.append(f"{name}: open question {q!r} is not on the review agenda")
            elif q in closed:
                problems.append(
                    f"{name}: `open_questions` names {q}, which the review agenda "
                    "records as closed — the index renders this as a question the "
                    "record still carries, and a reader has no way to tell it from "
                    "one that is open. Move it to `analysed_not_decided` if the "
                    "history matters")
        tags = fm.get("implementation_status") or []
        if fm.get("decision_status") == "superseded" and "planned" in tags:
            problems.append(
                f"{name}: a superseded record carries the `planned` tag — the index "
                "lists it under *Decided is not implemented*, which says a plan "
                "stands. Say what the Status section says instead")
        impl = str(fm.get("implementation") or "")
        for q in sorted(closed):
            # The defect shape is a plan and a closed question in ONE clause —
            # "…: planned, not implemented ([A6])". A record may legitimately say
            # that a question is closed and, in another sentence, that something
            # else is still planned, so a sentence break ends the match.
            near = rf"(\bplanned\b[^.;]{{0,120}}\b{q}\b|\b{q}\b[^.;]{{0,120}}\bplanned\b)"
            if re.search(near, impl, re.I):
                problems.append(
                    f"{name}: `implementation` describes work as planned in the same "
                    f"clause as {q}, which the agenda records as closed — a plan "
                    "whose question was withdrawn is not a plan")
        for s in fm.get("supersedes") or []:
            if ID_RE.match(str(s)) and s not in ids:
                problems.append(f"{name}: supersedes {s}, which does not exist")
        heads = re.findall(r"^## (.+?)\s*$", body, re.M)
        core = [h for h in heads if h in REQUIRED_SECTIONS]
        if core != REQUIRED_SECTIONS:
            problems.append(f"{name}: sections are {core}, expected {REQUIRED_SECTIONS} in that order")
        extra = [h for h in heads if h not in REQUIRED_SECTIONS and h not in OPTIONAL_SECTIONS]
        if extra:
            problems.append(f"{name}: unexpected sections {extra}")
        if (fm.get("open_questions") and "Open questions" not in heads):
            problems.append(f"{name}: names open questions but has no `Open questions` section")
        if (fm.get("author_questions") and "Unanswered" not in heads):
            problems.append(f"{name}: names author questions but has no `Unanswered` section")
        prose = re.sub(r"^(?:\s*<!--.*?-->)+", "", body, flags=re.S)   # the SPDX comment sits after the front matter
        if not prose.lstrip().startswith(f"# {ident} — "):
            problems.append(f"{name}: title line must be `# {ident} — <title>`")
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        problems.append(f"identifiers are not 0001..{len(numbers):04d} without gaps: {numbers}")
    if len(set(ids)) != len(ids):
        problems.append(f"duplicate identifiers: {ids}")
    if not problems:
        rendered = render_md(records)
        if not INDEX.exists() or INDEX.read_text(encoding="utf-8") != rendered:
            problems.append(f"{INDEX.relative_to(ROOT)} is stale: run `python3 scripts/adr_index.py --render`")
    return problems


def _rel(text):
    """Rewrite link targets written relative to docs/adr/ so they resolve from docs/."""
    text = text.replace("](../../", "\x00")
    text = text.replace("](../", "](")
    return text.replace("\x00", "](../")


def _cell(text):
    return " ".join(str(text).split())


def _link(fm):
    return f"[{fm['id']}](adr/{fm['id']}.md)"


def _open_cell(fm):
    qs = fm.get("open_questions") or []
    if not qs:
        return "—"
    return ", ".join(f"[{q}](REVIEW_AGENDA.md)" for q in qs)


def render_md(records=None):
    records = load() if records is None else records
    L = []
    L.append("<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->")
    L.append("<!-- SPDX-License" + "-Identifier: CC-BY-4.0 -->")   # split so reuse does not read this script as CC-BY
    L.append("<!-- GENERATED from docs/adr/SBM-ADR-*.md by scripts/adr_index.py --render. Do not edit: edit the record. -->")
    L.append("")
    L.append("# Decisions index — today's choices, what they cost, what is undecided")
    L.append("")
    L.append("**Status:** informative companion, generated from the [architecture decision records](adr/) · "
             "**Applies to:** the specification set at the versions in the README's version table "
             "(not restated here, so they cannot drift) · **Audience:** reviewers who want the design's "
             "reasons before its rules")
    L.append("")
    L.append("> **Exploratory design study — not an official proposal.** This index points at the decisions; "
             "it restates no rule. In any conflict, the normative documents prevail, and each record names the "
             "one that governs.")
    L.append("")
    L.append("---")
    L.append("")
    L.append("## How to read this")
    L.append("")
    L.append("One row per architecture decision record, one record per choice that shapes the design. "
             "A record's identifier is assigned once and never renumbered, so a decision can be cited durably. "
             "Each row gives the **choice**, its **status**, and the **principal trade-off** — what the choice "
             "buys and who pays for it. The alternative that was actually considered, why it was rejected, the "
             "normative owner and the full cost are in the record itself, one click away: nine columns of them "
             "in a table made the index a document to study rather than a map to choose from, which is the "
             "opposite of what an index is for.")
    L.append("")
    L.append("Two statuses are kept apart:")
    L.append("")
    L.append("- **Decision:** *proposed*, *accepted* or *superseded* — whether the choice stands;")
    L.append("- **Implementation:** *specified* (the normative text says it), *in the reference* (the reference "
             "implementation and its gates execute it), *planned* (decided, not implemented), *not established* "
             "(outside what the repository can show).")
    L.append("")
    L.append("The **open** column names the review-agenda question a choice rests on; the record names it and "
             "stops. Where a reason was never written down, the record says so as an **unanswered** question "
             "rather than supplying one. The umbrella's six trade-offs "
             "([§0.1](../Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative)) are the short "
             "version of several rows below. The byte-level and group-design reasons are records 3, 8, 9 and 12.")
    L.append("")
    L.append("## The choices")
    L.append("")
    L.append("| ADR | Choice | Principal trade-off | Decision | Implementation | Open |")
    L.append("|---|---|---|---|---|---|")
    for _, fm, _ in records:
        L.append("| " + " | ".join([
            _link(fm),
            f"**{_cell(fm['label'])}**",
            f"{_rel(_cell(fm['benefit']))} — at the cost of {_rel(_cell(fm['cost']))}",
            _cell(fm["decision_status"]),
            _rel(_cell(fm["implementation"])),
            _open_cell(fm),
        ]) + " |")
    L.append("")
    # Decided, not implemented
    planned = [fm for _, fm, _ in records if "planned" in (fm.get("implementation_status") or [])]
    L.append("## Decided is not implemented")
    L.append("")
    if planned:
        L.append("A decision stands from the day it is recorded, whether or not code has shipped it. "
                 "The records whose implementation is **planned**:")
        L.append("")
        for fm in planned:
            L.append(f"- {_link(fm)} **{_cell(fm['label'])}** — {_rel(_cell(fm['implementation']))}.")
    else:
        L.append("Every accepted decision is implemented as far as the repository can show.")
    L.append("")
    # Analysed, not decided
    analysed = [fm for _, fm, _ in records if fm.get("analysed_not_decided")]
    L.append("## Analysed is not decided")
    L.append("")
    if analysed:
        for fm in analysed:
            # A SUPERSEDED record's analysis is history, and this section renders
            # it as today's undecided choice unless it says otherwise. ADR-0004's
            # "No model is selected" appeared here for three weeks after
            # SBM-ADR-0015 selected one, under a heading that says nothing is
            # decided — the generator was promoting a withdrawn record's text
            # into the current summary with no qualification at all.
            historical = fm.get("decision_status") == "superseded"
            mark = (" — **from a superseded record**, kept as the analysis a later "
                    "decision rests on, not as an open choice" if historical else "")
            L.append(_rel(_cell(fm["analysed_not_decided"])) + mark + f" ({_link(fm)})")
            L.append("")
    else:
        L.append("No record carries an analysed-but-undecided question.")
        L.append("")
    # Open
    L.append("## Open")
    L.append("")
    by_q = {}
    for _, fm, _ in records:
        for q in fm.get("open_questions") or []:
            by_q.setdefault(q, []).append(fm["id"])
    if by_q:
        L.append("The review-agenda questions a record rests on, and the records that name them:")
        L.append("")
        for q in sorted(by_q, key=lambda s: (s[0], int(s[1:]))):
            L.append(f"- [{q}](REVIEW_AGENDA.md) — " + ", ".join(f"[{i}](adr/{i}.md)" for i in by_q[q]))
        L.append("")
    L.append("Every other open question — the implementer guide (G1–G4), the legal questions (L1–L8) and the "
             "agenda entries no record names — is on the [review agenda](REVIEW_AGENDA.md), each with the "
             "assumption it rests on and whose expertise would settle it.")
    L.append("")
    # Author questions
    L.append("## Author questions")
    L.append("")
    aq = [(fm, q) for _, fm, _ in records for q in (fm.get("author_questions") or [])]
    if aq:
        for fm, q in aq:
            L.append(f"- **{_cell(q).split('?')[0]}?** {_cell(q).split('?', 1)[1].strip()} ({_link(fm)})")
    else:
        L.append("None recorded.")
    L.append("")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--render", action="store_true",
                    help="regenerate docs/decisions-index.md from the records")
    ap.add_argument("--check", action="store_true", help="(default) verify records and index")
    args = ap.parse_args(argv)
    if args.render:
        records = load()
        problems = [p for p in check(records) if "is stale" not in p]
        if problems:
            print("[FAIL] records are not well-formed; not rendering:")
            for p in problems:
                print(f"  - {p}")
            return 1
        INDEX.write_text(render_md(records), encoding="utf-8")
        print(f"rendered {INDEX.relative_to(ROOT)} from {len(records)} records")
        return 0
    problems = check()
    if problems:
        print("[FAIL] architecture decision records:")
        for p in problems:
            print(f"  - {p}")
        return 1
    records = load()
    print(f"[OK] {len(records)} architecture decision records well-formed; docs/decisions-index.md current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
