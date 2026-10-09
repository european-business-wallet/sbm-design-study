# SPDX-License-Identifier: MIT
"""No document the export ships explains itself with an identifier only this
repository can resolve.

Three kinds of identifier look alike and are not alike:

  * **published** — `LINT-*` rule ids (the generated catalogue defines them),
    `INTF-*` interfaces and `D4` (the umbrella and the Internet-Draft name
    them), and the review-agenda ids `A*`/`G*`/`L*`/`P*` (the agenda is shipped
    and lists them). A reader can look every one of these up.
  * **internal** — the round findings and work-item ids this study runs on:
    `R39-01`, `R2-M6`, `R30-PUB-04`, `X-22`, `DR-11`, `CF-5`, `F-09`, `FED-X4`.
    They resolve against review documents the export deliberately excludes, so
    in the export they are letters and digits.
  * **provenance** — the same internal ids in CODE COMMENTS and DOCSTRINGS.
    Those stay: they are for whoever reads the code, and that is where this
    study's history belongs.

The line this file draws is the third one. A message the caller RECEIVES is not
a comment: an implementer running the reference gets it back from the published
operation, and `(R8-03)` tells them nothing. The generated trace is made of
exactly those messages, which is how 10 of them reached a shipped document.
"""
import ast
import io
import pathlib
import re
import tokenize

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Internal. `(?<!LINT-)` keeps `LINT-BND-W1` and friends out of it.
INTERNAL = re.compile(
    r"(?<!LINT-)(?<!LINT-BND-)\b(?:R\d+(?:-[A-Z0-9]{1,6}){1,3}|FED-X\d+|X-\d+"
    r"|DR-\d+|CF-\d+|F-\d+)\b")

#: Every document the export ships that explains something to a reader. The
#: review documents are NOT here: `rebuild_export.py` excludes them, and they
#: are where the identifiers resolve.
SHIPPED = [
    "README.md", "OPEN-ITEMS.md",
    "docs/REVIEWER_GUIDE.md", "docs/architecture-identity-trust.md",
    "docs/message-lifecycle.md", "docs/evidence-layer-explainer.md",
    "docs/federated-flow-explainer.md", "docs/end-to-end-encryption-explainer.md",
    "docs/decisions-index.md",
    "docs/REVIEW_AGENDA.md", "docs/lifecycle-and-custody.md",
    "docs/implementer-trace.md", "docs/retrievability.md",
    "docs/production-verifier-architecture.md", "docs/scope-resolution-examples.md",
    "docs/agent-profile-explainer.md", "docs/wallet-agent-interface.md",
    "docs/wallet-assurance-profile.md",
    "docs/lint-catalogue.md", "docs/rule-ownership.md",
]

#: The registers the two generated documents above are rendered FROM. Gated at
#: the source, because that is where an identifier would be put back.
REGISTERS = ["docs/lint-catalogue.json", "docs/rule-ownership.json",
             "docs/retrievability.json"]


def _exists(rel):
    p = ROOT / rel
    if not p.exists():
        pytest.skip(f"{rel} is not in this tree")
    return p


@pytest.mark.parametrize("rel", SHIPPED)
def test_a_shipped_explainer_carries_no_internal_identifier(rel):
    text = _exists(rel).read_text(encoding="utf-8")
    found = sorted(set(INTERNAL.findall(text)))
    assert found == [], f"{rel} explains itself with {found}, which the export cannot resolve"


@pytest.mark.parametrize("rel", REGISTERS)
def test_a_generated_register_carries_none_at_its_source(rel):
    """The rendered document is the thing a reader reads, and it is generated —
    so the identifier has to be absent from the register, not scrubbed after."""
    text = _exists(rel).read_text(encoding="utf-8")
    found = sorted(set(INTERNAL.findall(text)))
    assert found == [], f"{rel} carries {found}, which the render would publish"


def test_the_published_identifiers_are_not_caught_by_this_rule():
    """The negative control. A rule that also stripped `LINT-BND-38`, `INTF-1a`
    or `D4` would be deleting the references an implementer needs, and the three
    look enough alike to be worth proving apart."""
    for keep in ("LINT-BND-38", "LINT-BND-I9", "LINT-BND-W1", "LINT-DE-19",
                 "INTF-1", "INTF-1a", "INTF-2", "D4", "A12", "G1", "L4", "RFC 9420"):
        assert not INTERNAL.search(keep), keep
    for drop in ("R39-01", "R2-M6", "R30-PUB-04", "X-22", "DR-11", "CF-5",
                 "F-09", "FED-X4", "R12-X4"):
        assert INTERNAL.search(drop), drop


def _wire_messages(path):
    """Every string literal that is not a docstring, with its line."""
    src = path.read_text(encoding="utf-8")
    skip = set()
    for node in ast.walk(ast.parse(src)):
        body = getattr(node, "body", None)
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and body \
                and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            c = body[0].value
            skip.update(range(c.lineno, (c.end_lineno or c.lineno) + 1))
    out = []
    for t in tokenize.generate_tokens(io.StringIO(src).readline):
        if t.type == tokenize.STRING and t.start[0] not in skip:
            out.append((t.start[0], t.string))
    return out


def test_the_reference_does_not_end_a_wire_message_with_an_internal_identifier():
    """The shape that reached the trace: `"… a conflict (R9-03)"`. A caller sees
    it; a comment two lines up does not.

    Only the TRAILING shape is held, because that is the one the sweep removed
    and the one a copy-paste reintroduces. Mid-sentence uses survive in a handful
    of messages and are recorded in the changelog rather than hidden here.
    """
    # `(?<![A-Z])` before the `F-\d+` arm, or this matches the `F-2` inside
    # `INTF-2` — which it did on the first run, reporting two PUBLISHED
    # identifiers as offenders.
    tail = re.compile(
        r"(?:R\d+(?:-[A-Z0-9]{1,6}){1,3}|FED-X\d+|X-\d+|DR-\d+|CF-\d+"
        r"|(?<![A-Z])F-\d+)\)" r"\s*(?:'''|\"\"\"|\"|')$")
    offenders = []
    for name in ("mock_rdp.py", "trace_flow.py"):
        path = ROOT / "scripts" / name
        for line, lit in _wire_messages(path):
            if tail.search(lit) and not re.search(r"LINT-[A-Z]+-", lit):
                offenders.append(f"{name}:{line} {lit[:80]}")
    assert offenders == [], offenders


def test_the_generated_trace_is_made_of_those_messages():
    """Why the rule above is on the reference and not on the document: the trace
    is generated by driving it, so a message with an identifier in it puts the
    identifier into a shipped document on the next `make trace`. Shown, not
    asserted in prose: a refusal line in the trace is a reference message."""
    trace = (ROOT / "docs" / "implementer-trace.md").read_text(encoding="utf-8")
    refusals = re.findall(r"\*\*Refused:\*\* `([a-z-]+)` — \1: (.+)", trace)
    assert len(refusals) >= 5, refusals
    src = (ROOT / "scripts" / "mock_rdp.py").read_text(encoding="utf-8")
    hits = 0
    for _, detail in refusals:
        # the distinctive tail of the message, as the reference wrote it
        words = [w for w in re.findall(r"[a-z]{5,}", detail)][-4:]
        if words and all(w in src for w in words):
            hits += 1
    assert hits >= 3, f"only {hits} refusal line(s) traced back to the reference"
