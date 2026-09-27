# SPDX-License-Identifier: MIT
"""A test that seals an artefact checks it whole.

An external review of r26 found that the reference runtime sealed an NDE the
authoritative CDDL refused. The test written to prevent exactly that carried, in
a comment above its final assertion:

    # And the RETAINED-evidence linter accepts what the issuing path sealed —
    # the two paths share `lint_nde_semantics`, and a rule that passed at
    # issuance and failed at verification would be the worse defect.

and the assertion under it called `validate_body` — the JSON projection, and
nothing else. **A docstring is not a check.** The object was valid in the one
representation the test looked at and invalid in another, and the suite reported
coverage it did not have.

**Why no sample gate caught it.** `make cddl-check` validates the 35 shipped
samples against the CDDL. An artefact a test SEALS AT RUNTIME is not a shipped
sample: no gate sees it, so the test is the only thing standing behind it — and
the test has to stand behind the whole object, not one projection of it.

So the rule here is narrow on purpose: a test that seals an artefact at runtime
and asserts it valid must assert it against the JSON Schema, the CDDL and the
linter. Not "does the prose match the code" — that was tried first, and it finds
either noise or nothing:

- reading docstrings and comments for a named capability the body never calls
  reports fourteen tests, of which perhaps two are real: this repository's style
  is to narrate the defect a test was born from, and a narration mentions the
  CDDL without claiming to check it;
- tightening it to claims sitting next to their assertion reports three, all
  false — verification is usually one call deep, inside the helper the test
  calls.

And the harder class is not detectable at all. Two probes in the same review
were found to be **pinning a claim that was wrong** — one required the TS to
name the two transformations as permitted, the sentence contradicting the
Internet-Draft; one required an agenda row to rest on ground that did not exist.
A suite cannot tell that an assertion is about a false claim. That is what
review is for, and this file does not pretend otherwise.
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]

SEALS = re.compile(r"evidence_artifact\(|_deliver\(|deliver_confirmation\(")
ASSERTS_VALID = re.compile(r"validate_body\([^)]*\)\s*==\s*\[\]|"
                           r"\.lint\([^)]*\)\s*==\s*\[\]|"
                           r"assert not \w*\.?lint\(")
REPRESENTATIONS = {
    "the JSON Schema": re.compile(r"validate_body|jsonschema"),
    "the CDDL":        re.compile(r"cddl_check|_check_body"),
    "the linter":      re.compile(r"\.lint\(|evidence_lint"),
}


def _runtime_sealed_claims():
    """[(file, line, test, missing)] — a runtime-sealed artefact asserted valid
    against fewer than all three representations."""
    out = []
    for path in sorted(ROOT.glob("tests/test_*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue
        src = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(src)
        except SyntaxError:                                    # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name.startswith("test_")):
                continue
            code = re.sub(r"^\s*#.*$", "", ast.get_source_segment(src, node) or "", flags=re.M)
            if not (SEALS.search(code) and ASSERTS_VALID.search(code)):
                continue
            missing = [name for name, pat in REPRESENTATIONS.items() if not pat.search(code)]
            if missing:
                out.append((path.name, node.lineno, node.name, missing))
    return out


def test_a_runtime_sealed_artefact_is_asserted_valid_in_every_representation():
    """The defect, generalised. An artefact this suite seals is covered by no
    sample gate, so a test asserting it valid in one representation is claiming
    more than it establishes — an implementation following another would refuse
    what the reference issued, which is what happened."""
    problems = _runtime_sealed_claims()
    assert problems == [], "\n".join(
        f"{f}:{ln} {name} seals an artefact and asserts it valid without checking "
        f"{', '.join(missing)}" for f, ln, name, missing in problems)


def test_the_instrument_detects_the_shape_it_was_built_for(tmp_path):
    """Proved to detect before it is trusted — the rule this repository applies
    to every gate. The fixture is the pass-A defect in miniature: seal, then
    assert against one representation."""
    probe = tmp_path / "tests"
    probe.mkdir()
    (probe / "test_fixture.py").write_text(
        "def test_it():\n"
        "    art = mock.evidence_artifact(body)\n"
        "    assert lc.validate_body(art['projection']) == []\n", encoding="utf-8")
    import types
    mod = types.SimpleNamespace(ROOT=tmp_path)
    # Run the same walk against the fixture tree.
    found = []
    for path in sorted(probe.glob("test_*.py")):
        src = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                code = ast.get_source_segment(src, node) or ""
                if SEALS.search(code) and ASSERTS_VALID.search(code):
                    found.append([n for n, p in REPRESENTATIONS.items() if not p.search(code)])
    assert found == [["the CDDL", "the linter"]], found
    del mod


def test_the_rule_is_narrow_and_says_why():
    """A gate that fired on prose would be switched off within a week, and then
    it would catch nothing at all. This file records the two broader forms that
    were tried and what each produced, so the next person does not re-derive
    them."""
    doc = __doc__
    assert "A docstring is not a check" in doc
    flat = " ".join(doc.split())
    assert "reports fourteen tests" in flat
    assert "reports three, all false" in flat
    assert "not detectable at all" in doc, \
        "the class this cannot see must be named, or the file overclaims in its turn"
