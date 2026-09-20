# SPDX-License-Identifier: MIT
"""X-34 — one normative owner per rule; correct interface counts.

`docs/rule-ownership.json` assigns each rule family a single owning document and
records the informative summaries elsewhere. These gates enforce it and catch the
two concrete defects the review found: a rule reworded and restated normatively
in more than one document, and the I-D claiming "Two HTTP surfaces" while it lists
four.

The negative fixtures reproduce both former defects: a bare normative restatement
injected into a non-owner document is flagged, and a prose interface count that
disagrees with the bullets is flagged.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import rule_ownership as ro  # noqa: E402


def test_inventory_is_consistent():
    problems = ro.check(ro.load())
    assert not problems, "rule-ownership inventory violations:\n" + "\n".join(problems)


def test_markdown_is_not_stale():
    data = ro.load()
    assert ro.MD.read_text(encoding="utf-8") == ro.render_md(data), (
        "docs/rule-ownership.md is stale — run `make rule-ownership`"
    )


def test_interface_count_matches_reality():
    word, n_word, bullets = ro.interface_count(ro.load())
    assert bullets == 4, f"expected 4 interface bullets, found {bullets}"
    assert n_word == 4 and word == "Four", f"prose count is {word!r}, not Four"


def test_every_family_owner_is_a_known_doc():
    data = ro.load()
    keys = set(data["doc_keys"])
    for fam in data["families"]:
        assert fam["owner"] in keys, f"{fam['id']} owner {fam['owner']!r} unknown"
        for r in fam.get("informative_refs", []):
            assert r["doc"] in keys, f"{fam['id']} ref doc {r['doc']!r} unknown"


# --- negative fixtures: the two former defects ---

def test_negative_wrong_interface_count_is_flagged():
    """The reproduced defect: prose says 'Two' while four interfaces are listed."""
    data = ro.load()
    id_text = (ROOT / data["doc_keys"]["id"]).read_text(encoding="utf-8")
    doctored = id_text.replace("Four\nHTTP surfaces are deliberately NOT defined",
                               "Two\nHTTP surfaces are deliberately NOT defined")
    word, n_word, bullets = ro.interface_count(data, id_text=doctored)
    assert (word, n_word, bullets) == ("Two", 2, 4), (word, n_word, bullets)
    assert n_word != bullets, "a 'Two' claim over four bullets must be a mismatch"


def test_negative_bare_restatement_is_flagged(monkeypatch):
    """A non-owner document restating an owned rule normatively must be caught."""
    data = ro.load()
    real_text = ro._text
    injected = ("Intro.\n- The MSP MUST NOT access plaintext payloads, ever.\nOutro.\n")

    def fake_text(d, key):
        if key == "umbrella":
            return injected
        return real_text(d, key)

    monkeypatch.setattr(ro, "_text", fake_text)
    problems = ro.check(data)
    assert any("intermediary-plaintext-prohibition" in p and "umbrella" in p
               for p in problems), (
        "a bare 'MSP MUST NOT access plaintext' in a non-owner doc must be flagged;"
        f" got: {problems}"
    )
