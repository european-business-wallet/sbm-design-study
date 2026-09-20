# SPDX-License-Identifier: MIT
"""DR-13 — the umbrella's Current-versions paragraph is BOUND, not just true.

Former defect (design review round 2): umbrella §0 read "Evidence objects
2.0 · BW-ORG 2.0 · BW-MEMBER 2.0 · EDD 1.5.0 · TS v0.18" while the actual
streams stood at 2.6 / 2.4 / 2.1 / 1.10.0 / v0.30 — six releases of drift in
the single most-read normative paragraph of the repository — and
`make versions` was GREEN, because that paragraph carried no binding. R-01's
own acceptance criterion ("no current prose identifies an obsolete version")
was never met; it was tested everywhere except here.

This test is deliberately INDEPENDENT of `scripts/version_manifest.py`: it
re-parses the paragraph with its own regexes and compares against
`versions.json` directly. A test that called the manifest resolver would
share the producer's blind spot — the round-2 lesson (DR-01: the fixtures,
the tests and the producer all shared one faulty serializer and agreed
perfectly while all being wrong).
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
UMB_FILE = "Secure-Business-Messaging-Profile.md"
UMB = (ROOT / UMB_FILE).read_text()
MANIFEST = json.loads((ROOT / "versions.json").read_text())["dimensions"]

PARA = next(l for l in UMB.splitlines() if l.startswith("**Current versions.**"))

# The paragraph's own grammar, re-derived here rather than imported.
def _claims():
    """The paragraph's claims, DERIVED from `versions.json` rather than
    restated beside it.

    This was a hand-written map of ten patterns that already existed, verbatim,
    as the umbrella bindings of the same ten dimensions. So a dimension added
    to `versions.json` and to the paragraph — correctly bound, checked by
    `make versions` — was still an "unbound token" here, because the copy in
    this file had not been extended. That is the drift family the paragraph
    itself exists to close (DR-13), reproduced one level up in its own test.

    Derivation is exact: every dimension's umbrella text binding IS its claim
    pattern. Confirmed against the ten it replaced before the map was removed.
    """
    out = {}
    for name, dim in MANIFEST.items():
        pats = [b["pattern"] for b in dim.get("bindings", [])
                if b.get("kind") == "text" and b.get("file") == UMB_FILE
                and "(" in b.get("pattern", "")]
        if not pats:
            continue
        # A dimension may be bound in the umbrella MORE THAN ONCE — round 10
        # binds the edition both in this paragraph and in the `**Date:**`
        # header — so the paragraph's claim is the binding the paragraph
        # actually matches, not whichever was listed first. If it matches
        # none, the first is kept and the test below fails as it should.
        out[name] = next((q for q in pats if re.search(q, PARA)), pats[0])
    return out


CLAIMS = _claims()


def test_every_version_the_paragraph_states_is_current():
    """The values themselves — independently re-parsed."""
    for dim, pattern in CLAIMS.items():
        m = re.search(pattern, PARA)
        assert m, f"the paragraph no longer states {dim}"
        assert m.group(1) == MANIFEST[dim]["value"], \
            f"{dim}: prose says {m.group(1)}, manifest says {MANIFEST[dim]['value']}"


def test_every_version_the_paragraph_states_is_BOUND():
    """The defect was not the wrong number — it was the UNBOUND number. Each
    claim must have a binding pointing at this file, so drift fails the gate
    instead of ageing quietly."""
    for dim in CLAIMS:
        files = [b.get("file") for b in MANIFEST[dim]["bindings"]]
        assert UMB_FILE in files, \
            f"{dim} is stated in the umbrella §0 paragraph but NOT bound to it"


def test_no_unbound_version_token_hides_in_the_paragraph():
    """Anything version-shaped in the paragraph must be one of the bound
    claims — a new stream added to the prose without a binding would
    reintroduce the defect."""
    bound = {re.search(p, PARA).group(1) for p in CLAIMS.values()
             if re.search(p, PARA)}
    tokens = set(re.findall(r"\*\*(v?\d+\.\d+(?:\.\d+)?)\*\*", PARA))
    unbound = tokens - bound
    assert not unbound, f"unbound version tokens in the paragraph: {unbound}"


def test_the_paragraph_records_why_it_is_bound():
    assert "previously drifted" in PARA and "make versions" in PARA
