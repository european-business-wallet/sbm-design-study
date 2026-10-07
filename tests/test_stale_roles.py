# SPDX-License-Identifier: MIT
"""SBM-ADR-0015 — there is one provider role, and the text must not teach a second.

The decision folds the Delivery Service into the RDP. Prose, schemas, contracts
and figures named the withdrawn role in 113 places. Removing them is a sweep,
and a sweep without a gate comes back, so `doc_lint.scan_stale_roles` is the
gate. These are its rules, shown firing.

Two of them exist because this file's first run contradicted a sweep I had
already recorded as finished:

  * the scrubber that stops a LINK to the historical analysis folder from being
    read as a role name blanked ANY token holding a slash. `RDP/MSP` is not a
    path — and read as one, it left the withdrawn role standing in a TS
    change-indication clause, an I-D deployment note and the umbrella's own
    minimum-viable box, while the scan reported the tree clean.
  * a GENERATED document is exempt, because nobody edits it by hand. Its source
    was not scanned at all, so two rule TITLES naming the withdrawn role
    rendered into `docs/rule-ownership.md` unseen.

What must keep the word keeps it: the decision records, the historical trust
analysis, and the detector patterns that forbid the phrasing — a detector cannot
catch what it may not name.
"""
import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

#: The rule the guard shipped with: blank every token that holds a separator.
#: Kept here as the regression's own shape, so the probe below can show what it
#: used to let through rather than assert that something unspecified improved.
FIRST_SCRUB = re.compile(r"\b[\w.-]*[\w]/[\w./-]*")


def _dl(root):
    spec = importlib.util.spec_from_file_location("doc_lint_roles",
                                                  ROOT / "scripts" / "doc_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT = root
    return mod


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The tree
# ---------------------------------------------------------------------------

def test_no_current_facing_text_names_the_withdrawn_role():
    assert _dl(ROOT).scan_stale_roles() == []


def test_the_gate_fails_the_run(monkeypatch, capsys):
    """A scan nothing acts on is a report, not a gate."""
    dl = _dl(ROOT)
    monkeypatch.setattr(dl, "scan_stale_roles",
                        lambda: [("README.md", 1, "the MSP forwards it")])
    with pytest.raises(SystemExit) as exc:
        dl.main()
    assert exc.value.code == 2
    assert "withdrawn role name" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Two role names with a slash between them are not a path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "Under end-to-end encryption the RDP/MSP never sees plaintext.",
    "a static signed EDD, one co-located MSP/RDP, two wallets",
])
def test_a_slash_between_role_names_is_read_as_roles(tmp_path, line):
    _write(tmp_path, "Secure-Business-Messaging-Profile.md", line + "\n")
    hits = _dl(tmp_path).scan_stale_roles()
    assert [h[0] for h in hits] == ["Secure-Business-Messaging-Profile.md"], hits
    # and the shape of the regression: the first rule read it as a path.
    assert not re.search(r"\bMSPs?\b", FIRST_SCRUB.sub(" ", line)), \
        "this line must be one the shipped scrubber missed, or it proves nothing"


def test_a_path_or_link_to_the_historical_folder_is_not_a_role(tmp_path):
    """The folder keeps its name, and a reading path may point at it."""
    _write(tmp_path, "README.md",
           "the historical [trust analysis](docs/rdp-msp-trust-analysis/README.md),\n"
           "and the folder docs/rdp-msp-trust-analysis/ it lives in,\n"
           "and `docs/rdp-msp-trust-analysis/context.md` in a code span\n")
    assert _dl(tmp_path).scan_stale_roles() == []


def test_the_records_that_must_keep_the_word_keep_it(tmp_path):
    for rel in ("docs/adr/SBM-ADR-0004.md",
                "docs/rdp-msp-trust-analysis/README.md",
                "docs/reviews/round-12.md",
                "docs/decisions-index.md"):
        _write(tmp_path, rel, "The MSP is a participant of its own.\n")
    assert _dl(tmp_path).scan_stale_roles() == []


# ---------------------------------------------------------------------------
# A generated document is exempt, so its SOURCE is where the word must go
# ---------------------------------------------------------------------------

def test_a_generated_documents_source_is_scanned_but_not_its_detectors(tmp_path):
    """The exemption is right — nobody edits a rendered file — and it is exactly
    why the source must be read. The detector in the same record keeps the word:
    it is the pattern that FORBIDS the phrasing."""
    source = {"families": [{
        "id": "keypackage-consumption",
        "title": "KeyPackages are single-use; the MSP removes a consumed one",
        "owner_anchor": "Object model",
        "non_owner_forbidden": r"(MSP|RDPs?)\s+MUST\s+remove",
        "note": "A prose-ownership family.",
    }]}
    _write(tmp_path, "docs/rule-ownership.json", json.dumps(source, indent=2))
    # The rendered document is exempt and must stay so.
    _write(tmp_path, "docs/rule-ownership.md",
           "### KeyPackages are single-use; the MSP removes a consumed one\n")

    hits = _dl(tmp_path).scan_stale_roles()
    assert len(hits) == 1, hits
    rel, line_no, detail = hits[0]
    assert rel == "docs/rule-ownership.json"
    assert detail.startswith("families.0.title:"), detail
    assert line_no > 0, "a reported occurrence must say where to go"
    assert not any("non_owner_forbidden" in h[2] for h in hits), \
        "a detector must be allowed to name what it detects"

    # And the hole's own shape: with the source left out of the scanned set —
    # the state this guard shipped in — the same title is reported by nothing.
    dl = _dl(tmp_path)
    dl.STALE_ROLE_JSON_PROSE = ()
    assert dl.scan_stale_roles() == [], \
        "this probe must be the thing that catches it, or it proves nothing"


def test_a_stale_role_in_any_prose_field_of_that_source_is_caught(tmp_path):
    """Not only the title: `owner_anchor` and `note` render into the document a
    reader reads, so a claim parked in either is still a claim."""
    for field in ("owner_anchor", "note"):
        source = {"families": [{"id": "x", "title": "Clean title",
                                field: "the MSP evaluates the acceptance policy"}]}
        _write(tmp_path, "docs/rule-ownership.json", json.dumps(source, indent=2))
        hits = _dl(tmp_path).scan_stale_roles()
        assert [h[2].split(":")[0] for h in hits] == [f"families.0.{field}"], (field, hits)

# ---------------------------------------------------------------------------
# The role, however it is written
# ---------------------------------------------------------------------------

ACRONYM_ONLY = re.compile(r"\bMSPs?\b")


@pytest.mark.parametrize("line", [
    "a messaging service provider, which need not be qualified, is admitted",
    "a four-corner federation of Messaging Service Providers and RDPs",
    "the Messaging Service Provider as a federation participant on the wire",
])
def test_the_role_spelled_out_is_the_same_role(tmp_path, line):
    """A scan of the ACRONYM is not a scan of the role.

    The guard shipped matching `MSP` alone, and the sweep it green-lit had left
    the role spelled out in plain language in the README's own architecture
    roll-call, in the reviewer guide's status table, in the vision document's
    architecture paragraph, and — spelling it out being what outward-facing
    prose does — in the design study's executive brief.
    """
    _write(tmp_path, "README.md", line + "\n")
    assert [h[0] for h in _dl(tmp_path).scan_stale_roles()] == ["README.md"]
    assert not ACRONYM_ONLY.search(line), \
        "this line must be one the acronym-only pattern missed, or it proves nothing"


def test_a_stale_field_name_in_a_published_example_is_caught(tmp_path):
    """The umbrella's own BW-MED example carried `"msp": "https://msp.example.eu"`
    and `"version": "2.0"` while the schema was at 2.2 and had no such field. No
    gate read it: an embedded JSON example is prose, and the cross-representation
    gate holds schemas to sealed vectors, not paragraphs to schemas."""
    _write(tmp_path, "Secure-Business-Messaging-Profile.md",
           '```json\n{\n  "msp": "https://msp.example.eu",\n}\n```\n')
    hits = _dl(tmp_path).scan_stale_roles()
    assert len(hits) == 1 and '"msp"' in hits[0][2], hits


def test_a_role_name_split_across_a_line_break_is_caught(tmp_path):
    """Prose WRAPS, and the scan read one line at a time.

    A published open-items list said *A6 (the messaging service / provider's own
    admission, decided and not implemented)* with the name split over a newline,
    and the I-D's own introduction called the routing provider *a Messaging
    Service / Provider*. Both sat in the tree while this scan reported it clean,
    because neither line contains the name.
    """
    wrapped = ("A6 (the messaging service\n"
               "provider's own admission, decided and not implemented).\n")
    _write(tmp_path, "OPEN-ITEMS.md", wrapped)
    hits = _dl(tmp_path).scan_stale_roles()
    assert [(h[0], h[1]) for h in hits] == [("OPEN-ITEMS.md", 1)], hits
    # the shape of the regression: no single line holds the name
    assert not any(re.search(r"messaging service provider", l, re.I)
                   for l in wrapped.splitlines()), \
        "this fixture must wrap the name, or it proves nothing"


def test_a_wrapped_name_is_reported_once_at_the_line_it_starts_on(tmp_path):
    """Reading each line with the next one risks reporting the same occurrence
    twice — once where it starts and once from the line before. It is the line
    the name STARTS on."""
    _write(tmp_path, "README.md", "filler line\nthe messaging service\nprovider is withdrawn\n")
    hits = _dl(tmp_path).scan_stale_roles()
    assert [h[1] for h in hits] == [2], hits
