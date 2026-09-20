# SPDX-License-Identifier: MIT
"""D10-07 — the README's reading path points at sections that exist.

The review: "README :119-122 should link to actual section anchors." They named
sections in prose and linked only to the file, so a reader landed at the top of
a 1,300-line document. They now carry anchors — and an anchor is a claim that a
heading exists, which goes stale the day the heading is renamed. This checks
every `file.md#anchor` link in the README against the headings actually in
that file, using the slug rule GitHub renders with.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()


def _slug(heading):
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s, flags=re.UNICODE)
    return s.replace(" ", "-")


def _anchors(path):
    out = set()
    for line in (ROOT / path).read_text().split("\n"):
        m = re.match(r"^#{1,6} (.*)$", line)
        if m:
            out.add(_slug(m.group(1)))
    return out


def test_every_readme_anchor_resolves():
    links = re.findall(r"\]\(([^)#\s]+\.md)#([^)\s]+)\)", README)
    assert links, "no anchored links found — this gate would be vacuous"
    missing = [f"{f}#{a}" for f, a in links if a not in _anchors(f)]
    assert not missing, f"README links to headings that do not exist: {missing}"
