#!/usr/bin/env python3
"""Build executive-brief.docx from executive-brief.md.

WHY THIS EXISTS. The .docx is the file that actually gets emailed, and it was
the one artefact no gate read: it drifted two editions behind the Markdown
while `check_counts.py` — which verifies the prose against the specification's
generated counts — checked only the .md and the README. A reviewer opening the
.docx found "the loop has run twice" and "138 rules" against a source saying
six and 150. Derived artefacts that are produced by hand drift; that is the
defect family this repository spends its gates on, and it had one of its own.

So: this script is the ONLY supported way to produce the .docx, and
`check_counts.py` now reads the .docx too, so a stale one fails the check
rather than being emailed.

Three typographic fixes pandoc does not apply, each reported by a reader of the
printed document:

  * every table row gets `w:cantSplit`, so a row never breaks across a page
    boundary mid-cell (a page used to start inside a sentence);
  * the first row of every table gets `w:tblHeader`, so headers repeat when a
    table continues on the next page;
  * every list item gets `w:keepLines`, so a bullet is not split across a page
    (page 11 once opened on "recur. This is what…").

Requires: pandoc, cairosvg (the diagrams are SVG; Word needs raster).

    python3 brief/build_brief.py
"""

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
MD = HERE / "executive-brief.md"
DOCX = HERE / "executive-brief.docx"
DIAGRAMS = ("architecture-four-corner", "protocol-stack")
PNG_WIDTH = 2000          # print-legible; the SVG labels are small at 1600


def _rasterise(dest: pathlib.Path) -> None:
    import cairosvg
    (dest / "assets").mkdir(parents=True, exist_ok=True)
    for name in DIAGRAMS:
        cairosvg.svg2png(url=str(HERE / "assets" / f"{name}.svg"),
                         write_to=str(dest / "assets" / f"{name}.png"),
                         output_width=PNG_WIDTH)


def _source_for_word(dest: pathlib.Path) -> pathlib.Path:
    """The Markdown, with the two substitutions Word needs."""
    text = MD.read_text(encoding="utf-8")
    for name in DIAGRAMS:
        text = text.replace(f"assets/{name}.svg", f"assets/{name}.png")
    text = text.replace(" ↔ ", " to ")   # the glyph is missing from some fonts
    out = dest / "brief.md"
    out.write_text(text, encoding="utf-8")
    return out


def _tables_with_headers() -> list[bool]:
    """For each Markdown table, in order: does it have a NON-EMPTY header row?

    Pandoc DROPS an empty header (`| | |`), so the first row of the resulting
    Word table is real content. Marking that row `tblHeader` makes it repeat at
    every page break — which is exactly what happened: a reader found
    "Registered-delivery evidence without content access" and "Ecosystem
    prerequisites" printed as if they were column headings. The source tables
    now all carry real headers, and this reads the Markdown so the script stays
    right if one ever does not.
    """
    flags, lines = [], MD.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines[:-1]):
        nxt = lines[i + 1].strip()
        if (line.lstrip().startswith("|") and set(nxt) <= set("|-: ") and "-" in nxt):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            flags.append(any(cells))
    return flags


def _keep_paragraphs_whole(xml: str) -> tuple[str, int]:
    """Stop a list item from breaking across a page.

    A reader found page 11 opening on "recur. This is what…" — the tail of a
    bullet whose first lines were on the previous page. Word's default widow
    control only rescues a single stranded line; a bullet losing two or three
    reads as a fragment with no subject. `w:keepLines` holds each list item
    together. It is applied ONLY to list paragraphs: on long body paragraphs it
    would push half-empty pages, which is the defect one page further on.
    """
    count = 0
    out, cursor = [], 0
    for para in re.finditer(r"<w:p\b.*?</w:p>", xml, re.S):
        body = para.group(0)
        if "<w:numPr>" not in body or "<w:keepLines/>" in body:
            continue
        if "<w:pPr>" in body:
            fixed = body.replace("<w:pPr>", "<w:pPr><w:keepLines/>", 1)
        else:
            fixed = re.sub(r"(<w:p\b[^>]*>)", r"\1<w:pPr><w:keepLines/></w:pPr>",
                           body, count=1)
        count += 1
        out.append(xml[cursor:para.start()])
        out.append(fixed)
        cursor = para.end()
    out.append(xml[cursor:])
    return "".join(out), count


def _fix_tables(docx: pathlib.Path) -> tuple[int, int]:
    """Apply cantSplit to every row; tblHeader only where a header really exists."""
    with tempfile.TemporaryDirectory() as tmp:
        unpacked = pathlib.Path(tmp) / "unpacked"
        unpacked.mkdir()
        with zipfile.ZipFile(docx) as z:
            z.extractall(unpacked)
        doc = unpacked / "word" / "document.xml"
        xml = doc.read_text(encoding="utf-8")
        xml, kept = _keep_paragraphs_whole(xml)

        has_header = _tables_with_headers()
        rows = headers = 0
        pieces, cursor = [], 0
        for t_index, table in enumerate(re.finditer(r"<w:tbl>.*?</w:tbl>", xml, re.S)):
            # Default to False: if the Markdown scan and the Word tables ever
            # fall out of step, the failure is a header that does not repeat —
            # a cosmetic loss — rather than a content row printed as a heading.
            repeat = has_header[t_index] if t_index < len(has_header) else False
            body, inner, icursor = table.group(0), [], 0
            for i, row in enumerate(re.finditer(r"<w:tr[ >].*?</w:tr>", body, re.S)):
                raw = row.group(0)
                props = "<w:cantSplit/>" + ("<w:tblHeader/>" if i == 0 and repeat else "")
                if "<w:trPr>" in raw:
                    fixed = raw.replace("<w:trPr>", "<w:trPr>" + props, 1)
                else:
                    fixed = re.sub(r"(<w:tr[^>]*>)", r"\1<w:trPr>" + props + "</w:trPr>",
                                   raw, count=1)
                rows += 1
                headers += (i == 0 and repeat)
                inner.append(body[icursor:row.start()])
                inner.append(fixed)
                icursor = row.end()
            inner.append(body[icursor:])
            pieces.append(xml[cursor:table.start()])
            pieces.append("".join(inner))
            cursor = table.end()
        pieces.append(xml[cursor:])
        doc.write_text("".join(pieces), encoding="utf-8")
        _fix_tables.kept = kept

        rebuilt = pathlib.Path(tmp) / "out.docx"
        with zipfile.ZipFile(rebuilt, "w", zipfile.ZIP_DEFLATED) as z:
            for path in sorted(unpacked.rglob("*")):
                if path.is_file():
                    z.write(path, path.relative_to(unpacked))
        shutil.copyfile(rebuilt, docx)
    return rows, headers


def main() -> int:
    if not shutil.which("pandoc"):
        print("[FAIL] pandoc is not installed")
        return 2
    try:
        import cairosvg  # noqa: F401
    except ImportError:
        print("[FAIL] cairosvg is not installed (pip install cairosvg)")
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        build = pathlib.Path(tmp)
        _rasterise(build)
        source = _source_for_word(build)
        subprocess.run(
            ["pandoc", source.name, "-o", "out.docx",
             "--metadata", "author=Paolo De Rosa", "--metadata", "lang=en-GB"],
            cwd=build, check=True)
        shutil.copyfile(build / "out.docx", DOCX)

    rows, headers = _fix_tables(DOCX)
    print(f"[OK] {DOCX.name} rebuilt from {MD.name} "
          f"({rows} table rows and {getattr(_fix_tables, 'kept', 0)} list items kept whole, "
          f"{headers} headers set to repeat)")
    print("     Now run `python3 brief/check_counts.py` — it reads this file too.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
