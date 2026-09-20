#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build/check the Internet-Draft.

If kramdown-rfc (and xml2rfc) are installed, render the draft; otherwise fall
back to a markdown STRUCTURE check so CI is never gated on those tools being
present. Exit non-zero if the structure check fails.

Usage: python scripts/build_id.py [ietf/draft-sbm-mls-erd-00.md]
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys

DEFAULT = "ietf/draft-sbm-mls-erd-00.md"
REQUIRED_FM = ("title", "docname", "category", "ipr", "author")
REQUIRED_SECTIONS = ("# Introduction", "# Security Considerations", "# IANA Considerations")


def _front_matter(text):
    # kramdown-rfc: YAML between the opening '---' and the first '--- <name>'.
    if not text.startswith("---"):
        return None, "missing kramdown-rfc front matter"
    lines = text.splitlines()
    fm, started = [], False
    for ln in lines:
        if ln.strip() == "---" and not started:
            started = True
            continue
        if started and ln.startswith("---"):  # '--- abstract' / '--- middle'
            break
        if started:
            fm.append(ln)
    return "\n".join(fm), None


def structure_check(path):
    text = pathlib.Path(path).read_text(encoding="utf-8")
    errors = []
    fm, err = _front_matter(text)
    if err:
        errors.append(err)
    else:
        try:
            import yaml
            meta = yaml.safe_load(fm) or {}
        except Exception as exc:  # pragma: no cover
            meta = {}
            errors.append(f"front matter not valid YAML ({exc})")
        for k in REQUIRED_FM:
            if k not in meta:
                errors.append(f"front matter missing '{k}'")
        if meta.get("category") not in ("std", "exp", "info", "bcp"):
            errors.append(f"invalid category: {meta.get('category')!r}")
        authors = meta.get("author")
        authors = authors if isinstance(authors, list) else [authors]
        if not any(isinstance(a, dict) and a.get("email") for a in authors):
            errors.append("front matter author missing email")
    for sec in REQUIRED_SECTIONS:
        if not re.search(r"(?m)^" + re.escape(sec) + r"\s*$", text):
            errors.append(f"missing section '{sec}'")
    if "{::boilerplate bcp14-tagged}" not in text and "BCP 14" not in text:
        errors.append("missing BCP 14 boilerplate")
    if "--- back" not in text:
        errors.append("missing '--- back' (references/appendices) marker")
    errors.extend(_reference_check(text, meta if not err else {}))
    return errors


def _reference_check(text, meta):
    """Catch, WITHOUT a renderer, the duplicate-reference error that only CI
    could see before.

    kramdown-rfc auto-declares a reference written as `{{!RFCxxxx}}`. Where the
    front matter ALREADY declares it, xml2rfc fails with 'ID RFCxxxx redefined'
    — and the render gate is CI-only, so a contributor without kramdown-rfc and
    xml2rfc gets a green local bar and a red pull request. That is exactly what
    happened when DR-12's text cited RFC 8032, which was already declared as
    informative.

    The trigger is specifically an INFORMATIVE declaration cited normatively:
    the `!` asks for a normative entry, the front matter already produced an
    informative one, and the two collide. `{{!X}}` where X is already declared
    normative is harmless and common — this document has several — so flagging
    that too would be a false positive, and the RFC 8610 citation that has
    always rendered cleanly is the evidence."""
    import re as _re
    problems = []
    declared = {}
    for section in ("normative", "informative"):
        for key in (meta.get(section) or {}):
            declared[str(key)] = section
    for ref in sorted(set(_re.findall(r"\{\{!([A-Za-z0-9._-]+)\}\}", text))):
        if declared.get(ref) != "informative":
            continue        # absent (auto-declared) or already normative: fine
        problems.append(
            f"{{{{!{ref}}}}} cites as NORMATIVE a reference the front matter "
            f"declares INFORMATIVE — xml2rfc fails with 'ID {ref} redefined', "
            "because both entries are emitted. MOVE the front-matter entry to "
            "'normative' and cite it as {{" + ref + "}}.")
    return problems


def main(argv):
    path = argv[1] if len(argv) > 1 else DEFAULT
    if not pathlib.Path(path).is_file():
        print(f"[ERR] {path} not found", file=sys.stderr)
        return 2
    errors = structure_check(path)
    if errors:
        print(f"[FAIL] {path} structure check:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"[OK] {path} structure check passed")

    # Full render when the toolchain is present. Prefer the tools that emit
    # RFCXML on stdout (kramdown-rfc / -2629); fall back to kdrfc. With
    # ID_RENDER_STRICT set (the `render-id` CI job), a missing toolchain or a
    # render failure is fatal; otherwise CI is never gated on these tools.
    strict = bool(os.environ.get("ID_RENDER_STRICT"))
    tool = (shutil.which("kramdown-rfc2629") or shutil.which("kramdown-rfc")
            or shutil.which("kdrfc"))
    if not tool:
        msg = "kramdown-rfc not installed — structure check only (not a full render)"
        if strict:
            print(f"[FAIL] {msg} (ID_RENDER_STRICT set)")
            return 2
        print(f"[note] {msg}")
        return 0
    try:
        xml = path.replace(".md", ".xml")
        with open(xml, "w") as out:
            subprocess.run([tool, path], check=True, stdout=out)
        print(f"[OK] rendered {xml} with {os.path.basename(tool)}")
        if shutil.which("xml2rfc"):
            subprocess.run(["xml2rfc", xml], check=True)
            print("[OK] xml2rfc render succeeded")
        elif strict:
            print("[FAIL] xml2rfc not installed (ID_RENDER_STRICT set)")
            return 2
        else:
            print("[note] xml2rfc not installed — XML generated, text not rendered")
    except Exception as exc:
        if strict:
            print(f"[FAIL] kramdown-rfc/xml2rfc render failed ({exc})")
            return 2
        print(f"[warn] kramdown-rfc/xml2rfc render failed ({exc}); structure check still passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
