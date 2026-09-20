#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""R5-07/3 — the integration gate's own analysis, derived rather than stored.

Round 4 built a registry of the helpers that implement a normative rule and a
test that checked them. Round 5 found the registry **stale in two entries**:
`resolve_ds_receipt_key` and `check_certificate_binds_key` were recorded
`status: unintegrated` — a description written when round 4 *started* and never
revised after round 4's own Batch 3 wired both in. A registry whose entries can
be false is worse than no registry, because it is consulted instead of the code.

Three defects in the instrument, and each fix is a property of this module:

1. **The classification was STORED, so it could be false.** It is now
   **derived** from the AST, in both directions: a helper with a reachable
   production caller *is* integrated, one without *is not*, and the registry
   may not assert otherwise. What the registry still holds is the part no
   analysis can infer — which helpers carry a normative obligation, which
   arguments make them do their work, and which exemptions a human accepted.

2. **The act-time check asserted `at least one` caller.** `assert hits` is
   satisfied by a single correct call site, so one correct caller launders
   every incorrect one — which is exactly how the live receipt path went on
   passing `at` positionally while the gate stayed green. Coverage is now over
   **every** call site, and an exempt site is named individually.

3. **Reachability was "some module calls it".** A helper called by a function
   nobody reaches is not integrated. Reachability is now computed from declared
   **public entry points**.

**LIMIT, stated because it would otherwise be over-read.** The call graph
matches on NAME, not on resolved binding: two different functions with one name
are treated as one node, and a call through a variable or `getattr` is not seen
at all. That makes reachability an OVER-approximation and the act-time coverage
an UNDER-approximation of what a full resolver would compute. Both were chosen
so the residual error **fails closed**: a missing entry point makes a helper
look unreachable and the gate FAIL, and an unseen call site cannot silently
satisfy a coverage requirement. This is the opposite of the stored `status`,
whose staleness made the gate PASS — which is the whole finding.
"""
import ast
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REGISTRY = ROOT / "docs" / "normative-helpers.json"

# This module is the gate's instrument, not a checked artefact.
SELF = "helper_integration.py"


def production_modules():
    """Every module under `scripts/` except this one."""
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(SCRIPTS.glob("*.py")) if p.name != SELF}


def load_registry():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


class CallSite:
    """One syntactic call of a helper, with what it actually passed."""

    def __init__(self, module, lineno, enclosing, keywords, positional):
        self.module, self.lineno = module, lineno
        self.enclosing = enclosing          # the function containing the call
        self.keywords = keywords            # names passed as kwargs
        self.positional = positional        # how many positional arguments

    @property
    def id(self):
        return f"{self.module}:{self.lineno}"

    @property
    def key(self):
        """The stable identity of a call site: module and enclosing function.

        NOT the line number — an edit anywhere above would shift it and either
        exempt a site nobody reviewed or fail one that was. An exemption is a
        signed statement about a piece of code, so it is keyed by the code.
        """
        return f"{self.module}::{self.enclosing}"

    def __repr__(self):                                      # pragma: no cover
        return f"<{self.id} in {self.enclosing}()>"


def _called_name(node):
    f = node.func
    return getattr(f, "id", None) or getattr(f, "attr", None)


def _walk_functions(tree):
    """Yield (function_name, node) for every def, nested ones included.

    A nested rule function — `bundle_lint._bnd38` and friends are all nested —
    is attributed to ITSELF, and its parent records a call to it, so the chain
    from the entry point stays connected.
    """
    stack = [("<module>", tree)]
    while stack:
        name, node = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child.name, child
                stack.append((child.name, child))
            else:
                stack.append((name, child))


def call_graph(modules=None):
    """`{function_name: {names it calls}}` across all production modules.

    Names are GLOBAL — see the LIMIT in the module docstring.
    """
    modules = modules or production_modules()
    graph = {}
    for src in modules.values():
        try:
            tree = ast.parse(src)
        except SyntaxError:                                  # pragma: no cover
            continue
        # Module-level calls belong to a synthetic node so a script that wires
        # things up at import time still connects.
        graph.setdefault("<module>", set())
        for fname, fnode in _walk_functions(tree):
            edges = graph.setdefault(fname, set())
            for node in ast.walk(fnode):
                if isinstance(node, ast.Call):
                    called = _called_name(node)
                    if called:
                        edges.add(called)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                called = _called_name(node)
                if called:
                    graph["<module>"].add(called)
    return graph


def reachable(entry_points, graph=None):
    """Every function name reachable from `entry_points` by calls."""
    graph = graph if graph is not None else call_graph()
    seen, stack = set(), list(entry_points)
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(graph.get(name, ()))
    return seen


def call_sites(name, modules=None):
    """Every syntactic call of `name`, with the enclosing function.

    The definition, the import line and a docstring mention are not calls and
    do not appear.
    """
    modules = modules or production_modules()
    out = []
    for mod, src in modules.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:                                  # pragma: no cover
            continue
        scopes = [("<module>", tree)] + [(n, f) for n, f in _walk_functions(tree)]
        for enclosing, node in scopes:
            for child in ast.walk(node):
                if not isinstance(child, ast.Call) or _called_name(child) != name:
                    continue
                # Attribute the call to the INNERMOST enclosing function: walk
                # order visits outer scopes too, so keep the deepest match.
                out.append(CallSite(
                    mod, child.lineno, enclosing,
                    {k.arg for k in child.keywords if k.arg},
                    len(child.args)))
    # One call, one record — keep the innermost attribution.
    best = {}
    for site in out:
        prior = best.get(site.id)
        if prior is None or prior.enclosing == "<module>":
            best[site.id] = site
    return sorted(best.values(), key=lambda s: (s.module, s.lineno))


def classify(helper, *, graph=None, modules=None, entry_points=()):
    """The DERIVED status of one helper: 'integrated' or 'unintegrated'.

    Integrated means: called from production code, by a function that is itself
    reachable from a public entry point. Both halves matter — round 5's R5-05
    is a rule that IS called, from a path the CLI never feeds.
    """
    modules = modules or production_modules()
    graph = graph if graph is not None else call_graph(modules)
    sites = [s for s in call_sites(helper["name"], modules)
             if s.enclosing != helper["name"]]          # not its own recursion
    if not sites:
        return "unintegrated", []
    live = reachable(entry_points, graph)
    reached = [s for s in sites if s.enclosing in live or s.enclosing == "<module>"]
    return ("integrated" if reached else "unintegrated"), sites


def missing_arguments(helper, *, modules=None):
    """Call sites that omit an argument the helper needs to do its work.

    R4-04 was a call that passed everything except the one parameter the rule
    is about; round 4 then checked that SOME caller passed it. Every site is
    checked here, and a site the registry exempts must be named.
    """
    modules = modules or production_modules()
    required = helper.get("required_arguments") or []
    if not required:
        return []
    exempt = helper.get("argument_exemptions") or {}
    bad = []
    for site in call_sites(helper["name"], modules):
        if site.enclosing == helper["name"]:
            continue
        for arg in required:
            if arg in site.keywords:
                continue
            if site.key in exempt:
                continue
            bad.append((site, arg))
    return bad


def main():                                                  # pragma: no cover
    reg = load_registry()
    graph, mods = call_graph(), production_modules()
    entries = reg["entry_points"]
    for h in reg["helpers"]:
        status, sites = classify(h, graph=graph, modules=mods, entry_points=entries)
        gaps = missing_arguments(h, modules=mods)
        print(f"{h['name']:<32} {status:<14} "
              f"{len(sites)} site(s)" + (f"  MISSING {gaps}" if gaps else ""))
    return 0


if __name__ == "__main__":                                   # pragma: no cover
    raise SystemExit(main())
