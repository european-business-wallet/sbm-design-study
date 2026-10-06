#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-representation gate — does every surface carrying a concept carry it?

A concept in this specification is described more than once: as a JSON Schema,
as a CDDL rule, as an OpenAPI component, and as code in the reference. Nothing
asked whether a concept that reached one of those surfaces reached the others,
and the answer was repeatedly no:

  R26-PUB-01/02  a recipient confirmation the CDDL had always required to name
                 its device; the Schema did not, and the two described the same
                 object differently until a reviewer read both.
  G1             the pre-join refusal proof existed in the reference and in the
                 wire helper, and `WelcomeRefusalRequest` did not describe it —
                 so the published contract could not be used to build the
                 request the reference demanded.

Both were found by a human reading two files side by side. This gate asks the
question mechanically, in the two directions where an answer is provable.


XREP-01 — every field name a published evidence Schema declares is exercised by
          at least one sealed vector.

    Not a style rule. `cddl_check` validates every sealed sample against a
    SPECIFIC CDDL rule, against its JSON Schema, and asserts that the decoded
    body equals the projection. So for a name some vector carries, the three
    descriptions cannot drift: the vector holds them together. For a name NO
    vector carries, nothing holds anything — the Schema may say one thing, the
    CDDL another, and every gate in the tree passes.

    That is not hypothetical. The first vector written for `disputes` failed
    LINT-PKG-11 immediately: `ep_artifact` embedded the dispute artefacts in the
    sealed body and omitted them from the projection, so a package carrying a
    dispute sealed a document its own readable form denied. The branch for
    `changes` did both; the branch for `disputes` did half. It had shipped that
    way because no vector had ever carried one.

    SCOPE, stated rather than assumed: this covers the EVIDENCE schemas, whose
    bodies are described by both a specific CDDL rule and a JSON Schema. It does
    NOT cover `envelope.schema.json` (the CDDL describes the wire artefacts, not
    the plaintext inside the E2EE envelope) or the `bw-*` discovery schemas
    (`cddl_check` validates discovery bodies on their type/version discriminators
    only, leaving the JSON Schema their sole strict validator). Where a document
    has ONE strict description there are no two representations to hold
    together, and a check claiming otherwise would be theatre. Those surfaces
    need a different instrument, not this one.

    Granularity is the field NAME, not the JSON pointer. A name is the unit in
    which a concept arrives: `recipient_validation_failure` and its seven
    sub-fields were thirteen unexercised names in one batch, all mine. Pointer
    granularity would demand a vector for every optional field in every `anyOf`
    arm, most combinations of which are unreachable by construction — an
    exception list long enough that the gate would be switched off, which is the
    one outcome worse than not having it.

XREP-02 — every body field the reference accepts is described by the published
          contract, and every field the contract publishes is one the reference
          accepts.

    G1's defect, in the direction that produced it. An implementer holds only
    the contract; a field the reference requires and the contract omits cannot
    be supplied by anyone reading what was published.

    A keyword parameter is not automatically a body field, so two sources are
    subtracted: the operation's PATH parameters, derived from the OpenAPI
    document rather than listed here, and NON_BODY below — values the transport
    or the server supplies, each with its reason. `InvitationDeposit` is not
    compared by signature: `validate_invitation_deposit` EXECUTES the published
    schema over the whole record, which is a stronger binding than any
    comparison of names, and is recorded as such.

Exit 0 when every surface agrees, 1 otherwise. Wired into `make conformance`.
"""
import inspect
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


# ---------------------------------------------------------------------------
# XREP-01 — the vectors that hold the evidence representations together
# ---------------------------------------------------------------------------

def declared_names(node, out=None):
    """Every property NAME a schema declares, at any depth, through every
    combinator. A name reachable only inside an `anyOf` arm is still published."""
    out = set() if out is None else out
    if isinstance(node, dict):
        for name, sub in (node.get("properties") or {}).items():
            out.add(name)
            declared_names(sub, out)
        for key in ("$defs", "definitions"):
            for sub in (node.get(key) or {}).values():
                declared_names(sub, out)
        for key in ("allOf", "anyOf", "oneOf", "items", "not", "if", "then",
                    "else", "additionalProperties", "contains",
                    "unevaluatedProperties", "propertyNames"):
            sub = node.get(key)
            if isinstance(sub, list):
                for s in sub:
                    declared_names(s, out)
            elif isinstance(sub, dict):
                declared_names(sub, out)
        for sub in (node.get("patternProperties") or {}).values():
            declared_names(sub, out)
    return out


def vector_names(node, out=None):
    """Every key present in a sealed vector's projection, at any depth — so an
    EP's nested SE, outcomes, changes and disputes all count as exercised."""
    out = set() if out is None else out
    if isinstance(node, dict):
        for key, sub in node.items():
            out.add(key)
            vector_names(sub, out)
    elif isinstance(node, list):
        for sub in node:
            vector_names(sub, out)
    return out


def exercised():
    """The names carried by the SEALED vectors — the ones `cddl_check` holds to
    the CDDL, to the JSON Schema and to their own decoded body. A sample without
    a `projection` is not a sealed artefact and proves nothing here."""
    names = set()
    for path in sorted((ROOT / "samples").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "projection" in doc and "sm_artifact_b64" in doc:
            vector_names(doc["projection"], names)
    return names


def check_vectors():
    have = exercised()
    findings = []
    for path in sorted((ROOT / "schemas").glob("evidence-*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        for name in sorted(declared_names(schema) - have):
            findings.append(
                f"XREP-01 {path.name}: `{name}` is declared by the Schema and "
                "carried by no sealed vector, so nothing holds the Schema, the "
                "CDDL and the reference's projection to the same account of it — "
                "add a vector that exercises it (a vector is the binding; a "
                "second hand-written description is not)")
    return findings


# ---------------------------------------------------------------------------
# XREP-02 — the reference's request surface against the published contract
# ---------------------------------------------------------------------------

#: Keyword parameters that are NOT body fields, with the reason each one is not.
#: Path parameters are NOT listed here — they are derived from the OpenAPI
#: document, so a path that gains or loses one needs no edit in this file.
NON_BODY = {
    "WelcomeRefusalRequest": {
        "members": "the group roster, resolved by the server from the reservation",
        "refused_at": "the recording instant, injected so a test can place the "
                      "act inside or outside the window; the client does not "
                      "assert when the server recorded it",
    },
    "ReceiptAckRequest": {
        "session_binding": "the authenticated session the DS itself observes; a "
                           "client-asserted value would let a device name a "
                           "session it is not in (R7-02)",
        "octets": "the delivered bytes, held by the DS",
        "server_clock": "the DS's own clock — DR-10 exists precisely because a "
                        "client-supplied instant let a device backdate into a "
                        "window that had closed",
        "ds_kid": "the DS's signing key identifier",
        "ds_seed": "WHICH of its own keys the mock signs with — server-side key "
                   "material, not a wire value. A receipt is verified against the "
                   "key the ISSUING RDP publishes in its own descriptor "
                   "(SBM-ADR-0015), so a mock standing in for two providers must "
                   "be able to sign as either; a client that could choose it "
                   "would be choosing whose receipt this is",
    },
    "MessageSubmission": {
        "accepted_at": "the server's acceptance instant",
        "principal": "resolved from the presented credential, never asserted",
    },
}

#: Operations whose body is validated by EXECUTING the published schema over the
#: whole record. Stronger than comparing names, so they are recorded, not paired.
EXECUTED = {
    "InvitationDeposit": "mock_rdp.validate_invitation_deposit executes the "
                         "published schema over the deposited record",
}


def contract_properties(schemas, name, seen=None):
    """The property names a contract component publishes, through $ref and the
    combinators, so a component assembled from parts is measured whole."""
    seen = set() if seen is None else seen
    if name in seen or name not in schemas:
        return set()
    seen.add(name)
    node, out = schemas[name], set()

    def walk(sub):
        if not isinstance(sub, dict):
            return
        ref = sub.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            out.update(contract_properties(schemas, ref.rsplit("/", 1)[-1], seen))
        out.update(sub.get("properties") or {})
        for key in ("allOf", "anyOf", "oneOf"):
            for arm in sub.get(key) or []:
                walk(arm)

    walk(node)
    return out


def path_parameters(doc, component):
    """Every path/query parameter of the operation whose request body is this
    component — derived, so the contract stays the single source."""
    names = set()
    for path, item in (doc.get("paths") or {}).items():
        shared = item.get("parameters") or []
        for method, op in item.items():
            if not isinstance(op, dict) or method == "parameters":
                continue
            body = ((op.get("requestBody") or {}).get("content") or {})
            refs = {(c.get("schema") or {}).get("$ref", "").rsplit("/", 1)[-1]
                    for c in body.values() if isinstance(c, dict)}
            if component not in refs:
                continue
            for param in list(shared) + list(op.get("parameters") or []):
                if isinstance(param, dict) and param.get("name"):
                    names.add(param["name"])
    return names


def compare_request(component, entry, doc, non_body=None):
    """One request shape against one entry point, in BOTH directions. Separate
    from the tree so a probe can build its own contract and its own reference
    rather than mutate ours (invariant 13)."""
    schemas = (doc.get("components") or {}).get("schemas") or {}
    if component not in schemas:
        return [f"XREP-02 {component} is not a published component, so the "
                "reference executes a shape nobody can read"]
    non_body = NON_BODY if non_body is None else non_body
    published = contract_properties(schemas, component)
    accepted = {name for name, p in inspect.signature(entry).parameters.items()
                if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)}
    accepted -= {"self", "credential", "now"}
    findings = []
    for name in sorted(accepted - published - path_parameters(doc, component)
                       - set(non_body.get(component, {}))):
        findings.append(
            f"XREP-02 {component}: `{entry.__name__}` accepts `{name}` and the "
            "published contract does not describe it — an implementer holding "
            "only the contract cannot build the request the reference wants "
            "(G1). Publish the field, or record in NON_BODY why the transport "
            "or the server supplies it")
    for name in sorted(published - accepted):
        findings.append(
            f"XREP-02 {component}: the contract publishes `{name}` and "
            f"`{entry.__name__}` does not accept it — the reference cannot "
            "execute what was published")
    return findings


def check_contract():
    import yaml

    import mock_rdp

    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text(encoding="utf-8"))
    pairs = [("WelcomeRefusalRequest", mock_rdp.refuse_welcome),
             ("ReceiptAckRequest", mock_rdp.receipt_ack),
             ("MessageSubmission", mock_rdp.ds_accept_message)]
    return [f for component, entry in pairs
            for f in compare_request(component, entry, doc)]


# ---------------------------------------------------------------------------
# XREP-03 — the normative access table against the contract's declared security
# ---------------------------------------------------------------------------

#: The umbrella's normative access table: one row per published EDD path, with
#: the access rule that governs it. The prose around it says so outright — "The
#: table is normative; `edd-resolver-openapi.yaml` is the full contract" — which
#: makes the two descriptions of one access rule, and nothing compared them.
ACCESS_TABLE_HEADER = ("| Path | Authoritative operator | Data owner | Storage | Access |")
ACCESS_CONTRACT = "edd-resolver-openapi.yaml"

#: An Access cell demands authentication unless it only PERMITS it. The
#: `.well-known` row reads "Public; production MAY authenticate", which is a
#: deployment's option and not a requirement this contract must carry.
_DEMANDS_AUTH = re.compile(r"authenticated|authorised|authorized", re.I)
_PERMITS_ONLY = re.compile(r"MAY authenticate", re.I)


def _expand(path):
    """One table cell into the pattern(s) it rules on.

    `/.well-known/bw/med|org|member/…` names three families, not one path, and
    the `…` stands for a parameter suffix that differs between them
    (`/{uid}` for med and org, `/{uid}/{mid}` for member). So an alternation
    expands to one pattern each, and a trailing `…` makes the pattern a PREFIX
    rather than an exact path.
    """
    is_prefix = path.rstrip("/").endswith("…")
    match = re.search(r"([a-z-]+(?:\|[a-z-]+)+)", path)
    paths = ([path.replace(match.group(1), alt) for alt in match.group(1).split("|")]
             if match else [path])
    return [p.rstrip("…").rstrip("/") for p in paths], is_prefix


def access_table(prose):
    """[(path, demands_auth)] from the normative table, one entry per path."""
    if ACCESS_TABLE_HEADER not in prose:
        raise SystemExit("XREP-03: the normative access table is not in the profile "
                         "under the heading this gate reads — it was renamed, moved "
                         "or removed, and the comparison would silently check nothing")
    body = prose.split(ACCESS_TABLE_HEADER, 1)[1].split("\n\n", 1)[0]
    out = []
    for line in body.splitlines():
        if not line.startswith("|") or set(line) <= set("|-: "):
            continue
        # A cell may carry an UNESCAPED `|` inside a code span — the
        # `bw/med|org|member` row does — and splitting on it there shifts every
        # column right, so the Access cell read as something else entirely and
        # the row silently ruled on nothing. Protect code spans first.
        guarded = re.sub(r"`[^`]*`", lambda m: m.group(0).replace("|", "\x00"), line)
        cells = [c.strip().replace("\x00", "|") for c in guarded.split("|")[1:-1]]
        if len(cells) < 5:
            continue
        demands = bool(_DEMANDS_AUTH.search(cells[4])) and not _PERMITS_ONLY.search(cells[4])
        for quoted in re.findall(r"`([^`]+)`", cells[0]):
            for one in quoted.split(","):
                one = one.strip().removeprefix("GET ").strip()
                if not one.startswith("/"):
                    continue
                patterns, is_prefix = _expand(one)
                out.extend((p, is_prefix, demands) for p in patterns)
    return out


def declared_security(doc):
    """path -> the security schemes its operations declare (empty list = none)."""
    out = {}
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if not isinstance(op, dict) or method == "parameters":
                continue
            out[path] = sorted({k for entry in (op.get("security") or []) for k in entry})
    return out


def check_access():
    """The access rule, stated twice, compared once.

    A published contract that omits a security requirement its own specification
    states is not a documentation slip: a client is generated from the contract,
    so the contract is what gets built. Both of the mismatches this found were in
    that direction — `/uid/{uid}/roster-snapshot` and `/uid/{uid}/keypackages`
    demanded an authenticated counterparty in the umbrella and declared nothing
    here, and the roster snapshot is the entity's COMPLETE signed roster where
    the browsing mirror beside it, which discloses strictly less, was
    authenticated. The access control was inverted against the disclosure.
    """
    import yaml

    prose = (ROOT / "Secure-Business-Messaging-Profile.md").read_text(encoding="utf-8")
    doc = yaml.safe_load((ROOT / ACCESS_CONTRACT).read_text(encoding="utf-8"))
    declared, findings = declared_security(doc), []
    # Resolve each rule against the paths the contract actually publishes, so a
    # prefix rule governs the family it names and an exact rule governs one path.
    ruled = {}
    for pattern, is_prefix, demands in access_table(prose):
        matched = [p for p in declared
                   if (p.startswith(pattern) if is_prefix else p == pattern)]
        if not matched:
            findings.append(
                f"XREP-03 the normative access table rules on `{pattern}` and "
                f"{ACCESS_CONTRACT} publishes no such operation — a rule with "
                "nothing to govern")
        for path in matched:
            ruled[path] = demands

    for path, demands in sorted(ruled.items()):
        schemes = declared[path]
        if demands and not schemes:
            findings.append(
                f"XREP-03 `{path}`: the normative access table requires an "
                f"authenticated caller and {ACCESS_CONTRACT} declares no security, so "
                "a client generated from the published contract calls it anonymously "
                "— and the contract is what gets built")
        if schemes and not demands:
            findings.append(
                f"XREP-03 `{path}`: {ACCESS_CONTRACT} demands {schemes} and the "
                "normative access table calls it public — a caller entitled by the "
                "specification is refused by the contract")

    for path in sorted(set(declared) - set(ruled)):
        findings.append(
            f"XREP-03 {ACCESS_CONTRACT} publishes `{path}` and the normative access "
            "table does not rule on it — every path is supposed to have exactly one "
            "access-control rule, and this one has none")
    return findings


def main():
    findings = check_vectors() + check_contract() + check_access()
    for line in findings:
        print(f"[FAIL] {line}")
    schemas = len(list((ROOT / "schemas").glob("evidence-*.schema.json")))
    import yaml
    ruled = len(access_table((ROOT / "Secure-Business-Messaging-Profile.md")
                             .read_text(encoding="utf-8")))
    print(f"cross-representation: {schemas} evidence schemas held by sealed "
          f"vectors, {len(NON_BODY) + len(EXECUTED)} request shapes checked "
          f"against the reference, {ruled} published path(s) against the "
          f"normative access table — {len(findings)} divergence(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
