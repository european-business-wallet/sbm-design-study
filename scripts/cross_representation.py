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


def main():
    findings = check_vectors() + check_contract()
    for line in findings:
        print(f"[FAIL] {line}")
    schemas = len(list((ROOT / "schemas").glob("evidence-*.schema.json")))
    print(f"cross-representation: {schemas} evidence schemas held by sealed "
          f"vectors, {len(NON_BODY) + len(EXECUTED)} request shapes checked "
          f"against the reference — {len(findings)} divergence(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
