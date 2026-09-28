# SPDX-License-Identifier: MIT
"""G4 — who sees what, checked rather than asserted in prose.

`docs/architecture-identity-trust.md` §6 is the per-actor shape of the umbrella's
metadata-privacy inventory, and `Secure-Business-Messaging-Profile.md` §8 carries
the normative access table that says which caller may reach which published path.
Both were prose. The access table turned out to disagree with the contract for two
paths — `/uid/{uid}/roster-snapshot` and `/uid/{uid}/keypackages` both required an
authenticated counterparty and declared no security — so a client generated from
the published document read an entity's organisational structure anonymously.
That comparison now lives in the cross-representation gate as XREP-03; what is
here is the rest of §6, the part about which values may appear where.

The privacy-bearing claims in that table are the NEGATIVE ones — "never", "no" —
because a claim that an actor sees something is at worst generous, while a claim
that it sees nothing is the one a deployment relies on. So the confinement
invariant gets the most weight: the values the profile says travel only inside the
end-to-end-encrypted envelope must appear in no sealed evidence and no discovery
document, except where a dispute reveal deliberately opens one.

Every actor row must appear in `ACTORS`, so a row added to the prose cannot arrive
without a probe — the same drift guard `test_lifecycle_claims` uses for G3.
"""
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

ARCH = ROOT / "docs" / "architecture-identity-trust.md"

#: Values the profile confines to the E2EE envelope. `salt` is the generic name
#: the reveal structures use for the same secret once it is deliberately opened.
ENVELOPE_CONFINED = {"content_class", "grade_commitment_salt",
                     "mandate_commitment_salt", "salt"}

#: The only places a confined value may legitimately appear in sealed material:
#: a dispute reveal and the confirmation that opens it. Both are disclosures a
#: party CHOSE to make, to the parties of that dispute.
REVEAL_CONTAINERS = {"reveal", "reveal_confirmation", "reveals"}


def _in_reveal(trail):
    """Is this path inside a reveal structure?

    An instance nests the value under a key named `reveal`, `reveal_confirmation`
    or `reveals`. A SCHEMA nests it under a `$defs` name instead —
    `RecipientRevealConfirmation` — so the name is what identifies the container
    there, and matching only property keys excused nothing and flagged the one
    legitimate declaration.
    """
    return any(str(part) in REVEAL_CONTAINERS or "reveal" in str(part).lower()
               for part in trail)


def actor_rows():
    body = ARCH.read_text(encoding="utf-8").split("## 6. Who sees what", 1)[1]
    body = body.split("## 7.", 1)[0]
    rows = [line for line in body.splitlines()
            if line.startswith("|") and not set(line) <= set("|-: ")]
    return [row.split("|")[1].strip() for row in rows[1:]]


def _confined_in(node, trail=(), out=None):
    """Every confined value in a document, with the path that carries it."""
    out = [] if out is None else out
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ENVELOPE_CONFINED:
                out.append((tuple(trail), key))
            _confined_in(value, trail + (key,), out)
    elif isinstance(node, list):
        for item in node:
            _confined_in(item, trail, out)
    return out


def _sealed_documents():
    """Every sealed artefact the repository ships, by file name."""
    for path in sorted((ROOT / "samples").glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "projection" in doc and "sm_artifact_b64" in doc:
            yield path.name, doc["projection"]


# ---------------------------------------------------------------------------
# The confinement invariant — the claim the whole table rests on
# ---------------------------------------------------------------------------

def test_no_sealed_artefact_carries_a_confined_value_outside_a_reveal():
    """"The content class never appears in evidence; a reveal discloses one
    message's class to the parties of that dispute."

    The salts are the sharper half: a grade or mandate commitment is only as
    private as its salt, so a salt that reached a sealed object would let anyone
    holding that object test a guess against the commitment — and the commitment
    is published in evidence by design.
    """
    leaks = []
    for name, body in _sealed_documents():
        for trail, key in _confined_in(body):
            if not _in_reveal(trail):
                leaks.append(f"{name}: {'.'.join(trail + (key,))}")
    assert leaks == [], leaks


def test_a_confined_value_planted_outside_a_reveal_is_detected():
    """The probe's own control: it must fail on a document that does leak."""
    leaked = {"type": "SE-v1", "payload_hash": {"hex": "ab"},
              "grade_commitment_salt": "64" * 16}
    found = [t for t, _ in _confined_in(leaked) if not _in_reveal(t)]
    assert found == [()], found


def test_the_schemas_declare_confined_values_only_where_they_belong():
    """Vectors show what was shipped; the schemas show what MAY be. A sealed
    schema that declared a salt would permit the leak even with no vector."""
    allowed = {"envelope.schema.json"}
    offenders = []
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        if path.name in allowed:
            continue
        declared = json.loads(path.read_text(encoding="utf-8"))
        for trail, key in _confined_in(declared):
            # `properties`/`$defs` keys name the structure, so a reveal container
            # anywhere in the trail is the legitimate case.
            if not _in_reveal(trail):
                offenders.append(f"{path.name}: {'.'.join(trail + (key,))}")
    assert offenders == [], offenders


def test_the_envelope_is_the_one_place_they_are_declared():
    """And the positive half: the envelope really does carry them, so the
    confinement is a statement about where they live, not that they are unused."""
    envelope = json.loads((ROOT / "schemas" / "envelope.schema.json").read_text())
    declared = set(envelope.get("properties") or {})
    assert {"content_class", "grade_commitment_salt",
            "mandate_commitment_salt"} <= declared, sorted(declared)


# ---------------------------------------------------------------------------
# The per-actor rows
# ---------------------------------------------------------------------------

def claim_wallet_devices():
    """"yes — their own" plaintext. The wallet is the only actor with the
    plaintext, which is what makes every other row's "never" meaningful."""
    envelope = json.loads((ROOT / "samples" / "sample-ENVELOPE.json").read_text())
    assert "content_class" in envelope, "the envelope is the wallet's own view"
    # And no provider-sealed object repeats it — the rest of §6 in one line.
    for name, body in _sealed_documents():
        outside = [t for t, _ in _confined_in(body) if not _in_reveal(t)]
        assert outside == [], (name, outside)


def claim_delivery_service():
    """"never" plaintext; "the evidence fields of the origin's sealed SE,
    including `payload_hash` and `scope_ref`" on the forwarding path. The
    positive half is checkable: those fields are really there to be decoded."""
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    assert "payload_hash" in se and "scope_ref" in se
    assert "content_class" not in se, "the DS would read the class off the SE"


def claim_rdps():
    """"never" plaintext; "the evidence fields they seal, including `scope_ref`"."""
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    assert se.get("scope_ref"), "the scope reference is cleartext in evidence"
    # A scope reference names a scope, never the class inside it.
    assert "content_class" not in json.dumps(se["scope_ref"])


def claim_edd():
    """"never" plaintext, "no" ciphertext, "resolution queries" as metadata.

    The access rule for every EDD path is XREP-03's subject; what is asserted
    here is the storage claim the same table makes — the EDD stores no evidence
    and holds no KeyPackage pool, so both of those paths are pointers.
    """
    import yaml
    doc = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text(encoding="utf-8"))
    for path in ("/uid/{uid}/evidence/{message_id}", "/uid/{uid}/keypackages"):
        described = json.dumps(doc["paths"][path]["get"])
        assert "302" in described, f"{path} must be a pointer, not a served body"


def claim_time_stamping_service():
    """"never" plaintext, "no" ciphertext, "timing, over seal hashes". A
    timestamp is taken over the COSE bytes, so the service sees a digest."""
    import cbor2
    sample = json.loads((ROOT / "samples" / "sample-SE.json").read_text())
    import base64
    artefact = cbor2.loads(base64.b64decode(sample["sm_artifact_b64"]))
    assert isinstance(artefact, list) and len(artefact) == 2, \
        "an evidence artefact is [cose, qts] — the stamp is beside the seal"


def claim_a_later_verifier():
    """"only if it holds it" for plaintext; "everything the package carries" as
    metadata. So the package is the disclosure boundary, and what it carries is
    exactly what `docs/retrievability.md` enumerates as verification inputs."""
    ep = json.loads((ROOT / "samples" / "sample-EP.json").read_text())["projection"]
    assert {"se", "outcomes", "rdp_chain"} <= set(ep)
    outside = [t for t, _ in _confined_in(ep) if not _in_reveal(t)]
    assert outside == [], outside


ACTORS = {
    "Wallet devices of the two entities": claim_wallet_devices,
    "Delivery Service (MSP)": claim_delivery_service,
    "RDPs": claim_rdps,
    "EDD": claim_edd,
    "Time-stamping service": claim_time_stamping_service,
    "A later verifier of an Evidence Package": claim_a_later_verifier,
}


def test_every_actor_row_has_a_probe():
    rows, probed = set(actor_rows()), set(ACTORS)
    assert rows == probed, {"unprobed rows": sorted(rows - probed),
                            "probes for no row": sorted(probed - rows)}


@pytest.mark.parametrize("actor", sorted(ACTORS))
def test_the_table_tells_the_truth(actor):
    ACTORS[actor]()
