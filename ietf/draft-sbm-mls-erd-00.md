---
title: "MLS-based Electronic Registered Delivery (SM-MLS)"
abbrev: "SM-MLS-ERD"
docname: draft-sbm-mls-erd-00
category: exp
ipr: trust200902
area: "Security"
workgroup: "Independent Submission"
keyword: [MLS, registered delivery, COSE, evidence, CBOR]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  -
    ins: P. De Rosa
    name: Paolo De Rosa
    organization: "European Commission, DG CONNECT"
    email: paolo.de.rosa@linux.com
normative:
  RFC2119:
  RFC8174:
  RFC9420:
  RFC9052:
  RFC8949:
  RFC8610:
  RFC3161:
  RFC8615:
  RFC8032:
informative:
  RFC9750:
  RFC7748:
  I-D.ietf-mls-pq-ciphersuites-06:
    title: "ML-KEM and Hybrid Cipher Suites for Messaging Layer Security"
    author:
      - name: R. Mahy
      - name: R. L. Barnes
    date: 2026-07-21
    target: "https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-06.html"
  EU-910-2014:
    title: "Regulation (EU) No 910/2014 (as amended by Regulation (EU) 2024/1183)"
    target: "https://eur-lex.europa.eu/eli/reg/2014/910/oj"
  TS-SBM-QERDS:
    title: "Binding of ERD messages and evidence to MLS-based secure messaging (SM-MLS) — QERDS binding (companion TS-shaped profile)"
  SBM-UMBRELLA:
    title: "Secure Business Messaging Profile (umbrella)"

--- abstract

This document is an **exploratory** specification. It defines SM-MLS, a binding
of the Messaging Layer Security (MLS) protocol (RFC 9420) that carries
application messages end-to-end encrypted while a Registered Delivery Provider
issues signed, timestamped evidence of submission, delivery, non-delivery and
refusal — without ever seeing the plaintext. It specifies the MLS binding
(group topology, credential mapping, cipher suites, Delivery Service mapping,
KeyPackage rules), the application envelope, payload hashing over the
transmitted octets (`raw`; the authoritative encoding is deterministic
CBOR per the CDDL, which is the profile's only canonicalisation),
the message flows and delivery states, and the COSE-based evidence packaging
with a strict sign-then-timestamp sequencing.
Regulatory and identity-framework material is referenced informatively so that
the wire protocol stands on its own.

--- middle

# Introduction

This document is an independent, exploratory technical study. It is **not** a
standards-track proposal and confers no status; the author's affiliation does
not make it a position of the European Commission or any other body.

Registered electronic delivery provides legal evidence of sending and receipt.
End-to-end encryption keeps intermediaries from reading content. These two
properties are usually treated as a trade-off. SM-MLS composes them: evidence
is built over a cryptographic digest of the content and over the MLS session
state, never over the content itself.

SM-MLS binds MLS {{RFC9420}} to a registered-delivery context. Application
messages are MLS PrivateMessages; the routing provider (a Messaging Service
Provider, MSP) fulfils the MLS Delivery Service role and sees only ciphertext
and metadata; a Registered Delivery Provider (RDP) observes evidenced events
and issues COSE_Sign1 {{RFC9052}} evidence objects.

The legal and conformance framing (qualified electronic registered delivery,
identity proofing, the ETSI EN 319 522 event model) is out of scope here and is
addressed by the companion QERDS-binding profile {{TS-SBM-QERDS}}; identifiers,
directory, roles and governance are in the umbrella profile {{SBM-UMBRELLA}}.
References to Regulation (EU) No 910/2014 {{EU-910-2014}} in this document are
**informative**.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

- **Entity**: a legal person (company or public-sector body) identified by a UID.
- **UID**: the canonical entity identifier (defined in {{SBM-UMBRELLA}}).
- **MID / device_id**: pseudonymous member/device identifiers within an entity.
- **WU**: Wallet Unit, an MLS endpoint on an entity's device.
- **MSP**: Messaging Service Provider; the MLS Delivery Service (RFC 9750).
- **RDP**: Registered Delivery Provider; issues evidence.
- **Evidence object**: SE/DE/NDE/RE/CE; **EP**: Evidence Package.
- **Seal**: the COSE_Sign1 the RDP applies to an evidence object.

# SM-MLS Binding

SM-MLS-1.0 binds MLS {{RFC9420}}, with the architecture of {{RFC9750}}, to the
Business Wallet messaging context.

## Group Topology

An MLS group represents a secure channel between two entities; its leaf nodes
are the devices/MIDs of both entities.

For a channel between Entity A and Entity B, a single MLS group contains all
active devices of A's and B's participating MIDs as leaf nodes. Because every
recipient device in the group can decrypt, role- and quorum-based acceptance
(see the umbrella BW-ORG document) operate at the MLS level.

When an entity publishes a confidentiality-scope map (umbrella §8.3a, advertised
via `BW-MED.mls.scopes_supported`), the topology generalises to **one MLS group
per (entity pair, scope)**: the leaves are only the devices of members holding
the scope's roles, plus a declared records leaf where `recoverability: records`.
The whole-pair group above is the reserved `default` scope, used when no scope
map is published, so scopes are backwards compatible. Each scope group's
`group_context` MUST carry the **`sbm_scope`** extension (below) identifying the
`scope_id` and the descriptor `version` in force; a member MUST reject a group
whose scope extension is inconsistent with the sender-resolved descriptor.

**The `sbm_scope` GroupContext extension (normative).** ExtensionType
**`0xF53B`**, from the RFC 9420 private-use range (0xF000–0xFFFF); should this
profile standardise, an IANA MLS-extension-type registration is the published
intent (additive — no wire change). TLS presentation syntax:

~~~
struct {
  opaque scope_id<V>;             /* UTF-8; 1..64 bytes */
  opaque descriptor_version<V>;   /* UTF-8; 1..32 bytes */
  opaque entity_uids<V>;          /* 0..16 UIDs, each opaque<V> */
} SBMScopeExtension;
~~~

`entity_uids` MUST be EMPTY in this profile version (bilateral only, D1 —
above); the field is retained for the multiparty future-study extension, where
it would list all participating entity UIDs, bytewise-ascending with no
duplicates. A receiver MUST reject a non-empty, unordered, duplicated or
oversize extension. **Presence**: EVERY SM-MLS group carries the
extension — the reserved `default` scope included (`scope_id` `"default"`,
version `"1"`) — so every group is self-describing. **Capability**: a member
MUST advertise `0xF53B` in its LeafNode `capabilities.extensions`, and the
GroupContext `required_capabilities` MUST include it, so a member that does not
support the extension cannot join silently (RFC 9420 §7.2/§11). **Lifecycle**:
`scope_id` is IMMUTABLE for a group — a scope change is a NEW group (the
topology rule above); a descriptor-version change is carried by a
GroupContextExtensions proposal + Commit; a ReInit re-asserts the extension
unchanged. The reference serializer is `scripts/mls_wire.py`
(`serialize_scope_extension` — it rejects what the wire forbids), and the D3
`mls_state` commitment covers the extension bytes: the scope binding of every
evidenced epoch is itself evidence-visible, and removing or altering the
extension changes `mls_state`. Confidentiality then
coincides with the role. The sender resolution flow, the roster-transparency
rule and the role lifecycle are specified in {{confidentiality-scopes}}.

**Bilateral only (normative, D1).** A group MUST contain the devices of
EXACTLY TWO entities. A group containing devices of three or more entities is
NOT CONFORMANT to this profile version and MUST be rejected — at creation, at
join, and by any verifier: the entire evidence, addressing, policy and
directory model is singular sender/recipient, and the registered-delivery
attribution argument identifies one sender and one addressee. *Future study:*
multiparty channels are recorded as a possible SPECIFIED extension (recipient
sets, per-recipient delivery state and evidence, policy composition, partial
failure, membership disclosure) — not current scope; this is why the
`SBMScopeExtension.entity_uids` field remains in the wire struct, bound EMPTY
in this profile (a non-empty list is the multiparty marker and MUST be
rejected).

**Channel identity and convergence (normative).** The logical channel
for a `(entity set, scope)` is identified by
`channel_id = SHA-256(dCBOR(["sm-mls:channel:v1", [sorted entity UIDs],
scope_id]))` — order-insensitive in the entity set, scope-sensitive, and
computable by either side with no coordination (reference:
`scripts/mls_channel.py`). Two MLS groups whose rosters span the same entity
set and whose `sbm_scope` extension names the same `scope_id` are the SAME
logical channel; a second group for an existing channel is a **duplicate**.
When a duplicate is detected — both entities created first-contact groups
concurrently, or simultaneous Welcome/Commit flows crossed — the group with
the **bytewise-smaller `group_id`** survives: a total order both creators
evaluate locally and identically, so convergence needs no election protocol.
The losing creator MUST close its group (Remove + Commit, or abandonment
where no Welcome was processed) and MUST NOT submit new messages on it.
**Migration is evidence-governed**: a message DELIVERED in the losing group
before convergence keeps its evidence (the group existed; its state history
remains verifiable per the retention rules); an ACCEPTED-but-undelivered
message on the losing group closes its chain with NDE `mls-group-invalid`
(consignment stage) — its SE's `mls_group_id` identifies the superseded
group — and the sender resubmits on the surviving group as a NEW submission
with a new `message_id` (the `duplicate-message-id` intake rule prevents
double acceptance, so no message is delivered twice, and none is silently
lost: every accepted message ends in exactly one DE or NDE).

Group lifecycle: the initiator creates the group and adds the counterparty's
devices via Add proposals using their KeyPackages, then Commits. Member changes
are Add/Remove/Update proposals followed by a Commit, advancing the epoch.
Entity departure removes all its leaf nodes, preserving forward secrecy toward
the departed entity.

## Credential Mapping

Each MLS leaf node presents a Credential. The routine online leaf credential
MUST be a derived/delegated device or member credential bound to the entity UID
and to an active member/device binding (the umbrella BW-MEMBER document). The
entity seal key (QSealC) authorises that binding at enrolment (offline) and
SHOULD NOT be the per-device online credential. Two realisations are defined.
Realisation (a) is the **mandatory baseline** that interoperability depends on;
realisation (b) is **OPTIONAL and experimental** and MUST NOT be presented as an
interoperable or conformant leaf credential:

(a) **Device/member certificate (baseline, MANDATORY).** MLS credential type
`x509` (registered value 2, {{RFC9420}}), carrying the entity UID and the MID /
`device_id`. The credential chains to the entity's QSealC through a **signed
device binding**, not by treating the QSealC as a CA: the QSealC is a qualified
seal certificate, not necessarily a CA certificate, so the entity's seal key
**signs a binding** over `(UID, MID, device_id, leaf-signature-public-key)` rather
than issuing a subordinate certificate. The BW-MEMBER document publishes this as
`devices[].mls_leaf_binding` (umbrella §8; `discovery_lint` LINT-DISC-23), a
COSE_Sign1 by the entity seal key over the deterministic-CBOR
`{uid, mid, device_id, leaf_sig_pubkey_b64}`. Preserving the RFC 9420 rule, the
first (leaf) credential key **MUST** equal the MLS LeafNode signature key: the
bound `leaf_sig_pubkey_b64` is the LeafNode signature key, and its SHA-256 **MUST**
equal `mls_leaf_node_ref.signature_key_hash`. An implementation **MUST NOT** admit
a leaf whose signature key differs from the bound credential key. The X.509
**certificate profile** for a delegated-certificate realisation — Basic
Constraints (a QSealC **MUST NOT** be accepted as a CA unless it is one), Key
Usage / EKU, name constraints, and revocation — and validation of the entity
QSealC chain to an EU Trusted List are **production-verifier** obligations, not
established by the reference tooling. *[**TODO(legal/PKI):** the normative X.509 certificate profile and the QSealC-qualification clause are an external-counsel / PKI item.]*

(b) **UID QEAA per device (OPTIONAL, EXPERIMENTAL).** The custom MLS credential
type `bw_uid_qeaa` ({{iana-considerations}}) carrying the SD-JWT-VC of the entity's
UID attestation with a member-binding claim (MID / `device_id`). Its MLS credential
type sits in the RFC 9420 private-use range (no allocated code point; agreed
bilaterally), and its wire embedding, its `cnf` binding to the MLS leaf signature
key, and the coupling of its status/revocation to the UID lifecycle are **NOT yet
specified**. It is experimental only; a conformance-claiming deployment uses (a).
*[**TODO(legal):** a normative UID-QEAA profile (embedding, cnf/leaf-key holder binding, status-list coupling to suspend/retire/merge, and the Article 43(2) interaction) requires an IANA MLS-credential-type allocation and external counsel.]*

Validation: the MLS Authentication Service function verifies that the
device/member credential attests or chains to the entity's QSealC / UID
attestation, is unexpired and unrevoked, that the UID matches the group
context, and that the MID / `device_id` is an active member/device binding.
An implementation MUST NOT admit a leaf whose credential is revoked or whose
member binding is not active.

## Cipher Suites

**Usable-suite selection and vector transition (N-03).** The creator selects
with `select_usable_suite` (reference `scripts/mls_suite.py`): the
highest-preference suite present in every member's capabilities AND backed by
an available KeyPackage of that suite for every added member — a
capability-supported suite with no matching KeyPackage is skipped. The
preference vector is a VERSIONED name (currently `mls-suite-preference/v2`,
which renamed one member of v1 and changed nothing else); a future
vector is a NEW name, named by the deployment companion contracts and
**pinned at group creation** — an existing group is never reinterpreted under
a later vector, and upgrading it is a ReInit performed under the new vector.

| Cipher suite | Status | Description |
|---|---|---|
| `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` | REQUIRED | Baseline (X25519 HPKE, AES-128-GCM, SHA-256, Ed25519). |
| `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` | RECOMMENDED | Hardware-holdable (P-256/ECDSA-P256, AES-128-GCM, SHA-256); RFC 9420 suite `0x0002`. The one suite every commodity secure element supports (Android StrongBox, Apple Secure Enclave, TPM 2.0), so the MLS leaf private key can be non-exportable and hardware-backed (MWAP §1). |
| `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` | RECOMMENDED | Higher-margin (P-384, AES-256-GCM, SHA-384, ECDSA-P384). |
| `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` | RECOMMENDED | Post-quantum hybrid (ML-KEM-768 + X25519), exactly as {{I-D.ietf-mls-pq-ciphersuites-06}} defines it and under its name. Code point **`0xF5C1` (private use)** — the draft's allocation is TBD and IANA has allocated none. |

All implementations MUST support the baseline suite. A group is created by one
member — the group creator (RFC 9420 §11) — which selects the group's cipher
suite from the intersection of all members' KeyPackage capabilities. To make that
choice DETERMINISTIC (two conforming creators pick the same suite from the same
capability sets, closing N3), selection follows a versioned total order, the
**preference vector `mls-suite-preference/v2`** (v1 differed only in the post-quantum suite's name), strongest-first:

1. `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` — post-quantum hybrid
2. `MLS_256_DHKEMP384_AES256GCM_SHA384_P384` — higher classical margin
3. `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` — hardware-holdable
4. `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — baseline / interoperability floor

The creator selects the highest-preference suite present in the intersection of
every member's advertised `cipher_suites`; the baseline is always in the
intersection, so a selection always exists. This order also resolves the conflict
between post-quantum resistance, classical margin and hardware-holdability: PQ
resistance ranks first (harvest-now-decrypt-later), then classical margin
(P-384 > P-256), with hardware-holdable P-256 above the baseline — so two devices
that can only hold a hardware leaf key (P-256 + baseline) still negotiate P-256.
**The cipher-suite floor (normative).** This paragraph used to
say a member *MAY* refuse to join a group whose selected suite is below its
*configured* floor — optional, unpublished, unverifiable, and ambiguous,
because the same advertised list also contains the mandatory baseline. Worse,
a floor each participant declares protects only the participants who declare
one, and a member that publishes nothing is exactly where a provider-induced
downgrade lands. The rule is now two-layer:

1. **A MANDATORY floor, `mls-suite-floor/v1`**, a versioned constant of the
   federation registry (`registries/cipher-suites.json`), binding on EVERY
   conforming deployment including one that publishes nothing, and evaluable
   with no discovery fetch — so two creators with the same capability sets
   always reach the same decision. A group whose selected suite is below it
   **MUST NOT be formed**, and a member offered one **MUST** decline the
   Welcome with the typed `suite-below-published-floor` outcome. That outcome
   is NOT an NDE: an NDE reports the fate of a MESSAGE, and at this point there
   is none — no `message_id`, no SE, no chain — so the registry stages it under
   `group-establishment`, not under the intake event `A.2-SubmissionRejection`
   where it was first placed.

   **How the refusal travels (normative).** Through the Delivery
   Service, as a `POST /welcome/{welcome_id}/refusal` authenticated by the
   refusing device's **KeyPackage credential**, bound to the Welcome it
   declines and naming the offered suite and the floor the device requires.

   *An earlier round said this refusal travelled as an authenticated MLS message to the
   group creator, on the reasoning that "the refusing device is already an
   invited member of the group being formed". **That was wrong, and it is the
   kind of wrong worth recording**: INVITED IS NOT JOINED. To send an
   authenticated message in the group, the device must process the Welcome and
   operate the key schedule under the very cipher suite it is refusing as below
   its floor — the transport required doing the exact thing the refusal exists
   to avoid. A device MUST NOT instantiate a suite it has rejected.*

   The DS is already in the path, already authenticates devices (`deviceAuth`),
   and the KeyPackage credential is the one thing the device demonstrably holds
   **before joining** — it is the credential that put the device into the group
   being formed. HPKE to a published creator key is cleaner cryptographically
   but adds a key-distribution problem in order to solve a reporting problem.

   A silent non-join is not an acceptable alternative: it is
   indistinguishable from an offline device, so the creator cannot tell a
   capability refusal from a delivery failure and the typed outcome becomes
   unreportable.

   **And it must REACH the creator (normative).** The previous rule put the
   refusal on the DS and it terminated there: the creator is not listening on
   the refusing device's queue, so nothing delivered the outcome to the only
   party that can act on it, and a silent non-join stayed indistinguishable
   from an offline device — the very thing the typed outcome exists to prevent.
   The creator **polls** `GET /group-establishment/outcomes`, symmetric to
   Welcome collection, and acknowledges each item explicitly so a lost response
   converges on retry. It is already an authenticated DS client, so this needs
   no new trust relationship; a DS-to-RDP push would create one.

   Serving an outcome REQUIRES the DS to retain a server-side **invitation
   record** — the authenticated creator, the target device, the group or
   GroupInfo commitment, the offered suite, the consumed KeyPackage reference
   and an expiry — so the refusal is validated against what was actually
   offered rather than against what the refusing device asserts. A deployment
   that does not retain it cannot serve the operation and **MUST NOT**
   synthesise outcomes from the refusal alone.

   `GroupEstablishmentRefusal-v1`, the standalone Schema introduced and
   later withdrawn, **stays withdrawn**: this outcome has to ARRIVE, not
   to be retained. It can be reintroduced deliberately if a refusal ever has to
   be retainable evidence.

   The floor is a versioned constant rather than a number in this prose so
   that raising it is a governance action with an audit trail.
2. **An OPTIONAL per-device raise**, `BW-MEMBER.devices[].min_cipher_suite`,
   which may only RAISE the mandatory floor and never lower it (a weaker
   published value is non-conformant, `discovery_lint` LINT-DISC-30). This is
   for the case the floor exists to serve: a device with materially stronger
   key protection must be able to demand more than the common minimum.

The floor in force for a group is the mandatory one raised by the strongest
raise any addressable device publishes. The creator **MUST** pin the selected
suite **and** that floor in the group-establishment state, so the decision is
evidence-visible rather than local configuration. **That state is the
`sbm_group_params` GroupContext extension, version 2 at
private-use type `0xF53D`**, carrying the preference-vector
identifier, the floor identifier and registry version, the effective floor,
the selected suite, the per-device raises that produced it, the formation
instant `formed_at`, and `inputs_digest`. Each raise names the device's whole
principal — entity UID, MID and device ID — because a MID is unique only
within an entity and a group spans two. `inputs_digest` is the SHA-256 of the
deterministic CBOR of the exact formation inputs: both entities' BW-MEMBER
documents and each addressable device's KeyPackage availability at formation.
A verifier **MUST** recompute the decision only from retained inputs matching
that digest; without them the decision is INCOMPLETE and **MUST NOT** be
recomputed from current data, because a later raise would invalidate a
correct decision and a later lowering would erase a violation. Version 1
(`0xF53C`) named a raise by MID and device ID alone and bound no inputs: it is
decoded for history, never produced, and a version-1 decision is reported
INCOMPLETE. The extension sits beside `sbm_scope` and
`required_capabilities` lists it, so a member that cannot read the pinned
decision does not join silently. Because `mls_state` already commits to the
GroupContext, the pin is **evidence-visible with no further machinery** —
before the extension existed this paragraph's requirement was met by no schema, no API object,
no evidence field and no extension, and the conformance test asserted only that
this sentence existed. A member **MUST NOT**
silently accept a suite weaker than it advertised. A suite change for an existing group is a ReInit, which creates a
NEW group under the same rule. The PQ hybrid is RECOMMENDED, and already
ranks first. **It does not become REQUIRED automatically when an external
document is published** — this text used to say it would, "rising to rank 1",
when it held rank 1 already and when an external event cannot change what a
deployed verifier accepts. Elevation, and the move from the
private-use code point `0xF5C1` to whatever value IANA allocates, are each a
**new revision of this profile's cipher-suite registry**, taken deliberately.
Groups formed under `0xF5C1` keep it (changing a group's suite is a ReInit,
which forms a new group), and a verifier resolves a retained group under the
registry revision it was formed under — its wire values included.
Revision 1 published no wire values, so a revision-1 group resolves only
IANA-allocated code points; one claiming any other value (such as `0x004D`,
which existed only in reference code) is unverifiable and reported INCOMPLETE,
never decoded by a later revision's map. No revision defines `0x004D`, so it
remains unusable for new groups. The pinned revision is
{{I-D.ietf-mls-pq-ciphersuites-06}}; any intentional deviation from it would be
listed here, and there is none. That draft publishes no test vectors, and no
cross-implementation vector exists for the hybrid KEM: this profile's vectors
cover only what it defines for the suite (`samples/cipher-suite-vectors.json`). A reference selector is `scripts/mls_suite.py`.

The `0x0002` (P-256) suite is admitted for **hardware-holdability, not
cryptographic margin**: it sits *below* the P-384 higher-margin suite in the
assurance ordering, and is offered so that a device whose secure element is a
P-256 element — Android StrongBox, the Apple Secure Enclave, TPM 2.0 — can hold
its MLS **leaf** signature key in hardware, non-exportable and key-attested, which
is otherwise impossible under an Ed25519-only leaf on those platforms. It is
therefore **not** a downgrade of the baseline: the baseline stays REQUIRED and
remains the interoperability floor, negotiation selects the strongest mutually
supported suite, and both P-256 mechanisms (ECDH-P256 key establishment, ECDSA-P256
signature) are ACM-agreed (the TS [TS], clause 5.3). A deployment that enrols no
P-256 device is unaffected.

## MLS Delivery Service Mapping

The MSP fulfils the MLS Delivery Service role ({{RFC9750}}):

- The MSP MUST implement DS functions: queuing, handshake-message ordering
  within a group, and KeyPackage distribution.
- The MSP MUST NOT have access to plaintext Application message content.
- The MSP MAY observe metadata (sender/recipient UIDs, group id, size, times).
- The MSP MUST expose a KeyPackage retrieval endpoint for the entity's devices.

## KeyPackage Rules

B2B entities are not always online; asynchronous group creation uses KeyPackages
({{RFC9420}}, Section 10).

- Each active device MUST publish at least one KeyPackage and MUST maintain a
  pool of at least ten unused single-use KeyPackages. Confidentiality scopes
  ({{confidentiality-scopes}}) create one group per (entity pair, scope), so a
  device that participates in several scopes is added to several groups and its
  KeyPackage consumption grows accordingly; such a device SHOULD size its pool
  as roughly (peers × active scopes it joins) with margin for replenishment
  latency. MLS and the Delivery Service handle the additional groups natively.
- KeyPackages MUST be single-use: the MSP MUST remove a consumed KeyPackage,
  MUST NOT serve it again, and MUST notify the device to replenish. A device
  MAY additionally publish a single **last-resort** KeyPackage; its use MUST
  trigger immediate rotation of the device's leaf key.
- Replay: the MSP MUST reject any reuse of a consumed single-use KeyPackage;
  the recipient MUST reject a Welcome built on a KeyPackage it did not publish
  as current. A detected reuse MUST raise an alarm and SHOULD be evidenced as
  NDE with reason `keypackage-replay`.
- KeyPackages MUST carry a credential ({{credential-mapping}}); at group
  creation and on every Add the credential and its `kid` MUST be cross-checked
  against the current directory record.
- **Per-suite pools (N-03).** The Delivery-Service KeyPackage pool is
  partitioned **per cipher suite**: a KeyPackage pins ONE `cipher_suite`, so a
  pool advertisement MUST carry per-suite availability counts, and a
  reservation request MUST name the suite (the reserve→commit machinery is
  suite-filtered). A creator MUST select via the usable-suite rule (*Cipher
  Suites*): a suite is selectable only where an unused, unexpired KeyPackage
  of that suite exists for EVERY member being added — capability support
  alone never suffices. Where no suite is usable, establishment fails typed:
  the sender-facing outcome is NDE `keypackage-pool-exhausted`.
- The KeyPackage `lifetime` extension MUST be set; the profile bound on maximum
  validity is stated in {{TS-SBM-QERDS}}.

# Application Envelope

The application payload is the `application_data` of an MLS PrivateMessage. The
envelope carries: `message_id` (globally unique; UUIDv7 or ULID RECOMMENDED),
`correlation_id` (OPTIONAL), `ttl`, `content_type`, `content_class` (OPTIONAL),
`content_digest` (per {{canonicalisation-and-payload-hashing}}),
`sender_addr` / `recipient_addr`, and `grade_commitment_salt` (OPTIONAL). `content_class` is drawn from the
two-tier content-class registry ({{iana-considerations}}) — federation-governed
standard classes plus `x-`-prefixed entity-defined private classes — and is
used to select a confidentiality scope ({{confidentiality-scopes}}); it
is not echoed in evidence (the resolved `scope_ref` is). `content_digest` is
the **same hash object as the evidence `payload_hash`** — `{alg, hex,
hash_mode}`, under the coherence rules of
{{canonicalisation-and-payload-hashing}} — and the envelope `content_digest`
and the evidence `payload_hash` for the same message MUST be equal: that
equality is what the recipient's re-verification re-checks. `ttl` is an
integer count of seconds from submission after which the message expires
({{error-handling-and-retries}}), bounded by the recipient MED's
`policy.ttl_max_s` where published. `grade_commitment_salt` is present exactly when the
message's content class is availability-declared (umbrella §8.3b): 16 bytes of
cryptographically random, fresh per-message salt, lowercase hex, input to the
grade commitment ({{grade-commitment}}); it MUST NOT leave the encrypted
envelope except by deliberate reveal. A JSON Schema for the envelope headers is
provided as `schemas/envelope.schema.json` (v1.1). The header fields are
serialised as a JSON object prepended to the payload within the MLS application
data, separated by a null byte (0x00). MLS encryption protects both headers and
payload.

Multipart messages are bound via the manifest ({{canonicalisation-and-payload-hashing}}); evidence
binds to the manifest digest. A very large single part MAY be chunked, in which
case that part's manifest `digest` is the Merkle root over its chunks.

# Canonicalisation and Payload Hashing

**Authoritative encoding.** The COSE_Sign1 is the authoritative artefact; its
payload is the deterministic-CBOR (RFC 8949 §4.2) encoding of the body, defined
in the CDDL (`cddl/sm-mls-erd.cddl`, {{cbor-structure-definitions-cddl}}); the
JSON is a non-authoritative projection — `decode(payload)`. This applies to the
evidence signed payload and to the recipient confirmation signature. Two
conforming implementations MUST produce byte-identical output for that encoding;
`json.dumps`-style approximations (which differ in key ordering, string escaping
and number serialisation) are NOT the authoritative form. Payload hashing is
over the transmitted octets (`raw`, below), and deterministic CBOR is the
profile's only canonicalisation: a digest is a property of the bytes that
travelled, never of a re-serialised structure, so a verifier keeps those bytes
rather than re-deriving them.

**Restricted data model (I-JSON, safe integers).** Every canonical byte-string
in this profile is I-JSON {{!RFC7493}} under the following constraints, which
close the number-domain hazard that is the principal objection to JSON
canonicalisation:

- **Integers only, within the safe range.** No floating-point numbers, and no
  integer outside `[-(2^53-1), 2^53-1]`. JSON/ECMAScript represents numbers in
  IEEE-754 binary64, in which integers above `2^53-1` are not all exact — so a
  large integer on the wire cannot be round-tripped reliably. This is checked by
  `evidence_lint`/`discovery_lint` (LINT-PKG-09).
- **Large counters are decimal strings.** Values whose defined domain exceeds
  the safe range are carried as decimal strings (no leading zeros), not numbers.
  In particular `mls_epoch` is a `uint64` (MLS, RFC 9420) and MUST be a decimal
  string; the multipart manifest `length` is likewise a decimal string. Small
  bounded counters (`ttl`, `leaf_index`, `ttl_max_s`, `max_payload_kb`) remain
  integers with an explicit `maximum` within the safe range.
- **Duplicate object keys are rejected.** A conforming parser MUST reject an
  object with a repeated key rather than silently keeping one value; a duplicate
  key is a canonicalisation ambiguity and a signature-wrapping vector
  (LINT-PKG-10).
- **Unicode is pinned.** Canonical byte-strings are well-formed UTF-8 with no
  byte-order mark and no unpaired surrogates; object keys are drawn from the
  printable-ASCII field names fixed by the schemas. No field in any schema is
  typed `number`.

These constraints are a property of the data model, not of any one encoder: they
hold for the authoritative deterministic-CBOR form (RFC 8949 §4.2,
{{cbor-structure-definitions-cddl}}), which is the only form this profile
signs or hashes a structure in.

`hash_mode` is **`raw` over the transmitted octets** for every content type:
the recipient receives the sender's exact bytes inside the MLS envelope and
re-hashes them, so no divergence is possible. Signing the bytes you transmit is
the mainstream position, and every mode below follows it — a multipart digest
binds each part's own octets through the manifest.

- **Mode A — default (`raw`)**: SHA-256/512 over the payload's transmitted bytes;
  `hash_mode` = `raw-sha256` (or `raw-sha512`). Applies to JSON and non-JSON
  content alike.
  An application that stores a JSON payload parsed and re-serialised, its
  original octets gone, cannot recompute the digest and MUST retain those
  octets: that is the same rule every other artefact in this profile follows.
- **Mode C — multipart**: build a **manifest** (an ordered list of parts, each
  `{part_id, role, media_type, length, digest}`, `digest` over the part's
  decoded octets), encode it as a **deterministic-CBOR** fixed-position array
  (RFC 8949 §4.2), then SHA-256/512; `hash_mode` = `manifest-sha256` (or
  `manifest-sha512`):

~~~ cddl
manifest-def  = [ + manifest-part ]
manifest-part = {
    part_id: tstr,        ; ^[A-Za-z0-9._-]{1,64}$
    role: "body" / "attachment" / "evidence-bundle" / "signature" / "metadata",
    media_type: tstr,
    length: decimal-str,  ; the part's decoded-octet length, as a decimal string
    digest: hash,         ; { alg, hex } over the part's decoded octets
    ? filename: tstr,
}
~~~

  Unlike the seal and the commitments, this digest is **not statically checkable
  by the reference linter**: the parts are end-to-end encrypted and absent from
  evidence, so only a party holding the plaintext parts can recompute the
  per-part digests and hence the manifest digest. The linter checks the manifest
  *structure* (order, uniqueness, roles — LINT-MAN-01/02) but not the digest
  value.

Manifest rules: `part_id` MUST be unique and match `^[A-Za-z0-9._-]{1,64}$`; the
manifest MUST be in byte-wise ascending `part_id` order; duplicate `part_id` is
forbidden; `role` is from {`body`, `attachment`, `evidence-bundle`, `signature`,
`metadata`}; digests are over decoded octets (permitted content encodings
`identity`, `gzip`); nesting is at most one level.

`hash_mode` is REQUIRED in every evidence object and MUST be consistent across
all evidence for the same message. Every hash object MUST be internally
coherent: SHA-256 iff a `*-sha256` mode iff 64 lowercase hex chars; SHA-512 iff
a `*-sha512` mode iff 128.

**Every defined mode is mandatory to implement.** A receiver MUST implement
every `hash_mode` this profile defines: `raw-sha256`, `raw-sha512`,
`manifest-sha256` and `manifest-sha512`. The mode is chosen by the sender per
message; it is not negotiated, and no discovery document advertises which modes
a party supports. A receiver that met a mode it had not implemented could
neither recompute `payload_hash` nor say that it had not: a `mismatch`
confirmation asserts a comparison that was made, and this profile defines no
reason for one that was not. The profile therefore carries no mode that is
optional to implement, which is also why the JSON-canonicalisation modes were
removed in September 2026 rather than left optional — an option no party can
advertise and no party can refuse is not optional, it is an obligation the
specification failed to state.

**Recipient re-verification.** The SE `payload_hash` is computed by the sender
over the plaintext and cannot be verified by the RDP. The recipient wallet MUST
recompute `payload_hash` over the decrypted plaintext before acknowledging; DE
MUST carry the same `payload_hash`. On mismatch the recipient MUST NOT confirm
a match; it delivers a `mismatch` confirmation — its proof — and the RDP MUST
issue NDE `payload-hash-mismatch` embedding that proof instead of DE. Silence is
never a mismatch: without a confirmation the outcome at expiry is NDE `expired`. In
that NDE the top-level `payload_hash` is the sender/SE hash and
`recipient_confirmation.payload_hash` is the recipient-recomputed hash; the two
MUST differ.

**Confirmation object.** The recipient wallet produces a confirmation object
bound to `(message_id, mls_group_id, mls_epoch, acceptance_policy_ref,
payload_hash, result, verified_at)`, either signed (`wallet_signature_b64`) or
session-authenticated (`session_authenticated`); at least one proof is REQUIRED.
When signed, `wallet_signature_b64` is a COSE_Sign1 whose payload is the
deterministic-CBOR (RFC 8949 §4.2) encoding of the confirmation object with the
signature field removed — not a field subset — so it covers every bound field at
once; its COSE `alg` MUST be in the allowlist of
{{evidence-objects-and-cose-packaging}}. On a match it is carried as DE
`s3_attestation` (`result`=`match`); on a mismatch as NDE `recipient_confirmation`
(`result`=`mismatch`).

# Grade Commitment

**Dispute proof.** A grade-mismatch dispute (GCM-v1) MUST carry a
recipient-produced `reveal_confirmation` — the disputing device's wallet
signature over the full dispute tuple, verified against the device's
published key as of `read_at`. Commitment inequality alone MUST NOT be
treated as proof of anything: a party that invents a salt produces
inequality trivially. The confirmation establishes an ATTRIBUTABLE RECIPIENT
ASSERTION, not extraction from the ciphertext — see {{TS-SBM-QERDS}} clause 6
for the scope statement and the future-work construction.

Availability-grade delivery (umbrella §8.3b) is lawful only for content
classes the recipient has declared — but `content_class` is deliberately never
echoed in evidence. The **grade commitment** closes that gap without opening
the privacy one: availability-grade evidence carries a salted commitment that
any verifier can check after a deliberate reveal, so verifiability does not
rest on issuer honesty.

**Construction.** With `salt` the envelope's `grade_commitment_salt` (16
random bytes, fresh per message, as 32 lowercase hex characters) and
`org_digest` the `acceptance_policy_ref.doc_digest.hex` of the referenced
BW-ORG (the SHA-256 of its deterministic-CBOR body, `hash_mode` `raw-sha256` —
content-addressed and reseal-stable):

The input is a **deterministic-CBOR fixed-position array** (RFC 8949 §4.2), not
JSON — a typed, domain-separated construction any party recomputes from a reveal
with a CBOR encoder (already required for COSE) and no key-ordering, number or
parser ambiguity:

~~~ cddl
grade-commitment-input = [
    "sm-mls:grade-commitment:v2",   ; tstr, domain-separation tag, element 0
    salt,                           ; bstr .size 16  (grade_commitment_salt, hex-decoded)
    content_class,                  ; tstr           (the envelope content_class)
    "availability",                 ; tstr           (grade)
    org_digest,                     ; bstr .size 32  (doc_digest.hex, hex-decoded)
]
grade_commitment = lowercase-hex( SHA-256( dCBOR(grade-commitment-input) ) )
~~~

The array positions are fixed by this specification; `salt` and `org_digest` are
byte strings (the hex values decoded), the rest are text strings. The `dst`
suffix records the construction version; the on-wire disambiguator is the
evidence `version` — `>= 1.18` selects this v2 dCBOR construction, while `<= 1.17`
used `SHA-256(JCS({dst, salt, content_class, grade, org_digest}))` with the hex
strings verbatim. Any change to this construction bumps the `dst` suffix and the
evidence `version`.

**Duties.** The sender wallet computes the commitment (it alone knows
`content_class`) and supplies it with the submission metadata; the RDP echoes
it verbatim into SE (`grade_commitment`) and into the availability-grade DE,
and MUST NOT issue an availability-grade DE without one
({{TS-SBM-QERDS}}, clause 6). The recipient wallet MUST recompute the
commitment upon decryption and treat a mismatch as a dispute ground — the DE
is issued at authenticated S2, so recipient verification is post-delivery; its
remedy is the reveal, not a delivery block. The reveal procedure — either
party disclosing `(salt, content_class)`, any verifier recomputing against the
referenced BW-ORG version and checking the class maps to `availability` — is
specified in {{TS-SBM-QERDS}}, clause 6.

# Mandate Commitment

An agent (system member, umbrella Annex R) acts under a scoped mandate, but
`content_class` is never echoed in evidence — so without a commitment a verifier
cannot show the agent's message fell within the mandate's authorised class scope
(the same gap the grade commitment solves for availability). The **mandate
commitment** closes it: an **opposable** agent SE carries a salted commitment
any verifier can check after a deliberate reveal.

**Construction.** With `salt` the envelope's `mandate_commitment_salt` (16 random
bytes, fresh per message, 32 lowercase hex), `mandate_id` the `SE.mandate_ref.id`
(the acted-under mandate), and `org_digest` the `acceptance_policy_ref.doc_digest.hex`
of the referenced BW-ORG:

The input uses the same deterministic-CBOR fixed-position array as the grade
commitment ({{grade-commitment}}):

~~~ cddl
mandate-commitment-input = [
    "sm-mls:mandate-commitment:v2", ; tstr, domain-separation tag
    salt,                           ; bstr .size 16  (mandate_commitment_salt, hex-decoded)
    mandate_id,                     ; tstr           (SE.mandate_ref.id)
    content_class,                  ; tstr           (the envelope content_class)
    org_digest,                     ; bstr .size 32  (doc_digest.hex, hex-decoded)
]
mandate_commitment = lowercase-hex( SHA-256( dCBOR(mandate-commitment-input) ) )
~~~

The `dst` suffix records the construction version; the on-wire disambiguator is
the evidence `version` (`>= 1.18` selects v2 dCBOR; `<= 1.17` used
`SHA-256(JCS({dst, salt, mandate_id, content_class, org_digest}))`). Any change
bumps the `dst` suffix and the evidence `version`.

**Duties.** On an **opposable** agent SE (`mandate_ref.opposable` true or absent)
the sender wallet computes the commitment and the RDP echoes it verbatim into
`SE.mandate_ref.mandate_commitment`; it MUST be present and well-formed
(`evidence_lint` LINT-DE-15). Where `mandate_ref.opposable` is `false` the SE
carries **no** commitment, and its mandate-scope conformance is then establishable
only by internal audit, payload reveal, or the dispute path — never by external
verification. The reveal procedure — either party disclosing `(salt,
content_class)`, any verifier recomputing against the referenced BW-ORG version
and checking the class is **in the mandate's scope** (`BW-MEMBER.mandate_ref.scope`)
— is specified in {{TS-SBM-QERDS}}, clause 6; an out-of-scope reveal is provable
agent overreach.

# Confidentiality Scopes

A confidentiality scope lets the confidentiality boundary coincide with a role:
only members holding the scope's roles, on their enrolled devices, can decrypt
the content classes designated for that scope. The profile is fully functional
with the default scope alone; confidentiality scopes are an OPTIONAL, advanced
capability, backwards compatible — the reserved `default` scope is the
pre-scope behaviour. An entity
advertises support via `BW-MED.mls.scopes_supported` and publishes descriptors
in its signed BW-ORG scope map (umbrella §8.3a). The descriptor `version` in
force at submission governs the message and is echoed in evidence as `scope_ref`
({{evidence-objects-and-cose-packaging}}).

## Sender Resolution

To send a message the sender's wallet:

1. resolves the recipient's scope map from the recipient BW-ORG;
2. selects the scope whose `content_classes` include the message's
   `content_class` (Application Envelope);
3. if no scope matches, falls back to the `default` scope **if and only if** the
   recipient map declares `fallback: default` (map-level or on a matched scope
   descriptor); otherwise the submission MUST be refused with the reason
   `no-matching-scope` ({{iana-considerations}}). A silent fallback to `default`
   MUST NOT occur;
4. fetches KeyPackages for the eligible devices only — the union of the two
   entities' scope-eligible devices (each entity applies its own scope map to
   decide which of its members' devices join), the eligible set of each entity
   resolved via its member-enumeration surface (umbrella §8.3a, BW-ORG
   `member_endpoint` → the EDD resolver `GET /uid/{uid}/members`) — and creates
   or reuses the (pair, scope) group.

A message whose `content_class` is not listed by the group's scope descriptor
MUST NOT be sent in that group; a party that detects such a mismatch emits
`scope-violation` ({{iana-considerations}}).

### Cross-organisation scope agreement

A scope descriptor lives in one entity's BW-ORG `scope_map`, so the two entities'
maps must be reconciled deterministically. The (entity pair, scope) group is
keyed by the **recipient's** scope selection: the recipient's `scope_map` selects
the scope whose `content_classes` include the message's `content_class`, and the
resulting `scope_id` keys the group and governs delivery — the acceptance policy
evaluated within the scope and the roles that gate the recipient-side leaves. A
sender that **also** publishes a `scope_map` MUST route the same `content_class`
to the **same** `scope_id`; if the two maps route it to different `scope_id`s the
sender MUST refuse with `scope-violation` rather than form an ambiguous group —
routing is deterministic and there is no precedence. A **default-only sender**
(no `scope_map`, or `BW-MED.mls.scopes_supported` false or absent) contributes
**all active enrolled devices of the sending member** (the author member's
devices per its BW-MEMBER, under the same leaf-binding checks) to the
recipient-keyed group and applies no sender-side scope filter — multi-device
continuity is the member's: every device of the author member can
decrypt the thread and reply. Each entity's leaves are verified against **its own** scope
descriptor's roles, resolved from its own signed BW-ORG and its own member set
(member-enumeration surface, umbrella §8.3a): the recipient's leaves against the
recipient descriptor, and — where the sender is scoped — the sender's leaves
against the sender descriptor for the same `scope_id`.

**Sender multi-device continuity (normative).** The sending MEMBER'S
active enrolled devices — not only the authoring device — are members of the
group: replies and thread history are available on every device of the
member, and **loss of the authoring device has a defined recovery outcome**:
the member's remaining devices retain access, and a replacement device joins
through the existing device lifecycle (BW-MEMBER republication, then
Add + Commit). Device revocation is reflected by the existing role-lifecycle
rule (MLS Remove + Commit on the re-published BW-MEMBER). A scoped sender's
devices are additionally gated by its own scope descriptor (above).
**Sender-side leaves NEVER count toward the recipient's acceptance policy**:
the counting unit of acceptance is the recipient-side distinct active member
(the umbrella profile; the evaluator-of-record rule) — a sender device's
acknowledgement satisfies nothing.

## Roster Transparency — No Invisible Access

**Atomic snapshot.** The member-enumeration surface is a
non-authoritative mirror; the ATOMICITY anchor is the entity's signed
**ROSTER-v1** snapshot per evidenced (group, epoch): its signature attests
COMPLETENESS, its `member_doc_digest`s pin the exact sealed BW-MEMBER
versions in force, and its `tree_hash` MUST equal the ratchet-tree hash
inside the retained GroupContext that the evidence `mls_state` commits to —
enumeration ↔ tree ↔ evidence, one chain (the umbrella profile owns the
publication duty; the EDD contract serves it current and as-of).

MLS makes group membership visible to members. Before sending, the sender's
wallet MUST verify that the group roster is consistent with the resolved scope
descriptor:

- every leaf is a device of a member holding one of the roles of **that leaf's
  own entity's** scope descriptor (each entity applies its own registry), or is
  the declared records leaf;
- a records leaf is present **if and only if** the descriptor declares
  `recoverability: records`; the descriptor's `records_role` (umbrella §8.3a)
  names the organisation role whose active members are the records leaf, and its
  presence is evident in the roster by resolving the leaf to its member and roles
  via the member-enumeration surface (the records leaf's member holds the scope's
  `records_role`);
- under `recoverability: strict` no records or other non-role leaf is present.

A `recoverability: records` scope's roster is therefore exactly the union of the
devices of the scope-role holders and the devices of the `records_role` holders,
with no other non-role leaf; the `records_role` holders **recover but are not an
acceptance party** (acceptance counts scope-role holders only, {{TS-SBM-QERDS}}).

To perform this check the wallet resolves each group leaf to its member and
roles via the entity's member-enumeration surface (umbrella §8.3a, BW-ORG
`member_endpoint` → the EDD resolver `GET /uid/{uid}/members`), verifying each
resolved member against its individually sealed BW-MEMBER (the enumeration is a
non-authoritative mirror; the seal is the trust anchor).

If the roster is inconsistent with the descriptor the wallet MUST NOT send. The
audience of a role-scoped message is therefore *verified, not merely declared*:
there is **no invisible access** — every device that can decrypt is visible in
the MLS roster. This is a normative obligation on sending wallets and is what
keeps the extension honest.

Verifying the **full** roster requires both entities' inputs: a verifier resolves
each entity's scope descriptor from its signed BW-ORG `scope_map` and each
entity's members/roles/device-leaf references from its member-enumeration surface
(umbrella §8.3a), then checks every group leaf against the descriptor of the
entity that leaf belongs to. A sending wallet MUST at minimum verify the
**recipient-side** leaves against the recipient descriptor before sending —
*recipient-side confinement*, the check that protects the sender's content by
ensuring only authorised recipient devices can decrypt. A **scoped sender** MUST
additionally verify its own leaves against its own descriptor; a recipient or an
external verifier verifies the full symmetric roster. In the profile-1 / pilot
case of a default-only sender to a scoped recipient, recipient-side confinement
is the whole obligation, because the sender contributes the author member's own
devices (verified against its BW-MEMBER) and there is no sender-side
scope descriptor to gate them against.

## Role Lifecycle

Scope membership follows the entity's signed BW-MEMBER bindings (umbrella §8.4).
Granting a role adds the member's devices to the relevant scope groups via Add
proposals followed by a Commit; revoking a role removes them via Remove + Commit,
so the removed member cryptographically loses access to **future** messages in
the scope. Messages already delivered to a device before removal are an
endpoint-governance matter — the content is already on the device — not a
property this protocol can revoke. A BW-MEMBER binding change is the
authoritative trigger for the corresponding Add/Remove + Commit.

## Scoped-Group Lifecycle (Informative)

Naively, scopes multiply groups — pairs x scopes — and a deployment that
pre-created every combination would not scale. The intended lifecycle keeps the
population proportional to actual traffic:

- **Lazy creation.** A (pair, scope) group is created on the FIRST message that
  routes to that scope for that counterparty ({{sender-resolution}} defines the
  resolution; {{mls-group-creation-sequence-informative}} the sequence). No
  message, no group: a published scope map costs nothing until it is used.
- **Idle expiry and archival.** A group with no traffic MAY be closed after an
  operator-defined idle period: the members commit a final epoch, the MSP stops
  serving its KeyPackage bindings, and the wallets retain their local message
  history (evidence remains valid indefinitely — it binds to digests and session
  state, not to a live group).
- **Renewal.** Re-contact after expiry simply re-runs lazy creation with fresh
  KeyPackages ({{keypackage-rules}}); the scope descriptor `version` in force at
  the new submission governs it. No state from the expired group is needed.
- **Role changes.** Handled by the normative rules of {{role-lifecycle}} (Add/
  Remove + Commit per binding change) — a role change touches only the scope
  groups whose descriptors list the role, not the default group.
- **Inactive counterparties.** A counterparty that never messages a scope never
  joins its groups; scope maps published towards thousands of potential peers
  create no per-peer state until first contact.

The normative anchors are unchanged and referenced above: this subsection only
describes the intended operational pattern.

# Message Flows and Delivery States

An informative end-to-end sequence for the four-corner (federated) case —
resolution through evidence verification, verification-grade with the
digest-mismatch branch — is provided as a Mermaid source at
`docs/diagrams/federated-flow.mermaid` in the specification repository. It is
illustrative; this section and {{TS-SBM-QERDS}} (clauses 4.1, 6) are normative.
The relay evidence it shows (B.1/B.2/B.3) is the profile-2 four-corner target
({{TS-SBM-QERDS}}, four-corner relay requirements), not exercised by the
single-provider profile-1 deployment.

## First Contact

The sender wallet resolves the recipient UID, fetches the recipient devices'
KeyPackages, creates the MLS group (adding both parties' devices), and Commits;
the MLS handshake performs the cryptographic mutual authentication. Welcome
messages are queued by the recipient MSP for the recipient devices, which verify
credentials and join.

## Delivery

The sender computes the digest, encrypts the envelope and payload as an MLS
PrivateMessage, and submits it to the MSP; the sender-side RDP issues SE. The
message is relayed and queued; recipient devices decrypt. DE is issued at state
S4 with S3 as a precondition (see below).

## Non-delivery and Refusal

Non-delivery (expiry, unreachable recipient, invalid group, digest mismatch)
produces NDE with a reason code. Explicit decline produces RE. Reason codes are
a closed, extendable set (registry policy in {{iana-considerations}}).

## Delivery State Model

A recipient-status suspension HOLDS an in-flight message rather than
terminating it (the umbrella profile): the S1–S4 progression pauses —
no legal-effect event may occur while the suspension lasts — and resumes on
reactivation; the authenticated deadline (`expires_at`, SE) is the only
clock that terminates a held message. The hold is a **gating condition on
transitions**, not an additional state.

Recipient-side delivery progresses through four states; an implementation MUST
NOT conflate them.

- **S1 — available to the recipient provider** (accepted into the MSP queue).
- **S2 — acknowledged handover to the recipient device** (the message
  bytes were TRANSFERRED to an enrolled leaf within an authenticated session
  and the session transport ACKNOWLEDGED the receipt — one exact event, below).
- **S3 — decrypted and verified** (an authorised member/device decrypted and
  re-verified `payload_hash` in an authenticated session).
- **S4 — accepted under policy** (the entity's `acceptance_policy` is satisfied).

Normative rules:

- S1 MUST NOT trigger DE. S2 MUST NOT trigger DE except under the
  authenticated-S2 availability rule below. S1/S2 MAY be recorded as
  non-operative **state records** in `EP.states[]`; these are unsealed, carry
  no legal effect, and MUST NOT contain any delivery-establishing field.
- **Availability grade (declared only).** Where the recipient's signed BW-ORG
  in force at submission declares the `availability` grade for the message's
  content class (umbrella §8.3b), DE is issued at **authenticated S2**, which is
  ONE exact event — the **acknowledged handover**: the message bytes
  are TRANSFERRED to a device that (a) is an enrolled MLS leaf of the
  message's group and (b) acts within a session authenticated by the
  recipient's provider ({{TS-SBM-QERDS}}, clause 6), AND the session
  transport acknowledges the receipt. The Delivery-Service **receipt
  acknowledgement** is the protocol proof of the event and MUST be retained
  for the evidence-retention period.

  **The event instant is SERVER-OBSERVED (normative).** The DS
  observes the ack instant; a client-supplied timestamp MUST NOT determine
  it. Where the device sends one it is **non-authoritative** diagnostic
  metadata, retained for skew measurement only. Otherwise a device — or a
  compromised entity session — could acknowledge after `expires_at` while
  backdating into the valid window, defeating the deadline rule below and
  the authenticated-S2 proof that rests on it. The DS MUST authenticate the
  acknowledging **device** for this operation: an entity- or member-level
  credential does not satisfy it, since the event asserts that a particular
  DEVICE received the bytes.

  **The signed receipt and its forwarding (normative).** The DS MUST
  return, and forward to RDP(out), a **signed receipt** binding
  `(message_id, recipient_uid, mid, device_id, session_binding, server_time,
  message_digest)`, where `message_digest` is the transmitted-octet
  commitment over the exact MLSMessage handed to the device — the same
  commitment RDP(out) computed at submission. Before issuing the DE, RDP(out)
  MUST verify the receipt's signature against the DS's published key and
  MUST verify that `message_digest` equals the commitment it submitted; an
  unverifiable receipt yields NO DE.

  **Which key, and when (normative).** "The DS's published key"
  had no referent: no field, endpoint, identifier, history or rollover was
  defined anywhere, so the signature was unverifiable, pinned by private
  configuration, or open to ambiguous substitution. The receipt therefore
  carries `ds_kid` and `ds_alg`, and the DS operator publishes
  `ds_receipt_keys` in its **signed BW-MED** — an object already retained for
  the evidence period, so no new rotation, history or retention machinery is
  introduced for one key. RDP(out) resolves `ds_kid` there and MUST reject an
  unknown identifier, a **duplicated** identifier (the ambiguity the
  identifier exists to remove), or an algorithm that disagrees with the
  published key's. **Validity is evaluated at the receipt's own
  `server_time`, not at verification time** — that is what keeps a receipt
  verifiable after the key that signed it has been rotated out; evaluating it
  at verification time would expire the evidence along with the key. Windows
  are half-open, as elsewhere in this profile. The receipt's `server_time` is
  the **S2 instant**. It is `delivered_at` at the **availability** grade only; at
  the verification and acceptance grades the receipt proves S2 and the delivery
  instant is the completing confirmation ({{timing}}). An
  authenticated session whose queue merely HOLDS the message is NOT S2 and
  MUST NOT yield a DE — availability-without-transfer is explicitly not the
  selected semantics. **Duplicates and replay:** the FIRST acknowledged
  handover per (message_id, recipient entity) is THE event; later
  acknowledgements for the same message — from the same or another device —
  are idempotent and MUST NOT yield a second DE; an acknowledgement replayed
  outside its session is invalid (the ack is session-bound).
  `recipient_auth_method`/`auth_context` are recorded in the DE. Such a DE MUST
  carry `delivery_grade` = `availability`, `event` = `D.1-ContentConsignment`,
  `integrity_basis` = `sender-declared-digest` and the sender-supplied
  `grade_commitment` ({{grade-commitment}}), and MUST NOT carry an
  `s3_attestation` or an acceptance-policy evaluation (`acceptance_policy_kind`,
  `quorum`): it attests the availability of the sealed content and the
  sender-declared digest, not recipient-side verification. Availability to an
  unauthenticated queue or store MUST NOT trigger DE at any grade.
- At the `verification` and `acceptance` grades (the defaults, umbrella §8.3b),
  DE is issued at S4 with S3 as precondition and MUST carry an `s3_attestation`
  (the confirmation object of {{canonicalisation-and-payload-hashing}}),
  `integrity_basis` = `recipient-verified-digest` and the applicable
  `delivery_grade`.
- Collapse rule: when the **selected** acceptance policy (the umbrella §8.3
  deterministic selection — `acceptance_policy` is a role-keyed map, never a
  scalar) is `any-one`, S4 == S3 and DE uses
  `event` = `E.1-ContentHandover` (or `D.6-ContentAccessTracking`) with
  `delivery_grade` = `verification`. For `quorum:n`/`all`, S4 is reached only
  when the policy is satisfied and DE uses `event` = `C.3-ConsignmentAcceptance`
  (the acknowledging MIDs are listed in `quorum`) with `delivery_grade` =
  `acceptance`.
- **The deadline is authenticated (finding R1).** The `ttl` lives only in the
  E2EE envelope, so neither the RDP nor a verifier can read it. The sender wallet
  therefore computes the absolute expiry `expires_at` = `sent_at` + `ttl` and
  supplies it with the submission metadata; the RDP MUST echo it verbatim into
  the SE (`expires_at`, v1.15). `expires_at` is the deadline every party evaluates
  expiry against. **Temporal coherence (checkable):** an NDE `expired` MUST NOT be
  premature — its `observed_at` MUST be at or after `SE.expires_at`; and a DE MUST
  NOT post-date `SE.expires_at`, at every grade (next bullet).
  `bundle_lint` LINT-BND-22 enforces both over an EP or bundle.
- **Expiry per grade.** Expiry within `ttl` produces NDE `expired`
  (`C.5-AcceptanceRejectionExpiry`). At the availability grade, expiry occurs
  only where no authenticated-S2 event took place within `ttl`. **The
  availability grade carries NO exemption:** the EVENT time bounds
  every grade — `event_time <= expires_at` — and an availability DE whose
  acknowledged-handover event post-dates `expires_at` is invalid like any
  other. What may post-date the deadline is the *sealing* of the artefact (the
  qualified timestamp), never the event it attests: an in-time event sealed
  late is valid, a late event sealed promptly is not. A tie (event exactly at
  the deadline) is delivered. At the verification/acceptance grades, expiry occurs
  where S3/S4 is not reached within `ttl`, even if the message was retrieved. An RE
  (explicit refusal) can precede the availability event; after an
  availability-grade DE has been issued, a refusal has no delivery-blocking
  effect.

Informative note: the three colloquial meanings of "delivery" map onto this
model as availability (S1/S2), access (S3) and acceptance (S4), and each is a
declarable **delivery grade** (umbrella §8.3b). The legally operative act of
this profile is anchored at S3/S4 by default — authenticated
verification/acceptance by an authorised endpoint; the availability grade
(declared per content class, never implicit) anchors at authenticated S2 —
availability to an authenticated endpoint, never an unauthenticated mailbox.
The design rationale and the three grades are discussed in the umbrella
architecture clause; a fully implicit handover-grade profile remains excluded.

# Evidence Objects and COSE Packaging

All evidence is COSE_Sign1 {{RFC9052}} (CBOR {{RFC8949}}). Implementations MUST
support Ed25519 {{RFC8032}} for the seal; the allowed COSE `alg` values are
EdDSA (-8), ES256 (-7) and ES384 (-35). Evidence contains no plaintext, only
metadata and the payload hash.

## The authoritative artefact (octet-authoritative, evidence 2.0)

From evidence `2.0` the **COSE_Sign1 is the authoritative artefact**, its payload
is the deterministic-CBOR (RFC 8949 §4.2) encoding of the evidence body, and the
JSON is a **non-authoritative projection** (`decode(payload)`); see
{{cbor-structure-definitions-cddl}}. The wire artefact is the seal and its
qualified timestamp:

~~~ cddl
sm-evidence-artifact = [ cose-sign1, qualified-timestamp ]
~~~

The **signed payload** is `dCBOR(evidence-body)`; JCS is no longer used. An RDP
issues evidence in a fixed order:

1. produce the COSE_Sign1 seal over `dCBOR(body)` → `cose-sign1`;
2. obtain a qualified timestamp whose message imprint is `SHA-256(cose-sign1)`;
3. the artefact is `[cose-sign1, qualified-timestamp]`.

The timestamp attests the immutable inner COSE as a **sibling**, not a signed
field, so there is no signed-field exclusion and no imprint circularity.
**Verification:** decode the artefact → (`cose-sign1`, `qualified-timestamp`);
verify the COSE signature over its `dCBOR(body)` payload; verify the timestamp
imprints `SHA-256(cose-sign1)`; decode the payload → the body; validate the body
against the CDDL (the structural **outer bound**); and validate the body against
its **authoritative JSON Schema** — the Schema, not the CDDL, is the
authoritative validator of the decoded body, so a verifier MUST reject a body
that is CDDL-valid but Schema-invalid (the reference linters enforce this
fail-closed as LINT-PKG-12). **An EP** embeds each sub-object as its own
artefact bytes (preserving every issuer's seal for multi-party attribution) and
is sealed over that bundle; a verifier extracts and verifies each sub-artefact
independently. The reference tooling reconstructs the familiar flat shape from
the artefact and re-derives the binding (`evidence_lint` LINT-PKG-06).

**What this algorithm does NOT establish.** It establishes that an issuer sealed
this body and that a timestamp attests the seal — who signed, over what, when.
It does not establish that the issuer was **admitted to the federation** when it
acted. Admission is a governance property held in the membership registry, not a
property of the artefact, and it is evaluated **at the act's own instant** — the
SE's `sent_at`, the DE's `delivered_at`, each relay hop's and each `rdp_chain[]`
entry's own timestamp — over half-open windows, never at verification time,
and only from a register assertion made at or after that instant: an
assertion speaks for nothing later than itself (umbrella §13.1). For
an EP this includes its composer, at the instant the EP's own qualified
timestamp attests: composition is an act, distinct from the acts the
package records. A verifier that checks the seal and not the admission has
verified the evidence and not the provider; a **production-verifier** obligation,
and a separate input, not something the reference tooling can derive from the
artefact it is given.

Because the projection is non-authoritative, a consumer MUST NOT rely on it
beyond what the payload signs: the projection MUST equal `decode(payload)`
exactly — a recursive equality including array length and order, and reaching
into each embedded sub-artefact of an Evidence Package — and a projection that
carries any element the signed payload does not (extra, missing, reordered or
mutated) MUST be rejected. A producer SHOULD generate the projection from the
payload rather than accept it from the wire. The reference tooling enforces this
as `LINT-PKG-11` before reconstruction, and drives reconstruction strictly from
the payload so an unverified projection can never be substituted for it.

**Confirmation verification (part of the algorithm, not a delegation):** where
the decoded body carries a member-produced confirmation — the `s3_attestation`
on DE-v1, the `recipient_confirmation` on NDE-v1, a `wallet-signed` `quorum[]`
entry, the `refusal_confirmation` on RE-v1, or the `sender_confirmation` on
SE-v1 — the verifier MUST, as a step of THIS algorithm: (1) resolve the
confirming member's published `confirmation_key` anchor per (`mid`,
`device_id`) from the confirming entity's BW-MEMBER — the recipient entity's
for a recipient-side confirmation, the SENDER entity's for a
`sender_confirmation` — as it stood at the confirmation's own timestamp; (2) verify `wallet_signature_b64`
(a COSE_Sign1 over the confirmation object's deterministic CBOR with the
signature field removed) against that anchor **under the algorithm the anchor
declares** (see *Confirmation-key encodings* below); and (3) check the confirmation's
tuple against the enclosing evidence — `message_id`, `payload_hash`,
`acceptance_policy_ref` and, where present, `envelope_hash`/`mls_state` MUST
equal the enclosing object's values, **including `recipient_addr` and
`sender_addr`** — the addresses select the acceptance policy, so a
tuple agreeing with its SE on everything except who the message was addressed
to describes a different submission. A confirmation that fails any step MUST be
rejected.

**Confirmation-key encodings and algorithm agreement (normative).**
BW-MEMBER permits three confirmation-key algorithms. Each has EXACTLY ONE
public-key encoding, so that two implementations agree on the bytes rather
than each accepting whatever its library happens to parse:

| `confirmation_key.alg` | COSE `alg` | `public_key_b64` decodes to |
|---|---:|---|
| `EdDSA` | -8 | the raw 32-byte Ed25519 public key ({{RFC8032}} §5.1.5) |
| `ES256` | -7 | a SEC1 **uncompressed** point on P-256: `0x04 \|\| X(32) \|\| Y(32)`, 65 bytes |
| `ES384` | -35 | a SEC1 **uncompressed** point on P-384: `0x04 \|\| X(48) \|\| Y(48)`, 97 bytes |

A compressed point, a bare scalar, a key of the wrong length for its declared
algorithm, or a point not on the declared curve MUST be rejected — accepting
several encodings is how one key acquires two identities.

The COSE protected header MUST declare `alg`, and the verifier MUST check
**three-way agreement**: the COSE `alg`, the published
`confirmation_key.alg`, and the key's actual type/curve. Any disagreement is a
verification FAILURE, never a fallback to whichever the verifier can compute —
naming the algorithm in discovery is pointless if a verifier accepts a
signature naming a different one. ECDSA signatures are the fixed-width `r || s`
form of {{!RFC9053}} §2.1 (64 bytes for ES256, 96 for ES384); a DER-encoded
signature is not a COSE signature and MUST be rejected.

Where a production certificate accompanies the anchor, its subject public key
MUST equal `public_key_b64` — a certificate for a different key attests
nothing about the confirmations made under this one. A session-authenticated confirmation is verifiable only through its
retained `session_binding` digest; absent one it is a provider assertion and
MUST NOT be treated as member-produced proof. The assurance-level and roster
requirements for each step are imported by reference from [TS] clause 6
(INTF-1, INTF-1a, INTF-1b, INTF-2, INTF-3) — the wire algorithm names the
steps; the TS defines their conformance levels. The reference linters implement
the steps statically (`bundle_lint` LINT-BND-12/21/28/29, `evidence_lint`
LINT-DE-12/13/19/20, LINT-RE-01).

## Object Definitions

- **SE (Sending Evidence)** — issued by the sender-side RDP on accepted
  submission. Carries `message_id`, `sender_uid`, `recipient_uid`,
  `transport`="SM-MLS-1.0", `mls_group_id`, `mls_epoch`, `payload_hash`,
  `sent_at`, `expires_at` (the authenticated deadline, R1), `rdp_id` (and the
  identity/policy fields required by {{TS-SBM-QERDS}}). Its
  `acceptance_policy_ref` names the policy document (`policy_version`,
  `doc_digest`) AND the exact key selected within it (`policy_key`, evidence
  2.4 — the deterministic selection of the umbrella profile; the DE echoes
  the same reference, and the sender confirmation signs it); for an
  availability-declared content class it also echoes the sender-supplied
  `grade_commitment` ({{grade-commitment}}).
- **DE (Delivery Evidence)** — issued per the declared delivery grade
  ({{message-flows-and-delivery-states}}): at S4 (verification/acceptance
  grades) or at authenticated S2 (availability grade). Carries `recipient_uid`,
  `delivered_at`, `payload_hash`, `delivery_grade`,
  `integrity_basis`; `acceptance_policy_kind` and
  `s3_attestation` at the verification/acceptance grades only; `quorum` when
  `acceptance_policy_kind`=`quorum`; `grade_commitment` at the availability
  grade only ({{grade-commitment}}).
- **NDE (Non-Delivery Evidence)** — carries `reason`, `observed_at`, and ONE
  hash commitment whose field names its SEMANTIC DOMAIN (evidence 2.6):
  a **post-acceptance** NDE (B.3/C.5/D.2/E.2 events) carries `payload_hash` —
  the APPLICATION-CONTENT domain, the sender-declared digest of the accepted
  message's plaintext; an **intake-stage** NDE (`A.2-SubmissionRejection` —
  the envelope was never accepted, possibly never parsed) carries
  **`submission_hash`** instead — the REJECTED-SUBMISSION domain: SHA-256
  (`hash_mode` `raw-sha256`) over the EXACT submitted octets as received at
  the intake boundary, BEFORE any parsing or decoding (the posted request
  body bytes, byte-for-byte). Each event admits exactly one of the two
  fields (schema-enforced both directions); **hashes from different domains
  are NEVER compared** — a comparison is meaningful only within one domain.
  `redirect_uid` when `reason`=`uid-merged`; `recipient_confirmation` when
  `reason`=`payload-hash-mismatch`.
- **RE (Refusal Evidence)** — carries `reason`, `refused_at`, `payload_hash`.
- **CE (Change-Indication Evidence)** — carries `transformation` (`re-packaging` | `chunking` — OBSERVABLE envelope/framing operations only), `changed_at`, and the byte commitments the issuer legitimately observes: `envelope_hash_before` (the SE's transmitted-octet commitment) plus `envelope_hash_after` (re-packaging) or `part_envelope_hashes[]` (chunking). An MLS epoch change re-encrypts NO queued application message and an intermediary cannot transform the E2EE envelope — the former epoch-change CE type is removed; a sender resubmission after an epoch change is a NEW submission chain (new SE). The QERDS obligation to issue CE is in
  {{TS-SBM-QERDS}}.
- **EP (Evidence Package)** — bundles `se`, `outcomes[]`, `rdp_chain[]` as an octet-authoritative artefact whose
  body embeds each sub-object's artefact bytes. `states[]` are
  non-operative state records only. An EP is composed only once at least one
  outcome (DE, NDE or RE) exists — `outcomes` is non-empty by design, so no EP
  exists between submission and the first outcome; until then the evidence for
  a message is retrievable as the individual objects
  ({{deployment-defined-interfaces}}).

  **Outcome finality — a monotone state machine (finding R4).** Each of DE
  (delivery), NDE (non-delivery) and RE (refusal) is a **terminal** outcome for
  its message; a message reaches **exactly one** terminal outcome (per grade,
  where a class's grade differs), and the EP `outcomes[]` MUST carry **at most
  one** terminal outcome. A DE together with a terminal NDE or RE for the same
  message, or two terminals, is a contradiction and MUST NOT be represented.
  Retries are **idempotent** ({{error-handling-and-retries}}): re-processing a
  message returns the existing terminal outcome, never a second, contradictory
  one. Late or additional events after the terminal outcome are **supplementary**
  evidence — Change Evidence in `changes[]`, or non-operative records in
  `states[]` — that augment the audit trail but **never replace** the terminal
  result. `outcomes[]` is `uniqueItems`, and the at-most-one-terminal invariant is
  `evidence_lint` LINT-EP-07.

`message_id` MUST be globally unique; `payload_hash`/`hash_mode` MUST be
consistent across SE/DE/NDE/RE for the same message. `mls_group_id`/`mls_epoch`
on SE bind the evidence to the MLS session.

**MLS commitments (normative, evidence 2.2; R-02/D3).** Two dedicated
fixed-format commitments bind the evidence to the exact wire bytes and state —
SHA-256 is fixed by the type (there is no algorithm or mode selector, so
alternative hash constructions are unrepresentable), and the input is a
TLS-serialized RFC 9420 struct:

- **`envelope_hash`** = `{ format: "mls10-message", hex }` — SHA-256 over the
  TLS-serialized **`MLSMessage`** (protocol `mls10`, `wire_format`
  `mls_private_message`) exactly as handed to transport: the whole wire object,
  not the `PrivateMessage` alone. Every party that handles the octets can
  recompute it independently: RDP(out) from the octets accepted for transport,
  each relaying RDP from the octets it forwards, RDP(in)/the wallet from the
  octets received.
- **`mls_state`** = `{ format: "mls10-group-context", hex }` — SHA-256 over the
  TLS-serialized **`GroupContext`** (RFC 9420 Section 8.1): ONE value that pins
  the protocol version, the **cipher suite**, `group_id`, `epoch`, `tree_hash`,
  `confirmed_transcript_hash` AND the GroupContext extensions together — group
  id and epoch alone do not uniquely identify the state, and two forks sharing
  them produce different commitments.

SE and the recipient confirmation carry the same values (LINT-DE-16); the
reference serializer for both structs is `scripts/mls_wire.py`, and a
known-answer test pins the exact bytes.

**The commitment at every transport boundary (normative).** The
transmitted-octet commitment is not confined to the confirmation-bearing
grades: the **availability-grade DE** carries `envelope_hash` (REQUIRED — the
one grade without a recipient confirmation binds the exact octets made
available to the authenticated endpoint; within an EP it MUST equal the SE's,
LINT-DE-17), and **every RelayEvidence** hop carries `envelope_hash`
(REQUIRED — the hop attests the exact octets it received and handed over; in a
bundle it MUST equal the SE's for the same `message_id`, LINT-BND-25). Duties:
RDP(out) computes the commitment from the octets it accepts for transport; a
relaying RDP MUST recompute it from the octets it forwards and MUST refuse the
hop if its recomputation differs from the sending side's declared value;
RDP(in) and the recipient wallet recompute from the octets received before
confirming. A substituted ciphertext under unchanged metadata therefore fails
at every grade and at every hop, and the Evidence Package demonstrates the
end-to-end chain (SE = availability DE = each hop = confirmation), not merely
sender/recipient field equality.

**MLS state retention and historical verification (normative).** The
`mls_state` commitment is only as verifiable as the state it commits to, so:
the recipient's provider MUST retain, for the evidence-retention period
(umbrella §4.3), the **GroupContext** — and the **ratchet tree / GroupInfo**
its `tree_hash` commits to — for every `(group_id, epoch)` referenced by
evidence it issued or confirmed, and MUST serve them to an authorised verifier
through the deployment-defined Delivery-Service surface
({{deployment-defined-interfaces}}; a behavioural requirement like the
KeyPackage-pool rules — the wire contract is a profile-2 companion).
**Verification from evidence time:** (1) resolve the historical GroupContext
for the evidence's `(group_id, epoch)`; (2) recompute
`SHA-256(TLS-serialize(GroupContext))` and check it equals the evidence
`mls_state` — this pins protocol version, cipher suite and extensions, and is
deterministic per suite by construction; (3) verify the retained ratchet tree
against the GroupContext's `tree_hash`, which yields the historical roster
(membership and leaf keys) the evidence was issued under. Two forks sharing
`group_id` and `epoch` have different GroupContexts and therefore different
`mls_state` commitments — their evidence is not interchangeable.

**Grade-Commitment Mismatch evidence (GCM-v1; D5, normative).** The
availability-grade DE is **final at authenticated S2** — no pre-delivery
content proof exists at that grade by design. What the profile adds is the
**dispute machinery**: when the recipient, on eventually reading, finds the
actual `content_class` differs from what the sealed grade commitment binds, its
provider issues a **`GCM-v1`** evidence object carrying the envelope's true
`(salt, content_class)` reveal, the disputed sealed `grade_commitment` (echoed),
the reading member and instant, pinned to the referenced BW-ORG version.
**Verification:** recompute the grade commitment from the reveal against the
pinned ORG digest; the GCM is a **valid rebuttal** iff EITHER the recomputation
differs from the sealed commitment (the commitment never bound the actual
envelope) OR it matches but the revealed class's declared grade in that BW-ORG
is **not** `availability` (a truthfully-committed non-availability class
obtained availability treatment). A GCM whose reveal matches AND whose class IS
availability-declared proves nothing and MUST be rejected. A valid GCM
**rebuts** the availability DE in dispute — it never retracts it: the DE
remains the terminal outcome (LINT-EP-07 is unaffected), and the GCM travels in
the EP's OPTIONAL `disputes[]` array as sub-artefact bytes.
*[**TODO(legal):** the normative clause stating the effect of a proven mismatch on the Article 43(2) presumption (final-but-rebuttable) awaits external counsel (DESIGN_DECISIONS.md, D5 LEGAL-CONFIRM).]*

## Timing

**Event time vs artefact time (normative).** `delivered_at` is the
**delivery-event time** — the instant of authenticated S2 at the availability
grade, S3/S4 at the verification/acceptance grades — never the artefact
issuance or sealing time.

**Whose clock dates S3/S4 (normative).** At the availability
grade the event is the Delivery Service's observation of the acknowledged
handover, and `delivered_at` is the signed receipt's `server_time`. At the
verification and acceptance grades the event is the recipient confirmation
that **completed** the selected policy — the first eligible member's for
`any-one` (S4 == S3), the n-th distinct eligible member's for `quorum:<n>`,
the last eligible member's for `all` — and `delivered_at` is the instant
**RDP(in) received and verified that confirmation**, on RDP(in)'s own clock.
A wallet-declared `verified_at` does not decide it: a client clock deciding
timeliness is what the server-observed rule removed for S2. It follows that every act the DE
rests on — the `s3_attestation`'s `verified_at` and every `quorum` entry's
`ack_at` — MUST NOT be later than `delivered_at` (`evidence_lint`
LINT-DE-21), and RDP(in) MUST refuse a confirmation dated after its own
receipt of it. The S2 receipt never dates a verification- or acceptance-grade
delivery: an S2 before `expires_at` cannot make an S4 after it timely. A
confirmation RDP(in) receives after `expires_at` is late, whatever its
`verified_at`; one received exactly at `expires_at` is delivered. At **every** grade, availability included, the event
time MUST NOT exceed `expires_at` (`bundle_lint` LINT-BND-22; the former
availability exemption is removed — the one grade without a recipient
confirmation needs the temporal guard most). A tie (`delivered_at ==
expires_at`) is **delivered**. The qualified timestamp on the artefact remains
the possibly-later **issuance** time: a DE sealed late whose event time is in
bound is valid, and the gap between the two is the sealing latency, not a
delivery-time claim. `observed_at` on an NDE `expired` MUST NOT precede
`expires_at` (no premature expiry). The clock is the issuing RDP's, under the
TS's provider obligations.

**Expiry validation at submission (normative).** `expires_at` is
sender-computed but VALIDATED, never echoed: at intake the RDP MUST reject a
submission whose `expires_at` is not strictly later than `sent_at`
(LINT-DE-18), whose TTL (`expires_at − sent_at`) exceeds the recipient's
declared maximum (`BW-ORG.max_ttl`, an ISO 8601 duration; absent = the profile
default **P30D**; LINT-BND-27), or whose `sent_at` lies in the RDP's future
beyond the 5-minute propagation bound. On decrypt, the recipient wallet
compares the envelope `ttl` with the SE's committed `expires_at`; a mismatch is
the typed outcome **`expiry-mismatch`** (an NDE bound to
`D.2-ContentConsignmentFailure`) — registered as a **registry action** in
`registries/reason-codes.json` per the registry-layering model: no schema, CDDL or
lint-code change accompanied its registration.

Each SE/DE/NDE/RE, the EP, and any CE artefact carries a qualified timestamp —
the **second element of the evidence artefact `[cose-sign1, qualified-timestamp]`**,
a sibling of the seal, not a field inside it — whose imprint is SHA-256 of the
serialised COSE_Sign1 (`cose-sign1`), encoded as an RFC 3161 {{RFC3161}}
`TimeStampToken` (`format`="rfc3161") or an ETSI EN 319 422 profiled token
(`format`="etsi-ts-token"), base64 in `token_b64`. The qualification of the
time-stamping service is a QERDS matter ({{TS-SBM-QERDS}}).

# CBOR Structure Definitions (CDDL)

The wire structures are defined in CDDL {{!RFC8610}}. The complete definition is
`cddl/sm-mls-erd.cddl` in the reference repository; the fragments here are
introduced where the structures they describe are used.

**Status of the two descriptions.** From the octet-authoritative revision
(evidence `2.0`) the COSE_Sign1 payload is the deterministic-CBOR (RFC 8949 §4.2)
encoding of the `*-body` maps, and the qualified timestamp is a sibling in the
artefact envelope. The two descriptions play **distinct, non-overlapping roles**,
so they are not two definitions of one language (which could disagree):

- the **CDDL is a STRUCTURAL OUTER BOUND** — it fixes the artefact envelope, the
  map/array kinds, and each body's `type`/`version` discriminator. It does NOT
  restate the field-level constraints (some discovery bodies are deliberately
  `{ type, version, * tstr => any }`), both to avoid duplicating normative
  content and because the `cddl` tooling cannot enforce them (no map-choice
  backtracking, no strict multi-`tstr` matching).
- the **JSON Schemas in `schemas/` are AUTHORITATIVE for the body** — required
  fields, patterns and enumerations of the decoded body are defined there, once.
  They validate the **non-authoritative projection** (the JSON obtained by
  decoding the CBOR body); the CBOR values mirror the projection exactly
  (hex-string digests, decimal-string counters, text-string enumerations), so
  decoding the payload yields the projection verbatim.

The two are held in agreement by the `make cddl-check` gate, which for every
sample validates the artefact against the CDDL, validates the projection against
the JSON Schema, **and asserts that the decoded body equals the projection**
(recursive, reaching each EP sub-artefact) — so a document that is CDDL-valid but
Schema-invalid, or whose projection carries content the payload does not, is a
defect. A minimal `{ "type": "BW-ORG-v1", "version": "2.0" }` is within the CDDL
outer bound but is rejected by the authoritative body Schema (`uid` is required):
that is the boundary working as designed, not a divergence. Because the gate is a
required, tool-pinned CI step (§ the conformance bar), the descriptions cannot
drift silently.

**Artefact envelopes.** An evidence artefact embeds the serialised COSE_Sign1 as
a byte string alongside its qualified timestamp; a discovery artefact is the bare
COSE_Sign1 (a 4-element array per RFC 9052 {{RFC9052}}, no timestamp — discovery
documents carry none):

~~~ cddl
sm-evidence-artifact  = [ cose-sign1-bytes, qualified-timestamp ]
sm-discovery-artifact = cose-sign1-struct
cose-sign1-bytes  = bstr   ; a serialised COSE_Sign1, embedded as a byte string; payload = dCBOR(evidence-body)
cose-sign1-struct = [ bstr, { * int => any }, bstr, bstr ]  ; COSE_Sign1 = [protected, unprotected, payload, signature]; payload = dCBOR(discovery-body)
~~~

**Idiomatic modelling.** Where earlier revisions used JSON-Schema `if/then`
conditionals, the CDDL uses CHOICES between distinct shapes — this is where CDDL
is genuinely clearer: a DE is `de-availability` (no `s3_attestation`,
`integrity_basis = "sender-declared-digest"`, `grade_commitment` present) OR
`de-confirmed` (an `s3_attestation`, `recipient-verified-digest`); an NDE splits
on `reason` (a `payload-hash-mismatch` arm requires `recipient_confirmation`, a
`uid-merged` arm requires `redirect_uid`); a `Hash` has one arm per algorithm; a
recipient confirmation is `signed` (with `device_id` and `wallet_signature_b64`)
OR `session-authenticated`.

**What CDDL does not express.** Cross-field invariants stay normative prose and
the reference lint rules: `message_id` agreement across nested objects
(`evidence_lint` LINT-DE-01/EP-01), the commitment reveal recompute (LINT-BND-11/15),
the seal imprint (LINT-PKG-08), EP outcome finality (LINT-EP-07), the trust-store
identity bindings (LINT-TRUST-\*), and manifest canonical order (LINT-MAN-02).
CDDL fixes shape; the linters keep the semantics. This document does not claim
CDDL coverage of those rules.

# Error Handling and Retries

**Hash-domain rule.** Retry, deduplication and collision logic MUST
compare hashes only WITHIN one semantic domain: `payload_hash`
(application content) against `payload_hash`, `submission_hash` (rejected
submission octets) against `submission_hash`. A cross-domain comparison is
meaningless — the same submission legitimately yields different values in
the two domains — and MUST NOT drive any retry, duplicate or dispute
decision.

A sender MAY retry until `ttl` expires; the sender-side RDP MUST handle
retries idempotently (`message_id`). On MLS state errors the MSP SHOULD prompt a
group-state re-fetch; an irrecoverably corrupted group MUST be re-created. MLS
provides transport replay protection; RDPs MUST reject duplicate evidence
issuance for a given (`message_id`, `payload_hash`).

`message_id` is globally unique per issuing environment: it is the evidence
handle and the key of `GET /evidence/{message_id}`, not a per-recipient-queue
key. An **exact retry** — the same `message_id` with the same `recipient_uid`
and the same `payload_hash` — MUST be handled idempotently, returning the
already-issued evidence. A submission whose `message_id` equals that of a
previously accepted submission but whose `recipient_uid` or `payload_hash`
differs is a collision, not a retry: it MUST be rejected at intake with an NDE
`A.2-SubmissionRejection` carrying reason `duplicate-message-id`, and the RDP
MUST NOT open a second delivery for the reused `message_id`. This is a
Delivery-Service-intake obligation; a coherence check over an evidence set (no
`message_id` mapping to two `recipient_uid`s or two `payload_hash`es) is
`bundle_lint` LINT-BND-13.

Across providers (four-corner, {{TS-SBM-QERDS}} clause 4.1) the "issuing
environment" is the **issuing RDP**: the authoritative global evidence handle is
the pair (issuing-RDP identity, `message_id`), where the issuing-RDP identity is
the SE issuer — `rdp_chain[0].rdp_id` in the Evidence Package. `message_id`
remains the per-RDP evidence handle and the key of
`GET /evidence/{message_id}`; the issuing-RDP scope disambiguates it globally,
so two independent providers that mint the same `message_id` do not collide as
evidence handles. Because `message_id` is RECOMMENDED to be a UUIDv7 or ULID
(122 bits of entropy), an unprefixed collision between honest providers is
negligible; issuer-prefixing is therefore NOT required — it would break the
UUIDv7/ULID form — and the issuing-RDP scope is a **resolution** rule, not an
identifier-format rule. The `duplicate-message-id` intake check stays a **local**
obligation (an RDP rejects a reuse within its own namespace); cross-provider
disambiguation is by the recorded issuing RDP, and no shared handle registry is
required.

# Deployment-Defined Interfaces

This document defines the wire protocol — the MLS binding, the application
envelope, canonicalisation, the delivery states and the evidence objects —
and the behavioural obligations of the MSP acting as the MLS Delivery Service
({{mls-delivery-service-mapping}}, {{keypackage-rules}}) and of the RDPs. Four
HTTP surfaces are deliberately NOT defined by this profile — their WIRE FORM
is deployment-chosen at profile 1, while **profile 2 REQUIRES the three published
companion contracts** (`wallet-rdp-openapi.yaml`,
`delivery-service-openapi.yaml`, `rdp-relay-openapi.yaml`). The wallet-agent
interface document is **profile 5 only** (umbrella Annex R), and informative for
cross-deployment use; this sentence used to list it among profile 2's
requirements, contradicting the paragraph below and the TS — a four-corner interoperability claim
(the [TS] claim matrix) rides on those contracts, so no cross-provider
exchange rests on private agreements:

- **Wallet-RDP interface.** The submission-metadata contract carrying the SE
  fields only the sender wallet knows (`payload_hash`, `mls_group_id`,
  `mls_epoch`, `auth_method`, `expires_at`), the delivery of the recipient confirmation
  within an authenticated recipient session (the binding requirements are in
  {{TS-SBM-QERDS}}, clause 6), and the retrieval of evidence objects and
  Evidence Packages by the parties.
- **Delivery Service surface.** The API at `BW-MED.mls.ds_url`: KeyPackage
  publication and replenishment, Welcome deposit and collection, handshake
  message submission and ordering, and its error model. (KeyPackage
  *retrieval* is resolvable through the directory: the EDD resolver contract
  redirects to the MSP pool.) The wire form is deployment-chosen — the MLS
  Delivery Service (RFC 9750) has many valid realisations, so this profile
  constrains behaviour, not bytes — but the surface's REQUIRED properties are
  normative: **idempotent submission** keyed by `message_id` (a retried
  submission never opens a second delivery; see Error Handling and Retries),
  **ciphertext-only handling** (the Delivery Service MUST NOT access plaintext
  payloads — enforced by MLS encryption), per-group **handshake-message ordering**
  and Welcome-queue integrity, and, in a four-corner deployment, the relay and
  retry behaviour of {{TS-SBM-QERDS}} (clause 4.1). **KeyPackage-pool integrity
  (finding R7 / wallet finding H).** The single-use KeyPackage pool is consumable,
  so its retrieval surface **shall** protect it against exhaustion: (i) the
  requester **shall** be authenticated as a federation member (retrieval is not
  anonymous); (ii) the pool **shall** apply **per-peer quotas**; and (iii)
  single-use KeyPackages **shall** be handed out through an idempotent
  **reserve → commit** flow — a reservation held briefly, committed on first use,
  released on timeout — rather than irreversibly consumed on plain retrieval, so a
  retrieval that never delivers does not permanently deplete the pool (this
  complements the last-resort KeyPackage of {{keypackage-rules}}, which bounds but
  does not prevent depletion). Pool exhaustion **shall not** be silent: a first
  contact that cannot proceed because the recipient's pool is depleted yields
  **NDE-v1 `keypackage-pool-exhausted`** (event `A.2-SubmissionRejection`; an
  additive reason-code registration, §9.3 registry action — no evidence-object
  change), distinct from `recipient-unreachable`, so the failure is attributable.
  These are behavioural requirements on the deployment-defined surface — not a wire
  format. Its normative *definition* remains a profile-2 prerequisite; a profile-1
  pilot MAY leave it deployment-defined.
- **RDP-RDP relay interface.** The inter-provider relay of messages and
  evidence in a four-corner deployment. Its normative requirements — the B.x
  relay evidence set, issuance duties, per-hop qualified timestamps, peer
  authentication and the dispute chain — are stated in {{TS-SBM-QERDS}}
  (four-corner relay requirements); the contract itself is a profile-2
  companion deliverable.
- **Wallet-agent interface.** Where a system member (an agent, Annex R of the
  umbrella) acts for the entity, it instructs the wallet through a controlled
  local interface; it never holds the channel's MLS or seal keys. Its normative
  REQUIRED properties: the agent is authenticated to its wallet in a session
  bound to the system member; **key isolation** — the agent cannot extract MLS
  or seal private keys (it instructs, the wallet acts); **attributability** —
  every agent instruction is attributable to the system member (feeding the
  `auth_context.identity=system` acting-identity record); and **mandate-scope
  enforcement** — the wallet refuses an instruction outside the agent's mandate
  scope (umbrella Annex R). Profile-5 cross-deployment interoperability REQUIRES
  this contract to be normatively defined (as profile-2 interop requires the
  wallet-RDP contract); the contract is an agent-profile (profile-5) companion
  deliverable and its authoritative enumeration is the TS clause 4.1
  companion-contract list.

In a single-operator deployment (one co-located MSP/RDP — deployment
profile 1 of the umbrella's deployment-profiles annex) these interfaces are
**deployment-defined**: an implementation MUST satisfy the behavioural
requirements referenced above, but the HTTP shape is not standardised and no
cross-deployment interoperability claim attaches to it. Interoperability
between independently operated wallets, MSPs or RDPs (deployment profile 2
and later) MUST NOT be claimed on the basis of this document alone: it
additionally requires these interfaces to be normatively defined — companion
OpenAPI contracts in the style of the EDD resolver contract, aligned with the
ETSI EN 319 522 Common Services Interface four-corner target (the relay
clause of {{TS-SBM-QERDS}}). The **authoritative enumeration** of these
companion contracts and their required properties is the four-corner relay
requirements clause of {{TS-SBM-QERDS}}; this section only marks the boundary
of what the present document defines. Three different things are true of these
interfaces, and they must not be collapsed into one: the three
profile-2 contracts are **published** — normative definitions exist and the
reference tooling validates against them; cross-deployment interoperability is
**not demonstrated** — no second, independent implementation has exercised them;
and **no conformity assessment body** has confirmed any interoperability claim.
This paragraph used to say none of the interfaces "is interoperable across
deployments today", which read as though the contracts did not exist.

# Security Considerations

Confidentiality, integrity and authentication of application messages rest on
MLS {{RFC9420}}: only group members read content; messages are authenticated by
the sender's leaf signature; membership is authenticated by credentials; forward
secrecy and post-compromise security hold per epoch. MLS group ids are opaque
and reveal no entity identity. RDPs MUST NOT store or access plaintext.

The following design decisions record the tension points of a registered-delivery
service built on E2EE:

- **Plaintext commitment (T1/T2).** `payload_hash` identifies the content
  without disclosing it; the recipient MUST recompute it after decryption. A
  mismatch yields NDE `payload-hash-mismatch`.
- **Transmitted-octet commitment (finding 2, evidence 2.1).** Because
  `payload_hash` is computed over the plaintext, it does not bind the octets
  actually handed to transport. SE therefore also carries `envelope_hash` —
  SHA-256 of the exact MLS `MLSMessage` octets (the normative
  commitment section and the schema define the whole `MLSMessage`; this
  discussion said `PrivateMessage`) — and the recipient
  confirmation echoes it (LINT-DE-16). Unlike `payload_hash`, the ciphertext is
  observable by the relaying RDP, so `envelope_hash` is independently checkable
  and binds the evidence to what was transmitted, not only to what it decrypts
  to; AES-GCM's lack of key-commitment is no longer relied upon for the transport
  binding.
- **Attribution, not deniability.** Generic MLS offers
  a measure of deniability; THIS PROFILE DOES NOT, and does not want it — it
  is a registered-delivery profile whose legal-effect chain RELIES on
  attribution. The leaf credentials are X.509 QSealC chains or the UID QEAA,
  transcripts and GroupContexts are retained (the retention duty), and roster
  snapshots are signed (ROSTER-v1) — so signed MLS content is STRONGLY
  ATTRIBUTABLE. The attribution model, per signed object:
  * an **MLS-signed application message or Commit** is attributable to the
    signing LEAF (the device) by ANY party holding the retained transcript
    and the leaf credential chain (QSealC → EU Trusted List, or UID QEAA →
    issuing QTSP), and through the BW-MEMBER binding to the member and the
    entity;
  * a **wallet confirmation** (sender / s3 / refusal / quorum) is
    attributable to the member's DEVICE via the published
    `confirmation_key` anchor, by any party holding the discovery documents;
  * an **evidence object** is attributable to its issuing RDP or registry by
    its seal and the trust path.
  True third-party deniability would require a DIFFERENT credential design —
  pseudonymous per-group credentials or a deniable authenticated key
  exchange, neither of which this profile specifies — and is recorded here
  as what it would take, not as a property offered. Consequences under
  attribution: (i) *metadata/transcript exposure* — because retained
  transcripts attribute statements to identified devices, the retention duty
  carries an ACCESS-CONTROL duty: retained MLS material is served only to
  authorised verifiers (the DS surface's authenticated reads); (ii)
  *insider disclosure* — an insider leaking a transcript leaks ATTRIBUTABLE
  statements, not deniable chatter; the accountability log and the handling
  duties are the mitigations, and deployments MUST treat retained
  transcripts as evidence-grade material; (iii) *evidentiary analysis* —
  attribution is exactly what the registered-delivery argument needs: the
  evidence chain (SE/DE/confirmations) and the MLS layer now point the SAME
  way, and no legal analysis in the companion documents relies on
  deniability. A sender AdES over `(message_id, payload_hash)` remains
  OPTIONAL (the D4 sender confirmation is the profiled mechanism).
- **Key substitution.** KeyPackages MUST carry a credential, be single-use
  with a bounded lifetime and a replenishment pool, be cross-checked against the
  directory, and have reuse rejected and alarmed. These are the specified,
  enforced mitigations, and they all *trust the directory*. Key transparency is
  the additional control that would detect an equivocating or compromised
  directory; it is **roadmap, not yet profiled** by this document. A concrete
  mechanism would append-only log at least the BW-MEMBER document versions, their
  device `confirmation_key` anchors and MLS-leaf bindings, and the
  KeyPackage-signing keys — with inclusion, consistency and freshness proofs, a
  gossip/audit role and a client verification algorithm — none of which is defined
  here. Until it is, the discovery-key-substitution threat is not claimed closed.
- **Key loss (T9).** There MUST NOT be provider escrow of content or content
  keys; recovery relies on multi-device fan-out. If all recipient devices are
  lost the content is unrecoverable though legally delivered; a prior valid DE
  remains valid and re-transmission uses a new `message_id`.
- **Scope confidentiality and no invisible access (T10).** With confidentiality
  scopes ({{confidentiality-scopes}}) the decrypting audience is the scope
  group's roster, which MLS makes visible to members. The sender's wallet MUST
  verify the roster against the scope descriptor before sending, so a records or
  other non-role leaf cannot be added invisibly: a `records` leaf is present iff
  the descriptor declares `recoverability: records` and its member holds the
  descriptor's `records_role` (resolved via the member-enumeration surface).
  Scopes do not create intra-entity employee-vs-employer privacy —
  the entity administers enrolment and credentials; personal confidentiality
  belongs to the personal-wallet domain.
- **No content services (T5); store-and-forward (T6); metadata clear (T7);
  long-term validation (T8).** Only envelope/metadata transformations occur
  (evidenced by CE); routing metadata stays readable; the qualified timestamp is
  applied to the seal and supports AdES-LTA-style re-timestamping.

Additional considerations: DNSSEC is REQUIRED for directory aliasing zones; MID
rotation SHOULD be supported to avoid cross-conversation linkability; the PQ
hybrid suite protects against harvest-now-decrypt-later attacks when deployed.

**Grade-commitment privacy.** The commitment ({{grade-commitment}}) is hiding
in practice: its input contains 128 bits of fresh salt, so an observer cannot
dictionary-test the small, public content-class registry against a sealed
commitment; per-message fresh salt prevents correlating equal classes across
messages; and the salt never leaves the encrypted envelope except by
deliberate reveal, which discloses exactly one message's class to exactly the
parties of that dispute.

**Metadata privacy.** MLS protects content, not traffic metadata: UIDs, group
ids, sizes, instants and the evidence fields remain visible to the providers
and to evidence verifiers. The consolidated metadata privacy threat model —
what the metadata reveals, to which observer, the current mitigations
(pseudonymous MIDs, opaque group ids, `content_class` confined to the
encrypted envelope, MID rotation) and the residual risks — is maintained in
the umbrella's security and privacy clause; this document keeps only the
wire-level facts it rests on.

# IANA Considerations

This document requests the following registrations (values to be allocated).

**MLS Credential Type `bw_uid_qeaa`.** In the IANA "MLS Credential Types"
registry (RFC 9420, Section 17.5): a credential carrying the SD-JWT-VC of the
entity UID attestation with a member-binding claim (MID / `device_id`). Baseline
interop does not depend on this allocation; the `x509` credential type
(value 2) is the mandatory baseline. During experimentation, implementations MAY
use a value from the RFC 9420 private-use range, agreed bilaterally.

**Registry layering (what this document does and does not own).** This
document defines the **fields** `reason` (NDE/RE/RelayEvidence) and
`content_class` (the application envelope), their **lexical value spaces**, and
the **unknown-code processing rule** below. It does **not** own the registry
*contents or governance*: the registered code sets and their event bindings are
**federation registries owned by the design authority** under the umbrella's
registry-lifecycle clause (§13.4), published as machine-readable registry
artefacts (`registries/reason-codes.json`, `registries/content-classes.json`)
from which the reference conformance tools load their recognized sets.
Registering a code is an additive **registry action** that leaves every
already-issued object valid and unchanged; it is **not** an evidence-`version`
bump (umbrella §9.3), and — because the wire value spaces below are
pattern-bounded, not enumerated — it requires **no** schema, CDDL or lint-code
change. Likewise the `/.well-known/` URI registrations travel with the
documents that define those resources (the umbrella directory clause §8.1 and
the EDD resolver contract), not with this transport document.

**Lexical value spaces (normative).** A `reason` code and a `content_class` are
lowercase-kebab tokens matching `^(x-)?[a-z][a-z0-9-]{1,62}$` (content classes:
`{0,62}` after the first letter). The `x-` prefix is **private use**: an
`x-`-prefixed value is entity- or bilaterally-defined, is never registered, and
MUST NOT be presented as interoperable. An unprefixed value asserts a
**registered** code.

**Unknown-code processing (normative).** On ingest, a well-formed but
unrecognized `reason` code MUST be **preserved verbatim** and MAY be treated as
a generic NDE/RE (a non-delivery or refusal whose specific ground the consumer
does not implement); it MUST NOT be structurally rejected. The reference
linters implement this as a warning, not a violation (`LINT-NDE-W1`), while a
*registered* code still enforces its registered event binding (`LINT-NDE-07`).
This rule is what makes an additive registration safe for an older verifier.

--- back

# MLS Group-Creation Sequence (Informative)

WU-S resolves the recipient UID and MED, fetches KeyPackages for the target
devices, creates the group adding its own and the recipient's devices, Commits,
and submits the Welcome messages to the recipient MSP, which queues them; the
recipient devices verify credentials and join. No shared secret or prior
exchange is required.

# Profile Summary (Informative)

SM-MLS-1.0 = MLS {{RFC9420}} baseline suite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; `x509` or `bw_uid_qeaa`
credentials chaining to EU Trusted Lists; MSP as Delivery Service; single-use
KeyPackages; deterministic-CBOR evidence encoding defined in the CDDL; COSE_Sign1
evidence with seal-then-timestamp sequencing.

# Relationship to the Companion Documents (Informative)

The qualified-status, identity-proofing, ACM cryptography, and ETSI EN 319 522
event/semantics mapping are specified in the QERDS-binding profile
{{TS-SBM-QERDS}}. Identifiers, directory, roles, architecture and governance are
in the umbrella {{SBM-UMBRELLA}}. This document is self-contained for the wire
protocol.
