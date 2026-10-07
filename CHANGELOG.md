<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Changelog

The history of the **artefacts** — what changed on the wire, in the schemas and
in the contracts. This is history, not a second status page: what the current
artefacts establish is said where it is checked — the README's
[*What a green bar means*](README.md#what-a-green-bar-means--and-what-it-does-not),
[`OPEN-ITEMS.md`](OPEN-ITEMS.md) for what is not proven, and the
[decision records](docs/adr/) for why the design is the way it is. The
current version of every artefact is held in [`versions.json`](versions.json),
enforced by `make versions`, and never restated by hand; the tables below are
the versions each dated edition was cut with.

This snapshot was exported for review; the design study's internal development
record is not reproduced here.

---

## Current — 2026-10-07, edition r42

**The decision records, read by somebody who did not write them. No artefact
version moves, and no decision changes.** The sixteen architecture decision
records were reviewed for whether a reader who did not write them can follow
them. One record said something that disagreed with the rest of the snapshot,
and that is corrected; otherwise no record now says anything it did not say
before.

**What was wrong with them.** The summary fields that the generated decisions
index actually shows a reader were telegrams — semicolon-joined noun phrases,
compressed past the point of being sentences. One read, in full: *"one
accountable, qualified party observes, transfers and attests; A9 and L1 dissolve
by construction; one fewer identity, contract, descriptor and interface; the
model the consultation asked for"*. And the index welded two such lists together
with *"— at the cost of"*, so a reader met one long sentence and had to find the
hinge before knowing which half of the trade-off they were in. The two halves are
now labelled — **Buys** and **Costs** — and each is written as sentences.

**The vocabulary.** The records leaned on terms a reader was assumed to arrive
with: the provider roles, the evidence objects, the discovery documents, the key
identifier. Each record now expands the terms its own decision turns on, at their
first use in its body, and uses the short form after that. A record has to be
readable on its own, because that is how one is read — somebody follows a
citation into exactly one of them.

**One record disagreed with every other document.** The record on the entity
identifier expanded *EDD* as "entity discovery directory". The umbrella profile's
glossary, two published contracts, the architecture figure, the vision document
and the record on the federation all say **European Directory of Entities**. One
record was teaching a reader a second name for the same institution, and nothing
compared the two. A check does now, and it reads the expansions it holds the
records to out of the normative text rather than carrying its own list — so a
record cannot drift from that text by being edited on its own, and a second
expansion of one abbreviation is a failure. Two names for one thing is worse than
no name.

**The most recent record, rewritten.** The record that names the observing
provider on a delivery receipt now opens by naming the four things it turns on,
states the two-provider problem concretely before introducing the field that
solves it, sets out the two defects it was written for as a list rather than a
paragraph, and gives the three reasons its answer is trustworthy as three
reasons. Its consequences section keeps all three of its disclaimers and says
plainly that each has been mistaken for a consequence of the decision.

**Elsewhere.** Fifteen sentences carrying three or more clauses were split, across
eleven records; the longest ran to 86 words. Ten of the index's short labels are
plainer — *"MSP folded into the RDP"* is now *"One provider role, not two"*.
Those labels appear only in the record and in the generated index, so nothing
cites the old ones.

**Two checks were holding the prose to its phrasing rather than to its claims**,
and failed on rewordings that changed neither the decision nor the meaning. Both
now assert what the text must *say*. A check that cannot tell a rewording from a
removal teaches an editor to leave prose alone instead of keeping it readable,
which is the opposite of what it is for.

What this edition deliberately does **not** do: rewrite the bodies of the earlier
records end to end. They are records of past decisions, and rewriting a record's
reasoning can change what it is understood to have decided. Their titles are
untouched for the same reason — a title is how a record is cited.

## Edition r41 — 2026-10-07

**An unanswerable question must not erase an answered one. No artefact version
moves.** An independent verification confirmed both corrections in the previous
edition and found a defect inside the first of them: **adding evidence to a
package of retained material removed findings from the report.**

The demonstration is exact. Take an evidence package carrying a message's
submission evidence and its delivery evidence, sealed together; a delivery receipt
that really was signed by the right provider, 37 seconds after the delivery
evidence it is supposed to date; and a receipt entry that names the message's
origin explicitly. The verifier reports the disagreement. Now add one further
sealed submission evidence object, for the same bare identifier under an unrelated
origin — changing nothing about the receipt, nothing about the package, and
nothing about the relationship the package's own seal states — and the
disagreement is no longer reported at all. Its companion: a receipt whose
signature does **not** verify, filed under a bare identifier, stopped being
reported as unverifiable once the same unrelated object was added.

**The cause was one sequence doing four jobs.** The retained-receipt check asked
four questions in a single chain, each step returning early: *which delivery is
this receipt about; does the retained evidence record that delivery; is the receipt
authentic and internally consistent; does it agree with the delivery's own date.*
Chained that way, a question the material could not answer suppressed an answer the
material already contained. Nothing about a forged signature depends on knowing
which delivery it names.

The four are separate now, and each reports its own answer. Where the retained
material does not establish which delivery a receipt belongs to, that is reported
as an incomplete verification — and the key is still resolved, the signature still
verified, the signed fields still compared with the ones presented beside them.
The one thing not done is the comparison that genuinely needs the association.

**A package's seal states a relationship, and the walk discarded it.** An evidence
package holds every outcome it carries to its own submission evidence, and its seal
covers both — so an outcome retained inside a package is attributed by the party
that composed it, not by inference at verification time. Flattening the package
made an outcome inside one indistinguishable from a loose one, and a single
unrelated object elsewhere was then enough to detach a delivery record from the
submission record sealed beside it. A **standalone** outcome genuinely names no
origin, so where an identifier is ambiguous nothing attributes it: such an object
is set aside, and now *said* to be set aside, together with the comparisons that
needed it. Dropping it in silence made a comparison that never ran look like one
that passed.

**Three further instances of the same shape** were found while reproducing those
two: a receipt filed under an identifier no retained evidence names, one filed
under the wrong origin, and one omitting a field the delivery context needs. Each
reported the filing error and stopped, so a forged signature in any of them went
unmentioned. Stated with its weight: all three already failed the verification —
what was wrong is that *refile this correctly* and *this signature is forged* are
different conclusions, and only the first was printed.

**The worked demonstration's relay chain still preceded the message it relays.**
The previous edition moved the package's state records and left its chain of
provider hops timestamped before the submission. Those are act timestamps: a
verifier asks whether each provider was admitted **when it acted**, at that
entry's own instant. Each hop now timestamps the act it is — the originating
provider accepting at the submission instant, the relaying provider accepting at
the instant the first state record names — so the package's two records of the
same two acts agree. Only the package's own seal was recomputed: every enclosed
issuer's seal is byte-identical, and a field-by-field comparison confirms nothing
moved but those two instants.

**And the input register gated prose it did not render.** The register that names,
for each verification input, who serves it and what its absence costs, carried an
account of the receipt entry's own key syntax — and the renderer read that account
for a command-line input while ignoring it for a manifest key. So the syntax
existed in the register and in no document a reader reads, and the rule catalogue
still described the older shape. Both now carry the real one, with a worked
manifest fragment that a check parses out of the rendered page and runs through the
published entry point.

Five consecutive editions have now each found the previous one's correction to
contain the next one's defect, and in three of them a demonstration fixture was
asserting something nothing compared. Each was caught by a check added the edition
before. That is the review process working — and it is also the reason not to read
*all gates green* as *correct*: every edition's gates were green over the defect the
next verification found.

What this edition does **not** change: no published operation carries a receipt
from the provider that observed a handover to the party that issues the delivery
evidence, and the open-items list still records that, together with the limits on
corroborating a receipt's observer, device and session from published evidence.

## Edition r40 — 2026-10-07

**Order is not evidence, and one instant has more than one spelling. No artefact
version moves.** An independent verification confirmed the previous edition's
receipt-binding correction and found two further defects inside it. Both are fixed
here.

**A bare message identifier does not name a delivery.** The wire protocol makes a
delivery's handle the pair of its origin and its identifier, so one identifier can
occur in more than one provider's namespace. The new comparison grouped retained
evidence by the bare identifier and took the **first** Sending Evidence it found —
so two separately sealed Sending Evidences for the same identifier under different
origins produced opposite verdicts depending which was listed first: a clean result
one way, a definite "this receipt is about a different delivery" the other. The same
documents, the same receipt, and no signed value different between the two runs.

The delivery evidence cannot settle it either: the provider it names is the one
that **issued** that outcome, not the one the message came from, and reading it as
the origin would repeat the confusion the previous edition removed.

A retained receipt may now be filed under its full handle rather than the bare
identifier. A bare entry still resolves where exactly one evidenced origin carries
that identifier; where several do, which delivery is meant is **ambiguous** and
reported as such — identically in either order. The party assembling the package
states the association, and it is still checked: an entry filed under one origin
whose receipt attests another is a mismatch, not a relabelling the verifier
accepts.

**And a comparison of instants compared their spelling.** A receipt signed at the
delivery's own moment, written with fractional seconds, was reported as being from
another moment. The repository has one timestamp primitive for exactly this, and it
exists because a decimal point sorts before the trailing Z, which makes byte-wise
comparison wrong at fractional boundaries.

The cause was a document rather than an oversight: the timestamp definition's own
description told an implementer that byte-wise comparison of these strings is
chronological, while the pattern beside it admits fractional seconds and the
reference's parser documents why that claim is false. The check had been written to
the claim. The description now says what is true and names the primitive; the
comparison parses both sides and reports a timestamp it cannot read rather than
guessing.

| Artefact | This edition | Previous |
|---|---|---|
| Umbrella profile | **2.1, edition 2026-10-07** | 2.1, edition 2026-10-07 |
| TS-shaped QERDS binding | **v0.37** | v0.37 |
| Profile-2 companion contracts | **16.0.0** | 16.0.0 |
| BW-MED / BW-ORG / BW-MEMBER | **2.3** / 2.7 / 2.2 | 2.3 / 2.7 / 2.2 |
| EDD resolver contract (OpenAPI) | **2.1.0** | 2.1.0 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |

**The demonstration recorded a handover before its submission.** The
availability-grade example put submission at the instant every sample shares, and
its delivery evidence, its receipt and the dispute package's own state records put
the relay acceptance and the handover seventeen minutes **earlier**. No check
objected: the profile sets no bound on clock skew between two providers, and the
chronology was inherited rather than introduced. The later instants now follow the
submission they belong to. Every affected sealed artefact was regenerated and
compared field by field against its previous state: nothing changed but those
instants and the signatures and digests derived from them.

Four diagnostics in the receipt path, the architecture note's signing-key table and
the provider descriptor's own schema still named the originating provider as the
holder of the receipt key. They name the observing provider. A historical aside
left in the onboarding prose is removed; this changelog is where that belongs.

**A new agenda item records what no evidence can corroborate.** A receipt names the
provider that observed, the device that acknowledged and the session it
acknowledged in — and no published evidence object names any of the three, so the
verifier cannot check them against anything. The code marks them as the receipt's
own word rather than treating them as confirmed, and the agenda now carries the
question instead of leaving it to be inferred from two adjacent entries.

## Edition r39 — 2026-10-07

**A receipt now has to be about the delivery the evidence names. No artefact
version moves.** An independent verification of the previous edition confirmed
every earlier finding closed and raised one more, in the part the previous edition
had just rewritten. It was right.

**The expected delivery was copied from the receipt being checked.** The shared
check compares what a receipt says against what the caller expects it to say — and
the retained verifier assembled that expectation out of the receipt's own fields.
So it proved the receipt agreed with itself, and nothing about the delivery the
package evidences. A correctly signed receipt, for a message that **originated at a
different provider**, over **different ciphertext**, at a **different instant**,
filed under the same bare message identifier, passed through the published command
with no finding at all.

Nothing had to be forged and no provider had to misbehave: the receipt is simply
true about another delivery. A bare message identifier does not name one — it is
scoped by the message's origin, and the only object that proves an origin is the
Sending Evidence. The delivery evidence names its own issuer, which is a different
party, and reading the origin from it would have repeated the confusion the
previous edition removed.

The expectation is now taken from the retained evidence: the Sending Evidence's
origin and its commitment to the ciphertext, the recipient the evidence names,
and — at the **availability grade** only, where the receipt is what dates the
delivery — the delivery evidence's own instant. Not at the other grades, where the
recipient's completing confirmation dates it and the receipt dates nothing. Three
details still come from the receipt and the code says so plainly: no published
evidence object names the observing provider, the acknowledging device, or the
session it acknowledged in. That is a known open question, not a comparison
quietly skipped.

Where the material to compare is missing, the relationship is reported
**unproven** rather than passed on the strength of the signature, and the registry
of what must stay retrievable records whose material it is.

| Artefact | This edition | Previous |
|---|---|---|
| Umbrella profile | **2.1, edition 2026-10-07** | 2.1, edition 2026-10-07 |
| TS-shaped QERDS binding | **v0.37** | v0.37 |
| Profile-2 companion contracts | **16.0.0** | 16.0.0 |
| BW-MED / BW-ORG / BW-MEMBER | **2.3** / 2.7 / 2.2 | 2.3 / 2.7 / 2.2 |
| EDD resolver contract (OpenAPI) | **2.1.0** | 2.1.0 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |

**An Evidence Package carries evidence, and only its outside was being read.** The
Sending Evidence that proves the availability message's origin travels inside the
dispute package, so it was invisible to the comparison. The verifier now looks
inside a package as well, and the demonstration bundle carries that Sending
Evidence directly — byte for byte the same object — so the shipped conformance run
demonstrates a complete receipt-to-delivery check rather than reporting it
unproven.

**Two demonstration fixtures turned out never to have agreed with themselves.**
Receipt tests paired a receipt issued by one provider with Sending Evidence
originating at another, and acknowledged their own test bytes while that evidence
committed to different ones. Neither disagreement could be seen while the
expectation was copied from the receipt — the defect was concealing its own
fixtures.

**And the published rule text would have rebuilt it.** The catalogue entry for an
unresolvable receipt key still described that key as the issuing provider's, and
the provider descriptor's own schema said the same. The running code had been
corrected an edition earlier; the text an independent implementer would follow had
not. Two smaller residues went with them: the umbrella's abbreviated discovery
example still declared the previous document version thirty lines below the
required-field list that had moved on, and the architecture note still ended its
opening with a sentence denying the provider-to-provider relay it had just
described.

## Edition r38 — 2026-10-07

**The receipt names the provider that observed the handover.** An independent
review of the previous edition found the move of the Delivery-Service receipt key
half finished, in a way the edition before it had made worse rather than better.
It was right, and this edition is the other half.

**It was the wrong identity.** A receipt names the message's ORIGIN — the
published contract says so in terms, and carries a separate field for a provider
that forwarded. The handover a receipt attests happens on the other side: the
recipient's Delivery Service issues the collection token, authenticates the
device, records the acknowledgement, and its provider signs. The previous edition
required the ORIGIN to publish a key for a handover it did not observe, which
refuses the party that actually signed; the retained path looked the key up in
the same wrong document.

**And the example concealed it.** The generator had been passing the delivery
evidence issuer as the origin, so the receipt claimed one provider for a message
whose Sending Evidence names another. With both identifiers holding a single
value, neither the code nor the example could be shown wrong — the example had
been repaired by rewriting the origin to match the signer, which is the one
repair that demonstrates nothing.

A receipt now carries **`observed_by`**, signed and REQUIRED: the provider whose
Delivery Service observed. One implementation resolves and authenticates by it on
both the live and the retained path, refusing a document of the wrong kind, one
belonging to another participant, and a receipt that names no observer. The
generator reads the origin from the Sending Evidence and REFUSES to write an
example whose two providers coincide, so the shipped receipt is a genuine
four-corner case verified against the descriptor beside it.

| Artefact | This edition | Previous |
|---|---|---|
| Umbrella profile | **2.1, edition 2026-10-07** | 2.1, edition 2026-10-06 |
| TS-shaped QERDS binding | **v0.37** | v0.36 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **16.0.0** | 15.0.0 |
| BW-MED discovery document | **2.3** | 2.2 |
| EDD resolver contract (OpenAPI) | **2.1.0** | 2.0.0 |
| BW-ORG / BW-MEMBER | 2.7 / 2.2 | 2.7 / 2.2 |
| BW-PROVIDER provider descriptor | **1.1** | 1.1 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |

[A new decision record](docs/adr/SBM-ADR-0016.md) carries this, because the field
is one the one-provider decision had withdrawn. It returns for a different reason
than it was withdrawn with: not to attribute a false observation to a party
outside the provider, but to say which of two qualified providers observed, so
that the right key can be found. **One provider role does not mean one provider
per message** — the sentence the previous two editions needed and did not have.

**Three normative surfaces still sent a reader to the deleted location.** The
Internet-Draft required the keys in the customer's signed discovery document, the
Delivery-Service contract gave that lookup, and the production-verifier
explanation named it as the key source — while the reference, correctly, refuses
that document. A reader following the published instructions arrived at a
rejection. All three now name the provider's own descriptor, and which
provider's.

**And the endpoints.** The umbrella's own required-field list still placed the
KeyPackage and Delivery-Service URLs under the MLS parameters, contradicting its
own example thirty lines below; so did the Internet-Draft, the resolver contract
and the lint catalogue's predicate text. The schema accepted a discovery document
with neither endpoint while the semantic linter required both, so a schema-only
consumer accepted an incomplete document. Both are required now, which is what
moves the discovery document to **2.3** and the resolver contract to **2.1.0**: a
document that validated yesterday does not today, and that is what a version
says.

**The reading path contradicted itself in three places, two of them written by
the sweep meant to fix it.** The architecture note called the S2-observer
question resolved and said none of the three models is selected, in one sentence;
its minimal-deployment line still described one operator running two providers
where the deployment annex requires one; and the reviewer guide cited the
superseded record under a label a blanket replacement had mangled. The decisions
index promoted a superseded record's analysis into *Analysed is not decided*
without saying it was history; the generator marks it now.

**Two of the previous edition's own additions were defective.** The provider
descriptor added for the recipient side shipped with no entry in the demonstration
trust store, so the documented verification mode refused it while the bar stayed
green — the bar ran only the demo-signature mode, which never reads the store.
The entry is there and the bar now runs the documented mode. And the rule added
to make an unsupplied verification input a finding checked a key only when it
matched the argument's own name, exempting every alias and every typo — of a
field added to record exactly those cases. It is structured now, and the one alias
in the registry is checked.

[`OPEN-ITEMS.md`](OPEN-ITEMS.md) §2 described the withdrawn participant kind's
admission as decided and awaiting implementation. The register's single provider
kind is a decision, not a stage, and the agenda item closed with it.

## Edition r37 — 2026-10-06

**The receipt key must be reachable, and checked. No artefact version moves.**
The previous edition moved the Delivery-Service receipt key from the customer's
discovery document to the provider's own descriptor, where a provider's key
belongs. The schema move was real. The verifier's half of it was not, and this
edition is the half.

**It was a rename.** The function that resolves the key read the published key
list off whatever document it was handed, and the argument had simply been
renamed: handed the OLD version of a customer's document — which still publishes
the key — it resolved the receipt and returned a delivery instant. The reference
already carried the sentence *a key published only in a customer's document must
not resolve, or the move would be a rename*, and it was a property of the prose.
The check now refuses a document that is not a provider descriptor, one belonging
to a different provider than the receipt names, and a receipt that names no
provider at all. The test meant to forbid this handed in a document with no keys
at all, so it was refused for having nothing to resolve: it proved the property by
proxy and passes unchanged against the unfixed function.

**And the key could not be supplied.** The bundle verifier could take a provider
descriptor, and the command that verifies a bundle read no manifest entry for one
— so after the move a retained receipt could not be verified from the command
line at all, whatever the bundle supplied. No shipped bundle carried a receipt, so
nothing noticed. The identical omission had happened one cycle earlier to another
input, and the verifier carries its own note about it.

| Artefact | This edition | Previous |
|---|---|---|
| Umbrella profile | **2.1, edition 2026-10-06** | 2.1, edition 2026-10-06 |
| TS-shaped QERDS binding | **v0.36** | v0.36 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | **2.2** / 2.7 / 2.2 | 2.2 / 2.7 / 2.2 |
| BW-PROVIDER provider descriptor | **1.1** | 1.1 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **15.0.0** | 15.0.0 |

**A shipped bundle now retains a receipt**, so the rule is exercised by the
conformance bar instead of by a hand-built call. The receipt is the one behind the
availability-grade delivery evidence, generated from the octets that evidence
commits to and dated at the instant it published; the generator refuses to write
one that disagrees with either. Two provider descriptors travel with it, so
choosing the right one is a decision the verifier has to make rather than a
single candidate it cannot get wrong. A second descriptor had to be added: the
receipt belongs to the recipient's provider, and the only one this study shipped
was the sender's.

**What makes an input reachable is now stated and gated.** The retrievability
registry says, for every input a retained-evidence verification can take, how the
material REACHES a verifier — and a bundle entry the verifier does not read is a
finding rather than a documented input. That is the rule that would have caught
both omissions. It also records what a reader could not otherwise discover: one
input arrives under a different name than it has, two are the verifier's own
configuration, and one is supplied by nothing because no operation produces it.

**Three decision records claimed more than they should.** One, superseded three
weeks ago and never implemented beyond its relay, still carried a planned
implementation and named two questions as open — and the decisions index rendered
that as a plan that stands. The check accepted it because it asked whether a named
question is a real row on the review agenda, and a row stays on the agenda after
it closes: existence was never openness. The check now reads the agenda's own
closure markers, and it found the same defect in two records this round had not
set out to look at. Nothing in the superseded record's body changed — it is the
analysis the current decision rests on.

## Edition r36 — 2026-10-06

**One provider role. Nothing changes on the wire.** A decision taken in September
separated the delivery service from the evidence provider, each with its own
identity, admission, descriptor and interface. The consultation asked for the
opposite, and [`SBM-ADR-0015`](docs/adr/SBM-ADR-0015.md) folds the delivery
service into the registered delivery provider: one accountable, qualified,
supervised party carries the ciphertext, observes the handover and attests to it.
It supersedes [`SBM-ADR-0004`](docs/adr/SBM-ADR-0004.md), whose reasoning stays
readable where it was written. The cost is recorded in the decision, not softened:
transport and evidence are no longer separable markets, the provider sits in the
data path of every delivery, and the privacy argument for separation is given up.

Nothing on the wire moved because nothing on the wire ever carried a second
provider's identity: no schema, contract, CDDL rule or sample named one, and the
federation register has only ever admitted registered delivery providers. The
second role lived in the words — 119 places in the specification set, across the
umbrella, the Internet-Draft, the TS-shaped binding, nine companion documents,
four figures, two discovery schemas, the rule-ownership inventory and the review
agenda; and six more in this study's own README, executive brief and open-items
list, which are not carried from the specification and were corrected here.

| Artefact | This edition | Previous |
|---|---|---|
| Umbrella profile | **2.1, edition 2026-10-06** | 2.1, edition 2026-09-18 |
| TS-shaped QERDS binding | **v0.36** | v0.35 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | **2.2** / 2.7 / 2.2 | 2.1 / 2.7 / 2.2 |
| BW-PROVIDER provider descriptor | **1.1** | 1.0 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **15.0.0** | 15.0.0 |

**Two discovery documents moved, because a key is published by whoever holds it.**
The receipt that dates an availability-grade delivery is signed by the delivery
service, and the delivery service is the provider's own function — so the key that
signs it is published in the provider's descriptor, **BW-PROVIDER 1.1**, sealed by
the provider's own descriptor key and checked against its admission at the
receipt's instant. **BW-MED 2.2** no longer names a transport provider and no
longer carries its keys; it names the entity's registered delivery provider and
the endpoints that provider serves, its delivery service and KeyPackage pool among
them.

**The figures were the half a text sweep does not reach.** The four-corner
architecture now draws each delivery service inside its provider's boundary rather
than beside it, and says whose decision that is. The federated flow's two
transport participants became the providers' own delivery services. The
identity-proof map stops planning a descriptor for a role that no longer exists.
Correcting their alt text found a line where the recipient's provider signed the
handover receipt and, one clause later, no published operation carried that
receipt to a provider — and a figure claiming a single operator runs two providers
in the minimal deployment profile, where the normative table requires one.

**This study's own words were the last to be corrected, and they were the most
read.** The architecture roll-call said four parties; it is three. The assumptions
said a second provider "which need not be qualified" is admitted all the same.
The executive brief described that provider as a participant in its own right,
admitted under its own identity, with its admission decided and not yet on the
wire. [`OPEN-ITEMS.md`](OPEN-ITEMS.md) §8 described delivery evidence across two
providers and listed the question beneath it as open with three models analysed
and none chosen. §8 is now *Delivery evidence inside one provider*: **A1 stays
open** — no published operation carries the handover receipt to the party that
issues the delivery evidence, a gap now inside one provider rather than between
two, and no smaller for it — and the question beneath it is closed, the observer
being the provider.

**The check that was supposed to make this complete was counting the acronym.** A
sweep of the documents reported 113 occurrences closed and none left; a gate was
added so the next one cannot drift back. It matched the abbreviation, which is not
the role: outward-facing prose spells things out, and this study's brief spells it
out. Six more places were named in words the gate could not see, including the
umbrella's own example of a discovery document, which published a field the schema
had removed and a version two releases old — a reader copying it would have
written a document the shipped linter rejects. The gate now matches the role
however it is written, and the example is the shipped sample's shape, field for
field. What no gate reads is stated rather than implied: an embedded example is
prose, and nothing holds this study's JSON blocks to the schemas they illustrate.

## Edition r35 — 2026-09-29

**No artefact version moves and nothing changes on the wire.** The independent
verification of the previous edition confirmed its three outstanding observations
closed and repeated the go-ahead for expert review. It recorded one optional
wording improvement, explicitly not a reason to wait — and it was an overclaim of
the kind these editions have spent a week removing, so it is corrected rather
than carried into the edition that gets circulated.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **15.0.0** | 15.0.0 |

**One sentence claimed more than the document does.** Marking the one step that
reads the service's internal state, the previous edition wrote that every other
step in the walk-through is a published call. It is not. The walk-through also
records work a party does for itself — a device assembling its pre-join proof, a
recipient re-checking the parts it received — and those are named for what they
do rather than written as though an operation served them, which is why they need
no disclaimer. The sentence now says what is true: the walk-through mixes
published calls with local processing, and the one step in question differs in
kind, because it reads state that no operation exposes.

The check that guards this had the same reach in its own description, implying it
compared every step against the published contracts. It checks how a step is
presented. Comparing the contracts themselves is a different check's work, and it
now says so — a check that overstates what it proves is the same fault one level
down.

**On the review record.** Four rounds of independent verification stand behind
this edition. The first two found real faults in corrections this study had
already declared complete, including a required flow whose input the contract
never published and a generated document that contradicted itself on the page.
The last two found nothing blocking. Both the faults and their corrections are in
the entries below, because a study that records only its successes is the kind of
document this one is trying not to be.

## Edition r34 — 2026-09-29

**No artefact version moves and nothing changes on the wire.** An independent
verification of the previous edition returned a go-ahead — suitable for
publication as an exploratory design study inviting expert review, with every
outstanding correction from the two preceding rounds confirmed closed and no
blocking regression found. It recorded three items that did not justify holding
publication. They were cheap, and two of them were introduced by the previous
edition's own corrections, so they are closed here rather than carried.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **15.0.0** | 15.0.0 |

**A step in the walk-through read like a published operation and was not.** The
previous edition added a read of the confirmation state so the page would show
what the three acts before it produced, rather than asserting it in prose. That
was the right correction, and it was labelled as though a published operation
served it. None does: the value is read straight from the reference. In the one
document whose whole purpose is to show what the published surface can do, that
would have sent an implementer looking for an endpoint that does not exist. The
step now says on the page that it is not a published operation, and a check
requires every step either to be one or to say it is not.

**A refusal whose reason was not text crashed before anything could refuse it.**
The check for a registered reason ran before the check that the reason was text
at all, so a structured value raised an internal type error instead of a refusal.
The published request definition rejects such a value, so this was reachable only
by calling the reference directly — but a component whose refusals are all typed
except for one shape of input is still a rule an implementer cannot follow.

**And a count kept by hand, removed rather than corrected.** The review agenda
stated how many steps the walk-through contains; adding the state read-back made
that number wrong, as it had been once before. The agenda now describes what the
walk-through covers and leaves the counting to the generated document — the same
correction the custody inventory received a day earlier, applied to the number
that occasioned it.

## Edition r33 — 2026-09-29

**Contract-breaking.** An independent verification of the previous edition found
three of its six corrections complete and three only partly done. All four
residuals are closed here. The first is the plainest kind of fault: the previous
edition shipped a generated document that disagreed with itself, and the
disagreement was printed on the page.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **15.0.0** | 14.0.0 |

**Three acts the walk-through described as successful were refused.** The
previous edition carried the sent message into the confirmation stage — its
identifier and the policy that governs it — and left the example's *original*
commitment to the transmitted bytes. A confirmation that names one message while
committing to another message's bytes is not about that message, and the verifier
refused all three, correctly. The document then printed those three refusals
beneath headings saying that the first act counts, that the retry counts once,
and that the acceptance policy is satisfied.

The check added alongside that change asked whether the sent message's identifier
**appears** in the confirmation section. It does — the mismatch example carries
the same identifier — so the check passed while every act it was meant to
describe failed. An outcome is not evidence of a state transition, and a passing
check is not evidence about a generated page.

A confirmation now commits to the message it is about: the transmitted bytes, the
group state, the session and the declared payload, every value the verifier
compares. The walk-through reads the resulting state back as a step of its own,
so the page **shows** that the policy is satisfied and which two members counted,
rather than asserting it in prose. Three checks now assert the transition itself,
one of them simply refusing to let a step whose prose claims success be rendered
as a refusal.

**Two malformed requests escaped as untyped errors**, one of them introduced by
the previous edition's own correction. A refusal carrying an unregistered reason
skipped the check on the request's shape — that check was conditional on the
reason being known — and fell through to the proof's fields. And a refusal naming
a cipher suite the registry does not know reached the new key resolution, which
recomputed the package's identity under the suite the *request* supplied. The
reason, the shape and the claimed suite are settled before any cryptography now,
and the package is resolved under the suite the **retained reservation** records,
never a value the caller supplied. Neither case spends the device's single-use
value or changes any state.

**The contract contradicted itself about one field.** The response that delivers
the single-use refusal value allowed a one-character value; the proof that must
quote it required eight. A response its own validator accepted could therefore
carry a value the client was forbidden to echo. One shared definition now,
referenced by both, and the regression asserts that the two **agree** rather than
asserting the number. Because the delivering side tightens, the companion
contracts take a major version.

**And two summaries that restated a generated inventory** — the review agenda and
the lifecycle note — still carried the count and the blanket claim that the
inventory itself had corrected a day earlier. They link to the generated document
now instead of restating figures that go stale as it grows.

## Edition r32 — 2026-09-28

**Contract-breaking.** A refusal flow that could not be carried out, and a
signature checked against the wrong key. A publication-readiness review of the
previous edition raised six points; all six are corrected here, and two of them
mattered.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 2.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **14.0.0** | 13.0.0 |

**A device could not obtain the value its refusal had to sign.** The previous
edition made the pre-join proof mandatory: refusing a group invitation before
joining requires a signature over content that includes a single-use value the
delivery service issues with the invitation. That value was never published. The
response a device receives did not carry it, and the response's schema — which
rejects anything it does not describe — could not have carried it. **So the
specification demanded a proof whose input nobody holding the specification could
obtain.**

It looked finished because the reference's own client helper fetched the value
from the service's internal state, which is an access no real device has, while
the comment directly above that code said the value is never supplied by default.
A statement that was false, sitting exactly where a reader would go to check.

The value is now a required part of the response, and the helper refuses to
proceed without it rather than looking it up. Because a service that does not
deliver it cannot support the published refusal flow, the companion contracts
take a major version.

**And the signature was checked against the wrong key.** The point of a pre-join
proof is that it is verified against the key carried by the exact invitation
package the device was given: a device that has joined nothing has no published
document and no wallet key to be checked against. The reference recomputed a key
from the device's name instead — the same name the test fixtures use, so the two
always agreed and no test could tell them apart, while the error message said the
package had been consulted.

Putting a different, genuine key inside the package showed the inversion plainly:
a refusal signed with the key the package **actually carried** was rejected, and
one signed with a key that was **not in the package at all** was accepted. The key
now comes from the retained package, whose reference is recomputed over those
bytes before it is trusted.

**A trace that claimed more than it showed.** The generated walk-through of the
published operations says the stages compose in order, with the values the run
produced. They did not: the sending stage sealed one message, the delivery stage
took its group from a fixture, and the confirmation stage confirmed a different
message entirely. A fault stopping the sent message from reaching confirmation
would have left every heading in place and the document looking correct. One
message now crosses every stage, and the check is made against the run rather
than against the finished document.

**Four overstatements in the new custody inventory**, corrected. It called the
entity's messaging descriptor the document that pins every other sealing key —
the registry's directory record does that. It said a chain of policy versions can
show the pinned one was the latest, which is precisely what such a chain cannot
show and what the inventory's own next sentence said. It said an unopened
commitment keeps the message's class hidden, when what it withholds is the
committed value and not every inference about the message. And it promised one
consequence for every missing input, where the consequences differ. Reviewing it
turned up something the review had not: two trust anchors were missing from the
inventory altogether.

Two smaller corrections: a malformed proof now produces a typed refusal that
changes nothing, rather than an untyped error; and dispute evidence embedded in a
package is now checked against its own definition, as every other embedded object
already was.

## Edition r31 — 2026-09-28

**Access-breaking, and deliberately.** Two published operations now require the
authentication the specification always said they required. Nothing changes on the
wire for a message, and no evidence version moves.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| EDD resolver contract (OpenAPI) | **2.0.0** | 1.13.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **13.0.0** | 13.0.0 |

**An entity's complete member roster was readable by anyone.** The umbrella gives
every published resolver path exactly one access rule, in a table that says of
itself that the resolver contract is the full contract — so the two are
descriptions of one thing. Nothing compared them, and for two paths they
disagreed.

The signed roster snapshot is an entity's *complete* membership at one point in
its history: every active member, their roles, each pinned to the exact published
binding that described them. The umbrella required an authenticated counterparty
to read it. The contract asked for nothing, and there is no reference
implementation of that surface to settle the difference — so anyone generating a
client from the published document read an organisation's internal structure
without identifying themselves.

What makes it plainly a fault rather than a judgement call is the operation
beside it. The ordinary member listing — paginated, explicitly non-authoritative,
disclosing *less* — **was** authenticated, and the umbrella says in as many words
that anonymous access to that surface is not conformant. The control was inverted
against the disclosure. The KeyPackage pointer had the same shape on a smaller
scale: the resolver serves only a redirect, so what was readable was the pointer,
but a pointer names an entity's messaging provider and confirms the entity exists
to anyone who asks.

Both now require an authenticated counterparty. That breaks any client relying on
reaching them anonymously, which is the point, and why the resolver contract takes
its first major version.

**And the check that compares the two.** The access rule each path carries is now
read from the umbrella's table and from the contract and compared in both
directions — a path the umbrella protects and the contract does not, and a path
the contract protects that the umbrella calls public — with completeness, since
the umbrella's own claim is that every path has exactly one rule. Both sides were
already machine-readable; nothing had put them beside each other.

**Who sees what, elsewhere, is now checked rather than stated.** The weight is on
the negative claims, because a claim that a party sees something is at worst
generous while a claim that it sees nothing is what a deployment relies on. The
strongest of them: the values that travel only inside the end-to-end-encrypted
envelope — the content class, and the salts that open a grade or mandate
commitment — appear in no sealed object and in no schema outside a dispute
disclosure. The salts carry the most weight, because a commitment is only as
private as its salt and the commitment itself is published in evidence by design:
a salt that reached a sealed object would let anyone holding it test a guess.

**What is still not answered**: how long each party keeps what it sees. The
evidence retention period is a regulated duty and this profile does not choose it;
for the other parties nothing is set. That is a policy question rather than
something derivable, and putting numbers here would be the kind of over-claim this
edition removes.

## Edition r30 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** One of the four
deferred implementer questions is now partly answered: what changes at a key or
role transition, and what a provider's migration or exit does to evidence already
issued.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **13.0.0** | 13.0.0 |

**The transition claims are now checked rather than asserted.** The lifecycle
document states, for each change an organisation goes through, what happens to new
traffic, to messages in flight and to evidence already issued. Those statements
were prose, and a reader acting on one had nothing to tell the author when it
stopped being true. Every one of them is now a check, and a guard fails if a
change is described without one.

They all hold. A replaced device is a **new enrolment** and inherits nothing,
while the item already queued for the device it replaced is untouched. A policy
version published after an act leaves the version that act pinned alone — and one
already in force at the act is reported, because then the message pinned a
superseded version. A member suspended or retired afterwards keeps its
acknowledgement.

**And they hold for one reason worth stating plainly: verification reads the
documents a verifier was handed, never live state and never an address.** The
strongest form of that is now asserted — rewrite *every* endpoint in an
organisation's discovery document to point at a different provider, and its
evidence verifies exactly as before.

**Which is why what remains of the question is custody.** A verdict is only as
durable as somebody's willingness to keep answering the read that supplies it, and
nothing said which reads those were. A new document now says it per input: what the
material is, which published read retrieves it, who serves it, what its absence
does to the verdict, and whether that survives a provider exit. **Of seventeen
inputs a verification can take, ten depend on material a provider exit leaves with
no named server.**

Exactly one historical read is served by a party that is *not* the exiting provider
— the federation register's admission history, held by the Federation Authority —
and that is the shape the others lack. The asymmetry underneath it is worth seeing:
the evidence itself has a second independent holder by design, because each party
keeps its own copy, while most of the material needed to *check* that evidence has
only one.

The failure is **graceful**. An absent input degrades a verdict to *incomplete* and
never to a silent pass — the specification already had rules whose whole job is to
say "the material to decide is not here". So this is a gap in what has been
specified, not a fault in what has been built, and saying which it is decides how
much machinery it deserves.

**The new document is generated and gated, not written and trusted.** It is checked
against three things the tooling already states for itself: every input the
retained-evidence verifier accepts, every rule that reports material as absent, and
every published read that takes an as-of selector. It caught two mistakes in its own
first draft — a rule no input claimed, and an input asserting that nothing publishes
retained group state when a published read serves exactly that. The second was worth
more than a correction: the gap there is that nothing publishes the **bytes** that
read serves, which is the opposite shape from every other input, where the interface
is settled and only the custody after an exit is not.

**What is still not answered**: which party serves the history for acts before a
provider change, and what becomes of each item still in flight when a provider
exits. Both would change published surfaces, so they are left as decisions to be
taken deliberately rather than folded into an analysis.

## Edition r29 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** An external
verification of edition r27 found four of its seven points closed and three only
partly. All three are corrected here. One of them was a verification bypass, so
this edition supersedes r28 for any reader assessing recipient attribution.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **13.0.0** | 13.0.0 |

**A recipient's proof is now verified against its device's published key
whichever field carries it.** The bundle verifier selects the recipient-side
proofs from a set derived from the schemas, and the check against the device's
published confirmation key ran *after* that selection, on whichever proof the
selection happened to reach last. For evidence carrying a recipient confirmation
or the new validation-failure assertion and no delivery attestation, it ran on
nothing at all — so a proof naming a known, active member and device and signed
by an **unrelated key** was accepted. Nothing else objected, because the member
really did exist and the membership check really did pass.

That was a regression introduced by the previous edition's own work. The earlier
code named the two fields explicitly and checked whichever was present; replacing
that with a derived set left the check reading a leftover value. It stayed
invisible because the single shipped counterexample put its proof in the one field
the leftover happened to hold. The check now takes the proof it must examine as an
argument and runs once per proof, and twenty-three counterexamples are
parametrised over the field *name* — foreign key, altered signature, missing
anchor, another device's key, alone and inside a package — because a check whose
answer depends on which field carries the proof is precisely the defect.

**A recipient's assertion is now checked against itself.** What one part's detail
says about itself needs nothing from the sender, but those checks sat behind two
early exits — one taken when the sending evidence was not at hand, one taken for
every claim that a part was undescribed. A digest mismatch whose two digests were
**equal** therefore passed verification from retained evidence and failed only
once the sending evidence was supplied, which is how we know the dependency was on
the order of the code rather than on the evidence. And a part claimed undescribed
could carry a digest of octets nobody received, which real authenticated intake
**sealed** as a terminal outcome.

Validation is two layers now. What the assertion says about itself is checked
first and always: the fields each cause requires and forbids, a claimed mismatch
whose values actually differ, two digests from the **same** algorithm (digests of
different algorithms differ whatever the octets were, so their difference is not
evidence of anything), a digest mismatch that does not also claim differing
lengths — that is a length mismatch, the more precise cause — and a length
mismatch whose lengths differ. The per-cause table is taken from what the
recipient's own code emits, so no rule in it can be broken by an honest report.
What only the sender's manifest can settle is checked after.

**What a mandate commitment establishes now reads the same on every path.** The
binding specification carried the corrected account; the normative definitions,
the profile's threat table and the verifier companion still said the commitment
made the agent's *conduct* provable. A reader following one and a reader following
the other got different answers about one construction, and the normative document
was the weaker of the two. All three now state what a valid opening establishes —
the class the sender **committed to**, and whether that declared class lies within
the mandate's scope — and what it does not: no party to a reveal inspects the
plaintext, so a sender could commit to a permitted class and encrypt something
else. The guarantee that remains is kept rather than flattened away: revealing an
out-of-scope class still establishes overreach **in the declared act**.

**And two faults in the previous edition's own example.** It named one acceptance
policy key while the sending evidence it reports on names another — an assertion
incoherent with the message it claims to be about — and it claimed a digest
mismatch while also reporting differing lengths, which no recipient can produce,
because a wrong length is reported as the more precise cause and stops there. Both
were invisible for the reason above: a standalone outcome was never checked against
the evidence it refers to. The example's detail is now generated by the recipient's
own code, and a check keeps it that way.

## Edition r28 — 2026-09-27

**Contract-breaking.** A refusal made before joining a group now carries a proof,
and the published request describes it. Two of the review agenda's open questions
are answered, and the check that would have caught both is now part of the bar.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.12 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **13.0.0** | 12.0.0 |

**A device refusing a Welcome now proves it holds the package it is refusing
for.** Possession of a KeyPackage reference was treated as authority to refuse
against it — but that reference is a digest of the package's public bytes, held
by the group's creator and the delivery service alike, so anyone who had seen it
could refuse in the device's place and strand an invitation. The refusal now
carries a signature under the KeyPackage's own leaf key (RFC 9420 §5.1.2
`SignWithLabel`) over typed content including a single-use nonce the delivery
service issues. This is deliberately a *pre-join* proof: a device that has joined
nothing has no published document and no wallet key to be checked against, so the
package it was invited with is the only thing that can speak for it. The nonce is
spent on acceptance, not on arrival, so a recoverable rejection does not burn a
device's one attempt, and an exact retry converges before the proof is examined.

**The published request describes that proof.** `WelcomeRefusalRequest` now
requires `refusal_proof` and references a named `WelcomeRefusalProof` stating the
scheme, the label, the exact deterministic-CBOR content and the nonce's single-use
rule — and the reference *executes that request* rather than checking beside it.
The previous edition's contract asked for "a signature over the request binding"
and named no binding; a requirement whose content is left to the reader is the
same gap as a missing one.

**One run through the published operations, generated by driving the reference.**
A new trace walks formation, sending, delivery, confirmation and the multipart
outcomes in order, with the negative and retry branches and what each call
returned. It is generated from the reference's own entry points, so it cannot
describe operations that do not exist; it is not an interoperability result.

**And the check that would have caught the contract gap.** Every concept here is
described more than once — a JSON Schema, a CBOR definition, a contract
component, the reference. Nothing asked whether a concept reaching one of those
surfaces reached the others, and twice in two days the answer was no: the signed
assertion the previous edition corrected, then the refusal proof above. Both were
found by a person reading two files side by side. A new gate asks it mechanically:
every field a published evidence Schema declares must be exercised by at least one
sealed example, because an example is what binds the Schema, the CBOR definitions
and the reference's readable form to one account of it — and the reference's
request surface must match the published contract in both directions.

Thirteen fields were declared and never exercised, and the gate found two live
defects on arrival. Composing the first example of an evidence package carrying
dispute evidence showed that the package embedded that evidence in the sealed
bytes and left it out of the readable projection: a package carrying a dispute
sealed a document its own readable form denied. And that same example sent the
schema validator to the network for a definition its offline store had never been
given, because the only reference reaching it was the one nothing had exercised.
Five new examples close all thirteen fields, two of them exercising branches of
evidence types — an intake-stage rejection, and a re-packaging transformation —
that no example had ever reached.

The gate's scope is stated rather than assumed: it covers the evidence schemas,
whose bodies have both a CBOR definition and a JSON Schema. Where a document has
only one strict description there are no two representations to hold together,
and a check claiming otherwise would be theatre.

## Edition r27 — 2026-09-27

**Wire-breaking.** A second external review, of the previous edition, recorded
seven points. All seven are addressed here; three changed the protocol or the
tooling that verifies it.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.12** | 2.11 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **12.0.0** | 11.0.0 |

**The recipient's validation-failure assertion is now defined in every
representation.** The previous edition introduced it in the JSON Schema, the
wallet contract and the reference runtime — and not in the CBOR definitions, so
the reference sealed an outcome an implementation following those definitions
refused. The definitions carry it now, with its signed and session-authenticated
forms and its per-part detail, and the example outcome is checked against the
JSON Schema, the CBOR definitions and the verifier together rather than one of
them.

**A signed assertion names the device whose key signed it.** The CBOR
definitions have required that of a signed recipient confirmation since they
were written; the JSON Schema did not, and the two disagreed about the same
object. Both require it now — the narrowing that moves the evidence version.

**And the verifier checks the assertion it is given.** Signature verification,
the production identity precheck and the member resolution each worked from a
hand-kept list of proof fields, and the new assertion was in none of them: a
recipient proof with an invalid signature, wrapped in a valid provider seal,
raised nothing. The lists are derived from the schemas now. A recipient's
observation of its own received content still cannot be checked by anyone
else — the parts are encrypted and absent, which is why the assertion is
attributable rather than provable — but the **sender's** side of each comparison
is in the sending evidence, and an assertion that contradicts it is refused
before anything is sealed.

**One status for the envelope transformations.** The previous edition deferred
re-packaging and chunking in the specification and the open questions, while the
TS still called them the only permitted transformations and required evidence
for them, and the reading path still described them as available. An implementer
could satisfy the prohibition or the duty, not both. All of it says one thing
now: neither is profiled, a provider must not issue either, a verifier treats one
it meets as unproven — and the duty to evidence a transformation survives, for
whatever a later revision defines.

**Claims bounded where a specialist reader meets them.** The agent branch said
that before a dispute neither the mandate nor the class is disclosed. The
commitment discloses neither; the published mandate scope and the resolved
routing scope disclose what the privacy analysis says they disclose. And opening
a mandate commitment proves the class the sender **committed to**, not that the
committed class describes the encrypted document — the limit the grade
commitment already carried, now stated for the mandate too.

**The rationale for MLS argues from what it supplies.** The previous edition's
answer excluded alternatives on grounds that do not hold — it said a
key-agreement-per-message design leaves the device set to who is online, where
published-prekey and single-shot constructions exist precisely to encrypt to an
absent recipient. The record now sets out what MLS carries natively, what a
pairwise base would oblige this study to specify and prove itself, and which
single requirement is a boundary rather than a cost. Assurance and complexity,
not impossibility.

**And the framing edition is not a wire field.** The previous edition said an
envelope "declaring 1.4 or later" carries the specified multipart layout. The
envelope headers declare no version: the edition is the one an implementation is
built to, agreed out of band, with no in-band negotiation. The rule is unchanged
and the implication that a field exists is gone.

## Edition r26 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** One correction,
and the check that found it.

**The document map described the decisions index by columns it no longer has.**
It said the index gives "the alternative weighed, the benefit, the cost and who
pays, the status" — the nine-column shape the previous edition replaced, the same
day, with the choice, its principal trade-off and the two statuses. The
description in this snapshot and the one in the study's source repository agreed
with each other and were both wrong, which is why nothing caught it: a claim
about a generated document's shape is bound to no gate in either repository.
Both now describe the index as it is, and say that the alternative and the full
cost are in the record each row links to.

**What found it is new, and it works across the two repositories.** Five files
here are this snapshot's own and are carried forward when it is rebuilt rather
than taken from the source: this README, the open items, the changelog, the
contributing guide and the brief. Two of them have a counterpart of the same name
in the source, saying many of the same things in their own words — and nothing
compared them. In one working session three corrections had to be applied twice
because of it, the sharpest being a claim about what the repository's checks
establish, which was bounded on one side and left unqualified on the other.

The rebuild now compares the **structured claims** the two sides both make —
every table present in both documents, row by row — and refuses to publish an
edition where a shared row differs without a recorded reason. Prose is
deliberately not compared: the two documents are written for different readers,
and rewording one is the point of having two. Differences that are deliberate are
declared with their reason and pinned to the exact wording they excuse, so a
later change on either side has to be looked at again rather than inheriting an
old exception.

## Edition r25 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** This edition is
about how the study is approached rather than what it specifies: the external
review of edition r23 asked for changes to the reading path, and they are here.

**The route now begins with the problem.** It began with the architecture, so a
reviewer was judging a solution whose problem statement they had not seen. A
**step 0** states what registered delivery between legal entities has to achieve,
which requirements come from outside, which are this study's own choices, and
what is deliberately out of scope — with the requirements list this snapshot
carries named beside it.

**Why MLS at all** was recorded as an unanswered question, and it is the one an
architectural reviewer asks first. The group-topology decision record now answers
it from the requirements the choice was made against: delivery to a party who may
be offline for days, every enrolled device of an entity able to receive, a group
whose membership is itself the subject of proof, and a provider that never holds
content keys. It states what those requirements exclude in kind, what the choice
costs — persistent group state, roster synchronisation between organisations that
hire and dismiss independently, epoch handling, key-material supply, coordination
with a delivery service neither party controls — and, deliberately, **what MLS
does not give this profile**: it does not make delivery evidential, does not
identify a legal entity, does not timestamp anything a court would accept, and
does not decide who may accept a message. Those are this specification's own
work. What remains unanswered is narrower and says so: no named competing
protocol is assessed.

It sits in a new kind of section in the decision records — *why this choice* —
kept apart from *alternatives considered*, which weighs options inside a shape
already chosen. A reader asks the first question before the second.

**The decisions index is a map again.** It had nine columns and had become a
document to study rather than an index to choose from. It now gives the choice,
its principal trade-off — what it buys and who pays — and the two statuses, with
the alternative, its rejection and the full cost in the record itself, one click
away.

**Pointers that led nowhere for a reader of this snapshot.** Several documents
referred to a historical trust analysis by bare path, in a directory this
snapshot does not carry. The three models it analyses are in the decision record
on separating the messaging and delivery providers, which does travel, and every
document points there now.

**And four smaller corrections.** The reviewer guide opened by explaining two
review counters and the mistakes earlier readers had made with them; the
distinction is kept and the anecdote is not. A lifecycle heading counted four
state machines above a table of five. The evidence explainer's corrections
appendix kept four entries, two of which were bookkeeping; those are dropped,
and the document says they were. And the first claim in the claim matrix — that
the repository agrees with itself — is now bounded by what the checks actually
verify: external reviews have found real inconsistencies with every check green,
and each time the answer was a new check.

## Edition r24 — 2026-09-27

**Wire-breaking.** An external review of the previous edition found seven points;
all seven are addressed here, and two of them changed the protocol.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.11** | 2.10 |
| Application envelope | **1.4** | 1.3 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **11.0.0** | 10.0.0 |

**A recipient can now report a multipart failure it detects.** The previous
edition required a recipient to check each received part before the manifest
digest, and then directed every failure into the ordinary digest-mismatch
outcome — which requires the recipient's recomputed value to differ from the
sender's. For a multipart message it cannot differ: the payload digest is the
digest of the **manifest**, so a recipient whose received parts are wrong
recomputes the same value the sender declared, and a payload that is not the
specified layout yields no parts to describe at all. A recipient could therefore
**detect the failure and have no way to report it** — it would have had to invent
a digest, assert a comparison it never performed, or stay silent and let the
message expire.

There is now a distinct outcome for it: an attributable assertion by the
recipient, bound to the message, to the octets it decrypted and to the commitment
it was checking, carrying a typed cause — a part's digest, its length, a part
absent, a part the manifest does not describe, a duplicate identifier, or a
payload that is not the layout — and the per-part detail where parts exist. It
carries **no recomputed payload digest**, because there is none, and an observed
digest appears only for the one cause where a comparison was actually made. The
intake-stage refusal code is **not** reused for it: that code belongs where
nothing has been decrypted and no recipient has spoken. Single-part messages are
unaffected, and their digest-mismatch outcome is unchanged.

**And two provider transformations are withdrawn from use.** A
Change-Indication Evidence may record that a provider re-packaged the transmitted
envelope or split it into several, committing to the input and to each output.
Neither operation is defined. The output commitment is typed as a hash of a
**complete** wire message, which a fragment is not; re-packaging an unchanged
message in an outer wrapper leaves the inner bytes untouched, so the output
commitment equals the input; and no published contract defines a fragment
descriptor, a chunk order, a reassembly operation or the boundary at which the
original message is reconstructed. Two providers given the same message could not
perform the same transformation, and no verifier could reproduce either.

So a provider **must not** issue either transformation until this is defined, and
a verifier that meets one **must** treat the transformation as unproven rather
than as an attested re-framing: the seal still establishes who attested what, and
the relation of the outputs to the input is what nothing establishes. The
retained-bundle verifier reports it as an unproven property, alongside the
policy-history completeness it already reports, and the open question records what
a definition would have to pin.

**The previous edition's closure of the chunked-part question stands, on
corrected ground.** Nothing in this profile splits a content part — that is true
whatever happens to envelope framing — and citing the envelope transformations as
a defined operation in its support was wrong.

**Three introductory corrections, where a reader meets them first.** The executive
brief said nobody learns from the evidence what kind of content was exchanged; the
commitment discloses nothing, and the routing scope reference resolved against the
recipient's published map gives the set of classes that scope covers — a scope
covering one class gives that class. The first architecture figure placed protocol
change control inside the federation authority's box, merging two authorities the
profile keeps apart; it now draws both. And the README said there was no
transport-security underlay, where the profile specifies ordinary HTTPS beneath
MLS and says only that the security claims do not rest on it.

**A compatibility boundary that the previous edition did not name.** Defining the
multipart layout added no field and re-sealed nothing, so it was reported as
moving no version — but a layout previously unconstrained became the only
conformant one, and an implementer had no number to name in order to say which it
implements. The application-envelope version covers the layout of the application
data as well as the headers, and it moves with this change.

## Edition r23 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** Two open
questions close and one defect in a recipient obligation is corrected — the
last of which an implementer reading the previous edition would have got wrong.

**How a multipart payload is laid out is now specified.** The manifest described
the parts of a multipart message and bound them, and no document said how a
recipient finds a given part's octets: no delimiter, no length-prefix framing, no
reference to an existing multipart format. Two independent implementations could
satisfy every rule in the profile and fail to exchange one multipart message. The
payload is now the deterministic-CBOR encoding of an array of
`{part_id, octets}` records, in the manifest's own canonical order, carrying
exactly the parts the manifest describes. Keyed by part identifier rather than by
position, because a fixed-position encoding is one silent reordering away from
attributing one part's octets to another part's descriptor. The payload is
therefore self-describing: a recipient that has decrypted the envelope splits it
without holding any evidence. Single-part messages are unaffected.

**And a recipient obligation that could be satisfied without reading the
content.** For a multipart message the payload digest is the digest of the
*manifest*, not of the plaintext — while the re-verification rule said only that
the recipient recomputes the payload digest over the decrypted plaintext. A
recipient could therefore hash the manifest it already held, compare it with
itself, and **confirm a match for a message whose every part had been replaced**.
The rule now states two recomputations in order: each part's digest from the
octets received, compared with the manifest including its declared length, and
only then the manifest's digest against the declared payload digest. A failure is
reported exactly as any digest mismatch is, through the recipient's mismatch
confirmation; no new outcome is introduced.

**The published multipart example now proves the framing.** Its manifest is
reproduced from the two part files this snapshot carries, through the specified
layout, so an implementer who builds a payload as specified arrives at the digests
published here.

**A chunked part's digest: the question does not arise.** Whether such a digest
should ever be a Merkle root was open. This profile has no chunked part: the
framing operation it defines acts on the **envelope** — a provider may re-package
it or split it into several output envelopes, recording the operation in
change-indication evidence that commits to the input and to each output — and the
TS confines permitted transformations to the envelope and its metadata, because
content cannot be transformed under end-to-end encryption. A sentence permitting a
"very large part" to be chunked in transport named no descriptor, no evidence of a
split and no size at which a part becomes large; it is withdrawn, and the
invariant it existed to state is kept: **a part's digest is over that part's
octets whatever framing carried them**, so one envelope or several produce the
same manifest and the same payload digest. If a later revision wants part-level
chunking, the mechanism comes first and the construction after; the record says so
in that order.

**The manifest's own rules, made to agree.** Nesting was described three ways —
the specification permitted one level, both machine-readable definitions made it
inexpressible, and a conformance rule guarded a depth nothing could produce. A
manifest is flat, and a part that is itself a container is one part committed by
the digest of its own octets. The rule is retired and recorded with the reason,
because an identifier is assigned once and never reused. A content encoding was
permitted with no field in which to declare one, so a recipient could not have
known whether to decode and a verifier could not have known what the digest
covered; there is no encoding layer inside the encrypted envelope, compression is
content, and the term the rules use is now defined once.

**Two quoted definitions did not match the normative one.** The specification
embeds CDDL so a reader meets the wire format where the rule is explained. One
block named a type the previous edition removed and described a reduced form its
own prose forbids two lines above; another rule was embedded twice with two
different bodies, one naming a type the normative file does not define. A new
check holds every embedded block to the file, and a deliberately illustrative
block has to say so and give its reason — and is still held to the
domain-separation tags it carries.

## Edition r22 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** This edition
makes one open question decidable: **A12**, whether the content digest should
become a salted commitment, which stays open and is now put to the reviewers the
agenda assigns it to — applied cryptography, and registered-delivery operators —
with a record they can act on.

**A residual risk was missing from the document that is meant to hold all of
them.** The specification's security considerations describe what a bare digest
over the plaintext exposes: a party holding an evidence object or a package can
**confirm a candidate document** against the digest, which is a practical
disclosure wherever the content has little entropy — correspondence on a known
template, an amount within a narrow range, a form with few filled fields. That
paragraph defers to the umbrella profile for the consolidated metadata threat
model, and the umbrella's list of what the metadata can reveal did not include
it. A reader following the pointer found five entries and not this one. It is
there now, informatively and with no new obligation: who can confirm a guess
(the parties, both providers, an archive, a verifier, a court — whoever holds the
evidence), who cannot (an observer of the network, which sees no digest), that a
multipart message widens it through the manifest's per-part digests, and that the
question is open with nothing decided.

**The decision record was corrected against the two editions published since it
was written.** It asked the reviewers about salting a chunk construction the
previous edition withdrew; it proposed retiring hash modes by name for content,
which the per-field digest domains of the previous edition made unnecessary; it
priced moving the multipart manifest into the encrypted envelope against
"provider-side structural checks" that are three named conformance rules, one of
them added in that same edition; and it named a superseded artefact version where
the rule is about the version an artefact was sealed under.

**And the agenda row itself said the profile was silent about the assumption.**
It was, when the row was written. It is not now, and a reviewer reads the agenda
before the specification — that is what the agenda is for. The row says what is
actually open, which is no longer whether to state the exposure but **whether
stating it is enough**.

Nothing here accepts the proposal. It remains proposed and not implemented, the
question remains open, and the digest is unsalted.

## Edition r21 — 2026-09-27

**Wire-breaking. A hash mode is now admissible only in the domain of the field
that carries it**, and five artefact versions move with the restriction.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.10** | 2.9 |
| Application envelope | **1.3** | 1.2 |
| BW-ORG discovery document | **2.7** | 2.6 |
| EDD resolver contract (OpenAPI) | **1.13.0** | 1.12.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **10.0.0** | 9.0.0 |

One shared hash type was referenced by fourteen sites, so **every digest field
accepted every mode the profile defines** while the normative text gave each
field a narrower one. The effects were not theoretical: an acceptance-policy
reference could declare a manifest mode — a digest of a structure — where a
verifier recomputes SHA-256 over a published document's signed payload, so the
issuer accepted an artefact its own bundle verifier refused; an intake-stage
rejection's submission digest could declare SHA-512 or a manifest mode where the
Internet-Draft requires SHA-256 over the exact submitted octets, for a request
that may never have been parsed; and a multipart part's digest could declare a
manifest mode where the value is over that part's decoded octets.

There are now three named types, and the Internet-Draft states the three domains
before the schemas enforce them:

- **content** — the payload digest and the envelope's content digest: either the
  transmitted octets or the deterministic-CBOR manifest of a multipart payload.
  The only domain in which a manifest mode means anything;
- **observed octets** — a multipart part's digest: SHA-256 or SHA-512 over that
  part's decoded octets;
- **SHA-256 over octets, pinned to one algorithm** — the rejected-submission
  digest and a referenced document's digest, which a verifier recomputes from
  bytes it holds, so another algorithm makes the value unrecomputable.

**An artefact that declares a mode outside its field's domain is refused**,
whatever else validates. The published wallet-provider contract inherited the
restriction through its own reference to the shared type, so a submission with a
manifest-mode policy digest is now refused by the contract, naming the field and
the value the domain admits, **before the delivery service is contacted** — no
transport acceptance and no evidence are produced.

Two generic envelope-digest fields that appeared in one schema and the CBOR
definitions, and in no normative text, are removed; the defined envelope
commitments are unaffected.

**What this costs an implementer.** An implementation that put a manifest mode
on a policy reference, or SHA-512 on a rejected-submission digest, no longer
interoperates — it was producing artefacts the profile's own verifier refused.
Nothing that followed the normative text has to change.

*The edition note above is written for this edition. Editions r18, r19 and r20
carried this section forward from r9 unchanged, so it described a record added
three editions earlier and said "the artefact versions are unchanged" while two
of those editions changed normative text; the dated headline is written by the
rebuild and was correct, the body under it was not. What each of those editions
did is in this repository's commit for it.*

## Edition r8 — 2026-09-26

The artefact versions are those of the previous snapshot, unchanged; nothing
moves on the wire. That edition carried four source-side corrections:

- **The patent commitment's exclusion list** in `IPR.md` §3 no longer names
  the JSON Canonicalization Scheme, which the Specification stopped
  referencing at the previous edition. The exclusion is defined by reference
  and its list is illustrative, so the perimeter is unchanged; the review
  agenda's L9 row records the call.
- **Two links into the study's historical trust analysis**, in the
  architecture note and the reviewer guide, are plain text: the analysis is
  not part of this snapshot and was never a selected design.
- **Five identifier tokens** left in reader-facing prose by the earlier
  cleanup are gone from the umbrella, the TS, the Internet-Draft, the agenda
  and the agent explainer.
- **Three tests travel again** — the licence-list, repository-prose and
  historical-record tests read what they check from the tree they run in, so
  this snapshot runs them as the source does.

---

## Previous snapshot — 2026-09-25

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1, edition 2026-09-18 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.9** |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | 2.1 / 2.6 / 2.2 |
| BW-PROVIDER participant descriptor | 1.0 |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Federation register contract (OpenAPI) | 3.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | 9.0.0 |
| TS — QERDS binding | v0.35 |

### What changed on the wire since the previous snapshot (2026-09-20)

- **Wire-breaking: evidence objects 2.8 → 2.9**, every sample re-sealed. The
  `jcs-sha256` and `jcs-sha512` values of `payload_hash.hash_mode` are removed from the profile.
  An artefact that declares either is **refused by name** (`LINT-HASH-01`), not
  ignored, and there is **no replacement mode**: deterministic CBOR is the
  profile's only canonicalisation. An implementation that emitted those modes
  no longer interoperates, and a sender whose original octets are gone cannot
  produce a conformant `payload_hash` for that payload — the profile's answer
  is to retain the bytes.
- **Every defined hash mode is mandatory to implement**: `raw-sha256`,
  `raw-sha512`, `manifest-sha256`, `manifest-sha512`. The set is closed; the
  Internet-Draft owns the rule, the TS ICS carries a row for it, and a gate
  fails if the Internet-Draft stops stating it. Adding a mode reopens the
  question of advertisement (agenda A11).
- **A privacy statement corrected.** The umbrella no longer offers a neutral
  scope name as a mitigation: `scope_ref` travels in clear and the recipient's
  published scope map resolves it, so the name hides nothing; a coarser scope
  map does. Whether the content digest should be salted is opened as agenda
  question A12 and left unanswered.
- **The reference mock's `POST /send`** returned 500 on the body the README
  documents. Fixed; the quickstart is now executed by a test that derives the
  body from the README.
- **Licence overview 1.5** for this snapshot: it names the repository it is
  published from and lists only files this snapshot contains.
- **Documentation.** The drafting ordinals and migration-step codes are out of
  the reader-facing text; the vision note and the octet migration record left
  the snapshot; the executive brief, README, CONTRIBUTING, OPEN-ITEMS and this
  file were shortened to one home per topic.
- Unchanged: the discovery documents, the envelope, the three contracts and the
  TS revision. The catalogue holds 158 rules.

### Verification

The shipped bundles verify INCOMPLETE at this edition, by design; the README's
[*three verdicts*](README.md#the-three-verdicts-and-the-two-invocations)
section shows both invocations and what each leaves unproven.

---

## Previous snapshot — 2026-09-20

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1, edition 2026-09-18 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.8** |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | 2.1 / 2.6 / 2.2 |
| BW-PROVIDER participant descriptor | **1.0** (new) |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Federation register contract (OpenAPI) | **3.0.0** (new since the previous snapshot) |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **9.0.0** |
| TS — QERDS binding | **v0.35** |

### What changed on the wire since the previous snapshot (2026-08-01)

- **Companion contracts 4.0.0 → 9.0.0** (breaking, in five steps). Delivery
  items are fanned out per device, each bound to its own member, and a
  collection token records the transfer. Group-establishment refusals are
  collected by the creator from a delivery-service queue; refusal dequeues an
  invitation, expiry is read from the reservation, and an obsolete refusal
  cannot remove a newer invitation's routing. Member and device principals are
  bound whole, `(uid, mid)` and `(uid, mid, device_id)`, in the contract and
  not only in the reference. Confirmations are per-member acts with per-act
  idempotency; a wallet can deliver a digest-mismatch proof. A forwarded
  submission carries the originating provider's sealed SE as proof of its
  namespace, and the creating device registers itself as a group's founding
  member through a device-authenticated operation. Committed single-use
  packages and creator-scoped invitation handles close the deposit-identity
  gaps.
- **Federation register contract, new: 1.0.0 → 3.0.0.** The membership
  register as an instrument of its own, sealed record by record by a federation
  authority; the register is authenticated at ingress — seal, timestamp,
  Schema, history, all or nothing — before anything in it is read; `as_of`
  evaluates a complete record rather than truncating it; status histories are
  read chronologically. Two new dimensions in `versions.json`: the register
  contract and the `BW-PROVIDER` descriptor a participant seals for itself.
- **Evidence objects stay 2.8**; the EDD resolver contract stays 1.12.0; the
  discovery documents stay 2.1 / 2.6 / 2.2. No downstream re-pin.
- **TS v0.32 → v0.35.** Federation admission at act time in clause 6; the
  issuing identity derived from the authenticated principal, with the
  forwarded-origin exception; the clock for each grade; the companion-contract
  rows of the ICS pro forma at 9.0.0. The TS's version-by-version change
  history is kept with the source repository and is not reproduced here.
- **MLS profile.** The post-quantum hybrid suite is pinned to
  draft-ietf-mls-pq-ciphersuites-06 under the private-use code point `0xF5C1`;
  wire maps are per registry revision and a group decodes under the revision it
  pinned. `sbm_group_params` version 2 names whole device principals and
  commits the formation instant and a digest of the exact inputs the suite
  decision was taken on.
- **Verifier.** New rules for federation admission at the act
  (`LINT-TRUST-06`), a descriptor's seal key pinned by the register
  (`LINT-TRUST-07`), the register authenticated at ingress (`LINT-TRUST-08`),
  and a missing register or anchor as a third-verdict gap (`LINT-BND-I6`); the
  suite decision is recomputed from committed formation inputs and reported
  INCOMPLETE without them (`LINT-BND-I5`); expiry is validated at the live
  intake boundary as well as at verification. The catalogue now holds 157
  rules, published with their inputs, predicates and errors in
  [`docs/lint-catalogue.md`](docs/lint-catalogue.md).
- **Documentation.** A reviewer guide, an architecture and trust note, a
  message-lifecycle primer, a lifecycle-and-custody note, an extended
  production-verifier note with an annotated shipped bundle, a redrawn figure
  set with a freshness gate, thirteen architecture decision records with the
  decisions index generated from them, and a review agenda that names every
  open question with the expertise that would settle it.

---

## Previous snapshot — 2026-08-01

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1 |
| Evidence objects | 2.8 |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER | 2.1 / 2.6 / 2.2 |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Profile-2 companion contracts | 4.0.0 |
| TS — QERDS binding | v0.32 |

Breaking changes recorded at that snapshot: provider-to-provider submission
became mutual-TLS only under a canonical `urn:sbm:rdp:<uid>` identity, the
entity-level fallback removed because it collapsed several providers of one
entity into a shared idempotency namespace; the receipt acknowledgement moved
to a provider-namespaced path with the issuing provider identity signed into
the receipt; group-establishment refusals stopped travelling as group messages;
a published organisation policy stopped storing its own end instant.

## Earlier revisions

The evidence family, the discovery documents and the companion contracts were
developed iteratively, each version accompanied by regenerated sealed samples
and by the conformance rules that enforce it. Version numbers are sequential
within each stream and independent across streams — the discovery documents and
the contracts version independently of the evidence family. The milestones that
shaped the current wire format:

- **Octet-authoritative inversion.** The COSE_Sign1 became the authoritative
  artefact, its payload deterministic CBOR defined in CDDL, JSON a
  non-authoritative projection; canonicalised-JSON signing was removed.
- **Transmitted-octet and group-state commitments** (evidence 2.1 → 2.2):
  `envelope_hash` and `mls_state` as byte-exact dedicated types, extended to
  every transport boundary and every grade.
- **Sender, recipient and refusal proof** (evidence 2.2 → 2.3): the
  wallet-signed sender confirmation, portable quorum and session proofs, and a
  refusal bound like a confirmation.
- **Organisation policy** (evidence 2.3 → 2.4, BW-ORG 2.3 → 2.4): a
  self-contained policy document, deterministic selection, the selected key
  named in the evidence.
- **MLS profile and establishment** (evidence 2.4 → 2.5): change evidence
  restricted to observable bytes; the scope and group-parameter extensions.
- **Remaining wire semantics** (evidence 2.5 → 2.6): two hash domains, one S2
  event, the attribution model.
- **Fixtures and directory format**: one confirmation key per device, one
  mandatory directory-record signature format, the atomic roster snapshot.
- **The dispute model** (evidence 2.6 → 2.7): a grade-mismatch dispute carries
  an attributable recipient assertion; commitment inequality alone rebuts
  nothing.
- **Historical resolution** (evidence 2.7 → 2.8): member versions and device
  keys resolved as they stood at the act; the policy window derived from the
  signed successor and never stored.
