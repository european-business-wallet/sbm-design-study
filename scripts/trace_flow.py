#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: MIT
"""G2 — one trace through the public operations, composed rather than asserted.

The agenda records four things an implementer has in neither the contracts nor
the reference, and this is the second: *one complete trace through the public
operations, negative and retry branches included — reservation to evidence
retrieval, both entities, several members.*

**Why a document and not more tests.** The suite already exercises every
operation here, and passing helpers are precisely what the external review said
does not answer G2: "local successful helpers do not show that the state machines
compose". What an implementer needs is one run in order, with the values each
step actually produced, including the branches where it goes wrong — and a
reader cannot get that from two thousand assertions.

**Why generated and not written.** A trace written by hand is a trace that
drifts, and a stale trace is worse than none: it reads as a worked example and
teaches a flow the code no longer has. This drives `scripts/mock_rdp.py`'s
published entry points — the same functions the contracts describe — and prints
what came back. `make trace` regenerates it; a test fails if the committed
document is not what a fresh run produces.

**What it is not.** It is the REFERENCE composing with itself. It is not an
interoperability result: no second implementation has exercised these contracts,
which is claim 4 of the README's matrix and is not established. It also does not
cover the four-corner relay path, the CE transformations (deferred, A15) or the
production trust material. Those absences are stated in the document, not left
for a reader to discover.
"""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import sys
import contextlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "implementer-trace.md"
sys.path.insert(0, str(ROOT / "scripts"))
# The request builders come from the suite, deliberately. They are the shapes
# already validated against the published contracts, and a generator with its
# own copies would be a second set to keep in step — which is the defect R8-04
# found: the reference's own happy path was a request the published Schema
# REJECTED, because the fixtures had invented their own required fields.
sys.path.insert(0, str(ROOT / "tests"))

import lint_cli as lc  # noqa: E402
import multipart as mp  # noqa: E402


def _fresh_mock():
    """A mock with empty ledgers — every step of a trace is one run."""
    spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sample(name):
    return json.loads((ROOT / "samples" / name).read_text(encoding="utf-8"))["projection"]


class Trace:
    """The steps, and what each returned."""

    def __init__(self):
        self.steps = []

    def step(self, section, operation, note, fn):
        """Run one published operation and record what it produced."""
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                value = fn()
            outcome, detail = "ok", value
        except Exception as exc:                      # a refusal IS a result here
            reason = getattr(exc, "reason", None)
            outcome = f"refused: {reason}" if reason else f"refused: {type(exc).__name__}"
            detail = str(exc)
        self.steps.append({"section": section, "operation": operation,
                           "note": note, "outcome": outcome, "detail": detail})
        return detail if outcome == "ok" else None


# An evidence id is assigned per run, by design. Printing the one this run
# produced would make the document differ from itself every time it is
# generated, and a document that cannot be compared cannot be gated — so the
# varying part is named as varying rather than shown.
PER_RUN = re.compile(r"urn:uuid:[0-9a-f-]{36}|\b[0-9A-HJKMNP-TV-Z]{26}\b")


def _stable(text):
    return PER_RUN.sub("«assigned per run»", str(text))


def _short(value, limit=110):
    if isinstance(value, dict):
        for key in ("evidence_id", "message_id", "reservation_id", "welcome_id", "receipt_id"):
            if key in value:
                return f"`{key}` = `{_stable(value[key])}`"
        if "projection" in value:
            p = value["projection"]
            return (f"{p.get('type')} `{_stable(p.get('evidence_id', ''))}` — "
                    f"{p.get('event', '')}")
        if "state" in value:            # a confirmation aggregate: show what it REACHED
            counted = value.get("counted") or []
            return (f"`state` = `{value['state']}`, `counted` = "
                    f"`{', '.join(sorted(counted)) if counted else '—'}`")
        return "`" + ", ".join(sorted(value)[:5]) + "`"
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    text = _stable(value)
    return text[:limit] + ("…" if len(text) > limit else "")


# ---------------------------------------------------------------------------
# The trace. Each step calls a PUBLISHED operation; refusals are steps too.
# ---------------------------------------------------------------------------

FR = "EU-FR-PSBID-ZYWVTSRQPNM8M4"          # the recipient entity
SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
SESSION = {"kind": "token-digest", "digest": "a" * 64}


def _member(mid, uid=FR):
    return {"kind": "member", "uid": uid, "mid": mid}


def _device(mid, device_id, uid=FR, session=None):
    cred = {"kind": "device", "uid": uid, "mid": mid, "device_id": device_id}
    if session:
        cred["session"] = session["digest"]
    return cred


def run():
    t = Trace()
    m = _fresh_mock()
    import test_intake_obligations as intake          # its fixtures ARE the contract shapes
    import test_cross_service_transaction as xs

    # --- 1. Channel formation: reserve, commit, invite, join -----------------
    holder = _member("F1N2C3D4P")
    res = t.step("Channel formation", "POST /keypackages/{uid}/reservations",
                 "One usable KeyPackage per (member, device). The reservation id is "
                 "server-assigned; the client's replay handle is its `Idempotency-Key`.",
                 lambda: m.reserve_keypackages(
                     FR, credential=holder, cipher_suite=SUITE,
                     targets=[{"mid": "F1N2C3D4P", "device_id": "dev-01"},
                              {"mid": "F2X3Y4Z55", "device_id": "dev-02"}],
                     idempotency_key="idem-000000000001"))

    t.step("Channel formation", "POST /keypackages/{uid}/reservations (replay)",
           "**Retry branch.** The same idempotency key returns the same reservation "
           "rather than consuming a second package.",
           lambda: m.reserve_keypackages(
               FR, credential=holder, cipher_suite=SUITE,
               targets=[{"mid": "F1N2C3D4P", "device_id": "dev-01"},
                        {"mid": "F2X3Y4Z55", "device_id": "dev-02"}],
               idempotency_key="idem-000000000001"))

    t.step("Channel formation", "POST …/reservations (key reused, different content)",
           "**Negative branch.** The same key for different targets is a conflict, not a "
           "second reservation.",
           lambda: m.reserve_keypackages(
               FR, credential=holder, cipher_suite=SUITE,
               targets=[{"mid": "F1N2C3D4P", "device_id": "dev-03"}],
               idempotency_key="idem-000000000001"))

    t.step("Channel formation", "POST /reservations/{id}/commit",
           "Until it is committed, a deposit names packages that may still return to "
           "the pool.",
           lambda: m.commit_reservation(res["reservation_id"], credential=holder))

    pkg = {k["device_id"]: k for k in (res or {}).get("keypackages", [])}
    dep = t.step("Channel formation", "POST /welcomes",
                 "The Welcome is deposited WITH its invitation record, bound to the "
                 "committed reservation and to the KeyPackage it consumes.",
                 lambda: m.deposit_welcome(
                     xs._invitation("dev-01", "welcome-1",
                                    reservation_id=res["reservation_id"],
                                    keypackage_ref=pkg["dev-01"]["keypackage_ref"]),
                     credential=holder))

    col = t.step("Channel formation", "GET /welcomes",
                 "The invited DEVICE collects; a device that was not invited collects "
                 "nothing.",
                 lambda: m.collect_welcomes(credential=_device("F1N2C3D4P", "dev-01")))

    t.step("Channel formation", "POST /welcomes/{id}/ack",
           "The device joins. The acknowledgement is authenticated as the device, not "
           "as its member.",
           lambda: m.ack_welcome((col or {"welcomes": [{}]})["welcomes"][0]["welcome_id"],
                                 credential=_device("F1N2C3D4P", "dev-01")))

    dep2 = t.step("Channel formation", "POST /welcomes (second device)",
                  "The second member's device, invited on the same reservation.",
                  lambda: m.deposit_welcome(
                      xs._invitation("dev-02", "welcome-2",
                                     reservation_id=res["reservation_id"],
                                     keypackage_ref=pkg["dev-02"]["keypackage_ref"]),
                      credential=holder))
    kp2 = pkg["dev-02"]["keypackage_ref"]
    t.step("Channel formation", "POST /welcomes/{id}/refuse (no KeyPackage)",
           "**Negative branch.** The refusal is authenticated by the KeyPackage the "
           "device holds. Without it the item is indistinguishable from one that does "
           "not exist — the queue must not be an existence oracle over another "
           "device's state. This is the proof whose exact bytes **G1** still owes.",
           lambda: m.refuse_welcome((dep2 or {}).get("welcome_id"),
                                    credential=_device("F2X3Y4Z55", "dev-02"),
                                    reason="group-info-mismatch", offered_suite=SUITE))

    refuser = dict(_device("F2X3Y4Z55", "dev-02"), keypackage_ref=kp2)
    wid2 = (dep2 or {}).get("welcome_id")

    t.step("Channel formation", "POST /welcomes/{id}/refuse (no proof)",
           "**Negative branch.** Holding `keypackage_ref` proves nothing: it is a "
           "hash of the package's PUBLIC bytes, returned to the creator by the "
           "reservation and held by the Delivery Service — the two parties best "
           "placed to forge a refusal attributed to this device both have it.",
           lambda: m.refuse_welcome(wid2, credential=refuser,
                                    reason="group-info-mismatch", offered_suite=SUITE))

    # R30-PUB-01: the nonce comes from the device's own queue item, through the
    # published `GET /welcome`. This trace exists to show that the PUBLISHED
    # operations compose, so a step that reached into the service's state would
    # be demonstrating the opposite of what the document claims.
    _queued = t.step(
        "Channel formation", "GET /welcome (the refusing device)",
        "The device collects its Welcome and, with it, the single-use "
        "`refusal_nonce` a refusal must sign. Everything the proof commits to "
        "reaches the device through this response.",
        lambda: m.collect_welcomes(credential=refuser))
    _item = next((w for w in (_queued or {}).get("welcomes", [])
                  if w["welcome_id"] == wid2), None)
    proof = m.welcome_refusal_proof(wid2, credential=refuser,
                                    reason="group-info-mismatch", offered_suite=SUITE,
                                    nonce=(_item or {}).get("refusal_nonce"))

    t.step("Channel formation", "the device builds the pre-join proof",
           "**G1.** A signature under the KeyPackage's **leaf signature key** — RFC 9420 "
           "§5.1.2 `SignWithLabel`, label `SBMWelcomeRefusal` — over the "
           "deterministic-CBOR content `[domain, welcome_id, keypackage_ref, "
           "offered_suite, required_floor, reason, nonce]`. The nonce is the "
           "single-use value the Delivery Service issued with the Welcome. The DS "
           "verifies it against the key the KeyPackage carries: a device that has "
           "joined nothing has no discovery document and no wallet key to be checked "
           "against, which is what makes this a *pre-join* proof.",
           lambda: proof)

    t.step("Channel formation", "POST /welcomes/{id}/refuse (wrong nonce)",
           "**Negative branch.** The nonce is inside the signature, so a captured "
           "refusal cannot be replayed against another Welcome.",
           lambda: m.refuse_welcome(wid2, credential=refuser,
                                    reason="group-info-mismatch", offered_suite=SUITE,
                                    refusal_proof=dict(proof, nonce="rn-000000000000")))

    t.step("Channel formation", "POST /welcomes/{id}/refuse (unregistered reason)",
           "**Negative branch.** The refusal vocabulary is a closed registry; an "
           "invented reason is refused rather than echoed — and note the signature "
           "covers the reason, so a reason cannot be swapped after signing.",
           lambda: m.refuse_welcome(wid2, credential=refuser,
                                    reason="capability-mismatch", offered_suite=SUITE,
                                    refusal_proof=proof))

    t.step("Channel formation", "POST /welcomes/{id}/refuse",
           "The device refuses before joining, with its proof. The creator learns it "
           "from the outcome queue, not from silence.",
           lambda: m.refuse_welcome(wid2, credential=refuser,
                                    reason="group-info-mismatch", offered_suite=SUITE,
                                    refusal_proof=proof))

    t.step("Channel formation", "POST /welcomes/{id}/refuse (replay of an accepted proof)",
           "**Negative branch.** The nonce is spent when the refusal is ACCEPTED, so "
           "a captured copy is unusable — while an exact retry converges on the "
           "stored outcome before the proof is examined at all. Replay protection "
           "and idempotency do not fight each other.",
           lambda: m.refuse_welcome(wid2, credential=refuser,
                                    reason="suite-below-published-floor",
                                    offered_suite=SUITE, refusal_proof=proof))

    t.step("Channel formation", "GET /outcomes",
           "The creator collects what happened to each invitation — a join, or a "
           "refusal it can act on.",
           lambda: m.collect_outcomes(credential=holder))

    # --- 2. Sending: the intake performs what the contract assigns it --------
    i = _fresh_mock()                       # the sending provider, its own ledgers
    import test_intake_obligations as ob
    ORG, MEMBERS = ob.ORG, ob.MEMBERS

    se = t.step("Sending", "POST /submissions",
                "The intake validates the candidate against the published request "
                "Schema, recomputes the selected policy, verifies the sender's "
                "confirmation and checks identity coherence — all BEFORE the Delivery "
                "Service is contacted and before anything is sealed.",
                lambda: i.submit(ob._meta(), org=ORG, members=MEMBERS))

    t.step("Sending", "POST /submissions (incoherent identity)",
           "**Negative branch.** Every field is independently valid and they name two "
           "entities: a German recipient UID with a French address. Refused before a "
           "seal exists.",
           lambda: i.submit(ob._meta(message_id="01HZ5TRACE0000000000000N",
                                     recipient_uid=ob.DE_UID),
                            org=ORG, members=MEMBERS))

    def _bad_policy_digest():
        meta = ob._meta(message_id="01HZ5TRACE0000000000000P")
        meta["acceptance_policy_ref"] = copy.deepcopy(meta["acceptance_policy_ref"])
        meta["acceptance_policy_ref"]["doc_digest"]["hash_mode"] = "manifest-sha256"
        return i.submit(meta, org=ORG, members=MEMBERS)

    t.step("Sending", "POST /submissions (policy digest outside its domain)",
           "**Negative branch.** A digest mode admissible only in the content domain, "
           "on a reference to a published document. The published request Schema "
           "refuses it through its own `$ref` — the contract inherited the rule with "
           "no edit of its own.",
           _bad_policy_digest)

    t.step("Sending", "POST /submissions (reversed TTL)",
           "**Negative branch.** `expires_at` not later than `sent_at` — a zero or "
           "reversed lifetime, checked at intake rather than by a linter after sealing.",
           lambda: i.submit(ob._meta(message_id="01HZ5TRACE0000000000000T",
                                     expires_at=ob.SE["sent_at"]),
                            org=ORG, members=MEMBERS))

    t.step("Sending", "POST /submissions (exact retry)",
           "**Retry branch.** The same submission returns the evidence the first one "
           "produced; it does not seal a second.",
           lambda: i.submit(ob._meta(), org=ORG, members=MEMBERS))

    # --- 3. Delivery: the Delivery Service observes the handover ------------
    # R30-PUB-03: every stage from here on uses THE SEALED SE THE SUBMISSION
    # RETURNED. The delivery stage used to take its message id from the request
    # metadata and its group from a shipped fixture, and the confirmation stage
    # confirmed the fixture's message entirely — a different message from the
    # one submitted. So the document claimed the state machines compose while a
    # regression stopping the submitted message from reaching confirmation would
    # have left the trace green. The values below are the run's own.
    submitted = se.get("projection", se) if isinstance(se, dict) else {}
    if not submitted.get("message_id"):
        raise SystemExit(
            "the submission produced no sealed SE, so there is nothing to carry "
            "into delivery — the trace will not fall back to a fixture and call "
            "the result a composition (R30-PUB-03)")
    octets = base64.b64decode(ob._meta()["mls_message_b64"])
    rdp_out = "urn:sbm:rdp:demo-out"
    mid, dev_id = "F1N2C3D4P", "dev-01"
    message_id = submitted["message_id"]

    t.step("Delivery", "POST /messages (DS accepts)",
           "The Delivery Service accepts the transmitted octets for routing. Nothing "
           "is queued for a device until it has.",
           lambda: i.ds_accept_message(message_id, submitted["mls_group_id"],
                                       base64.b64encode(octets).decode(),
                                       principal=rdp_out))

    t.step("Delivery", "queue for the joined device",
           "One delivery item per routed device.",
           lambda: i.queue_delivery(rdp_out, message_id, recipient_uid=FR,
                                    mid=mid, device_id=dev_id))

    got = t.step("Delivery", "GET /messages",
                 "The device collects in a device-authenticated session and receives a "
                 "**collection token** — the handle its acknowledgement must carry.",
                 lambda: i.collect_messages(
                     credential=_device(mid, dev_id, session=SESSION),
                     session_binding=SESSION))

    token = None
    if got:
        token = next((it["collection_token"] for it in got["items"]
                      if it["message_id"] == message_id), None)

    t.step("Delivery", "POST /messages/{id}/ack (no collection token)",
           "**Negative branch.** The token is what ties the acknowledgement to the "
           "collection the DS observed; without it there is nothing to tie.",
           lambda: i.receipt_ack(message_id, dev_id,
                                 credential=_device(mid, dev_id, session=SESSION),
                                 session_binding=SESSION, octets=octets,
                                 server_clock="2026-04-04T10:20:00Z"))

    receipt = t.step("Delivery", "POST /messages/{id}/ack",
                     "The DS signs a receipt over the device's acknowledgement. The "
                     "instant is the **server's** observation; a client-supplied one "
                     "is retained as diagnostics and never becomes the event.",
                     lambda: i.receipt_ack(
                         message_id, dev_id,
                         credential=_device(mid, dev_id, session=SESSION),
                         session_binding=SESSION, octets=octets,
                         server_clock="2026-04-04T10:20:00Z",
                         client_acked_at="2026-04-04T10:00:00Z",
                         collection_token=token))

    # --- 4. Confirmation: the members speak, and the message ends -----------
    import test_confirmation_acts as ca
    c = ca._m()
    # The SE crosses the boundary as DATA — which is what a recipient-side
    # provider receives — so the members confirm the message that was actually
    # submitted, under the policy that SE pins.
    _se = submitted

    t.step("Confirmation", "POST /confirmations (s3, first member)",
           "One member of the recipient entity confirms verification. Under a quorum "
           "policy this counts and does not yet end the message.",
           lambda: ca._deliver(c, "s3", ca._s3("F1N2C3D4P", se=_se), ca._member("F1N2C3D4P"), se=_se))

    t.step("Confirmation", "POST /confirmations (s3, replay by the same member)",
           "**Retry branch.** An exact retry returns what the first returned; the "
           "member's act is counted once.",
           lambda: ca._deliver(c, "s3", ca._s3("F1N2C3D4P", se=_se), ca._member("F1N2C3D4P"), se=_se))

    t.step("Confirmation", "POST /confirmations (s3, second member)",
           "The quorum is satisfied — **S4**. The delivery decision is the instant "
           "THIS provider observed the completing act.",
           lambda: ca._deliver(c, "s3", ca._s3("F2X3Y4Z55", se=_se), ca._member("F2X3Y4Z55"), se=_se))

    t.step("Confirmation", "(diagnostic) the confirmation aggregate, read directly",
           "**Not a published operation.** No contract operation serves this; it is the "
           "reference's own `confirmation_state`, read here so the page SHOWS what the "
           "three acts above produced instead of asserting it in prose (R32-RES-01). "
           "Every other step in this document is a published call — an implementer "
           "should not go looking for this one (R33-OBS-02). The acceptance policy is "
           "**satisfied**: two distinct members, the retry counted once.",
           lambda: ca._state(c, se=_se))

    t.step("Confirmation", "POST /confirmations (foreign member)",
           "**Negative branch.** A member the recipient entity does not publish "
           "cannot confirm for it, whatever it signs.",
           lambda: ca._deliver(ca._m(), "s3", ca._s3("ZZZZZZZZZ", se=_se), ca._member("ZZZZZZZZZ"), se=_se))

    # a mismatch, on its own runtime so the terminal state is its own
    t.step("Confirmation", "POST /confirmations (mismatch) → NDE",
           "**Negative branch, terminal.** The recipient recomputed the payload digest "
           "and it differed. The NDE carries the recipient's proof, and the two "
           "digests must differ — equality would contradict the claim.",
           lambda: ca._deliver(ca._m(), "mismatch",
                               dict(copy.deepcopy(ca.PROOF), mid="F1N2C3D4P",
                                    message_id=_se["message_id"]),
                               ca._member("F1N2C3D4P"), se=_se))

    # --- 5. Multipart: the failure that has its own outcome -----------------
    import test_validation_failure_outcome as vf
    SE_MP = vf.SE_MP

    t.step("Multipart", "recipient re-verification (parts match)",
           "Mode C is TWO recomputations in order: each part's digest from the octets "
           "received, then the manifest's digest against the declared payload hash. "
           "Only the first touches the content.",
           lambda: mp.verify_against_manifest(
               mp.assemble(vf.parts()), SE_MP["manifest"], SE_MP["payload_hash"]))

    t.step("Multipart", "recipient re-verification (one part replaced)",
           "**Negative branch.** The failure is detected per part — and the declared "
           "payload hash still matches, because under Mode C it is the digest of the "
           "MANIFEST. That is why a mismatch confirmation cannot carry this.",
           lambda: mp.failure_report(
               mp.assemble(vf._broken(p1=b"x" * 713)), SE_MP["manifest"],
               SE_MP["payload_hash"]))

    t.step("Multipart", "POST /confirmations (validation-failure) → NDE",
           "**Terminal.** The recipient's typed, attributable assertion: what it "
           "decrypted, which commitment it was checking, the cause, and the per-part "
           "detail — carrying no recomputed payload hash, because there is none.",
           lambda: vf._deliver(vf._m(), vf._assertion(
               vf._m(), mp.failure_report(mp.assemble(vf._broken(p1=b"x" * 713)),
                                          SE_MP["manifest"], SE_MP["payload_hash"]))))

    t.step("Multipart", "POST /confirmations (assertion contradicting the manifest)",
           "**Negative branch.** The recipient's OBSERVATION cannot be checked by "
           "anyone else. The sender's DECLARATION is in the sending evidence, and an "
           "assertion that misstates it is refused before sealing.",
           lambda: vf._deliver(vf._m(), vf._assertion(
               vf._m(), {**mp.failure_report(mp.assemble(vf._broken(p1=b"x" * 713)),
                                             SE_MP["manifest"], SE_MP["payload_hash"]),
                         "parts": [{"part_id": "not-in-manifest",
                                    "failure": "part-digest-mismatch",
                                    "declared": SE_MP["manifest"][0]["digest"],
                                    "observed": dict(SE_MP["manifest"][0]["digest"],
                                                     hex="a" * 64)}]})))

    return t, m, i, se


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------

PREAMBLE = """<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- GENERATED by scripts/trace_flow.py. Do not edit: change the flow, or the reference. -->

# One trace through the public operations

**Status:** informative · **Generated** by driving `scripts/mock_rdp.py`'s published
entry points and recording what each returned · **Regenerate:** `make trace`

This is the second of the four things the [review agenda](REVIEW_AGENDA.md) records
as missing for an implementer — *one complete trace through the public operations,
negative and retry branches included*. The suite exercises every operation below,
and passing helpers are exactly what does not answer the question: they do not
show that the state machines **compose**. This does, in order, with the values the
run produced.

## What this is not

- **Not an interoperability result.** It is the reference composing with itself.
  No independent implementation has exercised these contracts — that is claim 4
  of the [claim matrix](../README.md#what-a-green-bar-means--and-what-it-does-not)
  and it is not established.
- **Not the four-corner path.** One provider plays both delivery roles here.
  The relay hop, the origin's sealed SE proving its namespace, and the
  cross-provider receipt question ([A1](REVIEW_AGENDA.md)) are not traced.
- **Not the transformations.** Change-Indication Evidence is deferred
  ([A15](REVIEW_AGENDA.md)): neither transformation is profiled and a provider
  must not issue one, so there is nothing to trace.
- **Not production trust.** Demonstration keys throughout; a production verifier
  needs the material set out in the
  [production-verifier note](production-verifier-architecture.md).
- **It does not reach a Delivery Evidence object.** The trace ends where the
  public operations do: the acceptance policy is satisfied (S4) and the terminal
  outcomes are sealed. DE issuance runs off the receipt-and-state path rather
  than off a published call, so a live DE is part of what **G2** still owes.

A refusal below is a **result**, not a failure of the trace: the negative
branches are the point, and each names the registered reason the operation
returned.

"""


def render(t):
    L = [PREAMBLE]
    ok = sum(1 for s in t.steps if s["outcome"] == "ok")
    L.append(f"**{len(t.steps)} steps**, of which {ok} succeeded and "
             f"{len(t.steps) - ok} were refused by design.\n")
    section = None
    for s in t.steps:
        if s["section"] != section:
            section = s["section"]
            L.append(f"\n## {section}\n")
        mark = "→" if s["outcome"] == "ok" else "✗"
        L.append(f"### {mark} `{s['operation']}`\n")
        L.append(s["note"] + "\n")
        if s["outcome"] == "ok":
            L.append(f"**Returned:** {_short(s['detail'])}\n")
        else:
            L.append(f"**Refused:** `{s['outcome'].split(': ', 1)[1]}` — "
                     f"{_short(s['detail'], 200)}\n")
    L.append("\n---\n")
    L.append("*Every step above is a call to a published operation of the reference "
             "implementation. If a step's behaviour changes, this document changes with "
             "it or `make trace` fails — a worked example that drifts teaches a flow the "
             "code no longer has.*\n")
    return "\n".join(L)


def main(argv):
    t, *_ = run()
    text = render(t)
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("[FAIL] docs/implementer-trace.md is stale — run `make trace`")
            return 1
        print(f"[OK] implementer trace current: {len(t.steps)} steps through the "
              "published operations")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(t.steps)} steps")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
