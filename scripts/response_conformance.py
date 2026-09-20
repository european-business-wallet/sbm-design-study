#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors
# SPDX-License-Identifier: CC-BY-4.0
"""R9 — every published operation's RESPONSE, against its own contract.

Round 8 validated public REQUESTS. Round 9's review named three responses the
reference produces and its own contract rejects, and cowork's verification
answered the round-8 ask — *where you would list three occurrences, send the
rule for finding all of them* — by sweeping the whole surface instead. It found
that ten of fourteen operations were wrong, in three distinct ways:

    invalid under its own contract       5   including the COMMIT response,
                                             which the review does not name
    declared `204`, returns a body       2   one of them carrying a value the
                                             next step needs
    no reference behind it at all        3

This is that sweep, kept. For each published operation it drives the reference
and validates what comes back against the exact published response Schema, and
it holds all three counts at their target values — so a new operation with no
reference, a response that drifts from its Schema, or a `204` that starts
answering, fails the bar rather than waiting for a review.

    python3 scripts/response_conformance.py           # verify
    python3 scripts/response_conformance.py --list     # show every operation
"""
import base64
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

# Operations whose reference realisation is a DECLARED residual. The list is
# exact and each entry carries its reason: an unexplained absence is what this
# gate exists to stop, so an absence has to be explained here to be tolerated.
DECLARED_RESIDUALS = {
    "GET /groups/{group_id}/context":
        "F-03 retained-material read. The bytes it serves — the GroupContext "
        "and ratchet tree — are supplied to the Delivery Service by NO "
        "published operation, so implementing it would mean inventing where "
        "they come from. That is the R9-02 routing-authority shape one level "
        "out: a published READ whose data has no published WRITE. Recorded as "
        "a finding rather than papered over with a reference that would have "
        "to make something up.",
}


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _operations(doc):
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if method in ("get", "post", "put", "delete", "patch"):
                yield f"{method.upper()} {path}", op


def _success(op):
    """(status, schema-name or None). None means the contract promises no body."""
    for code in sorted(c for c in op.get("responses", {}) if c.startswith("2")):
        body = op["responses"][code].get("content")
        if not body:
            return code, None
        schema = body["application/json"]["schema"]
        return code, schema.get("$ref", "").rsplit("/", 1)[-1] or None
    return None, None


def drive():
    """Run the whole published surface once and return {operation: outcome}."""
    import yaml
    import lint_cli as lc
    import mls_wire as w
    mock = _load("mock_rdp")

    SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    RDP, DEV = "urn:sbm:rdp:demo-out", "DEV-1"
    # R11-01: principals name their entity — a MID is unique only within it.
    MEMBER = {"kind": "member", "uid": SE["recipient_uid"], "mid": "F1N2C3D4P"}
    SESSION = {"kind": "token-digest", "digest": "a" * 64}
    DEVICE = {"kind": "device", "uid": SE["recipient_uid"], "mid": "F1N2C3D4P",
              "device_id": DEV, "session": SESSION["digest"]}
    FLOOR = [{"uid": SE["recipient_uid"], "mid": "F1N2C3D4P",
              "devices": [{"device_id": DEV, "min_cipher_suite": SUITE}]}]
    OCT = b"the octets the device receives"
    MSG = "01HZ9SWEEP0000000000001"

    res = mock.reserve_keypackages(
        SE["recipient_uid"], credential=MEMBER, cipher_suite=SUITE,
        targets=[{"mid": "F1N2C3D4P", "device_id": DEV}],
        idempotency_key="idem-sweep-00000001")
    pkg = res["keypackages"][0]
    committed = mock.commit_reservation(res["reservation_id"], credential=MEMBER)
    spare = mock.reserve_keypackages(
        SE["recipient_uid"], credential=MEMBER, cipher_suite=SUITE,
        targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-SPARE"}],
        idempotency_key="idem-sweep-00000002")

    deposit = {"invitation_id": "inv-sweep", "recipient_device": DEV,
               "welcome_b64": base64.b64encode(b"a Welcome").decode(),
               "mls_group_id": "Zzw1S4pWq9T5n7xYbXc2dQ",
               "group_info_commitment": w.group_info_commitment(
                   b"a demo GroupInfo", cipher_suite=SUITE),
               "offered_suite": SUITE, "reservation_id": res["reservation_id"],
               "keypackage_ref": pkg["keypackage_ref"],
               "created_at": "2026-04-04T09:00:00Z",
               "expires_at": "2026-04-04T10:00:00Z"}
    queued = mock.deposit_welcome(deposit, credential=MEMBER)

    mock.ds_accept_message(MSG, "demo-group", base64.b64encode(OCT).decode(),
                           principal=RDP)
    accepted = mock._DS_LEDGER[(RDP, MSG)]
    mock.queue_delivery(RDP, MSG, recipient_uid=SE["recipient_uid"],
                        mid="F1N2C3D4P", device_id=DEV)
    collection = mock.collect_messages(credential=DEVICE,
                                       session_binding=SESSION)
    receipt = mock.receipt_ack(
        message_id=MSG, issuing_rdp_id=RDP, device_id=DEV, credential=DEVICE,
        session_binding=SESSION, octets=OCT,
        server_clock="2026-04-04T10:16:23Z",
        collection_token=collection["items"][0]["collection_token"])

    # R11-06: this sweep refused a Welcome and then ACKNOWLEDGED THE SAME ONE —
    # the refused item was still queued, so the 204 came back as if it were
    # fresh, and a fallback turned an empty queue into a silent None. Two
    # invitations for the device now (overlap is legitimate, R11-07): one is
    # refused, the other acknowledged.
    res2 = mock.reserve_keypackages(
        SE["recipient_uid"], credential=MEMBER, cipher_suite=SUITE,
        targets=[{"mid": "F1N2C3D4P", "device_id": DEV}],
        idempotency_key="idem-sweep-00000003")
    mock.commit_reservation(res2["reservation_id"], credential=MEMBER)
    second = mock.deposit_welcome(
        dict(deposit, invitation_id="inv-sweep-2",
             reservation_id=res2["reservation_id"],
             keypackage_ref=res2["keypackages"][0]["keypackage_ref"]),
        credential=MEMBER)
    # Collection reads the DS clock, and these windows close at 10:00:
    # collected after it the queue is EMPTY and the item Schema goes unexercised.
    welcomes = mock.collect_welcomes(credential=DEVICE, at="2026-04-04T09:30:00Z")
    assert len(welcomes["welcomes"]) == 2, "the sweep must exercise a non-empty queue"
    refusal = mock.refuse_welcome(
        queued["welcome_id"],
        credential=dict(DEVICE, keypackage_ref=pkg["keypackage_ref"]),
        reason="suite-below-published-floor", offered_suite=SUITE,
        required_floor=SUITE, refused_at="2026-04-04T09:30:00Z",
        members=FLOOR)
    outcomes = {"outcomes": mock.collect_outcomes(credential=MEMBER)}

    return {
        "GET /keypackages/{uid}":
            mock.keypackage_availability(SE["recipient_uid"], credential=MEMBER),
        "POST /keypackages/{uid}/reservations": res,
        "POST /reservations/{reservation_id}/commit": committed,
        "DELETE /reservations/{reservation_id}":
            mock.release_reservation(spare["reservation_id"], credential=MEMBER),
        "POST /messages": accepted,
        "GET /messages": collection,
        "POST /messages/{issuing_rdp_id}/{message_id}/receipt-ack": receipt,
        "POST /welcome": queued,
        "GET /welcome": welcomes,
        "DELETE /welcome/{welcome_id}":
            mock.ack_welcome(second["welcome_id"], credential=DEVICE,
                             at="2026-04-04T09:30:00Z"),
        "POST /welcome/{welcome_id}/refusal": refusal,
        # R12-X3: the creator's own device registers as the group's founder.
        "POST /groups/{group_id}/founder": mock.register_founder(
            deposit["mls_group_id"],
            credential=dict(DEVICE, device_id="DEV-FOUNDER")),
        "GET /group-establishment/outcomes": outcomes,
        "DELETE /group-establishment/outcomes/{outcome_id}":
            mock.ack_outcome(refusal["outcome_id"], credential=MEMBER),
    }


def check():
    import yaml
    import lint_cli as lc
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    driven = drive()
    rows, problems = [], []
    for name, op in _operations(doc):
        code, schema_name = _success(op)
        if name not in driven:
            if name in DECLARED_RESIDUALS:
                rows.append((name, code, "declared residual"))
            else:
                rows.append((name, code, "NO REFERENCE"))
                problems.append(
                    f"{name}: published with no reference behind it, and not "
                    "in DECLARED_RESIDUALS. An implementer has nothing to "
                    "calibrate against.")
            continue
        got = driven[name]
        if schema_name is None:
            if got is not None:
                rows.append((name, code, "BODY UNDER A NO-CONTENT CODE"))
                problems.append(
                    f"{name}: the contract promises {code} with no content and "
                    f"the reference returns {got!r}. A generated client "
                    "receives nothing, because nothing was promised.")
            else:
                rows.append((name, code, "ok (no content)"))
            continue
        errs = lc.validate_contract_object("delivery-service-openapi.yaml",
                                           schema_name, got)
        if errs:
            rows.append((name, code, f"INVALID under {schema_name}"))
            problems.append(f"{name}: response violates {schema_name}: {errs[:2]}")
        else:
            rows.append((name, code, f"ok ({schema_name})"))
    return rows, problems


def main(argv):
    rows, problems = check()
    if "--list" in argv:
        for name, code, state in rows:
            print(f"{'[OK ]' if state.startswith(('ok', 'declared')) else '[BAD]'} "
                  f"{code or '   '}  {name:58} {state}")
    for p in problems:
        print(f"[FAIL] {p}")
    if problems:
        print(f"\n{len(problems)} published operation(s) do not behave as their "
              "contract says. A response nobody validates is where a value "
              "stops being obtainable from the contract (R9).")
        return 1
    residual = len(DECLARED_RESIDUALS)
    print(f"[OK] {len(rows) - residual} published operation(s) return exactly "
          f"what their contract promises; {residual} declared residual(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
