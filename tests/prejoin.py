# SPDX-License-Identifier: MIT
"""G1 — refusing a Welcome the way a device does.

A pre-join refusal carries a signature under the KeyPackage's leaf signature
key over a DS-issued single-use nonce. Every caller here builds it the same
way, through the reference's own `welcome_refusal_proof`, so no test assembles
the signed content itself: the device and the Delivery Service must sign and
verify the same bytes, and two builders is how they come to differ.

Tests that are about something else — windows, idempotency, floors, principals
— use this and stay about that. A test that wants to exercise the proof itself
calls `refuse_welcome` directly with the proof it wants to send.

R30-PUB-01: the nonce is FETCHED, from the device's own queue, through the
published `GET /welcome`. It used to be left out and defaulted inside the
builder, which read it from the Delivery Service's private state — so every
test here passed while an implementer holding the contract could not obtain the
value the proof must sign. Going through the public response is what makes
these tests evidence about the published operations rather than about the
reference's internals.
"""


COLLECTED_AT = "2026-04-04T09:30:00Z"
"""When the device collected its Welcome, unless a caller says otherwise.

Collection and refusal are two acts at two instants, and only the first has to
happen while the Welcome is LIVE — a device collects, decides, and may refuse
late or outside the window, which is precisely what the deadline tests are
about. So this is not derived from `refused_at`: a test refusing a second after
the deadline still collected before it, and tying the two together would make
those tests fail at the fetch instead of at the rule they exist to check.
"""


def nonce_for(m, welcome_id, *, credential, at=COLLECTED_AT):
    """The refusal nonce, from the queue item the DS returns to THIS device.

    Remembered once collected, because the DEVICE remembers it. A handled
    invitation leaves the queue, so a retry — the case the idempotent path
    exists for — cannot fetch again; a client whose response was lost still
    holds what it collected and re-sends it. The memory is kept on the runtime
    the test is driving, so it is the device's own and not a second reader of
    the service's state: fetching is still the only way the value ever enters it.
    """
    held = m.__dict__.setdefault("_collected_refusal_nonces", {})
    if welcome_id in held:
        return held[welcome_id]
    queue = m.collect_welcomes(credential=credential, at=at)
    item = next((w for w in queue["welcomes"] if w["welcome_id"] == welcome_id), None)
    if item is None:
        raise AssertionError(
            f"no queued Welcome {welcome_id!r} for this device at {at} — a "
            "refusal signs a value that arrives with the Welcome, so a test "
            "without one is not exercising a refusal a device could make. Pass "
            "`collected_at` if this invitation's window is elsewhere")
    held[welcome_id] = item["refusal_nonce"]
    return held[welcome_id]


def refuse(m, welcome_id, *, credential, collected_at=COLLECTED_AT, **kw):
    """`POST /welcome/{id}/refusal`, with the proof a device would produce."""
    kw.setdefault("refusal_proof", m.welcome_refusal_proof(
        welcome_id, credential=credential,
        reason=kw.get("reason"), offered_suite=kw.get("offered_suite"),
        required_floor=kw.get("required_floor"),
        nonce=nonce_for(m, welcome_id, credential=credential, at=collected_at)))
    return m.refuse_welcome(welcome_id, credential=credential, **kw)
