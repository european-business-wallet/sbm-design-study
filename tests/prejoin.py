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
"""


def refuse(m, welcome_id, *, credential, **kw):
    """`POST /welcome/{id}/refusal`, with the proof a device would produce."""
    kw.setdefault("refusal_proof", m.welcome_refusal_proof(
        welcome_id, credential=credential,
        reason=kw.get("reason"), offered_suite=kw.get("offered_suite"),
        required_floor=kw.get("required_floor")))
    return m.refuse_welcome(welcome_id, credential=credential, **kw)
