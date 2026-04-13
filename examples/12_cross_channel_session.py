"""
12_cross_channel_session.py — Cross-channel session continuity for enterprise AI.

Demonstrates how ``SessionState`` tracks a user interaction across three
channels — voice, chat, and email — without losing context or duplicating
actions when the user switches channels.

The session lifecycle shown:

  1. User initiates via IVR voice channel. Intent captured: check graduation status.
  2. Session handed off to chat (web advisor chat). Context replayed.
  3. Advisor escalates via email for follow-up documentation.
  4. Session re-enters chat. Checkpoints prevent re-asking for information.
  5. User requests a sensitive action (withdrawal) — escalation flag set.

Key concerns this example illustrates:
  - **Channel transitions** — session_id is the durable anchor; channel changes do not
    lose state
  - **Checkpoints** — replay-safe list of completed intents; prevents re-asking questions
    that have already been answered
  - **Escalation flag** — once set, cannot be unset; any channel seeing ``escalated=True``
    routes to a human advisor
  - **Channel registry** — ``known_channels`` shows the full interaction path for audit

Run:
    python examples/12_cross_channel_session.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.context import ContextEnvelope, ContextSource
from enterprise_rag_patterns.session import SessionState

# ---------------------------------------------------------------------------
# Channel event types
# ---------------------------------------------------------------------------

CHANNEL_IVR = "ivr_voice"
CHANNEL_CHAT = "web_advisor_chat"
CHANNEL_EMAIL = "email_followup"
CHANNEL_SMS = "sms_notification"


# ---------------------------------------------------------------------------
# Simulated channel handlers
# ---------------------------------------------------------------------------


@dataclass
class ChannelEvent:
    """An interaction event within a channel."""

    channel: str
    event_type: str  # "intent_captured" | "action_taken" | "channel_handoff" | "escalation"
    content: str
    timestamp: datetime


def log_event(session: SessionState, event: ChannelEvent) -> None:
    """Append an event to the session's checkpoint list and log it."""
    checkpoint = f"{event.channel}:{event.event_type}:{event.content[:40]}"
    session.add_checkpoint(checkpoint)


def print_session_state(session: SessionState, label: str = "") -> None:
    """Print the current session state summary."""
    print(f"\n  Session: {session.session_id}  [{label}]")
    print(f"    primary_channel:  {session.primary_channel}")
    print(f"    known_channels:   {sorted(session.known_channels)}")
    print(f"    escalated:        {session.escalated}")
    print(f"    checkpoints ({len(session.checkpoints)}):")
    for cp in session.checkpoints:
        print(f"      + {cp}")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 68)
    print("Cross-Channel Session Continuity — Enterprise AI Advisor")
    print("=" * 68)

    # -----------------------------------------------------------------------
    # Step 1: IVR voice initiates session
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 1: User initiates via IVR voice channel")
    print("─" * 68)

    session = SessionState(
        session_id="sess-S001-20260412-001",
        primary_channel=CHANNEL_IVR,
    )
    session.register_channel(CHANNEL_IVR)

    # IVR captures intent
    e1 = ChannelEvent(
        channel=CHANNEL_IVR,
        event_type="intent_captured",
        content="check graduation status",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e1)

    # IVR captures student identity (voice verification)
    e2 = ChannelEvent(
        channel=CHANNEL_IVR,
        event_type="identity_verified",
        content="student_id=S-001 via voice PIN",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e2)

    print(f"\n  IVR captured intent: {e1.content}")
    print(f"  IVR verified identity: {e2.content}")
    print_session_state(session, "after IVR")

    # -----------------------------------------------------------------------
    # Step 2: Handoff to chat
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 2: IVR routes to web chat — context replayed")
    print("─" * 68)

    session.register_channel(CHANNEL_CHAT)

    # The chat handler replays context from checkpoints — no need to re-ask
    # for intent or re-verify identity
    e3 = ChannelEvent(
        channel=CHANNEL_CHAT,
        event_type="context_replayed",
        content="intent=check_graduation, identity=verified",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e3)

    # Chat advisor retrieves graduation status
    e4 = ChannelEvent(
        channel=CHANNEL_CHAT,
        event_type="action_taken",
        content="graduation_status_retrieved: 87/120 credits",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e4)

    print()
    print("  Chat handler sees these checkpoints from IVR:")
    ivr_checkpoints = [cp for cp in session.checkpoints if cp.startswith(CHANNEL_IVR)]
    for cp in ivr_checkpoints:
        print(f"    • {cp}")
    print()
    print("  Chat does NOT re-ask: 'What is your intent?' or 'Please verify your identity.'")
    print("  → Checkpoints serve as a replay-safe state log across channels.")
    print_session_state(session, "after chat context replay")

    # -----------------------------------------------------------------------
    # Step 3: Advisor sends email follow-up
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 3: Advisor schedules email follow-up")
    print("─" * 68)

    session.register_channel(CHANNEL_EMAIL)

    e5 = ChannelEvent(
        channel=CHANNEL_EMAIL,
        event_type="action_taken",
        content="email_scheduled: graduation_audit_PDF to s001@strayer.edu",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e5)

    print()
    print(f"  Email channel registered. Session now spans 3 channels: {sorted(session.known_channels)}")

    # -----------------------------------------------------------------------
    # Step 4: User returns to chat — continuation
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 4: User returns to chat — asks about withdrawal")
    print("─" * 68)

    # Lookup checkpoints to see if graduation status was already retrieved
    already_fetched = any("graduation_status_retrieved" in cp for cp in session.checkpoints)
    print()
    print(f"  graduation_status_retrieved checkpoint found: {already_fetched}")
    print("  → Chat does not re-fetch graduation status.")

    e6 = ChannelEvent(
        channel=CHANNEL_CHAT,
        event_type="intent_captured",
        content="user_asks: can I withdraw from CHEM 301?",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e6)

    print(f"  New intent captured: {e6.content}")

    # -----------------------------------------------------------------------
    # Step 5: Withdrawal request triggers escalation
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 5: Withdrawal request — escalation flag set")
    print("─" * 68)

    # Withdrawal is a regulatory action (per escalation policy)
    session.escalated = True

    e7 = ChannelEvent(
        channel=CHANNEL_CHAT,
        event_type="escalation",
        content="withdrawal_request escalated to human advisor",
        timestamp=datetime.now(timezone.utc),
    )
    log_event(session, e7)

    print()
    print("  session.escalated set to True — regulatory action detected.")
    print()
    print("  From this point, ALL channels must route to human advisor:")

    for channel in sorted(session.known_channels) + [CHANNEL_SMS]:
        handling = "→ HUMAN_ADVISOR_QUEUE" if session.escalated else "→ AI agent"
        print(f"    {channel:<25} {handling}")

    print_session_state(session, "final state")

    # -----------------------------------------------------------------------
    # Step 6: Build a ContextEnvelope for the escalation handoff
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("STEP 6: Escalation handoff — ContextEnvelope for human advisor")
    print("─" * 68)

    envelope = ContextEnvelope(
        session_id=session.session_id,
        channel="human_advisor_handoff",
        sources=[
            ContextSource(name="session_state", required=True),
            ContextSource(name="graduation_audit", required=True),
        ],
    )
    envelope.add_fact("escalated", str(session.escalated))
    envelope.add_fact("channel_path", " → ".join([CHANNEL_IVR, CHANNEL_CHAT, CHANNEL_EMAIL, CHANNEL_CHAT]))
    envelope.add_fact("checkpoints", str(len(session.checkpoints)))
    envelope.add_fact("primary_intent", "check_graduation_status")
    envelope.add_fact("escalation_reason", "withdrawal_request (regulatory action)")

    print()
    print("  ContextEnvelope for advisor handoff:")
    print(f"    session_id:  {envelope.session_id}")
    print(f"    channel:     {envelope.channel}")
    print(f"    sources:     {envelope.source_names()}")
    print("    facts:")
    for k, v in envelope.facts.items():
        print(f"      {k}: {v}")

    # -----------------------------------------------------------------------
    # Design principles
    # -----------------------------------------------------------------------
    print("\n" + "─" * 68)
    print("DESIGN PRINCIPLES")
    print("─" * 68)
    print(
        """
  1. session_id is the durable anchor across channels.
     The primary_channel may change; session_id never does. Any channel
     receiving a session_id can reconstruct context from checkpoints.

  2. Checkpoints are append-only and replay-safe.
     A checkpoint records that an intent was captured or an action was
     taken. Replaying checkpoints does not re-execute actions — it only
     restores awareness. "Identity verified via voice" is a checkpoint,
     not a trigger to re-run voice verification.

  3. The escalation flag is monotonic — it can only be set, never cleared.
     Once escalated=True, no channel may resume automated handling without
     human approval. This prevents an adversarial interaction where a user
     switches channels to bypass escalation.

  4. known_channels provides the full audit trail of the interaction path.
     The path "ivr_voice → web_advisor_chat → email_followup → web_advisor_chat"
     is inspectable for audit or incident review without replaying logs.

  5. ContextEnvelope packages the session state for advisor handoff.
     The human advisor receives a structured envelope — not a raw chat
     transcript. They see: escalation reason, channel path, intent, and
     the session's checkpoint history.
"""
    )


if __name__ == "__main__":
    main()
