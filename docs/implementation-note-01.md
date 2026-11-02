# Implementation Note 01: Cross-Channel Continuity with Shared Workflow State

## Problem

Many enterprise AI workflows behave as if each channel is a separate system. A user may start in voice, continue by SMS, and later show up in an operator dashboard, but the workflow loses continuity because state is tied too closely to the current channel.

That creates:
- repeated qualification questions
- inconsistent status between systems
- poor operator visibility
- brittle handoff between automation and humans

## Pattern

Treat the workflow state as the primary object and the channel state as contextual metadata.

The implementation pattern is:
1. normalize inbound events from every channel into one session envelope
2. map channel-specific details into metadata fields, not business-state fields
3. persist workflow checkpoints independently from the active interaction surface
4. rehydrate the next interaction from workflow state plus channel metadata
5. expose the current workflow state to operator-facing systems

## Current implementation

Reviewed against main commit `30e2eaf` on 2026-11-01.
[`SessionState`](../src/enterprise_rag_patterns/session.py) is an in-memory
container for `session_id`, `primary_channel`, `known_channels`, `checkpoints`,
and `escalated`. `register_channel()` adds to the channel set;
`add_checkpoint()` appends a string. The primary channel is not automatically
registered, and adding the same checkpoint twice preserves both entries.

The executable example below targets the reviewed source checkout, not an
unverified installed release.

```python
from enterprise_rag_patterns.session import SessionState

state = SessionState(session_id="session-abc", primary_channel="voice")
state.register_channel("voice")
state.add_checkpoint("identity_verified")
state.register_channel("sms")
assert state.known_channels == {"voice", "sms"}
assert state.checkpoints == ["identity_verified"]
```

Persistence, inbound-event normalization, identity binding, replay protection,
concurrent updates, and operator dashboards belong to the application. This
class does not provide them. It also does not track retrieved sources, their
contents, or retrieval timestamps. The reference flow below describes the
application architecture to build around this container.

## Why it matters

With application persistence and event handling in place, this separation supports:
- continuity across voice, messaging, and dashboard actions
- replay-safe state reconstruction
- fewer duplicate prompts for users
- more reliable escalation when a human needs to take over

## Practical boundary

Do not let the currently active channel become the source of truth for:
- missing requirements
- case progress
- approval checkpoints
- escalation eligibility

Those belong to workflow state.

## Reference flow

1. user responds in channel A
2. system validates and updates workflow state
3. system logs outbound actions to the system of record
4. later interaction arrives in channel B
5. workflow state is rehydrated
6. user continues from the last real checkpoint, not from the last channel-specific prompt

## Failure mode to avoid

If each channel keeps its own local progress assumptions, continuity breaks and the operator view becomes unreliable. This is one of the fastest ways to make enterprise AI systems feel untrustworthy.

## Operational note

As channels increase, validate continuity by resuming the same authorized workflow across channels and replaying a duplicate event. A successful in-memory example alone does not establish durable recovery or replay safety.
