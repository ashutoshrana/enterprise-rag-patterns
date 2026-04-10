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

## Why it matters

This separation allows:
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

This pattern becomes more important, not less, as the number of channels increases.
