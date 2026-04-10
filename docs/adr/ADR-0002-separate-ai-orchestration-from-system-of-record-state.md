# ADR-0002: Separate AI Orchestration State from System-of-Record State

## Status

Accepted

## Context

Enterprise AI systems often combine conversational state, retrieval context, policy decisions, and operational updates. Problems appear when AI-layer state is treated as equivalent to authoritative business state.

That creates sync drift, unclear ownership, and weak auditability.

## Decision

This repository will distinguish between:
- orchestration state used by the AI workflow
- authoritative state held by systems of record

Patterns should make clear:
- what state is transient
- what state must be synchronized outward
- where retries and idempotency matter
- how action logging and escalation are captured safely

## Consequences

Positive:
- examples remain credible for enterprise operations
- design guidance stays compatible with regulated or failure-sensitive environments
- system boundaries are easier to reason about

Tradeoff:
- examples need extra structure to model both state layers
- readers must understand more than just prompt or model logic
