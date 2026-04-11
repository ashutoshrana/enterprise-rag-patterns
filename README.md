# enterprise-rag-patterns

[![CI](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml/badge.svg)](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![PyPI](https://img.shields.io/pypi/v/enterprise-rag-patterns.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)

Practical reference patterns for retrieval-augmented workflows, context continuity, and governed AI integration in enterprise environments.

## Why this repo exists

Most examples of AI assistants stop at demo quality. Real enterprise systems have harder problems:
- multiple source systems
- fragmented context
- workflow continuity across channels
- compliance and audit requirements
- human handoff only when it is actually needed

This repository is a public-safe, anonymized scaffold for those patterns.

## Pattern themes

The examples in this repository are designed for teams building systems such as:
- omnichannel service and enrollment workflows
- multi-step document and verification processes
- enterprise knowledge retrieval and action support
- AI-assisted operations that require auditability and controlled human handoff

## Scope

This repo focuses on:
- context assembly for AI workflows
- session continuity across channels
- human-in-loop escalation rules
- enterprise-safe action boundaries
- compliance and audit patterns for regulated environments (FERPA and similar frameworks)
- reference architecture notes for operationally sensitive deployments

The patterns are designed to be:
- **Cloud-agnostic** — applicable on AWS, GCP, Azure, OCI, or hybrid environments
- **Platform-agnostic** — not tied to any specific CRM, ERP, vector database, or LLM provider
- **Regulation-aware** — compliance module targets FERPA; the same pattern applies to HIPAA, GLBA, and similar record-access frameworks

It does not include customer data, institution-specific logic, or vendor-specific implementation artifacts.

## Repository structure

- `CONTRIBUTING.md`
- `GOVERNANCE.md`
- `CITATION.cff`
- `docs/architecture.md`
- `docs/implementation-note-01.md`
- `docs/implementation-note-02.md` — FERPA boundaries in RAG
- `docs/articles/`
- `docs/adr/`
- `docs/case-study-anonymized.md`
- `examples/context-pipeline.yaml`
- `examples/ferpa_rag_pipeline.py` — complete runnable FERPA-compliant pipeline
- `src/enterprise_rag_patterns/`
  - `context.py` — context envelope and source assembly
  - `session.py` — cross-channel session continuity
  - `policy.py` — escalation and action-boundary policy objects
  - `compliance.py` — FERPA-aware context governance with audit logging

## Why these patterns matter

Enterprise AI systems usually fail at the seams:
- between channels
- between memory and policy
- between the AI layer and the system-of-record

The goal here is to make those seams explicit and reusable.

## Modules

- `context.py`
  Context envelope and source assembly patterns.

- `session.py`
  Session memory and cross-channel continuity scaffolding.

- `policy.py`
  Escalation and action-boundary policy objects.

- `compliance.py`
  FERPA-aware context governance for regulated environments. Provides
  `StudentIdentityScope` for defining retrieval boundaries, `FERPAContextPolicy`
  for filtering retrieved documents before they enter the LLM context window,
  and `AuditRecord` for 34 CFR § 99.32 disclosure logging.
  See `docs/implementation-note-02.md` for design rationale and usage guidance.

## Intended audience

- enterprise architects
- AI platform engineers
- enterprise platform and workflow operators
- applied AI teams working in regulated or multi-system environments

## Public positioning

This repo is meant to show practical architecture thinking, not marketing language.

## Near-term roadmap

- add architecture decision records for cross-channel continuity
- publish a reference event flow for system-of-record synchronization
- add policy examples for human escalation thresholds
- document anonymized implementation lessons from production-style operating environments

## Published notes

- implementation note 01: [`docs/implementation-note-01.md`](./docs/implementation-note-01.md) — Cross-channel continuity problem and solution
- implementation note 02: [`docs/implementation-note-02.md`](./docs/implementation-note-02.md) — FERPA boundaries in retrieval-augmented generation
- article: [`docs/articles/production-grade-rag-in-regulated-enterprise-environments.md`](./docs/articles/production-grade-rag-in-regulated-enterprise-environments.md)

## Project governance

- contribution guidance: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- governance model: [`GOVERNANCE.md`](./GOVERNANCE.md)
- architecture decisions: [`docs/adr`](./docs/adr)
- system overview: [`docs/architecture.md`](./docs/architecture.md)

## Citing this work

If you use these patterns in your work, see `CITATION.cff` or use GitHub's "Cite this repository" button above.

## Status

Active development. Current focus: compliance-aware RAG patterns for regulated enterprise environments, applicable across cloud providers and enterprise platforms.
---


## Part of the enterprise AI patterns trilogy

| Library | Focus | Regulation |
|---------|-------|-----------|
| **enterprise-rag-patterns** | What to retrieve | FERPA identity-scoped RAG |
| [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) | What agents may do | FERPA, HIPAA, GLBA policy enforcement |
| [integration-automation-patterns](https://github.com/ashutoshrana/integration-automation-patterns) | How data flows | Event-driven enterprise integration |
