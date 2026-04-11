---
name: New Regulation Module
about: Add RAG-layer compliance patterns for a new regulation
title: "feat(regulations): add [RegulationName] RAG compliance module"
labels: enhancement, regulation, compliance
assignees: ''
---

## Regulation

**Name:** (e.g., CCPA, GDPR full, SOC 2, PIPEDA)
**Jurisdiction:** (e.g., US, EU, Canada)
**Relevant sections:** (e.g., CCPA § 1798.100, GDPR Art. 17)

## What RAG-layer enforcement is needed?

Describe the specific access-control or audit requirement at the retrieval layer:

- [ ] Identity scoping (only retrieve records for authorised subject)
- [ ] Data minimisation (limit fields returned)
- [ ] Erasure / right to be forgotten (track and propagate delete requests)
- [ ] Consent check before retrieval
- [ ] Audit record requirement (cite the specific regulatory section)

## Proposed Module

```
src/enterprise_rag_patterns/regulations/{regulation_name}.py
```

Key classes to implement:
1. Policy class (e.g., `GDPRRAGPolicy`)
2. Audit/log record dataclass
3. Any request/event dataclass

## Checklist

- [ ] Module is in `src/enterprise_rag_patterns/regulations/`
- [ ] All docstrings cite the specific regulatory section (e.g., `34 CFR § 99.32`)
- [ ] Tests added in `tests/test_{regulation_name}.py`
- [ ] Entry added to `ECOSYSTEM.md`
- [ ] `ruff check` passes
- [ ] `mypy --ignore-missing-imports` passes

## References

- Official regulation text:
- Any existing module to use as pattern: `src/enterprise_rag_patterns/regulations/gdpr.py`
