---
name: New Framework Integration
about: Add a compliance filter/callback for a new LLM framework
title: "feat(integrations): add [FrameworkName] FERPA/compliance integration"
labels: enhancement, framework-integration
assignees: ''
---

## Framework

**Name:** (e.g., DSPy, PydanticAI, LangGraph, Autogen)
**pip install:** (e.g., `dspy-ai>=2.4`)
**Min version:**
**Extension point:** (e.g., Module, Callback, NodePostprocessor, Plugin)

## Integration Pattern

Describe where in the framework pipeline the compliance filter should apply:

```
Input documents → [Retriever] → [THIS COMPONENT] → [LLM]
```

## Proposed Class

```
src/enterprise_rag_patterns/integrations/{framework_name}.py
```

Class name: `FERPA{FrameworkName}Filter` or `{FrameworkName}ComplianceComponent`

## Checklist

- [ ] Lazy import — framework SDK not imported at module level
- [ ] `run()` / `postprocess()` / equivalent method filters on `student_id` + `institution_id`
- [ ] Category filtering supported
- [ ] Audit log entry emitted via `logger.info()` (structured JSON fields)
- [ ] Tests use duck-typed stubs — no framework import required in tests
- [ ] Entry added to `ECOSYSTEM.md`
- [ ] `ruff check` passes
- [ ] `mypy --ignore-missing-imports` passes

## References

- Framework extension point docs:
- Existing integration to use as pattern: `src/enterprise_rag_patterns/integrations/haystack.py`
