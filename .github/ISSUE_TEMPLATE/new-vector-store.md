---
name: New Vector Store Adapter
about: Add compliance filter support for a new vector store
title: "feat(vector-stores): add [VectorStoreName] compliance adapter"
labels: enhancement, vector-store, good first issue
assignees: ''
---

## Vector Store

**Name:** (e.g., PGVector, OpenSearch, Redis VSS)
**pip install:** (e.g., `psycopg2>=2.9`)
**Min version:** 

## Filter API

Paste the vector store's metadata filter syntax below:

```python
# Example: how this store filters by metadata at query time
```

## Proposed Adapter Class

```
src/enterprise_rag_patterns/vector_stores/{name}_adapter.py
```

Implement `build_filter(scope: ComplianceFilter) -> <store-specific type>` in a class named `{Name}ComplianceFilter(VectorStoreFilterAdapter)`.

## Checklist

- [ ] `build_filter()` handles `student_id` + `institution_id` identity scope
- [ ] `build_filter()` handles `permitted_categories` set (skipped when empty)
- [ ] Lazy import — store SDK not imported at module level
- [ ] Tests added in `tests/test_vector_store_adapters.py`
- [ ] Entry added to `ECOSYSTEM.md`
- [ ] `ruff check` passes
- [ ] `mypy --ignore-missing-imports` passes

## References

- Store docs:
- Any existing similar adapters in the repo for reference: `src/enterprise_rag_patterns/vector_stores/pinecone_adapter.py`
