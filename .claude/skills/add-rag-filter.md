---
description: How to add a new regulated-sector RAG pre-filter example to enterprise-rag-patterns
---

# Skill: Add a New RAG Pre-filter Example

Use this when adding a new sector or regulatory jurisdiction to enterprise-rag-patterns.

## Files to create

1. `examples/NN_<sector>_rag.py` — the filter implementation
2. `tests/test_NN_<sector>_rag.py` — tests using importlib loader

## Filter structure (frozen dataclass)

Every filter is a `@dataclass(frozen=True)` with an `evaluate(context, document) -> FilterResult` method.

```python
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class FilterResult:
    decision: str               # APPROVED / DENIED / REDACTED / REQUIRES_HUMAN_REVIEW
    reason: str
    regulation_citation: str
    requires_logging: bool = True

    @property
    def is_denied(self) -> bool:
        return self.decision == "DENIED"  # NOT True for REDACTED or REQUIRES_HUMAN_REVIEW

@dataclass(frozen=True)
class MyRegulationFilter:
    LAYER_NAME = "my_regulation"

    def evaluate(self, context: dict, document: dict) -> FilterResult:
        # Rule 1: block X
        if document.get("field") == "bad_value":
            return FilterResult(
                decision="DENIED",
                reason="Plain English reason",
                regulation_citation="Regulation Name Art. N — description",
            )
        return FilterResult(
            decision="APPROVED",
            reason="Compliant with Regulation Name",
            regulation_citation="Regulation Name Art. N",
        )
```

## 4-layer pipeline structure

Every example must have exactly 4 filter classes in this order:
1. Primary data protection filter (the main regulation)
2. Sector-specific or secondary data filter
3. Automated decision / AI-specific filter
4. Cross-border transfer filter

## Test import pattern (required)

```python
import importlib.util, sys, types, os

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = types.ModuleType(name)
    sys.modules[name] = mod   # MUST register before exec_module (frozen dataclass pickling)
    spec.loader.exec_module(mod)
    return mod

EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), '..', 'examples')
m = load_module("my_filter", os.path.join(EXAMPLES_DIR, "NN_sector_rag.py"))
```

## Using FilterPipeline (src/ package)

```python
from enterprise_rag_patterns.pipeline import FilterPipeline

pipeline = FilterPipeline([
    MyFilter1().filter,
    MyFilter2().filter,
])
result = pipeline.run(document)
if not result.is_approved:
    raise PermissionError(result.reason)
```

## README update (required after every new example)

1. **Header line** (line 9): increment example count and test count
   `38 regulated sector examples` → `39 regulated sector examples`
   `1233 tests` → `1273 tests`

2. **Catalog table heading**: `## Example catalog — 38 regulated sectors` → `39`

3. **Catalog row**: add `| 39 | \`39_file.py\` | Sector | Key regulations enforced |`

4. **Trilogy footer** — update in ALL THREE repo READMEs:
   `38 sectors · 40 regulations · 1233 tests` → `39 sectors · 41 regulations · 1273 tests`

## CHANGELOG entry

```markdown
## [vX.Y.Z] — YYYY-MM-DD

### Added — Sector RAG Pre-filter (`NN_sector_rag.py`)

- `Filter1` (Regulation § N) — DENIED condition; REQUIRES_HUMAN_REVIEW condition
- `Filter2` (Regulation § N) — DENIED condition
- `Filter3` (Regulation § N) — DENIED condition
- `CrossBorderFilter` — adequacy list; sanction-country denial

N new tests. Total: **NNNN passed, 2 skipped**.
```

## Version bump

Bump `version` in `pyproject.toml` and `__version__` in `src/enterprise_rag_patterns/__init__.py` and the citation block in README.
