# Contributing to enterprise-rag-patterns

Thank you for your interest in contributing.  This repository provides
architecture-first reference patterns for compliance-aware retrieval-augmented
generation in regulated enterprise environments.  Contributions that make the
patterns clearer, more reusable, or more useful to teams building production
systems are welcome.

---

## Table of contents

1. [Development setup](#1-development-setup)
2. [Repository structure](#2-repository-structure)
3. [How to add a new vector store adapter](#3-how-to-add-a-new-vector-store-adapter)
4. [How to add a new regulation module](#4-how-to-add-a-new-regulation-module)
5. [How to add a new framework integration](#5-how-to-add-a-new-framework-integration)
6. [PR checklist](#6-pr-checklist)
7. [Ecosystem verification](#7-ecosystem-verification)
8. [Out of scope](#8-out-of-scope)

---

## 1. Development setup

```bash
# 1. Clone the repository
git clone https://github.com/ashutoshrana/enterprise-rag-patterns.git
cd enterprise-rag-patterns

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install the package in editable mode with all dev dependencies
pip install -e ".[dev]"

# 4. Verify the test suite passes
pytest tests/ -v

# 5. Verify linting and type checks pass
ruff check src/ tests/
mypy src/
```

The `[dev]` extra installs `pytest`, `pytest-cov`, `ruff`, and `mypy`.
No vector store clients, LLM frameworks, or cloud SDKs are required for
the test suite — all optional dependencies use lazy imports and tests
use duck-typed stubs.

---

## 2. Repository structure

```
src/enterprise_rag_patterns/
├── compliance.py             # Core FERPA primitives (StudentIdentityScope, FERPAContextPolicy)
├── async_compliance.py       # Async wrappers for async AI frameworks
├── context.py                # ContextEnvelope, ContextSource
├── policy.py                 # ActionPolicy, EscalationRule
├── session.py                # SessionState (cross-channel continuity)
├── vector_stores/            # Vector store filter adapters
│   ├── base.py               # ComplianceFilter, VectorStoreFilterAdapter ABC
│   ├── pinecone_adapter.py
│   ├── weaviate_adapter.py
│   ├── qdrant_adapter.py
│   └── chroma_adapter.py
├── integrations/             # Framework integration components
│   ├── llama_index.py
│   └── haystack.py
└── regulations/              # Regulation-specific RAG patterns
    └── gdpr.py
tests/
docs/
```

---

## 3. How to add a new vector store adapter

### Step 1 — Open an issue first

Before writing code, open an issue using the
[New vector store adapter](.github/ISSUE_TEMPLATE/new-vector-store.md) template.
Briefly describe the store, its filter syntax, and the minimum client version.

### Step 2 — Create the adapter file

Create `src/enterprise_rag_patterns/vector_stores/<store>_adapter.py`.

**Template:**

```python
"""
<store>_adapter.py — <StoreName> filter adapter for FERPA/HIPAA compliance scoping.

Brief description of the store's filter syntax and the version this adapter targets.

Regulatory context:
  FERPA 34 CFR § 99.3: retrieval must be scoped to the authorised student's
  records at the index query layer — pre-filter, not post-filter.
"""

from __future__ import annotations

from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class <StoreName>ComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a <StoreName> filter object for compliance-scoped queries.

    Lazy import: <store-client-package> is imported inside build_filter.

    Example::

        adapter = <StoreName>ComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="strayer",
            permitted_categories={"academic_record"},
        ))
        # Pass f to the store's query API
    """

    def build_filter(self, scope: ComplianceFilter) -> Any:
        """
        Build a <StoreName>-native filter from scope.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A filter value compatible with <StoreName>'s query API.

        Raises:
            ImportError: If <store-client-package> is not installed.
        """
        try:
            # Lazy import — keeps the package importable without the client
            import <store_client>  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "<store-client-package> is required. "
                "Install it with: pip install <store-client-package>>=<min-version>"
            ) from exc

        # Build and return the store-native filter object here
        raise NotImplementedError
```

### Step 3 — Export the adapter

Add the class to `src/enterprise_rag_patterns/vector_stores/__init__.py`:

```python
from .<store>_adapter import <StoreName>ComplianceFilter

__all__ = [
    ...
    "<StoreName>ComplianceFilter",
]
```

### Step 4 — Add an optional dependency

Add a new entry to `[project.optional-dependencies]` in `pyproject.toml`:

```toml
<store> = ["<store-client-package>>=<min-version>"]
```

Also add it to the `all` group.

### Step 5 — Write tests

Add tests to `tests/test_vector_store_adapters.py`.  Tests must not import
the optional client library — verify the filter structure using assertions
on the returned Python objects (dicts, attribute access on stubs, etc.).

### Step 6 — Update ECOSYSTEM.md

Add a row to the "Vector Stores" table in `ECOSYSTEM.md`.

---

## 4. How to add a new regulation module

### Step 1 — Open an issue

Use the [New regulation](.github/ISSUE_TEMPLATE/new-regulation.md) template.
Cite the specific regulation sections your module addresses.

### Step 2 — Create the regulation file

Create `src/enterprise_rag_patterns/regulations/<regulation>.py`.

**Structure to follow:**

```python
"""
regulations/<regulation>.py — <Regulation Name> RAG-layer compliance patterns.

Scope: RAG-layer patterns only. This is not a general-purpose <Regulation> engine.

Regulatory context:
  <Regulation> <Section> — <Quote or summary of requirement>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class <Regulation>Request:
    """
    Represents a <Regulation> compliance request.

    Regulatory reference: <Regulation> <Section>.
    """
    subject_id: str
    request_id: str
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    regulation: str = "<REGULATION>"


class <Regulation>RAGPolicy:
    """
    RAG-layer policy primitives for <Regulation> compliance.

    Regulatory reference: <Regulation> <Section>.
    """

    def filter_for_subject(
        self,
        documents: list[dict[str, object]],
        subject_id_field: str = "subject_id",
        subject_id: str | None = None,
    ) -> list[dict[str, object]]:
        """
        Remove documents belonging to a subject.

        Regulatory reference: <Regulation> <Section>.
        """
        ...
```

### Step 3 — Export from `regulations/__init__.py`

```python
from .<regulation> import <Regulation>Request, <Regulation>RAGPolicy

__all__ = [
    ...
    "<Regulation>Request",
    "<Regulation>RAGPolicy",
]
```

### Step 4 — Write tests

Add `tests/test_<regulation>.py` covering all public methods.

### Step 5 — Update ECOSYSTEM.md

Add a row to the "Regulations" table.

---

## 5. How to add a new framework integration

### Step 1 — Open an issue

Use the [New framework integration](.github/ISSUE_TEMPLATE/new-framework-integration.md) template.

### Step 2 — Create the integration file

Create `src/enterprise_rag_patterns/integrations/<framework>.py`.

Key requirements:

- **Lazy import**: Import the framework library inside the method, not at module level.
- **Duck typing**: Do not inherit from framework base classes at class definition time — only reference them inside methods where the import is already guarded.
- **Audit logging**: Emit a structured log entry (via `logging`) citing the relevant regulation section.
- **No hard dependency**: The module must be importable without the framework installed.

```python
"""
integrations/<framework>.py — <Framework> integration for FERPA compliance.

Lazy import: <framework-package> is imported inside methods only.

Regulatory context: FERPA 34 CFR § 99.32 — audit log requirement.
"""

from __future__ import annotations

import logging
from typing import Any

from ..compliance import StudentIdentityScope

logger = logging.getLogger(__name__)


class FERPA<Framework>Filter:
    """
    <Framework> component that enforces FERPA document-level scoping.

    Lazy import: <framework-package> imported inside run/process methods.
    """

    def __init__(self, scope: StudentIdentityScope) -> None:
        """Initialise with an authorised identity scope."""
        self.scope = scope

    def run(self, documents: list[Any], **kwargs: Any) -> dict[str, list[Any]]:
        """
        Filter documents to those matching self.scope.

        Regulatory reference: FERPA 34 CFR § 99.32.
        """
        ...
```

### Step 3 — Export from `integrations/__init__.py`

```python
from .<framework> import FERPA<Framework>Filter
__all__ = [..., "FERPA<Framework>Filter"]
```

### Step 4 — Write tests using duck-typed stubs

```python
class _StubDoc:
    def __init__(self, meta: dict) -> None:
        self.meta = meta

def test_ferpa_framework_filter_passes_matching_doc():
    ...
```

---

## 6. PR checklist

Before submitting a pull request, verify all of the following:

- [ ] **Tests pass**: `pytest tests/ -v` exits with code 0
- [ ] **Ruff clean**: `ruff check src/ tests/` reports no issues (line-length = 120)
- [ ] **Mypy clean**: `mypy src/` reports no errors (`ignore_missing_imports = true`)
- [ ] **Docstrings present**: Every public class and function has a docstring
- [ ] **Regulation citations**: Docstrings for compliance-relevant methods cite the specific regulation section (e.g., `34 CFR § 99.32`, `GDPR Article 17`)
- [ ] **Lazy imports**: Optional library imports are inside methods/functions, not at module level
- [ ] **Tests use stubs**: Test files do not import optional libraries (pinecone, weaviate, qdrant, chromadb, llama_index, haystack, etc.)
- [ ] **CHANGELOG updated**: New entries added under `## [Unreleased]` or a versioned section
- [ ] **ECOSYSTEM.md updated**: New adapter/regulation/integration added to the compatibility table
- [ ] **`__init__.py` updated**: New public symbols exported from the relevant sub-package

---

## 7. Ecosystem verification

After adding your contribution, run the full test suite to verify nothing is broken:

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run only your new tests
pytest tests/test_<your_module>.py -v

# Run with coverage report
pytest tests/ --cov=src/enterprise_rag_patterns --cov-report=term-missing

# Lint check
ruff check src/ tests/

# Type check
mypy src/
```

All four commands must exit with code 0 before the PR can be merged.

---

## 8. Out of scope

The following contributions will not be accepted:

- Vendor-specific sales material or promotional content
- Branded customer examples or non-anonymized case studies
- Private implementation details that expose operational security patterns
- Framework integrations that require the framework as a hard (non-optional) dependency
- Regulation modules that make legal conclusions rather than providing RAG-layer patterns
- Code that does not include regulatory citations in docstrings
