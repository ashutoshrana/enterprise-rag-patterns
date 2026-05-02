# Copilot Instructions — enterprise-rag-patterns

## Project Purpose
`enterprise-rag-patterns` is a Python library of regulated-sector RAG pre-filters. Each filter enforces a specific regulation (FERPA, HIPAA, GDPR, EU AI Act, GLBA, etc.) before documents reach the LLM — implementing a 4-layer pipeline pattern for enterprise compliance.

## Core Concepts
- **4-layer filter pipeline** — every example has exactly 4 filters in order: (1) primary data protection, (2) sector-specific, (3) automated-decision/AI-specific, (4) cross-border transfer
- **FilterResult** — frozen dataclass: decision (APPROVED/DENIED/REDACTED/REQUIRES_HUMAN_REVIEW), reason, regulation_citation, requires_logging
- **FilterPipeline** — chains filters; stops at first DENIED or REQUIRES_HUMAN_REVIEW
- **38 regulated-sector examples** — one file per sector in `examples/`

## Package Structure
```
src/enterprise_rag_patterns/
  pipeline.py        — FilterPipeline, FilterResult
  filters/           — shared base classes
examples/
  01_ferpa_rag.py through 38_*.py  — one per regulated sector
tests/
  test_01_ferpa_rag.py through test_38_*.py  — importlib loader pattern
```

## Code Conventions
- All filter classes are `@dataclass(frozen=True)` — immutable by design
- `is_denied` property: returns `True` only for `"DENIED"`, NOT for `"REDACTED"` or `"REQUIRES_HUMAN_REVIEW"`
- Test files use `importlib.util.spec_from_file_location` pattern — register module in `sys.modules` BEFORE `exec_module` (frozen dataclass pickling requirement)
- Every new example increments: README header count, catalog table, trilogy footer in all 3 repo READMEs

## Regulatory Citations
- FERPA 34 CFR Part 99 — education records
- HIPAA 45 CFR 164 — PHI
- GDPR Regulation EU 2016/679 — personal data
- EU AI Act Regulation EU 2024/1689 — AI system obligations
- GLBA 15 U.S.C. § 6801 — financial privacy

## What NOT to Include
- No institution-specific logic (no hardcoded school names, hospital names, financial institution names)
- No customer/client names (SEI, Capella, Strayer) or product names (ELLA, Falcon, Polaris)
- No production credentials or cloud-specific artifacts
- Filters must be cloud-agnostic and LLM-framework-agnostic

## PR Standards
- PR title: conventional commits — `feat: add CCPA California consumer privacy sector` / `fix: FERPA §99.31 exception logic`
- New example = new sector file + test file + README update (3 locations)
- Use the `.claude/skills/add-rag-filter.md` skill for step-by-step guidance
