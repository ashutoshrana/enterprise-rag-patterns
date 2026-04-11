"""
regulations — Regulation-specific RAG compliance patterns.

Each sub-module provides the RAG-layer primitives for a specific regulation.
These modules address the retrieval and context-assembly layer — they are not
general-purpose compliance policy engines.

Available modules
-----------------
- ``gdpr``  — GDPR Article 17 right-to-erasure patterns for RAG systems.
  FERPA patterns are in the parent package (``enterprise_rag_patterns.compliance``).
"""

from .gdpr import ErasureAuditRecord, ErasureRequest, GDPRRAGPolicy

__all__ = [
    "ErasureRequest",
    "ErasureAuditRecord",
    "GDPRRAGPolicy",
]
