"""
vector_stores — Compliance-scoped filter adapters for enterprise vector stores.

Each adapter translates a ``ComplianceFilter`` into the native filter format
expected by a specific vector store, enabling FERPA/HIPAA pre-filter scoping
without conditional branching in application code.

All optional library imports are lazy (inside ``build_filter``), so this
sub-package can be imported without any vector store client installed.

Supported stores
----------------
- Pinecone v8      → ``PineconeComplianceFilter``, ``PineconeNamespaceIsolation``
- Weaviate v4      → ``WeaviateComplianceFilter``
- Qdrant v1.17+    → ``QdrantComplianceFilter``
- ChromaDB v1.5+   → ``ChromaComplianceFilter``
- pgvector / PostgreSQL → ``PGVectorComplianceFilter`` (psycopg2/asyncpg),
                          ``PGVectorSQLAlchemyFilter`` (SQLAlchemy ORM/Core)
"""

from .base import ComplianceFilter, VectorStoreFilterAdapter
from .chroma_adapter import ChromaComplianceFilter
from .pgvector_adapter import PGVectorComplianceFilter, PGVectorSQLAlchemyFilter
from .pinecone_adapter import PineconeComplianceFilter, PineconeNamespaceIsolation
from .qdrant_adapter import QdrantComplianceFilter
from .weaviate_adapter import WeaviateComplianceFilter

__all__ = [
    "ComplianceFilter",
    "VectorStoreFilterAdapter",
    "PineconeComplianceFilter",
    "PineconeNamespaceIsolation",
    "WeaviateComplianceFilter",
    "QdrantComplianceFilter",
    "ChromaComplianceFilter",
    "PGVectorComplianceFilter",
    "PGVectorSQLAlchemyFilter",
]
