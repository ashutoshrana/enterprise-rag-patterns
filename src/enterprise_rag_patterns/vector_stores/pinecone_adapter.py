"""
pinecone_adapter.py — Pinecone compliance filter adapters for FERPA/HIPAA scoping.

Provides two complementary adapters:

1. ``PineconeComplianceFilter`` — builds a Pinecone metadata filter dict for use
   with ``Index.query(filter=...)``. Student + institution + category clauses.

2. ``PineconeNamespaceIsolation`` — defense-in-depth adapter for multi-institution
   deployments. Maps institution_id → Pinecone namespace (hardware-level isolation)
   AND adds student_id metadata filter (software-level isolation). Supports Pinecone
   v8 async API (``IndexAsyncio``) for FastAPI / asyncio environments.

   Defense-in-depth rationale:
     Layer 1 — Namespace scoping: Pinecone namespaces are physically isolated
               partitions. Cross-namespace queries are impossible at the index level.
     Layer 2 — Metadata filter: Even within a namespace, only vectors matching
               ``student_id`` (and optional ``category``) are returned.
   Both layers must match; a single filter bypass cannot expose cross-student data.

Pinecone filter syntax (v8):
  - Exact match:   {"key": {"$eq": "value"}}
  - Set membership: {"key": {"$in": ["a", "b"]}}
  - Logical AND:   {"$and": [{...}, {...}]}

Pinecone v8 async API (context7-verified):
  ``pc.IndexAsyncio(host=...)`` — async context manager
  ``await idx.query(vector=..., namespace=..., filter=..., top_k=..., include_metadata=True)``

Regulatory context:
  FERPA 34 CFR § 99.3: retrieval must be scoped to the authorised student's
  records at the index query layer, not post-hoc in application code.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .base import ComplianceFilter, VectorStoreFilterAdapter


class PineconeComplianceFilter(VectorStoreFilterAdapter):
    """
    Builds a Pinecone metadata filter dict for FERPA/HIPAA compliance scoping.

    The produced dict can be passed directly to
    ``pinecone.Index.query(filter=...)`` or ``Index.upsert`` namespace queries.

    Pinecone executes the filter at the ANN search layer, so only vectors whose
    metadata matches the filter are considered — pre-filter semantics by default
    when ``serverless_index=True`` or when the index has metadata index enabled.

    Example::

        adapter = PineconeComplianceFilter()
        f = adapter.build_filter(ComplianceFilter(
            student_id="S-001",
            institution_id="acme-univ",
            permitted_categories={"academic_record", "directory_information"},
        ))
        # f == {
        #     "$and": [
        #         {"student_id": {"$eq": "S-001"}},
        #         {"institution_id": {"$eq": "acme-univ"}},
        #         {"category": {"$in": ["academic_record", "directory_information"]}},
        #     ]
        # }
        index.query(vector=embedding, filter=f, top_k=10)
    """

    def build_filter(self, scope: ComplianceFilter) -> dict[str, Any]:
        """
        Build a Pinecone ``$and`` filter dict from *scope*.

        Always includes student_id and institution_id exact-match clauses.
        Adds a category ``$in`` clause when ``scope.permitted_categories`` is
        non-empty.  The metadata fields are assumed to be named ``student_id``,
        ``institution_id``, and ``category`` on each Pinecone vector — adjust
        the field names via subclassing if your index uses different names.

        Args:
            scope: Compliance filter specifying student, institution, and
                permitted record categories.

        Returns:
            A ``dict`` compatible with ``pinecone.Index.query(filter=...)``.
        """
        clauses: list[dict[str, Any]] = [
            {"student_id": {"$eq": scope.student_id}},
            {"institution_id": {"$eq": scope.institution_id}},
        ]

        if scope.permitted_categories:
            clauses.append({"category": {"$in": sorted(scope.permitted_categories)}})

        return {"$and": clauses}


class PineconeNamespaceIsolation:
    """
    Defense-in-depth namespace isolation for Pinecone v8 multi-institution deployments.

    Combines two independent FERPA enforcement layers:

    * **Layer 1 — Namespace**: each institution maps to a dedicated Pinecone
      namespace (hardware isolation). Cross-institution queries are structurally
      impossible — a query in namespace ``"acme-univ"`` never touches vectors in
      namespace ``"purdue"``.

    * **Layer 2 — Metadata filter**: within the institution namespace, only vectors
      whose ``student_id`` metadata matches the authorized student are returned.
      Optionally filtered by ``category`` for record-type enforcement.

    Both layers are applied on every query; neither alone is sufficient under
    a defense-in-depth model.

    Supports both synchronous (``query_sync``) and asynchronous (``async_query``)
    Pinecone v8 clients. The async variant uses ``IndexAsyncio`` for FastAPI and
    asyncio-based applications.

    Installation::

        pip install 'enterprise-rag-patterns[pinecone]'

    Usage — sync::

        from pinecone import Pinecone
        from enterprise_rag_patterns.compliance import StudentIdentityScope, RecordCategory
        from enterprise_rag_patterns.vector_stores.pinecone_adapter import (
            PineconeNamespaceIsolation,
        )

        scope = StudentIdentityScope(
            student_id="stu-001",
            institution_id="acme-univ",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
        isolator = PineconeNamespaceIsolation(index_host="my-index.pinecone.io")

        pc = Pinecone(api_key="...")
        index = pc.Index(host=isolator.index_host)
        results = isolator.query_sync(index, vector=embedding, scope=scope, top_k=10)

    Usage — async::

        from pinecone import Pinecone
        isolator = PineconeNamespaceIsolation(index_host="my-index.pinecone.io")

        pc = Pinecone(api_key="...")
        results = await isolator.async_query(pc, vector=embedding, scope=scope, top_k=10)

    Args:
        index_host: Pinecone index host URL (e.g. ``"my-idx.svc.us-east1.pinecone.io"``).
        namespace_resolver: Optional callable mapping ``institution_id → namespace``.
            Defaults to using ``institution_id`` directly as the namespace name.
        student_id_field: Metadata key for student ID. Default: ``"student_id"``.
        category_field: Metadata key for record category. Default: ``"category"``.
    """

    def __init__(
        self,
        index_host: str,
        namespace_resolver: Callable[[str], str] | None = None,
        student_id_field: str = "student_id",
        category_field: str = "category",
    ) -> None:
        self.index_host = index_host
        self._namespace_resolver = namespace_resolver
        self.student_id_field = student_id_field
        self.category_field = category_field

    def namespace_for(self, institution_id: str) -> str:
        """
        Resolve an institution identifier to a Pinecone namespace name.

        Args:
            institution_id: The institution identifier from ``StudentIdentityScope``.

        Returns:
            The Pinecone namespace string for this institution.
        """
        if self._namespace_resolver is not None:
            return self._namespace_resolver(institution_id)
        return institution_id

    def build_metadata_filter(self, scope: ComplianceFilter) -> dict[str, Any]:
        """
        Build the Layer 2 metadata filter (student_id + optional category).

        Note: ``institution_id`` is NOT included here because it is already
        enforced at the namespace level (Layer 1). Adding it to the metadata
        filter would be redundant but harmless; it is omitted to keep filters
        minimal and index-efficient.

        Args:
            scope: Compliance filter specifying student and permitted categories.

        Returns:
            A Pinecone metadata filter dict.
        """
        student_clause: dict[str, Any] = {self.student_id_field: {"$eq": scope.student_id}}

        if not scope.permitted_categories:
            return student_clause

        category_clause: dict[str, Any] = {self.category_field: {"$in": sorted(scope.permitted_categories)}}
        return {"$and": [student_clause, category_clause]}

    def query_sync(
        self,
        index: Any,
        vector: list[float],
        scope: ComplianceFilter,
        top_k: int = 10,
        include_values: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Synchronous namespace-isolated query (Pinecone v8 ``Index``).

        Applies namespace (Layer 1) and metadata filter (Layer 2) on every call.

        Args:
            index: A Pinecone v8 ``Index`` object (``pc.Index(host=...)``).
            vector: Query embedding vector.
            scope: ``ComplianceFilter`` defining authorized student and categories.
            top_k: Maximum number of results to return.
            include_values: Whether to include vector values in results.
            **kwargs: Additional kwargs forwarded to ``Index.query()``.

        Returns:
            Pinecone query response (``QueryResponse``).
        """
        namespace = self.namespace_for(scope.institution_id)
        metadata_filter = self.build_metadata_filter(scope)
        return index.query(
            vector=vector,
            namespace=namespace,
            filter=metadata_filter,
            top_k=top_k,
            include_metadata=True,
            include_values=include_values,
            **kwargs,
        )

    async def async_query(
        self,
        pinecone_client: Any,
        vector: list[float],
        scope: ComplianceFilter,
        top_k: int = 10,
        include_values: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Asynchronous namespace-isolated query (Pinecone v8 ``IndexAsyncio``).

        Opens an ``IndexAsyncio`` context manager, applies namespace (Layer 1)
        and metadata filter (Layer 2), and returns results.

        Compatible with FastAPI, aiohttp, and all asyncio-based applications.

        Args:
            pinecone_client: A Pinecone v8 ``Pinecone`` client instance.
            vector: Query embedding vector.
            scope: ``ComplianceFilter`` defining authorized student and categories.
            top_k: Maximum number of results to return.
            include_values: Whether to include vector values in results.
            **kwargs: Additional kwargs forwarded to ``IndexAsyncio.query()``.

        Returns:
            Pinecone query response (``QueryResponse``).

        Example::

            pc = Pinecone(api_key="...")
            isolator = PineconeNamespaceIsolation(host="my-idx.pinecone.io")
            results = await isolator.async_query(pc, vector=embedding, scope=scope)
        """
        namespace = self.namespace_for(scope.institution_id)
        metadata_filter = self.build_metadata_filter(scope)
        async with pinecone_client.IndexAsyncio(host=self.index_host) as idx:
            return await idx.query(
                vector=vector,
                namespace=namespace,
                filter=metadata_filter,
                top_k=top_k,
                include_metadata=True,
                include_values=include_values,
                **kwargs,
            )
