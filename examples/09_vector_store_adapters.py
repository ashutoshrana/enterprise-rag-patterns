"""
09_vector_store_adapters.py — FERPA compliance filters across vector stores.

Shows how the same ``ComplianceFilter`` (student + institution + categories)
is translated into each store's native filter format via the corresponding
adapter.  The four adapters covered:

  - ``PGVectorComplianceFilter``   — SQL WHERE clause (psycopg2 / asyncpg)
  - ``PineconeComplianceFilter``   — Pinecone ``$and`` metadata filter dict
  - ``ChromaComplianceFilter``     — ChromaDB ``where`` filter dict
  - ``WeaviateComplianceFilter``   — Weaviate v4 ``Filter`` object (lazy import)

All adapters accept the same ``ComplianceFilter`` input and return the store's
native pre-filter representation.  Because the filter is applied before ANN
ranking in every store, no unauthorized documents can leak through the
retrieval step — FERPA 34 CFR § 99.3 pre-filter requirement is satisfied at
the vector store layer.

Run:
    python examples/09_vector_store_adapters.py
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from enterprise_rag_patterns.vector_stores import (
    ChromaComplianceFilter,
    ComplianceFilter,
    PGVectorComplianceFilter,
    PineconeComplianceFilter,
)

# ---------------------------------------------------------------------------
# Scenario: Enrollment advisor querying academic records for one student
# ---------------------------------------------------------------------------
# The advisor is authorized to access ACADEMIC_RECORD and DIRECTORY_INFORMATION
# for student S-001 at ACME University.  Only documents with those exact
# metadata values should be returned — all other students and institutions must
# be excluded at the vector store query level.

SCOPE = ComplianceFilter(
    student_id="S-001",
    institution_id="acme-univ",
    permitted_categories={"academic_record", "directory_information"},
)

# ---------------------------------------------------------------------------
# Scenario 2: HIPAA — clinician accessing a patient's PHI for treatment
# ---------------------------------------------------------------------------
# No category restriction — all PHI categories authorized for this clinician.

HIPAA_SCOPE = ComplianceFilter(
    student_id="PAT-001",  # re-using student_id field as patient_id
    institution_id="clinic-a",  # covered entity
    permitted_categories=set(),  # no category restriction — all categories
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _pprint(obj: Any, indent: int = 2) -> str:
    """Pretty-print JSON-serialisable objects; fall back to repr."""
    try:
        return json.dumps(obj, indent=indent, sort_keys=True)
    except TypeError:
        return repr(obj)


# ---------------------------------------------------------------------------
# 1. pgvector (psycopg2) — JSON metadata column
# ---------------------------------------------------------------------------


def demo_pgvector_jsonb() -> None:
    adapter = PGVectorComplianceFilter()
    where_sql, params = adapter.build_filter(SCOPE)

    print("─" * 68)
    print("pgvector / psycopg2 — JSONB metadata column")
    print("─" * 68)
    print(
        """
Schema:
    CREATE TABLE documents (
        id         BIGSERIAL PRIMARY KEY,
        embedding  VECTOR(1536),
        metadata   JSONB NOT NULL DEFAULT '{}'
    );
    -- Each document has metadata:
    --   {"student_id": "S-001", "institution_id": "acme-univ",
    --    "category": "academic_record", "content": "..."}
"""
    )

    print("Generated WHERE clause:")
    print(f"  {where_sql}")
    print()
    print("Parameters:", params)
    print()

    full_query = f"""SELECT id, metadata->>'content' AS content
FROM documents
WHERE {where_sql}
ORDER BY embedding <=> %s   -- cosine distance to query embedding
LIMIT 5;"""
    print("Full query:")
    for line in full_query.strip().splitlines():
        print(f"  {line}")

    print()
    print("Usage (psycopg2):")
    print(
        """  where_sql, params = adapter.build_filter(scope)
  cursor.execute(
      f"SELECT id, metadata->>'content' AS content "
      f"FROM documents WHERE {where_sql} "
      f"ORDER BY embedding <=> %s LIMIT 5",
      params + [embedding_bytes],
  )"""
    )


# ---------------------------------------------------------------------------
# 2. pgvector (psycopg2) — normalised columns
# ---------------------------------------------------------------------------


def demo_pgvector_columns() -> None:
    adapter = PGVectorComplianceFilter(use_json_column=False)
    where_sql, params = adapter.build_filter(SCOPE)

    print()
    print("─" * 68)
    print("pgvector / psycopg2 — normalised columns (explicit schema)")
    print("─" * 68)
    print(
        """
Schema:
    CREATE TABLE documents (
        id             BIGSERIAL PRIMARY KEY,
        embedding      VECTOR(1536),
        student_id     TEXT NOT NULL,
        institution_id TEXT NOT NULL,
        category       TEXT
    );
"""
    )

    print("Generated WHERE clause:")
    print(f"  {where_sql}")
    print()
    print("Parameters:", params)


# ---------------------------------------------------------------------------
# 3. pgvector (asyncpg) — async variant
# ---------------------------------------------------------------------------


def demo_pgvector_asyncpg() -> None:
    adapter = PGVectorComplianceFilter()
    where_sql, params = adapter.build_asyncpg_filter(SCOPE)

    print()
    print("─" * 68)
    print("pgvector / asyncpg — async variant ($N placeholders)")
    print("─" * 68)
    print()
    print("Generated WHERE clause:")
    print(f"  {where_sql}")
    print()
    print("Parameters:", params)
    print()
    print("Usage (asyncpg with embedding as $1):")
    print(
        """  # Shift filter params to start at $2 by prepending the embedding param
  where_sql, params = adapter.build_asyncpg_filter(scope)
  # Then prepend embedding param and adjust indexes if needed
  rows = await conn.fetch(
      f"SELECT id, content FROM documents "
      f"WHERE {where_sql} "
      f"ORDER BY embedding <=> $1::vector LIMIT 5",
      embedding_list, *params,
  )"""
    )


# ---------------------------------------------------------------------------
# 4. Pinecone — metadata filter dict
# ---------------------------------------------------------------------------


def demo_pinecone() -> None:
    adapter = PineconeComplianceFilter()
    filter_dict = adapter.build_filter(SCOPE)

    print()
    print("─" * 68)
    print("Pinecone v8 — metadata filter dict ($and / $eq / $in)")
    print("─" * 68)
    print()
    print("Generated filter dict:")
    print(_pprint(filter_dict))
    print()
    print("Usage (Pinecone v8 sync):")
    print(
        """  from pinecone import Pinecone
  pc = Pinecone(api_key="...")
  index = pc.Index(host="https://my-index-xyz.svc.pinecone.io")

  filter_dict = adapter.build_filter(scope)
  results = index.query(
      vector=embedding,
      filter=filter_dict,
      top_k=5,
      include_metadata=True,
  )"""
    )
    print()
    print("Usage (Pinecone v8 async — FastAPI):")
    print(
        """  async with pc.IndexAsyncio(host="...") as idx:
      results = await idx.query(
          vector=embedding,
          filter=filter_dict,
          top_k=5,
          include_metadata=True,
      )"""
    )

    # Also show namespace isolation variant
    print()
    print("Variant — namespace isolation (defense-in-depth):")
    print(
        """  from enterprise_rag_patterns.vector_stores import PineconeNamespaceIsolation
  ns_adapter = PineconeNamespaceIsolation()
  namespace, filter_dict = ns_adapter.build_filter(scope)
  # namespace == "acme-univ"  (institution-level hardware isolation)
  # filter_dict == {"student_id": {"$eq": "S-001"}} + optional category
  results = index.query(
      vector=embedding,
      namespace=namespace,
      filter=filter_dict,
      top_k=5,
  )"""
    )


# ---------------------------------------------------------------------------
# 5. ChromaDB — where filter dict
# ---------------------------------------------------------------------------


def demo_chroma() -> None:
    adapter = ChromaComplianceFilter()
    filter_dict = adapter.build_filter(SCOPE)

    print()
    print("─" * 68)
    print("ChromaDB v1.5+ — where filter dict ($and / $eq / $in)")
    print("─" * 68)
    print()
    print("Generated where filter:")
    print(_pprint(filter_dict))
    print()
    print("Usage (ChromaDB):")
    print(
        """  import chromadb

  client = chromadb.HttpClient(host="localhost", port=8000)
  collection = client.get_collection("student_documents")

  filter_dict = adapter.build_filter(scope)
  results = collection.query(
      query_embeddings=[embedding],
      where=filter_dict,
      n_results=5,
      include=["documents", "metadatas", "distances"],
  )"""
    )


# ---------------------------------------------------------------------------
# 6. Weaviate — Filter object (no weaviate dependency needed for this demo)
# ---------------------------------------------------------------------------


def demo_weaviate() -> None:
    print()
    print("─" * 68)
    print("Weaviate v4 — Filter object (lazy import)")
    print("─" * 68)
    print()
    print(
        "Note: WeaviateComplianceFilter.build_filter() returns a native "
        "weaviate.classes.query.Filter object.\n"
        "The weaviate-client package must be installed to call build_filter().\n"
        "Showing equivalent filter construction for illustration:"
    )
    print()

    # Show the equivalent filter construction without importing weaviate
    # (weaviate is not in the test deps)
    print("Generated filter (equivalent):")
    print(
        """  from weaviate.classes.query import Filter

  f = (
      Filter.by_property("student_id").equal("S-001")
      & Filter.by_property(.equal("acme-univ")
      & (
          Filter.by_property("category").equal("academic_record")
          | Filter.by_property("category").equal("directory_information")
      )
  )"""
    )
    print()
    print("Usage (Weaviate v4):")
    print(
        """  from enterprise_rag_patterns.vector_stores import WeaviateComplianceFilter
  import weaviate

  client = weaviate.connect_to_local()
  collection = client.collections.get("StudentDocuments")

  adapter = WeaviateComplianceFilter()
  filter_obj = adapter.build_filter(scope)

  results = collection.query.near_text(
      query="graduation requirements",
      filters=filter_obj,
      limit=5,
      return_metadata=weaviate.classes.query.MetadataQuery(distance=True),
  )
  client.close()"""
    )


# ---------------------------------------------------------------------------
# 7. Filter semantics: no-category-restriction case (HIPAA scenario)
# ---------------------------------------------------------------------------


def demo_no_category_restriction() -> None:
    print()
    print("─" * 68)
    print("Variant — no category restriction (HIPAA treatment authorization)")
    print("─" * 68)
    print()
    print("ComplianceFilter(student_id='PAT-001', institution_id='clinic-a', permitted_categories=set())")
    print()

    # pgvector: no category clause generated
    adapter = PGVectorComplianceFilter()
    where_sql, params = adapter.build_filter(HIPAA_SCOPE)
    print(f"pgvector WHERE:  {where_sql}")
    print(f"params:          {params}")
    print("(no category clause — all PHI categories accessible for treatment purpose)")
    print()

    # Pinecone: no $in clause
    p_adapter = PineconeComplianceFilter()
    p_filter = p_adapter.build_filter(HIPAA_SCOPE)
    print("Pinecone filter:")
    print(_pprint(p_filter))

    # Chroma: no $in clause
    c_adapter = ChromaComplianceFilter()
    c_filter = c_adapter.build_filter(HIPAA_SCOPE)
    print()
    print("ChromaDB where filter:")
    print(_pprint(c_filter))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 68)
    print("Vector Store Compliance Filter Adapters — enterprise-rag-patterns")
    print("=" * 68)
    print()
    print("ComplianceFilter(")
    print(f"    student_id        = {SCOPE.student_id!r},")
    print(f"    institution_id    = {SCOPE.institution_id!r},")
    print(f"    permitted_categories = {sorted(SCOPE.permitted_categories)!r},")
    print(")")

    demo_pgvector_jsonb()
    demo_pgvector_columns()
    demo_pgvector_asyncpg()
    demo_pinecone()
    demo_chroma()
    demo_weaviate()
    demo_no_category_restriction()

    print()
    print("=" * 68)
    print("KEY POINTS")
    print("=" * 68)
    print(
        """
All four adapters implement the same interface:

    adapter.build_filter(ComplianceFilter(...)) → native_filter

The native filter is passed directly to the vector store's query method
*before* the ANN search runs.  This is pre-filter semantics: unauthorized
vectors are excluded from the candidate set, not just removed from results.

Pre-filter satisfies FERPA 34 CFR § 99.3 at the retrieval layer.

pgvector SQL reference:
    https://github.com/pgvector/pgvector

Pinecone metadata filter reference:
    https://docs.pinecone.io/guides/data/filter-with-metadata

ChromaDB where filter reference:
    https://docs.trychroma.com/guides#using-where-filters

Weaviate v4 filter reference:
    https://weaviate.io/developers/weaviate/search/filters
"""
    )


if __name__ == "__main__":
    main()
