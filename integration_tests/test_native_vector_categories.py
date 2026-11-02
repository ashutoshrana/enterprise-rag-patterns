"""Native vector filter shape/query checks; no hosted service or credentials."""

import pytest

from enterprise_rag_patterns.vector_stores import ComplianceFilter, PineconeComplianceFilter


def test_pinecone_explicit_grants_and_unrestricted_shape():
    scope = ComplianceFilter("s", "i", {"academic_record"})
    assert PineconeComplianceFilter().build_filter(scope)["$and"][-1] == {"category": {"$in": ["academic_record"]}}
    scope.unrestricted_categories = True
    assert len(PineconeComplianceFilter().build_filter(scope)["$and"]) == 2


def test_native_weaviate_filter_shape():
    pytest.importorskip("weaviate")
    from enterprise_rag_patterns.vector_stores import WeaviateComplianceFilter

    def leaves(node):
        if hasattr(node, "filters"):
            return [pair for child in node.filters for pair in leaves(child)]
        return [(node.target, node.value)]

    scope = ComplianceFilter("s", "i", {"academic_record"})
    assert sorted(leaves(WeaviateComplianceFilter().build_filter(scope))) == [
        ("category", "academic_record"),
        ("institution_id", "i"),
        ("student_id", "s"),
    ]
    scope.unrestricted_categories = True
    assert sorted(leaves(WeaviateComplianceFilter().build_filter(scope))) == [
        ("institution_id", "i"),
        ("student_id", "s"),
    ]


def test_native_qdrant_in_memory_query_respects_grants():
    pytest.importorskip("qdrant_client")
    from qdrant_client import QdrantClient, models

    from enterprise_rag_patterns.vector_stores import QdrantComplianceFilter

    client = QdrantClient(":memory:")
    client.create_collection("records", vectors_config=models.VectorParams(size=2, distance=models.Distance.COSINE))
    client.upsert(
        "records",
        points=[
            models.PointStruct(
                id=1,
                vector=[1.0, 0.0],
                payload={"student_id": "s", "institution_id": "i", "category": "academic_record"},
            ),
            models.PointStruct(
                id=2, vector=[1.0, 0.0], payload={"student_id": "s", "institution_id": "i", "category": "financial_aid"}
            ),
            models.PointStruct(
                id=3,
                vector=[1.0, 0.0],
                payload={"student_id": "other", "institution_id": "i", "category": "academic_record"},
            ),
        ],
    )

    def query_ids(selector):
        if hasattr(client, "query_points"):
            points = client.query_points("records", query=[1.0, 0.0], query_filter=selector).points
        else:
            points = client.search("records", query_vector=[1.0, 0.0], query_filter=selector)
        return {point.id for point in points}

    scope = ComplianceFilter("s", "i", {"academic_record"})
    selector = QdrantComplianceFilter().build_filter(scope)
    assert selector.model_dump()["must"][-1]["match"] == {"any": ["academic_record"]}
    assert query_ids(selector) == {1}
    scope.unrestricted_categories = True
    selector = QdrantComplianceFilter().build_filter(scope)
    assert query_ids(selector) == {1, 2}
    scope.unrestricted_categories = False
    scope.permitted_categories.clear()
    with pytest.raises(ValueError, match="No private category grants"):
        query_ids(QdrantComplianceFilter().build_filter(scope))
    client.close()
