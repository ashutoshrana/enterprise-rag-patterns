"""Real retrieval and complete prompt boundaries; no provider calls or unit mocks."""

import asyncio
import sys
from pathlib import Path

import pytest
from haystack.components.builders import PromptBuilder
from haystack.components.retrievers.in_memory import InMemoryBM25Retriever
from haystack.document_stores.in_memory import InMemoryDocumentStore

from enterprise_rag_patterns.compliance import FERPAContextPolicy, RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.haystack import FERPAHaystackFilter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.retrieval_boundary import (  # noqa: E402
    PATHS,
    TEMPLATE,
    RecordingGenerator,
    benchmark,
    documents_for,
    load_fixture,
    pipeline_for,
    run_once,
)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("path", PATHS)
def test_actual_prompt_matches_fixture_boundary(path, async_mode):
    fixture = load_fixture()
    store = InMemoryDocumentStore()
    store.write_documents(documents_for(fixture, len(fixture["documents"])))
    pipeline = pipeline_for(store, fixture["scope"], path, async_mode)
    result = run_once(pipeline, fixture["query"], async_mode)
    observed = set(result["observed_ids"])
    permitted = set(fixture["permitted_ids"])
    if path in ("gate", "combined"):
        assert observed == permitted
        assert "SECRET_" not in result["prompt"]
        assert "ALLOWED" in result["prompt"] and "PUBLIC" in result["prompt"]
    elif path == "bypass":
        assert observed == {document["id"] for document in fixture["documents"]}
        assert "SECRET_TENANT" in result["prompt"]
    else:
        # Attribute comparisons conflate an absent public identity key with null.
        # This is an explicit baseline limitation, not a native security guarantee.
        assert observed == permitted | {"null-public"}
        assert "SECRET_NULL" in result["prompt"]


@pytest.mark.parametrize("async_mode", [False, True])
def test_stale_candidates_rechecked_after_explicit_grant_removal(async_mode):
    fixture = load_fixture()
    store = InMemoryDocumentStore()
    store.write_documents(documents_for(fixture, len(fixture["documents"])))
    retriever = InMemoryBM25Retriever(store, top_k=20)
    if async_mode:
        stale = asyncio.run(retriever.run_async(fixture["query"]))["documents"]
    else:
        stale = retriever.run(fixture["query"])["documents"]
    scope = fixture["scope"]
    snapshots = [scope, {**scope, "authorized_categories": ["financial_aid"]}]
    prompts = []
    for snapshot in snapshots:
        # Existing adapter is synchronous even when an async pipeline schedules it.
        output = FERPAHaystackFilter().run(
            stale,
            student_id=snapshot["student_id"],
            institution_id=snapshot["institution_id"],
            permitted_categories=set(snapshot["authorized_categories"]),
        )
        built = PromptBuilder(template=TEMPLATE, required_variables=["question", "documents"]).run(
            question=fixture["query"], documents=output["filtered_documents"]
        )
        recorder = RecordingGenerator()
        recorded = asyncio.run(recorder.run_async(built["prompt"])) if async_mode else recorder.run(built["prompt"])
        prompts.append(recorded["prompt"])
    assert "[[allowed]]" in prompts[0]
    assert "[[allowed]]" not in prompts[1]
    assert "[[public]]" in prompts[1]
    assert "SECRET_CATEGORY" not in prompts[0]
    assert "SECRET_CATEGORY" in prompts[1]  # now authorized by the explicit new snapshot
    assert all("SECRET_TENANT" not in prompt for prompt in prompts)
    # This is a reused candidate list and a caller-provided updated grant snapshot,
    # not an external cache integration or immediate distributed revocation proof.


def test_report_counts_and_negative_control_are_measured():
    report = benchmark(repeats=2, modes=("sync",))
    assert report["negative_control_detected"] and report["protected_boundary_passed"]
    assert report["authorized_utility_passed"]
    assert len(report["fixture_sha256"]) == 64
    rows = {row["path"]: row for row in report["results"]}
    for path in ("gate", "combined"):
        for sample in rows[path]["samples"]:
            assert sample["authorized_recall"] == 1.0
            assert sample["unauthorized_ids"] == []
            assert sample["elapsed_ms"] >= 0
    assert rows["combined"]["samples"][0]["candidate_count"] < rows["gate"]["samples"][0]["candidate_count"]
    assert all(sample["unauthorized_ids"] for sample in rows["bypass"]["samples"])


def test_negative_control_rejects_uninformative_top_k():
    # With only the highest ranked permitted result, bypass may reveal nothing.
    # Such a run must fail rather than report a successful security benchmark.
    with pytest.raises(AssertionError, match="negative-control"):
        benchmark(repeats=1, top_k=1, modes=("sync",))


def test_oracle_agrees_with_core_only_for_explicit_fixture_scope():
    fixture = load_fixture()
    scope = fixture["scope"]
    policy = FERPAContextPolicy(
        StudentIdentityScope(
            scope["student_id"],
            scope["institution_id"],
            "synthetic-caller",
            authorized_categories={RecordCategory.ACADEMIC_RECORD},
        )
    )
    records = [{"id": row["id"], **row["meta"]} for row in fixture["documents"]]
    assert {row["id"] for row in policy.filter_retrieved_documents(records, category_field="category")} == set(
        fixture["permitted_ids"]
    )
    # Adapter accepts caller-specified strings; core rejects unknown enum values.
    # Do not claim these APIs have interchangeable category semantics.
    from haystack import Document

    unknown = {
        "student_id": scope["student_id"],
        "institution_id": scope["institution_id"],
        "category": "unknown_category",
    }
    assert policy.filter_retrieved_documents([unknown], category_field="category") == []
    document = Document(content="synthetic unknown", meta=unknown)
    assert FERPAHaystackFilter().run([document], scope["student_id"], scope["institution_id"], {"unknown_category"})[
        "filtered_documents"
    ] == [document]


def test_deny_all_gate_cannot_pass_benchmark(monkeypatch):
    def deny_all(self, documents, student_id, institution_id, permitted_categories=None):
        return {"filtered_documents": []}

    monkeypatch.setattr(FERPAHaystackFilter, "run", deny_all)
    with pytest.raises(AssertionError, match="utility"):
        benchmark(repeats=1, modes=("sync",))
