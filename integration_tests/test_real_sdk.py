"""Real framework/store boundaries; model input is recorded without API calls."""

import asyncio

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.langchain_lcel import FERPAFilterRunnable


def test_langchain_memory_store_to_model():
    from langchain_core.documents import Document
    from langchain_core.embeddings import DeterministicFakeEmbedding
    from langchain_core.runnables import RunnableLambda
    from langchain_core.vectorstores import InMemoryVectorStore

    store = InMemoryVectorStore(DeterministicFakeEmbedding(size=8))
    store.add_documents(
        [
            Document(
                page_content="ALLOWED",
                metadata={"student_id": "s", "institution_id": "i", "category": "academic_record"},
            ),
            Document(
                page_content="SECRET_CANARY",
                metadata={"student_id": "other", "institution_id": "i", "category": "academic_record"},
            ),
            Document(page_content="UNTAGGED_CANARY"),
        ]
    )
    scope = StudentIdentityScope(
        student_id="s",
        institution_id="i",
        requesting_user_id="tester",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )
    seen = []
    chain = (
        store.as_retriever(search_kwargs={"k": 3})
        | FERPAFilterRunnable(scope).as_runnable()
        | RunnableLambda(lambda docs: seen.append([d.page_content for d in docs]))
    )
    chain.invoke("records")
    asyncio.run(chain.ainvoke("records"))
    assert seen == [["ALLOWED"], ["ALLOWED"]]


def test_haystack_memory_store_to_model():
    from haystack import Document, Pipeline, component
    from haystack.components.retrievers.in_memory import InMemoryBM25Retriever
    from haystack.document_stores.in_memory import InMemoryDocumentStore

    from enterprise_rag_patterns.integrations.haystack import _make_haystack_component

    @component
    class Recorder:
        @component.output_types(contents=list)
        def run(self, documents: list):
            return {"contents": [d.content for d in documents]}

    store = InMemoryDocumentStore()
    store.write_documents(
        [
            Document(
                content="records ALLOWED",
                meta={"student_id": "s", "institution_id": "i", "category": "academic_record"},
            ),
            Document(
                content="records SECRET_CANARY",
                meta={"student_id": "other", "institution_id": "i", "category": "academic_record"},
            ),
            Document(content="records UNTAGGED_CANARY"),
        ]
    )
    pipeline = Pipeline()
    pipeline.add_component("retriever", InMemoryBM25Retriever(store))
    pipeline.add_component("guard", _make_haystack_component()())
    pipeline.add_component("model", Recorder())
    pipeline.connect("retriever.documents", "guard.documents")
    pipeline.connect("guard.filtered_documents", "model.documents")
    result = pipeline.run({"retriever": {"query": "records"}, "guard": {"student_id": "s", "institution_id": "i"}})
    assert result["model"]["contents"] == ["records ALLOWED"]


def test_callback_violation_cannot_leak_when_callback_errors_are_suppressed():
    from langchain_core.documents import Document
    from langchain_core.embeddings import DeterministicFakeEmbedding
    from langchain_core.vectorstores import InMemoryVectorStore

    from enterprise_rag_patterns.integrations.langchain import FERPAComplianceCallbackHandler

    store = InMemoryVectorStore(DeterministicFakeEmbedding(size=8))
    store.add_documents(
        [
            Document(
                page_content="SECRET_CANARY",
                metadata={"student_id": "other", "institution_id": "i", "category": "academic_record"},
            )
        ]
    )
    scope = StudentIdentityScope(
        student_id="s",
        institution_id="i",
        requesting_user_id="tester",
        authorized_categories={RecordCategory.ACADEMIC_RECORD},
    )
    handler = FERPAComplianceCallbackHandler(scope, raise_on_violation=True)
    retriever = store.as_retriever()
    assert retriever.invoke("records", config={"callbacks": [handler]}) == []
    assert asyncio.run(retriever.ainvoke("records", config={"callbacks": [handler]})) == []
