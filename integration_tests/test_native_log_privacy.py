"""Actual callback dispatch must not copy identities into ordinary SDK logs."""

import logging

import pytest
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.langchain import FERPAComplianceCallbackHandler

IDS = ("PRIVATE_STUDENT", "PRIVATE_INSTITUTION", "PRIVATE_REQUESTOR")


class Retriever(BaseRetriever):
    def _get_relevant_documents(self, query, *, run_manager):
        return [
            Document(
                page_content="owned",
                metadata={"student_id": IDS[0], "institution_id": IDS[1], "category": "academic_record"},
            ),
            Document(
                page_content="other",
                metadata={"student_id": "FOREIGN_STUDENT", "institution_id": IDS[1], "category": "academic_record"},
            ),
        ]


def handler(**kwargs):
    scope = StudentIdentityScope(*IDS, authorized_categories={RecordCategory.ACADEMIC_RECORD})
    return FERPAComplianceCallbackHandler(scope, **kwargs)


@pytest.mark.parametrize("violation", [False, True])
def test_default_callback_logs_and_violation_text_exclude_identifiers(caplog, violation):
    with caplog.at_level(logging.INFO):
        docs = Retriever().invoke("fixture", config={"callbacks": [handler(raise_on_violation=violation)]})
    assert [d.page_content for d in docs] == ["owned"]
    assert caplog.records
    for identifier in (*IDS, "FOREIGN_STUDENT"):
        assert identifier not in caplog.text
        assert all(identifier not in str(vars(record)) for record in caplog.records)
    assert "audit_id=" in caplog.text


def test_explicit_sink_receives_correlated_detail_without_log_copy(caplog):
    records = []
    with caplog.at_level(logging.INFO):
        Retriever().invoke("fixture", config={"callbacks": [handler(audit_sink=records.append)]})
    assert records[0].student_id == IDS[0]
    assert records[0].record_id in caplog.text
    assert all(identifier not in caplog.text for identifier in IDS)


def test_sink_mutation_cannot_replace_the_local_operational_correlation(caplog):
    def sink(record):
        record.record_id = IDS[0]

    with caplog.at_level(logging.INFO):
        Retriever().invoke("fixture", config={"callbacks": [handler(audit_sink=sink)]})
    assert all(identifier not in str(vars(record)) for identifier in IDS for record in caplog.records)


@pytest.mark.parametrize("kind", ["lcel", "workflow"])
@pytest.mark.parametrize("violation", [False, True])
def test_sibling_native_filters_keep_identity_in_explicit_sink_only(caplog, kind, violation):
    import asyncio

    from enterprise_rag_patterns.integrations.langchain_lcel import FERPAFilterRunnable
    from enterprise_rag_patterns.integrations.llama_index_workflow import FERPAFilterEvent, FERPAWorkflowStep

    records = []
    scope = StudentIdentityScope(*IDS, authorized_categories={RecordCategory.ACADEMIC_RECORD})
    docs = Retriever().invoke("fixture")
    if kind == "lcel":
        gate = FERPAFilterRunnable(scope, audit_sink=records.append, raise_on_violation=violation).as_runnable()

        def invoke():
            return gate.invoke(docs)
    else:
        from llama_index.core.schema import NodeWithScore, TextNode

        nodes = [NodeWithScore(node=TextNode(text=d.page_content, metadata=d.metadata)) for d in docs]
        step = FERPAWorkflowStep(scope, audit_sink=records.append, raise_on_violation=violation)

        def invoke():
            return asyncio.run(step(FERPAFilterEvent(nodes=nodes)))

    with caplog.at_level(logging.INFO):
        if violation:
            with pytest.raises((ValueError, PermissionError)) as error:
                invoke()
            assert all(identifier not in str(error.value) for identifier in IDS)
        else:
            invoke()
            assert records[0].student_id == IDS[0]
            assert records[0].record_id in caplog.text
    for identifier in (*IDS, "FOREIGN_STUDENT"):
        assert identifier not in caplog.text
        assert all(identifier not in str(vars(record)) for record in caplog.records)
