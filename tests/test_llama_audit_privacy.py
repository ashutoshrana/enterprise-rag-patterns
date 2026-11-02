"""Detailed identities belong only in an explicitly protected audit sink."""

import asyncio
import logging
from types import SimpleNamespace

import pytest

from enterprise_rag_patterns.compliance import RecordCategory, StudentIdentityScope
from enterprise_rag_patterns.integrations.llama_index import FERPANodePostprocessor


def scope():
    return StudentIdentityScope(
        "PRIVATE_STUDENT", "PRIVATE_INSTITUTION", "PRIVATE_REQUESTOR", {RecordCategory.DIRECTORY_INFORMATION}
    )


def nodes():
    return [
        SimpleNamespace(
            metadata={
                "student_id": "PRIVATE_STUDENT",
                "institution_id": "PRIVATE_INSTITUTION",
                "category": "directory_information",
            }
        )
    ]


def test_directory_grant_and_default_log_privacy(caplog):
    granted = scope()
    with caplog.at_level(logging.INFO):
        processor = FERPANodePostprocessor(granted)
        assert len(processor.postprocess_nodes(nodes())) == 1
        granted.authorized_categories.clear()
        assert asyncio.run(processor.apostprocess_nodes(nodes())) == []
    for identifier in ("PRIVATE_STUDENT", "PRIVATE_INSTITUTION", "PRIVATE_REQUESTOR"):
        assert identifier not in caplog.text
        assert all(identifier not in str(vars(record)) for record in caplog.records)
    assert "audit_id=" in caplog.text and "allowed=1" in caplog.text


def test_opt_in_audit_is_correlated(caplog):
    records = []
    with caplog.at_level(logging.INFO):
        FERPANodePostprocessor(scope(), audit_sink=records.append).postprocess_nodes(nodes())
    assert records[0]["student_id"] == "PRIVATE_STUDENT"
    assert records[0]["audit_id"] in caplog.text
    assert "PRIVATE_STUDENT" not in caplog.text


def test_protected_sink_failure_propagates():
    def sink(record):
        raise OSError("unavailable")

    with pytest.raises(OSError):
        FERPANodePostprocessor(scope(), audit_sink=sink).postprocess_nodes(nodes())


def test_async_sink_cannot_silently_drop_audit():
    async def sink(record):
        return None

    with pytest.raises(TypeError, match="synchronously"):
        FERPANodePostprocessor(scope(), audit_sink=sink)
    processor = FERPANodePostprocessor(scope(), audit_sink=lambda record: sink(record))
    with pytest.raises(TypeError, match="synchronously"):
        processor.postprocess_nodes(nodes())
