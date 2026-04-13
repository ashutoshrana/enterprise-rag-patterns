"""Tests for EU AI Act Article 12 tamper-evident audit logger."""

from __future__ import annotations

import hashlib
import json

from enterprise_rag_patterns.regulations.eu_ai_act import (
    SYSTEM_AI_DISCLOSURE,
    AnnexIIICategory,
    EUAIActAuditLogger,
    EUAIActRetrievalRecord,
    EUAIActRiskTier,
    classify_annex_iii_risk,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HMAC_KEY = b"test-hmac-key-32-bytes-exactly!!"
_QUERY = "What courses do I still need for graduation?"
_RESPONSE = "You need CS 401 and MATH 301."
_DOCS_STR = ["doc-001", "doc-002", "doc-003"]
_DOCS_DICT = [
    {"id": "doc-001", "content": "CS 401 requirement"},
    {"doc_id": "doc-002", "content": "MATH requirement"},
    {"metadata": {"doc_id": "doc-003"}, "content": "Electives"},
]


def _make_logger(**kwargs: object) -> EUAIActAuditLogger:
    defaults = dict(system_id="enrollment-advisor", risk_tier=EUAIActRiskTier.HIGH_RISK, hmac_key=_HMAC_KEY)
    defaults.update(kwargs)  # type: ignore[arg-type]
    return EUAIActAuditLogger(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# EUAIActRiskTier
# ===========================================================================


class TestEUAIActRiskTier:
    def test_values(self) -> None:
        assert EUAIActRiskTier.HIGH_RISK.value == "high_risk"
        assert EUAIActRiskTier.PROHIBITED.value == "prohibited"
        assert EUAIActRiskTier.LIMITED_RISK.value == "limited_risk"
        assert EUAIActRiskTier.MINIMAL_RISK.value == "minimal_risk"

    def test_str_enum(self) -> None:
        assert str(EUAIActRiskTier.HIGH_RISK) == "EUAIActRiskTier.HIGH_RISK"


# ===========================================================================
# EUAIActAuditLogger — basic logging
# ===========================================================================


class TestLogRetrievalEvent:
    def test_returns_record(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert isinstance(record, EUAIActRetrievalRecord)

    def test_record_has_system_id(self) -> None:
        logger = _make_logger(system_id="my-system")
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.system_id == "my-system"

    def test_record_risk_tier(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.risk_tier == EUAIActRiskTier.HIGH_RISK

    def test_record_query_hash(self) -> None:
        expected_hash = hashlib.sha256(_QUERY.encode("utf-8")).hexdigest()
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.query_hash == expected_hash

    def test_query_preview_absent_by_default(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.query_preview is None

    def test_query_preview_present_when_enabled(self) -> None:
        logger = _make_logger(include_query_preview=True)
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.query_preview == _QUERY

    def test_query_preview_truncated_to_200(self) -> None:
        long_query = "x" * 300
        logger = _make_logger(include_query_preview=True)
        record = logger.log_retrieval_event(long_query, _DOCS_STR)
        assert len(record.query_preview) == 200  # type: ignore[arg-type]

    def test_doc_ids_from_str_list(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert sorted(_DOCS_STR) == record.retrieved_doc_ids

    def test_doc_ids_from_dict_list(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_DICT)
        assert sorted(["doc-001", "doc-002", "doc-003"]) == record.retrieved_doc_ids

    def test_doc_count_matches(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.retrieved_doc_count == 3

    def test_empty_docs(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, [])
        assert record.retrieved_doc_ids == []
        assert record.retrieved_doc_count == 0

    def test_context_window_hash_when_provided(self) -> None:
        ctx = "context text"
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR, context_window=ctx)
        expected = hashlib.sha256(ctx.encode("utf-8")).hexdigest()
        assert record.context_window_hash == expected

    def test_context_window_hash_none_by_default(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.context_window_hash is None

    def test_response_hash_when_provided(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR, response=_RESPONSE)
        expected = hashlib.sha256(_RESPONSE.encode("utf-8")).hexdigest()
        assert record.response_hash == expected

    def test_actor_id_and_session_id(self) -> None:
        record = _make_logger().log_retrieval_event(
            _QUERY, _DOCS_STR, actor_id="stu-alice", session_id="sess-123"
        )
        assert record.actor_id == "stu-alice"
        assert record.session_id == "sess-123"

    def test_timestamp_is_utc(self) -> None:
        import datetime

        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.timestamp.tzinfo is not None
        assert record.timestamp.tzinfo == datetime.timezone.utc

    def test_record_id_is_uuid(self) -> None:
        import uuid

        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        uuid.UUID(record.record_id)  # raises if not valid UUID

    def test_log_sink_called(self) -> None:
        sink_calls: list[EUAIActRetrievalRecord] = []
        logger = _make_logger(log_sink=sink_calls.append)
        logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert len(sink_calls) == 1
        assert isinstance(sink_calls[0], EUAIActRetrievalRecord)


# ===========================================================================
# HMAC tamper-evidence
# ===========================================================================


class TestHMACSignature:
    def test_hmac_signature_set_when_key_provided(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.hmac_signature is not None
        assert len(record.hmac_signature) == 64  # SHA-256 hex

    def test_hmac_signature_none_when_no_key(self) -> None:
        logger = _make_logger(hmac_key=None)
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.hmac_signature is None

    def test_verify_record_valid_signature(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert logger.verify_record(record) is True

    def test_verify_record_fails_on_tamper(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        # Tamper: change actor_id after signing
        record.actor_id = "attacker"
        assert logger.verify_record(record) is False

    def test_verify_record_true_without_key(self) -> None:
        logger = _make_logger(hmac_key=None)
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert logger.verify_record(record) is True

    def test_verify_record_false_when_signature_missing(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        record.hmac_signature = None
        assert logger.verify_record(record) is False

    def test_different_keys_produce_different_signatures(self) -> None:
        logger_a = _make_logger(hmac_key=b"key-a-32-bytes-exactly----------")
        logger_b = _make_logger(hmac_key=b"key-b-32-bytes-exactly----------")
        record_a = logger_a.log_retrieval_event(_QUERY, _DOCS_STR)
        record_b = logger_b.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record_a.hmac_signature != record_b.hmac_signature


# ===========================================================================
# Hash chain
# ===========================================================================


class TestHashChain:
    def test_first_record_has_no_previous_hash(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.previous_record_hash is None

    def test_second_record_links_to_first(self) -> None:
        logger = _make_logger()
        r1 = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        r2 = logger.log_retrieval_event("second query", _DOCS_STR)
        assert r2.previous_record_hash == r1.record_hash()

    def test_chain_disabled(self) -> None:
        logger = _make_logger(enable_chain=False)
        logger.log_retrieval_event(_QUERY, _DOCS_STR)
        r2 = logger.log_retrieval_event("q2", _DOCS_STR)
        assert r2.previous_record_hash is None

    def test_verify_chain_single_record(self) -> None:
        logger = _make_logger()
        r = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert logger.verify_chain([r]) is True

    def test_verify_chain_multiple_records(self) -> None:
        logger = _make_logger()
        records = [logger.log_retrieval_event(f"query {i}", _DOCS_STR) for i in range(5)]
        assert logger.verify_chain(records) is True

    def test_verify_chain_detects_tamper(self) -> None:
        logger = _make_logger()
        r1 = logger.log_retrieval_event("q1", _DOCS_STR)
        r2 = logger.log_retrieval_event("q2", _DOCS_STR)
        r3 = logger.log_retrieval_event("q3", _DOCS_STR)
        # Break chain: replace r2 with a new record that doesn't link correctly
        r2.previous_record_hash = "0" * 64
        assert logger.verify_chain([r1, r2, r3]) is False

    def test_verify_chain_detects_insertion(self) -> None:
        logger = _make_logger()
        r1 = logger.log_retrieval_event("q1", _DOCS_STR)
        r2 = logger.log_retrieval_event("q2", _DOCS_STR)
        # Insert a record between r1 and r2 — r2's chain pointer won't match r_inserted
        r_inserted = _make_logger().log_retrieval_event("injected", _DOCS_STR)
        assert logger.verify_chain([r1, r_inserted, r2]) is False

    def test_verify_chain_empty_list(self) -> None:
        logger = _make_logger()
        assert logger.verify_chain([]) is True


# ===========================================================================
# seal_response
# ===========================================================================


class TestSealResponse:
    def test_seal_adds_response_hash(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        assert record.response_hash is None
        sealed = logger.seal_response(record, _RESPONSE)
        expected = hashlib.sha256(_RESPONSE.encode("utf-8")).hexdigest()
        assert sealed.response_hash == expected

    def test_seal_preserves_record_id(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        sealed = logger.seal_response(record, _RESPONSE)
        assert sealed.record_id == record.record_id

    def test_seal_preserves_other_fields(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR, actor_id="stu-alice")
        sealed = logger.seal_response(record, _RESPONSE)
        assert sealed.actor_id == "stu-alice"
        assert sealed.query_hash == record.query_hash

    def test_seal_recomputes_hmac(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        sealed = logger.seal_response(record, _RESPONSE)
        # Original and sealed have different HMAC because response_hash differs
        assert sealed.hmac_signature != record.hmac_signature
        assert logger.verify_record(sealed) is True

    def test_seal_calls_log_sink(self) -> None:
        sink_calls: list[EUAIActRetrievalRecord] = []
        logger = _make_logger(log_sink=sink_calls.append)
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        logger.seal_response(record, _RESPONSE)
        assert len(sink_calls) == 2  # initial log + sealed log

    def test_original_record_unmodified(self) -> None:
        logger = _make_logger()
        record = logger.log_retrieval_event(_QUERY, _DOCS_STR)
        original_hmac = record.hmac_signature
        logger.seal_response(record, _RESPONSE)
        assert record.response_hash is None  # original unmodified
        assert record.hmac_signature == original_hmac


# ===========================================================================
# to_log_entry
# ===========================================================================


class TestToLogEntry:
    def test_returns_dict(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        entry = record.to_log_entry()
        assert isinstance(entry, dict)

    def test_all_required_keys_present(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR)
        entry = record.to_log_entry()
        for key in (
            "record_id",
            "timestamp",
            "system_id",
            "risk_tier",
            "actor_id",
            "session_id",
            "query_hash",
            "query_preview",
            "retrieved_doc_ids",
            "retrieved_doc_count",
            "context_window_hash",
            "response_hash",
            "previous_record_hash",
            "hmac_signature",
        ):
            assert key in entry, f"Missing key: {key}"

    def test_json_serialisable(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, _DOCS_STR, actor_id="stu-alice")
        entry = record.to_log_entry()
        json.dumps(entry)  # must not raise


# ===========================================================================
# Annex III classification
# ===========================================================================


class TestAnnexIIIClassification:
    def test_education_is_high_risk(self) -> None:
        tier, rationale = classify_annex_iii_risk(AnnexIIICategory.EDUCATION_TRAINING)
        assert tier == EUAIActRiskTier.HIGH_RISK
        assert "Annex III §3" in rationale

    def test_all_categories_return_high_risk(self) -> None:
        for cat in AnnexIIICategory:
            tier, _ = classify_annex_iii_risk(cat)
            assert tier == EUAIActRiskTier.HIGH_RISK

    def test_rationale_is_string(self) -> None:
        _, rationale = classify_annex_iii_risk(AnnexIIICategory.EMPLOYMENT_WORKERS_MANAGEMENT)
        assert isinstance(rationale, str)
        assert len(rationale) > 20


# ===========================================================================
# Art. 13 transparency disclosure
# ===========================================================================


class TestTransparencyDisclosure:
    def test_disclosure_is_string(self) -> None:
        assert isinstance(SYSTEM_AI_DISCLOSURE, str)

    def test_disclosure_mentions_ai(self) -> None:
        assert "artificial intelligence" in SYSTEM_AI_DISCLOSURE.lower()


# ===========================================================================
# Document ID extraction
# ===========================================================================


class TestDocIdExtraction:
    def test_str_docs_used_directly(self) -> None:
        record = _make_logger().log_retrieval_event(_QUERY, ["id-a", "id-b"])
        assert "id-a" in record.retrieved_doc_ids
        assert "id-b" in record.retrieved_doc_ids

    def test_dict_with_id_key(self) -> None:
        docs = [{"id": "doc-x"}]
        record = _make_logger().log_retrieval_event(_QUERY, docs)
        assert "doc-x" in record.retrieved_doc_ids

    def test_dict_with_doc_id_key(self) -> None:
        docs = [{"doc_id": "doc-y"}]
        record = _make_logger().log_retrieval_event(_QUERY, docs)
        assert "doc-y" in record.retrieved_doc_ids

    def test_dict_with_metadata_doc_id(self) -> None:
        docs = [{"metadata": {"doc_id": "doc-z"}}]
        record = _make_logger().log_retrieval_event(_QUERY, docs)
        assert "doc-z" in record.retrieved_doc_ids

    def test_object_with_id_attr(self) -> None:
        class FakeDoc:
            def __init__(self) -> None:
                self.id = "obj-id-123"

        record = _make_logger().log_retrieval_event(_QUERY, [FakeDoc()])
        assert "obj-id-123" in record.retrieved_doc_ids

    def test_doc_ids_are_sorted(self) -> None:
        docs = ["z", "a", "m"]
        record = _make_logger().log_retrieval_event(_QUERY, docs)
        assert record.retrieved_doc_ids == sorted(docs)
