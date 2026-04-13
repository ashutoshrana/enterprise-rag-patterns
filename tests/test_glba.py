"""
Tests for regulations/glba.py — GLBA Safeguards Rule (16 CFR § 314) NPI access control.

Coverage:
  GLBADataCategory    — enum values, str conversion
  GLBAAccessContext   — has_authorized_purpose, is_marketing_role
  GLBAAccessScope     — permits (institution isolation, purpose, NPI category)
  GLBAContextPolicy   — institution isolation (§ 314.3),
                        purpose limitation (§ 314.4(e)),
                        marketing role restriction (§ 314.4(i)),
                        audit emission (§ 314.4(h)),
                        last_audit_record property,
                        mixed block scenarios
  GLBAAuditRecord     — to_log_entry round-trip, content_hash stability
"""

from __future__ import annotations

import json

import pytest

from enterprise_rag_patterns.regulations.glba import (
    GLBAAccessContext,
    GLBAAccessScope,
    GLBAAuditRecord,
    GLBAContextPolicy,
    GLBADataCategory,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ctx(
    actor_id: str = "agent_001",
    actor_role: str = "customer_service_rep",
    institution_id: str = "bank_acme",
    purpose: str = "customer_service",
    authorized_purposes: set[str] | None = None,
) -> GLBAAccessContext:
    return GLBAAccessContext(
        actor_id=actor_id,
        actor_role=actor_role,
        institution_id=institution_id,
        purpose=purpose,
        authorized_purposes=authorized_purposes if authorized_purposes is not None else {"customer_service"},
    )


def _marketing_ctx(institution_id: str = "bank_acme") -> GLBAAccessContext:
    return GLBAAccessContext(
        actor_id="mkt_001",
        actor_role="marketing_analyst",
        institution_id=institution_id,
        purpose="marketing",
        authorized_purposes={"marketing"},
    )


def _docs(*overrides: dict) -> list[dict]:
    """Build a list of minimal document dicts."""
    return [dict(d) for d in overrides]


# ---------------------------------------------------------------------------
# GLBADataCategory
# ---------------------------------------------------------------------------


class TestGLBADataCategory:
    def test_nonpublic_personal_value(self) -> None:
        assert GLBADataCategory.NONPUBLIC_PERSONAL.value == "nonpublic_personal"

    def test_account_data_value(self) -> None:
        assert GLBADataCategory.ACCOUNT_DATA.value == "account_data"

    def test_transaction_history_value(self) -> None:
        assert GLBADataCategory.TRANSACTION_HISTORY.value == "transaction_history"

    def test_credit_information_value(self) -> None:
        assert GLBADataCategory.CREDIT_INFORMATION.value == "credit_information"

    def test_public_information_value(self) -> None:
        assert GLBADataCategory.PUBLIC_INFORMATION.value == "public_information"

    def test_value_is_string(self) -> None:
        for member in GLBADataCategory:
            assert isinstance(member.value, str)

    def test_from_value(self) -> None:
        assert GLBADataCategory("nonpublic_personal") == GLBADataCategory.NONPUBLIC_PERSONAL
        assert GLBADataCategory("public_information") == GLBADataCategory.PUBLIC_INFORMATION

    def test_unknown_value_raises(self) -> None:
        with pytest.raises(ValueError):
            GLBADataCategory("unknown_category")


# ---------------------------------------------------------------------------
# GLBAAccessContext
# ---------------------------------------------------------------------------


class TestGLBAAccessContext:
    def test_has_authorized_purpose_true(self) -> None:
        ctx = _ctx(purpose="customer_service", authorized_purposes={"customer_service", "fraud_detection"})
        assert ctx.has_authorized_purpose() is True

    def test_has_authorized_purpose_false(self) -> None:
        ctx = _ctx(purpose="marketing", authorized_purposes={"customer_service"})
        assert ctx.has_authorized_purpose() is False

    def test_is_marketing_role_true(self) -> None:
        ctx = _ctx(actor_role="marketing_analyst")
        assert ctx.is_marketing_role() is True

    def test_is_marketing_role_case_insensitive(self) -> None:
        ctx = _ctx(actor_role="Senior_Marketing_Manager")
        assert ctx.is_marketing_role() is True

    def test_is_marketing_role_false(self) -> None:
        ctx = _ctx(actor_role="fraud_analyst")
        assert ctx.is_marketing_role() is False

    def test_empty_authorized_purposes_denies_npi(self) -> None:
        ctx = _ctx(purpose="customer_service", authorized_purposes=set())
        assert ctx.has_authorized_purpose() is False


# ---------------------------------------------------------------------------
# GLBAAccessScope — permits()
# ---------------------------------------------------------------------------


class TestGLBAAccessScope:
    def _scope(
        self,
        institution_id: str = "bank_acme",
        actor_id: str = "agent_001",
        authorized_purposes: set[str] | None = None,
    ) -> GLBAAccessScope:
        return GLBAAccessScope(
            institution_id=institution_id,
            actor_id=actor_id,
            authorized_purposes=authorized_purposes if authorized_purposes is not None else {"customer_service"},
        )

    def test_permits_matching_institution_and_purpose(self) -> None:
        scope = self._scope()
        doc = {"institution_id": "bank_acme", "data_category": "account_data"}
        assert scope.permits(doc, "customer_service") is True

    def test_blocks_mismatched_institution(self) -> None:
        scope = self._scope(institution_id="bank_acme")
        doc = {"institution_id": "bank_other"}
        assert scope.permits(doc, "customer_service") is False

    def test_blocks_unauthorized_purpose(self) -> None:
        scope = self._scope(authorized_purposes={"customer_service"})
        doc = {"data_category": "nonpublic_personal"}
        assert scope.permits(doc, "marketing") is False

    def test_permits_no_institution_field(self) -> None:
        """Documents without institution_id are not blocked by isolation rule."""
        scope = self._scope()
        doc = {"content": "general info"}
        assert scope.permits(doc, "customer_service") is True

    def test_permits_public_information_any_purpose(self) -> None:
        scope = self._scope(authorized_purposes={"customer_service"})
        doc = {"data_category": "public_information"}
        assert scope.permits(doc, "customer_service") is True

    def test_blocks_npi_with_unauthorized_purpose(self) -> None:
        scope = self._scope(authorized_purposes={"customer_service"})
        doc = {"data_category": "nonpublic_personal"}
        assert scope.permits(doc, "bulk_export") is False


# ---------------------------------------------------------------------------
# GLBAContextPolicy — § 314.3 institution isolation
# ---------------------------------------------------------------------------


class TestGLBAInstitutionIsolation:
    def test_matching_institution_allowed(self) -> None:
        ctx = _ctx(institution_id="bank_acme")
        docs = _docs({"institution_id": "bank_acme", "content": "ok"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mismatched_institution_blocked(self) -> None:
        ctx = _ctx(institution_id="bank_acme")
        docs = _docs({"institution_id": "bank_other", "content": "secret"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_no_institution_field_passes(self) -> None:
        """Documents without institution_id are outside isolation scope — permitted."""
        ctx = _ctx(institution_id="bank_acme")
        docs = _docs({"content": "no institution tag"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mixed_institutions(self) -> None:
        ctx = _ctx(institution_id="bank_acme")
        docs = _docs(
            {"institution_id": "bank_acme", "content": "mine"},
            {"institution_id": "bank_other", "content": "theirs"},
        )
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1
        assert result[0]["content"] == "mine"


# ---------------------------------------------------------------------------
# GLBAContextPolicy — § 314.4(e) purpose limitation
# ---------------------------------------------------------------------------


class TestGLBAPurposeLimitation:
    def test_authorized_purpose_allows_npi(self) -> None:
        ctx = _ctx(purpose="customer_service", authorized_purposes={"customer_service"})
        docs = _docs({"data_category": "nonpublic_personal", "content": "npi"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_unauthorized_purpose_blocks_npi(self) -> None:
        ctx = _ctx(purpose="marketing", authorized_purposes={"customer_service"})
        docs = _docs({"data_category": "nonpublic_personal", "content": "blocked"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_unauthorized_purpose_blocks_account_data(self) -> None:
        ctx = _ctx(purpose="bulk_export", authorized_purposes={"customer_service"})
        docs = _docs({"data_category": "account_data", "content": "blocked"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_public_information_always_permitted(self) -> None:
        """PUBLIC_INFORMATION bypasses purpose and role checks entirely."""
        ctx = _ctx(purpose="marketing", authorized_purposes=set())
        docs = _docs({"data_category": "public_information", "content": "ok"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_no_category_field_passes(self) -> None:
        """Documents without data_category are outside GLBA NPI scope — permitted."""
        ctx = _ctx(purpose="any", authorized_purposes=set())
        docs = _docs({"content": "no category"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_unknown_category_treated_as_public(self) -> None:
        """Unknown category → PUBLIC_INFORMATION (permissive — outside GLBA scope)."""
        ctx = _ctx(purpose="any", authorized_purposes=set())
        docs = _docs({"data_category": "unrecognized_category", "content": "ok"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_fraud_detection_purpose_allows_transaction_history(self) -> None:
        ctx = _ctx(
            actor_role="fraud_analyst",
            purpose="fraud_detection",
            authorized_purposes={"fraud_detection"},
        )
        docs = _docs({"data_category": "transaction_history", "content": "transactions"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# GLBAContextPolicy — § 314.4(i) marketing role restriction
# ---------------------------------------------------------------------------


class TestGLBAMarketingRoleRestriction:
    def test_marketing_role_blocked_from_credit_information(self) -> None:
        ctx = _marketing_ctx()
        docs = _docs({"data_category": "credit_information", "content": "credit report"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_marketing_role_blocked_from_transaction_history(self) -> None:
        ctx = _marketing_ctx()
        docs = _docs({"data_category": "transaction_history", "content": "txn history"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_marketing_role_can_access_public_information(self) -> None:
        ctx = _marketing_ctx()
        docs = _docs({"data_category": "public_information", "content": "public rates"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_non_marketing_role_can_access_credit_information(self) -> None:
        ctx = _ctx(actor_role="underwriter", purpose="loan_review", authorized_purposes={"loan_review"})
        docs = _docs({"data_category": "credit_information", "content": "credit score"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_non_marketing_role_can_access_transaction_history(self) -> None:
        ctx = _ctx(
            actor_role="fraud_analyst",
            purpose="fraud_detection",
            authorized_purposes={"fraud_detection"},
        )
        docs = _docs({"data_category": "transaction_history", "content": "txn log"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_marketing_block_takes_precedence_over_purpose(self) -> None:
        """Marketing role is blocked from credit_information even if purpose is authorized."""
        ctx = GLBAAccessContext(
            actor_id="mkt_001",
            actor_role="marketing_analyst",
            institution_id="bank_acme",
            purpose="marketing",
            authorized_purposes={"marketing", "customer_service", "fraud_detection"},
        )
        docs = _docs({"data_category": "credit_information", "content": "score"})
        result = GLBAContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []


# ---------------------------------------------------------------------------
# GLBAContextPolicy — audit emission (§ 314.4(h))
# ---------------------------------------------------------------------------


class TestGLBAauditEmission:
    def test_audit_sink_called_once_per_filter(self) -> None:
        ctx = _ctx()
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"content": "a"}, {"content": "b"}))
        assert len(records) == 1

    def test_audit_emitted_when_all_blocked(self) -> None:
        ctx = _ctx(institution_id="bank_acme")
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"institution_id": "bank_other"}))
        assert len(records) == 1
        assert records[0].documents_blocked == 1

    def test_audit_emitted_when_no_documents(self) -> None:
        ctx = _ctx()
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        assert len(records) == 1

    def test_audit_counts_correct(self) -> None:
        ctx = _ctx(institution_id="bank_acme")
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"institution_id": "bank_acme"},
            {"institution_id": "bank_other"},
            {"institution_id": "bank_acme"},
        )
        policy.filter_retrieved_documents(docs)
        r = records[0]
        assert r.documents_retrieved == 2
        assert r.documents_blocked == 1
        assert r.block_reasons.get("institution_mismatch") == 1

    def test_last_audit_record_starts_none(self) -> None:
        ctx = _ctx()
        policy = GLBAContextPolicy(ctx)
        assert policy.last_audit_record is None

    def test_last_audit_record_populated_after_filter(self) -> None:
        ctx = _ctx()
        policy = GLBAContextPolicy(ctx)
        policy.filter_retrieved_documents(_docs({"content": "x"}))
        assert policy.last_audit_record is not None

    def test_safeguards_controls_in_audit(self) -> None:
        ctx = _ctx()
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        controls = records[0].safeguards_controls
        assert "§314.3" in controls
        assert "§314.4(e)" in controls
        assert "§314.4(h)" in controls
        assert "§314.4(i)" in controls

    def test_block_reasons_aggregated(self) -> None:
        ctx = _ctx(
            institution_id="bank_acme",
            purpose="marketing",
            authorized_purposes={"customer_service"},
            actor_role="marketing_analyst",
        )
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"institution_id": "bank_other"},  # institution_mismatch
            {"institution_id": "bank_acme", "data_category": "nonpublic_personal"},  # purpose_not_authorized
            {"institution_id": "bank_acme", "data_category": "credit_information"},  # purpose_not_authorized
            {"institution_id": "bank_acme", "data_category": "public_information"},  # pass
        )
        result = policy.filter_retrieved_documents(docs)
        assert len(result) == 1
        r = records[0]
        assert r.block_reasons["institution_mismatch"] == 1
        assert r.block_reasons["purpose_not_authorized"] == 2

    def test_session_id_propagated_to_audit(self) -> None:
        ctx = _ctx()
        records: list[GLBAAuditRecord] = []
        policy = GLBAContextPolicy(ctx, audit_sink=records.append, session_id="sess_glba_001")
        policy.filter_retrieved_documents([])
        assert records[0].session_id == "sess_glba_001"

    def test_custom_safeguards_controls_override(self) -> None:
        ctx = _ctx()
        records: list[GLBAAuditRecord] = []
        custom = ["§314.3", "§314.4(e)"]
        policy = GLBAContextPolicy(ctx, audit_sink=records.append, safeguards_controls=custom)
        policy.filter_retrieved_documents([])
        assert records[0].safeguards_controls == custom


# ---------------------------------------------------------------------------
# GLBAAuditRecord
# ---------------------------------------------------------------------------


class TestGLBAAuditRecord:
    def _make_record(self) -> GLBAAuditRecord:
        return GLBAAuditRecord(
            actor_id="agent_001",
            actor_role="customer_service_rep",
            institution_id="bank_acme",
            purpose="customer_service",
            authorized_purposes=["customer_service", "account_management"],
            documents_retrieved=5,
            documents_blocked=2,
            block_reasons={"institution_mismatch": 1, "purpose_not_authorized": 1},
            safeguards_controls=["§314.3", "§314.4(e)", "§314.4(h)", "§314.4(i)"],
            session_id="sess_glba_abc",
        )

    def test_to_log_entry_is_valid_json(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["framework"] == "GLBA_16CFR314"
        assert entry["actor_id"] == "agent_001"
        assert entry["institution_id"] == "bank_acme"
        assert entry["purpose"] == "customer_service"
        assert entry["documents_retrieved"] == 5
        assert entry["documents_blocked"] == 2

    def test_to_log_entry_contains_event(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["event"] == "rag_retrieval"

    def test_to_log_entry_contains_safeguards_controls(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert "§314.3" in entry["safeguards_controls"]
        assert "§314.4(e)" in entry["safeguards_controls"]

    def test_to_log_entry_contains_block_reasons(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["block_reasons"]["institution_mismatch"] == 1
        assert entry["block_reasons"]["purpose_not_authorized"] == 1

    def test_to_log_entry_authorized_purposes_sorted(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["authorized_purposes"] == sorted(["customer_service", "account_management"])

    def test_content_hash_is_stable(self) -> None:
        record = self._make_record()
        h1 = record.content_hash()
        h2 = record.content_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_content_hash_changes_with_content(self) -> None:
        r1 = self._make_record()
        r2 = self._make_record()
        r2.documents_retrieved = 99
        assert r1.content_hash() != r2.content_hash()

    def test_content_hash_changes_with_block_reasons(self) -> None:
        r1 = self._make_record()
        r2 = self._make_record()
        r2.block_reasons["institution_mismatch"] = 5
        assert r1.content_hash() != r2.content_hash()

    def test_framework_field_in_log_entry(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["framework"] == "GLBA_16CFR314"
