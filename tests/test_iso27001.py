"""
Tests for regulations/iso27001.py — ISO/IEC 27001:2022 ISMS CBAC for RAG pipelines.

Coverage:
  ISMSClassification  — ordering, from_label, unknown label
  ISMSAccessContext   — has_role, may_access_classification
  ISMSContextPolicy   — organization isolation (A.5.15), classification enforcement
                        (A.5.12 / A.8.12), role-based access (A.8.2),
                        audit emission (A.8.15), last_audit_record property,
                        mixed block scenarios
  ISMSAuditRecord     — to_log_entry round-trip, content_hash stability
"""

from __future__ import annotations

import json

import pytest

from enterprise_rag_patterns.regulations.iso27001 import (
    ISMSAccessContext,
    ISMSAuditRecord,
    ISMSClassification,
    ISMSContextPolicy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ctx(
    roles: frozenset[str] | None = None,
    max_classification: ISMSClassification = ISMSClassification.CONFIDENTIAL,
    organization_id: str = "org_acme",
    subject_id: str = "user_001",
    purpose: str = "support_query",
) -> ISMSAccessContext:
    return ISMSAccessContext(
        subject_id=subject_id,
        organization_id=organization_id,
        roles=roles or frozenset({"analyst"}),
        max_classification=max_classification,
        purpose=purpose,
    )


def _docs(*overrides: dict) -> list[dict]:
    """Build a list of minimal doc dicts."""
    return [dict(d) for d in overrides]


# ---------------------------------------------------------------------------
# ISMSClassification
# ---------------------------------------------------------------------------


class TestISMSClassification:
    def test_ordering(self) -> None:
        assert ISMSClassification.PUBLIC < ISMSClassification.INTERNAL
        assert ISMSClassification.INTERNAL < ISMSClassification.CONFIDENTIAL
        assert ISMSClassification.CONFIDENTIAL < ISMSClassification.SECRET

    def test_from_label_case_insensitive(self) -> None:
        assert ISMSClassification.from_label("public") == ISMSClassification.PUBLIC
        assert ISMSClassification.from_label("INTERNAL") == ISMSClassification.INTERNAL
        assert ISMSClassification.from_label("Confidential") == ISMSClassification.CONFIDENTIAL
        assert ISMSClassification.from_label("SECRET") == ISMSClassification.SECRET

    def test_from_label_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown ISMS classification"):
            ISMSClassification.from_label("top_secret")

    def test_int_values_are_ordered(self) -> None:
        assert int(ISMSClassification.PUBLIC) == 0
        assert int(ISMSClassification.INTERNAL) == 1
        assert int(ISMSClassification.CONFIDENTIAL) == 2
        assert int(ISMSClassification.SECRET) == 3


# ---------------------------------------------------------------------------
# ISMSAccessContext
# ---------------------------------------------------------------------------


class TestISMSAccessContext:
    def test_has_role_true(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst", "viewer"}))
        assert ctx.has_role("analyst") is True

    def test_has_role_false(self) -> None:
        ctx = _ctx(roles=frozenset({"viewer"}))
        assert ctx.has_role("admin") is False

    def test_may_access_classification_within_range(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.CONFIDENTIAL)
        assert ctx.may_access_classification(ISMSClassification.PUBLIC) is True
        assert ctx.may_access_classification(ISMSClassification.INTERNAL) is True
        assert ctx.may_access_classification(ISMSClassification.CONFIDENTIAL) is True

    def test_may_access_classification_exceeds_max(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.INTERNAL)
        assert ctx.may_access_classification(ISMSClassification.CONFIDENTIAL) is False
        assert ctx.may_access_classification(ISMSClassification.SECRET) is False

    def test_default_max_classification_is_internal(self) -> None:
        ctx = ISMSAccessContext(
            subject_id="u1",
            organization_id="org",
            roles=frozenset({"analyst"}),
        )
        assert ctx.max_classification == ISMSClassification.INTERNAL


# ---------------------------------------------------------------------------
# ISMSContextPolicy — A.5.15 organization isolation
# ---------------------------------------------------------------------------


class TestISMSOrganizationIsolation:
    def test_matching_organization_allowed(self) -> None:
        ctx = _ctx(organization_id="org_acme")
        docs = _docs({"organization_id": "org_acme", "content": "ok"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mismatched_organization_blocked(self) -> None:
        ctx = _ctx(organization_id="org_acme")
        docs = _docs({"organization_id": "org_other", "content": "secret"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_no_organization_field_passes(self) -> None:
        """Documents without organization_id should not be blocked by A.5.15."""
        ctx = _ctx(organization_id="org_acme")
        docs = _docs({"content": "no org tag"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mixed_organizations(self) -> None:
        ctx = _ctx(organization_id="org_acme")
        docs = _docs(
            {"organization_id": "org_acme", "content": "mine"},
            {"organization_id": "org_other", "content": "theirs"},
        )
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1
        assert result[0]["content"] == "mine"


# ---------------------------------------------------------------------------
# ISMSContextPolicy — A.5.12 / A.8.12 classification enforcement
# ---------------------------------------------------------------------------


class TestISMSClassificationEnforcement:
    def test_public_doc_always_accessible(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.PUBLIC)
        docs = _docs({"classification": "public", "content": "ok"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_confidential_doc_blocked_for_internal_user(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.INTERNAL)
        docs = _docs({"classification": "confidential", "content": "restricted"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_secret_doc_blocked_even_for_confidential_user(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.CONFIDENTIAL)
        docs = _docs({"classification": "secret", "content": "top secret"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_unknown_classification_blocked_fail_safe(self) -> None:
        """Fail-safe: unknown classification must always block (A.8.12 DLP)."""
        ctx = _ctx(max_classification=ISMSClassification.SECRET)
        docs = _docs({"classification": "cosmic_top_secret", "content": "unknown"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_no_classification_field_passes(self) -> None:
        """Documents without a classification label are outside ISMS scope — permitted."""
        ctx = _ctx(max_classification=ISMSClassification.PUBLIC)
        docs = _docs({"content": "unclassified"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_secret_user_may_see_secret_doc(self) -> None:
        ctx = _ctx(max_classification=ISMSClassification.SECRET)
        docs = _docs({"classification": "secret", "content": "allowed"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# ISMSContextPolicy — A.8.2 role-based access
# ---------------------------------------------------------------------------


class TestISMSRoleBasedAccess:
    def test_subject_has_required_role(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst", "editor"}))
        docs = _docs({"required_roles": ["editor"], "content": "ok"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_subject_missing_required_role(self) -> None:
        ctx = _ctx(roles=frozenset({"viewer"}))
        docs = _docs({"required_roles": ["admin"], "content": "blocked"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_required_roles_as_comma_string(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst"}))
        docs = _docs({"required_roles": "analyst, viewer", "content": "ok"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_required_roles_as_tuple(self) -> None:
        ctx = _ctx(roles=frozenset({"supervisor"}))
        docs = _docs({"required_roles": ("supervisor", "manager"), "content": "ok"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_empty_required_roles_list_passes(self) -> None:
        """Empty required_roles → no restriction; doc passes A.8.2."""
        ctx = _ctx(roles=frozenset())
        docs = _docs({"required_roles": [], "content": "no restriction"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_no_required_roles_field_passes(self) -> None:
        ctx = _ctx(roles=frozenset())
        docs = _docs({"content": "no role restriction"})
        result = ISMSContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# ISMSContextPolicy — audit emission (A.8.15)
# ---------------------------------------------------------------------------


class TestISMSAuditEmission:
    def test_audit_sink_called_once_per_filter(self) -> None:
        ctx = _ctx()
        records: list[ISMSAuditRecord] = []
        policy = ISMSContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"content": "a"}, {"content": "b"}))
        assert len(records) == 1

    def test_audit_counts_correct(self) -> None:
        ctx = _ctx(organization_id="org_acme")
        records: list[ISMSAuditRecord] = []
        policy = ISMSContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"organization_id": "org_acme"},
            {"organization_id": "org_other"},
            {"organization_id": "org_acme"},
        )
        policy.filter_retrieved_documents(docs)
        r = records[0]
        assert r.documents_retrieved == 2
        assert r.documents_blocked == 1
        assert r.block_reasons.get("organization_mismatch") == 1

    def test_last_audit_record_starts_none(self) -> None:
        ctx = _ctx()
        policy = ISMSContextPolicy(ctx)
        assert policy.last_audit_record is None

    def test_last_audit_record_populated_after_filter(self) -> None:
        ctx = _ctx()
        policy = ISMSContextPolicy(ctx)
        policy.filter_retrieved_documents(_docs({"content": "x"}))
        assert policy.last_audit_record is not None

    def test_annex_a_controls_in_audit(self) -> None:
        ctx = _ctx()
        records: list[ISMSAuditRecord] = []
        policy = ISMSContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        controls = records[0].annex_a_controls
        assert "A.5.15" in controls
        assert "A.5.12" in controls
        assert "A.8.2" in controls
        assert "A.8.15" in controls

    def test_block_reasons_aggregated(self) -> None:
        ctx = _ctx(
            organization_id="org_acme",
            max_classification=ISMSClassification.INTERNAL,
            roles=frozenset({"viewer"}),
        )
        records: list[ISMSAuditRecord] = []
        policy = ISMSContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"organization_id": "org_other"},  # organization_mismatch
            {"classification": "secret"},  # classification_exceeded
            {"required_roles": ["admin"]},  # role_required
            {"organization_id": "org_acme", "classification": "public"},  # pass
        )
        result = policy.filter_retrieved_documents(docs)
        assert len(result) == 1
        r = records[0]
        assert r.block_reasons["organization_mismatch"] == 1
        assert r.block_reasons["classification_exceeded"] == 1
        assert r.block_reasons["role_required"] == 1

    def test_session_id_propagated_to_audit(self) -> None:
        ctx = _ctx()
        records: list[ISMSAuditRecord] = []
        policy = ISMSContextPolicy(ctx, audit_sink=records.append, session_id="sess_xyz")
        policy.filter_retrieved_documents([])
        assert records[0].session_id == "sess_xyz"

    def test_custom_annex_a_controls_override(self) -> None:
        ctx = _ctx()
        records: list[ISMSAuditRecord] = []
        custom = ["A.5.12", "A.8.15"]
        policy = ISMSContextPolicy(ctx, audit_sink=records.append, annex_a_controls=custom)
        policy.filter_retrieved_documents([])
        assert records[0].annex_a_controls == custom


# ---------------------------------------------------------------------------
# ISMSAuditRecord
# ---------------------------------------------------------------------------


class TestISMSAuditRecord:
    def _make_record(self) -> ISMSAuditRecord:
        return ISMSAuditRecord(
            subject_id="user_001",
            organization_id="org_acme",
            roles=["analyst"],
            max_classification="confidential",
            purpose="customer_query",
            documents_retrieved=3,
            documents_blocked=2,
            block_reasons={"classification_exceeded": 1, "organization_mismatch": 1},
            annex_a_controls=["A.5.12", "A.5.15", "A.8.2", "A.8.15", "A.8.16"],
            session_id="sess_abc",
        )

    def test_to_log_entry_is_valid_json(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["framework"] == "ISO_IEC_27001_2022"
        assert entry["subject_id"] == "user_001"
        assert entry["organization_id"] == "org_acme"
        assert entry["documents_retrieved"] == 3
        assert entry["documents_blocked"] == 2
        assert "A.5.15" in entry["annex_a_controls"]

    def test_to_log_entry_contains_block_reasons(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["block_reasons"]["classification_exceeded"] == 1
        assert entry["block_reasons"]["organization_mismatch"] == 1

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

    def test_event_field_in_log_entry(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["event"] == "rag_retrieval"
