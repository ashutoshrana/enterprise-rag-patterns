"""
Tests for regulations/soc2.py — SOC 2 Type II CBAC for RAG pipelines.

Coverage:
  SOC2ConfidentialityTier  — ordering, from_label, unknown label
  SOC2AccessContext        — has_role, may_access_tier
  SOC2ContextPolicy        — tenant isolation (CC6.1), confidentiality tier (C1.1),
                             role-based access (CC6.6), audit emission (CC7.2),
                             last_audit_record property, mixed block scenarios
  SOC2AuditRecord          — to_log_entry round-trip, content_hash stability
"""

from __future__ import annotations

import json

import pytest

from enterprise_rag_patterns.regulations.soc2 import (
    SOC2AccessContext,
    SOC2AuditRecord,
    SOC2ConfidentialityTier,
    SOC2ContextPolicy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ctx(
    roles: frozenset[str] | None = None,
    max_tier: SOC2ConfidentialityTier = SOC2ConfidentialityTier.CONFIDENTIAL,
    tenant: str = "org_acme",
    subject: str = "user_001",
    purpose: str = "support_query",
) -> SOC2AccessContext:
    return SOC2AccessContext(
        subject_id=subject,
        tenant_id=tenant,
        roles=roles or frozenset({"analyst"}),
        max_confidentiality_tier=max_tier,
        purpose=purpose,
    )


def _docs(*overrides: dict) -> list[dict]:
    """Build a list of minimal doc dicts."""
    return [dict(d) for d in overrides]


# ---------------------------------------------------------------------------
# SOC2ConfidentialityTier
# ---------------------------------------------------------------------------


class TestSOC2ConfidentialityTier:
    def test_ordering(self) -> None:
        assert SOC2ConfidentialityTier.PUBLIC < SOC2ConfidentialityTier.INTERNAL
        assert SOC2ConfidentialityTier.INTERNAL < SOC2ConfidentialityTier.CONFIDENTIAL
        assert SOC2ConfidentialityTier.CONFIDENTIAL < SOC2ConfidentialityTier.RESTRICTED

    def test_from_label_case_insensitive(self) -> None:
        assert SOC2ConfidentialityTier.from_label("public") == SOC2ConfidentialityTier.PUBLIC
        assert SOC2ConfidentialityTier.from_label("CONFIDENTIAL") == SOC2ConfidentialityTier.CONFIDENTIAL
        assert SOC2ConfidentialityTier.from_label("Restricted") == SOC2ConfidentialityTier.RESTRICTED

    def test_from_label_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown confidentiality tier"):
            SOC2ConfidentialityTier.from_label("top_secret")


# ---------------------------------------------------------------------------
# SOC2AccessContext
# ---------------------------------------------------------------------------


class TestSOC2AccessContext:
    def test_has_role_true(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst", "viewer"}))
        assert ctx.has_role("analyst") is True

    def test_has_role_false(self) -> None:
        ctx = _ctx(roles=frozenset({"viewer"}))
        assert ctx.has_role("admin") is False

    def test_may_access_tier_within_range(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.CONFIDENTIAL)
        assert ctx.may_access_tier(SOC2ConfidentialityTier.PUBLIC) is True
        assert ctx.may_access_tier(SOC2ConfidentialityTier.INTERNAL) is True
        assert ctx.may_access_tier(SOC2ConfidentialityTier.CONFIDENTIAL) is True

    def test_may_access_tier_exceeds_max(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.INTERNAL)
        assert ctx.may_access_tier(SOC2ConfidentialityTier.CONFIDENTIAL) is False
        assert ctx.may_access_tier(SOC2ConfidentialityTier.RESTRICTED) is False


# ---------------------------------------------------------------------------
# SOC2ContextPolicy — CC6.1 tenant isolation
# ---------------------------------------------------------------------------


class TestSOC2TenantIsolation:
    def test_matching_tenant_allowed(self) -> None:
        ctx = _ctx(tenant="org_acme")
        docs = _docs({"tenant_id": "org_acme", "content": "ok"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mismatched_tenant_blocked(self) -> None:
        ctx = _ctx(tenant="org_acme")
        docs = _docs({"tenant_id": "org_other", "content": "secret"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_no_tenant_field_passes(self) -> None:
        """Documents with no tenant_id field should not be blocked by CC6.1."""
        ctx = _ctx(tenant="org_acme")
        docs = _docs({"content": "no tenant tag"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mixed_tenants(self) -> None:
        ctx = _ctx(tenant="org_acme")
        docs = _docs(
            {"tenant_id": "org_acme", "content": "mine"},
            {"tenant_id": "org_other", "content": "theirs"},
        )
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1
        assert result[0]["content"] == "mine"


# ---------------------------------------------------------------------------
# SOC2ContextPolicy — C1.1 confidentiality tier
# ---------------------------------------------------------------------------


class TestSOC2ConfidentialityControl:
    def test_public_doc_always_accessible(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.PUBLIC)
        docs = _docs({"confidentiality_tier": "public", "content": "ok"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_confidential_doc_blocked_for_internal_user(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.INTERNAL)
        docs = _docs({"confidentiality_tier": "confidential", "content": "secret"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_restricted_doc_blocked_even_for_confidential_user(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.CONFIDENTIAL)
        docs = _docs({"confidentiality_tier": "restricted", "content": "top secret"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_unknown_tier_treated_as_restricted(self) -> None:
        """Fail-safe: unknown tier label must not grant access by default."""
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.CONFIDENTIAL)
        docs = _docs({"confidentiality_tier": "ultra_classified", "content": "unknown"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_unknown_tier_accessible_to_restricted_user(self) -> None:
        ctx = _ctx(max_tier=SOC2ConfidentialityTier.RESTRICTED)
        docs = _docs({"confidentiality_tier": "???", "content": "unknown"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []


# ---------------------------------------------------------------------------
# SOC2ContextPolicy — CC6.6 role-based access
# ---------------------------------------------------------------------------


class TestSOC2RoleBasedAccess:
    def test_subject_has_required_role(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst", "editor"}))
        docs = _docs({"required_roles": ["editor"], "content": "ok"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_subject_missing_required_role(self) -> None:
        ctx = _ctx(roles=frozenset({"viewer"}))
        docs = _docs({"required_roles": ["admin"], "content": "blocked"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert result == []

    def test_required_roles_as_comma_string(self) -> None:
        ctx = _ctx(roles=frozenset({"analyst"}))
        docs = _docs({"required_roles": "analyst, viewer", "content": "ok"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_no_required_roles_field_passes(self) -> None:
        ctx = _ctx(roles=frozenset())
        docs = _docs({"content": "no role restriction"})
        result = SOC2ContextPolicy(ctx).filter_retrieved_documents(docs)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# SOC2ContextPolicy — audit emission (CC7.2)
# ---------------------------------------------------------------------------


class TestSOC2AuditEmission:
    def test_audit_sink_called_once_per_filter(self) -> None:
        ctx = _ctx()
        records: list[SOC2AuditRecord] = []
        policy = SOC2ContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"content": "a"}, {"content": "b"}))
        assert len(records) == 1

    def test_audit_counts_correct(self) -> None:
        ctx = _ctx(tenant="org_acme")
        records: list[SOC2AuditRecord] = []
        policy = SOC2ContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"tenant_id": "org_acme"},
            {"tenant_id": "org_other"},
            {"tenant_id": "org_acme"},
        )
        policy.filter_retrieved_documents(docs)
        r = records[0]
        assert r.documents_retrieved == 2
        assert r.documents_blocked == 1
        assert r.block_reasons.get("tenant_mismatch") == 1

    def test_last_audit_record_property(self) -> None:
        ctx = _ctx()
        policy = SOC2ContextPolicy(ctx)
        assert policy.last_audit_record is None
        policy.filter_retrieved_documents(_docs({"content": "x"}))
        assert policy.last_audit_record is not None

    def test_tsc_controls_in_audit(self) -> None:
        ctx = _ctx()
        records: list[SOC2AuditRecord] = []
        policy = SOC2ContextPolicy(ctx, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        assert "CC6.1" in records[0].tsc_controls_applied
        assert "CC6.6" in records[0].tsc_controls_applied
        assert "CC7.2" in records[0].tsc_controls_applied

    def test_block_reasons_aggregated(self) -> None:
        ctx = _ctx(
            tenant="org_acme",
            max_tier=SOC2ConfidentialityTier.INTERNAL,
            roles=frozenset({"viewer"}),
        )
        records: list[SOC2AuditRecord] = []
        policy = SOC2ContextPolicy(ctx, audit_sink=records.append)
        docs = _docs(
            {"tenant_id": "org_other"},  # tenant_mismatch
            {"confidentiality_tier": "restricted"},  # tier_exceeded
            {"required_roles": ["admin"]},  # role_required
            {"tenant_id": "org_acme", "confidentiality_tier": "public"},  # pass
        )
        result = policy.filter_retrieved_documents(docs)
        assert len(result) == 1
        r = records[0]
        assert r.block_reasons["tenant_mismatch"] == 1
        assert r.block_reasons["tier_exceeded"] == 1
        assert r.block_reasons["role_required"] == 1


# ---------------------------------------------------------------------------
# SOC2AuditRecord
# ---------------------------------------------------------------------------


class TestSOC2AuditRecord:
    def _make_record(self) -> SOC2AuditRecord:
        return SOC2AuditRecord(
            subject_id="user_001",
            tenant_id="org_acme",
            roles=["analyst"],
            max_confidentiality_tier="confidential",
            purpose="customer_query",
            documents_retrieved=3,
            documents_blocked=1,
            block_reasons={"tier_exceeded": 1},
            tsc_controls_applied=["CC6.1", "CC6.6", "C1.1", "CC7.2"],
            session_id="sess_abc",
        )

    def test_to_log_entry_is_valid_json(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["framework"] == "SOC2_TypeII"
        assert entry["subject_id"] == "user_001"
        assert entry["tenant_id"] == "org_acme"
        assert entry["documents_retrieved"] == 3
        assert entry["documents_blocked"] == 1
        assert "CC6.1" in entry["tsc_controls"]

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
