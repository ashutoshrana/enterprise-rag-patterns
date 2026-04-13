"""
Tests for regulations/pci_dss.py — PCI DSS v4.0 access control and PAN masking.

Coverage:
  PCIDataCategory     — enum values, str conversion
  PCIAccessScope      — may_access_category (NON_CHD always allowed,
                        restricted categories require explicit authorization)
  PCIContextPolicy    — merchant isolation (Req 7.2),
                        category need-to-know (Req 7.2.1),
                        PAN masking (Req 3.4),
                        audit emission (Req 10.2.1),
                        last_audit_record + last_pan_masked_count properties
  PCIAuditRecord      — to_log_entry round-trip, content_hash stability
"""

from __future__ import annotations

import json

from enterprise_rag_patterns.regulations.pci_dss import (
    PCIAccessScope,
    PCIAuditRecord,
    PCIContextPolicy,
    PCIDataCategory,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _scope(
    merchant_id: str = "merchant_acme",
    user_id: str = "agent_001",
    roles: frozenset[str] | None = None,
    authorized_data_categories: frozenset[PCIDataCategory] | None = None,
    business_justification: str = "fraud_investigation",
) -> PCIAccessScope:
    return PCIAccessScope(
        merchant_id=merchant_id,
        user_id=user_id,
        roles=roles or frozenset({"fraud_analyst"}),
        authorized_data_categories=authorized_data_categories or frozenset(),
        business_justification=business_justification,
    )


def _docs(*overrides: dict) -> list[dict]:
    return [dict(d) for d in overrides]


# ---------------------------------------------------------------------------
# PCIDataCategory
# ---------------------------------------------------------------------------


class TestPCIDataCategory:
    def test_values(self) -> None:
        assert PCIDataCategory.CARDHOLDER_DATA.value == "cardholder_data"
        assert PCIDataCategory.SENSITIVE_AUTH_DATA.value == "sensitive_auth_data"
        assert PCIDataCategory.TRANSACTION_DATA.value == "transaction_data"
        assert PCIDataCategory.NON_CHD.value == "non_chd"

    def test_value_is_string(self) -> None:
        """PCIDataCategory value must be usable as a string identifier."""
        assert PCIDataCategory.CARDHOLDER_DATA.value == "cardholder_data"
        assert isinstance(PCIDataCategory.NON_CHD.value, str)

    def test_from_value(self) -> None:
        assert PCIDataCategory("non_chd") == PCIDataCategory.NON_CHD


# ---------------------------------------------------------------------------
# PCIAccessScope — may_access_category
# ---------------------------------------------------------------------------


class TestPCIAccessScope:
    def test_non_chd_always_permitted(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        assert scope.may_access_category(PCIDataCategory.NON_CHD) is True

    def test_transaction_data_requires_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        assert scope.may_access_category(PCIDataCategory.TRANSACTION_DATA) is False

    def test_cardholder_data_requires_explicit_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        assert scope.may_access_category(PCIDataCategory.CARDHOLDER_DATA) is False

    def test_sensitive_auth_data_requires_explicit_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        assert scope.may_access_category(PCIDataCategory.SENSITIVE_AUTH_DATA) is False

    def test_authorized_category_permitted(self) -> None:
        scope = _scope(
            authorized_data_categories=frozenset(
                {
                    PCIDataCategory.CARDHOLDER_DATA,
                    PCIDataCategory.TRANSACTION_DATA,
                }
            )
        )
        assert scope.may_access_category(PCIDataCategory.CARDHOLDER_DATA) is True
        assert scope.may_access_category(PCIDataCategory.TRANSACTION_DATA) is True

    def test_sad_not_authorized_even_with_chd(self) -> None:
        """SENSITIVE_AUTH_DATA must be separately authorized (Req 7.2.1)."""
        scope = _scope(authorized_data_categories=frozenset({PCIDataCategory.CARDHOLDER_DATA}))
        assert scope.may_access_category(PCIDataCategory.SENSITIVE_AUTH_DATA) is False


# ---------------------------------------------------------------------------
# PCIContextPolicy — Req 7.2 merchant isolation
# ---------------------------------------------------------------------------


class TestPCIMerchantIsolation:
    def test_matching_merchant_allowed(self) -> None:
        scope = _scope(merchant_id="merchant_acme")
        docs = _docs({"merchant_id": "merchant_acme", "content": "ok"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mismatched_merchant_blocked(self) -> None:
        scope = _scope(merchant_id="merchant_acme")
        docs = _docs({"merchant_id": "merchant_other", "content": "secret"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert result == []

    def test_no_merchant_field_passes(self) -> None:
        """Documents without merchant_id are outside PCI merchant scope — permitted."""
        scope = _scope(merchant_id="merchant_acme")
        docs = _docs({"content": "no merchant tag"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_mixed_merchants(self) -> None:
        scope = _scope(merchant_id="merchant_acme")
        docs = _docs(
            {"merchant_id": "merchant_acme", "content": "mine"},
            {"merchant_id": "merchant_other", "content": "theirs"},
        )
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1
        assert result[0]["content"] == "mine"


# ---------------------------------------------------------------------------
# PCIContextPolicy — Req 7.2.1 data category need-to-know
# ---------------------------------------------------------------------------


class TestPCICategoryNeedToKnow:
    def test_non_chd_always_accessible(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        docs = _docs({"data_category": "non_chd", "content": "ok"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_chd_blocked_without_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        docs = _docs({"data_category": "cardholder_data", "content": "blocked"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert result == []

    def test_sad_blocked_without_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        docs = _docs({"data_category": "sensitive_auth_data", "content": "blocked"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert result == []

    def test_chd_accessible_with_authorization(self) -> None:
        scope = _scope(authorized_data_categories=frozenset({PCIDataCategory.CARDHOLDER_DATA}))
        docs = _docs({"data_category": "cardholder_data", "content": "ok"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_unknown_category_treated_as_non_chd(self) -> None:
        """Unknown category → NON_CHD (permissive — outside PCI scope)."""
        scope = _scope(authorized_data_categories=frozenset())
        docs = _docs({"data_category": "unrecognized_category", "content": "ok"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1

    def test_no_category_field_passes(self) -> None:
        scope = _scope(authorized_data_categories=frozenset())
        docs = _docs({"content": "no category"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# PCIContextPolicy — Req 3.4 PAN masking
# ---------------------------------------------------------------------------


class TestPCIPANMasking:
    def test_pan_masked_in_content_field(self) -> None:
        scope = _scope()
        docs = _docs({"content": "Card number is 4111 1111 1111 1111 and more"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert "[PAN-MASKED]" in result[0]["content"]
        assert "4111" not in result[0]["content"]

    def test_pan_masked_with_hyphens(self) -> None:
        scope = _scope()
        docs = _docs({"content": "4111-1111-1111-1111 was charged"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert "[PAN-MASKED]" in result[0]["content"]

    def test_pan_masked_without_separators(self) -> None:
        scope = _scope()
        docs = _docs({"content": "4111111111111111 is the PAN"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert "[PAN-MASKED]" in result[0]["content"]

    def test_multiple_pans_all_masked(self) -> None:
        scope = _scope()
        docs = _docs({"content": "Cards: 4111 1111 1111 1111 and 5500 0000 0000 0004"})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert result[0]["content"].count("[PAN-MASKED]") == 2

    def test_non_string_fields_not_modified(self) -> None:
        scope = _scope()
        docs = _docs({"amount": 42, "masked_pan": None, "tags": ["visa", "credit"]})
        result = PCIContextPolicy(scope).filter_retrieved_documents(docs)
        assert result[0]["amount"] == 42
        assert result[0]["masked_pan"] is None
        assert result[0]["tags"] == ["visa", "credit"]

    def test_pan_not_masked_in_blocked_doc(self) -> None:
        """Blocked docs don't enter masking stage — PAN count should be 0."""
        scope = _scope(
            merchant_id="merchant_acme",
            authorized_data_categories=frozenset(),
        )
        docs = _docs(
            {
                "merchant_id": "merchant_other",
                "content": "4111 1111 1111 1111",
            }
        )
        policy = PCIContextPolicy(scope)
        result = policy.filter_retrieved_documents(docs)
        assert result == []
        assert policy.last_pan_masked_count == 0

    def test_last_pan_masked_count_property(self) -> None:
        scope = _scope()
        policy = PCIContextPolicy(scope)
        assert policy.last_pan_masked_count == 0
        policy.filter_retrieved_documents(_docs({"content": "4111 1111 1111 1111 and 5500 0000 0000 0004"}))
        assert policy.last_pan_masked_count == 2

    def test_last_pan_masked_count_accumulates_across_docs(self) -> None:
        scope = _scope()
        docs = _docs(
            {"content": "Card 1: 4111 1111 1111 1111"},
            {"content": "Card 2: 5500 0000 0000 0004"},
        )
        policy = PCIContextPolicy(scope)
        policy.filter_retrieved_documents(docs)
        assert policy.last_pan_masked_count == 2


# ---------------------------------------------------------------------------
# PCIContextPolicy — Req 10.2.1 audit emission
# ---------------------------------------------------------------------------


class TestPCIAuditEmission:
    def test_audit_sink_called_once_per_filter(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"content": "a"}, {"content": "b"}))
        assert len(records) == 1

    def test_audit_emitted_even_when_all_blocked(self) -> None:
        scope = _scope(merchant_id="merchant_acme")
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"merchant_id": "merchant_other"}))
        assert len(records) == 1
        assert records[0].documents_blocked == 1

    def test_audit_emitted_when_no_documents(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        assert len(records) == 1

    def test_audit_counts_correct(self) -> None:
        scope = _scope(merchant_id="merchant_acme")
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        docs = _docs(
            {"merchant_id": "merchant_acme", "content": "ok"},
            {"merchant_id": "merchant_other", "content": "blocked"},
            {"merchant_id": "merchant_acme", "content": "also ok"},
        )
        policy.filter_retrieved_documents(docs)
        r = records[0]
        assert r.documents_retrieved == 2
        assert r.documents_blocked == 1

    def test_last_audit_record_starts_none(self) -> None:
        scope = _scope()
        policy = PCIContextPolicy(scope)
        assert policy.last_audit_record is None

    def test_last_audit_record_populated_after_filter(self) -> None:
        scope = _scope()
        policy = PCIContextPolicy(scope)
        policy.filter_retrieved_documents(_docs({"content": "x"}))
        assert policy.last_audit_record is not None

    def test_pci_requirements_in_audit(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        policy.filter_retrieved_documents([])
        reqs = records[0].pci_requirements_applied
        assert "Req 3.4" in reqs
        assert "Req 7.2" in reqs
        assert "Req 7.2.1" in reqs
        assert "Req 10.2.1" in reqs

    def test_pan_count_in_audit_record(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append)
        policy.filter_retrieved_documents(_docs({"content": "4111 1111 1111 1111"}))
        assert records[0].pan_masked_count == 1

    def test_session_id_propagated_to_audit(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        policy = PCIContextPolicy(scope, audit_sink=records.append, session_id="sess_pci_001")
        policy.filter_retrieved_documents([])
        assert records[0].session_id == "sess_pci_001"

    def test_custom_pci_requirements_override(self) -> None:
        scope = _scope()
        records: list[PCIAuditRecord] = []
        custom = ["Req 3.4", "Req 7.2"]
        policy = PCIContextPolicy(scope, audit_sink=records.append, pci_requirements=custom)
        policy.filter_retrieved_documents([])
        assert records[0].pci_requirements_applied == custom


# ---------------------------------------------------------------------------
# PCIAuditRecord
# ---------------------------------------------------------------------------


class TestPCIAuditRecord:
    def _make_record(self) -> PCIAuditRecord:
        return PCIAuditRecord(
            merchant_id="merchant_acme",
            user_id="agent_001",
            roles=["fraud_analyst"],
            business_justification="dispute_resolution",
            documents_retrieved=4,
            documents_blocked=2,
            pan_masked_count=3,
            pci_requirements_applied=["Req 3.4", "Req 7.2", "Req 7.2.1", "Req 10.2.1"],
            session_id="sess_pci_abc",
        )

    def test_to_log_entry_is_valid_json(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["framework"] == "PCI_DSS_v4"
        assert entry["merchant_id"] == "merchant_acme"
        assert entry["user_id"] == "agent_001"
        assert entry["documents_retrieved"] == 4
        assert entry["documents_blocked"] == 2
        assert entry["pan_masked_count"] == 3
        assert "Req 3.4" in entry["pci_requirements"]

    def test_to_log_entry_contains_event(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["event"] == "rag_retrieval"

    def test_to_log_entry_contains_business_justification(self) -> None:
        record = self._make_record()
        entry = json.loads(record.to_log_entry())
        assert entry["business_justification"] == "dispute_resolution"

    def test_content_hash_is_stable(self) -> None:
        record = self._make_record()
        h1 = record.content_hash()
        h2 = record.content_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_content_hash_changes_with_content(self) -> None:
        r1 = self._make_record()
        r2 = self._make_record()
        r2.pan_masked_count = 99
        assert r1.content_hash() != r2.content_hash()

    def test_roles_sorted_in_log_entry(self) -> None:
        record = self._make_record()
        record.roles = ["zulu", "alpha", "bravo"]
        entry = json.loads(record.to_log_entry())
        assert entry["roles"] == sorted(["zulu", "alpha", "bravo"])
