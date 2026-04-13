"""
Tests for Financial Services RAG Pipeline (27_financial_services_rag.py).

Covers all four filter layers:
  Layer 1 — GLBAPrivacyFilter     (GLBA Title V, 15 USC §§ 6801-6809)
  Layer 2 — SECRegSPFilter        (SEC Regulation S-P, 17 CFR Part 248)
  Layer 3 — FINRASupervisionFilter(FINRA Rule 3110)
  Layer 4 — BSAAMLFilter          (BSA/AML, 31 USC § 5318(g)(2))

Plus end-to-end pipeline tests for FinancialServicesRAGPipeline.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).parent.parent / "examples" / "27_financial_services_rag.py"


def _load_module():
    module_name = "financial_services_rag"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, _MOD_PATH)
    mod = types.ModuleType(module_name)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def m():
    return _load_module()


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _ctx(m, **kwargs):
    """Fully compliant compliance officer context."""
    defaults = dict(
        user_id="COMP-001",
        user_role=m.FinancialRole.COMPLIANCE_OFFICER,
        customer_id="CUST-001",
        account_id="ACCT-001",
        is_same_customer=False,
        glba_opt_out_honored=True,
        affiliate_sharing_authorized=False,
        is_affiliated_institution=False,
        has_safeguard_controls=True,
        finra_wsp_current=True,
        is_licensed_principal=True,
        sar_access_authorized=True,
        ctr_review_authorized=True,
        is_law_enforcement=False,
        is_audit_access=False,
    )
    defaults.update(kwargs)
    return m.FinancialServicesContext(**defaults)


def _doc(m, **kwargs):
    """Default NPI account document, non-SAR, non-CTR."""
    defaults = dict(
        document_id="DOC-001",
        npi_category=m.NPICategory.ACCOUNT_INFORMATION,
        customer_id="CUST-001",
        is_sar=False,
        is_ctr=False,
        contains_aml_investigation=False,
        is_public=False,
    )
    defaults.update(kwargs)
    return m.FinancialDocument(**defaults)


# ---------------------------------------------------------------------------
# TestGLBAPrivacyFilter — 7 tests
# ---------------------------------------------------------------------------


class TestGLBAPrivacyFilter:
    @pytest.fixture
    def glba(self, m):
        return m.GLBAPrivacyFilter()

    def test_public_document_permitted(self, m, glba):
        """Public documents carry no GLBA restriction."""
        ctx = _ctx(m)
        doc = _doc(m, is_public=True)
        result = glba.evaluate(ctx, doc)
        assert not result.is_denied

    def test_non_npi_permitted(self, m, glba):
        """Documents with NPICategory.NOT_NPI are not subject to GLBA."""
        ctx = _ctx(m)
        doc = _doc(m, npi_category=m.NPICategory.NOT_NPI)
        result = glba.evaluate(ctx, doc)
        assert not result.is_denied

    def test_customer_self_access_permitted(self, m, glba):
        """Customer accessing their own NPI is always permitted under GLBA."""
        ctx = _ctx(m, user_role=m.FinancialRole.CUSTOMER, is_same_customer=True)
        doc = _doc(m)
        result = glba.evaluate(ctx, doc)
        assert not result.is_denied

    def test_compliance_officer_with_safeguards_permitted(self, m, glba):
        """Compliance officer with Safeguard Rule controls in place is permitted."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            has_safeguard_controls=True,
        )
        doc = _doc(m)
        result = glba.evaluate(ctx, doc)
        assert not result.is_denied

    def test_affiliate_without_authorization_denied(self, m, glba):
        """Affiliated institution without customer authorization is denied under §6802(b)(2).

        Uses REGISTERED_REPRESENTATIVE role so the compliance-officer safeguard
        branch does not fire before the affiliate check in the GLBA filter logic.
        """
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE,
            is_affiliated_institution=True,
            affiliate_sharing_authorized=False,
        )
        doc = _doc(m)
        result = glba.evaluate(ctx, doc)
        assert result.is_denied
        reason_lower = result.reason.lower()
        assert "6802" in result.reason or "opt-out" in reason_lower or "affiliate" in reason_lower

    def test_opt_out_not_honored_denied(self, m, glba):
        """Registered representative accessing NPI when opt-out is not honored is denied."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE,
            glba_opt_out_honored=False,
        )
        doc = _doc(m)
        result = glba.evaluate(ctx, doc)
        assert result.is_denied

    def test_regulator_access_permitted(self, m, glba):
        """Regulators are exempt from standard GLBA privacy rules."""
        ctx = _ctx(m, user_role=m.FinancialRole.REGULATOR)
        doc = _doc(m)
        result = glba.evaluate(ctx, doc)
        assert not result.is_denied


# ---------------------------------------------------------------------------
# TestSECRegSPFilter — 6 tests
# ---------------------------------------------------------------------------


class TestSECRegSPFilter:
    @pytest.fixture
    def reg_sp(self, m):
        return m.SECRegSPFilter()

    def test_public_document_permitted(self, m, reg_sp):
        """Public documents are not NPI; Reg S-P does not restrict access."""
        ctx = _ctx(m)
        doc = _doc(m, is_public=True)
        result = reg_sp.evaluate(ctx, doc)
        assert not result.is_denied

    def test_no_safeguard_controls_denied(self, m, reg_sp):
        """Absence of safeguard controls blocks all NPI access under §248.30."""
        ctx = _ctx(m, has_safeguard_controls=False)
        doc = _doc(m)
        result = reg_sp.evaluate(ctx, doc)
        assert result.is_denied
        assert "248.30" in result.reason or "Safeguard" in result.reason or "safeguard" in result.reason.lower()

    def test_registered_rep_with_safeguards_permitted(self, m, reg_sp):
        """Registered representative with safeguard program in place is permitted."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE,
            has_safeguard_controls=True,
        )
        doc = _doc(m)
        result = reg_sp.evaluate(ctx, doc)
        assert not result.is_denied

    def test_compliance_officer_permitted(self, m, reg_sp):
        """Compliance officer with safeguards is permitted for oversight access."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            has_safeguard_controls=True,
        )
        doc = _doc(m)
        result = reg_sp.evaluate(ctx, doc)
        assert not result.is_denied

    def test_regulator_permitted(self, m, reg_sp):
        """Regulators are exempt under §248.15 for examination purposes."""
        ctx = _ctx(m, user_role=m.FinancialRole.REGULATOR)
        doc = _doc(m)
        result = reg_sp.evaluate(ctx, doc)
        assert not result.is_denied

    def test_conditions_reference_reg_sp(self, m, reg_sp):
        """Compliant access produces conditions that reference Reg S-P or §248."""
        ctx = _ctx(m)
        doc = _doc(m)
        result = reg_sp.evaluate(ctx, doc)
        assert not result.is_denied
        combined = " ".join(result.conditions) + " " + result.reason
        assert "Reg S-P" in combined or "248" in combined or "safeguard" in combined.lower()


# ---------------------------------------------------------------------------
# TestFINRASupervisionFilter — 7 tests
# ---------------------------------------------------------------------------


class TestFINRASupervisionFilter:
    @pytest.fixture
    def finra(self, m):
        return m.FINRASupervisionFilter()

    def test_public_document_permitted(self, m, finra):
        """Public documents are not supervisory records; Rule 3110 does not restrict."""
        ctx = _ctx(m)
        doc = _doc(m, is_public=True)
        result = finra.evaluate(ctx, doc)
        assert not result.is_denied

    def test_compliance_officer_wsp_current_permitted(self, m, finra):
        """Compliance officer with current WSPs has Rule 3110(b) oversight access."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            finra_wsp_current=True,
        )
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert not result.is_denied

    def test_wsp_not_current_denied(self, m, finra):
        """Compliance officer with stale WSPs is denied under Rule 3110(b)."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            finra_wsp_current=False,
        )
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert result.is_denied
        assert "3110" in result.reason or "WSP" in result.reason or "wsp" in result.reason.lower()

    def test_branch_manager_licensed_permitted(self, m, finra):
        """Licensed branch manager (registered principal) is permitted under Rule 3110(a)."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.BRANCH_MANAGER,
            is_licensed_principal=True,
            finra_wsp_current=True,
        )
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert not result.is_denied

    def test_branch_manager_unlicensed_denied(self, m, finra):
        """Branch manager without principal designation is denied under Rule 3110(a)."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.BRANCH_MANAGER,
            is_licensed_principal=False,
            finra_wsp_current=True,
        )
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert result.is_denied
        reason_lower = result.reason.lower()
        assert "principal" in reason_lower or "licensed" in reason_lower

    def test_regulator_permitted(self, m, finra):
        """Regulators have full supervisory records access during examination."""
        ctx = _ctx(m, user_role=m.FinancialRole.REGULATOR)
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert not result.is_denied

    def test_conditions_reference_finra(self, m, finra):
        """Compliant access produces conditions that reference FINRA or Rule 3110 or WSP."""
        ctx = _ctx(m)
        doc = _doc(m)
        result = finra.evaluate(ctx, doc)
        assert not result.is_denied
        combined = " ".join(result.conditions) + " " + result.reason
        assert "3110" in combined or "FINRA" in combined or "WSP" in combined


# ---------------------------------------------------------------------------
# TestBSAAMLFilter — 8 tests
# ---------------------------------------------------------------------------


class TestBSAAMLFilter:
    @pytest.fixture
    def bsa(self, m):
        return m.BSAAMLFilter()

    def test_non_sar_non_ctr_non_aml_permitted(self, m, bsa):
        """Documents that are not SAR, CTR, or AML materials pass through without restriction."""
        ctx = _ctx(m)
        doc = _doc(m, is_sar=False, is_ctr=False, contains_aml_investigation=False)
        result = bsa.evaluate(ctx, doc)
        assert not result.is_denied

    def test_public_document_permitted(self, m, bsa):
        """Public documents bypass BSA/AML confidentiality rules even when is_sar=True."""
        ctx = _ctx(m)
        doc = _doc(m, is_public=True, is_sar=True)
        result = bsa.evaluate(ctx, doc)
        assert not result.is_denied

    def test_customer_accessing_own_sar_denied(self, m, bsa):
        """SAR subject (is_same_customer=True) is denied under 31 USC §5318(g)(2) tipping-off prohibition."""
        ctx = _ctx(m, is_same_customer=True)
        doc = _doc(m, is_sar=True)
        result = bsa.evaluate(ctx, doc)
        assert result.is_denied
        assert "tipping" in result.reason.lower() or "5318" in result.reason or "SAR" in result.reason

    def test_compliance_officer_sar_authorized_permitted(self, m, bsa):
        """Compliance officer with explicit SAR access authorization is permitted."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            sar_access_authorized=True,
        )
        doc = _doc(m, is_sar=True)
        result = bsa.evaluate(ctx, doc)
        assert not result.is_denied

    def test_compliance_officer_sar_not_authorized_denied(self, m, bsa):
        """Compliance officer without SAR authorization is denied."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            sar_access_authorized=False,
        )
        doc = _doc(m, is_sar=True)
        result = bsa.evaluate(ctx, doc)
        assert result.is_denied

    def test_law_enforcement_sar_permitted(self, m, bsa):
        """Law enforcement with proper legal process has access to SAR documents."""
        ctx = _ctx(m, is_law_enforcement=True)
        doc = _doc(m, is_sar=True)
        result = bsa.evaluate(ctx, doc)
        assert not result.is_denied

    def test_ctr_compliance_officer_permitted(self, m, bsa):
        """Compliance officer with CTR review authorization can access CTR documents."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.COMPLIANCE_OFFICER,
            ctr_review_authorized=True,
        )
        doc = _doc(m, is_ctr=True)
        result = bsa.evaluate(ctx, doc)
        assert not result.is_denied

    def test_aml_investigation_default_denied(self, m, bsa):
        """Registered representative is denied access to AML investigation materials."""
        ctx = _ctx(m, user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE)
        doc = _doc(m, contains_aml_investigation=True)
        result = bsa.evaluate(ctx, doc)
        assert result.is_denied


# ---------------------------------------------------------------------------
# TestFinancialServicesRAGPipeline — 8 tests
# ---------------------------------------------------------------------------


class TestFinancialServicesRAGPipeline:
    @pytest.fixture
    def pipeline(self, m):
        return m.FinancialServicesRAGPipeline()

    def test_compliance_officer_gets_npi_docs(self, m, pipeline):
        """Fully compliant compliance officer context permits all NPI documents."""
        ctx = _ctx(m)
        docs = [
            _doc(m, document_id="DOC-001", npi_category=m.NPICategory.ACCOUNT_INFORMATION),
            _doc(m, document_id="DOC-002", npi_category=m.NPICategory.TRANSACTION_HISTORY),
            _doc(m, document_id="DOC-003", npi_category=m.NPICategory.CREDIT_INFORMATION),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert len(result) == 3
        permitted_ids = {d.document_id for d in result}
        assert permitted_ids == {"DOC-001", "DOC-002", "DOC-003"}

    def test_customer_self_access_permitted(self, m, pipeline):
        """Customer self-access is permitted for NPI but SAR is still denied."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.CUSTOMER,
            is_same_customer=True,
        )
        npi_doc = _doc(m, document_id="NPI-DOC", is_sar=False)
        sar_doc = _doc(m, document_id="SAR-DOC", is_sar=True)
        result = pipeline.retrieve(ctx, [npi_doc, sar_doc])
        permitted_ids = {d.document_id for d in result}
        assert "NPI-DOC" in permitted_ids
        assert "SAR-DOC" not in permitted_ids

    def test_no_safeguards_blocks_all_npi(self, m, pipeline):
        """Missing safeguard controls cause all NPI documents to be denied at Reg S-P layer."""
        ctx = _ctx(m, has_safeguard_controls=False)
        docs = [
            _doc(m, document_id="DOC-001"),
            _doc(m, document_id="DOC-002"),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert result == []

    def test_public_docs_always_pass(self, m, pipeline):
        """Public documents pass through all four layers regardless of other context."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE,
            has_safeguard_controls=False,
            glba_opt_out_honored=False,
        )
        docs = [
            _doc(m, document_id="PUB-001", is_public=True),
            _doc(m, document_id="PUB-002", is_public=True),
        ]
        result = pipeline.retrieve(ctx, docs)
        assert len(result) == 2

    def test_sar_tipping_off_prevents_customer_access(self, m, pipeline):
        """SAR documents are denied for any customer (is_same_customer=True) via tipping-off prohibition."""
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.CUSTOMER,
            is_same_customer=True,
        )
        sar_doc = _doc(m, document_id="SAR-001", is_sar=True)
        result = pipeline.retrieve(ctx, [sar_doc])
        assert result == []

    def test_pipeline_has_four_layers(self, m, pipeline):
        """Pipeline must contain exactly four filter layers."""
        assert len(pipeline._layers) == 4

    def test_empty_document_list(self, m, pipeline):
        """Retrieving from an empty document list returns an empty list."""
        ctx = _ctx(m)
        result = pipeline.retrieve(ctx, [])
        assert result == []

    def test_affiliate_without_auth_blocked(self, m, pipeline):
        """Affiliated institution without customer authorization is blocked for NPI documents.

        Uses REGISTERED_REPRESENTATIVE role so the compliance-officer safeguard
        branch does not fire before the affiliate denial check in GLBA Layer 1.
        """
        ctx = _ctx(
            m,
            user_role=m.FinancialRole.REGISTERED_REPRESENTATIVE,
            is_affiliated_institution=True,
            affiliate_sharing_authorized=False,
        )
        npi_doc = _doc(m, document_id="NPI-001")
        result = pipeline.retrieve(ctx, [npi_doc])
        assert result == []
