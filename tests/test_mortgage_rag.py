"""Tests for 20_real_estate_mortgage_rag.py — Fair Housing Act + HMDA + CFPB UDAAP + RESPA"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


def _load_module(name: str):
    examples_dir = Path(__file__).parent.parent / "examples"
    spec = importlib.util.spec_from_file_location(name, examples_dir / "20_real_estate_mortgage_rag.py")
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def m():
    return _load_module("mortgage_rag")


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_context(m, **kwargs):
    defaults = dict(
        loan_officer_id="LO-TX-001",
        license_state="TX",
        property_state="TX",
        query_context=m.QueryContext.APPRAISAL_REVIEW,
        adverse_action_notice_required=False,
        hmda_reporting_context=False,
        loan_purpose=m.LoanPurpose.HOME_PURCHASE,
    )
    defaults.update(kwargs)
    return m.MortgageAccessContext(**defaults)


def _make_doc(m, **kwargs):
    defaults = dict(
        doc_id="DOC-001",
        category=m.MortgageDocumentCategory.CREDIT_REPORT,
        title="Test Doc",
        contains_protected_class_data=False,
        contains_hmda_demographic_fields=False,
        property_state="TX",
        adverse_action_factors=(),
        is_public_disclosure=False,
    )
    defaults.update(kwargs)
    return m.MortgageDocument(**defaults)


# ---------------------------------------------------------------------------
# TestFHADisparateImpactFilter
# ---------------------------------------------------------------------------


class TestFHADisparateImpactFilter:
    def test_neighborhood_demographic_blocked_in_appraisal(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(m, doc_id="D1", category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC)
        ctx = _make_context(m, query_context=m.QueryContext.APPRAISAL_REVIEW)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("D1" in r for r in reasons)
        assert any("disparate impact" in r.lower() for r in reasons)

    def test_census_tract_blocked_in_underwriting(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(m, doc_id="D2", category=m.MortgageDocumentCategory.CENSUS_TRACT_DATA)
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("D2" in r for r in reasons)

    def test_protected_class_data_blocked_in_underwriting(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(
            m, doc_id="D3", category=m.MortgageDocumentCategory.CREDIT_REPORT, contains_protected_class_data=True
        )
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0

    def test_public_disclosure_not_blocked(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(
            m, doc_id="D4", category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC, is_public_disclosure=True
        )
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_credit_report_permitted_in_underwriting(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(m, doc_id="D5", category=m.MortgageDocumentCategory.CREDIT_REPORT)
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1
        assert len(reasons) == 0

    def test_compliance_audit_context_not_restricted(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(
            m,
            doc_id="D6",
            category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC,
            contains_protected_class_data=True,
        )
        ctx = _make_context(m, query_context=m.QueryContext.COMPLIANCE_AUDIT)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_adverse_action_context_blocks_demographic(self, m):
        f = m.FHADisparateImpactFilter()
        doc = _make_doc(m, doc_id="D7", category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC)
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0

    def test_multiple_docs_partial_block(self, m):
        f = m.FHADisparateImpactFilter()
        docs = [
            _make_doc(m, doc_id="D8", category=m.MortgageDocumentCategory.CREDIT_REPORT),
            _make_doc(m, doc_id="D9", category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC),
            _make_doc(m, doc_id="D10", category=m.MortgageDocumentCategory.APPRAISAL_REPORT),
        ]
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter(docs, ctx)
        assert len(permitted) == 2
        assert len(reasons) == 1
        assert "D9" in reasons[0]


# ---------------------------------------------------------------------------
# TestHMDAComplianceFilter
# ---------------------------------------------------------------------------


class TestHMDAComplianceFilter:
    def test_hmda_demographic_blocked_in_underwriting(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(m, doc_id="H1", category=m.MortgageDocumentCategory.HMDA_DEMOGRAPHIC)
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("H1" in r for r in reasons)
        assert any("1002.5" in r or "Reg C" in r for r in reasons)

    def test_hmda_lar_blocked_in_appraisal(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(m, doc_id="H2", category=m.MortgageDocumentCategory.HMDA_LAR_DATA)
        ctx = _make_context(m, query_context=m.QueryContext.APPRAISAL_REVIEW)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0

    def test_hmda_reporting_context_permits_hmda_data(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(m, doc_id="H3", category=m.MortgageDocumentCategory.HMDA_DEMOGRAPHIC)
        ctx = _make_context(m, query_context=m.QueryContext.HMDA_REPORTING, hmda_reporting_context=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1
        assert len(reasons) == 0

    def test_doc_with_hmda_fields_blocked_in_underwriting(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(
            m, doc_id="H4", category=m.MortgageDocumentCategory.CREDIT_REPORT, contains_hmda_demographic_fields=True
        )
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("H4" in r for r in reasons)

    def test_normal_doc_without_hmda_fields_permitted(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(m, doc_id="H5", category=m.MortgageDocumentCategory.INCOME_VERIFICATION)
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_servicing_context_not_restricted(self, m):
        f = m.HMDAComplianceFilter()
        doc = _make_doc(m, doc_id="H6", category=m.MortgageDocumentCategory.HMDA_LAR_DATA)
        ctx = _make_context(m, query_context=m.QueryContext.SERVICING)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1


# ---------------------------------------------------------------------------
# TestCFPBUDAAPFilter
# ---------------------------------------------------------------------------


class TestCFPBUDAAPFilter:
    def test_denial_without_factors_blocked(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(m, doc_id="U1", category=m.MortgageDocumentCategory.DENIAL_NOTICE, adverse_action_factors=())
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("U1" in r for r in reasons)
        assert any("1002.9" in r for r in reasons)

    def test_denial_with_protected_class_factor_blocked(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(
            m,
            doc_id="U2",
            category=m.MortgageDocumentCategory.DENIAL_NOTICE,
            adverse_action_factors=("national origin — foreign income not counted",),
        )
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("national origin" in r.lower() for r in reasons)

    def test_denial_with_valid_factors_permitted(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(
            m,
            doc_id="U3",
            category=m.MortgageDocumentCategory.DENIAL_NOTICE,
            adverse_action_factors=(
                "Credit score below minimum (640)",
                "Debt-to-income ratio exceeds 50%",
            ),
        )
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1
        assert len(reasons) == 0

    def test_non_adverse_action_context_passthrough(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(m, doc_id="U4", category=m.MortgageDocumentCategory.DENIAL_NOTICE, adverse_action_factors=())
        ctx = _make_context(m, query_context=m.QueryContext.APPRAISAL_REVIEW, adverse_action_notice_required=False)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_neighborhood_demo_blocked_in_adverse_action(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(m, doc_id="U5", category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC)
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0

    def test_counter_offer_with_sex_factor_blocked(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(
            m,
            doc_id="U6",
            category=m.MortgageDocumentCategory.COUNTER_OFFER,
            adverse_action_factors=("applicant sex — maternity leave income excluded",),
        )
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0

    def test_adverse_action_not_required_flag_disables_filter(self, m):
        f = m.CFPBUDAAPFilter()
        doc = _make_doc(m, doc_id="U7", category=m.MortgageDocumentCategory.DENIAL_NOTICE, adverse_action_factors=())
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=False)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1


# ---------------------------------------------------------------------------
# TestRESPALicensingFilter
# ---------------------------------------------------------------------------


class TestRESPALicensingFilter:
    def test_cross_state_blocked(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R1", property_state="TX")
        ctx = _make_context(
            m, license_state="CA", property_state="TX", query_context=m.QueryContext.UNDERWRITING_DECISION
        )
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 0
        assert any("R1" in r for r in reasons)
        assert any("5104" in r or "SAFE" in r for r in reasons)

    def test_same_state_permitted(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R2", property_state="TX")
        ctx = _make_context(
            m, license_state="TX", property_state="TX", query_context=m.QueryContext.UNDERWRITING_DECISION
        )
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1
        assert len(reasons) == 0

    def test_compliance_audit_exempt(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R3", property_state="TX")
        ctx = _make_context(m, license_state="WA", property_state="TX", query_context=m.QueryContext.COMPLIANCE_AUDIT)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_hmda_reporting_exempt(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R4", property_state="FL")
        ctx = _make_context(
            m,
            license_state="CA",
            property_state="FL",
            query_context=m.QueryContext.HMDA_REPORTING,
            hmda_reporting_context=True,
        )
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_public_disclosure_not_restricted(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R5", property_state="NY", is_public_disclosure=True)
        ctx = _make_context(m, license_state="CA", property_state="NY", query_context=m.QueryContext.GENERAL_QUERY)
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1

    def test_case_insensitive_state_matching(self, m):
        f = m.RESPALicensingFilter()
        doc = _make_doc(m, doc_id="R6", property_state="tx")
        ctx = _make_context(
            m, license_state="TX", property_state="tx", query_context=m.QueryContext.UNDERWRITING_DECISION
        )
        permitted, reasons = f.filter([doc], ctx)
        assert len(permitted) == 1


# ---------------------------------------------------------------------------
# TestMortgageRAGPipeline
# ---------------------------------------------------------------------------


class TestMortgageRAGPipeline:
    def _full_kb(self, m):
        return [
            _make_doc(m, doc_id="CREDIT-001", category=m.MortgageDocumentCategory.CREDIT_REPORT, property_state="TX"),
            _make_doc(
                m, doc_id="INCOME-001", category=m.MortgageDocumentCategory.INCOME_VERIFICATION, property_state="TX"
            ),  # noqa: E501
            _make_doc(
                m,
                doc_id="DEMO-001",
                category=m.MortgageDocumentCategory.NEIGHBORHOOD_DEMOGRAPHIC,
                contains_protected_class_data=True,
                property_state="TX",
            ),
            _make_doc(
                m,
                doc_id="HMDA-001",
                category=m.MortgageDocumentCategory.HMDA_DEMOGRAPHIC,
                contains_hmda_demographic_fields=True,
                property_state="TX",
            ),
        ]

    def test_appraisal_review_blocks_demographic_and_hmda(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(m, query_context=m.QueryContext.APPRAISAL_REVIEW)
        docs = self._full_kb(m)
        permitted, audit = pipeline.retrieve(docs, ctx)
        doc_ids = {d.doc_id for d in permitted}
        assert "DEMO-001" not in doc_ids
        assert "HMDA-001" not in doc_ids
        assert "CREDIT-001" in doc_ids
        assert "INCOME-001" in doc_ids

    def test_audit_record_captures_all_blocks(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(m, query_context=m.QueryContext.UNDERWRITING_DECISION)
        docs = self._full_kb(m)
        _, audit = pipeline.retrieve(docs, ctx)
        assert audit.documents_requested == 4
        assert audit.documents_permitted < 4
        total_blocked = (
            len(audit.fha_blocks) + len(audit.hmda_blocks) + len(audit.udaap_blocks) + len(audit.respa_blocks)
        )
        assert total_blocked >= 2

    def test_cross_state_blocks_everything(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(
            m, license_state="CA", property_state="TX", query_context=m.QueryContext.UNDERWRITING_DECISION
        )
        docs = self._full_kb(m)
        permitted, audit = pipeline.retrieve(docs, ctx)
        assert len(permitted) == 0
        assert len(audit.respa_blocks) > 0

    def test_hmda_reporting_context_permits_hmda_data(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(
            m,
            license_state="WA",
            property_state="TX",
            query_context=m.QueryContext.HMDA_REPORTING,
            hmda_reporting_context=True,
        )
        docs = [
            _make_doc(
                m,
                doc_id="HMDA-LAR",
                category=m.MortgageDocumentCategory.HMDA_LAR_DATA,
                contains_hmda_demographic_fields=True,
                property_state="TX",
            ),
        ]
        permitted, audit = pipeline.retrieve(docs, ctx)
        assert len(permitted) == 1
        assert audit.hmda_reporting_context is True

    def test_adverse_action_blocks_denial_without_reasons(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(m, query_context=m.QueryContext.ADVERSE_ACTION, adverse_action_notice_required=True)
        docs = [
            _make_doc(
                m,
                doc_id="DENIAL-BAD",
                category=m.MortgageDocumentCategory.DENIAL_NOTICE,
                adverse_action_factors=(),
                property_state="TX",
            ),
            _make_doc(
                m,
                doc_id="DENIAL-GOOD",
                category=m.MortgageDocumentCategory.DENIAL_NOTICE,
                adverse_action_factors=("Credit score below 640",),
                property_state="TX",
            ),
        ]
        permitted, audit = pipeline.retrieve(docs, ctx)
        doc_ids = {d.doc_id for d in permitted}
        assert "DENIAL-GOOD" in doc_ids
        assert "DENIAL-BAD" not in doc_ids

    def test_audit_fair_lending_log_format(self, m):
        pipeline = m.MortgageRAGPipeline()
        ctx = _make_context(m, query_context=m.QueryContext.APPRAISAL_REVIEW)
        _, audit = pipeline.retrieve(self._full_kb(m), ctx)
        log = audit.to_fair_lending_log()
        assert "audit_id" in log
        assert "loan_officer_id" in log
        assert "query_context" in log
        assert "property_state" in log
        assert "requested" in log
        assert "permitted" in log
        assert "total_blocked" in log
        assert isinstance(log["permitted_docs"], list)


# ---------------------------------------------------------------------------
# TestScenarios (smoke tests)
# ---------------------------------------------------------------------------


class TestScenarios:
    def test_scenario_a_runs_without_error(self, m):
        m.run_scenario_a_appraisal_review()

    def test_scenario_b_runs_without_error(self, m):
        m.run_scenario_b_hmda_reporting()

    def test_scenario_c_runs_without_error(self, m):
        m.run_scenario_c_cross_state_block()

    def test_scenario_d_runs_without_error(self, m):
        m.run_scenario_d_adverse_action()
