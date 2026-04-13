"""
Tests for 19_pharma_clinical_rag.py

Covers FDA 21 CFR Part 11, ICH E6(R3) GCP, and HIPAA minimum necessary
filters, the ClinicalRAGPipeline, and all four demonstration scenarios.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Module loading helper (frozen-dataclass fix for Python 3.14+)
# ---------------------------------------------------------------------------

_MODULE_NAME = "pharma_clinical_rag"
_MODULE_PATH = Path(__file__).parent.parent / "examples" / "19_pharma_clinical_rag.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(_MODULE_NAME, _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    # Must be registered BEFORE exec_module so frozen dataclasses can resolve
    # their module reference via sys.modules (Python 3.14+ requirement).
    sys.modules[_MODULE_NAME] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_mod = _load_module()

# Pull names into the test module namespace for convenience
ClinicalDocument = _mod.ClinicalDocument
ClinicalAccessContext = _mod.ClinicalAccessContext
ClinicalRecordCategory = _mod.ClinicalRecordCategory
GCPRole = _mod.GCPRole
TrialPhase = _mod.TrialPhase
FDA21CFRPart11Filter = _mod.FDA21CFRPart11Filter
ICHGCPFilter = _mod.ICHGCPFilter
HIPAAMinimumNecessaryFilter = _mod.HIPAAMinimumNecessaryFilter
ClinicalRAGPipeline = _mod.ClinicalRAGPipeline
SAMPLE_DOCUMENTS = _mod.SAMPLE_DOCUMENTS
TRIAL_ID = _mod.TRIAL_ID
SITE_A = _mod.SITE_A
SITE_B = _mod.SITE_B


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def controlled_protocol_doc() -> ClinicalDocument:
    return ClinicalDocument(
        doc_id="DOC-PROTOCOL",
        content="Phase III trial protocol.",
        category=ClinicalRecordCategory.PROTOCOL,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    )


@pytest.fixture()
def public_summary_doc() -> ClinicalDocument:
    return ClinicalDocument(
        doc_id="DOC-PUBLIC",
        content="ClinicalTrials.gov public listing.",
        category=ClinicalRecordCategory.PUBLIC_SUMMARY,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=False,
        site_id=None,
        is_controlled_record=False,
    )


@pytest.fixture()
def phi_doc() -> ClinicalDocument:
    return ClinicalDocument(
        doc_id="DOC-PHI",
        content="Subject enrollment record with demographics.",
        category=ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=False,
        contains_phi=True,
        site_id=SITE_A,
        is_controlled_record=True,
    )


@pytest.fixture()
def randomization_doc() -> ClinicalDocument:
    return ClinicalDocument(
        doc_id="DOC-RAND",
        content="Randomization code list.",
        category=ClinicalRecordCategory.RANDOMIZATION_CODE,
        trial_id=TRIAL_ID,
        trial_phase=TrialPhase.PHASE_III,
        is_unblinded_data=True,
        contains_phi=False,
        site_id=None,
        is_controlled_record=True,
    )


@pytest.fixture()
def authorized_ctx() -> ClinicalAccessContext:
    return ClinicalAccessContext(
        role=GCPRole.DATA_MANAGER,
        gxp_credentials_valid=True,
        gcp_training_current=True,
        authorized_trial_ids=frozenset({TRIAL_ID}),
        is_blinded=False,
        authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
        phi_authorized=True,
    )


# ---------------------------------------------------------------------------
# FDA 21 CFR Part 11 Filter
# ---------------------------------------------------------------------------


class TestFDA21CFRPart11Filter:
    """Tests for §11.10(d) credentials and §11.10(g) authority checks."""

    def _filter(self) -> FDA21CFRPart11Filter:
        return FDA21CFRPart11Filter()

    def test_passes_with_valid_credentials(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        permitted, blocked = self._filter().filter([controlled_protocol_doc], authorized_ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_no_gxp_credentials(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "gxp_credentials_valid": False})
        permitted, blocked = self._filter().filter([controlled_protocol_doc], ctx)
        assert len(permitted) == 0
        assert "§11.10(d)" in blocked[0]

    def test_passes_public_record_without_credentials(self, public_summary_doc: ClinicalDocument) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.EXTERNAL_AUDITOR,
            gxp_credentials_valid=False,
            gcp_training_current=False,
            authorized_trial_ids=frozenset(),
            is_blinded=False,
            authorized_trial_phases=frozenset(),
            phi_authorized=False,
        )
        permitted, blocked = self._filter().filter([public_summary_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_unauthorized_trial(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "authorized_trial_ids": frozenset({"OTHER-TRIAL"})})
        permitted, blocked = self._filter().filter([controlled_protocol_doc], ctx)
        assert len(permitted) == 0
        assert "§11.10(g)" in blocked[0]

    def test_blocks_unauthorized_phase(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "authorized_trial_phases": frozenset({TrialPhase.PHASE_I})}
        )
        permitted, blocked = self._filter().filter([controlled_protocol_doc], ctx)
        assert len(permitted) == 0
        assert "PHASE_III" in blocked[0]

    def test_block_reason_contains_doc_id(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "gxp_credentials_valid": False})
        _, blocked = self._filter().filter([controlled_protocol_doc], ctx)
        assert "DOC-PROTOCOL" in blocked[0]


# ---------------------------------------------------------------------------
# ICH GCP Filter
# ---------------------------------------------------------------------------


class TestICHGCPFilter:
    """Tests for ICH E6(R3) blinding integrity and site isolation."""

    def _filter(self) -> ICHGCPFilter:
        return ICHGCPFilter()

    def test_passes_authorized_unblinded_role(
        self, randomization_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "role": GCPRole.UNBLINDED_STATISTICIAN, "is_blinded": False}
        )
        permitted, blocked = self._filter().filter([randomization_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_blinded_role_accessing_randomization_code(
        self, randomization_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "role": GCPRole.BLINDED_STATISTICIAN, "is_blinded": True}
        )
        permitted, blocked = self._filter().filter([randomization_doc], ctx)
        assert len(permitted) == 0
        assert "blinding violation" in blocked[0]

    def test_blocks_pi_accessing_interim_analysis(self, authorized_ctx: ClinicalAccessContext) -> None:
        interim_doc = ClinicalDocument(
            doc_id="DOC-INTERIM",
            content="Pre-specified interim analysis.",
            category=ClinicalRecordCategory.INTERIM_ANALYSIS,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=True,
            contains_phi=False,
            site_id=None,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "role": GCPRole.PRINCIPAL_INVESTIGATOR, "is_blinded": True}
        )
        permitted, blocked = self._filter().filter([interim_doc], ctx)
        assert len(permitted) == 0
        assert "blinding violation" in blocked[0]

    def test_blocks_cross_site_access_for_cra(self, authorized_ctx: ClinicalAccessContext) -> None:
        site_b_doc = ClinicalDocument(
            doc_id="DOC-SITE-B-AE",
            content="Site B adverse events.",
            category=ClinicalRecordCategory.ADVERSE_EVENT,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=False,
            contains_phi=True,
            site_id=SITE_B,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "role": GCPRole.CLINICAL_RESEARCH_ASSOCIATE, "site_id": SITE_A}
        )
        permitted, blocked = self._filter().filter([site_b_doc], ctx)
        assert len(permitted) == 0
        assert "cross-site" in blocked[0]

    def test_allows_same_site_access_for_cra(self, authorized_ctx: ClinicalAccessContext) -> None:
        site_a_doc = ClinicalDocument(
            doc_id="DOC-SITE-A-AE",
            content="Site A adverse events.",
            category=ClinicalRecordCategory.ADVERSE_EVENT,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=False,
            contains_phi=True,
            site_id=SITE_A,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            **{
                **authorized_ctx.__dict__,
                "role": GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
                "is_blinded": True,
                "site_id": SITE_A,
            }
        )
        permitted, blocked = self._filter().filter([site_a_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_expired_gcp_training(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "gcp_training_current": False})
        permitted, blocked = self._filter().filter([controlled_protocol_doc], ctx)
        assert len(permitted) == 0
        assert "GCP training" in blocked[0]

    def test_passes_public_record_without_gcp_training(self, public_summary_doc: ClinicalDocument) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.EXTERNAL_AUDITOR,
            gxp_credentials_valid=False,
            gcp_training_current=False,
            authorized_trial_ids=frozenset(),
            is_blinded=False,
            authorized_trial_phases=frozenset(),
            phi_authorized=False,
        )
        permitted, blocked = self._filter().filter([public_summary_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_docs_with_unblinded_flag_for_blinded_role(self, authorized_ctx: ClinicalAccessContext) -> None:
        unblinded_doc = ClinicalDocument(
            doc_id="DOC-CSR",
            content="Unblinded CSR draft.",
            category=ClinicalRecordCategory.CLINICAL_STUDY_REPORT,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=True,  # explicitly flagged unblinded
            contains_phi=False,
            site_id=None,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "role": GCPRole.PRINCIPAL_INVESTIGATOR, "is_blinded": True}
        )
        permitted, blocked = self._filter().filter([unblinded_doc], ctx)
        assert len(permitted) == 0
        assert "blinding violation" in blocked[0]


# ---------------------------------------------------------------------------
# HIPAA Minimum Necessary Filter
# ---------------------------------------------------------------------------


class TestHIPAAMinimumNecessaryFilter:
    """Tests for 45 CFR §164.502(b) minimum necessary PHI access."""

    def _filter(self) -> HIPAAMinimumNecessaryFilter:
        return HIPAAMinimumNecessaryFilter()

    def test_passes_non_phi_doc(
        self, controlled_protocol_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        permitted, blocked = self._filter().filter([controlled_protocol_doc], authorized_ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_phi_without_authorization(
        self, phi_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "phi_authorized": False})
        permitted, blocked = self._filter().filter([phi_doc], ctx)
        assert len(permitted) == 0
        assert "§164.502(b)" in blocked[0]

    def test_passes_phi_with_authorization(
        self, phi_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        permitted, blocked = self._filter().filter([phi_doc], authorized_ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_blocks_out_of_scope_phi_category(self, authorized_ctx: ClinicalAccessContext) -> None:
        lab_doc = ClinicalDocument(
            doc_id="DOC-LAB",
            content="Lab results.",
            category=ClinicalRecordCategory.LAB_RESULT,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=False,
            contains_phi=True,
            site_id=SITE_A,
            is_controlled_record=True,
        )
        # Minimum necessary scope only includes ADVERSE_EVENT, not LAB_RESULT
        ctx = ClinicalAccessContext(
            **{**authorized_ctx.__dict__, "minimum_necessary_scope": frozenset({ClinicalRecordCategory.ADVERSE_EVENT})}
        )
        permitted, blocked = self._filter().filter([lab_doc], ctx)
        assert len(permitted) == 0
        assert "minimum necessary scope" in blocked[0]

    def test_passes_phi_within_minimum_necessary_scope(
        self, phi_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        ctx = ClinicalAccessContext(
            **{
                **authorized_ctx.__dict__,
                "minimum_necessary_scope": frozenset(
                    {
                        ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
                    }
                ),
            }
        )
        permitted, blocked = self._filter().filter([phi_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0

    def test_empty_scope_permits_all_authorized_phi(
        self, phi_doc: ClinicalDocument, authorized_ctx: ClinicalAccessContext
    ) -> None:
        """Empty minimum_necessary_scope means no category restriction."""
        ctx = ClinicalAccessContext(**{**authorized_ctx.__dict__, "minimum_necessary_scope": frozenset()})
        permitted, blocked = self._filter().filter([phi_doc], ctx)
        assert len(permitted) == 1
        assert len(blocked) == 0


# ---------------------------------------------------------------------------
# ClinicalRAGPipeline — defence-in-depth
# ---------------------------------------------------------------------------


class TestClinicalRAGPipeline:
    """Integration tests for the three-layer pipeline."""

    def _pipeline(self) -> ClinicalRAGPipeline:
        return ClinicalRAGPipeline()

    def test_full_access_authorized_user(self, authorized_ctx: ClinicalAccessContext) -> None:
        """An unblinded data manager with full auth should access all non-PHI docs."""
        pipeline = self._pipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, authorized_ctx, "data management")
        # PATIENT-PHI is PHI and phi_authorized=True; all others should pass
        assert audit.permitted_count > 0
        doc_ids = {d.doc_id for d in permitted}
        assert "DOC-PROTOCOL" in doc_ids
        assert "DOC-PUBLIC-SUMMARY" in doc_ids

    def test_blocked_count_plus_permitted_count_equals_total(self, authorized_ctx: ClinicalAccessContext) -> None:
        pipeline = self._pipeline()
        _, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, authorized_ctx, "test")
        assert audit.permitted_count + audit.blocked_count == audit.total_candidates

    def test_union_blocking_logic(self) -> None:
        """A doc blocked by HIPAA should not appear in permitted even if ICH GCP passes it."""
        phi_only_doc = ClinicalDocument(
            doc_id="DOC-PHI-ONLY",
            content="Identifiable patient data.",
            category=ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=False,
            contains_phi=True,
            site_id=None,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            role=GCPRole.DATA_MANAGER,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=False,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=False,  # HIPAA will block
        )
        pipeline = self._pipeline()
        permitted, audit = pipeline.retrieve([phi_only_doc], ctx, "test")
        assert len(permitted) == 0
        assert audit.blocked_count == 1

    def test_audit_record_phi_accessed_flag(self, authorized_ctx: ClinicalAccessContext) -> None:
        phi_doc = ClinicalDocument(
            doc_id="DOC-PHI-2",
            content="PHI content.",
            category=ClinicalRecordCategory.ADVERSE_EVENT,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=False,
            contains_phi=True,
            site_id=None,
            is_controlled_record=True,
        )
        pipeline = self._pipeline()
        permitted, audit = pipeline.retrieve([phi_doc], authorized_ctx, "test")
        if any(d.contains_phi for d in permitted):
            assert audit.phi_accessed
        else:
            assert not audit.phi_accessed

    def test_audit_record_blinding_violation_flag(self) -> None:
        rand_doc = ClinicalDocument(
            doc_id="DOC-RAND-2",
            content="Randomization codes.",
            category=ClinicalRecordCategory.RANDOMIZATION_CODE,
            trial_id=TRIAL_ID,
            trial_phase=TrialPhase.PHASE_III,
            is_unblinded_data=True,
            contains_phi=False,
            site_id=None,
            is_controlled_record=True,
        )
        ctx = ClinicalAccessContext(
            role=GCPRole.BLINDED_STATISTICIAN,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=False,
        )
        pipeline = self._pipeline()
        _, audit = pipeline.retrieve([rand_doc], ctx, "test")
        assert audit.blinding_violation_blocked


# ---------------------------------------------------------------------------
# Scenario functions (integration smoke tests)
# ---------------------------------------------------------------------------


class TestScenarios:
    """Smoke tests for the four published demonstration scenarios."""

    def test_scenario_a_blinded_statistician(self) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.BLINDED_STATISTICIAN,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=False,
            minimum_necessary_scope=frozenset(),
        )
        pipeline = ClinicalRAGPipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "statistical analysis planning")
        assert audit.blinding_violation_blocked
        assert all(not d.is_unblinded_data for d in permitted)
        # PHI must be blocked (phi_authorized=False)
        assert all(not d.contains_phi for d in permitted)

    def test_scenario_b_cra_site_audit(self) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=True,
            site_id=SITE_A,
            minimum_necessary_scope=frozenset(
                {
                    ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
                    ClinicalRecordCategory.ADVERSE_EVENT,
                    ClinicalRecordCategory.LAB_RESULT,
                }
            ),
        )
        pipeline = ClinicalRAGPipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "site monitoring")
        permitted_ids = {d.doc_id for d in permitted}
        assert "DOC-AE-SITE-B" not in permitted_ids, "Cross-site access must be blocked"
        assert "DOC-AE-SITE-A" in permitted_ids, "Same-site AEs must be accessible"

    def test_scenario_c_unauthorized_external(self) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.EXTERNAL_AUDITOR,
            gxp_credentials_valid=False,
            gcp_training_current=False,
            authorized_trial_ids=frozenset(),
            is_blinded=False,
            authorized_trial_phases=frozenset(),
            phi_authorized=False,
        )
        pipeline = ClinicalRAGPipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "unauthorized access attempt")
        # Only non-controlled records (PUBLIC_SUMMARY) should pass
        assert all(not d.is_controlled_record for d in permitted)
        permitted_ids = {d.doc_id for d in permitted}
        assert "DOC-PUBLIC-SUMMARY" in permitted_ids

    def test_scenario_d_principal_investigator(self) -> None:
        ctx = ClinicalAccessContext(
            role=GCPRole.PRINCIPAL_INVESTIGATOR,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=True,
            site_id=SITE_A,
            minimum_necessary_scope=frozenset(
                {
                    ClinicalRecordCategory.ADVERSE_EVENT,
                    ClinicalRecordCategory.SERIOUS_ADVERSE_EVENT,
                    ClinicalRecordCategory.LAB_RESULT,
                }
            ),
        )
        pipeline = ClinicalRAGPipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "safety review")
        permitted_ids = {d.doc_id for d in permitted}
        assert all(not d.is_unblinded_data for d in permitted), "PI must not see unblinded data"
        assert "DOC-AE-SITE-A" in permitted_ids, "PI must see their site AEs"
        assert "DOC-AE-SITE-B" not in permitted_ids, "PI must not see other sites"

    def test_scenario_a_permitted_count(self) -> None:
        """Blinded statistician: 3 permitted (PROTOCOL, INV-BROCHURE, PUBLIC-SUMMARY)."""
        ctx = ClinicalAccessContext(
            role=GCPRole.BLINDED_STATISTICIAN,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=False,
            minimum_necessary_scope=frozenset(),
        )
        pipeline = ClinicalRAGPipeline()
        _, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "test")
        assert audit.permitted_count == 3

    def test_scenario_b_permitted_count(self) -> None:
        """CRA at Site A: 6 permitted (all Site A docs + non-site docs, no unblinded)."""
        ctx = ClinicalAccessContext(
            role=GCPRole.CLINICAL_RESEARCH_ASSOCIATE,
            gxp_credentials_valid=True,
            gcp_training_current=True,
            authorized_trial_ids=frozenset({TRIAL_ID}),
            is_blinded=True,
            authorized_trial_phases=frozenset({TrialPhase.PHASE_III}),
            phi_authorized=True,
            site_id=SITE_A,
            minimum_necessary_scope=frozenset(
                {
                    ClinicalRecordCategory.PATIENT_DATA_IDENTIFIABLE,
                    ClinicalRecordCategory.ADVERSE_EVENT,
                    ClinicalRecordCategory.LAB_RESULT,
                }
            ),
        )
        pipeline = ClinicalRAGPipeline()
        _, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "test")
        assert audit.permitted_count == 6

    def test_scenario_c_only_public_docs_returned(self) -> None:
        """External user with no credentials: exactly 1 public summary returned."""
        ctx = ClinicalAccessContext(
            role=GCPRole.EXTERNAL_AUDITOR,
            gxp_credentials_valid=False,
            gcp_training_current=False,
            authorized_trial_ids=frozenset(),
            is_blinded=False,
            authorized_trial_phases=frozenset(),
            phi_authorized=False,
        )
        pipeline = ClinicalRAGPipeline()
        permitted, audit = pipeline.retrieve(SAMPLE_DOCUMENTS, ctx, "test")
        assert audit.permitted_count == 1
        assert audit.blocked_count == 9
