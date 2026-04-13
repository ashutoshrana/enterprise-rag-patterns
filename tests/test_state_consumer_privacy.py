"""
Tests for 18_state_consumer_privacy_rag.py

Covers CCPACPRAFilter, VCDPAFilter, CPAFilter, CTDPAFilter, and
MultiStatePrivacyPipeline. Verifies opt-out enforcement, SPI consent gates,
GPC signal handling, and most-restrictive-jurisdiction logic.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import importlib.util
import types

# ---------------------------------------------------------------------------
# Load module from examples directory
# ---------------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location(
    "state_consumer_privacy",
    os.path.join(os.path.dirname(__file__), "..", "examples", "18_state_consumer_privacy_rag.py"),
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["state_consumer_privacy"] = _mod  # required for frozen dataclasses on Python 3.14
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

CCPACPRAFilter = _mod.CCPACPRAFilter
VCDPAFilter = _mod.VCDPAFilter
CPAFilter = _mod.CPAFilter
CTDPAFilter = _mod.CTDPAFilter
MultiStatePrivacyPipeline = _mod.MultiStatePrivacyPipeline
ConsumerPrivacyContext = _mod.ConsumerPrivacyContext
ConsumerPrivacyState = _mod.ConsumerPrivacyState
DataProcessingPurpose = _mod.DataProcessingPurpose
SensitivePICategory = _mod.SensitivePICategory
Document = _mod.Document
SAMPLE_DOCUMENTS = _mod.SAMPLE_DOCUMENTS


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _ctx(
    states: set,
    purpose: DataProcessingPurpose = DataProcessingPurpose.PERSONALIZATION,
    opted_out_of_sale: bool = False,
    opted_out_of_sharing: bool = False,
    opted_out_of_targeted_ads: bool = False,
    gpc: bool = False,
    spi_consent: dict | None = None,
    spi_limit_use: frozenset | None = None,
    minor: bool = False,
) -> ConsumerPrivacyContext:
    return ConsumerPrivacyContext(
        resident_states=frozenset(states),
        requested_purpose=purpose,
        consumer_opted_out_of_sale=opted_out_of_sale,
        consumer_opted_out_of_sharing=opted_out_of_sharing,
        consumer_opted_out_of_targeted_ads=opted_out_of_targeted_ads,
        consumer_gpc_signal=gpc,
        sensitive_pi_consent=spi_consent or {},
        spi_limit_use_instruction=spi_limit_use or frozenset(),
        consumer_age_minor=minor,
    )


def _doc(
    doc_id: str,
    pi: SensitivePICategory = SensitivePICategory.NON_SENSITIVE,
    requires_sale_opt_in: bool = False,
    requires_sharing_opt_in: bool = False,
    is_targeted: bool = False,
    is_profiling: bool = False,
    is_third_party_sale: bool = False,
) -> Document:
    return Document(
        doc_id=doc_id,
        content="test content",
        pi_classification=pi,
        requires_sale_opt_in=requires_sale_opt_in,
        requires_sharing_opt_in=requires_sharing_opt_in,
        is_targeted_advertising=is_targeted,
        is_behavioral_profiling=is_profiling,
        is_third_party_sale=is_third_party_sale,
    )


# ---------------------------------------------------------------------------
# CCPACPRAFilter tests
# ---------------------------------------------------------------------------

class TestCCPACPRAFilter:
    def setup_method(self) -> None:
        self.f = CCPACPRAFilter()

    def test_non_california_resident_passes_all(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA}, opted_out_of_sharing=True)
        docs = [_doc("D1", requires_sharing_opt_in=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert blocked == []

    def test_sharing_opt_out_blocks_sharing_required_docs(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sharing=True)
        docs = [_doc("D1", requires_sharing_opt_in=True), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D2"
        assert len(blocked) == 1

    def test_sharing_opt_out_blocks_targeted_advertising(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sharing=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§1798.135" in blocked[0]

    def test_sale_opt_out_blocks_third_party_sale(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sale=True)
        docs = [_doc("D1", is_third_party_sale=True), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D2"

    def test_spi_limit_use_blocks_non_essential_purpose(self) -> None:
        ctx = _ctx(
            {ConsumerPrivacyState.CALIFORNIA},
            purpose=DataProcessingPurpose.PERSONALIZATION,
            spi_limit_use=frozenset({SensitivePICategory.PRECISE_GEOLOCATION}),
        )
        docs = [_doc("D1", pi=SensitivePICategory.PRECISE_GEOLOCATION)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§1798.121" in blocked[0]

    def test_spi_limit_use_allows_essential_purpose(self) -> None:
        ctx = _ctx(
            {ConsumerPrivacyState.CALIFORNIA},
            purpose=DataProcessingPurpose.ACCOUNT_SERVICING,
            spi_limit_use=frozenset({SensitivePICategory.PRECISE_GEOLOCATION}),
        )
        docs = [_doc("D1", pi=SensitivePICategory.PRECISE_GEOLOCATION)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert blocked == []

    def test_minor_blocks_sale_sharing_opt_in(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, minor=True)
        docs = [_doc("D1", requires_sale_opt_in=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§1798.120(c)" in blocked[0]

    def test_no_opt_out_permits_all_non_sensitive(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA})
        docs = [_doc("D1"), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 2
        assert blocked == []

    def test_public_classification_always_permitted(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sale=True, opted_out_of_sharing=True)
        docs = [_doc("D1", pi=SensitivePICategory.PUBLIC)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1

    def test_block_reason_contains_doc_id(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sharing=True)
        docs = [_doc("MY-DOC-42", requires_sharing_opt_in=True)]
        _, blocked = self.f.filter(docs, ctx)
        assert "MY-DOC-42" in blocked[0]


# ---------------------------------------------------------------------------
# VCDPAFilter tests
# ---------------------------------------------------------------------------

class TestVCDPAFilter:
    def setup_method(self) -> None:
        self.f = VCDPAFilter()

    def test_non_virginia_passes_all(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA})
        docs = [_doc("D1", pi=SensitivePICategory.HEALTH_MEDICAL)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert blocked == []

    def test_sensitive_health_requires_consent(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA}, spi_consent={})
        docs = [_doc("D1", pi=SensitivePICategory.HEALTH_MEDICAL)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§59.1-578" in blocked[0]

    def test_sensitive_health_with_consent_permitted(self) -> None:
        ctx = _ctx(
            {ConsumerPrivacyState.VIRGINIA},
            spi_consent={SensitivePICategory.HEALTH_MEDICAL: True},
        )
        docs = [_doc("D1", pi=SensitivePICategory.HEALTH_MEDICAL)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1

    def test_geolocation_sensitive_without_consent_blocked(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA})
        docs = [_doc("D1", pi=SensitivePICategory.PRECISE_GEOLOCATION)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0

    def test_targeted_advertising_opt_out_blocks_ad_docs(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA}, opted_out_of_targeted_ads=True)
        docs = [_doc("D1", is_targeted=True), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D2"
        assert "§59.1-577(A)(5)" in blocked[0]

    def test_profiling_opt_out_blocks_profiling_docs(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA}, opted_out_of_targeted_ads=True)
        docs = [_doc("D1", is_profiling=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§59.1-577(A)(4)" in blocked[0]

    def test_non_sensitive_without_opt_out_permitted(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA})
        docs = [_doc("D1"), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 2


# ---------------------------------------------------------------------------
# CPAFilter tests
# ---------------------------------------------------------------------------

class TestCPAFilter:
    def setup_method(self) -> None:
        self.f = CPAFilter()

    def test_non_colorado_passes_all(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, gpc=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert blocked == []

    def test_gpc_signal_blocks_targeted_advertising(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO}, gpc=True)
        docs = [_doc("D1", is_targeted=True), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert "§6-1-1306(5)" in blocked[0]

    def test_gpc_signal_blocks_profiling(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO}, gpc=True)
        docs = [_doc("D1", is_profiling=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§6-1-1306(1)(b)" in blocked[0]

    def test_explicit_opt_out_without_gpc_also_blocks(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO}, opted_out_of_targeted_ads=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0

    def test_sensitive_data_requires_consent_colorado(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO})
        docs = [_doc("D1", pi=SensitivePICategory.FINANCIAL_ACCOUNT)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§6-1-1308(7)" in blocked[0]

    def test_sensitive_with_consent_permitted(self) -> None:
        ctx = _ctx(
            {ConsumerPrivacyState.COLORADO},
            spi_consent={SensitivePICategory.FINANCIAL_ACCOUNT: True},
        )
        docs = [_doc("D1", pi=SensitivePICategory.FINANCIAL_ACCOUNT)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1

    def test_no_gpc_no_opt_out_non_sensitive_permitted(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO})
        docs = [_doc("D1"), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 2


# ---------------------------------------------------------------------------
# CTDPAFilter tests
# ---------------------------------------------------------------------------

class TestCTDPAFilter:
    def setup_method(self) -> None:
        self.f = CTDPAFilter()

    def test_non_connecticut_passes_all(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO}, gpc=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert blocked == []

    def test_minor_blocks_targeted_advertising(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CONNECTICUT}, minor=True)
        docs = [_doc("D1", is_targeted=True), _doc("D2")]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 1
        assert "§9" in blocked[0]

    def test_minor_blocks_profiling(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CONNECTICUT}, minor=True)
        docs = [_doc("D1", is_profiling=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§9" in blocked[0]

    def test_gpc_signal_blocks_targeted_ads_connecticut(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CONNECTICUT}, gpc=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§4(a)" in blocked[0]

    def test_sensitive_requires_consent_connecticut(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CONNECTICUT})
        docs = [_doc("D1", pi=SensitivePICategory.RACIAL_ETHNIC_ORIGIN)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0
        assert "§6" in blocked[0]

    def test_opt_out_without_gpc_blocks_targeted_ads(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CONNECTICUT}, opted_out_of_targeted_ads=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, blocked = self.f.filter(docs, ctx)
        assert len(permitted) == 0


# ---------------------------------------------------------------------------
# MultiStatePrivacyPipeline tests
# ---------------------------------------------------------------------------

class TestMultiStatePrivacyPipeline:
    def setup_method(self) -> None:
        self.pipeline = MultiStatePrivacyPipeline()

    def test_single_state_california_sharing_opt_out(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA}, opted_out_of_sharing=True)
        docs = [
            _doc("D1", requires_sharing_opt_in=True),
            _doc("D2"),
        ]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D2"
        assert audit.blocked_count == 1
        assert "CCPA/CPRA" in audit.most_restrictive_law

    def test_most_restrictive_jurisdiction_union_of_blocks(self) -> None:
        # VA blocks sensitive health data; CA blocks sharing opt-out docs
        ctx = _ctx(
            {ConsumerPrivacyState.CALIFORNIA, ConsumerPrivacyState.VIRGINIA},
            opted_out_of_sharing=True,
        )
        docs = [
            _doc("D1", requires_sharing_opt_in=True),      # CA blocks
            _doc("D2", pi=SensitivePICategory.HEALTH_MEDICAL),  # VA blocks
            _doc("D3"),                                     # neither blocks
        ]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        # D1 blocked by CA, D2 blocked by VA, D3 permitted
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D3"
        assert audit.blocked_count == 2
        assert "CCPA/CPRA" in audit.per_law_blocked
        assert "VCDPA" in audit.per_law_blocked

    def test_colorado_gpc_overrides_all_targeted_ads(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.COLORADO}, gpc=True)
        docs = [_doc("D1", is_targeted=True), _doc("D2", is_profiling=True), _doc("D3")]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D3"
        assert audit.gpc_signal_honored is True

    def test_gpc_signal_not_honored_for_non_colorado_state(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.VIRGINIA}, gpc=True)
        docs = [_doc("D1", is_targeted=True)]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        # VCDPA does not mandate GPC honor (no VCDPA opt-out-of-targeted-ads from GPC)
        # Only CO (and CT from 2025) mandate GPC
        assert audit.gpc_signal_honored is False

    def test_audit_record_fields(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA, ConsumerPrivacyState.COLORADO})
        docs = [_doc("D1")]
        _, audit = self.pipeline.retrieve(docs, ctx)
        assert "CA" in audit.resident_states or "CO" in audit.resident_states
        assert len(audit.applicable_laws) == 2
        assert audit.total_candidates == 1

    def test_no_blocks_when_no_opt_outs_no_sensitive_docs(self) -> None:
        ctx = _ctx({ConsumerPrivacyState.CALIFORNIA, ConsumerPrivacyState.VIRGINIA})
        docs = [_doc("D1"), _doc("D2")]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        assert len(permitted) == 2
        assert audit.blocked_count == 0

    def test_sample_documents_scenario_a_returns_only_transactional(self) -> None:
        """Scenario A equivalent: CA CPRA sharing opt-out blocks marketing docs."""
        ctx = _ctx(
            {ConsumerPrivacyState.CALIFORNIA},
            purpose=DataProcessingPurpose.PERSONALIZATION,
            opted_out_of_sharing=True,
            opted_out_of_targeted_ads=True,
        )
        permitted, audit = self.pipeline.retrieve(SAMPLE_DOCUMENTS, ctx)
        # DOC-001, DOC-002, DOC-003, DOC-008, DOC-010 should be permitted
        permitted_ids = {d.doc_id for d in permitted}
        assert "DOC-001" in permitted_ids
        assert "DOC-002" in permitted_ids
        assert "DOC-003" in permitted_ids
        assert "DOC-004" not in permitted_ids   # sharing_opt_in required
        assert "DOC-009" not in permitted_ids   # targeted advertising

    def test_multi_state_blocks_are_union_not_intersection(self) -> None:
        """A doc blocked by ANY law must be excluded (union, not intersection)."""
        ctx = _ctx(
            {ConsumerPrivacyState.CALIFORNIA, ConsumerPrivacyState.COLORADO},
            opted_out_of_sharing=True,
            gpc=True,
        )
        docs = [
            _doc("D1", requires_sharing_opt_in=True),   # blocked only by CA
            _doc("D2", is_targeted=True),               # blocked only by CO (via GPC)
            _doc("D3"),
        ]
        permitted, audit = self.pipeline.retrieve(docs, ctx)
        assert len(permitted) == 1
        assert permitted[0].doc_id == "D3"
        assert audit.blocked_count == 2
