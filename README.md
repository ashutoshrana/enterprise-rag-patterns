# enterprise-rag-patterns

[![CI](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml/badge.svg)](https://github.com/ashutoshrana/enterprise-rag-patterns/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![Python](https://img.shields.io/pypi/pyversions/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/enterprise-rag-patterns.svg)](https://pypi.org/project/enterprise-rag-patterns/)

**Cross-industry compliance patterns for RAG pipelines — 47 regulated sector examples, 5 vector store adapters, 1722 tests.**

Defense-in-depth pre-filters that enforce regulatory requirements at the retrieval layer, before any document reaches the LLM context window.

---

## The problem this solves

Standard RAG implementations retrieve documents and pass them directly to an LLM — with no enforcement of who is allowed to see what. In regulated environments this creates a structural compliance failure: a student receives another student's financial aid record; a patient's ePHI surfaces in an unrelated clinical query; a grid operator's chatbot leaks BES Cyber System documentation to an unauthorized contractor.

This library provides the **missing compliance layer**: identity-scoped pre-filters, layered regulatory enforcement, and structured audit records. Documents that fail any compliance layer never reach the LLM.

---

## Architecture: Defense-in-Depth

```
User Query
    │
    ▼
┌─────────────────────────────────────────────────┐
│         Vector Store Retrieval (candidate docs)  │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  LAYER 1 — Identity / Access Gate               │
│  Who is the user? What are their clearances?    │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  LAYER 2 — Regulatory Domain Gate               │
│  Does this document belong to this regulation?  │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  LAYER 3 — Contextual Policy Gate               │
│  Is this access appropriate in this context?    │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  LAYER 4 — Sector-Specific Gate                 │
│  Are there additional domain requirements?      │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  Audit Record (written before LLM sees docs)    │
│  user_id · document_id · regulation_citation    │
│  layers_passed · layers_denied · timestamp      │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
                 LLM Context
```

**Why pre-filter, not post-filter?** Post-filtering is a UI concern — the LLM has already processed the unauthorized record. FERPA, HIPAA, and NERC CIP require that disclosure not occur, not that unauthorized data be hidden after the fact. See [docs/adr/001-pre-filter-not-post-filter.md](./docs/adr/001-pre-filter-not-post-filter.md).

---

## Installation

```bash
pip install enterprise-rag-patterns
```

With vector store or framework extras:

```bash
pip install 'enterprise-rag-patterns[langchain]'
pip install 'enterprise-rag-patterns[haystack]'
pip install 'enterprise-rag-patterns[llama-index]'
pip install 'enterprise-rag-patterns[pinecone]'
pip install 'enterprise-rag-patterns[weaviate]'
pip install 'enterprise-rag-patterns[qdrant]'
pip install 'enterprise-rag-patterns[chromadb]'
```

---

## Quick start

```python
from enterprise_rag_patterns.compliance import (
    StudentIdentityScope, RecordCategory,
    FERPAContextPolicy, DisclosureReason,
)

scope = StudentIdentityScope(
    student_id="stu_001",
    institution_id="univ_abc",
    requesting_user_id="advisor_007",
    authorized_categories={RecordCategory.ACADEMIC_RECORD},
    disclosure_reason=DisclosureReason.SCHOOL_OFFICIAL,
)
policy = FERPAContextPolicy(scope=scope)

# Filter before the LLM sees any document
safe_docs = policy.filter_retrieved_documents(
    retrieved_docs,
    student_id_field="student_id",
    institution_id_field="institution_id",
    category_field="category",
)

# Emit a 34 CFR §99.32 disclosure log entry
audit = policy.record_access(categories_accessed={RecordCategory.ACADEMIC_RECORD})
```

See the `examples/` directory for complete runnable pipelines.

---

## Example catalog — 47 regulated sectors

| # | File | Sector | Regulations Enforced |
|---|------|--------|---------------------|
| 01 | `01_basic_ferpa_filter.py` | Higher Education | FERPA 34 CFR §99 — StudentIdentityScope, cross-institution blocking |
| 02 | `02_multi_student_isolation.py` | Multi-Institution | FERPA §99.31 — cross-institution and cross-student isolation |
| 03 | `03_langchain_handler.py` | LangChain | FERPA + LangChain LCEL — FERPACallbackHandler |
| 04 | `04_lcel_ferpa_chain.py` | LCEL Chains | FERPA retriever integration — FERPALCELChain |
| 05 | `05_hipaa_rag_pipeline.py` | Healthcare | HIPAA 45 CFR §164.502 — PHI minimum necessary, ePHI audit |
| 06 | `06_owasp_security_scan.py` | Cybersecurity | OWASP LLM Top 10 (2025) — LLM01 injection, LLM02 PII |
| 07 | `07_soc2_cbac_pipeline.py` | Regulated SaaS | SOC 2 Type II CC6.1/C1.1 — tenant isolation, CBAC |
| 08 | `08_nist_ai_rmf_assessment.py` | AI Risk | NIST AI RMF 1.0 + AI 600-1 — MAP/MEASURE/MANAGE |
| 09 | `09_vector_store_adapters.py` | Vector Stores | Pinecone / Weaviate / Qdrant / ChromaDB compliance filters |
| 10 | `10_escalation_policy.py` | All Sectors | Escalation policy + action boundary enforcement |
| 11 | `11_context_assembly.py` | Enterprise RAG | Multi-source ContextEnvelope — CRM + ERP + KB assembly |
| 12 | `12_cross_channel_session.py` | Omnichannel | Cross-channel session continuity with compliance scope |
| 13 | `13_financial_services_rag.py` | Financial (early) | Dodd-Frank, CCAR — basic financial services filtering |
| 14 | `14_legal_sector_rag.py` | Legal (early) | Attorney-client privilege — basic privilege filter |
| 15 | `15_government_federal_rag.py` | Government (early) | FedRAMP, FISMA — basic federal filtering |
| 16 | `16_energy_utilities_rag.py` | Energy (early) | NERC CIP basics |
| 17 | `17_telecom_rag.py` | Telecommunications | CPNI 47 CFR Part 64 — customer proprietary network info |
| 18 | `18_state_consumer_privacy_rag.py` | State Privacy | CCPA/CPRA, VCDPA, CPA — multi-state privacy |
| 19 | `19_pharma_clinical_rag.py` | Pharma/Clinical | 21 CFR Part 11, ICH-GCP, GxP — regulated trial data |
| 20 | `20_real_estate_mortgage_rag.py` | Real Estate | RESPA, Fair Housing Act — mortgage record access |
| 21 | `21_energy_utilities_rag.py` | Energy (extended) | NERC CIP + FERC + multi-site |
| 22 | `22_government_contracting_rag.py` | Gov Contracting | FAR/DFARS, CUI, contractor access |
| 23 | `23_hr_employment_rag.py` | HR / Employment | EEOC, Title VII, ADA — personnel record access |
| 24 | `24_clinical_trials_rag.py` | Clinical Trials | FDA IND, IRB, HIPAA — trial data access |
| 25 | `25_digital_health_rag.py` | Digital Health | FDA SaMD + 42 CFR Part 2 + HIPAA special categories + ONC |
| 26 | `26_legal_services_rag.py` | Legal Services | ABA Rules 1.6/1.7/1.9 + FRCP Rule 26(b)(3) + State Bar Ethics |
| 27 | `27_financial_services_rag.py` | Financial Services | GLBA §§6801-6809 + SEC Reg S-P + FINRA Rule 3110 + BSA/AML |
| 28 | `28_energy_utilities_rag.py` | Energy & Utilities | NERC CIP-004/005/011/013 + FERC CEII 18 CFR §388.113 + DOE + NRC 10 CFR 73.21 |
| 29 | `29_government_public_sector_rag.py` | Government / Public Sector | FedRAMP + FISMA + NIST SP 800-53 + CUI 32 CFR Part 2002 + AU-9 |
| 30 | `30_telecom_cpni_rag.py` | Telecommunications | CPNI 47 CFR §64.2005/§64.2007, CALEA 47 USC §1002, FCC Broadband Privacy Part 64 Subpart U, CalOPPA + CCPA §1798.100 |
| 31 | `31_brazil_lgpd_rag.py` | Brazil / LGPD | LGPD Law 13.709/2018 Art. 7/11/15/18/33 — data subject access, legal basis, minimization, retention, cross-border transfer |
| 32 | `32_south_korea_rag.py` | South Korea / PIPA | PIPA Art. 15/16/23 (legal basis + sensitive data consent) + Art. 39-3 (cross-border — KR/EU/UK/CH/JP/NZ/CA adequate) + Korea AI Framework Act Art. 6 high-impact AI transparency |
| 33 | `33_insurance_naic_rag.py` | US Insurance | NAIC Model Privacy Protection Act §7/§13, FCRA §1681b(a)(3)(C) permissible purpose + §1681m(a) adverse action notice, CA CDI Bulletin 2022-5, IL IDOI AI guidance, CA Proposition 103 |
| 34 | `34_real_estate_rag.py` | US Real Estate | Fair Housing Act 42 U.S.C. §3604 + HUD regulations, ECOA 15 U.S.C. §1691 / Regulation B, Dodd-Frank §1472 (appraisal independence) + USPAP, CA Civil Code §1940.2, NY RPL §462, TX Property Code §5.008 |
| 35 | `35_southeast_asia_rag.py` | Southeast Asia | Thailand PDPA B.E. 2562 (§19/§20/§24/§30), Indonesia UU PDP No. 27/2022 (Art. 16/20/34), Vietnam Cybersecurity Law No. 24/2018 + Decree 13/2023 (Art. 5/8), ASEAN cross-border adequacy (TH/ID/VN/SG/MY/PH) |
| 36 | `36_latin_america_rag.py` | Latin America | Argentina LPDP 25.326 (Art. 5/7/12), Chile Law 19.628 (Art. 2(g)/4) + Law 21.719 Art. 16 (automated decisions), Colombia Law 1581/2012 (Art. 4(c)/7) + Decree 1377/2013 Art. 10, Ibero-American Data Protection Network cross-border adequacy (AR/CL/CO/MX/PE/UY/BR) |
| 37 | `37_canada_pipeda_rag.py` | Canada | PIPEDA Principles 3/4.3 + CPPA Bill C-27 §15/§62, Quebec Law 25 §8/§12.1/§63.3, Ontario PHIPA + BC PIPA §11, OPC cross-border adequacy + contractual safeguards + Quebec PIA |
| 38 | `38_telecommunications_rag.py` | US Telecom | FCC CPNI 47 U.S.C. §222 (billing/repair/support restriction + third-party opt-in), TCPA 47 U.S.C. §227 (autodialer/SMS consent + DNC Registry + 8AM-9PM rule), CALEA 47 U.S.C. §§1001-1010 (court order requirement + pen register), Section 214 + CLOUD Act cross-border (OFAC sanctions: CN/RU/IR/KP) |
| 39 | `39_us_state_privacy_rag.py` | US State Privacy | Colorado CPA CRS §6-1-1301 (sensitive data consent + profiling opt-out + sale opt-out), Virginia CDPA Va. Code §59.1-571 (sensitive opt-in + automated decision + targeted advertising), Texas TDPSA Tex. Bus. & Com. Code §541 (sensitive data + sale opt-out + minor data), CTDPA/CPA/VCDPA/TDPSA/CCPA multi-state cross-border applicability |
| 40 | `40_financial_services_rag.py` | US Financial Services | Dodd-Frank §728 (swap data regulatory authorization) + §619 Volcker Rule (12 CFR §248 compliance program), SEC Regulation S-P 17 CFR §248 (NPI privacy notice + opt-out + cyber disclosure 8-K), FINRA Rules 4370/2210/3110 (BCP filing + principal approval + supervisory procedures), FATCA 26 U.S.C. §1471 + FinCEN SAR 31 CFR §1010.320 + OFAC sanctions cross-border |
| 41 | `41_healthcare_ai_fda_rag.py` | US Healthcare AI / FDA | FDA SaMD 21 CFR §814 (PMA Class III) + §807.87 (510(k) Class II) + AI/ML Action Plan 2021 (PCCP adaptive algorithms) + 21 CFR Part 820 (QMS design controls), ONC 21st Century Cures Act 45 CFR §170 (EHR information blocking + FHIR API access) + §171 (information blocking exceptions + patient access), CMS Final Rule 85 FR 25510 (payer coverage AI + value-based care) + 88 FR 82510 (prior authorization decision support), HIPAA 45 CFR §164 (PHI cross-border) + EU Health Data Space Regulation 2024 + GDPR Art. 46 SCC |
| 42 | `42_iot_ot_security_rag.py` | IoT/OT Cybersecurity | NIST SP 800-213 §3.1 (device identity management) + §3.3 (configuration management) + §3.5 (logical access controls) + §3.6 (data protection in transit), IEC 62443-3-3 SL-C(1) (OT security level assessment) + IEC 62443-3-2 §4.3 (zone and conduit model) + IEC 62443-2-4 §SP.04.01 (remote access defense-in-depth) + IEC 62443-2-3 §5.2 (patch management), TSA Pipeline-2021-02C §I (incident reporting) + TSA SD 1580/82-2022-01 §E.2 (network segmentation) + §B (cybersecurity coordinator) + CISA CPG v2.0 OT controls, EAR ECCN 5E002 export controls (15 CFR §774) + CFIUS 50 U.S.C. §4565 + OFAC sanctions (RU/IR/KP/CU/SY) + EU NIS2 Art. 26 (essential entity cross-border notification) |
| 43 | `43_energy_nerc_cip_rag.py` | Energy / Utilities / NERC CIP | NERC CIP-007-6 (BES Cyber System security management: ports/services + patches + malicious code), CIP-005-7 (Electronic Security Perimeter access controls + remote access), CIP-006-6 (Physical Security Plans for BES Cyber Systems), CIP-008-6 (incident reporting to E-ISAC within 1 hour), FERC Order 888/889 OASIS (Open Access Transmission Tariff), 18 CFR §1c.2 Anti-Manipulation Rule, NGA §7 gas pipeline certificate, Part 12 dam safety, DOE 100-Day Plan OT monitoring, CISA ICS-CERT baseline, NIST AI RMF energy sector profile, DOE CESER/E-ISAC/CRISP, FPA §202(e) FERC export authorization, EO 13873/DOE ICTS adversarial nations (CN/RU/KP/IR), NGA §3 LNG authorization, EU NIS2 Art. 21 |
| 44 | `44_defense_itar_ear_rag.py` | Defense / Aerospace / Export Controls | ITAR 22 CFR Parts 120-130 (USML technical data §120.6/§120.10 + defense services §120.9/§123.1 DSP-5 + electronic transmission §125.4 + classified data §120.11/NISPOM), EAR 15 CFR Parts 730-774 (CCL Military End Use §744.21 CN/RU/VE/MM/BY + Entity List §744.11 + Semiconductor §744.23 Oct 2023 rule + Huawei FDPR §734.9), CFIUS 50 U.S.C. §4565 + 31 CFR Part 800 (defense contractor acquisition + TID US Business CN/RU/KP + sensitive gov contract data + minority TID §800.401 mandatory declaration), NATO MC 0049/15 classified + UKUSA/FVEY bilateral protocols + NSPM-33 adversarial nations (CN/RU/KP/IR/CU/SY) + DoDD 5230.11 foreign disclosure |
| 45 | `45_pharma_clinical_trials_rag.py` | Pharma / Clinical Trials | FDA IND 21 CFR Part 312 + NDA 21 CFR Part 314 + BLA 21 CFR Part 601 + CGMP 21 CFR Parts 210/211 (FDADrugDevelopmentFilter), ICH E6 R2/R3 GCP IRB/IEC approval §3.1/21 CFR Part 56 + informed consent §4.8.10 + investigator qualifications §4.1 + SAE 15-day reporting §4.11.1/21 CFR §312.32 (ICHGCPFilter), EU CTR 536/2014 + EMA Pediatric Regulation 1901/2006 PIP + Regulation 726/2004 centralized procedure + GDPR Art. 9(2)(j) research exception (EMARegulationsFilter), ICH E6 §5.15 + GDPR Art. 46 SCC cross-border trial data + FDA Import Alert 66-40/66-66 + DEA Schedules 21 U.S.C. §812 + FDA/EMA parallel biosimilar review (PharmaCrossBorderFilter) |
| 46 | `46_nuclear_nrc_rag.py` | Nuclear Energy / NRC Compliance | 10 CFR Part 50 reactor operating license + Part 70 special nuclear material + Part 71 package certification (NRCLicensingFilter), 10 CFR §20.1201 occupational 5 rem/year + §20.1301 public 100 mrem/year + §20.1101 ALARA + Appendix B effluents (NRCRadiationProtectionFilter), 42 U.S.C. §2162 Restricted Data Q-clearance + FRD L-clearance + 10 CFR §73.21 Safeguards Info + SUNSI need-to-know (NDAClassifiedFilter), 10 CFR Part 110 export license + NPT Art. III IAEA safeguards + 42 U.S.C. §2153 123 Agreement CN/RU/KP/IR + NRC sensitive country dual-use review (NuclearCrossBorderFilter) |
| 47 | `47_maritime_imo_rag.py` | Maritime / Shipping / IMO | SOLAS Chapter I Safety Certificate + ISM Code DOC/SMC + Chapter III LSA (IMOSafetyFilter), MARPOL Annex I IOPP + Oil Record Book Reg.17 + Annex VI Tier III NOx ECA post-2016 + sulfur 0.5% m/m (MARPOLFilter), ISPS ISSC + Ship Security Plan flag-state approval + Port Facility PFSP + Security Level 3 coastal comms (ISPSFilter), Paris/Tokyo MOU PSC deficient ports + OFAC SDN flag state KP/IR/SY/CU + OFAC crew nationality + CBP 96-hour NOA (MaritimeCrossBorderFilter) |

---

## Regulation coverage matrix

| Regulation | Citation | Sector | Example |
|------------|----------|--------|---------|
| FERPA | 34 CFR Part 99 | Higher Education | 01–04 |
| HIPAA | 45 CFR §§164.312, 164.502 | Healthcare | 05, 24, 25 |
| OWASP LLM Top 10 (2025) | LLM01–LLM10 | All sectors | 06 |
| SOC 2 Type II | CC6.1/CC6.6/C1.1/CC7.2 | SaaS | 07 |
| NIST AI RMF 1.0 | AI 600-1 GenAI Profile | All sectors | 08 |
| ISO/IEC 27001:2022 | Annex A.5.12/A.5.15/A.8.2 | Enterprise | 07–08 |
| CCPA / CPRA | Cal. Civ. Code §1798 | Consumer | 18 |
| VCDPA, CPA | State privacy laws | Consumer | 18 |
| 21 CFR Part 11 | FDA GxP e-records | Pharma | 19, 24 |
| Fair Housing Act | 42 USC §3604 | Real Estate | 20 |
| EEOC / Title VII / ADA | 42 USC §2000e | HR | 23 |
| FDA SaMD | AI/ML Action Plan | Digital Health | 25 |
| 42 CFR Part 2 | SUDs records | Digital Health | 25 |
| ONC Interoperability | 21st Cen. Cures Act | Digital Health | 25 |
| ABA Model Rules | 1.6/1.7/1.9 | Legal Services | 26 |
| FRCP Rule 26(b)(3) | Work product doctrine | Legal Services | 26 |
| GLBA Title V | 15 USC §§6801–6809 | Financial | 27 |
| SEC Regulation S-P | 17 CFR Part 248 | Financial | 27 |
| FINRA Rule 3110 | Written supervisory procedures | Financial | 27 |
| BSA / AML | 31 USC §5318(g)(2) | Financial | 27 |
| NERC CIP | CIP-004/005/011/013 | Energy | 28 |
| FERC CEII | 18 CFR §388.113 | Energy | 28 |
| NRC 10 CFR 73.21 | SGI tipping-off prohibition | Nuclear | 28 |
| FedRAMP | HIGH/MODERATE/LOW | Government | 29 |
| FISMA | 44 USC §3541 | Government | 29 |
| NIST SP 800-53 Rev. 5 | AC-3/AC-4/PS-3/AU-9 | Government | 29 |
| CUI 32 CFR Part 2002 | FOUO/LES/Privacy Act/EAR | Government | 29 |
| Privacy Act | 5 USC §552a | Government | 29 |
| CPNI | 47 CFR Part 64 §§64.2005/64.2007/64.2009 | Telecom | 30 |
| CALEA | 47 USC §1002 | Telecom | 30 |
| LGPD | Law 13.709/2018 Art. 7/11/15/18/33 | Brazil | 31 |
| PIPA | Personal Information Protection Act (Korea) | South Korea | 32 |
| Korea AI Framework Act | Art. 6 high-impact AI transparency | South Korea | 32 |
| NAIC Model Privacy Protection Act | §7/§13 insurance privacy | Insurance | 33 |
| FCRA §1681b | Insurance permissible purpose | Insurance | 33 |
| FCRA §1681m | Adverse action notice | Insurance | 33 |

---

## Framework and vector store integrations

| Integration | Class | Install |
|-------------|-------|---------|
| LangChain | `FERPAComplianceCallbackHandler` | `[langchain]` |
| LlamaIndex | `FERPANodePostprocessor` | `[llama-index]` |
| Haystack 2.x | `FERPAHaystackFilter` | `[haystack]` |
| Pinecone | `PineconeComplianceFilter` | `[pinecone]` |
| Weaviate | `WeaviateComplianceFilter` | `[weaviate]` |
| Qdrant | `QdrantComplianceFilter` | `[qdrant]` |
| ChromaDB | `ChromaComplianceFilter` | `[chromadb]` |
| Microsoft Agent Framework | `FERPAAgentMiddleware` | `[maf]` |

---

## Repository structure

```
src/enterprise_rag_patterns/
├── compliance.py               # FERPA identity scoping + 34 CFR §99.32 audit
├── context.py                  # Multi-source ContextEnvelope assembly
├── session.py                  # Cross-channel session continuity
├── policy.py                   # Escalation + action-boundary policy objects
├── async_compliance.py         # Async wrappers (asyncio / FastAPI)
├── regulations/
│   ├── gdpr.py                 # GDPR Article 17 right-to-erasure
│   ├── hipaa.py                # HIPAA ePHI minimum-necessary + audit
│   ├── iso27001.py             # ISO/IEC 27001:2022 ISMS CBAC
│   ├── nist_ai_rmf.py          # NIST AI RMF 1.0 + AI 600-1
│   ├── owasp_llm.py            # OWASP LLM Top 10 (2025) LLM01/LLM02
│   ├── pci_dss.py              # PCI DSS v4.0 CHD/PAN masking
│   └── soc2.py                 # SOC 2 Type II CC6.1/CC6.6/C1.1
├── vector_stores/
│   ├── pinecone_adapter.py
│   ├── weaviate_adapter.py
│   ├── qdrant_adapter.py
│   └── chroma_adapter.py
└── integrations/
    ├── langchain.py
    ├── langchain_lcel.py
    ├── llama_index.py
    ├── haystack.py
    └── maf.py
examples/                       # 30 runnable sector examples (see catalog above)
tests/                          # 924 passing tests (2 skipped)
docs/
├── architecture.md
├── adr/                        # Architecture Decision Records
│   ├── 001-pre-filter-not-post-filter.md
│   └── 002-two-layer-enforcement.md
└── implementation-note-*.md
```

---

## Published notes and articles

- [Implementation Note 01](./docs/implementation-note-01.md) — Cross-channel continuity and compliance scope
- [Implementation Note 02](./docs/implementation-note-02.md) — FERPA boundaries in retrieval-augmented generation
- [ADR 001](./docs/adr/001-pre-filter-not-post-filter.md) — Why pre-filter, not post-filter
- [ADR 002](./docs/adr/002-two-layer-enforcement.md) — Two-layer enforcement: vector store + policy

---

## Near-term roadmap

- `33_india_pipa_rag.py` — DPDP Act 2023 + MEITY AI Advisory (RAG pre-filter pattern)
- `34_middle_east_rag.py` — UAE PDPL + Saudi NDMO + Qatar PDPL
- `35_insurance_naic_rag.py` — NAIC Model Law + FCRA §615 + state insurance data
- Async vector store adapters for FastAPI/asyncio
- PyPI download and star count badges

---

## Contributing

Read [CONTRIBUTING.md](./CONTRIBUTING.md) and [GOVERNANCE.md](./GOVERNANCE.md). Run `pytest tests/ -v` before opening a pull request.

---

## Citation

```bibtex
@software{rana2026erp,
  author  = {Rana, Ashutosh},
  title   = {enterprise-rag-patterns: Cross-industry compliance patterns for RAG pipelines},
  year    = {2026},
  version = {0.36.0},
  url     = {https://github.com/ashutoshrana/enterprise-rag-patterns},
  license = {MIT}
}
```

---

## Part of the enterprise AI patterns trilogy

| Library | Focus | Coverage |
|---------|-------|---------|
| **enterprise-rag-patterns** | What to retrieve | 47 sectors · 64 regulations · 1722 tests |
| [regulated-ai-governance](https://github.com/ashutoshrana/regulated-ai-governance) | What agents may do | 38 governance examples · 25 jurisdictions · 2451 tests |
| [integration-automation-patterns](https://github.com/ashutoshrana/integration-automation-patterns) | How data flows | 40 patterns · schema registry · GraphQL · 1780 tests |

---

## License

MIT — see [LICENSE](LICENSE).
