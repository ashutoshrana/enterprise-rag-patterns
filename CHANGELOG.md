# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.42.0] — 2026-04-13

### Added — Nuclear Energy / NRC Compliance RAG Pre-filter (`46_nuclear_nrc_rag.py`)

Four-layer retrieval access control for US nuclear energy and non-proliferation compliance:

- `NRCLicensingFilter` (10 CFR Parts 50/70/71) — reactor without Part 50 operating license → DENIED; nuclear fuel facility without Part 70 SNM license → DENIED; radioactive material transport without Part 71 package cert → DENIED; research reactor license type → REQUIRES_HUMAN_REVIEW
- `NRCRadiationProtectionFilter` (10 CFR Part 20) — occupational dose exceeding 5 rem/year §20.1201 → DENIED; public dose exceeding 100 mrem/year §20.1301 → DENIED; ALARA program not documented §20.1101 → DENIED; Appendix B effluent limits → REQUIRES_HUMAN_REVIEW
- `NDAClassifiedFilter` (42 U.S.C. §2162 + 10 CFR §73.21) — Restricted Data without Q clearance → DENIED; Formerly Restricted Data without L clearance → DENIED; Safeguards information without authorized access → DENIED; SUNSI without need-to-know → REQUIRES_HUMAN_REVIEW
- `NuclearCrossBorderFilter` (10 CFR Part 110 + 42 U.S.C. §2153) — nuclear tech export to non-NPT country without export license → DENIED; fissile material without IAEA safeguards (NPT Art. III) → DENIED; nuclear cooperation with CN/RU/KP/IR without 123 Agreement → DENIED; dual-use items to NRC sensitive countries → REQUIRES_HUMAN_REVIEW

56 new tests. Total: **1668 passed, 2 skipped**.

---

## [0.41.0] — 2026-04-13

### Added — Pharma / Clinical Trials RAG Pre-filter (`45_pharma_clinical_trials_rag.py`)

Four-layer retrieval access control for pharmaceutical drug development and clinical trial compliance:

- `FDADrugDevelopmentFilter` (21 CFR Parts 312/314/601/210/211) — IND non-compliance → DENIED (Part 312); NDA non-compliance → DENIED (Part 314); BLA non-compliance → DENIED (Part 601); CGMP unverified → REQUIRES_HUMAN_REVIEW (Parts 210/211)
- `ICHGCPFilter` (ICH E6 R2/R3) — no IRB/IEC approval → DENIED (E6 §3.1 + 21 CFR Part 56); incomplete informed consent elements → DENIED (E6 §4.8.10); unqualified investigator → DENIED (E6 §4.1); SAE without 15-day expedited reporting → REQUIRES_HUMAN_REVIEW (E6 §4.11.1 + 21 CFR §312.32)
- `EMARegulationsFilter` (EU CTR 536/2014 + EMA Pediatric Regulation 1901/2006 + Regulation 726/2004 + GDPR) — no EU CTR authorization → DENIED; no PIP compliance → DENIED (Art. 7); EU MAA without centralized procedure → DENIED (Art. 3); GDPR Art. 9 health data without Art. 9(2)(j) research safeguards → REQUIRES_HUMAN_REVIEW
- `PharmaCrossBorderFilter` — cross-border trial data without ICH E6 §5.15 DTA + GDPR Art. 46 SCC → DENIED; manufacturing from FDA import-alert country without review → DENIED (Import Alert 66-40/66-66); controlled substance to non-DEA-compliant jurisdiction → DENIED (21 U.S.C. §812); biosimilar without FDA/EMA parallel review → REQUIRES_HUMAN_REVIEW

64 new tests. Total: **1612 passed, 2 skipped**.

---

## [0.40.0] — 2026-04-13

### Added — Defense / Aerospace / Export Controls RAG Pre-filter (`44_defense_itar_ear_rag.py`)

Four-layer retrieval access control for US defense and export compliance:

- `ITARFilter` (22 CFR Parts 120-130) — USML technical data without export license → DENIED (§120.6/§120.10); defense services to foreign persons without DSP-5 → DENIED (§120.9/§123.1); controlled electronic transmission without §125.4 exemption → DENIED; classified defense data without NISPOM markings → REQUIRES_HUMAN_REVIEW
- `EARFilter` (15 CFR Parts 730-774) — CCL MEU items to CN/RU/VE/MM/BY without BIS license → DENIED (§744.21); Entity List recipient without authorization → DENIED (§744.11); semiconductor export to CN/RU/KP without §744.23 license → DENIED (Oct 2023 rule); Huawei FDPR without compliance review → REQUIRES_HUMAN_REVIEW (§734.9)
- `CFIUSDefenseFilter` (50 U.S.C. §4565 + 31 CFR Part 800) — defense contractor acquisition without CFIUS → DENIED; TID US Business with CN/RU/KP entity without clearance → DENIED; sensitive gov contract data access → DENIED; minority TID investment without mandatory declaration → REQUIRES_HUMAN_REVIEW (§800.401)
- `DefenseCrossBorderFilter` — NATO classified without clearance+need-to-know → DENIED (MC 0049/15); FVEY data to non-FVEY without bilateral agreement → DENIED; defense industrial base data to CN/RU/KP/IR/CU/SY → DENIED (NSPM-33); joint military tech dev without foreign disclosure → REQUIRES_HUMAN_REVIEW (DoDD 5230.11)

56 new tests. Total: **1548 passed, 2 skipped**.

---

## [0.39.0] — 2026-04-13

### Added — Energy / Utilities / NERC CIP RAG Pre-filter (`43_energy_nerc_cip_rag.py`)

Four-layer retrieval access control for energy sector and bulk electric system compliance:

- `NERCCIPFilter` — CIP-007-6 BES Cyber System security management (ports/patches/malicious code) → DENIED; CIP-005-7 ESP access controls → DENIED; CIP-006-6 Physical Security Plans → DENIED; CIP-008-6 E-ISAC 1-hour incident reporting → REQUIRES_HUMAN_REVIEW
- `FERCEnergyFilter` — Order 888/889 OASIS compliance → DENIED; Anti-Manipulation 18 CFR §1c.2 → DENIED; NGA §7 gas pipeline certificate → DENIED; Part 12 dam safety review → REQUIRES_HUMAN_REVIEW
- `DOECybersecurityFilter` — DOE 100-Day Plan OT monitoring → DENIED; CISA ICS-CERT baseline → DENIED; NIST AI RMF energy sector profile → DENIED; DOE CESER/E-ISAC/CRISP threat sharing → REQUIRES_HUMAN_REVIEW
- `EnergyCrossBorderFilter` — FPA §202(e) non-NAFTA electricity export → DENIED; EO 13873/DOE ICTS adversarial nations (CN/RU/KP/IR) → DENIED; NGA §3 LNG export authorization → DENIED; EU NIS2 Art. 21 essential entity → REQUIRES_HUMAN_REVIEW

54 new tests. Total: **1492 passed, 2 skipped**.

---

## [0.38.0] — 2026-04-13

### Added — IoT/OT Cybersecurity RAG Pre-filter (`42_iot_ot_security_rag.py`)

Four-layer retrieval access control for IoT/OT security compliance:

- `NISTIoTFilter` (NIST SP 800-213) — IoT without device identity management → DENIED (§3.1); without configuration management → DENIED (§3.3); critical IoT without network access controls → DENIED (§3.5); data without cryptographic protection → REQUIRES_HUMAN_REVIEW (§3.6)
- `IEC62443OTFilter` (IEC 62443 IACS) — OT/SCADA without Security Level assessment → DENIED (62443-3-3 SL-C(1)); no zone/conduit model → DENIED (62443-3-2 §4.3); remote access without defense-in-depth → DENIED (62443-2-4 §SP.04.01); no patch management plan → REQUIRES_HUMAN_REVIEW (62443-2-3 §5.2)
- `TSAOTSecurityFilter` (TSA Security Directives) — critical pipeline without incident reporting → DENIED (Pipeline-2021-02C §I); aviation OT without IT/OT segmentation → DENIED (SD 1580/82-2022-01 §E.2); rail without cybersecurity coordinator → DENIED (§B); critical infrastructure without CISA CPG v2.0 goals → REQUIRES_HUMAN_REVIEW
- `OTCrossBorderFilter` — OFAC sanctioned jurisdictions (RU/IR/KP/CU/SY) → DENIED; ECCN 5E002 export without EAR license → DENIED (15 CFR §774); OT data to CN without CFIUS review → DENIED (50 U.S.C. §4565); NIS2 essential entity without NCA notification → REQUIRES_HUMAN_REVIEW (Directive 2022/2555 Art. 26)

52 new tests. Total: **1438 passed, 2 skipped**.

---

## [0.37.0] — 2026-04-13

### Added — US Healthcare AI / FDA RAG Pre-filter (`41_healthcare_ai_fda_rag.py`)

Four-layer retrieval access control for AI platforms subject to US healthcare regulations governing Software as a Medical Device, EHR interoperability, CMS payer rules, and cross-border PHI transfers:

- `FDASaMDFilter` (21 CFR §814/§807.87/Part 820 + AI/ML Action Plan 2021) — Class III SaMD without PMA → DENIED; Class II SaMD without 510(k) → DENIED; AI/ML SaMD without PCCP → REQUIRES_HUMAN_REVIEW; SaMD without QMS → DENIED
- `ONCInteroperabilityFilter` (45 CFR §170/§171 + ONC Cures Act Final Rule) — Information blocking EHR data → DENIED; FHIR R4 API access without ONC certification → DENIED; patient access without ONC compliant mechanism → DENIED; non-certified health IT software → REQUIRES_HUMAN_REVIEW
- `CMSPriorAuthFilter` (CMS Final Rule 85 FR 25510 + 88 FR 82510) — CMS payer AI coverage determination without human review → DENIED; Medicare Advantage AI without coverage criteria disclosure → DENIED; prior authorization decision support without 72-hour expedited pathway → DENIED; value-based care AI without quality measure alignment → REQUIRES_HUMAN_REVIEW
- `HealthcareCrossBorderFilter` (HIPAA 45 CFR §164 + EU Health Data Space Regulation 2024 + GDPR Art. 46) — PHI to non-HIPAA jurisdiction → DENIED; EU-US health data without EHDS adequacy → DENIED; PHI to OFAC sanctioned jurisdiction → DENIED; GDPR Art. 46 SCC for health data → REQUIRES_HUMAN_REVIEW

55 new tests. Total: **1386 passed, 2 skipped**.

---

## [0.36.0] — 2026-04-13

### Added — US Financial Services RAG Pre-filter (`40_financial_services_rag.py`)

Four-layer retrieval access control for US financial services regulatory compliance:

- `DoddFrankFilter` (12 U.S.C. §5301) — swap data without regulatory authorization → DENIED (§728/17 CFR Part 49); FSOC-designated institutions without enhanced oversight docs → REQUIRES_HUMAN_REVIEW (§113); Volcker Rule proprietary trading without compliance program → DENIED (§619/12 CFR §248)
- `SECRegulationSPFilter` (17 CFR Part 248) — NPI without privacy notice → DENIED (§248.4); NPI without opt-out opportunity → DENIED (§248.7); material cybersecurity incident without 4-day 8-K disclosure → REQUIRES_HUMAN_REVIEW (§229.106)
- `FINRAComplianceFilter` (Rules 4370/2210/3110) — customer communication without principal approval → DENIED (Rule 2210(b)(1)); order data without supervision → REQUIRES_HUMAN_REVIEW (Rule 3110); no BCP filed with FINRA → DENIED (Rule 4370)
- `FinancialServicesCrossBorderFilter` — FATCA Form 8938/FBAR → DENIED (26 U.S.C. §1471); SAR within 30 days → DENIED (31 CFR §1010.320); OFAC sanctioned jurisdictions (RU/IR/KP/CU/SY) → DENIED; EU DORA + GDPR Art. 46 SCC required → REQUIRES_HUMAN_REVIEW

52 new tests. Total: **1331 passed, 2 skipped**.

---

## [0.35.0] — 2026-04-13

### Added — US State Privacy Laws RAG Pre-filter (`39_us_state_privacy_rag.py`)

Four-layer retrieval access control for platforms subject to US state consumer privacy laws:

- `ColoradoCPAFilter` (CRS §6-1-1301 et seq.) — sensitive data (biometric/health/precise geolocation/racial origin/sexual orientation) → DENIED (§6-1-1303(19)); automated profiling without opt-out → REQUIRES_HUMAN_REVIEW (§6-1-1306(1)(a)(IV)); sale without opt-out → DENIED (§6-1-1306(1)(a)(III))
- `VirginiaVCDPAFilter` (Va. Code §59.1-571 et seq.) — sensitive data opt-in requirement (§59.1-578(A)); automated decision with legal effect without opt-out → REQUIRES_HUMAN_REVIEW (§59.1-579); targeted advertising on sensitive data → DENIED (§59.1-578(B))
- `TexasTDPSAFilter` (Tex. Bus. & Com. Code §541) — sensitive data consent (§541.101); sale opt-out (§541.052); minor data (under-13 and under-18 tiers) → DENIED
- `USStatePrivacyCrossBorderFilter` — multi-state applicability matrix for CCPA/CPA/VCDPA/TDPSA/CTDPA; state-specific DENIED/REVIEW outcomes based on `destination_state`

50 new tests. Total: **1315 passed, 2 skipped**.

---

## [0.34.0] — 2026-04-13

### Added — FilterPipeline and public API foundation

- `src/enterprise_rag_patterns/pipeline.py` — `FilterPipeline` (chains filter callables, short-circuits on DENIED, optional `stop_on_requires_review`) + `PipelineResult` dataclass with `is_approved`/`passed_all_filters`/`filter_batch`/`approved_only`
- `src/enterprise_rag_patterns/py.typed` — PEP 561 type marker; package now ships annotations
- `__init__.py` — `__version__ = "0.34.0"`, exports `FilterPipeline`, `PipelineResult`, `__all__`
- `pyproject.toml` — `[tool.setuptools.package-data]` declares `py.typed`
- `.claude/skills/add-rag-filter.md` — Claude Code skill encoding conventions for adding new filter examples

32 new tests. Total: **1265 passed, 2 skipped**.

---

## [0.33.0] — 2026-04-13

### Added — US Telecommunications Regulatory RAG Pre-filter (`38_telecommunications_rag.py`)

FCC, TCPA, CALEA, and Section 214 cross-border controls as a four-layer RAG pre-filter:

- `FCCCPNIFilter` (47 U.S.C. §222; 47 CFR Part 64 Subpart U) — CPNI restricted to billing/repair/support without opt-in (§222(c)(1)); third-party sharing → DENIED; marketing use → REQUIRES_HUMAN_REVIEW (§222(c)(3))
- `TCPAComplianceFilter` (47 U.S.C. §227; 47 CFR Part 64 Subpart L) — autodialer/SMS without prior express consent → DENIED (§227(b)(1)(A)); DNC Registry → DENIED (§227(c)(5)); calls outside 8 AM–9 PM → DENIED (47 CFR §64.1200(c)(1))
- `CALEAWiretapFilter` (47 U.S.C. §§1001-1010) — content/call-record intercept without court order → DENIED (18 U.S.C. §2511); pen register without order → DENIED (18 U.S.C. §3121); non-CALEA-certified carrier → REQUIRES_HUMAN_REVIEW
- `TelecoCrossBorderFilter` — CN/RU/IR/KP routing → DENIED (FCC 21-114 + OFAC); lawful-intercept data export → DENIED (CALEA §1004); no Section 214 license → REQUIRES_HUMAN_REVIEW (47 U.S.C. §214)

40 new tests. Total: **1233 passed, 2 skipped**.

---

## [0.32.0] — 2026-04-13

### Added — Canada PIPEDA/Quebec Law 25 RAG Pre-filter (`37_canada_pipeda_rag.py`)

Canada federal and provincial privacy laws as a four-layer RAG pre-filter:

- `PIPEDAConsentFilter` (PIPEDA S.C. 2000, c. 5) — personal info without consent → DENIED (Sch. 1 Principle 3); sensitive data without explicit consent → DENIED (Principle 3.3); cross-border transfer without safeguards → DENIED (Principle 4.1.3)
- `QuebecLaw25Filter` (Law 25 / Bill 64, 2021) — profiling without consent → DENIED (§9); automated decision without transparency → REQUIRES_HUMAN_REVIEW (§12.1); data outside Quebec without equivalent protection → DENIED (§17)
- `HealthcarePrivacyFilter` (PHIPA O. Reg. 329/04, HIA RSA 2000, FOIPPA RSBC 1996) — patient data to non-covered entity → DENIED; secondary use without consent → DENIED; mental health/substance use without explicit consent → DENIED
- `CanadaCrossBorderFilter` — EU adequacy confirmed; provincial health data restrictions; US transfers requiring contractual safeguards; Five Eyes derogation for intelligence

48 new tests. Total: **1193 passed, 2 skipped**.

---

## [0.31.0] — 2026-04-13

### Added — Latin America RAG Pre-filter (`36_latin_america_rag.py`)

Argentina, Chile, and Colombia data protection laws as a four-layer RAG pre-filter:

- `ArgentinaPersonalDataFilter` (LPDP 25.326) — sensitive data without written consent → DENIED (Art. 7); no consent/basis → DENIED (Art. 5); minor without parental auth → DENIED (Art. 12)
- `ChilePersonalDataFilter` (Law 19.628 + Law 21.719) — sensitive data without consent → DENIED; automated decisions without human review → REQUIRES_HUMAN_REVIEW (Law 21.719 Art. 16)
- `ColombiaHabeasDataFilter` (Law 1581/2012 + Decree 1377/2013) — sensitive data → DENIED (Art. 7); no consent → DENIED (Art. 4(c)); financial data without consent → DENIED (Decree 1377 Art. 10)
- `LatAmCrossBorderFilter` — Ibero-American Data Protection Network adequacy (AR/CL/CO/MX/PE/UY/BR); jurisdiction-specific denials

38 new tests. Total: **1145 passed, 2 skipped**.

---


## [0.30.0] — 2026-04-13

### Added — Southeast Asia RAG Pre-filter (`35_southeast_asia_rag.py`)

Thailand, Indonesia, and Vietnam data protection laws as a four-layer RAG pre-filter:

- `ThailandPDPAFilter` (PDPA B.E. 2562) — sensitive data without consent → DENIED (§19); collection without basis → DENIED (§24); minor without parental consent → DENIED (§20); data subject self-access bypass
- `IndonesiaPDPFilter` (UU PDP No. 27/2022) — sensitive data without consent → DENIED (Art. 20); no legal basis → DENIED (Art. 16); automated decision without human review → REQUIRES_HUMAN_REVIEW (Art. 34)
- `VietnamCybersecurityFilter` (Cybersecurity Law + Decree 13/2023) — sensitive data → DENIED (Art. 8); no consent → DENIED (Art. 5); regulator bypass
- `SEAsiaCrossBorderFilter` — ASEAN adequate jurisdictions (TH/ID/VN/SG/MY/PH); no safeguards → DENIED with jurisdiction-specific citation
- `SEAsiaRAGPipeline` + `SEAsiaAuditRecord`

38 new tests. Total: **1107 passed, 2 skipped**.

---


## [0.29.0] — 2026-04-13

### Added — US Real Estate / Proptech RAG Pre-filter (`34_real_estate_rag.py`)

US real estate sector compliance as a four-layer RAG retrieval pre-filter:

- `FairHousingActFilter` (42 U.S.C. §3604 + HUD) — protected class data blocked for buyer/seller roles; training requirement for agent access; regulator/lender bypass
- `ECOALendingFilter` (15 U.S.C. §1691 / Regulation B) — credit decisions without ECOA notice → DENIED; lender adverse action without written notice → REQUIRES_HUMAN_REVIEW
- `AppraisalIndependenceFilter` (Dodd-Frank §1472 + USPAP) — AVM for purchase → REQUIRES_HUMAN_REVIEW; lender appraisal without borrower disclosure → DENIED
- `StateRealEstateLawFilter` — CA Civil Code §1940.2 (rental disclosure), NY RPL §462 (purchase disclosure → DENIED), TX Property Code §5.008 (seller disclosure)
- `RealEstateRAGPipeline` + `RealEstateAuditRecord`

36 new tests. Total: **1069 passed, 2 skipped**.

---


## [0.28.0] — 2026-04-13

### Added — US Insurance NAIC/FCRA RAG Pre-filter (`33_insurance_naic_rag.py`)

US insurance sector compliance as a four-layer RAG retrieval pre-filter:

- `NAICModelActFilter` (NAIC Model Privacy Protection Act §7/§13 + state AI bulletins) — consumer own-file → APPROVED; regulator exam request → APPROVED; consumer blocked from underwriting data; unregistered AI model in CA/CO/IL → REQUIRES_HUMAN_REVIEW
- `FCRAInsuranceFilter` (FCRA 15 U.S.C. §1681) — credit score adverse action without notice → DENIED (§1681m); unauthorized permissible purpose → DENIED (§1681b(a)(3)(C))
- `StateInsuranceAIFilter` (CA CDI Bulletin 2022-5, IL IDOI 2021-9, CA Prop 103) — unregistered AI in CA → REQUIRES_HUMAN_REVIEW; credit scoring under Prop 103 → REQUIRES_HUMAN_REVIEW
- `InsuranceLoBFilter` — line-of-business authorization + actuarial data access control
- Regulator-override: regulatory exam role bypasses consumer-restriction layers

36 new tests. Total: **1033 passed, 2 skipped**.

### Changed — No real organization names in any code or documentation

Replaced all `strayer` / `capella` / `gwu` references with `acme-univ` / `acme-univ-b` across examples, src, tests, docs, and CONTRIBUTING.

---


## [0.27.0] — 2026-04-13

### Added — South Korea PIPA RAG Pre-filter (`32_south_korea_rag.py`)

PIPA (Personal Information Protection Act) and Korea AI Framework Act as a four-layer RAG retrieval pre-filter:

- `KoreaPIPADataSubjectFilter` (PIPA Art. 15-18, Art. 23) — data subject self-access → immediate APPROVED; no legal basis → DENIED; sensitive info without explicit consent → DENIED
- `KoreaPIPAMinimizationFilter` (PIPA Art. 3, Art. 16) — unauthorized data categories → DENIED; incompatible purpose → DENIED
- `KoreaAIActFilter` (Korea AI Framework Act Art. 6, Jan 2024) — high-impact AI without transparency disclosure → REQUIRES_HUMAN_REVIEW; high-impact with disclosure → APPROVED
- `KoreaCrossBorderFilter` (PIPA Art. 39-3) — adequate jurisdictions (KR/EU/UK/CH/JP/NZ/CA) → APPROVED; BCRs/SCCs → APPROVED; otherwise → DENIED
- `KoreaPIPARAGPipeline` + `KoreaRAGAuditRecord` emitting `event="KOREA_PIPA_RAG_RETRIEVAL"`

37 new tests. Total: **997 passed, 2 skipped**.

---

## [0.26.0] — 2026-04-13

### Added — Brazil LGPD RAG Pre-filter (`31_brazil_lgpd_rag.py`)

LGPD Law 13.709/2018 as a four-layer RAG retrieval pre-filter:

- `LGPDDataSubjectFilter` (Art. 7/11/18) — data subject self-access always APPROVED; denies retrieval without legal basis; denies sensitive data without explicit consent unless legal obligation
- `LGPDMinimizationFilter` (Art. 6(I)/(III)) — denies documents containing data categories outside `authorized_data_categories`; denies incompatible processing purposes
- `LGPDDataRetentionFilter` (Art. 15/18(VI)) — DENIED for expired retention without legal hold; REDACTED for deletion-requested documents without legal override
- `LGPDCrossBorderFilter` (Art. 33) — adequate jurisdictions (BR/EU/UK/CH) pass freely; non-adequate require `has_lgpd_transfer_mechanism=True`; non-personal data bypasses
- `BrazilLGPDRAGPipeline` + `BrazilRAGAuditRecord` emitting `event="BRAZIL_LGPD_RAG_RETRIEVAL"`

36 new tests. Total: **960 passed, 2 skipped**.

---

## [0.25.0] — 2026-04-13

### Added — Government/Public Sector RAG (FedRAMP + FISMA + NIST SP 800-53 + CUI 32 CFR Part 2002)

**`examples/29_government_public_sector_rag.py`** — four-layer defense-in-depth retrieval pipeline
for U.S. federal and state government platforms enforcing FedRAMP authorization levels,
FISMA/NIST SP 800-53 security controls, Controlled Unclassified Information (CUI) handling
requirements under 32 CFR Part 2002, and government audit log protection under NIST AU-9.

**New classes:**
- `FedRAMPImpactLevel` — HIGH / MODERATE / LOW / NOT_FEDRAMP
- `CUICategory` — UNCONTROLLED_PUBLIC / FOUO / LAW_ENFORCEMENT_SENSITIVE / PRIVACY_ACT / EXPORT_CONTROLLED
- `GovernmentRole` — FEDERAL_EMPLOYEE / CONTRACTOR / CLEARED_CONTRACTOR / IG_AUDITOR / CONGRESSIONAL_STAFF / STATE_GOVERNMENT / PUBLIC / SYSTEM_ADMIN
- `GovernmentDecision` — PERMITTED / DENIED / REDACTED
- `GovernmentRAGContext` — frozen dataclass (16 fields): FedRAMP level, background investigation, security clearance, need-to-know, Privacy Act training, ATO, FISMA categorization
- `GovernmentDocument` — frozen dataclass (8 fields): FedRAMP required level, CUI category, PII, export control, classification flags
- `GovernmentFilterResult` — filter output with `is_denied` property
- `FedRAMPAuthorizationFilter` — FedRAMP impact level authorization + ATO + authorized system enforcement
- `FISMASecurityControlFilter` — NIST SP 800-53 AC-3/AC-4 access enforcement, AC-3(7) need-to-know, PS-3 personnel screening
- `CUIMarkingFilter` — 32 CFR Part 2002 CUI categories; EAR/ITAR US person requirement; Privacy Act 5 USC §552a training gate; FAR 52.204-21 contractor agreement
- `GovernmentAuditFilter` — NIST AU-9 audit protection; Inspector General Act §6 independent access override; Congressional oversight override
- `GovernmentRAGPipeline` — orchestrates all four layers; `retrieve()` and `retrieve_with_audit()`
- `GovernmentAuditRecord` — structured audit log with `to_audit_log()` producing GOVERNMENT_RAG_RETRIEVAL events

**Tests:** 36 tests — all passing.

---

## [0.23.0] — 2026-04-13

### Added — Energy & Utilities RAG (NERC CIP + FERC CEII + DOE Cybersecurity + NRC Nuclear Safeguards)

**`examples/28_energy_utilities_rag.py`** — four-layer defense-in-depth retrieval pipeline
for energy and utilities platforms enforcing NERC Critical Infrastructure Protection (CIP)
standards for Bulk Electric System (BES) Cyber Systems, FERC Critical Energy Infrastructure
Information (CEII) protections under 18 CFR §388.113, DOE cybersecurity controls for
classified and sensitive energy information, and NRC nuclear safeguards information (SGI)
controls under 10 CFR 73.21 with tipping-off prohibition equivalent.

**New classes:**
- `EnergyRole` — GRID_OPERATOR / COMPLIANCE_OFFICER / SECURITY_ANALYST / FIELD_TECHNICIAN / CONTRACTOR / VENDOR / REGULATOR / EXECUTIVE / ADMIN
- `BESCyberSystemImpact` — HIGH / MEDIUM / LOW / NOT_BES
- `EnergyDecision` — PERMITTED / DENIED / REDACTED
- `EnergyUtilitiesContext` — frozen dataclass (14 fields): clearances, physical/electronic access, CEII/DOE/NRC authorizations
- `EnergyDocument` — frozen dataclass (8 fields): BES impact, CEII, DOE, NRC safeguards, public flags
- `EnergyFilterResult` — filter output with `is_denied` property
- `NERCCIPFilter` — CIP-004/005/011/013 personnel and electronic access controls for BES Cyber Systems
- `FERCRegulatoryFilter` — CEII NDA requirement and FERC restricted filing protections
- `DOECybersecurityFilter` — classified vs. sensitive energy information access gating
- `NRCNuclearSecurityFilter` — 10 CFR 73.21 SGI access controls with authorized inspector path
- `EnergyUtilitiesRAGPipeline` — orchestrates all four layers; `retrieve()` and `retrieve_with_audit()`
- `EnergyAuditRecord` — structured audit log with `to_audit_log()` producing ENERGY_RAG_RETRIEVAL events

**Tests:** 36 tests — all passing.

---

## [0.22.0] — 2026-04-13

### Added — Financial Services RAG (GLBA Title V + SEC Reg S-P + FINRA Rule 3110 + BSA/AML SAR Confidentiality)

**`examples/27_financial_services_rag.py`** — four-layer defense-in-depth retrieval pipeline
for financial services platforms enforcing GLBA Title V Non-Public Personal Information
protections, SEC Regulation S-P (17 CFR Part 248) safeguard rule and broker-dealer customer
records privacy, FINRA Rule 3110 written supervisory procedures and licensed principal
requirements, and Bank Secrecy Act 31 USC 5318(g)(2) SAR tipping-off prohibition and CTR
access controls.

**New classes:**
- `FinancialRole` — 8 roles: REGISTERED_REPRESENTATIVE, COMPLIANCE_OFFICER, CUSTOMER,
  BRANCH_MANAGER, INTERNAL_AUDITOR, EXTERNAL_AUDITOR, REGULATOR, ADMIN
- `NPICategory` — 5 categories: ACCOUNT_INFORMATION, TRANSACTION_HISTORY,
  CREDIT_INFORMATION, INCOME_ASSETS, NOT_NPI
- `FinancialDecision` — PERMITTED / DENIED / REDACTED
- `FinancialServicesContext` (frozen) — 15-field context: customer/account IDs, role,
  self-access flag, GLBA opt-out/affiliate flags, safeguard controls, FINRA WSP status,
  licensed principal flag, SAR/CTR authorization, law enforcement flag, audit access
- `FinancialDocument` (frozen) — 7-field document: NPI category, customer ID, SAR/CTR
  flags, AML investigation flag, public flag
- `GLBAPrivacyFilter` — GLBA §§6801–6809: NPI protection; affiliate sharing rules
  (§6802(a)/(b)); opt-out election; safeguard rule; regulatory examination exemption
- `SECRegSPFilter` — 17 CFR §248.30 safeguard prerequisite; §248.10 NPI disclosure
  restrictions; §248.15 regulatory examination access
- `FINRASupervisionFilter` — Rule 3110(a)/(b): WSP currency gate; licensed principal
  requirement for branch managers; regulatory examination access
- `BSAAMLFilter` — 31 USC §5318(g)(2): absolute SAR tipping-off prohibition (blocks even
  the SAR subject); 31 CFR §1010.311 CTR access; AML investigation confidentiality
- `FinancialServicesRAGPipeline` — sequential four-layer retrieval with `retrieve()` and
  `retrieve_with_audit()` methods
- `FinancialAuditRecord` — structured audit with `to_audit_log()` event serialization

**Tests:** 36 tests in `tests/test_financial_services_rag.py`

---

## [0.21.0] — 2026-04-13

### Added — Legal Services RAG (Attorney-Client Privilege + Conflict of Interest + Work Product Doctrine + State Bar Ethics)

**`examples/26_legal_services_rag.py`** — four-layer defense-in-depth retrieval pipeline
for legal services platforms enforcing ABA Model Rule 1.6 attorney-client confidentiality,
ABA Model Rules 1.7/1.9 conflict of interest screening, FRCP Rule 26(b)(3) work product
doctrine (ordinary vs. opinion work product), and state bar ethics compliance including
jurisdiction-specific bar admission verification and unauthorized practice of law prevention.

**New classes:**
- `LegalRole` — 6 roles: ATTORNEY, PARALEGAL, CLIENT, OPPOSING_COUNSEL, EXPERT_WITNESS, ADMIN
- `WorkProductType` — ORDINARY / OPINION / NOT_WORK_PRODUCT (FRCP Rule 26(b)(3) classification)
- `LegalDecision` — PERMITTED / DENIED / REDACTED
- `LegalServicesContext` (frozen) — 14-field context: user role, matter/client IDs, bar
  admission jurisdiction, conflict cleared status, adverse former client flag, privilege
  waiver, substantial need, and audit access designation
- `LegalDocument` (frozen) — 6-field document: privilege flag, work product type, owning
  client ID, matter jurisdiction, and public filing flag
- `LegalFilterResult` — per-layer result with decision, reason, conditions; `is_denied` property
- `AttorneyClientPrivilegeFilter` — ABA Rule 1.6: role-by-role privilege enforcement;
  opposing counsel denied; privilege waiver path; client/attorney/paralegal/admin branches
- `ConflictOfInterestFilter` — ABA Rule 1.7 (current client conflicts) + Rule 1.9 (former
  client adversity); written consent exception; public document bypass
- `WorkProductDoctrineFilter` — FRCP Rule 26(b)(3)(B): absolute opinion work product
  protection; Rule 26(b)(3)(A): substantial need exception for ordinary work product
- `StateBarEthicsFilter` — bar admission jurisdiction verification; pro hac vice requirement;
  paralegal supervision; admin audit designation; UPL prevention
- `LegalServicesRAGPipeline` — sequential four-layer retrieval with `retrieve()` and
  `retrieve_with_audit()` methods
- `LegalAuditRecord` — structured audit with `to_audit_log()` event serialization

**Tests:** 36 tests in `tests/test_legal_services_rag.py`

---

## [0.20.0] — 2026-04-13

### Added — Digital Health RAG (FDA SaMD + 42 CFR Part 2 SUD + HIPAA Special Categories + ONC Interoperability)

**`examples/25_digital_health_rag.py`** — four-layer defense-in-depth retrieval pipeline
for digital health and telehealth platforms enforcing FDA Software as a Medical Device (SaMD)
classification requirements (Class I/II/III device clearance), 42 CFR Part 2 Substance Use
Disorder records protections (no TPO exceptions — stricter than HIPAA), HIPAA Special Category
access controls (psychotherapy notes, HIV/AIDS status, genetic information, domestic violence),
and ONC 21st Century Cures Act information blocking prohibition with patient-directed access
rights.

**New classes:**
- `DigitalHealthRole` — 9 roles: PRESCRIBER, CARE_MANAGER, PATIENT, PATIENT_ADVOCATE,
  SUD_COUNSELOR, MENTAL_HEALTH_PROVIDER, DATA_ANALYST, RESEARCHER, ADMIN
- `SaMDClass` — CLASS_I / CLASS_II / CLASS_III (FDA device classification)
- `SpecialCategory` — PSYCHOTHERAPY_NOTES / HIV_STATUS / GENETIC_INFO /
  DOMESTIC_VIOLENCE / NONE
- `DigitalHealthContext` (frozen) — 9-field context: user role, device cleared status,
  intended use documentation, explicit Part 2 consent, same SUD program indicator,
  HIPAA authorization, information blocking exception, patient self-access flag
- `DigitalHealthDocument` (frozen) — 5-field document: SaMD class, SUD record flag,
  special category, public access flag
- `DigitalHealthDecision` — PERMITTED / DENIED / REDACTED
- `DigitalHealthResult` — per-layer result with decision, reason, and conditions
- `FDASaMDFilter` — Class III requires device_cleared + intended_use_documented;
  Class II requires intended_use_documented; Class I always permitted; public → bypass
- `Part2SUDFilter` — SUD records blocked unless explicit_part2_consent OR
  is_same_sud_program (no HIPAA Treatment/Payment/Operations exceptions)
- `HIPAASpecialCategoryFilter` — psychotherapy notes: MENTAL_HEALTH_PROVIDER only
  (patient blocked per 45 CFR 164.524(a)(1)(i)); HIV: authorized clinical roles or
  hipaa_authorization; genetic info: DATA_ANALYST/RESEARCHER blocked without authorization;
  domestic violence: MENTAL_HEALTH_PROVIDER or PRESCRIBER only
- `ONCInteroperabilityFilter` — patient-directed roles (PATIENT, PATIENT_ADVOCATE) and
  is_patient_self_access always permitted unless information_blocking_exception_applies;
  clinical roles pass through
- `DigitalHealthRAGPipeline` — sequential four-layer retrieval with per-document enforcement
- `DigitalHealthAuditRecord` — structured audit with `to_audit_log()` returning dict with
  event="DIGITAL_HEALTH_RAG_RETRIEVAL", permitted/denied/redacted counts, layer outcomes

**Tests:** 36 tests in `tests/test_digital_health_rag.py`

---

## [0.19.0] — 2026-04-13

### Added — Clinical Trials RAG (FDA 21 CFR Part 11 + GxP Tiers + ICH E6(R3) GCP + HIPAA)

**`examples/24_clinical_trials_rag.py`** — four-layer defense-in-depth retrieval pipeline
for clinical trial management systems enforcing FDA 21 CFR Part 11 electronic records and
signatures validation requirements, GxP tier-based document access controls (GMP/GLP/GCP/GDP),
ICH E6(R3) Good Clinical Practice blinding preservation and site-level access controls, and
HIPAA minimum necessary for PHI across identified, limited dataset, and de-identified data.

**New classes:**
- `ClinicalTrialRole` — 8 roles: SPONSOR, MONITOR, INVESTIGATOR, DSMB, REGULATORY,
  BIOSTATISTICIAN, QA, PHARMACIST
- `GxPTier` — GMP / GLP / GCP / GDP / NON_GXP
- `ClinicalDocumentType` — 16 types: BATCH_RECORD, DEVIATION_REPORT, CAPA_RECORD,
  NONCLINICAL_STUDY_REPORT, RAW_STUDY_DATA, PROTOCOL, INVESTIGATOR_BROCHURE, CASE_REPORT_FORM,
  INTERIM_ANALYSIS, FINAL_CLINICAL_STUDY_REPORT, SAE_REPORT, DISTRIBUTION_RECORD,
  CHAIN_OF_CUSTODY, INFORMED_CONSENT_TEMPLATE, REGULATORY_SUBMISSION, IRB_APPROVAL
- `PHIClassification` — IDENTIFIED / LIMITED_DATASET / DE_IDENTIFIED / NO_PHI
- `ClinicalAccessContext` (frozen) — user role, assigned site IDs, system validation,
  audit trail, e-signature binding, database lock, DSMB authorization, IRB waiver, DUA status
- `ClinicalDocument` (frozen) — document type, GxP tier, PHI classification, site ID,
  blinding flag, and public-access flag
- `FDA21CFR11Filter` — Layer 1: blocks unvalidated, no-audit-trail, or unsigned systems;
  public docs bypass
- `GxPDocumentFilter` — Layer 2: GMP → QA/REGULATORY only; GLP → REGULATORY only;
  GDP → PHARMACIST/QA/REGULATORY only; GCP passes
- `ICHE6GCPFilter` — Layer 3: REGULATORY always passes; blinding check for blinded docs
  or INTERIM_ANALYSIS type; site-level restriction for MONITOR/INVESTIGATOR vs assigned sites
- `HIPAAFilter` — Layer 4: IDENTIFIED PHI requires PHI-authorized role + IRB waiver;
  LIMITED_DATASET requires DUA; DE_IDENTIFIED/NO_PHI always pass
- `ClinicalTrialRAGPipeline` — sequential four-layer pipeline returning `ClinicalRetrievalResult`
  with per-document audit + block_reasons dict
- `ClinicalAccessAuditRecord` — `to_audit_log()` returns structured dict with event type,
  user, and per-document compliance outcomes

**Test coverage:** 44 tests across all four filters and the pipeline integration.

---

## [0.18.0] — 2026-04-13

### Added — HR/Employment RAG (NYC Local Law 144 AEDT + EEOC 4/5 Rule + Illinois AIVIA)

**`examples/23_hr_employment_rag.py`** — three-layer defense-in-depth retrieval pipeline
for HR and talent-acquisition systems enforcing NYC Local Law 144 Automated Employment
Decision Tool (AEDT) bias audit and candidate notice requirements, EEOC 4/5 (80%) adverse
impact rule for protected-class HR analytics and AI-driven selection criteria, and Illinois
Artificial Intelligence Video Interview Act (AIVIA) video interview AI consent, disclosure,
and deletion-request obligations.

**New classes:**
- `HRDocumentCategory` — 15 categories covering AEDT outputs, video AI, protected class
  analytics, and administrative HR documents
- `CandidateAccessContext` (frozen) — employer jurisdiction, AEDT audit status, EEOC
  selection rate ratio, AIVIA consent/disclosure/deletion state
- `HRDocument` (frozen) — document with category, public-release flag, and metadata
- `NYCLL144AuditRecord` — per-document access audit with AEDT block counts
- `NYCLL144Filter` — blocks AEDT category documents for NYC employers missing bias audit,
  acceptable impact ratios, or candidate notice; no-op for non-NYC jurisdictions
- `EEOCFilter` — blocks protected-class analytics and AEDT outputs when selection rate
  ratio < 0.80 with adequate sample; blocks when ratio is None or sample inadequate
- `AIVIAFilter` — blocks all video categories on deletion request; requires prior disclosure
  and consent for video AI; non-video documents unaffected
- `HRRAGPipeline` — three-layer sequential pipeline with per-layer audit logs

**New tests:** 40 tests across `tests/test_hr_employment_rag.py`

---

## [0.17.0] — 2026-04-13

### Added — Government Contracting RAG (FAR/DFARS CUI + ITAR/EAR Export Control + DD Form 254)

**`examples/22_government_contracting_rag.py`** — three-layer defense-in-depth retrieval pipeline
for government contractor knowledge base systems, enforcing FAR 52.204-21 / DFARS 252.204-7012
Controlled Unclassified Information (CUI) access control and personnel/facility security clearance
requirements, ITAR (22 CFR Parts 120-130) USML technical data access restriction for non-US
Persons (deemed-export license check), EAR (15 CFR Parts 730-774) CCL NS/MT domestic-recipient
restriction, and DD Form 254 contract-specific need-to-know enforcement per NISPOM Rule
(32 CFR Part 117).

**New classes:**
- `SecurityClearanceLevel` — six-level enum (UNCLASSIFIED through TOP_SECRET_SCI) with `rank` and
  `authorizes()` for clearance comparison
- `CUICategory` — CUI Registry categories: CTI, EXPORT_CONTROLLED, PRIVACY, PBI, LES, NUCLEAR,
  SPECIFIED_BASIC, UNCONTROLLED
- `ITARCategory` — USML categories I–XXII (9 categories) plus EAR CCL tiers (AT_ONLY, NS_MT,
  DUAL_USE, EAR99, NOT_SUBJECT_EAR)
- `ContractorAccessContext` (frozen dataclass) — contractor identity: US Person status, clearance
  levels, authorized CUI categories, active contract IDs (DD 254), deemed-export license flag,
  domestic recipient flag
- `GovContractDocument` (frozen dataclass) — document with minimum clearance, CUI category,
  ITAR/EAR classification, required contract IDs, facility clearance requirement, public release flag
- `GovContractComplianceAuditRecord` — per-layer access control statistics and block reasons list
  with `to_audit_log()` for DCSA compliance reporting
- `FARDFARSFilter` — Layer 1: facility clearance, personnel clearance, CUI category authorization;
  publicly releasable documents pass all checks
- `ITAREARFilter` — Layer 2: USML categories blocked for non-US Persons without deemed-export
  license; CCL NS/MT + DUAL_USE blocked for non-domestic recipients; EAR99/NOT_SUBJECT_EAR unrestricted
- `DD254NeedToKnowFilter` — Layer 3: intersection check between document required_contract_ids and
  contractor authorized_contract_ids; open documents (empty required set) pass all cleared personnel
- `GovContractRAGPipeline` — orchestrates FAR/DFARS → ITAR/EAR → DD 254; returns (permitted, audit)

**Tests:** 40 new tests in `tests/test_government_contracting_rag.py`

---

## [0.16.0] — 2026-04-13

### Added — Energy / Utilities RAG Example (NERC CIP + FERC Order 2222 + NRC 10 CFR Part 73)

**`examples/21_energy_utilities_rag.py`** — three-layer defense-in-depth retrieval pipeline
for energy utility operational knowledge base systems, enforcing NERC CIP v7 BES Cyber Security
Standards (CIP-004-7, CIP-007-7, CIP-011-3), FERC Order 2222 DER aggregation market data
restrictions (18 CFR §1c.2), and NRC 10 CFR Part 73.54 nuclear cybersecurity requirements
for Critical Digital Assets simultaneously and independently.

New classes (self-contained in the example):
- `BESCyberSystemImpactLevel` — HIGH, MEDIUM, LOW, NOT_APPLICABLE; drives NERC CIP access tiers
- `NERCCIPAccessLevel` — OPERATIONAL (HIGH/MEDIUM system access), INFORMATIONAL (BCSI read access),
  PUBLIC (no BES Cyber System access); maps to CIP-007-7 Electronic Access List requirements
- `EnergyDocumentCategory` — 20 categories: BCSI (SCADA_CONFIG, PROTECTION_SCHEME, NETWORK_DIAGRAM,
  CYBER_SECURITY_PLAN, ACCESS_CONTROL_LIST), operational non-BCSI (MAINTENANCE_PROCEDURE, OPERATOR_LOG,
  OUTAGE_REPORT, EQUIPMENT_MANUAL), market data (FERC_FILING, DER_DISPATCH_CURVE, MARKET_BID_DATA,
  CAPACITY_POSITION, MARKET_REPORT_PUBLIC), nuclear (NUCLEAR_SAFETY_SYSTEM, CRITICAL_DIGITAL_ASSET,
  SECURITY_PLAN_NUCLEAR, EMERGENCY_PROCEDURE), public (PUBLIC_NOTICE, ANNUAL_REPORT)
- `ControlAreaType` — TRANSMISSION, GENERATION, DISTRIBUTION, NUCLEAR, MARKET
- `EnergyAccessContext` — frozen dataclass: personnel_id, cip_access_level, nerc_training_current,
  authorized_asset_ids (tuple), market_participant_certified, nuclear_clearance, control_area_type
- `EnergyDocument` — frozen dataclass: doc_id, category, title, impact_level, bcsi_classification,
  is_nuclear_safety_system, requires_q_clearance, market_sensitive, asset_id, is_public
- `NERCCIPFilter` — Layer 1: enforces CIP-011-3 BCSI access control, CIP-004-7 training currency,
  CIP-007-7 Electronic Access List for HIGH/MEDIUM impact systems; `_BCSI_CATEGORIES` frozenset;
  `_OPERATIONAL_REQUIRED_LEVELS` frozenset
- `FERCOrder2222Filter` — Layer 2: blocks DER_DISPATCH_CURVE, MARKET_BID_DATA, CAPACITY_POSITION
  for non-certified market participants; `_CERTIFIED_REQUIRED_CATEGORIES` frozenset;
  `_PUBLIC_MARKET_CATEGORIES` frozenset (FERC_FILING, MARKET_REPORT_PUBLIC always pass)
- `NRCCybersecurityFilter` — Layer 3: blocks access to NUCLEAR_SAFETY_SYSTEM, CRITICAL_DIGITAL_ASSET,
  SECURITY_PLAN_NUCLEAR, EMERGENCY_PROCEDURE without nuclear_clearance; enforces is_nuclear_safety_system
  and requires_q_clearance flags regardless of category
- `EnergyComplianceAuditRecord` — CIP/NRC audit record with per-layer block counts; `to_cip_audit_log()`
  returns structured dict for CIP-004-7 R6 + CIP-007-7 R4 audit evidence
- `EnergyRAGPipeline` — three-layer orchestrator (NERC → FERC → NRC); returns (permitted_docs, audit)

Four demo scenarios: (A) authorized control room operator SCADA query; (B) unauthorized vendor blocked
by NERC CIP; (C) uncertified market analyst blocked by FERC Order 2222; (D) Q-cleared nuclear admin
retrieving reactor safety system documentation.

**Tests:** `tests/test_energy_utilities_rag.py` — 45 tests covering all three filter layers,
audit record structure, pipeline orchestration, and all four scenarios. Full suite: 633 passed, 2 skipped.

---

## [0.15.0] — 2026-04-13

### Added — Real Estate / Mortgage Lending RAG Example (Fair Housing Act + HMDA + CFPB UDAAP + RESPA)

**`examples/20_real_estate_mortgage_rag.py`** — four-layer defense-in-depth retrieval pipeline
for mortgage lending knowledge base systems, enforcing the Fair Housing Act (42 U.S.C. §§ 3604–3606),
Home Mortgage Disclosure Act (12 U.S.C. § 2801; Reg C), CFPB UDAAP adverse action explainability
(12 U.S.C. § 5531; Reg B 12 CFR 1002.9), and RESPA/SAFE Act state licensing requirements
(12 U.S.C. §§ 2607, 5104) independently and simultaneously.

New classes (self-contained in the example):
- `ProtectedCharacteristic` — 10 FHA/ECOA protected classes: RACE, COLOR, NATIONAL_ORIGIN,
  RELIGION, SEX, FAMILIAL_STATUS, DISABILITY (FHA), AGE, MARITAL_STATUS, RECEIPT_OF_PUBLIC_ASSISTANCE (ECOA)
- `MortgageDocumentCategory` — 18 document categories spanning underwriting credit file (CREDIT_REPORT,
  INCOME_VERIFICATION, ASSET_STATEMENT, DEBT_OBLIGATIONS), property docs (APPRAISAL_REPORT,
  COMPARABLE_SALES, PROPERTY_ASSESSMENT), demographic data (NEIGHBORHOOD_DEMOGRAPHIC, CENSUS_TRACT_DATA),
  HMDA data (HMDA_LAR_DATA, HMDA_DEMOGRAPHIC), decision docs (APPROVAL_NOTICE, DENIAL_NOTICE,
  RATE_SHEET, COUNTER_OFFER), settlement (CLOSING_DISCLOSURE, SETTLEMENT_STATEMENT, TITLE_COMMITMENT),
  and internal policy (UNDERWRITING_GUIDELINES, COMPLIANCE_PROCEDURE)
- `LoanPurpose` — HOME_PURCHASE, REFINANCE, HOME_IMPROVEMENT, CASH_OUT_REFINANCE, HELOC
- `QueryContext` — UNDERWRITING_DECISION, APPRAISAL_REVIEW, ADVERSE_ACTION, HMDA_REPORTING,
  COMPLIANCE_AUDIT, SERVICING, GENERAL_QUERY
- `MortgageAccessContext` — frozen dataclass: loan_officer_id, license_state, property_state,
  query_context, adverse_action_notice_required, hmda_reporting_context, loan_purpose
- `MortgageDocument` — frozen dataclass: doc_id, category, title, contains_protected_class_data,
  contains_hmda_demographic_fields, property_state, adverse_action_factors, is_public_disclosure
- `FHADisparateImpactFilter` — Layer 1: blocks NEIGHBORHOOD_DEMOGRAPHIC and CENSUS_TRACT_DATA in
  underwriting/appraisal/adverse action contexts (Texas Dept. of Housing v. Inclusive Communities,
  576 U.S. 519, 2015); blocks any document with protected class data in restricted contexts;
  COMPLIANCE_AUDIT and public disclosures exempt
- `HMDAComplianceFilter` — Layer 2: blocks HMDA_DEMOGRAPHIC and HMDA_LAR_DATA in underwriting/
  appraisal/adverse action contexts per 12 CFR 1002.5(d); permits HMDA data in hmda_reporting_context;
  blocks any document with HMDA demographic fields in underwriting per FFIEC guidance
- `CFPBUDAAPFilter` — Layer 3: in ADVERSE_ACTION contexts with adverse_action_notice_required=True,
  blocks DENIAL_NOTICE documents with empty adverse_action_factors (CFPB Circular 2022-03) and blocks
  adverse action documents citing protected class attributes as denial reasons (ECOA §1691);
  blocks demographic categories from serving as adverse action basis
- `RESPALicensingFilter` — Layer 4: blocks documents where license_state ≠ property_state per
  SAFE Act 12 U.S.C. § 5104; COMPLIANCE_AUDIT and HMDA_REPORTING contexts exempt; public
  disclosures exempt; case-insensitive state matching
- `MortgageComplianceAuditRecord` — fair lending audit log capturing all filter decisions per
  required HMDA/ECOA/BSA record-keeping; `to_fair_lending_log()` returns dict for examination

4 end-to-end scenarios: (A) loan officer appraisal review with FHA/HMDA/RESPA enforcement,
(B) compliance analyst HMDA reporting query permitting HMDA data access, (C) cross-state
officer blocked by RESPA/SAFE Act licensing, (D) adverse action notice with CFPB UDAAP
explainability gate (valid factors permitted, missing factors / protected class factors blocked)

Tests: 37 new tests in `tests/test_mortgage_rag.py` — TestFHADisparateImpactFilter (8),
TestHMDAComplianceFilter (6), TestCFPBUDAAPFilter (7), TestRESPALicensingFilter (6),
TestMortgageRAGPipeline (6), TestScenarios (4)

---

## [0.14.0] — 2026-04-13

### Added — Pharmaceutical/Clinical Trial RAG Example (FDA 21 CFR Part 11 + ICH E6(R3) GCP + HIPAA)

**`examples/19_pharma_clinical_rag.py`** — three-layer defense-in-depth retrieval pipeline
for pharmaceutical clinical trial systems, enforcing FDA 21 CFR Part 11 (electronic records),
ICH E6(R3) Good Clinical Practice (blinding integrity and site isolation), and HIPAA Privacy Rule
(minimum necessary standard for PHI) independently and simultaneously.

New classes (self-contained in the example):
- `ClinicalRecordCategory` — 14 document categories including RANDOMIZATION_CODE, INTERIM_ANALYSIS,
  BLIND_BREAK_LOG (unblinded), PATIENT_DATA_IDENTIFIABLE, ADVERSE_EVENT, LAB_RESULT (PHI),
  INVESTIGATOR_BROCHURE, PROTOCOL, CLINICAL_STUDY_REPORT, PUBLIC_SUMMARY
- `GCPRole` — 11 clinical trial roles: PI, SUB_INVESTIGATOR, CRA, DATA_MANAGER, REGULATORY_AFFAIRS,
  BLINDED_STATISTICIAN, UNBLINDED_STATISTICIAN, PHARMACOVIGILANCE, SPONSOR_MEDICAL_MONITOR, QA, EXTERNAL_AUDITOR
- `TrialPhase` — PHASE_I through PHASE_IV and OBSERVATIONAL
- `ClinicalAccessContext` — frozen dataclass: GxP credentials, GCP training currency, authorized trial
  IDs, blinding status, authorized phases, PHI authorization, site assignment, minimum necessary scope
- `ClinicalDocument` — frozen dataclass: category, trial_id, trial_phase, is_unblinded_data,
  contains_phi, site_id, is_controlled_record
- `FDA21CFRPart11Filter` — Layer 1: §11.10(d) credential gate for controlled electronic records;
  §11.10(g) trial-specific authority check; public records exempt
- `ICHGCPFilter` — Layer 2: GCP training currency (Section 5.1); blinding integrity enforcement
  — RANDOMIZATION_CODE, INTERIM_ANALYSIS, BLIND_BREAK_LOG, and is_unblinded_data=True blocked for
  blinded roles (Section 5.7); site-restricted access for PI/SUB_I/CRA (Section 4.9);
  non-controlled records exempt
- `HIPAAMinimumNecessaryFilter` — Layer 3: phi_authorized gate (§164.502(b)); minimum_necessary_scope
  category check for PHI access scoped to stated request purpose
- `ClinicalRAGPipeline` — orchestrates all three layers; union of blocked IDs governs final retrieval;
  blocked ID extraction via `split(" blocked ")[1].split(":")[0]` (handles multi-word prefixes)
- `ClinicalComplianceAuditRecord` — 21 CFR Part 11 §11.10(e) compliant audit: user_id, role,
  trial_ids, query_purpose, permitted/blocked counts, per-regulation block details, phi_accessed,
  blinding_violation_blocked

Four scenarios demonstrate: blinded statistician (unblinded data blocked), CRA site audit
(cross-site isolation), unauthorized external (only public summary returned), PI safety review
(site-restricted AE access, no unblinded data).

**Test coverage:** 32 tests (`tests/test_pharma_clinical_rag.py`)

---

## [0.13.0] — 2026-04-13

### Added — Multi-State US Consumer Privacy RAG Example (CCPA/CPRA, VCDPA, CPA, CTDPA)

**`examples/18_state_consumer_privacy_rag.py`** — four-layer defense-in-depth retrieval
pipeline applying all four leading US state consumer privacy statutes independently;
most-restrictive-jurisdiction logic ensures the union of all applicable state blocks
governs final retrieval.

New classes (self-contained in the example):
- `ConsumerPrivacyState` — covered states: CALIFORNIA, VIRGINIA, COLORADO, CONNECTICUT
- `SensitivePICategory` — 10 sensitive PI categories (PRECISE_GEOLOCATION, HEALTH_MEDICAL,
  RACIAL_ETHNIC_ORIGIN, SEXUAL_ORIENTATION, CITIZENSHIP_IMMIGRATION, BIOMETRIC,
  FINANCIAL_ACCOUNT, SSN_GOVERNMENT_ID, CHILDREN_DATA, PERSONAL_COMM_CONTENT)
- `DataProcessingPurpose` — 10 processing purposes including TARGETED_ADVERTISING,
  PERSONALIZATION, PROFILING, THIRD_PARTY_SALE, SHARING_CROSS_CONTEXT
- `ConsumerPrivacyContext` — session boundary: resident states, opt-out flags,
  GPC signal, sensitive PI consent dict, SPI limit-use instruction, minor flag
- `CCPACPRAFilter` — Layer 1: CCPA/CPRA (Cal. Civ. Code §§ 1798.100–1798.199.100);
  sharing opt-out (§1798.135), sale opt-out (§1798.120), SPI limit-use (§1798.121),
  minor affirmative opt-in requirement (§1798.120(c))
- `VCDPAFilter` — Layer 2: VCDPA (Va. Code §§ 59.1-571 to 59.1-585); consent gate
  for sensitive data (§59.1-578); targeted advertising and profiling opt-out (§59.1-577)
- `CPAFilter` — Layer 3: CPA (Colo. Rev. Stat. §§ 6-1-1301 to 6-1-1313); GPC signal
  honored as universal opt-out (§6-1-1306(5)); sensitive data consent (§6-1-1308(7))
- `CTDPAFilter` — Layer 4: CTDPA (Conn. P.A. 22-15); minor protections (under 18, §9);
  universal opt-out signal recognition; sensitive data consent (§6)
- `StatePrivacyAuditRecord` — per-query audit: resident states, applicable laws,
  per-law block details, most-restrictive law, GPC signal honored flag
- `MultiStatePrivacyPipeline` — orchestrates all four filters independently; computes
  union of blocked doc IDs (most-restrictive-jurisdiction); returns intersection of
  documents permitted by every applicable state law

Key design decisions:
- **Independent filter evaluation:** each filter receives the full candidate set and
  returns its own blocked list; documents are excluded if blocked by ANY state
- **GPC signal:** honored by Colorado (§6-1-1306(5)) and Connecticut as a universal
  opt-out of targeted advertising and sale; not mandated by Virginia VCDPA
- **Most-restrictive-jurisdiction:** a California opt-out blocks documents even if
  the consumer is also a Virginia resident and Virginia would permit them

Four scenarios covering: CPRA opt-out with SPI limit-use (CA), no sensitive data
consent (VA), GPC universal opt-out (CO), dual-state most-restrictive (CA + VA).

Tests: 38 new test cases in `tests/test_state_consumer_privacy.py`.

Sectors covered: **14** (added US State Consumer Privacy: CCPA/CPRA, VCDPA, CPA, CTDPA).

---

## [0.12.0] — 2026-04-13

### Added — Telecommunications Sector RAG Example (FCC CPNI + TCPA + NPAC)

**`examples/17_telecom_rag.py`** — three-layer defense-in-depth retrieval pipeline
for a telecommunications carrier's customer service and operations knowledge base:

New classes (self-contained in the example):
- `CPNICategory` — CPNI categories under 47 CFR Part 64 (CALL_DETAIL_RECORDS,
  LOCATION_DATA, NETWORK_USAGE, ACCOUNT_INFORMATION, AGGREGATE_ONLY, NON_CPNI, PUBLIC)
- `CPNIAuthorizedPurpose` — 47 CFR Part 64.2005 authorized purposes:
  ACCOUNT_SERVICING (always permitted), MARKETING_WIRELINE_SERVICES (same-type
  existing customers), MARKETING_JOINT_VENTURE / MARKETING_THIRD_PARTY (opt-in
  required), NETWORK_OPERATIONS (internal), LAW_ENFORCEMENT (compelled disclosure)
- `NPACDataType` — NPAC data types under 47 CFR Part 52 (PORTING_STATUS,
  ROUTING_RECORD, SPID_DATA, SUBSCRIPTION_DATA, NON_NPAC)
- `AgentRole` — telecom agent roles: CUSTOMER_SERVICE, MARKETING, NETWORK_OPERATIONS,
  PORTING_TEAM, CARRIER_RELATIONS, COMPLIANCE
- `TelecomAccessContext` — session boundary: authorized purposes, customer CPNI
  opt-out status (47 CFR 64.2008), TCPA consent status, NPAC authorization
- `TelecomComplianceAuditRecord` — per-query record with FCC/TCPA/NPAC citations
- `CPNIFilter` — Layer 1: enforces 47 CFR Part 64; blocks CPNI documents for
  marketing purpose when customer has not opted in; blocks all CPNI when
  customer has opted out (opt-out overrides all purpose claims)
- `TCPAFilter` — Layer 2: blocks customer contact data (phone numbers, contact
  preferences) for marketing agents without documented TCPA prior express written
  consent (PEWC); non-marketing roles are not subject to TCPA restriction
- `NPACFilter` — Layer 3: restricts NPAC routing/porting data to PORTING_TEAM,
  CARRIER_RELATIONS, NETWORK_OPERATIONS, COMPLIANCE roles with npac_authorized=True

Design notes: CPNI opt-out (customer-controlled) overrides all agent purpose claims.
TCPA restricts marketing agents specifically — operational roles accessing contact
data for legitimate non-marketing purposes are not restricted by TCPA.
NPAC data is inter-carrier routing data (not customer data) — exposure to customer-
facing agents creates competitive intelligence risk between carriers.

Scenarios:
- A: CSR with account_servicing purpose — all CPNI account/usage docs returned;
  NPAC blocked (customer service role not authorized)
- B: Marketing agent (no TCPA consent, no CPNI opt-in) — CPNI blocks only for
  marketing purpose; TCPA blocks contact preference docs; public product docs returned
- C: Customer opted out (47 CFR 64.2008) — CPNI filter blocks all CPNI regardless
  of agent purpose; non-CPNI docs returned
- D: Porting team (npac_authorized=True) — full access including NPAC porting/routing
  data; NETWORK_OPERATIONS purpose passes CPNI filter

Closes #38.

---

## [0.11.0] — 2026-04-13

### Added — Energy/Utilities Sector RAG Example (FERC CEII + NERC CIP + NRC SUNSI)

**`examples/16_energy_utilities_rag.py`** — three-layer defense-in-depth retrieval
pipeline for a bulk electric system (BES) operator's grid operations knowledge base:

New classes (self-contained in the example):
- `CEIICategory` — FERC CEII categories (CRITICAL_ASSET_LOCATION, GRID_VULNERABILITY,
  PROTECTION_SYSTEM, CONTROL_SYSTEM, CAPACITY_SENSITIVE, NON_CEII, PUBLIC)
- `NERCCIPTier` — NERC CIP reliability standard tiers (HIGH_IMPACT, MEDIUM_IMPACT,
  LOW_IMPACT, NOT_APPLICABLE); HIGH = transmission ≥ 500kV control centers, MEDIUM =
  substations ≥ 200kV and generation ≥ 1500 MW, LOW = distribution-level systems
- `OperatorRole` — utility roles (SYSTEM_OPERATOR, CIP_COMPLIANCE_ANALYST,
  FIELD_ENGINEER, THIRD_PARTY_CONTRACTOR, NRC_AUTHORIZED, PUBLIC)
- `SUNSIType` — NRC SUNSI types (SAFEGUARDS_INFORMATION, SECURITY_RELATED_INFO,
  EXPORT_CONTROLLED, NON_SUNSI)
- `EnergyAccessContext` — session boundary: authorized CEII categories, NERC CIP
  training completion status, authorized CIP tiers, NRC SUNSI authorization
- `EnergyComplianceAuditRecord` — per-query record: CEII blocked, NERC CIP blocked,
  NRC SUNSI blocked, documents returned, applicable regulations
- `CEIIFilter` — Layer 1: enforces FERC 18 CFR Part 388.113; blocks documents whose
  CEII category is not in the requester's authorized set
- `NERCCIPFilter` — Layer 2: enforces CIP-004-7 (personnel training) and CIP-011-3
  (information protection); blocks BCSI when training is not complete or tier is not
  in the requester's authorized tier set
- `SUNSIFilter` — Layer 3: enforces NRC 10 CFR Part 2.390; blocks safeguards
  information from non-NRC-authorized personnel
- `EnergyRAGPipeline` — three-layer orchestrator

Design note: CEII authorization (FERC-granted), NERC CIP authorization (utility-internal
training + access management), and NRC SUNSI authorization (NRC-granted) are three
independent authorization hierarchies. A CIP compliance analyst with all-tier CIP
training does not automatically have CEII authorization — and vice versa.

Scenarios:
- A: Certified system operator (CEII HIGH+MEDIUM+VULNERABILITY authorized, CIP HIGH+MEDIUM
  trained) — NRC SUNSI blocks nuclear safeguards; NERC CIP LOW-tier blocked (operator
  authorized for HIGH+MEDIUM only); CEII infrastructure docs returned
- B: Third-party contractor (no CEII authorization, CIP training not complete) — CEII
  blocks all critical infrastructure docs; CIP blocks BCSI; only PUBLIC docs returned
- C: CIP Compliance Analyst (all tiers trained, no CEII authorization) — CEII blocks
  critical asset/vulnerability docs; LOW-tier BCSI (distribution automation) returns
- D: Public information request — all three layers pass; pricing and tariff docs returned

Closes #33.

---

## [0.10.0] — 2026-04-13

### Added — Federal/Government RAG Example (CUI + FedRAMP + NIST 800-53 AC-3)

**`examples/15_government_federal_rag.py`** — three-layer defense-in-depth retrieval
pipeline for a federal procurement knowledge-base assistant, covering CUI handling
(32 CFR Part 2002), FedRAMP source authorization, and NIST 800-53 AC-3 role-based
access enforcement.

New classes (self-contained in the example):
- `CUICategory` — enumeration of CUI categories (PROCUREMENT_AND_ACQUISITION, EXPORT_CONTROLLED,
  LAW_ENFORCEMENT_SENSITIVE, CRITICAL_INFRASTRUCTURE, PRIVACY, CONTROLLED_TECHNICAL,
  UNCLASSIFIED, PUBLIC)
- `AgencyRole` — federal role hierarchy (PUBLIC_USER through CUI_AUTHORIZED_OFFICER)
- `CUIAccessContext` — access boundary for a retrieval session: agency role, authorized
  CUI categories, FedRAMP boundary flag; `may_access_cui()` enforces authorized-category
  membership before any retrieval executes
- `FederalComplianceAuditRecord` — per-query audit record capturing documents retrieved,
  documents blocked, CUI categories blocked, FedRAMP sources blocked, AC-3 level violations,
  and applicable regulations (32 CFR 2002, FedRAMP High Baseline, NIST 800-53 AC-3)
- `CUIFilter` — Layer 1: enforces 32 CFR Part 2002 CUI handling; blocks documents whose
  CUI category is not in the requester's `authorized_cui_categories`
- `FedRAMPSourceFilter` — Layer 2: blocks documents sourced from non-FedRAMP-authorized
  cloud providers; default authorized set: aws_govcloud, azure_government, gcp_assured_workloads,
  oracle_cloud_government, ibm_cloud_for_government
- `NIST80053AC3Filter` — Layer 3: role-hierarchy enforcement; `_ROLE_HIERARCHY` maps each
  `AgencyRole` to a numeric level; `_LEVEL_REQUIREMENTS` maps document sensitivity levels
  (PUBLIC/UNCLASSIFIED/SENSITIVE_BUT_UNCLASSIFIED/CONTROLLED/RESTRICTED) to minimum role
  level; documents blocked when `role_level < required_level`

Scenarios:
- A: CMMC-certified contractor (role=CONTRACTOR_CUI_CLEARED, authorized CUI//PROC+CTI) —
  FedRAMP blocks sam.gov/commercial sources; AC-3 blocks CONTROLLED documents (requires
  Contracting Officer level 3, contractor is level 2); FOUO/SBU documents returned
- B: Uncleared vendor (role=CONTRACTOR_UNCLEARED, no CUI authorization) — CUI layer
  blocks all CUI//PROC documents; no documents reach LLM context
- C: Contracting officer with partial CUI scope (authorized CUI//PROC only, not CTI) —
  CUI//CTI documents blocked by Layer 1; CONTROLLED documents pass AC-3 (officer=level 3);
  mixed retrieval result
- D: Non-FedRAMP cloud source — FedRAMP layer blocks all commercial cloud documents
  regardless of CUI category or role level; zero documents returned

Closes #32.

---

## [0.9.0] — 2026-04-13

### Added — Legal Sector RAG Example

**`examples/14_legal_sector_rag.py`** — attorney-client privilege and ABA Model Rules
compliance for a law firm matter research assistant. Three compliance layers:

- **Layer 1 — ABA Rule 1.6 (Confidentiality):** `MatterScopeFilter` restricts retrieval
  to authorized matter personnel. Documents tagged with a `matter_id` are accessible only
  if the requester's `authorized_matter_ids` includes that matter.
- **Layer 2 — ABA Rule 1.7 / 1.9 (Conflicts of Interest):** `ConflictChecker` scans
  retrieved documents for adverse-party entity names. If a conflict is detected, retrieval
  halts and a conflict record is raised before any document reaches the LLM context window.
- **Layer 3 — ABA Rule 1.15 (Safekeeping of Client Property):** `Rule1_15Filter` isolates
  `CLIENT_FINANCIAL` documents to their scoped `matter_id`. A billing partner authorized
  on both matters cannot aggregate financial data across clients in a single query.

New classes:
- `MatterScope` — authorized access boundary for a matter research session (analogous to
  `StudentIdentityScope` for FERPA)
- `MatterScopeFilter` — ABA Rule 1.6 scope enforcement with `LegalAuditRecord` emission
- `ConflictChecker` — ABA Rule 1.7/1.9 adverse-party scanner; halts retrieval on conflict
- `Rule1_15Filter` — cross-matter financial isolation filter
- `LegalAuditRecord` — audit record capturing matter_id, requester, privilege_tags_blocked,
  conflict_parties_detected, ABA rules invoked, outcome

Scenarios:
- A: Authorized associate queries own matter → full retrieval (ALLOW)
- B: Paralegal queries matter they're not on → privileged documents blocked (Rule 1.6)
- C: Query returns document mentioning adverse party → retrieval halted (Rule 1.7)
- D: Billing partner cross-matter financial query → Rule 1.15 isolation applied

Closes #31.

---

## [0.8.5] — 2026-04-13

### Added — Financial Services RAG Example (PCI DSS + GLBA)

**`examples/13_financial_services_rag.py`** — defense-in-depth RAG pipeline for a
wealth management chatbot combining PCI DSS v4.0 and GLBA Safeguards Rule compliance:
- Three-layer defense model: OWASP LLM01 injection scan → GLBA NPI purpose limitation
  → PCI DSS PAN masking + cardholder data category enforcement
- Scenario A: authorized wealth advisor — all 5 docs pass; raw PAN masked to `[PAN-MASKED]`
- Scenario B: PAN masking demonstration — `4532-0151-2345-6789` replaced before LLM context
- Scenario C: unauthenticated user (no authorized purposes) — GLBA blocks 4/5 NPI docs;
  only public market research reaches the LLM
- Scenario D: prompt injection attempt — OWASP LLM01 scanner halts pipeline before retrieval
- Compliance audit summary: GLBA/PCI audit events, OWASP scan events, total PAN masked
- Defense-in-depth layer map with PCI DSS Req and GLBA § references
- Closes #30.

---

## [0.8.4] — 2026-04-13

### Added — Cross-Channel Session Continuity Example

**`examples/12_cross_channel_session.py`** — 6-step `SessionState` lifecycle across
IVR voice → web chat → email → chat:
- `register_channel` tracks the full interaction path (IVR → chat → email)
- `add_checkpoint` records intents and actions; chat replays IVR context without
  re-asking identity or intent
- `escalated` flag set on withdrawal request — monotonically True, all channels
  route to human thereafter
- `ContextEnvelope` packages escalation handoff for human advisor with channel_path,
  escalation_reason, and checkpoint count
- Five session continuity design principles
- Closes #1.

---

## [0.8.3] — 2026-04-13

### Added — Multi-Source Context Assembly Example

**`examples/11_context_assembly.py`** — assembles `ContextEnvelope` from five enterprise
data sources (SIS, financial aid, knowledge base, policy docs, real-time data) with
FERPA pre-filtering and freshness enforcement:
- Scenario 1: enrollment advisor scope (ACADEMIC_RECORD only) — 2 financial docs filtered
- Scenario 2: financial aid advisor scope (academic + financial) — all docs available
- Scenario 3: cross-institution contamination test — `acme-univ-b` doc blocked despite correct student_id
- Freshness enforcement: SIS ≤ 1h, real-time ≤ 60s; stale sources excluded and logged
- `ContextEnvelope` metadata tracks source count, pre/post filter counts, FERPA removals
- LLM context string formatting via `to_llm_context()`
- Closes #2.

---

## [0.8.2] — 2026-04-13

### Added — Human Escalation Policy Example

**`examples/10_escalation_policy.py`** — `ActionPolicy` and `EscalationRule` applied to an
enrollment advisor agent with three escalation trigger types:
- **Regulatory triggers**: `submit_withdrawal`, `process_financial_aid_change`, `override_academic_hold`,
  `release_pii_export` — always route to human regardless of confidence
- **Content-based triggers**: `disciplinary`, `financial hardship`, `legal dispute`, `grievance`, `deceased`
  keywords in retrieved context trigger required human handoff
- **Confidence thresholds**: `REQUIRED` < 50% (agent cannot respond), `SOFT` < 75%
  (agent may attempt with human available)
- **Audit trail**: `EscalationEvent` records which rule triggered each escalation
- **FERPA-correct message**: agent never discloses escalation reason to user (34 CFR § 99.12)
- Closes #3.

---

## [0.8.1] — 2026-04-13

### Added — Vector Store Integration Examples

**`examples/09_vector_store_adapters.py`** — end-to-end showcase of all four
compliance filter adapters applied to the same `ComplianceFilter` input:

- **pgvector / psycopg2 (JSONB column):** `metadata->>'student_id' = %s AND ... = ANY(%s)`
- **pgvector / psycopg2 (normalised columns):** `student_id = %s AND ...`
- **pgvector / asyncpg:** `$N`-style placeholders with `::text[]` cast
- **Pinecone v8:** `{"$and": [{"student_id": {"$eq": "..."}}, ...]}`
- **ChromaDB v1.5+:** `{"$and": [{"student_id": {"$eq": "..."}}, ...]}`
- **Weaviate v4:** `Filter.by_property(...).equal(...) & ...` (lazy import)
- **No-category-restriction variant** (HIPAA treatment authorization — no `$in` clause generated)

Shows full usage patterns including FastAPI async (Pinecone `IndexAsyncio`),
defense-in-depth namespace + metadata isolation, and correct query construction
with the compliance filter appended to the embedding parameter tuple.
Closes #5.

---

## [0.8.0] — 2026-04-13

### Added

- `integrations/dspy.py`: `FERPADSPyRetriever` and `HIPAADSPyRetriever` — DSPy
  retriever wrappers that apply FERPA identity-scope filtering and HIPAA
  minimum-necessary filtering respectively (DSPy ≥ 2.5.0, Pydantic v2).

  **`FERPADSPyRetriever`**:
  - Wraps any DSPy ``Retrieve`` module or compatible callable.
  - Intercepts retrieved passages and runs them through
    ``FERPAContextPolicy.filter_retrieved_documents()``.
  - Passages tagged to a different student, institution, or unauthorized category
    are silently removed — consistent with FERPA's prohibition on disclosing which
    records were withheld (34 CFR § 99.12).
  - ``__getattr__`` delegation — DSPy pipeline composition and introspection
    work transparently through the wrapper.
  - Used exactly like the original retriever in a DSPy ``Module.forward()`` method.

  **`HIPAADSPyRetriever`**:
  - Same pattern; applies ``HIPAAContextPolicy.filter_retrieved_documents()``
    (45 CFR § 164.502(b) minimum-necessary) before passages reach the LLM.

  Closes #14, #10. 31 new tests.

- `integrations/__init__.py`: exports `FERPADSPyRetriever`, `HIPAADSPyRetriever`.

---

## [0.7.0] — 2026-04-13

### Added

- `regulations/eu_ai_act.py`: `EUAIActAuditLogger`, `EUAIActRetrievalRecord`,
  `EUAIActRiskTier`, `AnnexIIICategory`, `classify_annex_iii_risk`,
  `SYSTEM_AI_DISCLOSURE` — EU AI Act 2024/1689 Article 12 tamper-evident audit
  log for high-risk RAG systems.

  **Article 12 capabilities:**
  - `EUAIActAuditLogger` captures the full chain-of-custody per retrieval event:
    query hash → retrieved document IDs → context window hash → response hash.
  - Every record is **HMAC-SHA256 signed** (tamper-evidence). `verify_record()`
    re-computes the HMAC; a mismatch means the record was altered after creation.
  - Records are **hash-chained**: each record's `previous_record_hash` is the
    SHA-256 of the preceding record. `verify_chain()` detects insertions,
    deletions, and reordering.
  - `seal_response(record, response_text)` seals the model response into an
    existing record (creates a new immutable record with updated HMAC).
  - `include_query_preview=False` by default — storing cleartext queries requires
    a lawful basis under GDPR Art. 6.
  - `to_log_entry()` serialises to a JSON-safe dict for append-only log stores
    (AWS CloudTrail, Azure Immutable Blob, Google Cloud Audit Logs).

  **Annex III risk classification:**
  - `AnnexIIICategory` enum maps to Annex III §1–§8 use case categories.
  - `classify_annex_iii_risk(category)` returns the risk tier and plain-English
    rationale citing the relevant Annex III section.
  - Education AI (§3), employment AI (§4), law enforcement AI (§6), etc. all
    return `EUAIActRiskTier.HIGH_RISK`.

  **Art. 13 transparency:** `SYSTEM_AI_DISCLOSURE` constant for human-facing
  disclosure that responses were generated by an AI system.

  Penalty context: up to €35M or 7% of global annual revenue for Art. 12
  non-compliance (Art. 99(3)).  Closes #28.  55 new tests.

- `regulations/__init__.py`: exports all 6 EU AI Act symbols; updated
  cross-industry module table with EU AI Act entry.

---

## [0.6.0] — 2026-04-13

### Added

- `vector_stores/pgvector_adapter.py`: `PGVectorComplianceFilter` and
  `PGVectorSQLAlchemyFilter` — compliance-scoped filter adapters for PostgreSQL
  with the `pgvector` extension, the most common enterprise vector store.

  **`PGVectorComplianceFilter`** builds SQL `WHERE` clause fragments + parameterised
  argument tuples for direct database drivers:
  - `build_filter()` — psycopg2 `%s` placeholders; supports both JSONB metadata
    column (`metadata->>'student_id' = %s … AND metadata->>'category' = ANY(%s)`)
    and normalised column (`student_id = %s … AND category = ANY(%s)`) schemas.
  - `build_asyncpg_filter()` — asyncpg `$N` positional placeholders with explicit
    `::text[]` cast for array parameters (`= ANY($3::text[])`).
  - Configurable column / field names (`metadata_column_name`, `student_id_field`,
    `institution_id_field`, `category_field`).
  - Categories sorted deterministically in all output parameter lists.

  **`PGVectorSQLAlchemyFilter`** builds a `sqlalchemy.sql.ColumnElement` boolean
  expression for SQLAlchemy ORM / Core queries (recommended for FastAPI apps):
  - JSONB column mode: `metadata_col["key"].as_string() == value` with `or_()`
    for multi-category matching.
  - Normalised column mode: `col == value` / `col.in_(sorted_categories)`.
  - `sqlalchemy` import is lazy — the module can be imported without SQLAlchemy
    installed; `ImportError` is raised only when `build_filter()` is called.
  - `ValueError` raised at construction time if neither `metadata_column` nor
    the `student_id_column + institution_id_column` pair is provided.

  Satisfies FERPA 34 CFR § 99.3 pre-filter requirement: SQL `WHERE` clauses applied
  before the `<=>` (cosine distance) ranking step guarantee identity scoping at the
  query layer. Closes #16, #9. 31 new tests (29 passing + 2 skipped when SQLAlchemy
  not installed).

- `vector_stores/__init__.py`: exports `PGVectorComplianceFilter`,
  `PGVectorSQLAlchemyFilter`; updated module docstring.

---

## [0.5.3] — 2026-04-12

### Added

- `regulations/glba.py`: `GLBAContextPolicy`, `GLBAAccessContext`, `GLBAAccessScope`,
  `GLBADataCategory`, `GLBAAuditRecord` — GLBA Safeguards Rule (16 CFR § 314) NPI access
  control for RAG pipelines.  Three independent controls applied per document:
  (1) **§ 314.3** institution isolation — documents from other financial institutions are
  blocked unconditionally;
  (2) **§ 314.4(e)** purpose limitation — NPI categories (`NONPUBLIC_PERSONAL`,
  `ACCOUNT_DATA`, `TRANSACTION_HISTORY`, `CREDIT_INFORMATION`) require the actor's declared
  purpose to be in their authorized purposes set;
  (3) **§ 314.4(i)** marketing-role restriction — `CREDIT_INFORMATION` and
  `TRANSACTION_HISTORY` are always blocked for marketing-role actors regardless of purpose.
  `GLBAAccessScope.permits()` helper for pre-validated scope checks.
  SHA-256 tamper-evident `GLBAAuditRecord` with `content_hash()` (§ 314.4(h) monitoring).
  56 new tests.
- `regulations/__init__.py`: exports all five GLBA symbols; updated cross-industry module
  table and docstring with GLBA Safeguards Rule entry.

---

## [0.5.2] — 2026-04-13

### Added

- `regulations/iso27001.py`: `ISMSContextPolicy`, `ISMSAccessContext`, `ISMSClassification`,
  `ISMSAuditRecord` — ISO/IEC 27001:2022 ISMS context-based access control (CBAC) for RAG
  pipelines.  Three independent controls applied per document:
  (1) **A.5.15** organization isolation — tenant boundary enforcement;
  (2) **A.5.12 / A.8.12** classification enforcement — PUBLIC/INTERNAL/CONFIDENTIAL/SECRET
  label hierarchy with fail-safe unknown-label blocking;
  (3) **A.8.2** role-based access — per-document `required_roles` intersection check.
  SHA-256 tamper-evident `ISMSAuditRecord` (A.8.15). 44 new tests.
- `regulations/pci_dss.py`: `PCIContextPolicy`, `PCIAccessScope`, `PCIDataCategory`,
  `PCIAuditRecord` — PCI DSS v4.0 access control and PAN masking for RAG pipelines.
  Three controls:
  (1) **Req 7.2** merchant isolation — per-merchant tenant boundary;
  (2) **Req 7.2.1** category need-to-know — CARDHOLDER_DATA and SENSITIVE_AUTH_DATA require
  explicit authorization; unknown categories default to NON_CHD (permissive, outside PCI scope);
  (3) **Req 3.4** PAN masking — `\\b(?:\\d{{4}}[- ]?){{3}}\\d{{4}}\\b` → `[PAN-MASKED]` in all
  string-valued document fields.  `last_pan_masked_count` property tracks aggregate substitution
  count.  SHA-256 tamper-evident `PCIAuditRecord` (Req 10.3). 37 new tests.
- `regulations/__init__.py`: exports all ISO 27001 and PCI DSS symbols; updated cross-industry
  module table with IT audit / security framework categorisation.

---

## [0.5.1] — 2026-04-13

### Added

- `regulations/soc2.py`: `SOC2ContextPolicy`, `SOC2AccessContext`, `SOC2ConfidentialityTier`,
  `SOC2AuditRecord` — SOC 2 Type II context-based access control (CBAC) for RAG pipelines.
  Three-layer defense-in-depth:
  (1) **CC6.1** tenant isolation — documents outside the authorized tenant boundary are blocked
  unconditionally;
  (2) **C1.1/C1.2** confidentiality tier — PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED label
  enforcement with fail-safe unknown-tier blocking;
  (3) **CC6.6** role-based access — role intersection check on per-document `required_roles`
  fields.  SHA-256 tamper-evident `SOC2AuditRecord` with `content_hash()`. 28 new tests. Closes #27.
- `regulations/__init__.py`: exports all four SOC 2 symbols; updated cross-industry table
  in module docstring.

---

## [0.5.0] — 2026-04-12

### Added — Cross-Industry Compliance Framework

This release expands `enterprise-rag-patterns` from a single-regulation library
(FERPA) into a **cross-industry compliance framework** for RAG pipelines. New
regulation modules apply to healthcare, government, software, and any sector
requiring governed AI.

- `regulations/hipaa.py`: `HIPAAContextPolicy`, `HIPAAAccessScope`, `HIPAAPurpose`,
  `HIPAAAuditRecord` — HIPAA minimum-necessary enforcement (45 CFR § 164.502(b))
  for ePHI retrieval. Three-layer filter: patient identity, HIPAA purpose
  (treatment/payment/operations/research), PHI category. SHA-256 tamper-evident
  audit records per 45 CFR § 164.312(b). Closes #27.

- `regulations/nist_ai_rmf.py`: `AIRMFRAGPolicy`, `AIRMFRetrievalRisk`,
  `AIRMFAuditRecord`, `AIRMFRiskLevel`, `AIRMFFunction` — NIST AI RMF 1.0
  (NIST AI 100-1) + Generative AI Profile (NIST AI 600-1) risk assessment for
  RAG events. MAP/MEASURE/MANAGE function coverage: PII exposure scoring,
  confabulation risk from relevance scores, incident tracking. Closes #28.

- `regulations/owasp_llm.py`: `OWASPSensitiveDisclosureFilter` (LLM02:2025),
  `OWASPPromptInjectionScanner` (LLM01:2025), `OWASPLLMRisk`, `OWASPAuditRecord`
  — OWASP LLM Top 10 (2025 edition) security controls. Redact/block mode for
  PII fields; pattern-based prompt injection detection with quarantine support.
  Closes #29.

- `regulations/__init__.py`: updated to export all 3 new modules alongside
  existing GDPR patterns; compliance table in module docstring.

- `py.typed` marker (PEP 561) — enables mypy/pyright type inference for consumers.

### Fixed
- `pyproject.toml`: `pinecone>=5.0.0` → `>=8.0.0` (IndexAsyncio requires v8).
- `integrations/langchain_lcel.py`: `FERPAFilterRunnable` now exposes `invoke()`
  and `ainvoke()` satisfying the LangChain duck-typed Runnable protocol.
- GitHub Actions: `actions/checkout@v6` → `@v4`, `setup-python@v6` → `@v5`
  (v6 does not exist; jobs silently failed on version resolution).

---

## [0.4.2] — 2026-04-13

### Added
- `vector_stores/pinecone_adapter.py`: `PineconeNamespaceIsolation` — defense-in-depth adapter for Pinecone v8 multi-institution deployments. Layer 1: maps `institution_id` → Pinecone namespace (hardware isolation, cross-institution queries structurally impossible). Layer 2: adds `student_id` metadata filter (software isolation). Supports both sync (`query_sync`) and async (`async_query` via `IndexAsyncio`) Pinecone v8 clients. Custom `namespace_resolver` callable for institution-ID-to-namespace mapping. Closes #26.
- `vector_stores/__init__.py`: exports `PineconeNamespaceIsolation`

---

## [0.4.1] — 2026-04-13

### Added
- `integrations/langchain_lcel.py`: `FERPAFilterRunnable` — LangChain LCEL step that makes FERPA filtering an explicit `Runnable` in the `|` pipe chain. Supports per-request scope injection via `RunnableConfig["metadata"]["ferpa_scope"]`. Closes #25.
- `integrations/langchain_lcel.py`: `make_ferpa_chain()` — factory that wires `retriever | FERPAFilterRunnable | prompt | llm [| output_parser]` in one call.
- `integrations/__init__.py`: exports `FERPAFilterRunnable`, `make_ferpa_chain`

### Fixed
- `integrations/llama_index_workflow.py`: ruff format fix (whitespace normalization)

---

## [0.4.0] — 2026-04-12

### Added
- `integrations/maf.py`: `FERPAAgentMiddleware` — Microsoft Agent Framework (MAF) middleware intercepting agent tool-call messages, applying FERPA identity-scope filtering, emitting 34 CFR § 99.32 audit records. MAF is the enterprise-ready successor to AutoGen and Semantic Kernel (released 2026).
- `integrations/llama_index_workflow.py`: `FERPAWorkflowStep` + `FERPAFilterEvent` — LlamaIndex 0.12+ event-driven Workflow step enforcing FERPA scoping between retrieval and synthesis steps. Compatible with `llama-index-core>=0.12.0` (current: 0.14.20).
- New `[maf]` optional dependency: `microsoft-agent-framework>=1.0.0`

### Changed
- Bumped ecosystem compatibility pins:
  - `llama-index-core`: `>=0.10.0` → `>=0.12.0` (LlamaIndex 0.14.20 current)
  - `haystack-ai`: `>=2.0.0` → `>=2.20.0` (Haystack 2.27.0 current)
  - `pinecone`: `>=3.0.0` → `>=5.0.0` (Pinecone 8.1.2 current; v5 required for async API)
  - `weaviate-client`: `>=4.0.0` → `>=4.10.0` (Weaviate 4.20.5 current)
  - `chromadb`: `>=0.5.0` → `>=1.0.0` (ChromaDB 1.5.7 current; v1.0 is GA)
- `integrations/__init__.py`: exports `FERPAAgentMiddleware`, `FERPAWorkflowStep`, `FERPAFilterEvent`
- `pyproject.toml`: version bumped to 0.4.0; `[all]` extra now includes `[maf]`

---

## [0.3.0] — 2026-04-12

### Added
- Enhanced CI: coverage reporting (Codecov), ruff format check, build-check job, pip cache, concurrency cancellation
- Automation: PR auto-labeler, stale bot, Conventional Commits PR title check, first-contributor welcome bot
- Dependabot; CODEOWNERS; SECURITY.md; pre-commit config; automated release notes
- `integrations/langchain.py`: `FERPAComplianceCallbackHandler` — LangChain callback handler intercepting `on_retriever_end`, applying identity-scope filtering in-place, emitting 34 CFR § 99.32 audit records
- LangChain added as `[langchain]` optional dependency (`langchain-core>=0.3.0`)
- ADRs: `docs/adr/004-pydantic-v2-data-models.md`
- README: badge row, FERPA pipeline ASCII diagram, ecosystem integration table, 60-second quickstart, regulations table, BibTeX citation
- GitHub Discussions enabled; 22 standardized labels (type/*, priority/*, status/*, area/*); milestones v0.3.0 + v1.0.0

---

## [0.2.0] - 2026-04-11

### Added

**Vector store filter adapters** (`src/enterprise_rag_patterns/vector_stores/`):
- `base.py` — `ComplianceFilter` dataclass and `VectorStoreFilterAdapter` ABC; portable filter specification for compliance-scoped vector queries
- `pinecone_adapter.py` — `PineconeComplianceFilter`: builds Pinecone v8 metadata filter dict (`$and` / `$eq` / `$in`) for FERPA/HIPAA scoping
- `weaviate_adapter.py` — `WeaviateComplianceFilter`: builds Weaviate v4 `Filter` object using `Filter.by_property().equal()` and `&` combinator; lazy import
- `qdrant_adapter.py` — `QdrantComplianceFilter`: builds Qdrant `Filter` with `FieldCondition` / `MatchValue` / `MatchAny`; lazy import
- `chroma_adapter.py` — `ChromaComplianceFilter`: builds ChromaDB `where` dict with `$and` / `$eq` / `$in` operators

**Framework integrations** (`src/enterprise_rag_patterns/integrations/`):
- `llama_index.py` — `FERPANodePostprocessor`: LlamaIndex `BaseNodePostprocessor` enforcing student identity scoping; emits 34 CFR § 99.32 audit log entries
- `haystack.py` — `FERPAHaystackFilter`: Haystack 2.x `@component` filtering documents on `meta["student_id"]` and `meta["institution_id"]`; lazy import with `_make_haystack_component()` for pipeline serialisation

**GDPR regulation module** (`src/enterprise_rag_patterns/regulations/`):
- `gdpr.py` — GDPR Article 17 RAG-layer erasure patterns: `ErasureRequest`, `ErasureAuditRecord`, `GDPRRAGPolicy`; supports `filter_for_subject`, `record_erasure`, and `to_log_entry`
- `__init__.py` — exports all GDPR symbols

**Async compliance** (`src/enterprise_rag_patterns/async_compliance.py`):
- `async_filter_retrieved_documents` — async wrapper for `FERPAContextPolicy.filter_retrieved_documents`
- `async_record_access` — async wrapper for `FERPAContextPolicy.record_access`
- Async-wrapper pattern: `await asyncio.sleep(0)` yields to event loop then delegates to synchronous implementation — compatible with all async AI frameworks

**Tests**:
- `tests/test_vector_store_adapters.py` — full coverage of all four adapters; verifies filter structure without real vector store connections
- `tests/test_gdpr.py` — covers `ErasureRequest`, `GDPRRAGPolicy.filter_for_subject`, `record_erasure`, `to_log_entry`
- `tests/test_integrations.py` — covers `FERPAHaystackFilter` and `FERPANodePostprocessor` with duck-typed stubs; no framework import required
- `tests/test_async_compliance.py` — covers `async_filter_retrieved_documents` and `async_record_access` via `asyncio.run`

**Open-source contribution infrastructure**:
- `CONTRIBUTING.md` — comprehensive guide: dev setup, how to add adapters/regulations/integrations, PR checklist with regulatory citation requirement
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1
- `ECOSYSTEM.md` — compatibility matrix for vector stores, frameworks, and regulations
- `.github/ISSUE_TEMPLATE/new-vector-store.md` — issue template for new vector store adapters
- `.github/ISSUE_TEMPLATE/new-regulation.md` — issue template for new regulation modules
- `.github/ISSUE_TEMPLATE/new-framework-integration.md` — issue template for new framework integrations

**Package configuration**:
- `pyproject.toml` — version bumped to `0.2.0`; added optional dependency groups: `llama-index`, `haystack`, `pinecone`, `weaviate`, `qdrant`, `chromadb`, `all`

---

## [0.1.0] — 2026-04-11

### Added

**Core modules:**
- `context.py` — `ContextEnvelope` and `ContextSource` for context assembly across multiple source systems
- `session.py` — `SessionState` for cross-channel continuity (web, voice, messaging, dashboard)
- `policy.py` — `ActionPolicy` and `EscalationRule` for workflow-safe action boundaries and human escalation
- `compliance.py` — FERPA-aware context governance:
  - `StudentIdentityScope` — defines retrieval boundary per student and institution
  - `FERPAContextPolicy` — two-layer enforcement (pre-filter + category authorization)
  - `AuditRecord` — structured 34 CFR § 99.32 disclosure logging
  - `make_enrollment_advisor_policy` — factory for the most common higher-education RAG use case

**Documentation:**
- `docs/architecture.md` — layered architecture overview with design principles
- `docs/implementation-note-01.md` — cross-channel continuity problem and solution
- `docs/implementation-note-02.md` — FERPA boundaries in retrieval-augmented generation
- `docs/articles/production-grade-rag-in-regulated-enterprise-environments.md`
- `docs/case-study-anonymized.md` — anonymized production deployment notes

**Examples:**
- `examples/context-pipeline.yaml` — declarative context assembly reference
- `examples/ferpa_rag_pipeline.py` — complete runnable FERPA-compliant four-layer RAG pipeline

**Project infrastructure:**
- `CITATION.cff` — enables GitHub "Cite this repository" button
- `CONTRIBUTING.md` — contribution guidance
- `GOVERNANCE.md` — project governance model
- `ROADMAP.md` — near-term development direction
- `pyproject.toml` — setuptools build configuration with keywords, classifiers, and optional dependency groups
- GitHub Actions CI: pytest (Python 3.10–3.12), ruff lint, mypy type check
- Issue templates: bug report, feature request
- 85 passing tests covering all public module APIs
