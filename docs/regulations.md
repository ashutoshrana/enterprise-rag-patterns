# Regulation Coverage — enterprise-rag-patterns

This page maps each regulation to its implementing example, the document metadata fields it inspects, and the audit record format it produces.

---

## United States

### FERPA — Family Educational Rights and Privacy Act (34 CFR Part 99)

**Sector:** Higher Education  
**Examples:** `01_basic_ferpa_filter.py`, `02_multi_student_isolation.py`, `03_langchain_handler.py`, `04_lcel_ferpa_chain.py`  
**Standalone package:** [`ferpa-haystack`](https://github.com/ashutoshrana/ferpa-haystack)

**What it enforces:**
- Identity-scope pre-filter: only documents belonging to the authorized student (`student_id` + `institution_id`) pass through
- Record category authorization: `ACADEMIC_RECORD`, `FINANCIAL_AID`, `DISCIPLINARY`, `HEALTH`, `DIRECTORY`
- Disclosure reason validation: must be one of the §99.31 exceptions (school official, judicial order, etc.)
- 34 CFR §99.32 disclosure log: every access produces a structured audit record

**Document metadata fields:**
```python
{
    "student_id": "stu_001",           # required for FERPA filter
    "institution_id": "univ_abc",      # required for cross-institution blocking
    "category": "academic_record",     # RecordCategory enum value
}
```

Documents without `student_id` (course catalogues, policy handbooks) pass through unchanged.

**Audit record:**
```
[FERPA_DISCLOSURE] student_id='stu_001' institution_id='univ_abc'
requesting_user_id='advisor_007' categories_disclosed=['academic_record']
disclosure_reason='SCHOOL_OFFICIAL' disclosed_at='2026-04-17T09:23:41Z'
regulation_citation='34 CFR §99.32'
```

---

### HIPAA — Health Insurance Portability and Accountability Act (45 CFR §164)

**Sector:** Healthcare  
**Examples:** `05_hipaa_rag_pipeline.py`, `24_clinical_trials_rag.py`, `25_digital_health_rag.py`

**What it enforces:**
- Minimum necessary standard (45 CFR §164.502): only PHI categories required for the treatment purpose
- 18 Safe Harbor PHI identifiers detected and blocked from LLM context
- ePHI audit log (45 CFR §164.312(b))

**PHI categories:** `CLINICAL_NOTE`, `LAB_RESULT`, `PRESCRIPTION`, `RADIOLOGY`, `DEMOGRAPHIC`, `BILLING`, `MENTAL_HEALTH`, `SUDs_RECORDS` (42 CFR Part 2 special category)

---

### OWASP LLM Top 10 (2025)

**Sector:** All sectors  
**Example:** `06_owasp_security_scan.py`

**Controls implemented:**
- **LLM01 Prompt Injection:** Detects direct and indirect injection patterns in retrieved documents before they enter the LLM context
- **LLM02 Insecure Output Handling:** PII and credential detection in retrieval results
- **LLM06 Sensitive Information Disclosure:** Classification marker and data leakage prevention
- **LLM08 Embedding Weakness:** Poisoned vector payload detection

---

### GLBA — Gramm-Leach-Bliley Act (15 USC §§6801–6809)

**Sector:** Financial Services  
**Example:** `27_financial_services_rag.py`

**What it enforces:**
- Consumer financial data scoped to account holder only
- NPI (Non-Public Personal Information) category access control
- SEC Regulation S-P (17 CFR Part 248) privacy notice compliance

---

### NERC CIP (CIP-004/005/011/013)

**Sector:** Energy / Utilities  
**Examples:** `28_energy_utilities_rag.py`, `43_energy_nerc_cip_rag.py`

**What it enforces:**
- BES Cyber System (BCS) documentation access control
- Electronic Security Perimeter (ESP) authorization check
- FERC CEII (18 CFR §388.113) — Critical Energy Infrastructure Information tipping-off prohibition
- NRC 10 CFR §73.21 — Nuclear SGI tipping-off prohibition

---

### FedRAMP + FISMA + CUI

**Sector:** Government / Federal  
**Example:** `29_government_public_sector_rag.py`

**What it enforces:**
- CUI 32 CFR Part 2002 category access (FOUO/LES/Privacy Act/EAR)
- NIST SP 800-53 Rev. 5 AC-3 (Access Enforcement) / AC-4 (Information Flow)
- Privacy Act 5 USC §552a record access control

---

### ITAR/EAR (Defense / Export Controls)

**Sector:** Defense / Aerospace  
**Example:** `44_defense_itar_ear_rag.py`

**What it enforces:**
- ITAR 22 CFR Parts 120–130: USML technical data access control
- EAR 15 CFR Parts 730–774: CCL Military End Use § 744.21
- CFIUS 50 U.S.C. §4565: defense contractor acquisition gating
- NATO classified + FVEY bilateral protocols

---

## European Union

### GDPR — General Data Protection Regulation

**Example:** Referenced in examples 31–36 for cross-border adequacy

**What it enforces:**
- Art. 5 data minimisation
- Art. 6 lawful basis for processing
- Art. 17 right to erasure (pre-filter blocks erasure-flagged records)
- Art. 46 standard contractual clauses for cross-border transfers

---

## International

### Brazil — LGPD (Law 13.709/2018)

**Example:** `31_brazil_lgpd_rag.py`

Art. 7/11/15/18/33 — legal basis, sensitive data consent, data subject rights, cross-border adequacy.

### South Korea — PIPA + Korea AI Framework Act

**Example:** `32_south_korea_rag.py`

PIPA Art. 15/16/23 (legal basis + sensitive data consent) + Korea AI Framework Act Art. 6 high-impact AI transparency.

### Canada — PIPEDA + Québec Law 25

**Example:** `37_canada_pipeda_rag.py`

PIPEDA Principles 3/4.3 + CPPA Bill C-27 §15/§62, Québec Law 25 §8/§12.1/§63.3.

---

## Regulation index

| Regulation | Jurisdiction | Example |
|------------|-------------|---------|
| FERPA 34 CFR Part 99 | US Education | 01–04 |
| HIPAA 45 CFR §164 | US Healthcare | 05, 24, 25 |
| OWASP LLM Top 10 (2025) | All | 06, 49 |
| SOC 2 Type II CC6.1/C1.1 | SaaS | 07 |
| NIST AI RMF 1.0 + AI 600-1 | All | 08 |
| CCPA / CPRA Cal. Civ. Code §1798 | US Consumer | 18, 39 |
| 21 CFR Part 11 (FDA GxP) | Pharma | 19, 24, 45 |
| GLBA 15 USC §§6801–6809 | US Financial | 27, 40 |
| SEC Regulation S-P 17 CFR §248 | US Financial | 27, 40 |
| NERC CIP-004/005/011/013 | US Energy | 28, 43 |
| FedRAMP / FISMA | US Government | 29 |
| CUI 32 CFR Part 2002 | US Government | 29 |
| CPNI 47 CFR §64 | US Telecom | 30, 48 |
| LGPD Law 13.709/2018 | Brazil | 31 |
| PIPA + Korea AI Framework Act | South Korea | 32 |
| NAIC Model Privacy Protection Act | US Insurance | 33 |
| GDPR Art. 5/6/17/46 | EU / EEA | 31–37 |
| PIPEDA + CPPA + Québec Law 25 | Canada | 37 |
| Colorado CPA / Virginia CDPA | US State | 39 |
| ITAR 22 CFR Parts 120–130 | US Defense | 44 |
| EAR 15 CFR Parts 730–774 | US Defense | 44 |
| 10 CFR Part 50 (NRC) | US Nuclear | 46 |
| IMO SOLAS / MARPOL / ISPS | Maritime | 47 |
| OWASP LLM Top 10 + ASI 2026 | Agentic AI | 49, 50 |
