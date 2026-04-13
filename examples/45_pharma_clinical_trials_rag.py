"""
Pharmaceutical / Clinical Trials Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to pharmaceutical drug development, clinical trial
operations, regulatory submissions, and cross-border pharmaceutical data flows.
Four independent filter layers run sequentially; a document must pass all four
to be returned to the caller.

Commercial use cases:

  +----------------------------------------------------------+------------------------------------------+
  | Platform / Product                                       | Applicable Regulation(s)                 |
  +----------------------------------------------------------+------------------------------------------+
  | IND/NDA/BLA regulatory submission management            | FDA 21 CFR Parts 312, 314, 601           |
  | Clinical trial management systems (CTMS)                | ICH E6 R2/R3 GCP; 21 CFR Part 56        |
  | Drug manufacturing and CGMP compliance platforms         | FDA 21 CFR Parts 210/211 CGMP            |
  | Clinical investigator qualification systems             | ICH E6 §4.1; 21 CFR §312.53             |
  | SAE reporting and signal management platforms            | ICH E6 §4.11.1; 21 CFR §312.32          |
  | EU clinical trial authorization / EudraCT platforms     | EU CTR 536/2014 Art. 5/6; EudraCT       |
  | Pediatric clinical trial management platforms            | EU Pediatric Reg. 1901/2006 Art. 7 PIP  |
  | EMA centralized procedure submission platforms           | Regulation 726/2004 Art. 3               |
  | GDPR-compliant clinical research data management         | GDPR Art. 9(2)(j) research exception     |
  | Cross-border clinical data / pharmacovigilance           | ICH E6 §5.15; GDPR Art. 46 SCC          |
  | Controlled substance regulatory compliance               | 21 U.S.C. §812 DEA; Single Convention    |
  | Biosimilar reference product regulatory analysis         | FDA-EMA parallel scientific advice       |
  +----------------------------------------------------------+------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — FDADrugDevelopmentFilter
      (U.S. Food and Drug Administration Drug Development Regulations;
       administered by FDA Center for Drug Evaluation and Research (CDER)
       and Center for Biologics Evaluation and Research (CBER))
      Controls access to documents containing IND application data, NDA
      submission data, BLA manufacturing and quality data, and drug
      manufacturing CGMP compliance information.

      FDA 21 CFR Part 312 IND Safety Reporting + Protocol Amendments +
      Sponsor Obligations: Investigational New Drug application data
      without 21 CFR Part 312 compliance — including IND safety reporting
      obligations (§312.32), protocol amendment requirements (§312.30),
      and sponsor obligations (§312.50) — may not be processed in RAG
      pipelines.  IND data without confirmed Part 312 compliance is denied.

      FDA 21 CFR Part 314 NDA Submission + Labeling + Manufacturing —
      Complete Response Requirements: New Drug Application data submitted
      without meeting 21 CFR Part 314 complete response requirements —
      including NDA submission content (§314.50), labeling requirements
      (§314.70), and manufacturing change controls (§314.70) — may not be
      processed.  NDA data without confirmed Part 314 complete response
      compliance is denied.

      FDA 21 CFR Part 601 BLA Manufacturing + Characterization + Quality:
      Biologics License Application data involving biological product
      manufacturing, characterization, and quality controls without 21 CFR
      Part 601 compliance — including establishment license requirements
      (§601.2), manufacturing standards (§601.12), and lot release
      procedures (§601.20) — may not be processed.  BLA data without
      confirmed Part 601 compliance is denied.

      FDA CGMP 21 CFR Parts 210/211 — Drug Manufacturing CGMP Compliance
      Verification: Drug manufacturing data involving facilities, equipment,
      records, and procedures without Current Good Manufacturing Practice
      compliance under 21 CFR Parts 210 (current good manufacturing
      practice in manufacturing, processing, packing, or holding of drugs)
      and 211 (current good manufacturing practice for finished
      pharmaceuticals) requires human review to verify CGMP status.
      Drug manufacturing data without confirmed CGMP compliance is
      escalated to REQUIRES_HUMAN_REVIEW.

  Layer 2 — ICHGCPFilter
      (International Council for Harmonisation Good Clinical Practice
       ICH E6 R2 / R3; implemented in the United States via 21 CFR
       Part 56 — Institutional Review Boards and 21 CFR Part 50 —
       Protection of Human Subjects)
      Controls access to clinical trial documents lacking IRB/IEC approval,
      informed consent data missing required elements, clinical investigator
      qualification records, and serious adverse event (SAE) expedited
      reporting documentation.

      ICH E6 §3.1 IRB/IEC Responsibilities + 21 CFR Part 56 — IRB/IEC
      Approval Documentation: All clinical trial data must be supported by
      documented IRB (Institutional Review Board) or IEC (Independent
      Ethics Committee) approval in accordance with ICH E6 §3.1 and
      21 CFR Part 56.  Clinical trial data without confirmed IRB/IEC
      approval documentation is denied.

      ICH E6 §4.8.10 Informed Consent Elements — Required Elements
      Documentation: Informed consent documentation must contain all
      required elements specified in ICH E6 §4.8.10 and 21 CFR §50.25,
      including the nature of the study, foreseeable risks and benefits,
      available alternatives, confidentiality protections, compensation
      for injury, and voluntary participation statement.  Informed consent
      documentation lacking confirmed required elements is denied.

      ICH E6 §4.1 Investigator Qualifications + Protocol Adherence:
      Clinical investigator data must demonstrate that investigators are
      qualified by education, training, and experience to assume
      responsibility for the proper conduct of the clinical investigation
      under ICH E6 §4.1 and must include protocol adherence records.
      Clinical investigator data without confirmed ICH E6 §4.1
      qualification and agreement documentation is denied.

      ICH E6 §4.11.1 SAE Expedited Reporting + 21 CFR §312.32 Expedited
      IND Safety Reports: Serious Adverse Events (SAEs) that are unexpected
      and serious must be reported to the sponsor within 15 calendar days
      of the investigator becoming aware of the event per ICH E6 §4.11.1,
      and fatal or life-threatening unexpected SAEs within 7 days per
      21 CFR §312.32(c)(1)(i).  SAE data without confirmed 15-day
      expedited reporting documentation is escalated to REQUIRES_HUMAN_REVIEW.

  Layer 3 — EMARegulationsFilter
      (European Medicines Agency Clinical Trials and Marketing
       Authorization Regulations; EU Regulation 536/2014 (EU CTR);
       EU Pediatric Regulation 1901/2006; Regulation (EC) 726/2004;
       GDPR Regulation 2016/679)
      Controls access to EU clinical trial data lacking EU CTR 536/2014
      authorization, pediatric trial data without EMA PIP compliance,
      EU marketing authorization applications without centralized procedure
      compliance, and clinical research health data processed without GDPR
      Art. 9 safeguards.

      EU CTR 536/2014 Art. 5/6 Authorization + EudraCT Submission:
      EU clinical trial data must have authorization under EU Clinical
      Trials Regulation 536/2014, including a Member State authorization
      decision (Art. 5) and ethics committee opinion (Art. 6), and must be
      registered in the EU Clinical Trials Information System (CTIS)
      (formerly EudraCT).  EU clinical trial data without confirmed
      EU CTR authorization is denied.

      EU Pediatric Regulation 1901/2006 Art. 7 PIP Obligation — Pediatric
      Investigation Plan Compliance: Pediatric clinical trial data for
      medicinal products requires compliance with the Pediatric
      Investigation Plan (PIP) approved by the EMA Paediatric Committee
      (PDCO) under EU Pediatric Regulation 1901/2006 Art. 7.  Pediatric
      trial data without confirmed EMA PIP compliance is denied.

      Regulation 726/2004 Art. 3 Centralized Procedure — EMA Marketing
      Authorization: EU drug marketing authorization application data for
      products falling under the mandatory scope of the EMA centralized
      procedure (Regulation 726/2004 Art. 3(1), including biotech products,
      new active substances, orphan medicines, and advanced therapies) must
      be processed through the centralized procedure.  EU marketing
      authorization applications without confirmed centralized procedure
      compliance are denied.

      GDPR Art. 9 Clinical Trial Health Data + Art. 9(2)(j) Scientific
      Research Exception Documentation: Processing of special category
      health data in clinical trials requires a specific lawful basis under
      GDPR Art. 9(2), with clinical research typically relying on
      Art. 9(2)(j) (scientific research) supplemented by Member State
      derogation.  Clinical trial health data processing without confirmed
      GDPR Art. 9 safeguards is escalated to REQUIRES_HUMAN_REVIEW.

  Layer 4 — PharmaCrossBorderFilter
      (Cross-border pharmaceutical data, clinical trial data transfers,
       and controlled substance regulatory controls;
       ICH E6 §5.15 trial master file; GDPR Art. 46 SCCs; FDA Import
       Alert 66-40/66-66; 21 U.S.C. §812 DEA Schedules;
       Single Convention on Narcotic Drugs 1961;
       FDA-EMA parallel scientific advice program)
      Controls cross-border clinical trial data transfers to non-ICH
      member countries, drug substance manufacturing data from prohibited
      countries, controlled substance scheduling data to non-DEA-compliant
      jurisdictions, and biosimilar reference product data cross-border
      transfers.

      ICH E6 §5.15 + GDPR Art. 46 SCC — Clinical Trial Data Transfer to
      Non-ICH Country: Clinical trial data transferred to non-ICH member
      countries must be governed by an appropriate data transfer agreement —
      Standard Contractual Clauses (SCCs) under GDPR Art. 46 for EU-
      originating trial data — consistent with ICH E6 §5.15 trial master
      file and essential document retention obligations.  Clinical trial
      data transfers to non-ICH member countries without a confirmed data
      transfer agreement are denied.

      FDA Import Alert 66-40 / 66-66 + 21 CFR §314.45 — Drug Substance
      Manufacturing from Prohibited Countries: Drug substance manufacturing
      data originating from facilities in countries listed under FDA
      Import Alert 66-40 (drugs manufactured under conditions that appear
      to violate CGMP) or Import Alert 66-66 (drugs from firms not compliant
      with U.S. drug law) without an FDA import alert review and clearance
      under 21 CFR §314.45 may not be processed.  Drug substance
      manufacturing data from prohibited countries without FDA import alert
      review is denied.

      21 U.S.C. §812 DEA Schedules + Single Convention on Narcotic Drugs
      1961 — Controlled Substance Scheduling Cross-Border: Controlled
      substance scheduling and handling data transmitted to jurisdictions
      that do not maintain DEA Schedule equivalence under the Controlled
      Substances Act (21 U.S.C. §812) or the 1961 UN Single Convention on
      Narcotic Drugs must comply with applicable export controls and
      international treaty obligations.  Controlled substance scheduling
      data transmitted to non-DEA-compliant jurisdictions without confirmed
      international treaty compliance is denied.

      FDA-EMA Parallel Scientific Advice Program — Biosimilar Reference
      Product Cross-Border: Biosimilar reference product data transferred
      cross-border between FDA and EMA jurisdictions should ideally be
      processed through the FDA-EMA parallel scientific advice program
      to ensure regulatory alignment.  Biosimilar reference product data
      transferred cross-border without a confirmed FDA-EMA parallel review
      agreement or equivalent bilateral arrangement is escalated to
      REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: ICH member countries / regions (countries where ICH guidelines apply and
#: ICH data transfer agreements are considered adequate).
ICH_MEMBER_REGIONS: frozenset[str] = frozenset(
    {
        "US",  # United States (FDA)
        "EU",  # European Union (EMA)
        "JP",  # Japan (PMDA)
        "CA",  # Canada (Health Canada)
        "CH",  # Switzerland (Swissmedic)
        "AU",  # Australia (TGA) — ICH observer with full participation
        "GB",  # United Kingdom (MHRA) — post-Brexit ICH member
        "KR",  # South Korea (MFDS)
        "SG",  # Singapore (HSA)
        "BR",  # Brazil (ANVISA) — ICH member since 2016
        "MX",  # Mexico (COFEPRIS) — ICH member
        "CN",  # China (NMPA) — ICH member since 2017
    }
)

#: Country codes subject to FDA Import Alert 66-40 (CGMP violations) or
#: Import Alert 66-66 (drugs from firms not compliant with U.S. law).
#: This is a representative set; actual import alerts are facility-specific.
FDA_IMPORT_ALERT_COUNTRIES: frozenset[str] = frozenset(
    {
        "IN_PROHIBITED",   # India — specific facilities on import alert
        "CN_PROHIBITED",   # China — specific facilities on import alert
        "MX_PROHIBITED",   # Mexico — specific facilities on import alert
        "PK",              # Pakistan — facilities with documented CGMP issues
        "BD",              # Bangladesh — documented CGMP compliance concerns
    }
)

#: Country codes that do not maintain DEA Schedule equivalence or are not
#: signatories / compliant with the 1961 Single Convention on Narcotic Drugs.
NON_DEA_COMPLIANT_JURISDICTIONS: frozenset[str] = frozenset(
    {
        "AF",  # Afghanistan — opium production; enforcement gaps
        "MM",  # Myanmar — precursor chemical controls absent
        "KP",  # North Korea — not party to Single Convention controls
        "SD",  # Sudan — limited controlled substance regulatory framework
        "LY",  # Libya — enforcement gaps post-conflict
    }
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", or "REQUIRES_HUMAN_REVIEW"
    regulation   : Short citation string (e.g. "21 CFR Part 312")
    reason       : Human-readable explanation of the decision
    filter_name  : Name of the filter that produced this result
    """

    decision: str
    regulation: str
    reason: str
    filter_name: str

    @property
    def is_denied(self) -> bool:
        """Return True only when decision is exactly ``"DENIED"``."""
        return self.decision == "DENIED"


# ---------------------------------------------------------------------------
# Layer 1 — FDADrugDevelopmentFilter
#            FDA Drug Development and IND/NDA/BLA Regulations
#            (21 CFR Parts 312, 314, 601, 210/211)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FDADrugDevelopmentFilter:
    """Enforces FDA drug development regulatory requirements for IND, NDA, BLA,
    and CGMP compliance.

    21 CFR Part 312 IND compliance (safety reporting + protocol amendments +
    sponsor obligations): IND data without confirmed Part 312 compliance
    → DENIED.

    21 CFR Part 314 NDA complete response requirements (submission + labeling
    + manufacturing): NDA data without confirmed Part 314 complete response
    compliance → DENIED.

    21 CFR Part 601 BLA manufacturing + characterization + quality: BLA data
    without confirmed Part 601 compliance → DENIED.

    21 CFR Parts 210/211 CGMP — drug manufacturing CGMP compliance
    verification: Drug manufacturing data without confirmed CGMP compliance
    → REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "FDADrugDevelopmentFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate FDA drug development regulatory requirements for *doc*.

        Evaluation order
        ----------------
        1. IND data without confirmed 21 CFR Part 312 compliance → DENIED
           (IND safety reporting + protocol amendments + sponsor obligations).
        2. NDA data without confirmed 21 CFR Part 314 complete response
           compliance → DENIED (NDA submission + labeling + manufacturing).
        3. BLA data without confirmed 21 CFR Part 601 compliance → DENIED
           (BLA manufacturing + characterization + quality).
        4. Drug manufacturing data without confirmed CGMP compliance
           (21 CFR Parts 210/211) → REQUIRES_HUMAN_REVIEW.
        5. Otherwise → PERMITTED.
        """
        is_ind_data = doc.get("is_ind_application_data", False)
        is_nda_data = doc.get("is_nda_application_data", False)
        is_bla_data = doc.get("is_bla_application_data", False)
        is_drug_manufacturing_data = doc.get("is_drug_manufacturing_data", False)

        # 21 CFR Part 312 — IND compliance
        if is_ind_data and not doc.get("ind_part312_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="21 CFR Part 312 IND",
                reason=(
                    "FDA 21 CFR Part 312: Investigational New Drug (IND) application data "
                    "processed without confirmed 21 CFR Part 312 compliance. IND safety "
                    "reporting obligations (§312.32 expedited IND safety reports), protocol "
                    "amendment requirements (§312.30), and sponsor obligations (§312.50) must "
                    "be documented and confirmed before IND data is accessible in this pipeline. "
                    "Sponsors must report unexpected fatal or life-threatening suspected adverse "
                    "reactions within 7 days and other unexpected serious reactions within 15 days."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 21 CFR Part 314 — NDA complete response requirements
        if is_nda_data and not doc.get("nda_part314_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="21 CFR Part 314 NDA",
                reason=(
                    "FDA 21 CFR Part 314: New Drug Application (NDA) data processed without "
                    "confirmed 21 CFR Part 314 complete response requirements. NDA submission "
                    "content requirements (§314.50), labeling requirements and post-approval "
                    "labeling changes (§314.70), and manufacturing change controls must all be "
                    "satisfied. A Complete Response Letter (CRL) from FDA requires the applicant "
                    "to address all deficiencies before the NDA data may be accessed here."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 21 CFR Part 601 — BLA compliance
        if is_bla_data and not doc.get("bla_part601_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="21 CFR Part 601 BLA",
                reason=(
                    "FDA 21 CFR Part 601: Biologics License Application (BLA) data processed "
                    "without confirmed 21 CFR Part 601 compliance. BLA establishment license "
                    "requirements (§601.2), biological product manufacturing standards (§601.12), "
                    "and lot release procedures (§601.20) must be satisfied. Biological products "
                    "— including vaccines, blood components, allergenics, somatic cells, gene "
                    "therapy, tissues, and recombinant therapeutic proteins — require CBER or "
                    "CDER BLA approval prior to introduction into interstate commerce."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 21 CFR Parts 210/211 — CGMP compliance verification
        if is_drug_manufacturing_data and not doc.get("cgmp_compliance_verified", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="21 CFR Parts 210/211 CGMP",
                reason=(
                    "FDA 21 CFR Parts 210/211: Drug manufacturing data accessed without "
                    "confirmed Current Good Manufacturing Practice (CGMP) compliance "
                    "verification. Part 210 (general CGMP in manufacturing, processing, "
                    "packing, or holding of drugs) and Part 211 (CGMP for finished "
                    "pharmaceuticals) compliance — including facility qualification, equipment "
                    "calibration, batch record review, and quality control laboratory procedures "
                    "— must be verified by a qualified person before this data is released. "
                    "Human review required to confirm CGMP status."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="21 CFR Parts 312, 314, 601, 210/211",
            reason=(
                "Document satisfies FDA drug development regulatory requirements under "
                "21 CFR Parts 312 (IND), 314 (NDA), 601 (BLA), and 210/211 (CGMP) "
                "for pharmaceutical development and regulatory submissions."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — ICHGCPFilter
#            ICH Good Clinical Practice (ICH E6 R2/R3)
#            21 CFR Parts 50 and 56
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ICHGCPFilter:
    """Enforces ICH E6 R2/R3 Good Clinical Practice requirements and 21 CFR
    Parts 50/56 human subject protection regulations.

    ICH E6 §3.1 IRB/IEC Responsibilities + 21 CFR Part 56: Clinical trial
    data without confirmed IRB/IEC approval documentation → DENIED.

    ICH E6 §4.8.10 Informed Consent Elements: Informed consent documentation
    lacking confirmed required elements → DENIED.

    ICH E6 §4.1 Investigator Qualifications + Protocol Adherence: Clinical
    investigator data without confirmed ICH E6 §4.1 qualifications and
    agreement documentation → DENIED.

    ICH E6 §4.11.1 SAE Expedited Reporting + 21 CFR §312.32: SAE data without
    confirmed 15-day expedited reporting documentation →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "ICHGCPFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate ICH E6 GCP compliance requirements for *doc*.

        Evaluation order
        ----------------
        1. Clinical trial data without confirmed IRB/IEC approval → DENIED
           (ICH E6 §3.1 + 21 CFR Part 56).
        2. Informed consent documentation lacking required elements → DENIED
           (ICH E6 §4.8.10 + 21 CFR §50.25).
        3. Clinical investigator data without confirmed qualifications and
           agreements → DENIED (ICH E6 §4.1).
        4. SAE without confirmed 15-day expedited reporting → REQUIRES_HUMAN_REVIEW
           (ICH E6 §4.11.1 + 21 CFR §312.32).
        5. Otherwise → PERMITTED.
        """
        is_clinical_trial_data = doc.get("is_clinical_trial_data", False)
        is_informed_consent_data = doc.get("is_informed_consent_data", False)
        is_investigator_data = doc.get("is_clinical_investigator_data", False)
        is_sae_data = doc.get("is_serious_adverse_event_data", False)

        # ICH E6 §3.1 IRB/IEC approval + 21 CFR Part 56
        if is_clinical_trial_data and not doc.get("irb_iec_approval_documented", False):
            return FilterResult(
                decision="DENIED",
                regulation="ICH E6 §3.1 IRB/IEC + 21 CFR Part 56",
                reason=(
                    "ICH E6 §3.1 / 21 CFR Part 56: Clinical trial data processed without "
                    "confirmed IRB (Institutional Review Board) or IEC (Independent Ethics "
                    "Committee) approval documentation. ICH E6 §3.1 requires the IRB/IEC to "
                    "safeguard the rights, safety, and well-being of all trial subjects. "
                    "21 CFR Part 56 mandates IRB review and approval before any clinical "
                    "investigation may commence. Approval documentation — including the initial "
                    "approval letter, approved protocol version, and continuing review records "
                    "— must be confirmed prior to accessing this data."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ICH E6 §4.8.10 Informed Consent Elements
        if is_informed_consent_data and not doc.get("informed_consent_elements_complete", False):
            return FilterResult(
                decision="DENIED",
                regulation="ICH E6 §4.8.10 + 21 CFR §50.25",
                reason=(
                    "ICH E6 §4.8.10 / 21 CFR §50.25: Informed consent documentation lacking "
                    "confirmation that all required elements are present. ICH E6 §4.8.10 "
                    "specifies the required elements of informed consent, including: the nature "
                    "of the trial and its purpose; foreseeable risks and discomforts; expected "
                    "benefits; available alternatives; confidentiality of records; compensation "
                    "and medical treatment for injury; contacts for questions; and the voluntary "
                    "nature of participation with right to withdraw. All elements per "
                    "21 CFR §50.25(a) must be documented."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ICH E6 §4.1 Investigator Qualifications + Protocol Adherence
        if is_investigator_data and not doc.get("investigator_qualifications_confirmed", False):
            return FilterResult(
                decision="DENIED",
                regulation="ICH E6 §4.1 Investigator Qualifications",
                reason=(
                    "ICH E6 §4.1: Clinical investigator data processed without confirmed "
                    "investigator qualifications and protocol agreements. ICH E6 §4.1 requires "
                    "that investigators be qualified by education, training, and experience to "
                    "assume responsibility for the proper conduct of the clinical investigation. "
                    "Qualification documentation must include the investigator's CV or other "
                    "relevant documents, signed protocol agreement (Form FDA 1572 for U.S. INDs), "
                    "and evidence of protocol adherence and delegation of trial-related duties."
                ),
                filter_name=self.FILTER_NAME,
            )

        # ICH E6 §4.11.1 SAE Expedited Reporting + 21 CFR §312.32
        if is_sae_data and not doc.get("sae_expedited_reporting_confirmed", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="ICH E6 §4.11.1 + 21 CFR §312.32 SAE Reporting",
                reason=(
                    "ICH E6 §4.11.1 / 21 CFR §312.32: Serious Adverse Event (SAE) data "
                    "processed without confirmed 15-day expedited reporting documentation. "
                    "ICH E6 §4.11.1 requires investigators to report all SAEs to the sponsor "
                    "immediately (within 24 hours) and to document expedited reporting within "
                    "15 calendar days. 21 CFR §312.32(c)(1)(i) requires sponsors to report "
                    "fatal or life-threatening unexpected suspected adverse reactions within "
                    "7 calendar days (IND Safety Report) and other unexpected serious reactions "
                    "within 15 calendar days. Human review required to confirm timely SAE "
                    "reporting compliance."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="ICH E6 R2/R3 GCP; 21 CFR Parts 50, 56; §312.32",
            reason=(
                "Document satisfies ICH E6 R2/R3 Good Clinical Practice requirements, "
                "including IRB/IEC approval, informed consent documentation, investigator "
                "qualifications, and SAE reporting obligations under 21 CFR Parts 50 and 56."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — EMARegulationsFilter
#            European Medicines Agency Clinical Trials and Marketing
#            Authorization Regulations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EMARegulationsFilter:
    """Enforces EMA clinical trials regulation and marketing authorization
    requirements under EU CTR 536/2014, Pediatric Regulation 1901/2006,
    Regulation 726/2004, and GDPR Art. 9.

    EU CTR 536/2014 Art. 5/6 Authorization + EudraCT: EU clinical trial data
    without confirmed EU CTR authorization → DENIED.

    EU Pediatric Regulation 1901/2006 Art. 7 PIP Obligation: Pediatric trial
    data without confirmed EMA PIP compliance → DENIED.

    Regulation 726/2004 Art. 3 Centralized Procedure: EU drug marketing
    authorization application without confirmed centralized procedure
    compliance → DENIED.

    GDPR Art. 9 Clinical Trial Health Data + Art. 9(2)(j): Clinical research
    health data processing without confirmed GDPR Art. 9 safeguards →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "EMARegulationsFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate EMA regulatory requirements for *doc*.

        Evaluation order
        ----------------
        1. EU clinical trial data without confirmed EU CTR 536/2014
           authorization → DENIED (Art. 5/6 + EudraCT/CTIS).
        2. Pediatric trial data without confirmed EMA PIP compliance → DENIED
           (EU Pediatric Regulation 1901/2006 Art. 7).
        3. EU drug marketing authorization application without confirmed EMA
           centralized procedure compliance → DENIED (Reg. 726/2004 Art. 3).
        4. GDPR Art. 9 clinical research health data without confirmed Art. 9
           safeguards → REQUIRES_HUMAN_REVIEW.
        5. Otherwise → PERMITTED.
        """
        is_eu_clinical_trial = doc.get("is_eu_clinical_trial_data", False)
        is_pediatric_trial = doc.get("is_pediatric_trial_data", False)
        is_eu_maa = doc.get("is_eu_marketing_authorization_application", False)
        is_gdpr_health_data = doc.get("is_gdpr_clinical_health_data", False)

        # EU CTR 536/2014 Art. 5/6 Authorization + EudraCT/CTIS
        if is_eu_clinical_trial and not doc.get("eu_ctr_authorization_confirmed", False):
            return FilterResult(
                decision="DENIED",
                regulation="EU CTR 536/2014 Art. 5/6 + EudraCT",
                reason=(
                    "EU Regulation 536/2014 Art. 5/6: EU clinical trial data processed without "
                    "confirmed EU Clinical Trials Regulation authorization. Art. 5 requires a "
                    "Member State authorization decision and Art. 6 requires a favorable ethics "
                    "committee opinion before a clinical trial may commence in the EU. The trial "
                    "must also be registered in the EU Clinical Trials Information System (CTIS) "
                    "(formerly EudraCT). Confirmation of authorization decision, ethics opinion, "
                    "and CTIS/EudraCT registration number is required before accessing this data."
                ),
                filter_name=self.FILTER_NAME,
            )

        # EU Pediatric Regulation 1901/2006 Art. 7 PIP Obligation
        if is_pediatric_trial and not doc.get("ema_pip_compliance_confirmed", False):
            return FilterResult(
                decision="DENIED",
                regulation="EU Pediatric Regulation 1901/2006 Art. 7 PIP",
                reason=(
                    "EU Regulation 1901/2006 Art. 7: Pediatric clinical trial data processed "
                    "without confirmed EMA Pediatric Investigation Plan (PIP) compliance. "
                    "Art. 7 of the EU Pediatric Regulation requires that applicants for "
                    "marketing authorization include the results of studies conducted in "
                    "compliance with an agreed PIP approved by the EMA Paediatric Committee "
                    "(PDCO). A waiver or deferral decision from PDCO (Art. 11/12) may substitute "
                    "for a full PIP where applicable. Confirmation of PIP compliance, waiver, "
                    "or deferral is required before accessing pediatric trial data."
                ),
                filter_name=self.FILTER_NAME,
            )

        # Regulation 726/2004 Art. 3 Centralized Procedure
        if is_eu_maa and not doc.get("ema_centralized_procedure_compliant", False):
            return FilterResult(
                decision="DENIED",
                regulation="Regulation 726/2004 Art. 3 Centralized Procedure",
                reason=(
                    "Regulation (EC) 726/2004 Art. 3: EU drug marketing authorization "
                    "application (MAA) data processed without confirmed EMA centralized "
                    "procedure compliance. Art. 3(1) mandates use of the centralized procedure "
                    "for: biotech-derived products; new active substances for AIDS, cancer, "
                    "neurodegenerative disease, diabetes, autoimmune disease; orphan medicinal "
                    "products; and advanced therapy medicinal products (ATMPs). Applications "
                    "must be submitted to EMA and assessed by the Committee for Medicinal "
                    "Products for Human Use (CHMP) before EU-wide marketing authorization "
                    "may be granted."
                ),
                filter_name=self.FILTER_NAME,
            )

        # GDPR Art. 9 Clinical Trial Health Data + Art. 9(2)(j)
        if is_gdpr_health_data and not doc.get("gdpr_art9_safeguards_documented", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="GDPR Art. 9(2)(j) Scientific Research Exception",
                reason=(
                    "GDPR Art. 9 / Art. 9(2)(j): Clinical trial health data (special category "
                    "data under GDPR Art. 9(1)) processed without confirmed GDPR Art. 9 "
                    "safeguards documentation. Clinical research relies on Art. 9(2)(j) "
                    "(scientific or historical research purposes) as the lawful basis for "
                    "processing health data, subject to Member State derogation under Art. 9(4) "
                    "and Recital 159. Required safeguards include: appropriate technical and "
                    "organisational measures; pseudonymisation where feasible; Data Protection "
                    "Impact Assessment (DPIA) under Art. 35; and Data Processing Agreement (DPA) "
                    "with the clinical site. Human review required to confirm GDPR Art. 9 "
                    "safeguards are in place."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="EU CTR 536/2014; Reg. 1901/2006; Reg. 726/2004; GDPR Art. 9",
            reason=(
                "Document satisfies EMA regulatory requirements under EU CTR 536/2014, "
                "EU Pediatric Regulation 1901/2006, Regulation 726/2004 centralized procedure, "
                "and GDPR Art. 9 clinical research health data safeguards."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — PharmaCrossBorderFilter
#            Cross-Border Pharmaceutical Data and Clinical Trial Controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PharmaCrossBorderFilter:
    """Enforces cross-border pharmaceutical data and clinical trial controls.

    ICH E6 §5.15 + GDPR Art. 46 SCC — Clinical trial data to non-ICH member
    country without data transfer agreement → DENIED.

    FDA Import Alert 66-40/66-66 + 21 CFR §314.45 — Drug substance
    manufacturing data from prohibited country without FDA import alert
    review → DENIED.

    21 U.S.C. §812 DEA Schedules + Single Convention 1961 — Controlled
    substance scheduling data to non-DEA-compliant jurisdiction without
    treaty compliance → DENIED.

    FDA-EMA Parallel Scientific Advice — Biosimilar reference product data
    cross-border without confirmed FDA-EMA parallel review agreement →
    REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "PharmaCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate cross-border pharmaceutical compliance controls for *doc*.

        Evaluation order
        ----------------
        1. Clinical trial data to non-ICH member country without data
           transfer agreement → DENIED (ICH E6 §5.15 + GDPR Art. 46 SCC).
        2. Drug substance manufacturing data from FDA import-alert country
           without import alert review → DENIED
           (FDA Import Alert 66-40/66-66 + 21 CFR §314.45).
        3. Controlled substance scheduling data to non-DEA-compliant
           jurisdiction without treaty compliance → DENIED
           (21 U.S.C. §812 DEA Schedules + Single Convention 1961).
        4. Biosimilar reference product data cross-border without confirmed
           FDA-EMA parallel review agreement → REQUIRES_HUMAN_REVIEW.
        5. Otherwise → PERMITTED.
        """
        destination_country = doc.get("destination_country", "")
        manufacturing_country = doc.get("manufacturing_country", "")
        is_clinical_trial_data = doc.get("is_clinical_trial_data_transfer", False)
        is_drug_manufacturing_data = doc.get("is_drug_substance_manufacturing_data", False)
        is_controlled_substance_data = doc.get("is_controlled_substance_scheduling_data", False)
        is_biosimilar_reference_data = doc.get("is_biosimilar_reference_product_data", False)

        # ICH E6 §5.15 + GDPR Art. 46 SCC
        if (
            is_clinical_trial_data
            and destination_country not in ICH_MEMBER_REGIONS
            and not doc.get("data_transfer_agreement_executed", False)
        ):
            return FilterResult(
                decision="DENIED",
                regulation="ICH E6 §5.15 + GDPR Art. 46 SCC",
                reason=(
                    f"ICH E6 §5.15 / GDPR Art. 46: Clinical trial data transferred to "
                    f"'{destination_country}' (non-ICH member country) without a confirmed "
                    f"data transfer agreement. ICH E6 §5.15 requires that the trial master "
                    f"file (TMF) and essential documents be maintained with appropriate access "
                    f"controls. GDPR Art. 46 requires Standard Contractual Clauses (SCCs) or "
                    f"equivalent safeguards for cross-border transfers of EU trial data to "
                    f"third countries. A data transfer agreement must be executed and "
                    f"documented before EU clinical trial data may be transferred to "
                    f"'{destination_country}'."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FDA Import Alert 66-40 / 66-66 + 21 CFR §314.45
        if (
            is_drug_manufacturing_data
            and manufacturing_country in FDA_IMPORT_ALERT_COUNTRIES
            and not doc.get("fda_import_alert_reviewed", False)
        ):
            return FilterResult(
                decision="DENIED",
                regulation="FDA Import Alert 66-40/66-66 + 21 CFR §314.45",
                reason=(
                    f"FDA Import Alert 66-40/66-66 / 21 CFR §314.45: Drug substance "
                    f"manufacturing data from '{manufacturing_country}' — a country with "
                    f"facilities subject to FDA Import Alert 66-40 (CGMP violations) or "
                    f"Import Alert 66-66 (drugs from firms not compliant with U.S. drug law) "
                    f"— processed without confirmed FDA import alert review and clearance. "
                    f"21 CFR §314.45 requires a waiver or import alert clearance before drug "
                    f"products from affected facilities may be imported. FDA review and "
                    f"clearance documentation must be confirmed."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 21 U.S.C. §812 DEA Schedules + Single Convention 1961
        if (
            is_controlled_substance_data
            and destination_country in NON_DEA_COMPLIANT_JURISDICTIONS
            and not doc.get("international_treaty_compliance_confirmed", False)
        ):
            return FilterResult(
                decision="DENIED",
                regulation="21 U.S.C. §812 DEA Schedules + Single Convention 1961",
                reason=(
                    f"21 U.S.C. §812 / Single Convention on Narcotic Drugs 1961: Controlled "
                    f"substance scheduling and handling data transmitted to '{destination_country}' "
                    f"— a non-DEA-compliant jurisdiction — without confirmed international treaty "
                    f"compliance documentation. The Controlled Substances Act (21 U.S.C. §812) "
                    f"DEA Schedules I–V govern controlled substance export controls in the U.S., "
                    f"and the 1961 UN Single Convention on Narcotic Drugs establishes obligations "
                    f"for signatory states. Transmission to '{destination_country}' requires "
                    f"confirmed treaty compliance, DEA export authorization (21 CFR §1312.21), "
                    f"and applicable INCB import authorization."
                ),
                filter_name=self.FILTER_NAME,
            )

        # FDA-EMA Parallel Scientific Advice — Biosimilar Reference Product
        if is_biosimilar_reference_data and not doc.get(
            "fda_ema_parallel_review_agreement_confirmed", False
        ):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="FDA-EMA Parallel Scientific Advice Program",
                reason=(
                    "FDA-EMA Parallel Scientific Advice: Biosimilar reference product data "
                    "transferred cross-border without a confirmed FDA-EMA parallel review "
                    "agreement or equivalent bilateral regulatory arrangement. The FDA-EMA "
                    "parallel scientific advice program enables sponsors to receive coordinated "
                    "regulatory feedback from both FDA and EMA simultaneously, ensuring "
                    "alignment on reference product comparability, analytical similarity, "
                    "and clinical data requirements for biosimilar development. Human review "
                    "required to determine whether a parallel review agreement applies or an "
                    "alternative bilateral arrangement is in place."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="ICH E6 §5.15; FDA Import Alert; 21 U.S.C. §812; FDA-EMA",
            reason=(
                "Document satisfies cross-border pharmaceutical data controls under "
                "ICH E6 §5.15, FDA Import Alert requirements, DEA Schedule / Single "
                "Convention obligations, and FDA-EMA parallel review program requirements."
            ),
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four pharmaceutical / clinical trials compliance filter layers
    against *doc*.

    Returns a list of FilterResult objects, one per layer evaluated.  The
    pipeline short-circuits on the first DENIED decision; subsequent filters
    are not evaluated for denied documents.
    """
    filters = [
        FDADrugDevelopmentFilter(),
        ICHGCPFilter(),
        EMARegulationsFilter(),
        PharmaCrossBorderFilter(),
    ]
    results: list[FilterResult] = []
    for flt in filters:
        result = flt.filter(doc)
        results.append(result)
        if result.is_denied:
            break
    return results


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Pharmaceutical / Clinical Trials Compliance RAG Pipeline — Demo ===\n")

    # --- IND data without Part 312 compliance ---
    doc_ind_no_compliance = {
        "doc_id": "fda-ind-001",
        "is_ind_application_data": True,
        "ind_part312_compliant": False,
    }
    print("Document: IND application data without 21 CFR Part 312 compliance")
    for r in run_pipeline(doc_ind_no_compliance):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Clinical trial data without IRB/IEC approval ---
    doc_no_irb = {
        "doc_id": "gcp-002",
        "is_ind_application_data": False,
        "is_clinical_trial_data": True,
        "irb_iec_approval_documented": False,
    }
    print("Document: Clinical trial data without IRB/IEC approval documentation")
    for r in run_pipeline(doc_no_irb):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- EU clinical trial without CTR authorization ---
    doc_eu_no_auth = {
        "doc_id": "ema-003",
        "is_eu_clinical_trial_data": True,
        "eu_ctr_authorization_confirmed": False,
    }
    print("Document: EU clinical trial data without EU CTR 536/2014 authorization")
    for r in run_pipeline(doc_eu_no_auth):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Cross-border trial data to non-ICH country without DTA ---
    doc_non_ich_transfer = {
        "doc_id": "border-004",
        "is_clinical_trial_data_transfer": True,
        "destination_country": "NG",
        "data_transfer_agreement_executed": False,
    }
    print("Document: Clinical trial data transfer to non-ICH country without DTA")
    for r in run_pipeline(doc_non_ich_transfer):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant document ---
    doc_compliant = {
        "doc_id": "compliant-005",
        "is_ind_application_data": True,
        "ind_part312_compliant": True,
        "is_clinical_trial_data": True,
        "irb_iec_approval_documented": True,
        "is_eu_clinical_trial_data": True,
        "eu_ctr_authorization_confirmed": True,
        "is_clinical_trial_data_transfer": True,
        "destination_country": "GB",
        "data_transfer_agreement_executed": True,
    }
    print("Document: Fully compliant pharmaceutical / clinical trials document")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
