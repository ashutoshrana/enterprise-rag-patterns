"""
IoT/OT Security Compliance RAG Pipeline — Four-Layer Retrieval Access Control

This module implements a compliance-aware RAG retrieval pre-filter for platforms
that process documents related to Internet of Things (IoT) devices and Operational
Technology (OT) / Industrial Control Systems (ICS).  Four independent filter layers
run sequentially; a document must pass all four to be returned to the caller.

Commercial use cases:

  +--------------------------------------------------------------+--------------------------------------------+
  | Platform / Product                                           | Applicable Regulation(s)                   |
  +--------------------------------------------------------------+--------------------------------------------+
  | Industrial IoT device management and monitoring platforms    | NIST SP 800-213; IEC 62443                 |
  | SCADA/DCS configuration and patch management systems        | IEC 62443-2-3; IEC 62443-3-3              |
  | Smart grid and energy OT analytics platforms                 | NERC CIP; IEC 62443-3-2                    |
  | Pipeline and rail cybersecurity compliance systems           | TSA Security Directives 2021-02C; 1580/82  |
  | Aviation OT network segmentation platforms                   | TSA SD 1580/82-2022-01 §E.2                |
  | IoT data export compliance and supply-chain platforms        | EAR 15 CFR §774; CFIUS 50 U.S.C. §4565    |
  | Critical infrastructure OT monitoring platforms             | CISA Cyber Performance Goals v2.0          |
  | EU essential entity OT compliance platforms                  | EU NIS2 Directive 2022/2555                |
  | Industrial control system procurement and audit platforms    | IEC 62443-2-4; IEC 62443-3-3              |
  | Cross-border OT/IoT data transfer and analytics platforms   | OFAC SDN List; EU NIS2 Art. 26            |
  +--------------------------------------------------------------+--------------------------------------------+

Regulatory frameworks enforced:

  Layer 1 — NISTIoTFilter
      (NIST SP 800-213: IoT Device Cybersecurity Guidance for the Federal
       Government; NIST IR 8259A — IoT Device Cybersecurity Core Baseline)
      Controls access to documents involving IoT devices deployed in federal
      or enterprise environments, enforcing device identity, configuration
      management, logical access control, and data-protection baselines.

      NIST SP 800-213 §3.1 (Device Identity): IoT devices must support a
      unique logical identifier and the ability to cryptographically bind that
      identity to the device.  Documents describing IoT deployments without
      device identity management are denied.

      NIST SP 800-213 §3.3 (Device Configuration): IoT devices must support
      the ability to have their software configuration changed and must restrict
      configuration capabilities to authorised entities.  Documents describing
      IoT deployments without configuration management controls are denied.

      NIST SP 800-213 §3.5 (Logical Access to Interfaces): IoT devices must
      support the ability to enforce logical access to each local and network
      interface and to the protocols and services used by those interfaces.
      Documents describing critical IoT systems without network access controls
      are denied.

      NIST SP 800-213 §3.6 (Data Protection): IoT devices must support the
      ability to use cryptographic means to protect the confidentiality and
      integrity of data transmitted to and from the device.  Documents
      describing IoT data transmission without cryptographic protection are
      escalated to REQUIRES_HUMAN_REVIEW.

  Layer 2 — IEC62443OTFilter
      (IEC 62443: Industrial Automation and Control Systems (IACS) Security —
       IEC 62443-3-3 System Security Requirements and Security Levels;
       IEC 62443-3-2 Security Risk Assessment for System Design;
       IEC 62443-2-4 Security Program Requirements for IACS Service Providers;
       IEC 62443-2-3 Patch Management in the IACS Environment)
      Controls access to documents involving industrial control systems and
      SCADA environments, enforcing Security Level assessment, zone/conduit
      models, defense-in-depth for remote access, and patch management.

      IEC 62443-3-3 SL-C(1) (Security Level Capability): All OT/SCADA systems
      must undergo a Security Level assessment to determine the target security
      level (SL-T) and the capability security level (SL-C) achievable by the
      system.  Documents describing OT/SCADA systems without a Security Level
      assessment are denied.

      IEC 62443-3-2 §4.3 (Zone and Conduit Model): Industrial automation
      systems must partition assets into security zones based on risk and connect
      zones only through defined conduits with controlled communications.
      Documents describing industrial control systems without a zone and conduit
      model are denied.

      IEC 62443-2-4 §SP.04.01 (Remote Access Defense-in-Depth): Service
      providers performing remote maintenance on OT systems must implement
      defense-in-depth measures including multi-factor authentication, encrypted
      channels, and session monitoring.  Documents describing remote OT access
      without defense-in-depth are denied.

      IEC 62443-2-3 §5.2 (Patch Management Plan): IACS asset owners and service
      providers must maintain a documented patch management plan covering patch
      identification, assessment, testing, and deployment for all IACS
      components.  Documents describing IACS components without a patch
      management plan are escalated to REQUIRES_HUMAN_REVIEW.

  Layer 3 — TSAOTSecurityFilter
      (TSA Security Directive Pipeline-2021-02C — Critical Pipeline
       Cybersecurity; TSA Security Directive 1580/82-2022-01 — Surface and
       Aviation Transportation Cybersecurity; CISA Cyber Performance Goals
       v2.0 OT-specific controls)
      Controls access to documents involving critical pipeline, rail, and
      aviation OT infrastructure subject to TSA cybersecurity mandates.

      TSA Security Directive Pipeline-2021-02C §I (Incident Reporting): Owner/
      operators of TSA-designated critical pipeline facilities must report
      cybersecurity incidents to CISA within 12 hours.  Documents describing
      critical pipeline OT systems without TSA-mandated incident reporting
      capability are denied.

      TSA SD 1580/82-2022-01 §E.2 (Network Segmentation — Aviation): Aviation
      operators must implement network segmentation to prevent pivot from IT
      networks to OT/operational networks.  Documents describing aviation OT
      without IT/OT network segmentation are denied.

      TSA SD 1580/82-2022-01 §B (Cybersecurity Coordinator — Rail): Surface
      transportation operators, including rail, must designate a primary and
      alternate Cybersecurity Coordinator responsible for coordinating
      cybersecurity practices.  Documents describing rail OT without a
      designated cybersecurity coordinator are denied.

      CISA Cyber Performance Goals v2.0 OT-specific (CPG 2.O): OT asset
      owners at critical infrastructure organisations are expected to meet
      CISA-defined Cyber Performance Goals covering asset visibility, secure
      remote access, and OT-specific detection.  Documents describing critical
      infrastructure OT without evidence of CPG attainment are escalated to
      REQUIRES_HUMAN_REVIEW.

  Layer 4 — OTCrossBorderFilter
      (OFAC Sanctions Programs; Export Administration Regulations 15 CFR §774;
       CFIUS 50 U.S.C. §4565; EU NIS2 Directive 2022/2555 Art. 26)
      Controls access to documents involving cross-border transfer of OT system
      data or export of industrial control system technology subject to US
      export controls, CFIUS national-security review, and EU NIS2 cross-border
      notification requirements.

      OFAC Sanctions Programs: The Office of Foreign Assets Control prohibits
      US persons from exporting, re-exporting, or providing technology, data,
      or services to comprehensively sanctioned jurisdictions including Russia
      (RU), Iran (IR), North Korea (KP), Cuba (CU), and Syria (SY).
      Documents describing OT data export to OFAC-sanctioned jurisdictions are
      denied.

      15 CFR §774 EAR (Export Administration Regulations — ECCN 5E002):
      Dual-use industrial control system technology classified under ECCN
      5E002 (information security) requires a US Department of Commerce export
      licence before export to most non-EAR99 destinations.  Documents
      describing export of ECCN-5E002 ICS without a confirmed export licence
      are denied.

      50 U.S.C. §4565 CFIUS (Committee on Foreign Investment in the United
      States): Transactions that give foreign persons control over US critical
      infrastructure, including OT systems, are subject to mandatory CFIUS
      review and potential mitigation or prohibition.  Documents describing
      OT critical infrastructure data transfers to China (CN) without a
      confirmed CFIUS review are denied.

      EU NIS2 Directive 2022/2555 Art. 26 (Cross-Border Incident
      Notification): Essential entities under NIS2 that experience significant
      cybersecurity incidents affecting cross-border OT services must notify
      their National Competent Authority (NCA) within the prescribed
      timeframes.  Documents describing NIS2-essential OT cross-border data
      sharing without NCA notification are escalated to REQUIRES_HUMAN_REVIEW.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

OFAC_SANCTIONED: frozenset[str] = frozenset({"RU", "IR", "KP", "CU", "SY"})


@dataclass
class FilterResult:
    """Result produced by a single filter layer for one document.

    Fields
    ------
    decision     : "PERMITTED", "DENIED", "REQUIRES_HUMAN_REVIEW", or "REDACTED"
    regulation   : Short citation string (e.g. "NIST SP 800-213 §3.1")
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
# Layer 1 — NISTIoTFilter
#            NIST SP 800-213 IoT Cybersecurity Baseline Controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NISTIoTFilter:
    """Enforces NIST SP 800-213 IoT device cybersecurity baseline controls.

    NIST SP 800-213 §3.1 (Device Identity): IoT devices without device
    identity management are denied.

    NIST SP 800-213 §3.3 (Device Configuration): IoT devices without
    configuration management controls are denied.

    NIST SP 800-213 §3.5 (Logical Access): Critical IoT devices without
    network access controls are denied.

    NIST SP 800-213 §3.6 (Data Protection): IoT data transmitted without
    cryptographic protection is escalated to REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "NISTIoTFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate NIST SP 800-213 IoT baseline controls for *doc*.

        Evaluation order
        ----------------
        1. IoT device without device identity management → DENIED (§3.1).
        2. IoT device without configuration management controls → DENIED (§3.3).
        3. Critical IoT without network access controls → DENIED (§3.5).
        4. IoT data without cryptographic protection in transit →
           REQUIRES_HUMAN_REVIEW (§3.6).
        5. Otherwise → PERMITTED.
        """
        is_iot = doc.get("is_iot_device", False)
        is_critical = doc.get("is_critical_iot", False)

        # §3.1 — Device Identity
        if is_iot and not doc.get("device_identity_management", False):
            return FilterResult(
                decision="DENIED",
                regulation="NIST SP 800-213 §3.1",
                reason=(
                    "NIST SP 800-213 §3.1: IoT device lacks device identity management. "
                    "Devices must support a unique logical identifier and cryptographic "
                    "device binding before deployment."
                ),
                filter_name=self.FILTER_NAME,
            )

        # §3.3 — Device Configuration
        if is_iot and not doc.get("configuration_management", False):
            return FilterResult(
                decision="DENIED",
                regulation="NIST SP 800-213 §3.3",
                reason=(
                    "NIST SP 800-213 §3.3: IoT device lacks configuration management "
                    "controls. Devices must restrict configuration changes to authorised "
                    "entities and support auditable configuration updates."
                ),
                filter_name=self.FILTER_NAME,
            )

        # §3.5 — Logical Access to Interfaces
        if is_critical and not doc.get("network_access_controls", False):
            return FilterResult(
                decision="DENIED",
                regulation="NIST SP 800-213 §3.5",
                reason=(
                    "NIST SP 800-213 §3.5: Critical IoT device lacks logical access "
                    "controls on network interfaces. Devices must enforce access control "
                    "on all local and network-facing interfaces."
                ),
                filter_name=self.FILTER_NAME,
            )

        # §3.6 — Data Protection (cryptographic protection in transit)
        if is_iot and not doc.get("crypto_protection_in_transit", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="NIST SP 800-213 §3.6",
                reason=(
                    "NIST SP 800-213 §3.6: IoT data transmission lacks cryptographic "
                    "protection. Devices should use cryptographic means to protect "
                    "confidentiality and integrity of data in transit."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="NIST SP 800-213",
            reason="Document satisfies NIST SP 800-213 IoT cybersecurity baseline controls.",
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 2 — IEC62443OTFilter
#            IEC 62443 Industrial Automation and Control Systems Security
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IEC62443OTFilter:
    """Enforces IEC 62443 IACS security requirements for OT/SCADA systems.

    IEC 62443-3-3 SL-C(1): OT/SCADA systems without a Security Level
    assessment are denied.

    IEC 62443-3-2 §4.3: Industrial control systems without a zone and
    conduit model are denied.

    IEC 62443-2-4 §SP.04.01: Remote access to OT systems without
    defense-in-depth controls is denied.

    IEC 62443-2-3 §5.2: IACS components without a patch management plan
    are escalated to REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "IEC62443OTFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate IEC 62443 IACS security requirements for *doc*.

        Evaluation order
        ----------------
        1. OT/SCADA without Security Level assessment → DENIED
           (IEC 62443-3-3 SL-C(1)).
        2. ICS without zone and conduit model → DENIED
           (IEC 62443-3-2 §4.3).
        3. Remote access to OT without defense-in-depth → DENIED
           (IEC 62443-2-4 §SP.04.01).
        4. IACS component without patch management plan →
           REQUIRES_HUMAN_REVIEW (IEC 62443-2-3 §5.2).
        5. Otherwise → PERMITTED.
        """
        is_ot_scada = doc.get("is_ot_scada", False)
        is_ics = doc.get("is_industrial_control_system", False)
        is_iacs = doc.get("is_iacs_component", False)
        remote_access = doc.get("remote_access_to_ot", False)

        # IEC 62443-3-3 SL-C(1) — Security Level assessment
        if is_ot_scada and not doc.get("security_level_assessed", False):
            return FilterResult(
                decision="DENIED",
                regulation="IEC 62443-3-3 SL-C(1)",
                reason=(
                    "IEC 62443-3-3 SL-C(1): OT/SCADA system lacks a Security Level "
                    "assessment. Systems must undergo SL-T and SL-C assessment before "
                    "operational deployment."
                ),
                filter_name=self.FILTER_NAME,
            )

        # IEC 62443-3-2 §4.3 — Zone and Conduit Model
        if is_ics and not doc.get("zone_conduit_model", False):
            return FilterResult(
                decision="DENIED",
                regulation="IEC 62443-3-2 §4.3",
                reason=(
                    "IEC 62443-3-2 §4.3: Industrial control system lacks a zone and "
                    "conduit model. Assets must be partitioned into security zones with "
                    "defined conduits controlling inter-zone communications."
                ),
                filter_name=self.FILTER_NAME,
            )

        # IEC 62443-2-4 §SP.04.01 — Remote Access Defense-in-Depth
        if remote_access and not doc.get("defense_in_depth_remote", False):
            return FilterResult(
                decision="DENIED",
                regulation="IEC 62443-2-4 §SP.04.01",
                reason=(
                    "IEC 62443-2-4 §SP.04.01: Remote access to OT system lacks "
                    "defense-in-depth controls. Remote maintenance must use MFA, "
                    "encrypted channels, and session monitoring."
                ),
                filter_name=self.FILTER_NAME,
            )

        # IEC 62443-2-3 §5.2 — Patch Management Plan
        if is_iacs and not doc.get("patch_management_plan", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="IEC 62443-2-3 §5.2",
                reason=(
                    "IEC 62443-2-3 §5.2: IACS component lacks a documented patch "
                    "management plan. A plan covering patch identification, assessment, "
                    "testing, and deployment is required."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="IEC 62443",
            reason="Document satisfies IEC 62443 IACS security requirements.",
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 3 — TSAOTSecurityFilter
#            TSA Security Directives for Pipeline / Rail / Aviation OT
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TSAOTSecurityFilter:
    """Enforces TSA OT cybersecurity mandates for critical infrastructure.

    TSA Security Directive Pipeline-2021-02C §I: Critical pipeline OT
    systems without TSA-mandated incident reporting capability are denied.

    TSA SD 1580/82-2022-01 §E.2: Aviation OT without IT/OT network
    segmentation is denied.

    TSA SD 1580/82-2022-01 §B: Rail OT without a designated cybersecurity
    coordinator is denied.

    CISA Cyber Performance Goals v2.0 OT-specific: Critical infrastructure
    OT without CPG attainment evidence is escalated to REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "TSAOTSecurityFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate TSA cybersecurity directives and CISA CPG for *doc*.

        Evaluation order
        ----------------
        1. Critical pipeline OT without TSA incident reporting → DENIED
           (TSA Security Directive Pipeline-2021-02C §I).
        2. Aviation OT without IT/OT network segmentation → DENIED
           (TSA SD 1580/82-2022-01 §E.2).
        3. Rail OT without designated cybersecurity coordinator → DENIED
           (TSA SD 1580/82-2022-01 §B).
        4. Critical infrastructure OT without CISA CPG met →
           REQUIRES_HUMAN_REVIEW (CISA CPG v2.0 OT-specific).
        5. Otherwise → PERMITTED.
        """
        is_critical_pipeline = doc.get("is_critical_pipeline_ot", False)
        is_aviation_ot = doc.get("is_aviation_ot", False)
        is_rail_ot = doc.get("is_rail_ot", False)
        is_critical_infra = doc.get("is_critical_infrastructure_ot", False)

        # TSA Security Directive Pipeline-2021-02C §I — Incident Reporting
        if is_critical_pipeline and not doc.get("tsa_incident_reporting_capable", False):
            return FilterResult(
                decision="DENIED",
                regulation="TSA Security Directive Pipeline-2021-02C §I",
                reason=(
                    "TSA Security Directive Pipeline-2021-02C §I: Critical pipeline OT "
                    "system lacks TSA-mandated cybersecurity incident reporting capability. "
                    "Operators must report incidents to CISA within 12 hours."
                ),
                filter_name=self.FILTER_NAME,
            )

        # TSA SD 1580/82-2022-01 §E.2 — Aviation IT/OT Network Segmentation
        if is_aviation_ot and not doc.get("it_ot_network_segmentation", False):
            return FilterResult(
                decision="DENIED",
                regulation="TSA SD 1580/82-2022-01 §E.2",
                reason=(
                    "TSA SD 1580/82-2022-01 §E.2: Aviation OT system lacks network "
                    "segmentation from IT networks. Segmentation is required to prevent "
                    "lateral movement from IT to OT/operational networks."
                ),
                filter_name=self.FILTER_NAME,
            )

        # TSA SD 1580/82-2022-01 §B — Rail Cybersecurity Coordinator
        if is_rail_ot and not doc.get("cybersecurity_coordinator_designated", False):
            return FilterResult(
                decision="DENIED",
                regulation="TSA SD 1580/82-2022-01 §B",
                reason=(
                    "TSA SD 1580/82-2022-01 §B: Rail OT system lacks a designated "
                    "Cybersecurity Coordinator. Surface operators must designate a "
                    "primary and alternate coordinator."
                ),
                filter_name=self.FILTER_NAME,
            )

        # CISA CPG v2.0 OT-specific — Cyber Performance Goals
        if is_critical_infra and not doc.get("cisa_cpg_ot_met", False):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="CISA CPG v2.0 OT-specific",
                reason=(
                    "CISA CPG v2.0 OT-specific: Critical infrastructure OT system lacks "
                    "evidence of CISA Cyber Performance Goals attainment covering asset "
                    "visibility, secure remote access, and OT-specific detection."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="TSA OT Security Directives; CISA CPG v2.0",
            reason="Document satisfies TSA OT cybersecurity mandates and CISA CPG requirements.",
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Layer 4 — OTCrossBorderFilter
#            Cross-border OT/IoT Data and Equipment Export Controls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OTCrossBorderFilter:
    """Enforces cross-border OT/IoT export controls and transfer restrictions.

    OFAC sanctions: OT data exports to RU/IR/KP/CU/SY are denied.

    15 CFR §774 EAR (ECCN 5E002): ICS exports without an export licence
    are denied.

    50 U.S.C. §4565 CFIUS: OT critical infrastructure data transfers to
    China without CFIUS review are denied.

    EU NIS2 Directive 2022/2555 Art. 26: NIS2-essential OT cross-border
    data sharing without NCA notification is REQUIRES_HUMAN_REVIEW.
    """

    FILTER_NAME: str = "OTCrossBorderFilter"

    def filter(self, doc: dict) -> FilterResult:  # noqa: A003
        """Evaluate cross-border OT/IoT export controls for *doc*.

        Evaluation order
        ----------------
        1. OT data export to OFAC sanctioned jurisdiction → DENIED.
        2. ICS with ECCN 5E002 export without licence → DENIED
           (15 CFR §774 EAR).
        3. OT critical infrastructure data to CN without CFIUS review →
           DENIED (50 U.S.C. §4565).
        4. NIS2 essential entity OT cross-border without NCA notification →
           REQUIRES_HUMAN_REVIEW (EU NIS2 Directive 2022/2555 Art. 26).
        5. Otherwise → PERMITTED.
        """
        destination = doc.get("destination_country", "")

        # OFAC — sanctioned jurisdictions
        if destination in OFAC_SANCTIONED:
            return FilterResult(
                decision="DENIED",
                regulation="OFAC Sanctions Programs",
                reason=(
                    f"OFAC: OT system data export to sanctioned jurisdiction "
                    f"'{destination}' is prohibited. US persons may not export "
                    f"technology or data to comprehensively sanctioned countries "
                    f"(RU, IR, KP, CU, SY)."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 15 CFR §774 EAR — ECCN 5E002 export licence
        if doc.get("eccn_5e002_classification", False) and not doc.get("ear_export_licence", False):
            return FilterResult(
                decision="DENIED",
                regulation="15 CFR §774 EAR ECCN 5E002",
                reason=(
                    "15 CFR §774 EAR: Industrial control system technology classified "
                    "under ECCN 5E002 requires a US Department of Commerce export licence "
                    "before export to non-EAR99 destinations."
                ),
                filter_name=self.FILTER_NAME,
            )

        # 50 U.S.C. §4565 CFIUS — China OT critical infrastructure
        if destination == "CN" and doc.get("ot_critical_infrastructure_data", False) and not doc.get(
            "cfius_review_completed", False
        ):
            return FilterResult(
                decision="DENIED",
                regulation="50 U.S.C. §4565 CFIUS",
                reason=(
                    "50 U.S.C. §4565 CFIUS: Transfer of OT critical infrastructure data "
                    "to China (CN) requires mandatory CFIUS review. Transaction must be "
                    "reviewed and cleared before data transfer proceeds."
                ),
                filter_name=self.FILTER_NAME,
            )

        # EU NIS2 Directive 2022/2555 Art. 26 — NCA notification
        if doc.get("nis2_essential_entity", False) and doc.get("cross_border_ot_data", False) and not doc.get(
            "nca_notification_filed", False
        ):
            return FilterResult(
                decision="REQUIRES_HUMAN_REVIEW",
                regulation="EU NIS2 Directive 2022/2555 Art. 26",
                reason=(
                    "EU NIS2 Directive 2022/2555 Art. 26: NIS2-essential entity OT "
                    "cross-border data sharing requires National Competent Authority "
                    "(NCA) notification within the prescribed timeframe."
                ),
                filter_name=self.FILTER_NAME,
            )

        return FilterResult(
            decision="PERMITTED",
            regulation="OFAC; EAR 15 CFR §774; CFIUS; EU NIS2 Art. 26",
            reason="Document satisfies cross-border OT/IoT export control requirements.",
            filter_name=self.FILTER_NAME,
        )


# ---------------------------------------------------------------------------
# Pipeline helper
# ---------------------------------------------------------------------------


def run_pipeline(doc: dict) -> list[FilterResult]:
    """Run all four IoT/OT security filter layers against *doc*.

    Returns a list of four FilterResult objects, one per layer.  The pipeline
    short-circuits on the first DENIED decision; subsequent filters are not
    evaluated for denied documents.
    """
    filters = [
        NISTIoTFilter(),
        IEC62443OTFilter(),
        TSAOTSecurityFilter(),
        OTCrossBorderFilter(),
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
    print("=== IoT/OT Security Compliance RAG Pipeline — Demo ===\n")

    # --- Non-compliant IoT device (no identity management) ---
    doc_no_identity = {
        "doc_id": "iot-001",
        "is_iot_device": True,
        "device_identity_management": False,
    }
    print("Document: IoT device without identity management")
    for r in run_pipeline(doc_no_identity):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- OT/SCADA without Security Level assessment ---
    doc_no_sl = {
        "doc_id": "ot-002",
        "is_ot_scada": True,
        "security_level_assessed": False,
    }
    print("Document: OT/SCADA without Security Level assessment")
    for r in run_pipeline(doc_no_sl):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Critical pipeline OT without incident reporting ---
    doc_pipeline = {
        "doc_id": "pipe-003",
        "is_critical_pipeline_ot": True,
        "tsa_incident_reporting_capable": False,
    }
    print("Document: Critical pipeline OT without TSA incident reporting")
    for r in run_pipeline(doc_pipeline):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- OT data export to Russia ---
    doc_ofac = {
        "doc_id": "export-004",
        "destination_country": "RU",
    }
    print("Document: OT data export to Russia (OFAC sanctioned)")
    for r in run_pipeline(doc_ofac):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()

    # --- Fully compliant IoT/OT document ---
    doc_compliant = {
        "doc_id": "compliant-005",
        "is_iot_device": True,
        "device_identity_management": True,
        "configuration_management": True,
        "is_critical_iot": True,
        "network_access_controls": True,
        "crypto_protection_in_transit": True,
        "is_ot_scada": True,
        "security_level_assessed": True,
        "is_industrial_control_system": True,
        "zone_conduit_model": True,
        "remote_access_to_ot": True,
        "defense_in_depth_remote": True,
        "is_iacs_component": True,
        "patch_management_plan": True,
        "is_critical_pipeline_ot": True,
        "tsa_incident_reporting_capable": True,
        "destination_country": "DE",
    }
    print("Document: Fully compliant IoT/OT system")
    for r in run_pipeline(doc_compliant):
        print(f"  [{r.filter_name}] {r.decision} — {r.regulation}")
    print()
    print("Demo complete.")
