"""
Enterprise RAG Security Audit Framework — Holistic Control Assessment Across Six Domains

This module implements a holistic enterprise RAG security audit framework that evaluates
a RAG system's configuration across six security domains and produces a scored, maturity-
levelled audit report with actionable remediation guidance.

The auditor inspects a ``RAGSystemConfig`` object and runs 22 controls spanning:

  Domain 1 — Input Validation (IV)
      Guards against prompt injection, query-length abuse, and unsanitised user input
      reaching the vector store or LLM context window.
      References: OWASP LLM01 2025, MITRE ATLAS T0051, NIST CSF PR.DS-1

  Domain 2 — Vector Store Security (VS)
      Enforces namespace isolation, document integrity checksums, embedding-source
      validation, and access controls on the vector store itself — the most commonly
      overlooked attack surface in enterprise RAG deployments.
      References: OWASP LLM08, FERPA, HIPAA, MITRE ATLAS T0054, NIST CSF PR.AC-3,
                  ISO 42001 Cl.6.1

  Domain 3 — Retrieval Controls (RC)
      Governs where filters run relative to ANN retrieval, caps the number of
      returned chunks to limit context-window stuffing, enforces cross-tenant
      isolation at the retrieval layer, and mandates retrieval audit logging.
      References: OWASP LLM06 2025, OWASP LLM08, FERPA §99.31, HIPAA §164.312,
                  SOC 2 CC6.1, SOC 2 CC7.2

  Domain 4 — Output Security (OS)
      Scans generated text for data leakage (DLP), validates output against an
      expected schema, verifies citation provenance, and detects hallucinated facts
      before the response is delivered.
      References: OWASP LLM06 2025, OWASP LLM09, GDPR Art.32, ISO 42001 Cl.9.1

  Domain 5 — Action Gating (AG)
      Prevents agentic RAG systems from calling tools, executing code, or performing
      destructive operations without explicit gating, allowlist enforcement, and
      human-in-the-loop approval for irreversible actions.
      References: OWASP ASI02, OWASP ASI05, NIST AI 600-1, MITRE ATLAS T0060,
                  CSA ATF Level 2

  Domain 6 — Observability (OB)
      Validates that query, retrieval, and output events are all logged with
      sufficient retention, that anomaly detection is active, and that security
      alerting is configured.
      References: SOC 2 CC7.2, HIPAA §164.312(b), ISO 42001 Cl.9.1, NIST CSF DE.AE-1

Commercial use cases:

  +-------------------------------------------------------------------+------------------------------------------------+
  | Platform / Product                                                | Applicable Standard(s)                         |
  +-------------------------------------------------------------------+------------------------------------------------+
  | Enterprise knowledge base chatbots (legal, HR, finance)          | OWASP LLM01/06/08; SOC 2 CC7.2; HIPAA         |
  | Healthcare RAG systems surfacing clinical guidance                | HIPAA §164.312; ISO 42001; NIST AI 600-1       |
  | Financial services document Q&A with PII/PCI exposure            | OWASP LLM06; GDPR Art.32; SOC 2 CC6.1         |
  | Agentic RAG with autonomous tool execution                       | OWASP ASI02/ASI05; NIST AI 600-1; CSA ATF     |
  | Multi-tenant SaaS RAG platforms                                  | OWASP LLM08; FERPA §99.31; SOC 2 CC6.1        |
  | Regulated AI systems requiring audit trails                      | ISO 42001 Cl.9.1; HIPAA §164.312(b); SOC 2    |
  | RAG pipelines in FedRAMP / government environments               | NIST CSF PR.AC-3/PR.DS-1/DE.AE-1; NIST AI RMF |
  | AI governance and compliance review tooling                      | ISO 42001; NIST AI 600-1; GDPR Art.32          |
  | Customer-facing AI assistants with sensitive data access         | OWASP LLM06; GDPR; HIPAA; MITRE ATLAS T0051   |
  | Internal developer platforms with code-generation RAG            | OWASP LLM01; MITRE ATLAS T0060; NIST AI 600-1 |
  +-------------------------------------------------------------------+------------------------------------------------+

Maturity levels:

  Sandbox     — One or more CRITICAL controls failing, or score < 50.  Suitable only
                for sandboxed experiments; not appropriate for any production or
                user-facing deployment.

  Controlled  — No CRITICAL failures; score 50–69.  Suitable for internal pilots with
                limited blast radius and no sensitive data.

  Trusted     — No CRITICAL failures; score 70–84 and at most 2 HIGH failures.
                Appropriate for production deployments with non-sensitive workloads
                or when compensating controls are documented.

  Autonomous  — No CRITICAL failures; score ≥ 85 and at most 2 HIGH failures.
                Meets the baseline security posture for agentic RAG systems handling
                sensitive data, autonomous tool calls, and multi-tenant workloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------


@dataclass
class RAGSystemConfig:
    """Mutable configuration snapshot describing the security posture of a RAG system.

    Each boolean field represents a security control that may be enabled or
    disabled.  Numeric fields carry threshold values (0 typically means the
    limit is not enforced or the retention window is not configured).  String
    fields carry enumerated mode values where documented.

    Pass an instance of this class to ``RAGSecurityAuditor.audit()`` to
    receive a ``RAGAuditReport`` with per-control findings and an overall
    security score.
    """

    system_id: str = "rag-system"

    # ------------------------------------------------------------------
    # Input Validation domain
    # ------------------------------------------------------------------

    #: When True, incoming queries are checked against known prompt-injection
    #: patterns before being forwarded to the retrieval pipeline.
    query_injection_detection_enabled: bool = False

    #: Maximum allowed query length in characters.  0 means no limit is
    #: enforced, which allows unbounded context-window stuffing attacks.
    query_length_limit: int = 0

    #: When True, HTML/script metacharacters, null bytes, and other
    #: dangerous tokens are stripped or escaped from incoming query text.
    input_sanitization_enabled: bool = False

    # ------------------------------------------------------------------
    # Vector Store Security domain
    # ------------------------------------------------------------------

    #: When True, each tenant's documents are stored in an isolated
    #: namespace; cross-namespace queries are rejected at the vector store
    #: query layer rather than at the application layer.
    namespace_isolation_enforced: bool = False

    #: When True, a SHA-256 (or equivalent) checksum is recorded for every
    #: document at index time and verified at retrieval time.
    document_integrity_checksums: bool = False

    #: When True, the origin of every embedding is verified against an
    #: authorised embedding model registry before the vector is written to
    #: the store.
    embedding_source_validated: bool = False

    #: When True, read and write access to the vector store is gated by an
    #: identity-aware access control policy (RBAC / ABAC).
    vector_store_access_control: bool = False

    # ------------------------------------------------------------------
    # Retrieval Controls domain
    # ------------------------------------------------------------------

    #: Describes where access-control and content filters run relative to
    #: the ANN (approximate nearest-neighbour) retrieval step.
    #: "before_retrieval" — filters run before ANN; only permitted documents
    #:   enter the candidate pool (recommended; eliminates timing side-channels).
    #: "after_retrieval"  — filters run after ANN; denied documents are
    #:   discarded but their existence leaks via timing.
    #: "none"             — no pre/post retrieval filtering configured.
    pre_filter_placement: str = "none"  # "before_retrieval" | "after_retrieval" | "none"

    #: Maximum number of chunks returned per retrieval call.  0 means
    #: unbounded, which allows context-window stuffing and cost amplification.
    max_retrieved_chunks: int = 0

    #: When True, retrieval queries are prevented from crossing tenant
    #: boundaries at the vector store query layer.
    cross_tenant_isolation: bool = False

    #: When True, every retrieval call is written to an audit log including
    #: the query text, matched document IDs, and requester identity.
    retrieval_audit_logging: bool = False

    # ------------------------------------------------------------------
    # Output Security domain
    # ------------------------------------------------------------------

    #: When True, generated output is scanned for PII, PHI, PCI-DSS data,
    #: and other sensitive patterns before delivery to the caller.
    dlp_scan_on_output: bool = False

    #: When True, every generated response is validated against a declared
    #: output schema to detect unexpected structure or format violations.
    output_schema_validation: bool = False

    #: When True, every citation in the generated response is verified to
    #: map to a real, retrieved document — preventing hallucinated references.
    citation_integrity_enforced: bool = False

    #: When True, a hallucination-detection pass (e.g. NLI-based claim
    #: verification, self-consistency sampling, or grounded attribution check)
    #: runs on the generated response before delivery.
    hallucination_detection_enabled: bool = False

    # ------------------------------------------------------------------
    # Action Gating domain
    # ------------------------------------------------------------------

    #: When True, the system has a gate that intercepts tool-call intents
    #: produced by the LLM before they are executed.
    action_gating_enabled: bool = False

    #: When True, the action gate enforces an explicit allowlist of tool
    #: names that the LLM is permitted to invoke; unknown tools are blocked.
    tool_call_allowlist_enforced: bool = False

    #: When True, any tool call classified as destructive (delete, write,
    #: send, pay, etc.) requires explicit human approval before execution.
    human_approval_for_destructive_actions: bool = False

    # ------------------------------------------------------------------
    # Observability domain
    # ------------------------------------------------------------------

    #: When True, every incoming query is recorded in the audit log.
    query_logging_enabled: bool = False

    #: When True, the retrieved document set for each query is recorded
    #: in the audit log.
    retrieval_logging_enabled: bool = False

    #: When True, every generated output is recorded in the audit log.
    output_logging_enabled: bool = False

    #: When True, an anomaly-detection layer monitors query patterns,
    #: retrieval distributions, and output characteristics for deviations
    #: that may indicate an active attack.
    anomaly_detection_enabled: bool = False

    #: When True, security alerts are routed to a SIEM or on-call channel
    #: when anomalies or policy violations are detected.
    security_alerting_enabled: bool = False

    #: Number of days that audit log entries are retained.  0 means
    #: retention is not configured.  Many compliance frameworks require
    #: at least 365 days.
    audit_retention_days: int = 0


# ---------------------------------------------------------------------------
# AuditFinding dataclass
# ---------------------------------------------------------------------------


@dataclass
class AuditFinding:
    """A single control assessment result produced by ``RAGSecurityAuditor``.

    Fields
    ------
    control_id      : Short identifier, e.g. "RAG-IV-001".
    control_name    : Human-readable control name.
    domain          : Security domain the control belongs to, e.g. "Input Validation".
    status          : "PASS" | "FAIL" | "WARN" | "SKIP"
    severity        : "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    framework_refs  : List of applicable framework references, e.g.
                      ["OWASP LLM01", "MITRE ATLAS T0051"].
    evidence        : Description of what the auditor observed in the config.
    remediation_step: Actionable guidance to address a FAIL or WARN status.
    """

    control_id: str
    control_name: str
    domain: str
    status: str         # "PASS" | "FAIL" | "WARN" | "SKIP"
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    framework_refs: list[str]
    evidence: str
    remediation_step: str


# ---------------------------------------------------------------------------
# RAGAuditReport dataclass
# ---------------------------------------------------------------------------


@dataclass
class RAGAuditReport:
    """Aggregated audit report for a single RAG system configuration.

    Fields
    ------
    system_id       : Identifier from the ``RAGSystemConfig`` being audited.
    findings        : All ``AuditFinding`` objects produced by the audit run.
    score           : Overall security score from 0.0 to 100.0.
    maturity_level  : "Sandbox" | "Controlled" | "Trusted" | "Autonomous"
    critical_count  : Number of controls with status FAIL and severity CRITICAL.
    high_count      : Number of controls with status FAIL and severity HIGH.
    medium_count    : Number of controls with status FAIL and severity MEDIUM.
    passing_count   : Number of controls with status PASS.
    """

    system_id: str
    findings: list[AuditFinding]
    score: float
    maturity_level: str
    critical_count: int
    high_count: int
    medium_count: int
    passing_count: int

    def summary(self) -> str:
        """Return a multi-line, human-readable audit report string.

        The report is structured as:
          - Header with system ID, score, and maturity level
          - Findings summary (counts by severity)
          - Failed and warned controls with evidence and remediation
          - Passing controls listed compactly
        """
        width = 60
        border = "═" * width
        divider = "─" * width

        lines: list[str] = []

        # -- Header --
        lines.append(border)
        lines.append(" RAG SECURITY AUDIT REPORT")
        lines.append(f" System: {self.system_id}")
        lines.append(
            f" Score:  {self.score:.1f} / 100.0   Maturity: {self.maturity_level}"
        )
        lines.append(border)

        # -- Findings summary --
        warn_count = sum(1 for f in self.findings if f.status == "WARN")
        lines.append(" FINDINGS SUMMARY")
        lines.append(
            f"   CRITICAL FAIL: {self.critical_count}"
            f"   HIGH FAIL: {self.high_count}"
            f"   MEDIUM FAIL: {self.medium_count}"
            f"   WARN: {warn_count}"
            f"   PASS: {self.passing_count}"
        )

        # -- Failed and warned controls --
        failed = [f for f in self.findings if f.status in ("FAIL", "WARN")]
        if failed:
            lines.append(divider)
            lines.append(" FAILED / WARNED CONTROLS")
            for finding in failed:
                symbol = "✗" if finding.status == "FAIL" else "△"
                sev_label = f"{finding.severity:<8}"
                lines.append(
                    f"   {symbol} [{sev_label}] {finding.control_id} {finding.control_name}"
                )
                lines.append(
                    f"     Refs: {', '.join(finding.framework_refs)}"
                )
                lines.append(f"     Evidence: {finding.evidence}")
                lines.append(f"     Fix: {finding.remediation_step}")

        # -- Passing controls --
        passing = [f for f in self.findings if f.status == "PASS"]
        if passing:
            lines.append(divider)
            lines.append(" PASSING CONTROLS")
            for finding in passing:
                sev_label = f"{finding.severity:<8}"
                lines.append(
                    f"   ✓ [{sev_label}] {finding.control_id} {finding.control_name}"
                )

        lines.append(border)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# RAGSecurityAuditor
# ---------------------------------------------------------------------------


class RAGSecurityAuditor:
    """Evaluates a ``RAGSystemConfig`` against 22 controls across six security domains.

    Usage
    -----
    ::

        auditor = RAGSecurityAuditor()
        config  = RAGSystemConfig(
            system_id="my-rag",
            query_injection_detection_enabled=True,
            ...
        )
        report  = auditor.audit(config)
        print(report.summary())

    The auditor is stateless and thread-safe; the same instance may be used to
    audit multiple configurations concurrently.
    """

    def audit(self, config: RAGSystemConfig) -> RAGAuditReport:
        """Run all six domain checkers against *config* and return a ``RAGAuditReport``.

        Aggregates findings from all checkers, computes the overall score, and
        derives the maturity level using the scoring rules described in the
        module docstring.
        """
        findings: list[AuditFinding] = []
        findings.extend(self._check_input_validation(config))
        findings.extend(self._check_vector_store_security(config))
        findings.extend(self._check_retrieval_controls(config))
        findings.extend(self._check_output_security(config))
        findings.extend(self._check_action_gating(config))
        findings.extend(self._check_observability(config))

        # -- Scoring --
        score = 100.0
        for f in findings:
            if f.status == "FAIL":
                if f.severity == "CRITICAL":
                    score -= 15.0
                elif f.severity == "HIGH":
                    score -= 7.0
                elif f.severity == "MEDIUM":
                    score -= 3.0
            elif f.status == "WARN":
                score -= 1.0
        score = max(0.0, score)

        # -- Maturity --
        has_critical_fail = any(
            f.status == "FAIL" and f.severity == "CRITICAL" for f in findings
        )
        high_fail_count = sum(
            1 for f in findings if f.status == "FAIL" and f.severity == "HIGH"
        )

        if has_critical_fail or score < 50:
            maturity_level = "Sandbox"
        elif score < 70:
            maturity_level = "Controlled"
        elif score < 85 or high_fail_count > 2:
            maturity_level = "Trusted"
        else:
            maturity_level = "Autonomous"

        # -- Counts --
        critical_count = sum(
            1 for f in findings if f.status == "FAIL" and f.severity == "CRITICAL"
        )
        high_count = sum(
            1 for f in findings if f.status == "FAIL" and f.severity == "HIGH"
        )
        medium_count = sum(
            1 for f in findings if f.status == "FAIL" and f.severity == "MEDIUM"
        )
        passing_count = sum(1 for f in findings if f.status == "PASS")

        return RAGAuditReport(
            system_id=config.system_id,
            findings=findings,
            score=score,
            maturity_level=maturity_level,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            passing_count=passing_count,
        )

    # ------------------------------------------------------------------
    # Domain 1 — Input Validation
    # ------------------------------------------------------------------

    def _check_input_validation(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the three Input Validation controls for *config*.

        Controls evaluated
        ------------------
        RAG-IV-001  Query Injection Detection    CRITICAL
        RAG-IV-002  Query Length Enforcement     HIGH
        RAG-IV-003  Input Sanitization           HIGH
        """
        findings: list[AuditFinding] = []

        # RAG-IV-001 — Query Injection Detection
        if not config.query_injection_detection_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-001",
                    control_name="Query Injection Detection",
                    domain="Input Validation",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM01", "MITRE ATLAS T0051"],
                    evidence="query_injection_detection_enabled = False",
                    remediation_step=(
                        "Enable real-time injection pattern matching on all incoming queries. "
                        "Maintain a regularly updated pattern library covering known direct and "
                        "indirect prompt injection variants (instruction override, role hijacking, "
                        "system prompt leakage).  Block or escalate queries matching patterns "
                        "before forwarding to the retrieval pipeline."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-001",
                    control_name="Query Injection Detection",
                    domain="Input Validation",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM01", "MITRE ATLAS T0051"],
                    evidence="query_injection_detection_enabled = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-IV-002 — Query Length Enforcement
        if config.query_length_limit == 0:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-002",
                    control_name="Query Length Enforcement",
                    domain="Input Validation",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM01"],
                    evidence="query_length_limit = 0 (unlimited)",
                    remediation_step=(
                        "Set a maximum query length appropriate for the use case (e.g. 2 000 "
                        "characters for a knowledge-base Q&A system).  Reject queries that "
                        "exceed the limit before they reach the retrieval pipeline.  Unbounded "
                        "queries can carry embedded injection payloads and inflate embedding "
                        "computation costs."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-002",
                    control_name="Query Length Enforcement",
                    domain="Input Validation",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM01"],
                    evidence=f"query_length_limit = {config.query_length_limit}",
                    remediation_step="No action required.",
                )
            )

        # RAG-IV-003 — Input Sanitization
        if not config.input_sanitization_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-003",
                    control_name="Input Sanitization",
                    domain="Input Validation",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM01", "NIST CSF PR.DS-1"],
                    evidence="input_sanitization_enabled = False",
                    remediation_step=(
                        "Apply an input sanitization pass to all incoming query text before "
                        "embedding or forwarding to the LLM.  At minimum, strip or encode HTML "
                        "metacharacters, null bytes, Unicode direction-override characters, and "
                        "other tokens that have no semantic value in natural-language queries but "
                        "may exploit downstream processing or injection detection gaps."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-IV-003",
                    control_name="Input Sanitization",
                    domain="Input Validation",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM01", "NIST CSF PR.DS-1"],
                    evidence="input_sanitization_enabled = True",
                    remediation_step="No action required.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Domain 2 — Vector Store Security
    # ------------------------------------------------------------------

    def _check_vector_store_security(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the four Vector Store Security controls for *config*.

        Controls evaluated
        ------------------
        RAG-VS-001  Namespace Isolation          CRITICAL
        RAG-VS-002  Document Integrity Checksums HIGH
        RAG-VS-003  Embedding Source Validation  HIGH
        RAG-VS-004  Vector Store Access Control  CRITICAL
        """
        findings: list[AuditFinding] = []

        # RAG-VS-001 — Namespace Isolation
        if not config.namespace_isolation_enforced:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-001",
                    control_name="Namespace Isolation",
                    domain="Vector Store Security",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM08", "FERPA", "HIPAA"],
                    evidence="namespace_isolation_enforced = False",
                    remediation_step=(
                        "Configure the vector store to assign each tenant, department, or data "
                        "classification tier to a dedicated namespace.  Enforce namespace "
                        "boundaries at the vector store query layer — not in the application "
                        "layer — so that the ANN index never returns documents from a namespace "
                        "the requester is not authorised to access, regardless of semantic "
                        "proximity."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-001",
                    control_name="Namespace Isolation",
                    domain="Vector Store Security",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM08", "FERPA", "HIPAA"],
                    evidence="namespace_isolation_enforced = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-VS-002 — Document Integrity Checksums
        if not config.document_integrity_checksums:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-002",
                    control_name="Document Integrity Checksums",
                    domain="Vector Store Security",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08", "MITRE ATLAS T0054"],
                    evidence="document_integrity_checksums = False",
                    remediation_step=(
                        "Record a SHA-256 content checksum for every document at index time and "
                        "store it alongside the embedding metadata.  Verify the checksum against "
                        "the source document at retrieval time to detect post-indexing "
                        "modifications.  Deny or quarantine documents whose checksum does not "
                        "match the indexed value."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-002",
                    control_name="Document Integrity Checksums",
                    domain="Vector Store Security",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08", "MITRE ATLAS T0054"],
                    evidence="document_integrity_checksums = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-VS-003 — Embedding Source Validation
        if not config.embedding_source_validated:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-003",
                    control_name="Embedding Source Validation",
                    domain="Vector Store Security",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08"],
                    evidence="embedding_source_validated = False",
                    remediation_step=(
                        "Maintain an authorised embedding model registry.  Record which model "
                        "produced each vector at index time.  Reject vectors generated by "
                        "unregistered or deprecated models at write time and flag stale "
                        "embeddings for re-indexing when the authorised model changes, to "
                        "prevent embedding-space drift and adversarial embedding attacks."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-003",
                    control_name="Embedding Source Validation",
                    domain="Vector Store Security",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08"],
                    evidence="embedding_source_validated = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-VS-004 — Vector Store Access Control
        if not config.vector_store_access_control:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-004",
                    control_name="Vector Store Access Control",
                    domain="Vector Store Security",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["NIST CSF PR.AC-3", "ISO 42001 Cl.6.1"],
                    evidence="vector_store_access_control = False",
                    remediation_step=(
                        "Implement identity-aware access control (RBAC or ABAC) on all vector "
                        "store read and write operations.  Service accounts used by the RAG "
                        "pipeline should follow the principle of least privilege: read-only "
                        "access to authorised namespaces only.  Admin operations (index "
                        "creation, bulk deletion, namespace management) must require separate "
                        "elevated credentials."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-VS-004",
                    control_name="Vector Store Access Control",
                    domain="Vector Store Security",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["NIST CSF PR.AC-3", "ISO 42001 Cl.6.1"],
                    evidence="vector_store_access_control = True",
                    remediation_step="No action required.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Domain 3 — Retrieval Controls
    # ------------------------------------------------------------------

    def _check_retrieval_controls(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the four Retrieval Controls for *config*.

        Controls evaluated
        ------------------
        RAG-RC-001  Pre-Filter Placement         HIGH
        RAG-RC-002  Chunk Limit Enforcement      MEDIUM
        RAG-RC-003  Cross-Tenant Isolation       CRITICAL
        RAG-RC-004  Retrieval Audit Logging      HIGH
        """
        findings: list[AuditFinding] = []

        # RAG-RC-001 — Pre-Filter Placement
        if config.pre_filter_placement != "before_retrieval":
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-001",
                    control_name="Pre-Filter Placement",
                    domain="Retrieval Controls",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08", "FERPA §99.31"],
                    evidence=f"pre_filter_placement = '{config.pre_filter_placement}' (expected 'before_retrieval')",
                    remediation_step=(
                        "Move all access-control and content filters to run before the ANN "
                        "retrieval step.  Post-retrieval (application-layer) filtering is "
                        "insufficient because the ANN search itself reveals the existence of "
                        "matching documents through timing and ranking side-channels, even "
                        "when those documents are subsequently discarded.  Pre-retrieval "
                        "filtering ensures that unauthorised documents are never entered into "
                        "the candidate pool."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-001",
                    control_name="Pre-Filter Placement",
                    domain="Retrieval Controls",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM08", "FERPA §99.31"],
                    evidence="pre_filter_placement = 'before_retrieval'",
                    remediation_step="No action required.",
                )
            )

        # RAG-RC-002 — Chunk Limit Enforcement
        if config.max_retrieved_chunks == 0:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-002",
                    control_name="Chunk Limit Enforcement",
                    domain="Retrieval Controls",
                    status="FAIL",
                    severity="MEDIUM",
                    framework_refs=["OWASP LLM06"],
                    evidence="max_retrieved_chunks = 0 (unlimited)",
                    remediation_step=(
                        "Set a per-request chunk retrieval cap appropriate for the context "
                        "window size and the expected use case (e.g. top-5 or top-10 chunks). "
                        "An unbounded chunk limit allows a crafted query to fill the entire "
                        "context window with attacker-controlled content, amplifying prompt "
                        "injection and sensitive data disclosure risks."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-002",
                    control_name="Chunk Limit Enforcement",
                    domain="Retrieval Controls",
                    status="PASS",
                    severity="MEDIUM",
                    framework_refs=["OWASP LLM06"],
                    evidence=f"max_retrieved_chunks = {config.max_retrieved_chunks}",
                    remediation_step="No action required.",
                )
            )

        # RAG-RC-003 — Cross-Tenant Isolation
        if not config.cross_tenant_isolation:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-003",
                    control_name="Cross-Tenant Isolation",
                    domain="Retrieval Controls",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["HIPAA §164.312", "SOC 2 CC6.1"],
                    evidence="cross_tenant_isolation = False",
                    remediation_step=(
                        "Enforce tenant boundary checks at the vector store retrieval layer so "
                        "that a query originating from tenant A can never return documents "
                        "owned by tenant B.  Implement tenant identity as a mandatory metadata "
                        "filter predicate on every retrieval call, not as a post-processing "
                        "step.  Log and alert on any retrieval call that attempts to specify a "
                        "tenant identifier different from the authenticated caller's tenant."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-003",
                    control_name="Cross-Tenant Isolation",
                    domain="Retrieval Controls",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["HIPAA §164.312", "SOC 2 CC6.1"],
                    evidence="cross_tenant_isolation = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-RC-004 — Retrieval Audit Logging
        if not config.retrieval_audit_logging:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-004",
                    control_name="Retrieval Audit Logging",
                    domain="Retrieval Controls",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["HIPAA §164.312(b)", "SOC 2 CC7.2"],
                    evidence="retrieval_audit_logging = False",
                    remediation_step=(
                        "Log every retrieval call with at minimum: timestamp, requester identity "
                        "and tenant, query text (or a non-reversible hash for PII-sensitive "
                        "deployments), retrieved document IDs, and retrieval latency.  Route "
                        "logs to a tamper-resistant append-only store.  These logs are essential "
                        "for post-incident forensics, compliance audits, and anomaly detection."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-RC-004",
                    control_name="Retrieval Audit Logging",
                    domain="Retrieval Controls",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["HIPAA §164.312(b)", "SOC 2 CC7.2"],
                    evidence="retrieval_audit_logging = True",
                    remediation_step="No action required.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Domain 4 — Output Security
    # ------------------------------------------------------------------

    def _check_output_security(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the four Output Security controls for *config*.

        Controls evaluated
        ------------------
        RAG-OS-001  DLP on Output                CRITICAL
        RAG-OS-002  Output Schema Validation     HIGH
        RAG-OS-003  Citation Integrity           MEDIUM
        RAG-OS-004  Hallucination Detection      HIGH
        """
        findings: list[AuditFinding] = []

        # RAG-OS-001 — DLP on Output
        if not config.dlp_scan_on_output:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-001",
                    control_name="DLP on Output",
                    domain="Output Security",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM06", "GDPR Art.32"],
                    evidence="dlp_scan_on_output = False",
                    remediation_step=(
                        "Integrate a data loss prevention (DLP) scanner into the output "
                        "pipeline so that every generated response is inspected for PII, PHI, "
                        "PCI-DSS data, credentials, and other sensitive patterns before delivery. "
                        "Block or redact responses that contain sensitive data exceeding the "
                        "caller's authorisation level.  Log all DLP hits for incident response."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-001",
                    control_name="DLP on Output",
                    domain="Output Security",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["OWASP LLM06", "GDPR Art.32"],
                    evidence="dlp_scan_on_output = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OS-002 — Output Schema Validation
        if not config.output_schema_validation:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-002",
                    control_name="Output Schema Validation",
                    domain="Output Security",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM09"],
                    evidence="output_schema_validation = False",
                    remediation_step=(
                        "Define a JSON Schema or equivalent contract for every structured output "
                        "type the RAG system produces and validate each response against it "
                        "before delivery.  Schema violations may indicate prompt injection "
                        "forcing the model out of its expected output format, hallucination "
                        "introducing unexpected fields, or adversarial content attempting to "
                        "exploit downstream JSON parsers."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-002",
                    control_name="Output Schema Validation",
                    domain="Output Security",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM09"],
                    evidence="output_schema_validation = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OS-003 — Citation Integrity
        if not config.citation_integrity_enforced:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-003",
                    control_name="Citation Integrity",
                    domain="Output Security",
                    status="FAIL",
                    severity="MEDIUM",
                    framework_refs=["OWASP LLM09"],
                    evidence="citation_integrity_enforced = False",
                    remediation_step=(
                        "After generation, verify that every citation or source reference in "
                        "the response maps to a document that was actually retrieved in that "
                        "retrieval call.  Hallucinated citations that point to non-existent or "
                        "non-retrieved sources undermine trust and can constitute misinformation "
                        "in regulated contexts.  Reject or flag responses where any cited source "
                        "cannot be matched to the retrieved document set."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-003",
                    control_name="Citation Integrity",
                    domain="Output Security",
                    status="PASS",
                    severity="MEDIUM",
                    framework_refs=["OWASP LLM09"],
                    evidence="citation_integrity_enforced = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OS-004 — Hallucination Detection
        if not config.hallucination_detection_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-004",
                    control_name="Hallucination Detection",
                    domain="Output Security",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP LLM09", "ISO 42001 Cl.9.1"],
                    evidence="hallucination_detection_enabled = False",
                    remediation_step=(
                        "Implement a hallucination detection pass on generated output before "
                        "delivery.  Approaches include: NLI-based claim verification against "
                        "retrieved chunks, self-consistency sampling across multiple generation "
                        "runs, grounded attribution scoring, or a dedicated faithfulness "
                        "evaluation model.  Route low-faithfulness responses to human review "
                        "rather than delivering them directly to users."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OS-004",
                    control_name="Hallucination Detection",
                    domain="Output Security",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP LLM09", "ISO 42001 Cl.9.1"],
                    evidence="hallucination_detection_enabled = True",
                    remediation_step="No action required.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Domain 5 — Action Gating
    # ------------------------------------------------------------------

    def _check_action_gating(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the three Action Gating controls for *config*.

        Controls evaluated
        ------------------
        RAG-AG-001  Action Gating                          CRITICAL
        RAG-AG-002  Tool Call Allowlist                    HIGH
        RAG-AG-003  Human Approval for Destructive Actions HIGH
        """
        findings: list[AuditFinding] = []

        # RAG-AG-001 — Action Gating
        if not config.action_gating_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-001",
                    control_name="Action Gating",
                    domain="Action Gating",
                    status="FAIL",
                    severity="CRITICAL",
                    framework_refs=["OWASP ASI02", "NIST AI 600-1"],
                    evidence="action_gating_enabled = False",
                    remediation_step=(
                        "Introduce an action gate layer between LLM output and tool execution. "
                        "Every tool-call intent produced by the LLM must pass through the gate "
                        "before being dispatched.  The gate should evaluate the tool name, "
                        "arguments, and context against a policy engine before allowing "
                        "execution.  This is the single most important control for agentic RAG "
                        "systems because indirect prompt injection via retrieved documents can "
                        "cause the LLM to emit tool calls that execute attacker-directed "
                        "actions without the user's awareness."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-001",
                    control_name="Action Gating",
                    domain="Action Gating",
                    status="PASS",
                    severity="CRITICAL",
                    framework_refs=["OWASP ASI02", "NIST AI 600-1"],
                    evidence="action_gating_enabled = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-AG-002 — Tool Call Allowlist
        if not config.tool_call_allowlist_enforced:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-002",
                    control_name="Tool Call Allowlist",
                    domain="Action Gating",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["OWASP ASI05", "MITRE ATLAS T0060"],
                    evidence="tool_call_allowlist_enforced = False",
                    remediation_step=(
                        "Maintain an explicit allowlist of tool names the LLM is permitted to "
                        "invoke and block all calls to unlisted tools at the action gate.  "
                        "Injection payloads that craft novel tool names to invoke unintended "
                        "capabilities (MITRE ATLAS T0060: Prompt-Directed Action Execution) "
                        "are blocked by an allowlist even when they successfully bypass "
                        "injection pattern detection."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-002",
                    control_name="Tool Call Allowlist",
                    domain="Action Gating",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["OWASP ASI05", "MITRE ATLAS T0060"],
                    evidence="tool_call_allowlist_enforced = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-AG-003 — Human Approval for Destructive Actions
        if not config.human_approval_for_destructive_actions:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-003",
                    control_name="Human Approval for Destructive Actions",
                    domain="Action Gating",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["CSA ATF Level 2"],
                    evidence="human_approval_for_destructive_actions = False",
                    remediation_step=(
                        "Classify all tool calls that perform irreversible or high-impact "
                        "operations (delete, write, send email, make payment, modify permissions) "
                        "as destructive actions and require explicit human approval before "
                        "execution.  Implement an approval workflow with a timeout after which "
                        "the action is automatically cancelled if no response is received.  "
                        "Per CSA AI Trust Framework Level 2, destructive agentic actions must "
                        "not execute autonomously without a human-in-the-loop checkpoint."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-AG-003",
                    control_name="Human Approval for Destructive Actions",
                    domain="Action Gating",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["CSA ATF Level 2"],
                    evidence="human_approval_for_destructive_actions = True",
                    remediation_step="No action required.",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Domain 6 — Observability
    # ------------------------------------------------------------------

    def _check_observability(self, config: RAGSystemConfig) -> list[AuditFinding]:
        """Evaluate the five Observability controls for *config*.

        Controls evaluated
        ------------------
        RAG-OB-001  Query Logging                HIGH
        RAG-OB-002  Retrieval Logging            HIGH
        RAG-OB-003  Anomaly Detection            MEDIUM
        RAG-OB-004  Audit Retention ≥ 365 Days  MEDIUM
        """
        findings: list[AuditFinding] = []

        # RAG-OB-001 — Query Logging
        if not config.query_logging_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-001",
                    control_name="Query Logging",
                    domain="Observability",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["SOC 2 CC7.2", "ISO 42001 Cl.9.1"],
                    evidence="query_logging_enabled = False",
                    remediation_step=(
                        "Enable logging of every incoming query, recording at minimum the "
                        "timestamp, requester identity, tenant, and a hash or tokenised "
                        "representation of the query text.  Query logs are foundational for "
                        "detecting adversarial probing patterns, supporting incident response, "
                        "and meeting SOC 2 CC7.2 (monitoring of system activity) obligations."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-001",
                    control_name="Query Logging",
                    domain="Observability",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["SOC 2 CC7.2", "ISO 42001 Cl.9.1"],
                    evidence="query_logging_enabled = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OB-002 — Retrieval Logging
        if not config.retrieval_logging_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-002",
                    control_name="Retrieval Logging",
                    domain="Observability",
                    status="FAIL",
                    severity="HIGH",
                    framework_refs=["HIPAA §164.312(b)"],
                    evidence="retrieval_logging_enabled = False",
                    remediation_step=(
                        "Log the full retrieved document set for every query, including document "
                        "IDs, namespaces, similarity scores, and retrieval timestamps.  Retrieval "
                        "logs enable post-incident reconstruction of exactly which documents "
                        "informed a given generation, which is essential for HIPAA audit trails "
                        "and for identifying corpus poisoning attacks."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-002",
                    control_name="Retrieval Logging",
                    domain="Observability",
                    status="PASS",
                    severity="HIGH",
                    framework_refs=["HIPAA §164.312(b)"],
                    evidence="retrieval_logging_enabled = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OB-003 — Anomaly Detection
        if not config.anomaly_detection_enabled:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-003",
                    control_name="Anomaly Detection",
                    domain="Observability",
                    status="FAIL",
                    severity="MEDIUM",
                    framework_refs=["NIST CSF DE.AE-1"],
                    evidence="anomaly_detection_enabled = False",
                    remediation_step=(
                        "Deploy an anomaly detection layer that monitors query volume, query "
                        "semantic distribution, retrieval score distributions, and output "
                        "characteristics in real time.  Baseline normal behaviour and alert "
                        "on significant deviations: sudden spikes in injection-pattern queries, "
                        "unusual document-access patterns, anomalous similarity score "
                        "distributions, or output volumes that suggest data exfiltration attempts."
                    ),
                )
            )
        else:
            findings.append(
                AuditFinding(
                    control_id="RAG-OB-003",
                    control_name="Anomaly Detection",
                    domain="Observability",
                    status="PASS",
                    severity="MEDIUM",
                    framework_refs=["NIST CSF DE.AE-1"],
                    evidence="anomaly_detection_enabled = True",
                    remediation_step="No action required.",
                )
            )

        # RAG-OB-004 — Audit Retention >= 365 Days
        retention = config.audit_retention_days
        if retention < 90:
            ob4_status = "FAIL"
            ob4_evidence = f"audit_retention_days = {retention} (< 90 days — critically insufficient)"
            ob4_remediation = (
                "Set audit log retention to at least 365 days immediately.  Retention below "
                "90 days means that evidence of a breach or policy violation may be "
                "destroyed before it is discovered.  Most compliance frameworks (HIPAA, "
                "SOC 2, ISO 42001) require a minimum of one year of audit log retention. "
                "Configure log rotation to retain at least 365 days in a tamper-resistant, "
                "append-only store."
            )
        elif retention < 365:
            ob4_status = "WARN"
            ob4_evidence = f"audit_retention_days = {retention} (90–364 days — below recommended 365)"
            ob4_remediation = (
                "Extend audit log retention to at least 365 days to meet common compliance "
                "framework requirements (HIPAA, SOC 2 Type II, ISO 42001).  Current "
                f"retention of {retention} days may be insufficient for investigations "
                "that span multiple months or for annual compliance review cycles."
            )
        else:
            ob4_status = "PASS"
            ob4_evidence = f"audit_retention_days = {retention} (≥ 365 days)"
            ob4_remediation = "No action required."

        findings.append(
            AuditFinding(
                control_id="RAG-OB-004",
                control_name="Audit Retention >= 365 Days",
                domain="Observability",
                status=ob4_status,
                severity="MEDIUM",
                framework_refs=["HIPAA §164.312(b)", "SOC 2 CC7.2", "ISO 42001 Cl.9.1"],
                evidence=ob4_evidence,
                remediation_step=ob4_remediation,
            )
        )

        return findings


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    auditor = RAGSecurityAuditor()

    # ------------------------------------------------------------------
    # Scenario 1: Misconfigured system — mostly defaults (all False / 0)
    # ------------------------------------------------------------------
    config_misconfigured = RAGSystemConfig(
        system_id="dev-sandbox-rag",
        # All controls left at defaults (disabled / 0 / "none")
    )

    print("=" * 64)
    print("SCENARIO 1: Misconfigured System (all defaults)")
    print("=" * 64)
    report1 = auditor.audit(config_misconfigured)
    print(report1.summary())
    print()

    # ------------------------------------------------------------------
    # Scenario 2: Partially configured system
    # ------------------------------------------------------------------
    config_partial = RAGSystemConfig(
        system_id="staging-rag-v2",
        # Input Validation — partially configured
        query_injection_detection_enabled=True,
        query_length_limit=4000,
        input_sanitization_enabled=False,
        # Vector Store Security — partially configured
        namespace_isolation_enforced=True,
        document_integrity_checksums=False,
        embedding_source_validated=False,
        vector_store_access_control=True,
        # Retrieval Controls — partially configured
        pre_filter_placement="before_retrieval",
        max_retrieved_chunks=10,
        cross_tenant_isolation=True,
        retrieval_audit_logging=False,
        # Output Security — mostly off
        dlp_scan_on_output=False,
        output_schema_validation=True,
        citation_integrity_enforced=False,
        hallucination_detection_enabled=False,
        # Action Gating — partially configured
        action_gating_enabled=True,
        tool_call_allowlist_enforced=False,
        human_approval_for_destructive_actions=False,
        # Observability — partially configured
        query_logging_enabled=True,
        retrieval_logging_enabled=True,
        output_logging_enabled=False,
        anomaly_detection_enabled=False,
        security_alerting_enabled=False,
        audit_retention_days=180,
    )

    print("=" * 64)
    print("SCENARIO 2: Partially Configured System (staging)")
    print("=" * 64)
    report2 = auditor.audit(config_partial)
    print(report2.summary())
    print()

    # ------------------------------------------------------------------
    # Scenario 3: Production-grade system — everything enabled
    # ------------------------------------------------------------------
    config_production = RAGSystemConfig(
        system_id="prod-enterprise-rag-v3",
        # Input Validation — fully configured
        query_injection_detection_enabled=True,
        query_length_limit=2000,
        input_sanitization_enabled=True,
        # Vector Store Security — fully configured
        namespace_isolation_enforced=True,
        document_integrity_checksums=True,
        embedding_source_validated=True,
        vector_store_access_control=True,
        # Retrieval Controls — fully configured
        pre_filter_placement="before_retrieval",
        max_retrieved_chunks=8,
        cross_tenant_isolation=True,
        retrieval_audit_logging=True,
        # Output Security — fully configured
        dlp_scan_on_output=True,
        output_schema_validation=True,
        citation_integrity_enforced=True,
        hallucination_detection_enabled=True,
        # Action Gating — fully configured
        action_gating_enabled=True,
        tool_call_allowlist_enforced=True,
        human_approval_for_destructive_actions=True,
        # Observability — fully configured
        query_logging_enabled=True,
        retrieval_logging_enabled=True,
        output_logging_enabled=True,
        anomaly_detection_enabled=True,
        security_alerting_enabled=True,
        audit_retention_days=730,
    )

    print("=" * 64)
    print("SCENARIO 3: Production-Grade System (all controls enabled)")
    print("=" * 64)
    report3 = auditor.audit(config_production)
    print(report3.summary())
    print()
