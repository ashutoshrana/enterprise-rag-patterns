"""
regulations/owasp_llm.py — OWASP LLM Top 10 (2025) security patterns for RAG.

Provides RAG-specific security controls aligned with the OWASP Top 10 for Large
Language Model Applications (v2.0, 2025 edition).

The two OWASP LLM risks most directly applicable to RAG pipelines are:

  LLM02 — Sensitive Information Disclosure
    RAG pipelines retrieve documents from knowledge bases that may contain PII,
    credentials, confidential contracts, or regulated data (HIPAA, FERPA, GDPR).
    Without pre-retrieval scoping, the LLM context window becomes an
    uncontrolled data exposure surface.

  LLM08 — Excessive Agency
    A RAG pipeline with tool-calling capability may retrieve documents that
    grant the LLM access to actions beyond its intended scope.  Vector store
    queries should be scoped to the minimum data set authorized for the agent.

Additional risks addressed:

  LLM01 — Prompt Injection
    Adversarial content embedded in retrieved documents can hijack the LLM.
    A pre-synthesis content scan detects and quarantines suspicious patterns.

  LLM06 — Excessive Autonomy (moved to LLM08 in v2.0)
    Retrieval-based tool discovery should be policy-gated.

Usage
------

.. code-block:: python

    from enterprise_rag_patterns.regulations.owasp_llm import (
        OWASPLLMRisk,
        OWASPSensitiveDisclosureFilter,
        OWASPPromptInjectionScanner,
        OWASPAuditRecord,
    )

    # LLM02: filter sensitive fields before context assembly
    filter = OWASPSensitiveDisclosureFilter(
        sensitive_fields={"ssn", "credit_card", "password", "api_key"},
    )
    safe_docs = filter.redact(retrieved_docs)

    # LLM01: scan retrieved docs for prompt injection patterns
    scanner = OWASPPromptInjectionScanner()
    clean_docs, flagged = scanner.scan(retrieved_docs)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class OWASPLLMRisk(str, Enum):
    """OWASP LLM Top 10 (2025) risk identifiers."""

    LLM01_PROMPT_INJECTION = "LLM01:2025"
    LLM02_SENSITIVE_DISCLOSURE = "LLM02:2025"
    LLM03_SUPPLY_CHAIN = "LLM03:2025"
    LLM04_DATA_POISONING = "LLM04:2025"
    LLM05_INSECURE_OUTPUT = "LLM05:2025"
    LLM06_EXCESSIVE_AGENCY = "LLM06:2025"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2025"
    LLM08_VECTOR_EMBEDDING_WEAKNESS = "LLM08:2025"
    LLM09_MISINFORMATION = "LLM09:2025"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025"


# ------------------------------------------------------------------
# Default PII detection patterns (non-exhaustive; extend for your context)
# ------------------------------------------------------------------
_DEFAULT_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d{4}[- ]){3}\d{4}\b")),
    ("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")),
    ("phone_us", re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("api_key", re.compile(r"\b[A-Za-z0-9]{32,64}\b")),
]

# Patterns that suggest prompt injection attempts in retrieved content
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+(?:now|a)\s+(?:an?\s+)?(?:new|different)\s+(?:ai|assistant|model)", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+(?:are|must|should)", re.IGNORECASE),
    re.compile(r"<\s*/?(?:system|user|assistant|human|ai)\s*>", re.IGNORECASE),
    re.compile(
        r"(?:disregard|forget|bypass)\s+(?:all\s+)?(?:your\s+)?(?:instructions?|constraints?|rules?)",
        re.IGNORECASE,
    ),
    re.compile(r"\[\s*INST\s*\]|\[\/INST\]|<\|(?:im_start|im_end|endoftext)\|>"),
]


@dataclass
class OWASPAuditRecord:
    """
    OWASP LLM Top 10 security event audit record for RAG pipelines.

    Captures security-relevant events (PII disclosure prevention, prompt
    injection detection, excessive agency blocks) for SIEM integration.

    Attributes:
        risk_id: OWASP LLM Top 10 risk identifier (e.g. ``"LLM02:2025"``).
        event_type: Specific event (``"pii_redacted"``, ``"injection_detected"``,
            ``"agency_blocked"``).
        documents_affected: Number of documents with detected security issue.
        fields_redacted: Names of fields redacted (for LLM02).
        injection_patterns_matched: Patterns matched (for LLM01).
        timestamp_utc: ISO 8601 UTC timestamp.
    """

    risk_id: str
    event_type: str
    documents_affected: int
    fields_redacted: list[str] = field(default_factory=list)
    injection_patterns_matched: list[str] = field(default_factory=list)
    timestamp_utc: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_log_entry(self) -> str:
        """Serialize to JSON for SIEM / security audit storage."""
        return json.dumps(
            {
                "framework": "OWASP_LLM_Top10_2025",
                "risk_id": self.risk_id,
                "event": self.event_type,
                "documents_affected": self.documents_affected,
                "fields_redacted": self.fields_redacted,
                "injection_patterns_matched": self.injection_patterns_matched,
                "timestamp_utc": self.timestamp_utc,
            },
            separators=(",", ":"),
        )


class OWASPSensitiveDisclosureFilter:
    """
    OWASP LLM02:2025 — Sensitive Information Disclosure prevention filter.

    Redacts or blocks documents containing sensitive fields before they enter
    the LLM context window.  Two enforcement modes:

    * ``redact`` — Replace sensitive field values with ``"[REDACTED]"``.
      Preserves document structure; LLM still sees all metadata keys.
    * ``block`` — Remove entire documents containing sensitive fields.
      Higher security; may reduce retrieval quality.

    Sensitive fields are checked in document metadata (dict keys).  For
    free-text content detection, add PII patterns via ``pii_patterns``.

    Args:
        sensitive_fields: Set of metadata field names to redact/block.
        pii_patterns: Additional (name, compiled_regex) pairs for text-level
            PII scanning.  Merged with the default patterns.
        mode: ``"redact"`` (default) or ``"block"``.
        audit_sink: Optional callable receiving ``OWASPAuditRecord``.
    """

    def __init__(
        self,
        sensitive_fields: set[str] | None = None,
        pii_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
        mode: str = "redact",
        audit_sink: Any | None = None,
    ) -> None:
        self._sensitive_fields = sensitive_fields or {
            "ssn",
            "credit_card",
            "password",
            "api_key",
            "secret",
            "private_key",
            "token",
        }
        self._pii_patterns = list(_DEFAULT_PII_PATTERNS) + (pii_patterns or [])
        if mode not in ("redact", "block"):
            raise ValueError("mode must be 'redact' or 'block'")
        self._mode = mode
        self._audit_sink = audit_sink

    def redact(self, documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Apply LLM02 protective filtering to retrieved documents.

        Args:
            documents: List of document dicts (keys are metadata fields).

        Returns:
            List with sensitive fields redacted or documents removed,
            depending on ``mode``.
        """
        result: list[dict[str, Any]] = []
        total_redacted_fields: set[str] = set()
        docs_affected = 0

        for doc in documents:
            redacted_fields: list[str] = []
            new_doc = dict(doc)

            # Field-level sensitivity check
            for key in list(new_doc.keys()):
                if key in self._sensitive_fields:
                    redacted_fields.append(key)
                    if self._mode == "redact":
                        new_doc[key] = "[REDACTED:LLM02]"

            # Text-content PII scan (on string fields)
            for key, value in new_doc.items():
                if not isinstance(value, str):
                    continue
                for pii_name, pattern in self._pii_patterns:
                    if pattern.search(value):
                        if self._mode == "redact":
                            new_doc[key] = pattern.sub("[REDACTED:PII]", new_doc[key])  # type: ignore[index]
                        redacted_fields.append(f"{key}:{pii_name}")

            if redacted_fields:
                docs_affected += 1
                total_redacted_fields.update(redacted_fields)
                if self._mode == "block":
                    continue  # drop document

            result.append(new_doc)

        if docs_affected > 0 and self._audit_sink is not None:
            self._audit_sink(
                OWASPAuditRecord(
                    risk_id=OWASPLLMRisk.LLM02_SENSITIVE_DISCLOSURE,
                    event_type="pii_redacted" if self._mode == "redact" else "documents_blocked",
                    documents_affected=docs_affected,
                    fields_redacted=sorted(total_redacted_fields),
                )
            )

        return result


class OWASPPromptInjectionScanner:
    """
    OWASP LLM01:2025 — Prompt Injection detection for retrieved documents.

    Scans document content for adversarial patterns that could hijack the
    LLM when the document is included in the context window.  This is a
    "defence-in-depth" control; it does NOT replace prompt hardening at
    the instruction level.

    Knowledge base poisoning (LLM04:2025) is mitigated by catching injection
    payloads at retrieval time rather than at ingestion time.

    Args:
        custom_patterns: Additional compiled patterns to scan for.
        audit_sink: Optional callable receiving ``OWASPAuditRecord``.
        quarantine_field: Document key to mark flagged documents.
            Set to None to remove flagged documents from results entirely.
    """

    def __init__(
        self,
        custom_patterns: list[re.Pattern[str]] | None = None,
        audit_sink: Any | None = None,
        quarantine_field: str | None = "_owasp_injection_flagged",
    ) -> None:
        self._patterns = list(_PROMPT_INJECTION_PATTERNS) + (custom_patterns or [])
        self._audit_sink = audit_sink
        self._quarantine_field = quarantine_field

    def scan(
        self,
        documents: list[dict[str, Any]],
        content_field: str = "content",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """
        Scan retrieved documents for prompt injection patterns.

        Args:
            documents: List of document dicts.
            content_field: Name of the text content field to scan.

        Returns:
            Tuple of (``clean_docs``, ``flagged_docs``).

            ``clean_docs`` — safe documents (or quarantine-marked if
            ``quarantine_field`` is set).
            ``flagged_docs`` — documents matching injection patterns.
        """
        clean: list[dict[str, Any]] = []
        flagged: list[dict[str, Any]] = []
        patterns_seen: set[str] = set()

        for doc in documents:
            content = doc.get(content_field, "")
            if not isinstance(content, str):
                clean.append(doc)
                continue

            matched: list[str] = []
            for pattern in self._patterns:
                if pattern.search(content):
                    matched.append(pattern.pattern)
                    patterns_seen.add(pattern.pattern[:60])

            if matched:
                flagged_doc = dict(doc)
                if self._quarantine_field is not None:
                    flagged_doc[self._quarantine_field] = True
                    flagged_doc["_owasp_matched_patterns"] = matched
                    clean.append(flagged_doc)
                flagged.append(flagged_doc)
            else:
                clean.append(doc)

        if flagged and self._audit_sink is not None:
            self._audit_sink(
                OWASPAuditRecord(
                    risk_id=OWASPLLMRisk.LLM01_PROMPT_INJECTION,
                    event_type="injection_detected",
                    documents_affected=len(flagged),
                    injection_patterns_matched=sorted(patterns_seen),
                )
            )

        return clean, flagged
