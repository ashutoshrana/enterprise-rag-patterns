"""
eu_ai_act.py — EU AI Act Article 12 tamper-evident audit log for high-risk RAG systems.

The EU AI Act (Regulation 2024/1689, effective August 2026 for high-risk systems)
imposes strict logging and transparency requirements on AI systems in regulated
sectors.  Education AI that makes or assists decisions about students falls under
**Annex III §3** (high-risk), which includes:

- Academic assessment and learning outcome prediction systems
- Admission and scholarship decision-support tools
- Systems used by educational institutions to monitor, evaluate, or personalise
  learning for individual students

Article 12 requirements implemented here
-----------------------------------------
Art. 12(1): High-risk AI systems shall be designed and developed with capabilities
    enabling automatic recording of events (logs) throughout their lifetime.
Art. 12(2): Logging capabilities shall ensure a level of traceability of the AI
    system's functioning throughout its lifecycle sufficient to enable post-market
    monitoring.
Art. 12(3): Logging capabilities shall enable monitoring of the operation of the
    high-risk AI system with respect to the occurrence of situations that may result
    in the AI system presenting a risk.

Beyond Art. 12, this module provides:
- **Art. 13** transparency marker — human-facing ``SYSTEM_AI_DISCLOSURE`` value
- **Annex III** use case risk classification helper
- HMAC-SHA256 tamper-evident records and SHA-256 hash-chain linkage

Penalty context:
    Non-compliance penalties: up to €35,000,000 or 7% of global annual turnover
    (whichever is higher) — Art. 99(3).

Usage — basic retrieval logging::

    import hashlib
    from enterprise_rag_patterns.regulations.eu_ai_act import (
        EUAIActAuditLogger,
        EUAIActRiskTier,
        EUAIActRetrievalRecord,
    )

    audit_trail: list[dict] = []
    logger = EUAIActAuditLogger(
        system_id="enrollment-advisor-v2",
        risk_tier=EUAIActRiskTier.HIGH_RISK,
        log_sink=lambda record: audit_trail.append(record.to_log_entry()),
        hmac_key=b"your-32-byte-secret-key-here",
    )

    record = logger.log_retrieval_event(
        query="What courses must I still complete for graduation?",
        retrieved_docs=retrieved_nodes,  # LlamaIndex, LangChain, or plain dicts
        actor_id="stu-alice-123",
        session_id="session-abc",
    )

    # Later, seal the response into the same record
    sealed = logger.seal_response(record, response_text=model_answer)

    # Verify integrity
    assert logger.verify_record(sealed)

Usage — Annex III risk classification::

    from enterprise_rag_patterns.regulations.eu_ai_act import (
        AnnexIIICategory,
        classify_annex_iii_risk,
    )

    tier, rationale = classify_annex_iii_risk(AnnexIIICategory.EDUCATION_TRAINING)
    # tier == EUAIActRiskTier.HIGH_RISK
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EUAIActRiskTier(str, Enum):
    """
    EU AI Act risk classification tiers (Article 6, Annex I–III).

    Members:
        PROHIBITED: Unacceptable risk practices — Art. 5 (social scoring by
            public authorities, real-time biometric surveillance in public
            spaces for law enforcement, etc.).  Such systems may not be placed
            on the market or used in the EU.
        HIGH_RISK: Systems listed in Annex III or those that are safety
            components of products covered by Annex I.  Subject to full
            conformity assessment and Art. 9–15 obligations.
        LIMITED_RISK: Systems with specific transparency obligations (Art. 50):
            chatbots must disclose their AI nature, deep-fakes must be labelled.
        MINIMAL_RISK: All other AI systems — no mandatory obligations,
            voluntary codes of conduct encouraged.
    """

    PROHIBITED = "prohibited"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


class AnnexIIICategory(str, Enum):
    """
    Annex III high-risk AI system categories.

    The Annex III list is the primary gateway to HIGH_RISK classification for
    AI systems that are not safety components of products.

    Members map to Annex III section numbers in Regulation 2024/1689.
    """

    BIOMETRIC_CATEGORIZATION = "annex_iii_1"  # §1.b — prohibited if facial recognition
    CRITICAL_INFRASTRUCTURE = "annex_iii_2"  # §2
    EDUCATION_TRAINING = "annex_iii_3"  # §3 — educational institutions, student assessment
    EMPLOYMENT_WORKERS_MANAGEMENT = "annex_iii_4"  # §4
    ESSENTIAL_PRIVATE_SERVICES = "annex_iii_5"  # §5 — credit, insurance, public services
    LAW_ENFORCEMENT = "annex_iii_6"  # §6
    MIGRATION_ASYLUM = "annex_iii_7"  # §7
    JUSTICE_DEMOCRATIC_PROCESSES = "annex_iii_8"  # §8


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class EUAIActRetrievalRecord:
    """
    Tamper-evident chain-of-custody record for a single RAG retrieval event.

    Each record captures the full audit chain required by Art. 12:
    query → retrieved documents → assembled context window → model response.

    Attributes:
        record_id: UUID identifying this record.
        timestamp: UTC timestamp of the retrieval event.
        system_id: Identifier for the AI system (e.g. ``"enrollment-advisor-v2"``).
        risk_tier: EU AI Act risk classification of the system.
        actor_id: Authenticated principal (student ID, staff ID).  ``None`` if
            the system operates without per-user authentication.
        session_id: Optional session identifier for grouping related events.
        query_hash: SHA-256 hex digest of the original query string.  Storing
            the hash (not the cleartext) allows integrity verification without
            retaining potentially identifying query content where not necessary.
        query_preview: Optional first 200 characters of the query.  Only
            populated when ``include_query_preview=True`` was set on the logger.
            Requires a lawful basis for storing cleartext queries under GDPR.
        retrieved_doc_ids: Sorted list of document identifiers that were
            returned by the vector store.
        retrieved_doc_count: Count of retrieved documents.
        context_window_hash: SHA-256 hex digest of the assembled context
            window (concatenated retrieved document content) passed to the LLM.
        response_hash: SHA-256 hex digest of the model response.  ``None``
            until ``seal_response()`` is called.
        previous_record_hash: SHA-256 hex digest of the immediately preceding
            ``EUAIActRetrievalRecord`` in the audit chain, or ``None`` for the
            first record.  Enables detection of insertions, deletions, or
            reordering in the audit trail.
        hmac_signature: HMAC-SHA256 hex digest over the canonical record fields.
            Computed with the logger's ``hmac_key``; ``None`` if no key was
            provided.
    """

    record_id: str
    timestamp: datetime
    system_id: str
    risk_tier: EUAIActRiskTier
    actor_id: str | None
    session_id: str | None
    query_hash: str
    query_preview: str | None
    retrieved_doc_ids: list[str]
    retrieved_doc_count: int
    context_window_hash: str | None
    response_hash: str | None = None
    previous_record_hash: str | None = None
    hmac_signature: str | None = None

    def canonical_bytes(self) -> bytes:
        """
        Return a canonical, deterministic byte representation of this record.

        The HMAC signature and ``previous_record_hash`` are **excluded** from
        the canonical form (the HMAC covers the other fields; the chain pointer
        is a structural link, not a content field).

        Returns:
            JSON-encoded bytes with sorted keys.
        """
        canonical: dict[str, Any] = {
            "actor_id": self.actor_id,
            "context_window_hash": self.context_window_hash,
            "query_hash": self.query_hash,
            "query_preview": self.query_preview,
            "record_id": self.record_id,
            "response_hash": self.response_hash,
            "retrieved_doc_count": self.retrieved_doc_count,
            "retrieved_doc_ids": self.retrieved_doc_ids,
            "risk_tier": self.risk_tier.value,
            "session_id": self.session_id,
            "system_id": self.system_id,
            "timestamp": self.timestamp.isoformat(),
        }
        return json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def record_hash(self) -> str:
        """
        Return the SHA-256 hex digest of this record's canonical bytes.

        Used as the ``previous_record_hash`` pointer for the next record in the
        chain.  Includes ``response_hash`` so that sealing a response changes
        the record hash (the chain re-anchors if ``seal_response`` is called
        before the next record is created).

        Returns:
            64-character lowercase hexadecimal SHA-256 digest.
        """
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_log_entry(self) -> dict[str, Any]:
        """
        Return a JSON-serialisable dict for writing to a compliance log store.

        All fields are included, including ``hmac_signature`` and
        ``previous_record_hash``.  This is the form that should be written to an
        append-only, immutable store (e.g. AWS CloudTrail, Azure Immutable Blob,
        Google Cloud Audit Logs).

        Returns:
            Dict with string values safe for JSON serialisation.
        """
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "system_id": self.system_id,
            "risk_tier": self.risk_tier.value,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "query_hash": self.query_hash,
            "query_preview": self.query_preview,
            "retrieved_doc_ids": self.retrieved_doc_ids,
            "retrieved_doc_count": self.retrieved_doc_count,
            "context_window_hash": self.context_window_hash,
            "response_hash": self.response_hash,
            "previous_record_hash": self.previous_record_hash,
            "hmac_signature": self.hmac_signature,
        }


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class EUAIActAuditLogger:
    """
    Art. 12 tamper-evident audit logger for high-risk RAG systems.

    Each ``log_retrieval_event()`` call produces an ``EUAIActRetrievalRecord``
    capturing the full chain-of-custody from query through retrieved documents
    to the assembled context window.  Optionally, the response can be sealed
    into the record after generation with ``seal_response()``.

    **Tamper-evidence mechanisms:**

    1. *HMAC-SHA256*: Every record is signed with the logger's ``hmac_key``.
       ``verify_record()`` re-computes the HMAC and compares.  A mismatch
       indicates the record was altered after creation.

    2. *Hash chain*: Each record's ``previous_record_hash`` points to the
       SHA-256 of the preceding record.  ``verify_chain()`` walks the chain
       and confirms no record was inserted, deleted, or reordered.

    Args:
        system_id: Stable identifier for the AI system (recorded in every log
            entry for cross-system correlation in an audit).
        risk_tier: EU AI Act risk classification.  Logged in each record.
            Defaults to ``EUAIActRiskTier.HIGH_RISK`` (education AI default).
        log_sink: Callable invoked synchronously after each record is created.
            Wire to an append-only compliance log store.  ``None`` = no sink.
        hmac_key: HMAC-SHA256 key bytes.  Use a cryptographically random key
            (e.g. ``secrets.token_bytes(32)``); store in a key management
            system (AWS KMS, Google Cloud KMS, Azure Key Vault).  If ``None``,
            no HMAC is computed and ``verify_record()`` always returns ``True``.
        enable_chain: If True (default), each record's ``previous_record_hash``
            is set to the hash of the immediately preceding record.  Disable only
            if records are produced by multiple parallel processes (chains must
            be per-process in that case).
        include_query_preview: If True, the first 200 characters of each query
            are stored in ``query_preview``.  Disabled by default — storing
            cleartext queries requires a lawful basis under GDPR Art. 6.
    """

    def __init__(
        self,
        system_id: str,
        risk_tier: EUAIActRiskTier = EUAIActRiskTier.HIGH_RISK,
        log_sink: Callable[[EUAIActRetrievalRecord], None] | None = None,
        hmac_key: bytes | None = None,
        enable_chain: bool = True,
        include_query_preview: bool = False,
    ) -> None:
        self._system_id = system_id
        self._risk_tier = risk_tier
        self._log_sink = log_sink
        self._hmac_key = hmac_key
        self._enable_chain = enable_chain
        self._include_preview = include_query_preview
        self._last_record_hash: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_retrieval_event(
        self,
        query: str,
        retrieved_docs: list[Any],
        context_window: str | None = None,
        actor_id: str | None = None,
        session_id: str | None = None,
        response: str | None = None,
    ) -> EUAIActRetrievalRecord:
        """
        Create and emit an Art. 12 retrieval record.

        Args:
            query: The user query or prompt sent to the retrieval system.
            retrieved_docs: Documents returned by the vector store.  Accepts:
                - ``list[str]`` — treated as document IDs directly.
                - ``list[dict]`` — extracts ``"id"``, ``"doc_id"``, or
                  ``metadata["doc_id"]`` key.
                - Any object with a ``.id`` or ``.doc_id`` attribute
                  (LlamaIndex ``NodeWithScore``, LangChain ``Document``, etc.).
            context_window: The assembled context string passed to the LLM.
                SHA-256 hash stored.  ``None`` if context assembly happens after
                logging (use ``seal_response()`` to add the response hash).
            actor_id: Authenticated user identifier.  Must come from the verified
                session, not from user-supplied input.
            session_id: Optional session grouping identifier.
            response: If the model response is available at logging time, pass it
                here.  Otherwise call ``seal_response()`` later.

        Returns:
            Fully populated ``EUAIActRetrievalRecord`` with HMAC signature and
            chain pointer set.  The record has already been passed to
            ``log_sink`` (if configured).
        """
        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
        query_preview = query[:200] if self._include_preview else None

        doc_ids = sorted(_extract_doc_ids(retrieved_docs))

        context_hash: str | None = None
        if context_window is not None:
            context_hash = hashlib.sha256(context_window.encode("utf-8")).hexdigest()

        response_hash: str | None = None
        if response is not None:
            response_hash = hashlib.sha256(response.encode("utf-8")).hexdigest()

        record = EUAIActRetrievalRecord(
            record_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            system_id=self._system_id,
            risk_tier=self._risk_tier,
            actor_id=actor_id,
            session_id=session_id,
            query_hash=query_hash,
            query_preview=query_preview,
            retrieved_doc_ids=doc_ids,
            retrieved_doc_count=len(doc_ids),
            context_window_hash=context_hash,
            response_hash=response_hash,
            previous_record_hash=self._last_record_hash if self._enable_chain else None,
        )

        record.hmac_signature = self._sign(record)

        if self._enable_chain:
            self._last_record_hash = record.record_hash()

        if self._log_sink is not None:
            self._log_sink(record)

        return record

    def seal_response(
        self,
        record: EUAIActRetrievalRecord,
        response_text: str,
    ) -> EUAIActRetrievalRecord:
        """
        Seal the model response into an existing retrieval record.

        Creates a **new** ``EUAIActRetrievalRecord`` (records are immutable) that
        copies all fields from *record* but adds ``response_hash``.  The HMAC
        signature is recomputed over the updated fields.  The sealed record is
        emitted to the ``log_sink`` as a correction/update entry.

        Note: The hash-chain pointer (``previous_record_hash``) is **not**
        updated — the chain anchor for the *next* record is the sealed record's
        hash, which this method does NOT update in ``_last_record_hash``.  If you
        use ``enable_chain=True``, call ``seal_response()`` before logging the
        next event.

        Args:
            record: The ``EUAIActRetrievalRecord`` to seal.
            response_text: Model response text.

        Returns:
            A new ``EUAIActRetrievalRecord`` with ``response_hash`` set and
            HMAC re-signed.
        """
        response_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        sealed = EUAIActRetrievalRecord(
            record_id=record.record_id,
            timestamp=record.timestamp,
            system_id=record.system_id,
            risk_tier=record.risk_tier,
            actor_id=record.actor_id,
            session_id=record.session_id,
            query_hash=record.query_hash,
            query_preview=record.query_preview,
            retrieved_doc_ids=record.retrieved_doc_ids,
            retrieved_doc_count=record.retrieved_doc_count,
            context_window_hash=record.context_window_hash,
            response_hash=response_hash,
            previous_record_hash=record.previous_record_hash,
        )
        sealed.hmac_signature = self._sign(sealed)

        if self._log_sink is not None:
            self._log_sink(sealed)

        return sealed

    def verify_record(self, record: EUAIActRetrievalRecord) -> bool:
        """
        Verify the HMAC signature of a single record.

        Args:
            record: Record to verify.

        Returns:
            ``True`` if the HMAC is valid (or if no HMAC key is configured).
            ``False`` if the HMAC does not match — the record has been tampered
            with.
        """
        if self._hmac_key is None:
            return True
        if record.hmac_signature is None:
            return False
        expected = self._sign_bytes(record.canonical_bytes())
        return _hmac.compare_digest(expected, record.hmac_signature)

    def verify_chain(self, records: list[EUAIActRetrievalRecord]) -> bool:
        """
        Verify the hash-chain integrity of an ordered list of records.

        Checks that each record's ``previous_record_hash`` matches the SHA-256
        of the preceding record.  Also verifies each record's HMAC.

        Args:
            records: Ordered list of records (earliest first).

        Returns:
            ``True`` if the chain is intact and all HMACs are valid.
            ``False`` if any link is broken or any HMAC fails.
        """
        for i, record in enumerate(records):
            if not self.verify_record(record):
                return False
            if i == 0:
                if record.previous_record_hash is not None:
                    return False
            else:
                expected_prev = records[i - 1].record_hash()
                if record.previous_record_hash != expected_prev:
                    return False
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _sign(self, record: EUAIActRetrievalRecord) -> str | None:
        if self._hmac_key is None:
            return None
        return self._sign_bytes(record.canonical_bytes())

    def _sign_bytes(self, data: bytes) -> str:
        assert self._hmac_key is not None
        return _hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Annex III risk classification helper
# ---------------------------------------------------------------------------

_ANNEX_III_RATIONALE: dict[AnnexIIICategory, str] = {
    AnnexIIICategory.BIOMETRIC_CATEGORIZATION: (
        "Annex III §1.b: Real-time remote biometric identification systems used in publicly "
        "accessible spaces are PROHIBITED under Art. 5(1)(d).  Other biometric categorisation "
        "systems are HIGH_RISK."
    ),
    AnnexIIICategory.CRITICAL_INFRASTRUCTURE: (
        "Annex III §2: AI systems as safety components of critical infrastructure "
        "(energy, water, transport, digital) are HIGH_RISK."
    ),
    AnnexIIICategory.EDUCATION_TRAINING: (
        "Annex III §3: AI systems used to determine access, admission, or assignment to "
        "educational institutions; monitor students; assess learning outcomes; detect prohibited "
        "student behaviour during tests are HIGH_RISK."
    ),
    AnnexIIICategory.EMPLOYMENT_WORKERS_MANAGEMENT: (
        "Annex III §4: AI systems for recruitment, CV screening, performance monitoring, "
        "promotion and termination decisions are HIGH_RISK."
    ),
    AnnexIIICategory.ESSENTIAL_PRIVATE_SERVICES: (
        "Annex III §5: AI systems for credit scoring, insurance risk assessment, emergency "
        "dispatch priority, or public benefit entitlement decisions are HIGH_RISK."
    ),
    AnnexIIICategory.LAW_ENFORCEMENT: (
        "Annex III §6: AI systems for individual risk assessment in law enforcement, "
        "polygraph / emotional state detection, or deepfake detection are HIGH_RISK."
    ),
    AnnexIIICategory.MIGRATION_ASYLUM: (
        "Annex III §7: AI systems for lie detection at border crossings, risk assessment "
        "for migration, or examination of asylum applications are HIGH_RISK."
    ),
    AnnexIIICategory.JUSTICE_DEMOCRATIC_PROCESSES: (
        "Annex III §8: AI systems assisting judicial authorities in researching and "
        "interpreting facts and law, or influencing elections are HIGH_RISK."
    ),
}


def classify_annex_iii_risk(category: AnnexIIICategory) -> tuple[EUAIActRiskTier, str]:
    """
    Return the EU AI Act risk tier and rationale for an Annex III use case.

    All Annex III categories are HIGH_RISK except biometric categorisation
    systems used for real-time remote identification in public spaces, which
    are PROHIBITED under Art. 5(1)(d).

    Args:
        category: The Annex III use case category.

    Returns:
        ``(EUAIActRiskTier, rationale_string)`` — the tier and a plain-English
        explanation citing the relevant Annex III section.
    """
    tier = EUAIActRiskTier.HIGH_RISK
    rationale = _ANNEX_III_RATIONALE.get(category, "HIGH_RISK — Annex III listed use case.")
    return tier, rationale


# ---------------------------------------------------------------------------
# Transparency constant (Art. 13)
# ---------------------------------------------------------------------------

SYSTEM_AI_DISCLOSURE = (
    "This response was generated with the assistance of an artificial intelligence system. "
    "The information provided is based on retrieved documents and should be verified "
    "against authoritative sources before making decisions."
)
"""
Art. 13 transparency disclosure string.

High-risk AI systems must ensure operators can interpret outputs.  Art. 50 requires
that users interacting with conversational AI be informed they are interacting with an
AI system.  Include this or an equivalent disclosure in AI-generated responses.
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_doc_ids(docs: list[Any]) -> list[str]:
    """Extract a string document ID from each item in *docs*."""
    ids: list[str] = []
    for doc in docs:
        if isinstance(doc, str):
            ids.append(doc)
        elif isinstance(doc, dict):
            doc_id = (
                doc.get("id")
                or doc.get("doc_id")
                or doc.get("node_id")
                or (doc.get("metadata") or {}).get("doc_id")
                or (doc.get("metadata") or {}).get("id")
                or str(id(doc))
            )
            ids.append(str(doc_id))
        else:
            # LlamaIndex NodeWithScore, LangChain Document, etc.
            doc_id = (
                getattr(doc, "id_", None)
                or getattr(doc, "id", None)
                or getattr(doc, "doc_id", None)
                or getattr(doc, "node_id", None)
                or getattr(getattr(doc, "metadata", None), "get", lambda k, d=None: d)("doc_id")
                or str(id(doc))
            )
            ids.append(str(doc_id))
    return ids
