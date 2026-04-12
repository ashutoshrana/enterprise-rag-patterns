"""
integrations — Framework integration adapters for enterprise RAG compliance.

Provides compliance-aware bridge components for popular AI orchestration
frameworks.  All framework-specific imports are lazy so the package can be
installed without any framework dependency.

Available integrations
----------------------
- ``FERPANodePostprocessor``         — LlamaIndex 0.10+ ``BaseNodePostprocessor``
- ``FERPAHaystackFilter``            — Haystack 2.x ``@component``
- ``FERPAComplianceCallbackHandler`` — LangChain callback handler (duck-typed)
"""

from .haystack import FERPAHaystackFilter
from .langchain import FERPAComplianceCallbackHandler
from .llama_index import FERPANodePostprocessor

__all__ = [
    "FERPANodePostprocessor",
    "FERPAHaystackFilter",
    "FERPAComplianceCallbackHandler",
]
