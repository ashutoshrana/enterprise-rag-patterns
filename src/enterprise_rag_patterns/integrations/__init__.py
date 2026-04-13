"""
integrations — Framework integration adapters for enterprise RAG compliance.

Provides compliance-aware bridge components for popular AI orchestration
frameworks.  All framework-specific imports are lazy so the package can be
installed without any framework dependency.

Available integrations
----------------------
- ``FERPANodePostprocessor``         — LlamaIndex 0.10+ ``BaseNodePostprocessor``
- ``FERPAWorkflowStep``              — LlamaIndex 0.12+ ``Workflow`` step (event-driven)
- ``FERPAFilterEvent``               — LlamaIndex Workflow event type
- ``FERPAHaystackFilter``            — Haystack 2.x ``@component``
- ``FERPAComplianceCallbackHandler`` — LangChain callback handler (duck-typed)
- ``FERPAAgentMiddleware``           — Microsoft Agent Framework (MAF) middleware
"""

from .haystack import FERPAHaystackFilter
from .langchain import FERPAComplianceCallbackHandler
from .langchain_lcel import FERPAFilterRunnable, make_ferpa_chain
from .llama_index import FERPANodePostprocessor
from .llama_index_workflow import FERPAFilterEvent, FERPAWorkflowStep
from .maf import FERPAAgentMiddleware

__all__ = [
    "FERPANodePostprocessor",
    "FERPAWorkflowStep",
    "FERPAFilterEvent",
    "FERPAHaystackFilter",
    "FERPAComplianceCallbackHandler",
    "FERPAFilterRunnable",
    "make_ferpa_chain",
    "FERPAAgentMiddleware",
]
