# Strict retrieval authorization (unreleased)

Private records must contain non-empty string student, institution, and category metadata. Missing, null, empty, or malformed values are denied. Existing valid scopes retain their category allowlists. This is an intentional breaking security change: repair ingestion metadata before upgrading; do not automatically classify missing metadata as public.

Shared documents must be explicitly tagged `classification: public` and contain neither student nor institution identity keys. The public classification is an ingestion trust boundary: only trusted ingestion administrators may apply it after reviewing the content. A public label does not override conflicting identity tags. Custom identity/category field names continue to apply.

Use an explicit authorization step immediately before prompt assembly. Treat metadata and scope supplied by an authenticated application as policy inputs; do not let model output or untrusted callers choose their own scope. These software controls do not themselves establish regulatory compliance.

## Verification

Run the ordinary tests and `pytest integration_tests` separately: legacy tests use module-level framework mocks. Real integration tests require installed SDKs and record model inputs locally without model API calls. No release or package publication occurs from these changes. Repository source versions can be ahead of GitHub/PyPI releases; install a reviewed commit when testing unreleased changes.

## SDK compatibility

The real integration matrix tests LangChain Core 0.3.0 and latest with InMemoryVectorStore, and Haystack 2.20.0 and latest with InMemoryDocumentStore/BM25. Local validation on 2026-10-26 passed with LangChain Core 1.7.0, LlamaIndex Core 0.14.25 and Haystack 3.4.1, and repeated the Haystack tests with 2.20.0 on Python 3.12.12. Python 3.10 was checked for source syntax only in this run; the current Haystack 3 line requires Python 3.11 or newer. These are local store tests, not certification of hosted stores. Latest dependency resolution is checked in CI; it is not a promise that every future version will work.

Prefer `FERPAFilterRunnable.as_runnable()` for explicit enforcement. The compatibility callback now implements callback-manager attributes and sanitizes before raising, because managers may suppress callback exceptions. It runs inline; pass it using invocation `config={"callbacks": [handler]}`. Haystack pipelines now instantiate `FERPAHaystackFilter()` directly; the private factory remains available for existing callers. Construction registers the component lazily, preserving imports without Haystack installed. Saved pipelines reference a stable optional component module, so loading them in a fresh process registers it automatically. Haystack 3 additionally requires `allowed_modules=["enterprise_rag_patterns.integrations._haystack_component"]` when loading this component; include any other application components explicitly, following the [upstream migration guide](https://github.com/deepset-ai/haystack/blob/main/MIGRATION.md).

The Haystack component runs after retrieval and before prompt construction. It does not apply document-store query filters. `ComplianceFilter` validates non-empty string principals at construction for the existing native store adapters; the Haystack component validates them on every run. Invalid principals raise `ValueError`, even for empty document lists.

## Standalone LlamaIndex adapter (0.47.1)

`FERPANodePostprocessor` now applies the same strict category and metadata policy as the workflow and LCEL adapters, including explicit public classification. It preserves `NodeWithScore` objects and implements async postprocessing. Real query-engine tests inspect the full synthetic model prompt on both sync and async paths. CI tests LlamaIndex Core 0.12.0 and the latest resolved version; see the [upstream postprocessor interface](https://github.com/run-llama/llama_index/blob/main/llama-index-core/llama_index/core/postprocessor/types.py).

## Retired MAF extra (0.48.0)

The earlier `[maf]` extra required `microsoft-agent-framework`, which is unavailable from the package registry. Its `FERPAAgentMiddleware.on_message` implementation was exercised with SDK stubs, not native SDK registration. The unavailable extra is retired and excluded from `[all]`; the existing module and callable API remain for legacy callers. This release does not claim native Microsoft Agent Framework support. Use the framework-independent policy core while a native integration remains unimplemented and untested.

## Security quarantine (0.48.0)

The `[dspy]` and `[chromadb]` extras are removed from metadata and `[all]`. Their resolved SDK graphs include outstanding advisories: DSPy brings LiteLLM and DiskCache; ChromaDB has server authorization/code-execution findings. No compatible, reviewed graph clears all findings. Adapter modules remain importable for legacy callers, but these integrations are unsupported and security quarantined. Unknown-extra warnings from pip are not evidence that an old installation command provides the SDK. Install the core or a supported extra instead. Restoration requires a fresh Python 3.10/3.12 dependency audit with no ignored CVEs plus native permit, deny, malformed-input and bypass tests. This is a dependency-risk boundary; it does not claim a reproduced exploit in this package.

## Python support by installation path

The core package remains supported on Python 3.10+. `llama-index` and `all` require Python 3.11+ because the patched Pillow 13 / dnspython 2.9 dependency versions no longer support 3.10. These fixed dependencies are unconditional: requesting an affected extra on Python 3.10 fails dependency resolution rather than silently omitting its SDK or selecting an affected older fallback. The native SDK CI matrix for these paths runs on Python 3.11 and 3.12. Other extras and core tests retain their declared Python 3.10 support.
