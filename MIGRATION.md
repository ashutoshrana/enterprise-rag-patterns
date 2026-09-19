# Strict retrieval authorization (unreleased)

Private records must contain non-empty string student, institution, and category metadata. Missing, null, empty, or malformed values are denied. Existing valid scopes retain their category allowlists. This is an intentional breaking security change: repair ingestion metadata before upgrading; do not automatically classify missing metadata as public.

Shared documents must be explicitly tagged `classification: public` and contain neither student nor institution identity keys. The public classification is an ingestion trust boundary: only trusted ingestion administrators may apply it after reviewing the content. A public label does not override conflicting identity tags. Custom identity/category field names continue to apply.

Use an explicit authorization step immediately before prompt assembly. Treat metadata and scope supplied by an authenticated application as policy inputs; do not let model output or untrusted callers choose their own scope. These software controls do not themselves establish regulatory compliance.

## Verification

Run the ordinary tests and `pytest integration_tests` separately: legacy tests use module-level framework mocks. Real integration tests require installed SDKs and record model inputs locally without model API calls. No release or package publication occurs from these changes. Repository source versions can be ahead of GitHub/PyPI releases; install a reviewed commit when testing unreleased changes.

## SDK compatibility

The real integration matrix tests LangChain Core 0.3.0 and latest with InMemoryVectorStore, and Haystack 2.20.0 and latest with InMemoryDocumentStore/BM25. Current versions observed during validation: LangChain Core 1.6.3 and Haystack 3.1.1. These are local store tests, not certification of hosted stores. Latest dependency resolution is checked in CI; it is not a promise that every future version will work.

Prefer `FERPAFilterRunnable.as_runnable()` for explicit enforcement. The compatibility callback now implements callback-manager attributes and sanitizes before raising, because managers may suppress callback exceptions. It runs inline; pass it using invocation `config={"callbacks": [handler]}`. Haystack pipelines should instantiate `_make_haystack_component()()` until a public registered factory is introduced.

## Standalone LlamaIndex adapter (0.47.1)

`FERPANodePostprocessor` now applies the same strict category and metadata policy as the workflow and LCEL adapters, including explicit public classification. It preserves `NodeWithScore` objects and implements async postprocessing. Real query-engine tests inspect the full synthetic model prompt on both sync and async paths. CI tests LlamaIndex Core 0.12.0 and the latest resolved version; see the [upstream postprocessor interface](https://github.com/run-llama/llama_index/blob/main/llama-index-core/llama_index/core/postprocessor/types.py).
