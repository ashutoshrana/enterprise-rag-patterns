"""Small synthetic boundary benchmark: actual BM25 retrieval, no model service."""

import argparse
import asyncio
import hashlib
import inspect
import json
import math
import platform
import re
import statistics
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

from haystack import Document, Pipeline, component
from haystack.components.builders import PromptBuilder
from haystack.components.retrievers.in_memory import InMemoryBM25Retriever
from haystack.document_stores.in_memory import InMemoryDocumentStore

from enterprise_rag_patterns import __version__
from enterprise_rag_patterns.integrations.haystack import FERPAHaystackFilter, _make_haystack_component

FIXTURE = Path(__file__).with_name("retrieval_cases.json")
PATHS = ("native", "gate", "combined", "bypass")
TEMPLATE = "Question: {{ question }}\n{% for doc in documents %}[[{{ doc.id }}]] {{ doc.content }}\n{% endfor %}"


@component
class RecordingGenerator:
    """Record the complete prompt at the generator boundary; generate no answer."""

    @component.output_types(prompt=str)
    def run(self, prompt: str):
        return {"prompt": prompt}

    @component.output_types(prompt=str)
    async def run_async(self, prompt: str):
        return self.run(prompt)


def load_fixture():
    return json.loads(FIXTURE.read_text())


def documents_for(fixture, corpus_size):
    if corpus_size < len(fixture["documents"]):
        raise ValueError("corpus_size must include the complete boundary fixture")
    documents = [Document(**row) for row in fixture["documents"]]
    documents.extend(
        Document(
            id=f"filler-{i}",
            content="unrelated background material",
            meta={"student_id": "other", "institution_id": "other", "category": "academic_record"},
        )
        for i in range(corpus_size - len(documents))
    )
    return documents


def native_filters(scope):
    """Attribute-based baseline; native null equality also matches absent fields.

    This cannot express this package's public rule (identity keys must be absent)
    using these comparisons alone. The null-public fixture measures that difference.
    """
    return {
        "operator": "OR",
        "conditions": [
            {
                "operator": "AND",
                "conditions": [
                    {"field": "meta.student_id", "operator": "==", "value": scope["student_id"]},
                    {"field": "meta.institution_id", "operator": "==", "value": scope["institution_id"]},
                    {"field": "meta.category", "operator": "in", "value": scope["authorized_categories"]},
                ],
            },
            {
                "operator": "AND",
                "conditions": [
                    {"field": "meta.classification", "operator": "==", "value": "public"},
                    {"field": "meta.student_id", "operator": "==", "value": None},
                    {"field": "meta.institution_id", "operator": "==", "value": None},
                ],
            },
        ],
    }


def pipeline_for(store, scope, path, async_mode=False, top_k=20):
    if path not in PATHS:
        raise ValueError("unknown benchmark path")
    pipeline_class = Pipeline
    if async_mode and not hasattr(Pipeline, "run_async"):
        from haystack import AsyncPipeline

        pipeline_class = AsyncPipeline
    pipeline = pipeline_class()
    pipeline.add_component(
        "retriever",
        InMemoryBM25Retriever(
            store, top_k=top_k, filters=native_filters(scope) if path in ("native", "combined") else None
        ),
    )
    pipeline.add_component("prompt", PromptBuilder(template=TEMPLATE, required_variables=["question", "documents"]))
    pipeline.add_component("generator", RecordingGenerator())
    if path in ("gate", "combined"):
        pipeline.add_component("guard", _make_haystack_component()())
        pipeline.connect("retriever.documents", "guard.documents")
        pipeline.connect("guard.filtered_documents", "prompt.documents")
    else:
        pipeline.connect("retriever.documents", "prompt.documents")
    pipeline.connect("prompt.prompt", "generator.prompt")
    return pipeline


def run_once(pipeline, query, async_mode=False, scope=None):
    data = {"retriever": {"query": query}, "prompt": {"question": query}}
    if "guard" in pipeline.inputs():
        scope = scope or load_fixture()["scope"]
        data["guard"] = {
            "student_id": scope["student_id"],
            "institution_id": scope["institution_id"],
            "permitted_categories": set(scope["authorized_categories"]),
        }
    start = perf_counter()
    if async_mode:
        result = asyncio.run(pipeline.run_async(data, include_outputs_from={"retriever"}))
    else:
        result = pipeline.run(data, include_outputs_from={"retriever"})
    elapsed_ms = (perf_counter() - start) * 1000
    prompt = result["generator"]["prompt"]
    return {
        "prompt": prompt,
        "observed_ids": re.findall(r"\[\[([^\]]+)\]\]", prompt),
        "candidate_ids": [doc.id for doc in result["retriever"]["documents"]],
        "elapsed_ms": elapsed_ms,
    }


def benchmark(corpus_size=20, repeats=3, top_k=20, modes=("sync", "async")):
    if repeats < 1 or top_k < 1:
        raise ValueError("repeats and top_k must be positive")
    if any(mode not in ("sync", "async") for mode in modes):
        raise ValueError("modes must be sync or async")
    fixture = load_fixture()
    store = InMemoryDocumentStore()
    store.write_documents(documents_for(fixture, corpus_size))
    permitted = set(fixture["permitted_ids"])
    forbidden_content = {doc["id"]: doc["content"] for doc in fixture["documents"] if doc["id"] not in permitted}
    rows = []
    for mode in modes:
        for path in PATHS:
            pipeline = pipeline_for(store, fixture["scope"], path, mode == "async", top_k)
            run_once(pipeline, fixture["query"], mode == "async")  # warm up, excluded
            samples = []
            for _ in range(repeats):
                result = run_once(pipeline, fixture["query"], mode == "async")
                observed = set(result["observed_ids"])
                samples.append(
                    {
                        "candidate_count": len(result["candidate_ids"]),
                        "observed_ids": result["observed_ids"],
                        "unauthorized_ids": sorted(observed - permitted),
                        "unauthorized_count": len(observed - permitted),
                        "unauthorized_content_ids": sorted(
                            doc_id for doc_id, content in forbidden_content.items() if content in result["prompt"]
                        ),
                        "authorized_recall": len(observed & permitted) / len(permitted),
                        "elapsed_ms": result["elapsed_ms"],
                    }
                )
            durations = sorted(sample["elapsed_ms"] for sample in samples)
            rows.append(
                {
                    "mode": mode,
                    "path": path,
                    "samples": samples,
                    "latency_ms_p50": statistics.median(durations),
                    "latency_ms_p95": durations[math.ceil(0.95 * len(durations)) - 1],
                }
            )
    negative_control = all(
        all(s["unauthorized_content_ids"] for s in row["samples"]) for row in rows if row["path"] == "bypass"
    )
    protected = all(
        not s["unauthorized_ids"] and not s["unauthorized_content_ids"]
        for row in rows
        if row["path"] in ("gate", "combined")
        for s in row["samples"]
    )
    utility = all(
        sample["authorized_recall"] == 1.0
        for row in rows
        if row["path"] in ("gate", "combined")
        for sample in row["samples"]
    )
    if not rows or not negative_control or not protected:
        raise AssertionError("boundary or bypass negative-control check failed")
    if not utility:
        raise AssertionError(
            "authorized utility check failed: protected paths must retain every permitted fixture document"
        )
    return {
        "schema_version": 1,
        "fixture_sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        "versions": {
            "haystack-ai": version("haystack-ai"),
            "enterprise-rag-patterns": __version__,
            "installed-enterprise-rag-patterns-metadata": version("enterprise-rag-patterns"),
            "python": platform.python_version(),
        },
        "source_sha256": {
            "benchmark": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "haystack_adapter": hashlib.sha256(Path(inspect.getfile(FERPAHaystackFilter)).read_bytes()).hexdigest(),
        },
        "environment": {"platform": platform.platform(), "processor": platform.processor()},
        "corpus_size": corpus_size,
        "top_k": top_k,
        "repeats": repeats,
        "warmup_runs_per_path": 1,
        "timing_scope": "pipeline execution; async includes asyncio.run overhead; excludes store/pipeline construction",
        "negative_control_detected": negative_control,
        "protected_boundary_passed": protected,
        "authorized_utility_passed": utility,
        "limitations": (
            "Enterprise Haystack adapter with explicit category allowlist; other framework routes are not benchmarked. "
            "Async pipeline executes the adapter's synchronous run method. "
            "Synthetic BM25 corpus and recording generator; "
            "no model quality, provider cache, external revocation or production performance claim. "
            "Native null/absent semantics differ from strict public classification."
        ),
        "results": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-size", type=int, default=20)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--top-k", type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.corpus_size, args.repeats, args.top_k), indent=2))


if __name__ == "__main__":
    main()
