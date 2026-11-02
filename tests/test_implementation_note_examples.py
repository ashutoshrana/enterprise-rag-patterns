"""Keep the published implementation-note Python examples executable."""

import re
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "document",
    [
        "implementation-note-01.md",
        "implementation-note-02.md",
        "implementation-note-03.md",
        "agentic-security-trends-2026.md",
    ],
)
def test_document_python_examples(document):
    path = Path(__file__).resolve().parents[1] / "docs" / document
    blocks = re.findall(r"^```python\n(.*?)^```", path.read_text(), re.MULTILINE | re.DOTALL)
    assert blocks, f"No executable example in {document}"
    namespace = {"__name__": "__documentation_example__"}
    for block in blocks:
        exec(compile(block, str(path), "exec"), namespace)
