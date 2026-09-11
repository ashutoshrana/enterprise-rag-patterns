"""Validate source version, release tag, and built wheel metadata; no network."""

import ast
import re
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path

root = Path(__file__).resolve().parents[1]
project_text = (root / "pyproject.toml").read_text()
project = {
    key: ast.literal_eval(match.group(1))
    for key in ("name", "version")
    if (match := re.search(r"^" + key + r"\s*=\s*(\"[^\"]*\")", project_text, re.MULTILINE))
}
runtime = root / "src/enterprise_rag_patterns/__init__.py"
version = next(
    ast.literal_eval(node.value)
    for node in ast.parse(runtime.read_text()).body
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
)
assert project.get("version", version) == version, "Source versions disagree"
if len(sys.argv) > 1:
    assert sys.argv[1] == "v" + version, "Release tag must match source version"
for wheel in (root / "dist").glob("*.whl"):
    with zipfile.ZipFile(wheel) as archive:
        metadata = BytesParser().parsebytes(
            archive.read(next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA")))
        )
        assert metadata["Version"] == version, "Wheel version mismatch"
        assert metadata["Name"].replace("_", "-") == project["name"], "Wheel distribution mismatch"
        assert str(runtime.relative_to(root / "src")) in archive.namelist(), "Runtime module absent"
print(version)
