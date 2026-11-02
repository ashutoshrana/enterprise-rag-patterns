"""Validate stable source/tag identity and the exact wheel/sdist pair; no network."""

import ast
import re
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def validate_version(version: str, tag: str | None = None) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Only stable three-component release versions are allowed")
    if tag is not None and tag != "v" + version:
        raise ValueError("Release tag must match source version")


def validate_artifacts(dist: Path, name: str, version: str, runtime: str) -> None:
    wheels, sources = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1 or len(list(dist.iterdir())) != 2:
        raise ValueError("dist must contain exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        records = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(records) != 1 or runtime not in archive.namelist():
            raise ValueError("Wheel metadata or runtime module absent or ambiguous")
        wheel_meta = BytesParser().parsebytes(archive.read(records[0]))

    with tarfile.open(sources[0]) as archive:
        records = [m for m in archive.getmembers() if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO")]
        if len(records) != 1 or not records[0].isfile():
            raise ValueError("Source package metadata absent or ambiguous")
        stream = archive.extractfile(records[0])
        if stream is None:
            raise ValueError("Source package metadata is not readable")
        source_meta = BytesParser().parsebytes(stream.read())

    for metadata in (wheel_meta, source_meta):
        canonical = re.sub(r"[-_.]+", "-", metadata["Name"] or "").lower()
        if canonical != name or metadata["Version"] != version:
            raise ValueError("Artifact name/version does not match source")


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    project_text = (root / "pyproject.toml").read_text()
    project = {
        key: ast.literal_eval(match.group(1))
        for key in ("name", "version")
        if (match := re.search(r"^" + key + r'\s*=\s*("[^"]*")', project_text, re.MULTILINE))
    }
    runtime = root / "src/enterprise_rag_patterns/__init__.py"
    version = next(
        ast.literal_eval(node.value)
        for node in ast.parse(runtime.read_text()).body
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets)
    )
    if project.get("version", version) != version:
        raise ValueError("Source versions disagree")
    validate_version(version, sys.argv[1] if len(sys.argv) > 1 else None)

    if (root / "dist").exists():
        validate_artifacts(root / "dist", project["name"], version, str(runtime.relative_to(root / "src")))
    print(version)


if __name__ == "__main__":
    main()
