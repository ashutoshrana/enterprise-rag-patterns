"""Reject malformed release identities and incomplete or mismatched archives."""

import io
import runpy
import tarfile
import zipfile
from pathlib import Path

import pytest

HELPER = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check_release.py"))
NAME = "enterprise-rag-patterns"
RUNTIME = "enterprise_rag_patterns/__init__.py"
LICENSE = b"fixture license"


def artifacts(dist, *, source_name=NAME, source_version="1.2.3", wheel_name=NAME, wheel_version="1.2.3"):
    with zipfile.ZipFile(dist / "fixture.whl", "w") as archive:
        archive.writestr("fixture.dist-info/METADATA", f"Name: {wheel_name}\nVersion: {wheel_version}\n")
        archive.writestr(RUNTIME, "")
        archive.writestr("fixture.dist-info/licenses/LICENSE", LICENSE)
    with tarfile.open(dist / "fixture.tar.gz", "w:gz") as archive:
        for name, data in {
            "fixture/PKG-INFO": f"Name: {source_name}\nVersion: {source_version}\n".encode(),
            "fixture/LICENSE": LICENSE,
        }.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


def check(dist):
    HELPER["validate_artifacts"](dist, NAME, "1.2.3", RUNTIME)


@pytest.mark.parametrize("version", ["1.2", "1.2.3rc1", "1.2.3.dev1", "v1.2.3", "1.2.3+local"])
def test_unstable_source_version_rejected(version):
    with pytest.raises(ValueError, match="stable"):
        HELPER["validate_version"](version)


def test_valid_artifact_pair(tmp_path):
    artifacts(tmp_path)
    HELPER["validate_version"]("1.2.3", "v1.2.3")
    check(tmp_path)


@pytest.mark.parametrize("missing", ["fixture.whl", "fixture.tar.gz"])
def test_missing_artifact_rejected(tmp_path, missing):
    artifacts(tmp_path)
    (tmp_path / missing).unlink()
    with pytest.raises(ValueError, match="exactly one"):
        check(tmp_path)


def test_extra_artifact_rejected(tmp_path):
    artifacts(tmp_path)
    (tmp_path / "extra.whl").write_bytes(b"extra")
    with pytest.raises(ValueError, match="exactly one"):
        check(tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [("source_name", "wrong"), ("source_version", "9.9.9"), ("wheel_name", "wrong"), ("wheel_version", "9.9.9")],
)
def test_mismatched_artifact_identity_rejected(tmp_path, field, value):
    artifacts(tmp_path, **{field: value})
    with pytest.raises(ValueError, match="name/version"):
        check(tmp_path)
