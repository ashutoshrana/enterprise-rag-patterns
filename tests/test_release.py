"""Release tag guard must accept the source version and reject a mismatch."""

import subprocess
import sys
from pathlib import Path


def test_release_tag_guard():
    script = Path(__file__).resolve().parents[1] / "scripts/check_release.py"
    version = subprocess.check_output([sys.executable, str(script)], text=True).strip()
    subprocess.run([sys.executable, str(script), "v" + version], check=True, capture_output=True)
    assert subprocess.run([sys.executable, str(script), "v999.0.0"], capture_output=True).returncode != 0
