from __future__ import annotations

import re
import tomllib
from pathlib import Path

from pry.version import VERSION as CLI_VERSION

REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_version_py(path: Path) -> str:
    text = path.read_text()
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, f"no VERSION assignment found in {path}"
    return match.group(1)


def test_cli_and_plugin_version_files_match():
    """The plugin keeps a standalone copy of version.py (it must import inside
    GDB without the pry package). The two copies must never drift."""
    plugin_version = _read_version_py(
        REPO_ROOT / "plugin" / "pry_agent_bridge" / "version.py"
    )
    assert plugin_version == CLI_VERSION


def test_pyproject_version_matches():
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    assert data["project"]["version"] == CLI_VERSION
