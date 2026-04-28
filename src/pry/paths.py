from __future__ import annotations

import os
import platform
import tempfile
from pathlib import Path


PLUGIN_NAME = "pry_agent_bridge"
SKILL_NAME = "pry"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def claude_home() -> Path:
    env = os.environ.get("CLAUDE_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".claude"


def codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".codex"


def cache_home() -> Path:
    env = os.environ.get("PRY_CACHE_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Caches" / "pry"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "pry"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "pry"
    return home / ".cache" / "pry"


def instances_dir() -> Path:
    return cache_home() / "instances"


def bridge_registry_path(pid: int | None = None) -> Path:
    if pid is not None:
        return instances_dir() / f"{pid}.json"
    return cache_home() / f"{PLUGIN_NAME}.json"


def bridge_socket_path(pid: int | None = None) -> Path:
    if pid is not None:
        return instances_dir() / f"{pid}.sock"
    return cache_home() / f"{PLUGIN_NAME}.sock"


def gdb_log_path(pid: int | None = None) -> Path:
    if pid is not None:
        return instances_dir() / f"{pid}.log"
    return cache_home() / "gdb.log"


def gdb_pid_path() -> Path:
    return cache_home() / "gdb.pid"


def spill_root() -> Path:
    root = Path(tempfile.gettempdir()) / "pry-spills"
    root.mkdir(parents=True, exist_ok=True)
    return root


def plugin_source_dir() -> Path:
    return repo_root() / "plugin" / PLUGIN_NAME


def gdb_data_dir() -> Path:
    env = os.environ.get("GDB_DATA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".gdb"


def plugin_install_dir() -> Path:
    return gdb_data_dir() / PLUGIN_NAME


def claude_skills_dir() -> Path:
    return claude_home() / "skills"


def codex_skills_dir() -> Path:
    return codex_home() / "skills"


def skill_source_dir() -> Path:
    return repo_root() / "skills" / SKILL_NAME


def skill_install_dir() -> Path:
    return claude_skills_dir() / SKILL_NAME
