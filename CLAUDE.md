# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`pry` is an agent-friendly CLI for GDB. It has two parts: a Python CLI (`src/pry/`) and a GDB bridge plugin (`plugin/pry_agent_bridge/`). They communicate over a Unix socket using a JSON request/response protocol.

## Build & Run

```bash
uv tool install -e .          # Install CLI on PATH
pry plugin install            # Symlink bridge into GDB's data dir
pry skill install             # Symlink skills into ~/.claude/skills/ and, when present, ~/.codex/skills/

uv run pry --help             # Run CLI from repo without installing
```

Requires Python >= 3.10, uv, and GDB with Python support.

## Testing

```bash
uv run pytest                              # All tests
uv run pytest tests/test_cli.py            # CLI tests only
uv run pytest tests/test_cli.py::test_foo  # Single test
uv run pytest -v                           # Verbose output
```

Tests mock or avoid live GDB interaction where practical.

## Architecture

### Two-Process Model

CLI -> Unix socket -> Bridge inside GDB

The bridge runs inside a GDB Python session. `pry launch` starts headless GDB with the bridge loaded and registers an instance under `~/.cache/pry/instances/`. CLI commands auto-select the only running instance, or use `--instance <pid>` when multiple GDB sessions are active.

### Key Files

- `src/pry/cli.py` - CLI commands, argument parsing, and output rendering
- `src/pry/transport.py` - Socket communication and bridge instance discovery
- `src/pry/output.py` - Token-aware rendering and artifact spillover
- `src/pry/paths.py` - Shared filesystem locations for cache, plugin, and skills
- `plugin/pry_agent_bridge/bridge.py` - GDB-side request dispatcher and operation handlers
- `plugin/pry_agent_bridge/paths.py` / `version.py` - Plugin-local copies of shared path/version helpers

## Conventions

- Keep CLI-only code free of a GDB import dependency.
- Use `BridgeError` for user-facing command failures.
- Read commands generally default to `--format text`; installation/setup commands can expose JSON with `--format json`.
- Test files mirror source behavior in `tests/test_cli.py`, `tests/test_bridge.py`, `tests/test_transport.py`, and `tests/test_output.py`.
