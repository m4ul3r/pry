# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

`pry` is an agent-friendly CLI for GDB. It has two parts: a Python CLI (`src/pry/`) and a GDB bridge plugin (`plugin/pry_agent_bridge/`). They communicate over newline-delimited JSON (`{"id", "op", "params"}` / `{"ok", "result", "error"}`) on a Unix socket.

## Build & Run

```bash
uv tool install -e .          # Install CLI on PATH
pry plugin install            # Symlink bridge into GDB's data dir (~/.gdb/ or $GDB_DATA_DIR)
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

No live GDB needed: `tests/test_bridge.py` injects a fake `gdb` module into `sys.modules` before importing the plugin, and other tests mock the transport layer. `tmp/` holds scratch C programs and binaries for manual end-to-end testing; it is not used by pytest.

## Architecture

### Two-Process Model

CLI -> Unix socket -> Bridge inside GDB

`pry launch` spawns headless GDB with the bridge loaded. Each bridge registers itself under `~/.cache/pry/instances/` (override with `PRY_CACHE_DIR`) as `<gdb-pid>.json` (registry metadata), `<pid>.sock`, and `<pid>.log`. `transport.list_instances()` discovers instances by probing the socket, purging stale registrations and orphaned files as it goes. Commands auto-select the only running instance; with multiple, `--instance <pid>` is required.

The CLI is stateless: every command opens a fresh socket connection, sends one request, and reads to EOF.

### Bridge Concurrency (plugin/pry_agent_bridge/bridge.py)

The bridge runs a threaded socket server inside GDB, but the GDB Python API is only safe on GDB's main thread, so handlers funnel work through `_run_on_gdb_thread()` (`gdb.post_event` + wait). Ops are classified for locking in `GdbBridge.dispatch()`:

- **Lock-free ops** (`interrupt`, `status`, `wait`): must work while the inferior is running, e.g. during background execution.
- **EXEC_OPS** (`run`, `continue`, `step`, ...): take the write lock; they block until the inferior stops (via `gdb.events.stop`) or return immediately with `--background`. `--timeout` auto-interrupts and returns stop info with `timeout_interrupt: true`.
- **READ_LOCKED_OPS** (`backtrace`, `locals`, ...): take the read lock, so inspection commands can run concurrently with each other but not during a mutation.

### Output Spilling (src/pry/output.py)

`write_output_result()` counts tokens (`o200k_base` via tiktoken); output over 10k tokens is spilled to `<cache_home>/spills/<date>/` (via `spill_root()`) and replaced by a JSON artifact envelope (path, bytes, tokens, sha256, summary). `--out <path>` always writes to a file. This is deliberate context-window protection for agents — don't bypass it when adding commands.

### Key Files

- `src/pry/cli.py` - CLI commands, argument parsing, and per-command `_render_*_text()` output rendering
- `src/pry/transport.py` - Socket communication, instance discovery, stale-instance reaping
- `src/pry/output.py` - Token-aware rendering and artifact spillover
- `src/pry/paths.py` - Shared filesystem locations for cache, plugin, and skills
- `plugin/pry_agent_bridge/bridge.py` - GDB-side request dispatcher and operation handlers
- `plugin/pry_agent_bridge/paths.py` / `version.py` - Duplicates of `src/pry/paths.py` / `version.py`; the plugin must be importable inside GDB without the `pry` package, so keep both copies in sync when editing either
- `skills/pry/SKILL.md` - Bundled agent skill documenting the CLI; update it when adding or changing commands

## Conventions

- Keep CLI-only code free of a GDB import dependency; `import gdb` only exists inside `plugin/`.
- Use `BridgeError` for user-facing command failures.
- Read commands generally default to `--format text`; installation/setup commands can expose JSON with `--format json`.
- Adding a bridge op means: handler + dispatch entry + lock classification in `bridge.py`, a CLI subcommand and text renderer in `cli.py`, and usually a `skills/pry/SKILL.md` update.
- Test files mirror source behavior in `tests/test_cli.py`, `tests/test_bridge.py`, `tests/test_transport.py`, and `tests/test_output.py`.
