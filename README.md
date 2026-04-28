# pry

Agent-friendly GDB CLI with an in-process bridge.

pry runs a Python socket server inside GDB and exposes every debugging capability as a clean JSON-over-Unix-socket RPC call. Agents drive GDB by invoking `pry <command>` shell commands — no GDB/MI parsing, no expect scripts, no fragile screen scraping.

## Architecture

```
Agent (Claude Code, OpenAI, etc.)
  │  shell exec
  ▼
pry CLI
  │  JSON over Unix socket
  ▼
GDB bridge plugin (runs inside GDB)
  │  gdb Python API
  ▼
GDB
```

The bridge runs in-process using `gdb.post_event()` for thread-safe access to the full GDB Python API — frames, breakpoints, inferiors, memory, registers, and more. A reader-writer lock allows concurrent inspection commands while serializing mutations.

## Install

Requires Python >= 3.10, [uv](https://docs.astral.sh/uv/), and GDB with Python support.

```bash
uv tool install -e .
```

Then install the GDB plugin:

```bash
pry plugin install
```

This symlinks the bridge into `~/.gdb/pry_agent_bridge/` and prints a `source` line to add to your `~/.gdbinit`.

Install the bundled Claude Code/Codex skills:

```bash
pry skill install
```

That symlinks the bundled skills into `~/.claude/skills/` by default. If `~/.codex/` exists, it also installs them into `~/.codex/skills/`. Use `--mode copy` if you want standalone copies instead. Restart your agent to pick up a new or renamed skill.

## Quick start

Launch a headless GDB session and start debugging:

```bash
# Start GDB with your binary (headless, bridge auto-starts)
pry launch ./mybinary

# Set a breakpoint and run
pry break set main
pry run

# Inspect state
pry backtrace
pry locals
pry registers
pry print "some_variable"
pry disasm

# Step through code
pry next
pry step
pry continue

# Done
pry kill
```

## Commands

Every command accepts `--format [text|json|ndjson]`, `--out <path>`, and `--instance <pid>`.

### Lifecycle

| Command | Description |
|---------|-------------|
| `pry launch [binary] [-- gdb-args...]` | Spawn headless GDB with bridge |
| `pry kill` | Terminate GDB session |
| `pry doctor` | Bridge health check and version info |
| `pry plugin install` | Install GDB bridge plugin |
| `pry skill install` | Install bundled agent skills |

### Execution control

All execution commands block until the inferior stops or exits, returning structured stop info (reason, frame, thread). Use `--timeout N` to auto-interrupt after N seconds. Use `--background` to return immediately while the inferior keeps running.

| Command | Description |
|---------|-------------|
| `pry run [args...]` | Start program (`--timeout`, `--background`) |
| `pry continue` | Continue from stop (`--timeout`, `--background`) |
| `pry step [count]` | Source-level step into |
| `pry next [count]` | Source-level step over |
| `pry stepi` | Instruction-level step into |
| `pry nexti` | Instruction-level step over |
| `pry finish` | Run until function returns (`--timeout`, `--background`) |
| `pry until <location>` | Run until location (`--timeout`, `--background`) |
| `pry interrupt` | Interrupt running inferior (always works, even during background exec) |
| `pry status` | Show inferior execution state (running/stopped) |
| `pry wait` | Wait for running inferior to stop (`--timeout`) |
| `pry threads` | List threads with selected frame info (`--pc`, `--function`) |

When `--timeout` fires, the bridge auto-interrupts the inferior and returns the stop info with `timeout_interrupt: true`. The bridge remains responsive for subsequent commands.

### Breakpoints & watchpoints

| Command | Description |
|---------|-------------|
| `pry break set <loc>` | Set breakpoint (`--condition`, `--temporary`, `--hardware`, `--rebase`, `--image-base`) |
| `pry break list` | List all breakpoints |
| `pry break delete <num>` | Delete breakpoint |
| `pry break enable/disable <num>` | Toggle breakpoint |
| `pry watch set <expr>` | Set watchpoint (`--type write\|read\|access`) |
| `pry watch list/delete/enable/disable` | Manage watchpoints |

#### PIE/ASLR rebasing

For PIE binaries, use `--rebase MODULE` to set breakpoints by static offset:

```bash
# Binary Ninja says function is at 0x1234 — pry resolves the runtime address automatically
pry break set *0x1234 --rebase myprogram

# If your tool uses a non-zero image base (e.g., Binary Ninja's default 0x400000)
pry break set *0x40656e --rebase myprogram --image-base 0x400000
```

### Memory tracing

| Command | Description |
|---------|-------------|
| `pry trace` | Trace memory accesses within a code range |

```bash
pry trace --watch 0x7fffffffd5d4 --range 0x404610-0x405e30
pry trace --watch 0x7fffffffd5d4 --watch-size 4 --range 0x404610-0x405e30 --type access --timeout 60
```

Uses hardware watchpoints gated by range boundary breakpoints for native-speed tracing. Reports every instruction within the range that touches the watched memory.

### Inspection

| Command | Description |
|---------|-------------|
| `pry backtrace` | Stack backtrace (`--full`, `--limit N`) |
| `pry frame info` | Current frame info |
| `pry frame select <level>` | Select stack frame |
| `pry locals` | Local variables |
| `pry args` | Function arguments |
| `pry print <expr>` | Evaluate expression |
| `pry registers` | CPU registers (`--all`) |
| `pry memory read <addr> <len>` | Read memory (`--display hex\|string\|bytes\|pretty`, `--plain`) |
| `pry memory write <addr> <hex>` | Write memory |

### Code & symbols

| Command | Description |
|---------|-------------|
| `pry disasm [location]` | Disassemble (`--count N`) |
| `pry functions` | List functions (`--query`, `--limit`, `--offset`) |
| `pry symbols` | List symbols (`--query`, `--limit`, `--offset`) |
| `pry types show <name>` | Type info (size, fields, declaration) |
| `pry source list [location]` | Source listing (`--count N`) |
| `pry info files` | ELF section info |

### Session

| Command | Description |
|---------|-------------|
| `pry load <path>` | Load binary |
| `pry attach <pid>` | Attach to process |
| `pry inferior list` | List inferiors |
| `pry threads` | List threads with frame PCs/functions |

### Escape hatch

```bash
pry py exec --code 'result["value"] = gdb.parse_and_eval("argc").string()'
pry py exec --script trace.py --timeout 120
```

Runs arbitrary Python inside GDB with the `gdb` module and a `result` dict in scope. Use `--timeout` to prevent long-running scripts from hanging the bridge.

## Multiple sessions

pry supports multiple concurrent GDB sessions. Each registers at `~/.cache/pry/instances/<pid>.sock`. With one session, commands auto-connect. With multiple, use `--instance <pid>`:

```bash
pry launch ./server
pry launch ./client
pry --instance 12345 break set handle_request
```

## Output spilling

When output exceeds 10,000 tokens (measured with the `o200k_base` tokenizer), pry automatically spills to `/tmp/pry-spills/` and prints an artifact envelope to stderr with the path, byte count, token count, and SHA-256. This prevents blowing agent context windows. Use `--out <path>` to always write to a file.

## Wire protocol

Newline-delimited JSON over a Unix stream socket.

**Request:**
```json
{"id": "uuid", "op": "backtrace", "params": {"full": true}}
```

**Response:**
```json
{"ok": true, "result": [...], "error": null}
```

## Development

```bash
# Install in editable mode
uv tool install -e .

# Build test fixtures
make -C tests/fixtures

# Run tests
pytest
```

## License

MIT
