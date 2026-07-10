---
name: pry
description: Use the local pry CLI for GDB debugging work through the pry bridge. Works with a running GDB session that has the bridge plugin loaded. Prefer this skill for breakpoint management, stepping, backtrace inspection, register/memory reads, disassembly, symbol search, and inline Python execution inside GDB.
---

# pry

Use this skill when the user wants debugging work against a running program and the local `pry` CLI is available. The bridge runs inside a GDB session that has sourced the pry_agent_bridge plugin.

## Setup

### Quick start (recommended)

```bash
pry launch ./binary          # Spawns GDB headlessly with the bridge loaded
pry doctor                   # Verify the bridge is live
```

`pry launch` spawns GDB in the background with stdin kept alive via a self-pipe. It waits for the bridge socket to appear and reports status. Use `pry kill` to tear down the session.

```bash
pry launch ./binary -- -ex "set disassembly-flavor intel"   # Pass extra GDB args
pry launch --timeout 20 ./big_binary                        # Custom wait timeout
pry kill                                                     # Kill the GDB session
```

### Multiple concurrent sessions

Each `pry launch` creates a separate GDB instance with its own socket at `~/.cache/pry/instances/<pid>.sock`. Commands auto-select the instance when only one is running. With multiple instances, use `--instance <pid>`:

```bash
pry launch ./binary_a        # Returns pid=12345
pry launch ./binary_b        # Returns pid=12346
pry --instance 12345 break set main
pry --instance 12346 break set process_input
pry --instance 12345 run
pry --instance 12346 run
pry kill --instance 12345    # Kill specific session
pry kill --all               # Kill every running session
```

### Manual setup

If you need interactive GDB access or a custom setup:

1. **Installed plugin (recommended, persistent):**
   ```bash
   pry plugin install        # symlinks the bridge into GDB's data dir (~/.gdb/pry_agent_bridge)
   # It prints the exact `python ... import pry_agent_bridge` snippet to add to ~/.gdbinit.
   ```

2. **Manual source** — use the path `pry plugin install` printed (its parent of `pry_agent_bridge`, e.g. `~/.gdb`), not a hardcoded one:
   ```bash
   gdb -q ./binary -ex "python import sys; sys.path.insert(0, '$HOME/.gdb'); import pry_agent_bridge"
   ```

For headless/agent contexts without `pry launch`, keep GDB's stdin open:
```bash
sleep 99999 | gdb -q ./binary -ex "python import sys; sys.path.insert(0, '$HOME/.gdb'); import pry_agent_bridge"
```

## Remote Debugging (QEMU / gdbserver)

### Quick start

```bash
pry launch --symbols ./vmlinux --connect localhost:1234
```

This launches GDB, loads the symbol file, and connects to the remote target in one step.

### Step-by-step

```bash
pry launch                          # Launch bare GDB session
pry load ./vmlinux                  # Load symbol file
pry connect localhost:1234          # Connect to QEMU/gdbserver
pry break set commit_creds          # Set kernel breakpoint
pry continue                        # Continue execution
```

> **KASLR kernels:** loading vmlinux at its link-time base (via `--symbols`/`pry load`) leaves symbols at the wrong addresses, so `pry break set <fn>` / `pry print <global>` won't resolve. Connect **without** symbols, read the base, then rebase in one clean step:
> ```bash
> pry launch --connect localhost:1234
> pry gdb kbase                       # -> Found virtual text base address: 0x....
> pry load ./vmlinux --base 0x<kbase> # offsets ALL sections; text + data resolve
> ```
> Do **not** use `kbase -r` for this — it leaves a stale duplicate and skips data symbols (see [reference/pwndbg.md](reference/pwndbg.md)).

### Connection management

```bash
pry connect localhost:1234          # Connect to remote target
pry info target                     # Show target connection info
pry disconnect                      # Disconnect from remote target
```

### Typical QEMU kernel debugging workflow

```bash
# Terminal 1: Start QEMU with GDB stub
qemu-system-x86_64 -kernel bzImage -s -S ...

# Terminal 2: Debug with pry
pry launch --symbols ./vmlinux --connect localhost:1234
pry break set start_kernel
pry continue
pry backtrace
```

The `-s` flag enables the GDB stub on port 1234. The `-S` flag freezes the CPU at startup.

## Workflow

1. Start with bridge health check:

```bash
pry doctor
```

2. Load a binary and start debugging:

```bash
pry load /path/to/binary
pry break set main
pry run
```

3. Pick the right output mode:
- Most commands default to `text` for human-readable output.
- Use `--format json` for structured/programmatic output, `--format ndjson` for streaming.
- Use `--out <path>` to write output to a file.

Outputs above 10,000 `o200k_base` tokens auto-spill to disk. When that happens, **stdout carries the artifact envelope** (a JSON object with `artifact_path`, `bytes`, `tokens`, `sha256`, `summary`) and stderr gets a one-line `warning: ... spilled to <path>` note. Read `artifact_path` from the stdout envelope to retrieve the full data.

4. **Output/exit-code contract** (important for programmatic use): on **success** a command exits **0** and the result goes to **stdout** — in JSON mode a bare value/object (NOT wrapped in `{"ok":true}`). On **failure** the command exits **non-zero** and the error goes to **stderr** (`--format json` makes it `{"ok": false, "error": "..."}`); nothing goes to stdout. So you can gate on `$?`, and a success result never carries an `ok` field.

5. **Parallel calls are safe.** Read-only inspection commands (`backtrace`, `registers`, `locals`, `memory read`, `disasm`, `print`, etc.) take only a read lock and can be batched in parallel freely. Avoid parallelising execution/mutation commands (`run`, `continue`, `step`, `break set`, `memory write`) as they acquire an exclusive lock and will serialise anyway.

## Execution Control

```bash
pry run [args...]            # Run the program (blocks until stop/exit)
pry run --stdin-file /path/to/payload [args...]  # Feed raw stdin from a file (CTF/exploit)
pry continue                 # Continue from current stop
pry step [count]             # Step into (source-level)
pry next [count]             # Step over (source-level)
pry stepi                    # Step into (instruction-level)
pry nexti                    # Step over (instruction-level)
pry finish                   # Run until current function returns (reports return value)
pry until main.c:42          # Run until a specific location
pry jump main.c:42           # Resume execution at a location (GDB jump)
pry interrupt                # Interrupt a running inferior
pry status                   # Check if inferior is running or stopped
pry wait                     # Wait for a background exec to stop
pry threads                  # List threads with selected frame info
pry threads --pc 0x401400    # Filter threads stopped at an exact PC
pry threads --function worker  # Filter by current frame function substring
pry thread select 3          # Make thread 3 the persistently selected one
```

`pry finish` reports the function's return value as `return value: ...` (x86-64 integer/pointer returns; void/float/struct are omitted). Most inspection commands accept `--thread N` to run against a specific thread without persistently switching (the prior selection is restored); use `pry thread select N` to switch persistently.

Execution commands block until the inferior stops or exits. Use `--timeout N` to auto-interrupt after N seconds — the bridge interrupts the inferior and returns stop info with `timeout_interrupt: true`, staying responsive for subsequent commands. Set breakpoints before running to ensure the program stops where you want.

**Stdin for the inferior:** use `pry run --stdin-file PATH` to open `PATH` as the inferior's real stdin (fd 0). Bytes are delivered raw — no PTY, so cooked-mode XON/XOFF cannot eat payload bytes (e.g. `0x11` in addresses). Program args stay separate (`pry run --stdin-file payload.bin arg1 arg2`). Shell-style redirection via `pry gdb 'run < file'` is **not** supported: `pry launch` sets `startup-with-shell off` for byte-precise argv, so `<` and the path become argv tokens. Prefer `--stdin-file`.

`pry status` reports one of: `running`, `stopped`, `exited`, or `not-started`.

### Seeing the program's output

The inferior's **stdout/stderr does not come back in command results** — it (plus GDB's own output) is captured to a per-session log. Use `pry logs` to read it; this is how you confirm what the program printed (e.g. to check a function actually ran):

```bash
pry logs                     # Full captured output for the (auto-selected) session
pry logs -n 20               # Just the last 20 lines
pry logs --instance 12345    # A specific session
```

Execution commands also accept `--output` to print any new session output (inferior stdout/stderr plus GDB messages) produced during the command, so you can act and check output in one step:

```bash
pry continue --output        # Continue, then print new output to stderr
```

Note: libc line-buffers stdout when not a TTY, so output may be withheld until a flush, a newline, or normal exit — a program that crashes mid-line may show nothing. `--output` surfaces whatever has actually been written.

### Background execution

Use `--background` on `run`, `continue`, `finish`, or `until` to return immediately while the inferior keeps running:

```bash
pry continue --background    # Returns immediately with status: running
pry status                   # Check state: running or stopped
pry wait --timeout 60        # Block until stopped (with optional timeout)
pry interrupt                # Manually interrupt if needed
```

`pry interrupt` always works — even during a background exec or when the write lock is held.

### Timeout recovery

```bash
pry continue --timeout 60    # Auto-interrupts after 60s, bridge stays usable
```

When `--timeout` fires, the bridge auto-interrupts the inferior and returns the stop info. No more `pry kill` + relaunch cycles.

Execution commands report the **stop reason** when available:
- `reason: breakpoint #1 hit` — stopped at a breakpoint
- `reason: watchpoint #2 (buf) hit` — watchpoint triggered
- `reason: signal SIGSEGV` — received a signal
- `reason: step` — a step/next/finish/until completed normally

`pry status` and `pry wait` carry the same `reason`, so you can always ask "why is it stopped?" after a background exec or poll.

## Breakpoint Management

```bash
pry break set main                          # Break at function
pry break set main.c:42                     # Break at file:line
pry break set *0x401000                     # Break at address
pry break set *0x1234 --rebase myprog       # PIE: offset from module load base (see PIE/ASLR rebasing)
pry break set main --condition "argc > 1"   # Conditional breakpoint
pry break set main --temporary              # One-shot breakpoint
pry break set main --ignore 5               # Skip the next 5 hits before stopping
pry break set *0x401000 --hardware          # Hardware breakpoint (read-only/remote/kernel memory)
pry break list                              # List all breakpoints (shows thread/ignore/condition; catchpoints show their "what")
pry break delete 1                          # Delete breakpoint #1
pry break enable 1                          # Enable breakpoint #1
pry break disable 1                         # Disable breakpoint #1
pry watch set my_var                        # Write watchpoint
pry watch set my_var --type read            # Read watchpoint
pry watch set my_var --type access          # Read/write watchpoint
pry watch delete 2                          # Delete watchpoint #2
pry watch enable 2                          # Enable watchpoint #2
pry watch disable 2                         # Disable watchpoint #2
pry watch list                              # List all (same as break list)
```

**Multi-location breakpoints:** GDB can resolve one symbolic breakpoint to several sites (common with inlined callees — e.g. `free_msg` may also land inside `load_msg`). `pry break set` / `pry break list` report `location_count` and a full `locations[]` of `{address,file,line,function}` (text lists every site). Do not assume the top-level `address`/`function` is the only hit site; inspect `locations` when `location_count > 1`.

### PIE/ASLR rebasing

For PIE binaries, use `--rebase MODULE` to set breakpoints by static analysis offset — pry resolves the runtime address automatically:

```bash
pry break set *0x1234 --rebase myprogram                      # Offset from module load base
pry break set *0x40656e --rebase myprogram --image-base 0x400000  # Subtract BN's image base
```

The response includes rebasing metadata showing the module base and resolved runtime address.

`--rebase` is the equivalent of pwndbg's `brva`, but works for any loaded module (libc, plugins, kernel modules), not just the main executable. If you specifically want raw `brva`, use `pry gdb "brva 0x1234"`.

Combine `--rebase` with `pry trace` (below) for static-analysis-driven memory tracing — give it ranges relative to a module and pry resolves them at runtime.

Breakpoints and watchpoints share the same number space in GDB. `pry watch delete 2` and `pry break delete 2` are equivalent.

## Memory Tracing

Trace every instruction within a code range that touches a specific memory address:

```bash
pry trace --watch 0x7fffffffd5d4 --range 0x404610-0x405e30
pry trace --watch 0x7fffffffd5d4 --watch-size 4 --range 0x404610-0x405e30 --type access --timeout 60 --max-hits 1000
```

Uses a hardware watchpoint gated by the code range: it's armed while the PC is in `[START, END)` and disarmed outside it, and hits **accumulate across repeated passes** (e.g. every loop iteration) up to `--max-hits`. All automation runs inside GDB at native speed via `Breakpoint.stop()` callbacks — no socket round-trips for intermediate hits.

**Pick `START` so it lies on the execution path** (typically the loop body), or start the trace with the inferior already stopped inside the range. If execution never enters the range during the trace, nothing is recorded and the result reports `armed: false` with an explanatory `note` — that is a "the window never opened" false negative, **not** proof the address was untouched. A plain `0 hits` with `armed: true` does mean no accesses occurred in range.

If `--timeout` fires before `--max-hits`, the bridge auto-interrupts and returns the partial hits collected so far — the bridge stays usable, no relaunch needed.

Options:
- `--watch ADDR` — memory address to watch (required)
- `--watch-size N` — bytes to watch (default: 4)
- `--range START-END` — code range that gates recording (required)
- `--type write|read|access` — watch type (default: access)
- `--max-hits N` — stop after this many hits, accumulated across passes (default: 10000)
- `--timeout N` — max seconds (default: 120)

## Inspection Commands

```bash
pry backtrace                    # Stack backtrace
pry backtrace --full             # Backtrace with local variables
pry backtrace --limit 5          # Limit to 5 frames
pry frame info                   # Current frame info
pry frame select 3               # Select frame #3 (absolute)
pry frame up                     # Move toward callers (up [N])
pry frame down                   # Move toward callees (down [N])
pry locals                       # Local variables
pry args                         # Function arguments
pry locals --thread 3            # Any of these can target a specific thread
pry print argc                   # Evaluate expression
pry print "sizeof(struct foo)"   # Evaluate C expression
pry print argc --fmt x           # Format the value (GDB print/F): x d u o t a c f s z
pry print "/x flags"             # GDB muscle-memory `print /x expr` also works
pry call 'fn(1, "x")'            # Call an inferior function, return its value
pry registers                    # General-purpose registers
pry registers --all              # All registers (including FP/SIMD)
pry registers write rip 0x401234 # Set a register ($pc/$rsp/etc.; leading $ optional)
pry mappings                     # Process memory map (structured vmmap)
pry mappings --contains 0x7ffff7d00000   # Mapping that holds an address
pry mappings --name libc         # Mappings whose objfile matches a substring
```

**Auto-display:** register expressions that are re-evaluated and attached to every stop result (and shown in `pry status` while stopped):

```bash
pry display add "head->id"       # Show this on every stop
pry display add "head->id" --fmt x  # ...formatted (GDB print/F): x d u o t a c f s z
pry display list                 # List displays with current values
pry display remove 1             # Stop showing display #1
```

`pry print "expr"` evaluates C expressions, and when `expr` is a call it runs **inside the inferior** (e.g. `pry print 'malloc(0x100)'` to shape the heap; `pry call` is a dedicated verb for the same thing). A watchpoint stop reports the value change as `old -> new` (rendered in the session's output radix — hex by default under pwndbg, e.g. `0x6 -> 0xa`). After the inferior exits, `pry print` reads the static binary image (not live memory) and flags the result with a `note`. `pry disasm` annotates each instruction with its `symbol+offset`.

## Memory Access

```bash
pry memory read 0x7fffffffe000 64              # Read 64 bytes as hex
pry memory read 0x7fffffffe000 64 --plain      # Print only hex bytes for scripts
pry memory read 0x7fffffffe000 64 --display pretty   # xxd-style hex + ASCII dump
pry memory read 0x7fffffffe000 64 --display string   # Read as string
pry memory read 0x7fffffffe000 64 --display bytes    # Read as base64
pry memory write 0x7fffffffe000 deadbeef       # Write hex bytes
```

**Searching memory:** there's no `pry memory search` — use the pwndbg passthrough: `pry gdb 'search "needle"'` (plain form matches a substring/prefix), `pry gdb "search -x deadbeef"` (hex), `pry gdb "search -p 0xADDR"` (pointer). Note `search -t string "x"` requires the *complete* NUL-terminated string. See [reference/pwndbg.md](reference/pwndbg.md).

## Code and Symbol Inspection

```bash
pry disasm main                  # Disassemble function
pry disasm 0x401000 --count 20  # Disassemble 20 instructions from address
pry disasm --start main --end main+32   # Disassemble an explicit address range
pry disasm main --source         # Interleave source lines (GDB /s)
pry examine '$rsp' --spec 8xw    # GDB-style examine (x/8xw): 8 words in hex
pry examine '$pc' --spec 3i      # Examine as instructions (x/3i)
pry examine &buf --count 16 --fmt x --size b   # Build the spec from parts
pry functions                    # List all functions
pry functions --query main       # Search functions
pry symbols --query errno        # Search global symbols/variables
pry types show "struct sockaddr" # Show type definition
pry info files                   # Loaded files and sections
pry source list main             # Show source code for function
pry source list main.c:42       # Show source around line
```

**Note:** `pry symbols` and `pry functions` search global symbols from all loaded shared libraries (via `info variables` / `info functions`). They do not find local variables — use `pry locals` for that. Results are paginated with `--limit` (default 100) and `--offset`.

**No reverse xref/call-graph:** pry can't list a function's *callers* directly. For static caller discovery, prefer the `bn`/`bn-re` skills (Binary Ninja exposes `caller_static`); within pry you'd disassemble candidate functions and scan their call targets. `pry disasm` resolves call targets to symbol names, so the forward direction (what a function calls) is easy.

## Python Escape Hatch

Execute arbitrary Python inside GDB when the built-in commands are insufficient:

```bash
pry py exec --code "result['value'] = [str(f) for f in gdb.selected_frame().block()]"
pry py exec --script /path/to/script.py
pry py exec --script trace.py --timeout 120   # Timeout for long-running scripts
echo 'print(gdb.selected_frame().name())' | pry py exec --stdin
```

The Python environment has `gdb` in scope. Set `result['value']` to return structured data. Use `--timeout` to prevent long-running scripts from hanging the bridge.

## Raw GDB Command Passthrough

Execute any GDB command directly, including pwndbg commands and custom scripts:

```bash
pry gdb "info proc mappings"     # Any GDB command
pry gdb --format json kbase      # Get raw output as JSON
pry gdb --timeout 60 kdmesg      # Custom timeout for slow commands
```

This is the escape hatch for any GDB/pwndbg command not covered by pry's built-in ops.

## pwndbg Command Reference

pwndbg is loaded alongside the bridge, so **any** pwndbg command runs verbatim through `pry gdb "..."`. The full catalogue (KASLR/`kbase`, glibc heap, SLUB, ROP, GOT/PLT, memory search, context) lives in [reference/pwndbg.md](reference/pwndbg.md) — read it on demand for kernel/heap/exploit work. It is kept out of this always-loaded skill to save context.

```bash
pry gdb "pwndbg"                      # Full list of pwndbg commands (--list-categories for groups)
pry gdb kbase                         # Kernel virtual base (KASLR) — then `pry load vmlinux --base <kbase>`
pry gdb checksec                      # Binary security (NX, PIE, RELRO, canary)
pry gdb vmmap                         # Virtual memory map
```

For KASLR symbol rebasing use `pry load vmlinux --base <kbase>` — see **Remote Debugging → KASLR kernels** above for the recipe and [reference/pwndbg.md](reference/pwndbg.md) for why not `kbase -r`.

Prefer the first-class structured commands where they exist — `pry mappings` (over `vmmap`), `pry registers` / `pry registers write`, `pry disasm` (symbol-annotated), `pry backtrace` — and drop to `pry gdb` for everything else.


## Inferior Management

```bash
pry inferior list                # List inferiors (processes)
pry attach 1234                  # Attach to running process
pry connect localhost:1234       # Connect to remote target (QEMU/gdbserver)
pry disconnect                   # Disconnect from remote target
pry info target                  # Show target connection info
```

## Known Quirks

- **No shell stdin redirect via `pry gdb 'run < file'`**: launch disables `startup-with-shell`, so `<` and the path become argv. Use `pry run --stdin-file PATH` for true file-as-stdin (raw bytes, no PTY).
- **Multiple sessions require `--instance`**: commands auto-select the bridge only when exactly one `pry launch` session is alive. The moment a second one exists, every command needs `pry --instance <pid> ...` or it hard-errors — copying a bare example will fail. Run `pry doctor` to list live PIDs.
- **Socket timeout vs bridge timeout**: without `--timeout`, the CLI socket gives up at 30s while the bridge only auto-interrupts at 120s — so a plain `pry continue` on a program that runs >30s returns a transport error even though the inferior is still running. For long runs pass `--timeout N` (the bridge honors it and auto-interrupts) or use `--background` + `pry wait`.
- **Execution commands block**: `pry run`, `pry continue`, `pry finish` block until the inferior stops. Use `--timeout` for auto-interrupt recovery, or `--background` to return immediately and poll with `pry status`/`pry wait`.
- **Thread safety**: The bridge posts all GDB commands onto GDB's main thread. This means GDB stays responsive, but only one op executes at a time.
- **No undo**: Unlike Binary Ninja's bn tool, GDB mutations (memory writes, register changes) are immediate and not reversible. There is no `--preview` mode.
- **Inferior calls in multithreaded programs**: `pry call` / `pry print '<call>'` run the function inside the inferior, which by default lets *all* threads run. Sibling threads then hit any active breakpoint (or hold a libc lock the call needs), so GDB abandons the call with "stopped in another thread" / "stopped while in a function called from GDB" — and the inferior is left perturbed. For a clean call: disable breakpoints the callee would hit and `pry gdb "set scheduler-locking on"` first (restore `off` after). Even then, calls that touch the heap/locks can deadlock against frozen siblings; pure/self-contained functions are safest.
- **Source availability**: `pry source list` and file/line info in backtraces require debug symbols (`-g` flag when compiling).
- **Long values are previewed in bulk listings**: `pry locals`, `pry args`, and `pry backtrace --full` cap each individual value at ~2KB (a single uninitialized STL container, for instance, can otherwise dump KBs of garbage). A capped value ends with `… <value truncated …>`; run `pry print <name>` for the full value (which token-spills to a file when huge).
- **Symbol search scope**: `pry functions --query` searches functions; `pry symbols --query` searches *data/variable* symbols only (it will **not** find a function — a function name returns an empty result indistinguishable from a true miss, so try `pry functions --query` too). Both cover global/exported symbols; local variables are only visible via `pry locals` within the current frame.
- **Remote targets**: `pry connect` issues `target remote`, which expects the target to be paused. QEMU's `-S` flag or a gdbserver in stopped mode is required for reliable initial connection.
