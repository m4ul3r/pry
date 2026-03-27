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
```

### Manual setup

If you need interactive GDB access or a custom setup:

1. **Manual source:**
   ```bash
   gdb -q ./binary -ex "python import sys; sys.path.insert(0, '/opt/pry/plugin'); import pry_agent_bridge"
   ```

2. **Installed plugin (persistent):**
   ```bash
   pry plugin install
   # Then add the printed snippet to ~/.gdbinit
   ```

For headless/agent contexts without `pry launch`, keep GDB's stdin open:
```bash
sleep 99999 | gdb -q ./binary -ex "python import sys; sys.path.insert(0, '/opt/pry/plugin'); import pry_agent_bridge"
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

Outputs above 10,000 `o200k_base` tokens auto-spill to disk. When that happens, stdout is empty and stderr carries the spill metadata.

## Execution Control

```bash
pry run [args...]            # Run the program (blocks until stop/exit)
pry continue                 # Continue from current stop
pry step [count]             # Step into (source-level)
pry next [count]             # Step over (source-level)
pry stepi                    # Step into (instruction-level)
pry nexti                    # Step over (instruction-level)
pry finish                   # Run until current function returns
pry until main.c:42          # Run until a specific location
pry interrupt                # Interrupt a running inferior
```

Execution commands block until the inferior stops or exits. Use `--timeout` to override the default 30s transport timeout for long-running programs. Set breakpoints before running to ensure the program stops where you want.

Execution commands report the **stop reason** when available:
- `reason: breakpoint #1 hit` — stopped at a breakpoint
- `reason: watchpoint #2 (buf) hit` — watchpoint triggered
- `reason: signal SIGSEGV` — received a signal

## Breakpoint Management

```bash
pry break set main                          # Break at function
pry break set main.c:42                     # Break at file:line
pry break set *0x401000                     # Break at address
pry break set main --condition "argc > 1"   # Conditional breakpoint
pry break set main --temporary              # One-shot breakpoint
pry break list                              # List all breakpoints
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

Breakpoints and watchpoints share the same number space in GDB. `pry watch delete 2` and `pry break delete 2` are equivalent.

## Inspection Commands

```bash
pry backtrace                    # Stack backtrace
pry backtrace --full             # Backtrace with local variables
pry backtrace --limit 5          # Limit to 5 frames
pry frame info                   # Current frame info
pry frame select 3               # Select frame #3
pry locals                       # Local variables
pry args                         # Function arguments
pry print argc                   # Evaluate expression
pry print "sizeof(struct foo)"   # Evaluate C expression
pry registers                    # General-purpose registers
pry registers --all              # All registers (including FP/SIMD)
```

## Memory Access

```bash
pry memory read 0x7fffffffe000 64              # Read 64 bytes as hex
pry memory read 0x7fffffffe000 64 --display string   # Read as string
pry memory read 0x7fffffffe000 64 --display bytes    # Read as base64
pry memory write 0x7fffffffe000 deadbeef       # Write hex bytes
```

## Code and Symbol Inspection

```bash
pry disasm main                  # Disassemble function
pry disasm 0x401000 --count 20  # Disassemble 20 instructions from address
pry functions                    # List all functions
pry functions --query main       # Search functions
pry symbols --query errno        # Search global symbols/variables
pry types show "struct sockaddr" # Show type definition
pry info files                   # Loaded files and sections
pry source list main             # Show source code for function
pry source list main.c:42       # Show source around line
```

**Note:** `pry symbols` and `pry functions` search global symbols from all loaded shared libraries (via `info variables` / `info functions`). They do not find local variables — use `pry locals` for that. Results are paginated with `--limit` (default 100) and `--offset`.

## Python Escape Hatch

Execute arbitrary Python inside GDB when the built-in commands are insufficient:

```bash
pry py exec --code "result['value'] = [str(f) for f in gdb.selected_frame().block()]"
pry py exec --script /path/to/script.py
echo 'print(gdb.selected_frame().name())' | pry py exec --stdin
```

The Python environment has `gdb` in scope. Set `result['value']` to return structured data.

## Raw GDB Command Passthrough

Execute any GDB command directly, including pwndbg commands and custom scripts:

```bash
pry gdb "info proc mappings"     # Any GDB command
pry gdb --format json kbase      # Get raw output as JSON
pry gdb --timeout 60 kdmesg      # Custom timeout for slow commands
```

This is the escape hatch for any GDB/pwndbg command not covered by pry's built-in ops.

## pwndbg Command Reference

pwndbg is a GDB plugin loaded alongside the pry bridge. All pwndbg commands are available via `pry gdb`. This reference covers the most useful ones — run `pry gdb "pwndbg --all"` for the full list.

### KASLR / Kernel Symbols

When connected to a QEMU kernel with KASLR enabled, symbols loaded from vmlinux will be at the wrong addresses. Use `kbase -r` to fix this:

```bash
# Detect kernel base and reload symbols at the correct KASLR'd offset (one command)
pry gdb "kbase -r"

# Or inspect first, then rebase manually:
pry gdb kbase                         # Print kernel virtual base address
pry gdb "add-symbol-file vmlinux 0xffffffff81e00000"  # Manual rebase
```

**How `kbase` works:** On x86-64 it reads the IDT via the IDTR register (available from the GDB stub without symbols), parses IDT entry 0 to get a `.text` address, then walks page tables to find the containing mapping's base. On AArch64 it reads VBAR_EL1. No symbols or /proc access needed.

**Typical KASLR workflow:**
```bash
pry launch --symbols ./vmlinux --connect localhost:1234
pry gdb "kbase -r"                    # Rebase symbols to actual KASLR'd base
pry break set commit_creds            # Now symbol breakpoints work correctly
pry continue
```

### Kernel Inspection

```bash
pry gdb kbase                         # Kernel virtual base address
pry gdb "kbase -r"                    # Detect kbase and reload symbols at correct offset
pry gdb "klookup commit_creds"        # Symbol lookup via in-memory kallsyms (no debug syms needed)
pry gdb "klookup 0xffffffff81234567"  # Reverse lookup: address → symbol name
pry gdb kcmdline                      # /proc/cmdline from kernel memory
pry gdb kchecksec                     # Kernel hardening config (KASLR, SMEP, SMAP, etc.)
pry gdb kversion                      # Kernel version banner (no debug syms needed)
pry gdb kconfig                       # Embedded kernel config (IKCONFIG)
pry gdb kdmesg                        # Kernel ring buffer (dmesg)
pry gdb ktask                         # Kernel task list (processes)
pry gdb kmod                          # Loaded kernel modules
```

**Note:** `klookup` parses the in-memory kallsyms table by pattern-matching on kernel memory. It works without debug symbols and reflects the actual KASLR'd addresses. Use it to find function addresses when you don't have vmlinux.

### Heap (glibc ptmalloc)

```bash
pry gdb heap                          # Summary of all arenas
pry gdb "heap -v"                     # Verbose: all chunks in all arenas
pry gdb bins                          # All bin chains (tcache, fast, small, large, unsorted)
pry gdb tcache                        # Tcache bins only
pry gdb tcachebins                    # Alias for tcache
pry gdb fastbins                      # Fastbin chains
pry gdb smallbins                     # Smallbin chains
pry gdb largebins                     # Largebin chains
pry gdb unsortedbin                   # Unsorted bin chain
pry gdb "find_fake_fast &__malloc_hook"  # Find fake fastbin-sized chunks near an address
pry gdb mp                            # malloc_par struct
pry gdb "top_chunk"                   # Top chunk info
pry gdb "malloc_chunk 0x555555757260" # Parse a specific malloc chunk
pry gdb arena                         # Current arena info
```

### SLUB / Kernel Heap

```bash
pry gdb "slab list"                   # List all SLUB caches
pry gdb "slab info kmalloc-64"        # Info for a specific slab cache
pry gdb "slab -v"                     # Verbose SLUB allocator info
```

### Memory and Mappings

```bash
pry gdb vmmap                         # Virtual memory map (all mappings with permissions)
pry gdb "vmmap libc"                  # Filter mappings by name
pry gdb "vmmap 0x7ffff7d00000"        # Show mapping containing address
pry gdb "search -s flag{"             # Search memory for string
pry gdb "search -x deadbeef"         # Search memory for hex bytes
pry gdb "search -p 0x7ffff7d00000"   # Search memory for pointer value
pry gdb "hexdump 0x7ffff7d00000 64"  # Hex dump
pry gdb "xinfo 0x7ffff7d00000"       # Detailed info about an address (mapping, symbol, offset)
```

### Binary Security

```bash
pry gdb checksec                      # Binary security checks (NX, PIE, RELRO, canary, etc.)
pry gdb got                           # GOT table entries
pry gdb plt                           # PLT entries
pry gdb "got puts"                    # Specific GOT entry
```

### Context and Display

```bash
pry gdb context                       # Full pwndbg context (regs, disasm, stack, backtrace)
pry gdb "context regs"                # Just the register context
pry gdb "context disasm"              # Just the disassembly context
pry gdb "context stack"               # Just the stack context
pry gdb "set context-sections regs disasm code stack backtrace"  # Customize context layout
```

### Disassembly and Code

```bash
pry gdb "nearpc 20"                   # Disassemble 20 instructions around PC
pry gdb "emulate 10"                  # Emulate next 10 instructions (via unicorn)
pry gdb "pdisass main"                # pwndbg-enhanced disassembly of function
```

### ROP / Exploit Development

```bash
pry gdb "rop --grep 'pop rdi'"        # Search for ROP gadgets matching pattern
pry gdb "rop --grep 'ret'"            # Find ret gadgets
pry gdb "ropper -- --search 'pop rdi; ret'"  # Ropper integration if available
pry gdb "cyclic 200"                  # Generate cyclic pattern
pry gdb "cyclic -l 0x61616168"        # Find offset in cyclic pattern
pry gdb "dereference $rsp 20"         # Dereference chain from stack pointer
pry gdb "telescope $rsp 20"           # Alias for dereference
```

### Process and Threads

```bash
pry gdb procinfo                      # Process info (pid, uid, groups, etc.)
pry gdb "info threads"                # List all threads
pry gdb "thread apply all bt"         # Backtrace all threads
pry gdb canary                        # Leak the stack canary value
pry gdb "tls"                         # Thread-local storage info
```

## Inferior Management

```bash
pry inferior list                # List inferiors (processes)
pry attach 1234                  # Attach to running process
pry connect localhost:1234       # Connect to remote target (QEMU/gdbserver)
pry disconnect                   # Disconnect from remote target
pry info target                  # Show target connection info
```

## Known Quirks

- **Execution commands block**: `pry run`, `pry continue`, `pry finish` block until the inferior stops. Always set breakpoints before running, or use `--timeout` for long-running programs.
- **Thread safety**: The bridge posts all GDB commands onto GDB's main thread. This means GDB stays responsive, but only one op executes at a time.
- **No undo**: Unlike Binary Ninja's bn tool, GDB mutations (memory writes, register changes) are immediate and not reversible. There is no `--preview` mode.
- **Source availability**: `pry source list` and file/line info in backtraces require debug symbols (`-g` flag when compiling).
- **Symbol search scope**: `pry symbols` and `pry functions` search global/exported symbols. Local variables are only visible via `pry locals` within the current frame.
- **Remote targets**: `pry connect` issues `target remote`, which expects the target to be paused. QEMU's `-S` flag or a gdbserver in stopped mode is required for reliable initial connection.
