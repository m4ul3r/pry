---
name: pry
description: Use the local pry CLI for GDB debugging work through the pry bridge. Works with a running GDB session that has the bridge plugin loaded. Prefer this skill for breakpoint management, stepping, backtrace inspection, register/memory reads, disassembly, symbol search, and inline Python execution inside GDB.
---

# pry

Use this skill when the user wants debugging work against a running program and the local `pry` CLI is available. The bridge runs inside a GDB session that has sourced the pry_agent_bridge plugin.

## Setup

`pry skill install` symlinks this skill into `~/.claude/skills/` and `~/.agents/skills/`, plus `~/.codex/skills/` when `~/.codex/` exists. Use `--dest <path>` to override these destinations or `--mode copy` for standalone copies.

### Quick start (recommended)

```bash
pry launch ./binary          # Spawns GDB headlessly with the bridge loaded
pry doctor                   # Verify the bridge is live
```

`pry launch` spawns GDB in the background with stdin kept alive via a self-pipe. It waits for the bridge socket to appear and reports status. Use `pry kill` to tear down the session.

`pry kill` signals GDB, which detaches from (or kills) its target on the way out. GDB takes its breakpoints out of an all-stop remote target (QEMU gdbstub, gdbserver) only at a stop, so when that target is running, `pry kill` first has the bridge stop it (`note: the remote target was running: pry stopped it first …`, JSON `stopped_target: true`; `stopped_targets` with `--all`); a QEMU guest then resumes when GDB detaches, with none of GDB's `int3`s left in RAM. If the bridge does not answer within 5 s, GDB is killed anyway and a `warning:` (JSON `warning`/`warnings`) says the breakpoints may remain in target memory: a QEMU guest then halts at the first one it reaches, until a debugger connects again (QEMU drops them for a new client).

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
   # Add its generated Python snippet verbatim to ~/.gdbinit.
   ```

2. **Manual source** — save the generated snippet to a GDB command file and load it:
   ```bash
   gdb -q ./binary -x /path/to/bridge.gdb
   ```
   The snippet loads the installed package directly, including custom destinations with arbitrary basenames, spaces, or quotes.

For headless/agent contexts without `pry launch`, keep GDB's stdin open:
```bash
sleep 99999 | gdb -q ./binary -x /path/to/bridge.gdb
```

## Remote Debugging (QEMU / gdbserver)

### Quick start

```bash
pry launch --symbols ./vmlinux --connect localhost:1234
```

This launches GDB, loads the symbol file, and connects to the remote target in one step.

**Server binding:** some `gdbserver` builds ignore the HOST in `127.0.0.1:PORT` and listen on all interfaces. Verify the actual listener with `ss -ltnp`; do not treat the supplied HOST as an access restriction. Use a stdio transport, a verified loopback-only adapter, or an isolated network when exposing a debugger is not intended.

### Step-by-step

```bash
pry launch                          # Launch bare GDB session
pry load ./vmlinux                  # Load symbol file
pry connect localhost:1234          # Connect to QEMU/gdbserver
pry break set commit_creds          # Set kernel breakpoint
pry continue                        # Continue execution
```

> **KASLR kernels:** a vmlinux loaded at its link-time base (via `--symbols`/`pry load`) leaves symbols at the wrong addresses, so `pry break set <fn>` / `pry print <global>` won't resolve. `pry kbase` finds the runtime `_text` and rebases the loaded vmlinux to it:
> ```bash
> pry launch --symbols ./vmlinux --connect localhost:1234   # or `pry load ./vmlinux` after connecting
> pry kbase                     # validates the base against ./vmlinux, then rebases it (symbols: rebased ...)
> ```
> **What `pry kbase` guarantees:** exit 0 only with a **validated** base: the guest's bytes at `linux_banner`'s link address plus the slide equal the symbol file's. Candidates, most specific first: the IDT[0] (x86-64) or VBAR (arm64) handler mapped back through the symbol table (exact on any layout), pwndbg's page-table walk, the handler rounded down to 2 MiB (only an upper bound: on x86-64 5.11–6.6 the handler is 14–24 MiB above `_text`). With no kernel symbol file, or a vmlinux that is not the running kernel's, it exits 1 with `could not determine the kernel base` and lists the unvalidated hints; it never prints an unchecked number as the base. Without `--symbols` it validates against the loaded symbol file that is a kernel image (it has `linux_banner` and `_text`), whatever was loaded after it: module symbols added with `pry load mod.ko --base` do not get in the way. `--symbols PATH` validates against a file that is not loaded and prints the `pry load PATH --base ...` that applies it. Like `load`, it stops a running remote target and resumes it afterwards. JSON: `base`, `slide`, `method` (`idt`/`vbar`/`pwndbg`), `derivation` (`symbol`/`page-tables`/`rounded`), `validated{symbols, symbol, address, text}`, `apply{path, applied, previous_slide, reason, command, load}`.
>
> Base from elsewhere (`qmu kbase`, kallsyms `_text`)? `pry load ./vmlinux --base 0x<kbase>` offsets every image section by one slide, so text and data resolve. Zero-based per-CPU sections (`.data..percpu` on x86-64 6.x: `current_task`, …) hold per-CPU offsets that KASLR does not move, so they stay at their link address (`unslid_sections`): read one as `*(unsigned long *)($gs_base + (unsigned long)&current_task)` while stopped in the kernel. A later plain `pry load ./vmlinux` replaces the slid copy: one table again, at link-time addresses. Rebasing (with `load --base`, `kbase` or `resync --base`) a vmlinux GDB holds as its main symbol file (`pry launch --symbols`, a plain `pry load`) keeps every other file added with `--base`/`--slide`, such as module symbols, loaded at its address; one pry cannot put back (added by a raw `add-symbol-file`, a shared library) is listed in the JSON `dropped` (`apply.load.dropped` for `kbase`, `symbols.dropped` for `resync`).
>
> Prefer `pry kbase` over `pry gdb kbase` (raw pwndbg, which fails under `kernel.yama.ptrace_scope=1` when pry's GDB is not QEMU's parent). Do **not** use `kbase -r` for rebasing — it leaves a stale duplicate and skips data symbols (see [reference/pwndbg.md](reference/pwndbg.md)).

> **Kernel source + lx scripts:** DWARF often has relative paths (`kernel/sys.c`) or absolute Docker kbuild paths (`/src/...`), so `pry source list` fails until GDB knows where the tree is. Linux also ships `scripts/gdb/vmlinux-gdb.py` (`lx-ps`, `$lx_current()`, …) that is **not** auto-loaded from a cached vmlinux alone:
> ```bash
> # KBASE: `pry kbase`'s `base`, or `qmu kbase`
> pry load $VMLINUX --base $KBASE --src /path/to/linux-src --gdb-scripts
> # --src         → `directory DIR` + `set substitute-path /src DIR`
> # --gdb-scripts → auto-find DIR/scripts/gdb/vmlinux-gdb.py (or sibling of vmlinux)
> #                 then add-auto-load-safe-path + source it
> # Or pass an explicit script: --gdb-scripts /path/to/vmlinux-gdb.py
> pry source list __x64_sys_newuname
> pry gdb 'p $lx_current()->pid'
> ```

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

### Re-syncing after a snapshot load or reset (`pry resync`)

A QEMU gdbstub never tells GDB that the machine changed under it. After `qmu snapshot load` (loadvm), a `system_reset`, or a guest reboot, GDB keeps the old stop reason and believes its breakpoints are still in memory. `pry resync` re-establishes the truth:

```bash
pry resync                              # after a snapshot load or a nokaslr reset
pry resync --base 0x<kbase>             # KASLR re-slid (reset/reboot): reload the kernel's symbols at the new base first
pry resync --base 0x<kbase> --symbols ./vmlinux   # name the symbol file (default: the loaded kernel image, as `pry kbase` picks it; without one, the last `pry load`)
```

It stops a running target (and resumes it afterwards), drops the stale stop reason, the register/memory caches and any finished background result (so `pry status` and `pry wait` both report the re-read state), re-reads a rebased symbol file whose breakpoints GDB gave up on (`<PENDING>`), has GDB re-read every enabled watchpoint's value (below), restores baked traps and drops stub records nobody owns at breakpoint sites (below), looks for stray traps nobody owns away from them (below), then makes GDB insert every breakpoint at that stop and reads each trap back from target memory. Left stopped, it removes them again, so a snapshot taken at that stop holds no `int3`.

JSON result (`--format json`), a stable interface for callers such as qmu:

| Key | Meaning |
|-----|---------|
| `resynced` | always `true` |
| `state` / `status` | where the target is now: `stopped` or `running` |
| `reason` | when stopped: `{"kind": "resynced"}`, or the target's own stop if it stopped by itself while resync was stopping it; absent when running |
| `frame`, `thread` | freshly re-read, when stopped |
| `run_state` | `{was_running, interrupted, resumed}`, plus `stop` (it stopped on its own, or again at once after the resume) or `error` (it could not be resumed and is stopped) |
| `symbols` | with `--base`: `{loaded, base, slide, reference}` as `pry load` reports them |
| `reloaded` | paths of rebased symbol files re-read to recover `<PENDING>` locations |
| `breakpoints[]` | one entry per breakpoint location (per watchpoint/catchpoint): `number`, `location` (`"N.M"`), `kind`, `address` (absent when pending), `function` / `expression`, `status`, `detail`, `value` (watchpoints: the value GDB re-read at resync's stop, `null` if unreadable; see below), `trap_resident`, `reseated` (only when true), and for software breakpoints with readable memory `guest_bytes`, `elf_bytes`, `elf_match`, `baked_trap`, `stub_record` (only when true), `repaired` |
| `stray_traps[]` | traps nobody owns found away from breakpoint sites: `address`, `function` (`func+off`), `source` (`stop`: the trap the target last stopped on; `scan`: found by the code scan), `guest_bytes`, `elf_bytes` (`null` where no symbol file maps the address), `trap_in_memory` (a trap was in memory there when resync looked; `false` for a stub record alone), `stub_record` (only when true), `repaired` |
| `scan` | what the code scan read: `{files, bytes, unreadable}` (paths, bytes read, bytes that could not be read), or `{skipped: "<why>"}` |
| `summary` | `{breakpoints, armed, not_armed, baked_traps, repaired, elf_mismatch, stray_traps, stray_repaired}` |

`status` is one of: `armed` (GDB inserted it at resync's stop without error, and its trap is in memory wherever that is observable), `pending` (no address GDB will insert: unresolved, or `<PENDING>`), `unreadable` (target memory at the address cannot be read, so no trap can go there: the code moved after a KASLR re-slide, or is not mapped yet), `insert-failed` (the stub refused; `detail` has GDB's message), `not-resident` (the stub accepted it but its trap is not in memory, even after re-inserting it), `disabled` (by the user, or a watchpoint GDB would not enable again, below: then `detail` says so), `unverified` (watchpoints and catchpoints: nothing is read back for them, so only an observed insert error changes this). `not_armed` counts `pending` + `unreadable` + `insert-failed` + `not-resident`.

**Watchpoints.** GDB compares the value a trapped write leaves with the value it read last, and resumes without a word when they are equal; a snapshot load or a reset changes memory behind its back. So resync re-enables every enabled watchpoint at its stop, which makes GDB re-read that value from target memory (`value`, and `detail` says so); pry's own `old` of `old -> new` is re-read at the same moment. Without it, after a rewind, the first write that puts back the value GDB saw before the rewind would be swallowed. A write the target makes before resync runs (between a reset and resync, a reset's own boot code) is still compared with the old value. A caller that holds the target across the reset (`pry interrupt --hold`, see *A stop a caller holds*) and resyncs at the reset vector has GDB read the value as `<unreadable>` there, so the first write after the release is reported, the boot's own included; but GDB resumes a guest from the reset vector only with no software breakpoint set at a kernel address.

`trap_resident` is the trap instruction read back from target memory while GDB had the breakpoint inserted. It is `true`/`false` where traps are observable in memory (native targets, QEMU with KVM, or any stub where one was seen) and `null` where the stub keeps breakpoints out of the memory it reports (QEMU TCG, gdbserver), and for hardware breakpoints, watchpoints and entries that were not inserted. `reseated: true` means the first insert wrote nothing because QEMU's KVM gdbstub still held a record for that address (it survives a failed removal, e.g. the first stop after a reset, before the kernel maps its text), so resync dropped the record and inserted the breakpoint again. `elf_match: false` means target memory at the site is not what the symbol file has there, usually symbols at a stale KASLR base: rerun with `--base`.

Exit 0 means the report is current, not that every breakpoint is armed: check `summary.not_armed`, and `summary.elf_mismatch` (an `armed` breakpoint whose site does not match the symbol file traps wherever the stale symbols point, usually not the code you meant). Exit 1 means resync could not do its job (no live target, remote lost, a reload failed, or a running target could not be stopped, in which case nothing was changed).

**Stray traps.** A breakpoint deleted before a snapshot load, or one GDB orphaned, leaves a trap at an address no breakpoint leads to. Resync looks in two places. The trap the target last stopped on (stop reason `trap`): the stub's record there is dropped (QEMU writes back the byte it saved; under QEMU TCG an orphan exists only as that record) and a trap the symbol file does not have is restored. And, where the stub writes its traps into memory (QEMU under KVM), the code of every symbol file pry can map onto target memory (a plainly loaded non-PIE ELF such as a nokaslr vmlinux, or a file loaded with `pry load --base/--slide` or `resync --base`): every read-only executable section that stays code is read and every trap instruction the symbol file does not have, where one of the symbol file's instructions starts, with the following bytes matching, is restored the same way. On x86 an instruction start is found by decoding the symbol file's bytes from the nearest function or label symbol before it. For a vmlinux that is `.text`: 24 MiB for 6.1.128, 26 MiB for 6.6.75 and 53 MiB for 7.0 (KASAN builds), and a whole resync takes about 4–6 s, 6 s and 7 s under KVM, nearly all of it reading guest memory (checking the bytes takes about 0.6 s, 0.5 s and 0.8 s). Writable sections are never scanned, even when flagged executable (Linux 7.0 links `.data` WAX): their bytes are live data. Nor is init code (`.init.*`/`.exit.*` sections, and anything between `__init_begin` and `__init_end`, such as `.altinstr_*`): Linux poisons it with `0xcc` after boot and hands its pages to whoever allocates next. The `int3`s x86 Linux writes into its own text are left alone: one inside an instruction it rewrote at boot starts no instruction of the symbol file (the `ret; int3…` it writes over each `jmp __x86_return_thunk`, tens of thousands of them, told by their bytes alone; a `0xcc` byte in the new rel32 of a static call or alternative it retargeted), and the `jmp +N; int3…` padding its alternatives write over NOP runs is recognised.

**What exit 0 promises** about traps on a remote target: no trap pry can attribute to a debugger remains at any breakpoint site, at the trap the target last stopped on, or anywhere in the scanned code (`scan.files`), and every breakpoint location's `status` is current. It does **not** cover:
- code no mapped symbol file covers: kernel modules, PIE images and shared libraries loaded without `--base`, user space, JIT code. A trap there is handled only if the target stopped on it, and restored only if the stub recorded it;
- memory the scan could not read (`scan.unreadable`; all of it when the symbols sit at a stale KASLR base: rerun with `--base`);
- a stub record with no trap in memory (QEMU TCG) other than at breakpoint sites and the last trap stop: the protocol cannot list them. Under TCG or gdbserver the code is not scanned at all (`scan.skipped`): they keep traps out of the memory they report, and none is baked into a snapshot;
- on x86, a byte with no function or label symbol before it in its section (within 256 KiB): nothing proves an instruction starts there, so it is never written;
- writable sections (`.data`, also when flagged executable) and init code the kernel freed after boot are never scanned;
- an unoptimised kprobe's `int3` looks exactly like a planted one: resync restores it too, and the probe stops firing;
- native targets are never touched.

Between resyncs, every execution (`continue`, `step`, `finish`, …) on a remote target checks the breakpoint sites before it resumes (see *Baked traps* below), but only resync looks away from them.

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

Automatic spills use exclusively created unique files, so concurrent commands cannot overwrite one another's artifacts. An explicit `--out PATH` deliberately overwrites that path. Artifact success envelopes, like ordinary success values, have no `ok` field.

4. **Output/exit-code contract** (important for programmatic use): on **success** a command exits **0** and the result goes to **stdout** — in JSON mode a bare value/object (NOT wrapped in `{"ok":true}`). On **failure** the command exits **non-zero** and the error goes to **stderr** (`--format json` makes it `{"ok": false, "error": "..."}`); nothing goes to stdout. So you can gate on `$?`, and a success result never carries an `ok` field.

5. **Parallel calls are safe.** Read-only inspection commands (`backtrace`, `registers`, `locals`, `memory read`, `disasm`, `print`, etc.) take only a read lock and can be batched in parallel freely. Avoid parallelising execution/mutation commands (`run`, `continue`, `step`, `break set`, `memory write`) as they acquire an exclusive lock and will serialise anyway.

## Execution Control

```bash
pry run [args...]            # Run the program (blocks until stop/exit)
pry run -- -threads 1 -i crash.avi  # `--` before args that begin with '-'
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
pry interrupt --hold         # Stop it for a caller; waiters keep waiting (see "A stop a caller holds")
pry continue --release       # Resume what --hold stopped
pry status                   # Check if inferior is running or stopped
pry wait                     # Wait for a background exec to stop
pry threads                  # List threads with selected frame info
pry threads --pc 0x401400    # Filter threads stopped at an exact PC
pry threads --function worker  # Filter by current frame function substring
pry thread select 3          # Make thread 3 the persistently selected one
```

`pry finish` reports the function's return value as `return value: ...` (x86-64 integer/pointer returns; void/float/struct are omitted). Most inspection commands accept `--thread N` to run against a specific thread without persistently switching (the prior selection is restored); use `pry thread select N` to switch persistently.

Execution commands block until the inferior stops or exits. Use `--timeout N` to auto-interrupt after N seconds — the bridge interrupts the inferior and returns stop info with `timeout_interrupt: true`, staying responsive for subsequent commands. Set breakpoints before running to ensure the program stops where you want.

**Program arguments:** pry's own `run` options (`--timeout`, `--background`, `--stdin-file`, `--output`, `--format`, `--out`, `--instance`) go after `run` and come first, then the program arguments. When any program argument begins with `-`, put `--` in front of them: `pry run --timeout 10 -- -threads 1 -i crash.avi -f null -`. Without the sentinel pry rejects the command and prints the corrected command line; this includes arguments such as `-hide_banner` or `-help` that start like `-h`, and ambiguous prefixes such as `--o`. A `run` flag placed before `run` (`pry --background run`, `pry --timeout=5 run`, `pry --timeout 5 run`) is rejected with the corrected command too (`pry run --timeout 5`), and so is any subcommand's option placed before its subcommand (`pry --format json status` → `pry status --format json`). An argument that spells one of pry's options (or an unambiguous prefix like `--time`) is taken by pry unless it follows `--`.

**Stdin for the inferior:** use `pry run --stdin-file PATH` to open `PATH` as the inferior's real stdin (fd 0). Bytes are delivered raw — no PTY, so cooked-mode XON/XOFF cannot eat control bytes. Program args stay separate (`pry run --stdin-file payload.bin arg1 arg2`).

**Exact argv:** `pry run` preserves empty arguments, whitespace, quotes, backslashes, and literal shell metacharacters. It temporarily uses `/bin/sh` with each argument safely quoted, then restores GDB's `startup-with-shell` and the debugger's `SHELL`. This avoids old GDB no-shell parsers that split on whitespace regardless of quoting. Rerunning without new arguments reuses the previous vector. Raw `pry gdb 'run ...'` remains a GDB command and does not use pry's argv handling; the default launch setting is still `startup-with-shell off`, so use `--stdin-file` rather than raw shell redirection.

`pry status` reports `running`, `stopped`, `exited`, or `not-started`; `state` and `status` agree. `wait` returns the same terminal state rather than calling an exited inferior stopped. Once GDB reports a remote transport loss, execution, status/wait, and inspection return an operational error until reconnect/attach succeeds. A normal exit or confirmed signal termination remains a successful debugger operation. GDB may retain cached frames before it observes the loss; cached data alone cannot establish remote liveness.

Idle remote inspection refreshes GDB's register/frame caches before reading target state. This prevents the observed GDB 15 native abort when stale registers meet a failed lazy unwind-data fetch; it is not a separate liveness-probe packet. The selected frame level is preserved, but externally retained Python `gdb.Frame` objects can be invalidated: reacquire them in each `pry py exec` command. Active execution/trace bookkeeping is excluded from this refresh. After known transport loss, raw GDB permits only recovery commands (`target`, `attach`, `file`/`exec-file`, `detach`, `disconnect`) until the target is re-established.

Loading or clearing an executable discards prior exit codes and retained background results. Failed loads preserve the existing context. Intentional detach/disconnect leaves `state`/`status: "not-started"` with a `detached`/`disconnected` reason, not a fabricated process exit; the detached process may still be alive. This also applies to raw GDB lifecycle commands.

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

### A stop a caller holds (`pry interrupt --hold` / `pry continue --release`)

A plain `pry interrupt` makes its stop the operator's: a `pry wait` or foreground `continue` already waiting returns it (`reason: signal SIGINT`), even when whoever sent it resumes the target right after. A caller that needs the target stopped for work of its own (qmu around a snapshot save of a running guest, or a KASLR rebase after a snapshot load: `kbase`, then `resync`, with no resume between them) takes a held stop instead:

```bash
pry interrupt --hold        # stop it; a wait or foreground continue in flight keeps waiting
pry kbase && pry resync     # the holder's own ops run at the held stop
pry continue --release      # resume it; whoever waited now waits for its next stop
```

- Waiters in flight keep waiting through the hold, then for the stop of the execution the release resumes. A foreground `continue --timeout N` keeps its deadline; if the hold outlasts it, it exits 1 saying a caller holds the target. Meanwhile `pry status` says `reason: held` (JSON `{"kind": "held"}`), never a SIGINT nobody sent, and a new `pry wait` waits too.
- Nothing but the release resumes a held target: `continue`, `step`, `run`, `finish`, … and `trace` exit 1. Breakpoint ops, `kbase`, `resync`, raw `pry gdb` and inspection run at the held stop. A `resync` there leaves the breakpoints out of memory (a snapshot taken at the hold holds no `int3`); GDB inserts them when the release resumes the target.
- A target that was stopped already, or that stopped on its own while pry was stopping it (a breakpoint hit racing the interrupt), is held where it is and the release leaves it there: that stop is the operator's, and a waiter gets it at once. Like a breakpoint op, a hold will not stop a background `finish`/`until`/`step` (that would cancel it) or a `trace`.
- One hold at a time: a second `--hold` exits 1, and so does `--release` with nothing held (or with `--timeout`: the release returns at once). A release GDB cannot resume (a breakpoint it cannot insert) exits 1 like a failed `continue`: the hold is over and the target stays stopped, and a waiter gets that error.
- A hold across a machine reset (`system_reset` while held): the guest waits at the reset vector (QEMU `prelaunch`), where no kernel address is readable, so `resync` there reports every software breakpoint `unreadable` and every watchpoint's value `<unreadable>`. GDB then resumes it only with no software breakpoint set at a kernel address: with one, the release fails (`Cannot insert breakpoint N. Cannot access memory`) and the guest stays at the reset vector. With only watchpoints it boots, and the first write to a watched variable is reported (the old value was unreadable), the boot's own included.
- JSON: `--hold` returns the stop state with `held: true` and `run_state: {was_running, interrupted, will_resume, stop?}` (`will_resume`: the release resumes it; `stop`: the stop it reached on its own). `--release` returns `released: true`, `state`/`status` (with `reason`/`frame` when stopped), `run_state: {was_running, interrupted, resumed, stop?, pending_after_resume?}` as breakpoint ops report it, and the `baked_traps` it restored under breakpoints as it resumed.

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
- `reason: trap at ADDR: ...` — `continue`/`run`/`jump` stopped on a trap no breakpoint of pry's owns (JSON `kind: "trap"`, `address`; `trap_in_memory: true` with `trap_address` when a trap instruction is in memory there: the program's own `int3`, or one left behind, orphaned or baked into a restored snapshot; without one in memory on QEMU TCG, a breakpoint the stub still records for nobody). On a remote target `pry resync` removes one left behind (*Stray traps* above); otherwise every `continue` stops there again
- No `reason`, exit 1 — a `continue`/`run`/`jump` that GDB stopped because it could not insert its breakpoints (e.g. a 5th hardware breakpoint on x86, found after it stepped past the breakpoint at the PC or stopped for a shared-library event) failed: the error says where GDB stopped it and carries GDB's `Cannot insert …` reason. Free some (`pry break delete N` / `pry watch delete N`) before resuming. A raw `pry gdb continue` (or `stepi`, …) that GDB aborts the same way (`Command aborted.`) never resumed the target: `pry status` says `stopped`, and `pry interrupt`, breakpoint ops, `resync` and `pry kill` find it stopped
- `reason: resynced` — `pry resync` re-read the state after the machine changed; the previous stop reason no longer applies
- `reason: held` — a caller holds the target stopped (`pry interrupt --hold`, above); `pry continue --release` resumes it

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

**Running remote targets:** an all-stop remote stub (QEMU gdbstub, gdbserver) accepts no packets while it runs, and GDB edits its breakpoint table before it talks to the target. So when the target is running, `break set/delete/enable/disable`, `watch set/delete/enable/disable` and `load` stop it, apply the change at that stop, and resume it. JSON results carry `run_state: {was_running, interrupted, resumed}` and text ends with a `note:` line. GDB inserts breakpoints only when it resumes: a location it gives up on then (`<PENDING>`) is listed in `run_state.pending_after_resume` (`"N.M"`), marked pending in the returned breakpoint, and added to `load`'s `pending_breakpoints`. If the target stopped on its own meanwhile (a breakpoint hit racing the stop), it is left stopped and `run_state.stop` holds that stop. If the resume fails (GDB could not insert a breakpoint), the change still stands, `run_state.error` carries GDB's reason (e.g. `Cannot insert breakpoint 6. Cannot access memory at address …`), and the target is left stopped with no trap of GDB's in memory. If pry cannot stop the target, or the running execution is a background `finish`/`until`/`step`/`next` that a stop would cancel, the command exits 1 and nothing is changed. A `pry wait` already waiting keeps waiting through this internal stop. A command that failed while the target runs (e.g. `pry print '$pc'`: `Selected thread is running`) does not change any of this. Native targets take these changes live (no `run_state`). Raw `pry gdb 'delete 3'` bypasses all of this.

**Pending locations:** `pending: true` (text `(pending)` / `<PENDING>`) also covers a location GDB tried to insert and gave up on (it shows `<PENDING>` in `maint info breakpoints`): such a location carries `pending: true` and no `address`, because nothing will trap there. `pry load` lists the breakpoints it left pending in `pending_breakpoints`, including those GDB gave up on when it resumed a running target. `pry resync` re-reads a rebased symbol file to recover them.

**Baked traps and orphaned records:** at a stop GDB holds none of its breakpoints in memory, so a lone trap instruction (`0xcc` on x86, `brk #0` on arm64) at a breakpoint site, where the symbol file has another instruction and the following bytes match, belongs to nobody. It is typically an `int3` baked into a snapshot saved while breakpoints were inserted. Arming over it would save the trap as the "original": the breakpoint is hit, and stepping over the hit runs the saved trap with no breakpoint behind it (a guest `int3` Oops), and every removal leaves it behind. Likewise any record the stub still keeps for that address belongs to nobody: an orphaned `int3` (its trap still in memory) or a stale record from a failed removal (the first stop after a reset). QEMU's KVM gdbstub turns GDB's next insert at such an address into a no-op, so the breakpoint would be listed `[enabled]` and never fire. On remote targets, `break set/enable/disable/delete`, `load` and `resync` check the sites they touch, and every execution (`continue`, `run`, `jump`, `step`, `next`, `stepi`, `nexti`, `finish`, `until`) checks every breakpoint site before GDB resumes the target. Each first drops any such stub record (a raw `z0`; QEMU writes an orphan's saved byte back), then restores the symbol file's byte(s) over a trap still there, and reports `baked_traps: [{number, location, address, function, guest_bytes, elf_bytes, stub_record, repaired}]` (text: a `warning:` line; `stub_record: true` marks an orphan the stub still recorded). An execution reports them in its result at the stop (`pry wait` after `--background`); one that fails says so in its error. A breakpoint op that stops and resumes a running target reports those its resume restored in its own `baked_traps`. A stale record with no trap in memory is dropped silently: the breakpoint then simply works. A site whose surrounding bytes do not match the symbol file (stale base, patched text) is never written. An unoptimised kprobe's `int3` at the very same address looks identical and is restored too. The byte check needs the symbol file's mapping: a plainly loaded non-PIE ELF (a nokaslr vmlinux), or one loaded with `pry load --base/--slide`. Native processes are never touched (a lone `int3` there is the program's own). A trap away from every breakpoint site is resync's job (*Stray traps* above).

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

Record hardware-watchpoint hits attributed to instructions within a code range:

```bash
pry trace --watch 0x7fffffffd5d4 --range 0x404610-0x405e30
pry trace --watch 0x7fffffffd5d4 --watch-size 4 --range 0x404610-0x405e30 --type access --timeout 60 --max-hits 1000
```

The bridge single-steps instructions inside `[START, END)` with a hardware watchpoint enabled, and continues outside with that watchpoint disabled. It installs **persistent entry breakpoints at every decoded instruction**, so arbitrary branches into the middle and concurrent callers returning to the same address remain covered. Hits accumulate across repeated passes, and execution stops on the `--max-hits`th access rather than one access later.

This is **instruction-stepped, not native-speed tracing**. Setup time and breakpoint storage scale with the number of decoded instructions; use tight ranges. Each step temporarily isolates the source thread through GDB's scheduler locking, which can change multithreaded timing. The target must support the requested hardware watchpoint, software entry breakpoints, and scheduler-locking operations.

Each hit's `pc`/`asm` identifies the isolated accessing instruction; `stop_pc`/`stop_asm` separately records where GDB stopped. They need not be the same, and a hardware watchpoint can trap before instruction completion on some targets. `attribution: "instruction-step"` describes the method. An unidentifiable access stops tracing with an explicit incomplete `note` and `last_unattributed`, not a guessed instruction.

Only hits accepted by GDB count; filtered watchpoint events are not accesses. Existing user breakpoint conditions, ignore counts, and thread restrictions still apply without evaluating conditions a second time.

**Pick `START` on a valid instruction boundary in stable code.** Execution may enter at any decoded instruction in the range; it need not visit `START`. The range selects instruction start PCs, so the final instruction may extend past `END`. Decode/setup failures and observed PCs inconsistent with decoded boundaries are explicit errors. `armed: false` means no in-range instruction was stepped, not proof of no accesses elsewhere. `armed: true` with zero hits and no incomplete note means no watched hits were observed in the range.

If `--timeout` fires first, the bridge interrupts and returns partial hits with `timeout_interrupt: true`. `pry interrupt` cancels an active trace even between its internal steps, waits for internal-breakpoint cleanup, and marks the trace result `interrupted: true`. The prior scheduler setting is preserved, including after normal exit. Remote loss returns an operational error rather than a successful `exited` trace; confirmed normal and signal exits retain their terminal details.

Text output warns explicitly when a timeout or user interrupt leaves partial results.

Tracing owns execution through internal-breakpoint cleanup. Concurrent run/continue/step requests are rejected, including between trace steps; `pry interrupt` remains available.

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
pry registers read rip rdi       # Named registers only (aliases pc/sp, sub-registers eax; leading $ optional)
pry registers write rip 0x401234 # Set a register ($pc/$rsp/etc.; leading $ optional)
pry registers write --thread 2 r15 0x4141  # ...in thread 2 (read/write both take --thread)
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

**While an all-stop remote target runs** (QEMU gdbstub, gdbserver: after `pry continue --background` or a raw `continue &`), `pry gdb` runs only commands that read nothing from the target: `interrupt`, `help`, `show` (not `show convenience`/`show values`, which evaluate), and `info breakpoints`/`watchpoints`/`display` (also `maint info breakpoints`). GDB runs every line of a multi-line command, so every line must be one of these. Anything else exits 1 and is not run, not even its allowed lines (`the inferior is running — pry interrupt (or pry wait) first`): a read of a running all-stop stub can make GDB 15 abort (`x/i`, `disassemble`), which kills the bridge and leaves every trap GDB inserted in target memory, and no list of the commands that read (`x`, `print`, `info registers`, pwndbg's `telescope`/`search`/…) is complete. Stop the target first (`pry interrupt`), run the command, then `pry continue --background`. Native targets are not limited. `pry py exec` is not checked: do not read target memory from it while a remote target runs.

## pwndbg Command Reference

pwndbg is loaded alongside the bridge, so **any** pwndbg command runs verbatim through `pry gdb "..."`. The full catalogue (KASLR/`kbase`, glibc heap, SLUB, ROP, GOT/PLT, memory search, context) lives in [reference/pwndbg.md](reference/pwndbg.md) — read it on demand for kernel/heap/exploit work. It is kept out of this always-loaded skill to save context.

```bash
pry gdb "pwndbg"                      # Full list of pwndbg commands (--list-categories for groups)
pry kbase                             # Validated kernel base (KASLR); rebases the loaded vmlinux — prefer over `pry gdb kbase`
pry gdb checksec                      # Binary security (NX, PIE, RELRO, canary)
pry gdb vmmap                         # Virtual memory map
```

For KASLR symbol rebasing load the vmlinux, then run `pry kbase` (it validates the base and rebases the loaded file) — see **Remote Debugging → KASLR kernels** above for the guarantee and the recipe, and [reference/pwndbg.md](reference/pwndbg.md) for why not `kbase -r` and for the yama/ptrace_scope footgun.

Prefer the first-class structured commands where they exist — `pry kbase` (over `pry gdb kbase`), `pry mappings` (over `vmmap`), `pry registers` / `pry registers write`, `pry disasm` (symbol-annotated), `pry backtrace` — and drop to `pry gdb` for everything else.


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
