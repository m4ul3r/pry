# pwndbg Command Reference (on-demand)

pwndbg is a GDB plugin loaded alongside the pry bridge. All pwndbg commands are available via `pry gdb`. This reference covers the most useful ones — run `pry gdb "pwndbg"` for the full list (or `pry gdb "pwndbg --list-categories"` for the category names).

### KASLR / Kernel Symbols

When connected to a QEMU kernel with KASLR enabled, vmlinux symbols are at link-time addresses and won't match the running kernel. **Use `pry load --base` to rebase them — do NOT pre-load symbols and then `kbase -r`** (see the pitfall below).

**Recommended KASLR workflow** (verified: both function *and* data symbols resolve):
```bash
pry launch --connect localhost:1234   # connect WITHOUT --symbols (no link-time copy)
                                      # (with qmu: `qmu gdb --vm <id>` and DON'T pass --symbols)
pry gdb kbase                         # -> "Found virtual text base address: 0x...."
pry load ./vmlinux --base 0x<kbase> --src /path/to/linux-src --gdb-scripts
# one clean copy; offsets ALL sections; maps source; sources vmlinux-gdb.py (lx-*)
pry break set commit_creds            # symbol breakpoints, print, disasm now resolve correctly
pry print "init_task.comm"            # data symbols work too
pry source list commit_creds          # needs --src when DWARF paths are relative / under /src
pry gdb 'p $lx_current()->pid'        # needs --gdb-scripts (Linux lx helpers)
pry continue
```

`pry load --base` reads vmlinux's link-time `.text` address, computes `slide = base - .text`, and runs `add-symbol-file vmlinux -o <slide>` after dropping any prior copy — so there is exactly one symbol table and every section (text + data) lands at its runtime address.

**How `kbase` works:** On x86-64 it reads the IDT via the IDTR register (available from the GDB stub without symbols), parses IDT entry 0 to get a `.text` address, then walks page tables to find the containing mapping's base. On AArch64 it reads VBAR_EL1. No symbols or /proc access needed.

> **Pitfall — `kbase -r` is not enough.** `pry gdb "kbase -r"` does `add-symbol-file vmlinux <base>`, which (a) *adds* a second copy without removing the link-time one (so `print &sym`/`break sym` resolve to the stale, unmapped link-time address → `MemoryError`), and (b) only relocates `.text`, leaving data symbols (`jiffies`, `init_task`) at link addresses. If you loaded vmlinux as the primary file (e.g. `pry launch --symbols vmlinux` or `qmu gdb --symbols vmlinux`), `kbase -r` will *not* make symbol lookups work. Prefer `pry load --base`. If you don't have vmlinux at all, `klookup` reads the in-memory kallsyms and gives correct runtime addresses.

### Kernel Inspection

```bash
pry gdb kbase                         # Kernel virtual base address (then: pry load vmlinux --base <kbase>)
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
pry gdb 'search "flag{"'             # Search memory for a substring (plain form; matches a prefix of a longer string)
pry gdb 'search -t string "flag{"'   # EXACT string match — `-t string` appends a NUL, so this only hits a whole NUL-terminated "flag{"; use the plain form above for prefixes/substrings
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
pry threads                           # Structured thread list
pry gdb "info threads"                # Raw GDB thread list
pry gdb "thread apply all bt"         # Backtrace all threads
pry gdb canary                        # Leak the stack canary value
pry gdb "tls"                         # Thread-local storage info
```
