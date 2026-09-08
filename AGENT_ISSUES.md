# pry — Agent Issue Log

Append friction/bugs/rough-edges hit while driving the `pry` CLI during VR work.
One entry per issue. Keep it reproducible so it can become a real fix or a `pry` test.

Template:
```
## YYYY-MM-DD — <one-line summary>
- **Command:** `pry ...`
- **Expected:** ...
- **Actual:** ... (paste the error / wrong output)
- **Workaround:** ... (if any)
- **Context:** what task, which binary/session
```

---

## 2026-07-22 — `pry run` eats inferior args that begin with a dash
- **Command:** `pry run -threads 1 -i crash.avi -f null -`
- **Expected:** everything after `run` is forwarded to the inferior as argv (skill doc shows `pry run [args...]`).
- **Actual:** argparse claims them: `pry: error: unrecognized arguments: -threads -i crash.avi -f null -`. Any inferior arg starting with `-`/`--` (ffmpeg, most CLIs) collides with pry's own option parser.
- **Workaround:** insert a `--` sentinel: `pry run -- -threads 1 -i crash.avi -f null -`. Works cleanly.
- **Suggestion:** document the `--` requirement in the skill's `pry run` example (it currently implies bare pass-through), or auto-insert `--` before forwarding.
- **Context:** CVE-2026-8461 FFmpeg MagicYUV heap-OOB recon; driving build-plain/ffmpeg under real glibc.

## 2026-07-22 — reading a register needs `pry print $reg`, not `pry registers <name>`
- **Command:** `pry registers rip` / `pry registers rdi`
- **Expected:** print the named register (symmetry with `pry memory read`, `pry print`).
- **Actual:** `error: argument registers_command: invalid choice: 'rip' (choose from write)` — the `registers` verb only exposes a `write` subcommand; there is no `read`.
- **Workaround:** use GDB convenience vars via print: `pry print '$rip'`, `pry print '(char*)$rdi'`. Works cleanly.
- **Suggestion:** add `pry registers read [names...]` (or a bare `pry registers` dump) mirroring `memory read`.
- **Context:** CVE-2026-8461 weaponization; capturing rip=system / rdi=cmd-string at the hijacked indirect call.

## 2026-07-23 — `pry kbase` (IDT fallback) is inexact and does not auto-apply the slide
- **Command:** `pry kbase` at a halted stub (x86_64), then trying to use symbols
- **Expected:** an exact kernel `_text` base that gets applied to the loaded symbol table so subsequent lookups resolve.
- **Actual:** IDT-derived base was off — reads landed on `0xCC` padding, so the computed base was inexact. Even when reported, the slide is not auto-applied to the symbol file, so symbols stay unrebased.
- **Workaround:** boot the guest with `nokaslr` (removes the slide entirely; symbols then match without rebasing). `qmu kbase` is not an option here — it needs SSH, which is dead while halted at the stub.
- **Suggestion:** (a) auto-apply the discovered slide to the loaded symbol table; (b) harden the IDT method against `0xCC`-padded reads / validate the derived base against a known symbol. On arm64 the VBAR route (pry #50) is exact — consider an equivalent exact source for x86.
- **Context:** kernel exploit-dev under qmu+pry; rebasing symbols at a breakpoint before boot completes.
