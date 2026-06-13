from __future__ import annotations

import atexit
import base64
import contextlib
import ctypes
import errno
import json
import os
import re
import socketserver
import struct
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gdb

from .paths import PLUGIN_NAME, bridge_registry_path, bridge_socket_path, instances_dir
from .version import VERSION, build_id_for_file

PLUGIN_BUILD_ID = build_id_for_file(Path(__file__).resolve())


def _json_response(*, ok: bool, result: Any = None, error: str | None = None) -> dict[str, Any]:
    return {"ok": ok, "result": result, "error": error}


# ---------------------------------------------------------------------------
# Reader-writer lock (same pattern as bn)
# ---------------------------------------------------------------------------

class _ReadWriteLock:
    def __init__(self):
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False

    @contextlib.contextmanager
    def read(self):
        with self._condition:
            while self._writer:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextlib.contextmanager
    def write(self):
        with self._condition:
            while self._writer or self._readers:
                self._condition.wait()
            self._writer = True
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


# ---------------------------------------------------------------------------
# Op classification
# ---------------------------------------------------------------------------

READ_LOCKED_OPS = {
    "backtrace",
    "frame_info",
    "frame_select",
    "frame_up",
    "frame_down",
    "locals",
    "args",
    "print",
    "registers",
    "memory_read",
    "disasm",
    "examine",
    "functions",
    "symbols",
    "types_show",
    "info_files",
    "source_list",
    "break_list",
    "list_inferiors",
    "list_threads",
    "target_info",
    "mappings",
    "display_list",
}

EXEC_OPS = {
    "run",
    "continue",
    "step",
    "next",
    "stepi",
    "nexti",
    "finish",
    "until",
    "jump",
}

WRITE_LOCKED_OPS = {
    "load",
    "attach",
    "connect",
    "disconnect",
    "run",
    "continue",
    "step",
    "next",
    "stepi",
    "nexti",
    "finish",
    "until",
    "jump",
    "break_set",
    "break_delete",
    "break_enable",
    "break_disable",
    "watch_set",
    "memory_write",
    "register_write",
    "thread_select",
    "call",
    "display_add",
    "display_remove",
    "py_exec",
    "gdb_exec",
}


# ---------------------------------------------------------------------------
# info functions / info variables parsing
# ---------------------------------------------------------------------------

_DEBUG_LINE_RE = re.compile(r"^\s*(\d+):\s*(.+?)\s*;?\s*$")
_NON_DEBUG_LINE_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+(.+?)\s*$")
_FILE_HEADER_RE = re.compile(r"^\s*File\s+(.+?):\s*$")
# Last identifier before '(' (functions) or before ';' / '[' (variables).
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _looks_like_bare_hex_address(s: str) -> bool:
    """True when s matches /^0x[0-9a-f]+$/i — no '*' prefix, no spaces,
    no module qualifier. Such inputs almost always mean "raw address"
    (not a source line number, which is gdb's default interpretation).
    """
    if not s or s.startswith("*"):
        return False
    s = s.strip()
    if not s.startswith(("0x", "0X")):
        return False
    rest = s[2:]
    return bool(rest) and all(c in "0123456789abcdefABCDEF" for c in rest)


def _extract_function_name(signature: str) -> str | None:
    """Pull the function name out of a `info functions` signature."""
    paren = signature.find("(")
    head = signature[:paren] if paren != -1 else signature
    idents = _IDENT_RE.findall(head)
    return idents[-1] if idents else None


def _extract_variable_name(decl: str) -> str | None:
    """Pull the variable name out of a `info variables` declaration."""
    # Strip trailing initializer, array dims, bit-field widths.
    head = re.split(r"[\[=:]", decl, maxsplit=1)[0]
    idents = _IDENT_RE.findall(head)
    return idents[-1] if idents else None


def _lookup_function_address(name: str) -> str | None:
    """Resolve a function's runtime address via GDB. Best-effort."""
    try:
        val = gdb.parse_and_eval(f"&{name}")
        return f"0x{int(val):x}"
    except Exception:
        return None


def _resolve_to_address(expr: str) -> int | None:
    """Resolve *expr* to an integer address. Handles functions, registers,
    symbols, and raw addresses. Returns None if GDB can't produce one.

    gdb.parse_and_eval("main") returns a function-typed Value; int() of it
    raises "Cannot convert value to long". Retry as &expr in that case so a
    function name works the same as a pointer/address.
    """
    try:
        val = gdb.parse_and_eval(expr)
    except Exception:
        return None
    try:
        return int(val)
    except Exception:
        pass
    try:
        return int(val.address)
    except Exception:
        pass
    try:
        return int(gdb.parse_and_eval(f"&({expr})"))
    except Exception:
        return None


def _elf_text_vaddr(path: str) -> int | None:
    """Link-time virtual address of the ``.text`` section of an ELF64 file.

    Used to compute the uniform relocation slide for ``pry load --base``:
    ``slide = runtime_base - link_text_vaddr``. Returns None if the file isn't
    a readable ELF64 or has no ``.text`` section.
    """
    try:
        with open(path, "rb") as f:
            ehdr = f.read(64)
            if len(ehdr) < 64 or ehdr[:4] != b"\x7fELF" or ehdr[4] != 2:
                return None  # not ELF64
            endian = "<" if ehdr[5] == 1 else ">"
            e_shoff = struct.unpack_from(endian + "Q", ehdr, 0x28)[0]
            e_shentsize = struct.unpack_from(endian + "H", ehdr, 0x3A)[0]
            e_shnum = struct.unpack_from(endian + "H", ehdr, 0x3C)[0]
            e_shstrndx = struct.unpack_from(endian + "H", ehdr, 0x3E)[0]
            if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
                return None
            f.seek(e_shoff)
            shdrs = f.read(e_shentsize * e_shnum)

            def _sh(i: int) -> bytes:
                return shdrs[i * e_shentsize:(i + 1) * e_shentsize]

            strhdr = _sh(e_shstrndx)
            str_off = struct.unpack_from(endian + "Q", strhdr, 0x18)[0]
            str_size = struct.unpack_from(endian + "Q", strhdr, 0x20)[0]
            f.seek(str_off)
            strtab = f.read(str_size)
            for i in range(e_shnum):
                h = _sh(i)
                name_off = struct.unpack_from(endian + "I", h, 0)[0]
                end = strtab.find(b"\x00", name_off)
                name = strtab[name_off:end if end != -1 else None]
                if name == b".text":
                    return struct.unpack_from(endian + "Q", h, 0x10)[0]
    except (OSError, struct.error):
        return None
    return None


_DISASM_LINE_RE = re.compile(
    r"^\s*(?:=>\s*)?(0x[0-9a-fA-F]+)\s*(?:<([^>]+)>)?:\s*(.+?)\s*$"
)


def _parse_disassemble_output(output: str) -> list[dict[str, Any]]:
    """Parse GDB ``disassemble`` text into the same list shape as the
    architecture-based fast path: [{address, asm, symbol?}]. Returns [] if
    nothing parses (caller then falls back to the raw text)."""
    result: list[dict[str, Any]] = []
    for raw in output.splitlines():
        m = _DISASM_LINE_RE.match(raw)
        if not m:
            continue
        entry: dict[str, Any] = {"address": m.group(1), "asm": m.group(3)}
        sym = m.group(2)
        if sym:
            # Normalise "func+4" / "func + 4" -> "func+4".
            entry["symbol"] = re.sub(r"\s*\+\s*", "+", sym.strip())
        result.append(entry)
    return result


def _parse_info_functions(output: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    current_file: str | None = None
    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("All functions", "All defined functions")):
            continue
        if stripped.startswith("Non-debugging symbols"):
            current_file = None
            continue
        m = _FILE_HEADER_RE.match(line)
        if m:
            current_file = m.group(1)
            continue
        # Address-prefixed form ("0xADDR NAME") appears in both
        # Non-debugging-symbols sections and (in some GDB outputs) directly
        # under a File: header. Handle either.
        m = _NON_DEBUG_LINE_RE.match(line)
        if m:
            entry: dict[str, Any] = {"name": m.group(2), "address": m.group(1)}
            if current_file:
                entry["file"] = current_file
            result.append(entry)
            continue
        m = _DEBUG_LINE_RE.match(line)
        if not m:
            continue
        line_num = int(m.group(1))
        signature = m.group(2).strip()
        name = _extract_function_name(signature)
        if not name:
            continue
        entry = {"name": name, "signature": signature, "line": line_num}
        if current_file:
            entry["file"] = current_file
        address = _lookup_function_address(name)
        if address:
            entry["address"] = address
        result.append(entry)
    return result


def _parse_info_variables(output: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    current_file: str | None = None
    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("All variables", "All defined variables")):
            continue
        if stripped.startswith("Non-debugging symbols"):
            current_file = None
            continue
        m = _FILE_HEADER_RE.match(line)
        if m:
            current_file = m.group(1)
            continue
        m = _NON_DEBUG_LINE_RE.match(line)
        if m:
            entry: dict[str, Any] = {"name": m.group(2), "address": m.group(1)}
            if current_file:
                entry["file"] = current_file
            result.append(entry)
            continue
        m = _DEBUG_LINE_RE.match(line)
        if not m:
            continue
        line_num = int(m.group(1))
        decl = m.group(2).strip()
        name = _extract_variable_name(decl)
        if not name:
            continue
        entry = {"name": name, "decl": decl, "line": line_num}
        if current_file:
            entry["file"] = current_file
        address = _lookup_function_address(name)
        if address:
            entry["address"] = address
        result.append(entry)
    return result


# ---------------------------------------------------------------------------
# GDB thread safety: post work to GDB's event loop
# ---------------------------------------------------------------------------

# Identity of the thread that runs GDB's event loop (and thus every posted
# callback). Captured on first callback so a timed-out runaway can be
# interrupted by injecting an async exception into that exact thread.
_gdb_main_thread_ident: int | None = None


class _AsyncTimeout(Exception):
    """Injected into the GDB main thread to break a timed-out runaway.

    A regular Exception (not KeyboardInterrupt) so it is caught by the same
    ``except Exception`` paths as any other op error and reported cleanly,
    rather than escaping into the socket server and dropping the connection.
    """

    def __str__(self) -> str:
        return (
            "operation exceeded its timeout and was interrupted "
            "(a runaway loop in `py exec`?)"
        )


def _async_raise(thread_ident: int | None, exc_type: type) -> bool:
    """Inject *exc_type* into the thread with *thread_ident* (best-effort).

    Uses CPython's PyThreadState_SetAsyncExc: the interpreter raises the
    exception in that thread between bytecode instructions. This breaks a
    runaway *Python* loop (e.g. a `while True` in `py exec`), but cannot
    preempt a thread blocked in C (e.g. inside a long GDB operation) — the
    exception is delivered only once control returns to Python bytecode.
    """
    if thread_ident is None:
        return False
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_ulong(thread_ident), ctypes.py_object(exc_type)
    )
    if res > 1:
        # More than one thread was affected (shouldn't happen): undo it.
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_ident), None)
        return False
    return res == 1


def _run_on_gdb_thread(func, *, timeout: float = 120.0):
    """Execute *func* on GDB's main thread via gdb.post_event and wait."""
    holder: dict[str, Any] = {}
    event = threading.Event()

    def _callback():
        global _gdb_main_thread_ident
        _gdb_main_thread_ident = threading.get_ident()
        try:
            holder["result"] = func()
        except BaseException as exc:  # noqa: BLE001 — also catch injected _AsyncTimeout
            holder["error"] = exc
            holder["traceback"] = traceback.format_exc()
        event.set()

    gdb.post_event(_callback)
    if not event.wait(timeout=timeout):
        # The callback is still running on GDB's main thread and would wedge
        # the bridge indefinitely (e.g. an infinite loop in `py exec`). Try to
        # break a runaway Python loop, then give it a short grace period to
        # unwind so the bridge stays responsive for subsequent commands.
        _async_raise(_gdb_main_thread_ident, _AsyncTimeout)
        if not event.wait(timeout=5.0):
            raise RuntimeError(
                f"Timed out waiting for GDB main thread after {timeout:.0f}s "
                "(the operation may still be running in GDB)"
            )

    if "error" in holder:
        raise holder["error"]
    return holder.get("result")


# ---------------------------------------------------------------------------
# Socket server
# ---------------------------------------------------------------------------

class BridgeHandler(socketserver.StreamRequestHandler):
    def _write_response(
        self,
        encoded: bytes,
        *,
        op: str | None = None,
        request_id: str | None = None,
    ) -> None:
        try:
            self.wfile.write(encoded)
        except OSError as exc:
            if exc.errno not in {errno.EPIPE, errno.ECONNRESET}:
                raise
            details = []
            if op:
                details.append(f"op={op}")
            if request_id:
                details.append(f"id={request_id}")
            suffix = f" ({', '.join(details)})" if details else ""
            gdb.write(f"pry bridge: client disconnected before response{suffix}\n")

    def handle(self):
        raw = self.rfile.readline()
        if not raw:
            return
        op = None
        request_id = None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            response = _json_response(ok=False, error="Invalid JSON request")
        else:
            op = payload.get("op")
            request_id = payload.get("id")
            response = self.server.bridge.dispatch(payload)
        encoded = json.dumps(response, sort_keys=True, default=str).encode("utf-8")
        self._write_response(encoded, op=op, request_id=request_id)


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, socket_path: str, handler, bridge):
        self.bridge = bridge
        super().__init__(socket_path, handler)


# ---------------------------------------------------------------------------
# Helpers for extracting GDB state
# ---------------------------------------------------------------------------

def _frame_to_dict(frame) -> dict[str, Any]:
    """Convert a gdb.Frame to a JSON-friendly dict."""
    result: dict[str, Any] = {}
    try:
        result["address"] = hex(frame.pc())
    except Exception:
        result["address"] = None
    try:
        name = frame.name()
        result["function"] = str(name) if name is not None else None
    except Exception:
        result["function"] = None
    try:
        sal = frame.find_sal()
        if sal and sal.symtab:
            result["file"] = sal.symtab.filename
            result["line"] = sal.line
    except Exception:
        pass
    return result


def _stop_info() -> dict[str, Any]:
    """Capture current stop state after an execution command.

    Prefer ``GdbBridge._stop_info()`` when a bridge instance is available —
    it enriches the result with the stop *reason* captured from GDB events.
    This module-level helper is kept for backwards compatibility.
    """
    result: dict[str, Any] = {}
    try:
        frame = gdb.selected_frame()
        result["frame"] = _frame_to_dict(frame)
    except gdb.error:
        result["frame"] = None

    try:
        thread = gdb.selected_thread()
        if thread is not None:
            result["thread"] = thread.num
            if thread.is_exited():
                result["status"] = "exited"
            elif thread.is_running():
                result["status"] = "running"
            elif thread.is_stopped():
                result["status"] = "stopped"
            else:
                result["status"] = "unknown"
        else:
            result["status"] = "exited"
            result["thread"] = None
    except Exception:
        result["status"] = "unknown"
        result["thread"] = None

    return result


_BP_KIND_BY_TYPE: dict[int, str] = {}


def _bp_kind(bp_type: int) -> str:
    """Map a gdb.BP_* integer to a stable string name."""
    if not _BP_KIND_BY_TYPE:
        for attr, name in (
            ("BP_BREAKPOINT", "breakpoint"),
            ("BP_HARDWARE_BREAKPOINT", "hw-breakpoint"),
            ("BP_WATCHPOINT", "watchpoint"),
            ("BP_HARDWARE_WATCHPOINT", "hw-watchpoint"),
            ("BP_READ_WATCHPOINT", "read-watchpoint"),
            ("BP_ACCESS_WATCHPOINT", "access-watchpoint"),
            ("BP_CATCHPOINT", "catchpoint"),
        ):
            val = getattr(gdb, attr, None)
            if val is not None:
                _BP_KIND_BY_TYPE[int(val)] = name
    return _BP_KIND_BY_TYPE.get(int(bp_type), f"type-{bp_type}")


def _breakpoint_to_dict(bp) -> dict[str, Any]:
    """Convert a gdb.Breakpoint to a JSON-friendly dict."""
    result: dict[str, Any] = {
        "number": bp.number,
        "type": bp.type,
        "kind": _bp_kind(bp.type),
        "enabled": bp.enabled,
        "location": getattr(bp, "location", None),
        "expression": getattr(bp, "expression", None),
        "condition": bp.condition,
        "hits": bp.hit_count,
        "temporary": bp.temporary,
        # gdb.Breakpoint.pending is True when the location has not been
        # resolved yet (e.g. set on a symbol in an unloaded shared library,
        # or a typo'd function name). Agents otherwise can't tell a zombie
        # BP from a live one.
        "pending": bool(getattr(bp, "pending", False)),
        # Thread restriction (None = fires on any thread) and ignore count
        # are otherwise invisible — a thread-scoped or ignore-gated breakpoint
        # looks identical to a plain one in the list.
        "thread": getattr(bp, "thread", None),
        "ignore": getattr(bp, "ignore_count", 0),
    }
    return result


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------

class GdbBridge:
    def __init__(self):
        pid = os.getpid()
        self.socket_path = bridge_socket_path(pid)
        self.registry_path = bridge_registry_path(pid)
        self._server: ThreadedUnixServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = _ReadWriteLock()
        self._last_stop_reason: dict[str, Any] | None = None
        # Last-seen value per watchpoint number, so a watchpoint-hit stop can
        # report old -> new even though the GDB Python event API doesn't carry
        # the values GDB prints to the console.
        self._watchpoint_values: dict[int, str] = {}
        # Background execution state
        self._running = False
        # Whether the inferior has ever started (run/attach/connect). Lets
        # status distinguish "not-started" from "exited" — both have pid 0.
        self._has_run = False
        # Exit code of the most recent inferior exit (None if exited via signal
        # or never exited). Surfaced by `status` so agents can read the code
        # after the process is gone.
        self._last_exit_code: int | None = None
        self._background_completion: threading.Event | None = None
        self._background_result: dict[str, Any] | None = None
        # Set by _finish just before running `finish` so the stop handler can
        # recover the return value: the frame that is finishing (to confirm it
        # actually returned vs. stopping at an intervening breakpoint) and its
        # return type (to cast the ABI return register).
        self._finish_frame = None
        self._finish_ret_type = None
        # Auto-display expressions: re-evaluated and attached to every stop
        # result. Each entry is {"number": int, "expr": str}.
        self._displays: list[dict[str, Any]] = []
        self._display_counter = 0
        gdb.events.stop.connect(self._on_stop)
        if hasattr(gdb.events, "exited"):
            gdb.events.exited.connect(self._on_exited)
        # Never let a GDB command block the bridge waiting on an interactive
        # y/n prompt (e.g. remove-symbol-file), which would wedge the session.
        for _setup in ("set confirm off", "set pagination off"):
            with contextlib.suppress(Exception):
                gdb.execute(_setup, to_string=True)

    def start(self):
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._server = ThreadedUnixServer(str(self.socket_path), BridgeHandler, self)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._write_registry()
        gdb.write(f"pry bridge listening on {self.socket_path}\n")

    def stop(self):
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.shutdown()
            with contextlib.suppress(Exception):
                self._server.server_close()
        if self.socket_path.exists():
            with contextlib.suppress(OSError):
                self.socket_path.unlink()
        if self.registry_path.exists():
            with contextlib.suppress(OSError):
                self.registry_path.unlink()

    @staticmethod
    def _is_watchpoint_type(bp_type: int) -> bool:
        """Check if a breakpoint type is any kind of watchpoint."""
        for attr in ("BP_WATCHPOINT", "BP_HARDWARE_WATCHPOINT",
                     "BP_READ_WATCHPOINT", "BP_ACCESS_WATCHPOINT"):
            val = getattr(gdb, attr, None)
            if val is not None and bp_type == val:
                return True
        return False

    @staticmethod
    def _safe_eval_str(expression: str) -> str | None:
        """Evaluate *expression* and stringify it, or None if that fails."""
        try:
            return str(gdb.parse_and_eval(expression))
        except Exception:
            return None

    def _snapshot_watchpoints(self) -> None:
        """Record each active watchpoint's current value (GDB thread only).

        Called just before the inferior resumes so the next watchpoint-hit can
        report old -> new. Snapshotting once per resume (rather than mutating
        in _bp_reason) keeps the transition correct when multiple stop handlers
        process the same stop.
        """
        for bp in (gdb.breakpoints() or []):
            if not self._is_watchpoint_type(bp.type):
                continue
            expression = getattr(bp, "expression", None)
            if not expression:
                continue
            value = self._safe_eval_str(expression)
            if value is not None:
                self._watchpoint_values[bp.number] = value
            else:
                # Transiently unevaluable: drop any stale snapshot so the next
                # hit reports no old_value rather than one from an earlier resume.
                self._watchpoint_values.pop(bp.number, None)

    def _bp_reason(self, bp) -> dict[str, Any]:
        """Build a stop-reason dict for a breakpoint/watchpoint."""
        reason: dict[str, Any] = {}
        if self._is_watchpoint_type(bp.type):
            reason["kind"] = "watchpoint-hit"
            reason["number"] = bp.number
            expression = getattr(bp, "expression", None)
            reason["expression"] = expression
            # GDB prints "Old value = .. / New value = .." to the console but
            # the Python event API doesn't expose it. Re-evaluate the watched
            # expression (the inferior has already performed the write by the
            # time the stop fires) and diff against the value snapshotted just
            # before the inferior resumed, so the agent gets the single datum a
            # watchpoint exists to provide. This is READ-ONLY on purpose: a
            # single stop fires every connected stop handler, each of which
            # builds a reason, so mutating the cache here would let the first
            # handler advance it and make the rest see old == new.
            if expression:
                new_value = self._safe_eval_str(expression)
                old_value = self._watchpoint_values.get(bp.number)
                if new_value is not None:
                    reason["new_value"] = new_value
                    if old_value is not None and old_value != new_value:
                        reason["old_value"] = old_value
                elif old_value is not None:
                    # The watched expression became unreadable (e.g. a pointer
                    # was NULLed, or a local left scope). Still report the
                    # transition the watchpoint exists for, mirroring GDB's
                    # "Old value = .. / New value = <unreadable>".
                    reason["old_value"] = old_value
                    reason["new_value"] = "<unreadable>"
            # A watchpoint on a local is auto-deleted by GDB when its scope
            # exits; flag that so the agent knows it won't fire again.
            if bp.number not in {b.number for b in (gdb.breakpoints() or [])}:
                reason["deleted"] = True
        else:
            reason["kind"] = "breakpoint-hit"
            reason["number"] = bp.number
            reason["location"] = getattr(bp, "location", None)
        if bp.temporary:
            reason["temporary"] = True
        return reason

    def _on_stop(self, event):
        """GDB stop-event callback — captures the stop reason."""
        self._running = False
        reason: dict[str, Any] = {}
        if hasattr(gdb, "BreakpointEvent") and isinstance(event, gdb.BreakpointEvent):
            bps = event.breakpoints
            if bps:
                reason = self._bp_reason(bps[0])
        elif hasattr(gdb, "SignalEvent") and isinstance(event, gdb.SignalEvent):
            reason["kind"] = "signal"
            reason["signal"] = event.stop_signal
        # A plain stop with no breakpoint/signal is a completed step/next/
        # finish/until. Record a generic reason so `status`/`wait` can always
        # answer "why is it stopped?" instead of returning nothing.
        self._last_stop_reason = reason or {"kind": "step"}

    def _on_exited(self, event):
        """GDB exited-event callback — clears stale stop reason, records code."""
        self._running = False
        self._last_stop_reason = None
        self._last_exit_code = getattr(event, "exit_code", None)

    def _exec_and_stop(self, cmd: str) -> None:
        """Execute *cmd* on the GDB thread.

        The actual stop info is captured by ``_dispatch_exec``'s temporary
        stop event handler, not by this method.  This just runs the command.
        """
        gdb.execute(cmd, to_string=True)

    def _derive_stop_reason(
        self, hit_counts: dict[int, int], gdb_output: str
    ) -> dict[str, Any] | None:
        """Derive stop reason from GDB output text, hit-count changes, or events."""
        import re

        if not gdb_output:
            return self._derive_from_hit_counts(hit_counts)

        # Parse "Breakpoint N, ..." from output
        m = re.search(r"Breakpoint\s+(\d+),", gdb_output)
        if m:
            num = int(m.group(1))
            for bp in (gdb.breakpoints() or []):
                if bp.number == num:
                    return self._bp_reason(bp)
            return {"kind": "breakpoint-hit", "number": num, "location": None}

        # Parse "Hardware watchpoint N: expr\nOld value = ..." or
        # "Watchpoint N: expr\nOld value = ..."
        m = re.search(r"(?:Hardware\s+)?[Ww]atchpoint\s+(\d+):", gdb_output)
        if m:
            num = int(m.group(1))
            for bp in (gdb.breakpoints() or []):
                if bp.number == num:
                    return self._bp_reason(bp)
            return {"kind": "watchpoint-hit", "number": num, "expression": None}

        # Parse "Program received signal SIG..."
        m = re.search(r"Program received signal (\S+),", gdb_output)
        if m:
            return {"kind": "signal", "signal": m.group(1)}

        # Parse "exited with code N" or "exited normally"
        if "exited" in gdb_output:
            m = re.search(r"exited with code (\d+)", gdb_output)
            if m:
                return {"kind": "exited", "code": int(m.group(1))}
            if "exited normally" in gdb_output:
                return {"kind": "exited", "code": 0}

        return self._derive_from_hit_counts(hit_counts)

    def _derive_from_hit_counts(
        self, hit_counts: dict[int, int]
    ) -> dict[str, Any] | None:
        """Fallback: check if any breakpoint's hit count changed."""
        for bp in (gdb.breakpoints() or []):
            old = hit_counts.get(bp.number, 0)
            if bp.hit_count > old:
                return self._bp_reason(bp)
        return None

    def _stop_info(self) -> dict[str, Any]:
        """Capture current stop state, enriched with event-based stop reason."""
        result = _stop_info()
        if self._last_stop_reason:
            result["reason"] = self._last_stop_reason
            self._last_stop_reason = None
        return result

    def _write_registry(self):
        payload = {
            "pid": os.getpid(),
            "socket_path": str(self.socket_path),
            "plugin_name": PLUGIN_NAME,
            "plugin_version": VERSION,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:
        op = payload.get("op")
        params = payload.get("params") or {}
        try:
            # Lock-free ops: these must work even when the write lock is held
            # by a running background exec.
            if op == "interrupt":
                return self._dispatch_interrupt()
            if op == "status":
                return self._dispatch_status()
            if op == "wait":
                return self._dispatch_wait(params)

            if op == "trace":
                return self._dispatch_trace(params)

            if op in EXEC_OPS:
                return self._dispatch_exec(op, params)

            gdb_timeout = params.pop("_timeout", None) or 120.0
            lock = contextlib.nullcontext()
            if op in WRITE_LOCKED_OPS:
                lock = self._lock.write()
            elif op in READ_LOCKED_OPS:
                lock = self._lock.read()
            with lock:
                result = _run_on_gdb_thread(
                    lambda: self._dispatch_op(op, params),
                    timeout=gdb_timeout,
                )
            return _json_response(ok=True, result=result)
        except Exception as exc:
            return _json_response(ok=False, error=self._augment_error(exc))

    def _augment_error(self, exc: Exception) -> str:
        """Turn a raw GDB/Python error into an agent-actionable message.

        Matches GDB's exact, stable error strings (anchored, not arbitrary
        substrings — so a custom message that merely contains "no registers"
        isn't mis-hinted) and gates state-dependent hints on the actual
        inferior state, so the next step is accurate whether the inferior is
        running, never-started, or exited.
        """
        base = f"{type(exc).__name__}: {exc}"
        low = str(exc).strip().lower()

        def _state_hint() -> str:
            if self._running:
                return "the inferior is running — `pry interrupt` (or `pry wait`) first"
            if not self._inferior_is_live():
                return "the inferior is not running — use `pry run` or `pry continue`"
            return "no frame is selected — `pry frame select 0`"

        hint = None
        # These are GDB's exact messages when nothing is stopped at a frame.
        if low in (
            "no registers.",
            "no stack.",
            "no frame is currently selected.",
            "the program is not being run.",
            "the program has no registers now.",
        ):
            hint = _state_hint()
        elif "selected thread is running" in low:
            hint = "the inferior is running — `pry interrupt` (or `pry wait`) first"
        elif re.match(r'^no symbol ".*" in current context\.$', low):
            hint = (
                "symbol not in scope — check spelling; it may be a function "
                "(`pry functions --query NAME`), a global (`pry symbols "
                "--query NAME`), or live in another frame (`pry frame select N`)"
            )
        elif low.startswith("cannot access memory at address"):
            hint = "address not mapped — check `pry mappings` for valid ranges"
        if hint:
            return f"{base} ({hint})"
        return base

    def _dispatch_interrupt(self) -> dict[str, Any]:
        """Interrupt the inferior without acquiring any lock.

        This must work even when ``_dispatch_exec`` holds the write lock,
        since the primary use case is interrupting a running continue.
        """
        if not self._running:
            # Don't lie about interrupting a stopped/exited inferior. Report
            # the observed state so callers can react instead of assuming a
            # running program was stopped.
            return _json_response(
                ok=True, result={"interrupted": False, "state": "stopped"}
            )

        event = threading.Event()
        holder: dict[str, Any] = {}

        def _do_interrupt():
            try:
                gdb.execute("interrupt", to_string=True)
                holder["ok"] = True
            except Exception as exc:
                holder["error"] = str(exc)
            event.set()

        gdb.post_event(_do_interrupt)
        if not event.wait(timeout=10.0):
            return _json_response(
                ok=False, error="Timed out posting interrupt to GDB"
            )
        if "error" in holder:
            return _json_response(ok=False, error=holder["error"])

        # The "interrupt" command only *requests* a stop; the SIGINT is
        # delivered and the stop event fires shortly after. Wait briefly for
        # the stop handler to clear _running so an immediately-following
        # `status` reflects "stopped" rather than a transient "running".
        deadline = time.monotonic() + 2.0
        while self._running and time.monotonic() < deadline:
            time.sleep(0.01)
        return _json_response(
            ok=True, result={"interrupted": True, "stopped": not self._running}
        )

    def _dispatch_status(self) -> dict[str, Any]:
        """Return the inferior's current execution state (lock-free)."""
        result: dict[str, Any] = {}
        if self._running:
            result["state"] = "running"
        else:
            info = _stop_info()
            try:
                inf_pid = gdb.selected_inferior().pid
            except Exception:
                inf_pid = 0
            if not inf_pid:
                # pid 0 means either the inferior never started OR it has
                # exited — both leave no thread. _has_run distinguishes them
                # so a freshly-loaded program isn't reported as "exited".
                result["state"] = "exited" if self._has_run else "not-started"
            elif info.get("status") == "exited":
                result["state"] = "exited"
            else:
                result["state"] = "stopped"
            result.update(info)
            if self._last_stop_reason:
                result["reason"] = self._last_stop_reason
            if result["state"] == "exited":
                # The process is gone; surface the exit code so agents can read
                # it after the fact (None when it exited via a signal).
                result["reason"] = {"kind": "exited", "code": self._last_exit_code}
                if self._last_exit_code is not None:
                    result["exit_code"] = self._last_exit_code
            if self._displays and result["state"] == "stopped":
                result["displays"] = self._eval_displays()
        if self._background_result is not None:
            result["last_background_result"] = self._background_result
        return _json_response(ok=True, result=result)

    def _dispatch_wait(self, params: dict[str, Any]) -> dict[str, Any]:
        """Block until the inferior stops after a background exec (lock-free)."""
        wait_timeout: float = params.pop("_timeout", 120.0)
        completion = self._background_completion
        if completion is None:
            if self._running:
                return _json_response(
                    ok=False,
                    error="Inferior is running but not from a background exec",
                )
            result = _stop_info()
            result["state"] = "stopped"
            if self._last_stop_reason:
                result["reason"] = self._last_stop_reason
            return _json_response(ok=True, result=result)

        if not completion.wait(timeout=wait_timeout):
            return _json_response(
                ok=False,
                error=f"Timed out after {wait_timeout:.0f}s waiting for inferior to stop",
            )

        result = self._background_result or _stop_info()
        result["state"] = "stopped"
        self._background_result = None
        return _json_response(ok=True, result=result)

    def _background_monitor(
        self,
        completion: threading.Event,
        result_box: list[dict[str, Any]],
        error_box: list[Exception],
        on_stop,
        on_exited,
    ):
        """Wait for a background exec to complete and clean up."""
        completion.wait()  # wait indefinitely
        with contextlib.suppress(Exception):
            gdb.events.stop.disconnect(on_stop)
        if hasattr(gdb.events, "exited"):
            with contextlib.suppress(Exception):
                gdb.events.exited.disconnect(on_exited)
        if result_box:
            self._background_result = result_box[0]
        elif error_box:
            self._background_result = {"error": str(error_box[0])}
        self._background_completion = None
        self._running = False

    def _dispatch_exec(self, op: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dispatch an execution command and wait for the stop/exited event.

        Unlike normal dispatch which waits for the gdb.post_event callback
        to return, this waits for GDB's stop or exited event to fire — which
        happens AFTER the callback returns and GDB processes the stop.
        """
        exec_timeout: float = params.pop("_timeout", 120.0)
        background: bool = params.pop("_background", False)

        if self._running:
            raise RuntimeError(
                "Inferior is already running (from a background exec). "
                "Use 'pry wait' to wait for it to stop, "
                "or 'pry interrupt' to interrupt it."
            )

        # The inferior is about to run; mark it so `status` can tell a later
        # pid-0 state apart as "exited" rather than "not-started". Clear any
        # prior exit code so a new run doesn't report a stale one.
        self._has_run = True
        self._last_exit_code = None

        completion = threading.Event()
        result_box: list[dict[str, Any]] = []
        error_box: list[Exception] = []

        def _on_exec_stop(event):
            result = _stop_info()
            reason: dict[str, Any] = {}
            if hasattr(gdb, "BreakpointEvent") and isinstance(event, gdb.BreakpointEvent):
                bps = event.breakpoints
                if bps:
                    reason = self._bp_reason(bps[0])
            elif hasattr(gdb, "SignalEvent") and isinstance(event, gdb.SignalEvent):
                reason = {"kind": "signal", "signal": event.stop_signal}
            if reason:
                result["reason"] = reason
            # For `finish`, recover the function's return value now that the
            # inferior is genuinely stopped (reading registers mid-run fails).
            if op == "finish":
                rv = self._finish_return_value()
                if rv is not None:
                    result["return_value"] = rv
            if self._displays:
                result["displays"] = self._eval_displays()
            result_box.append(result)
            completion.set()

        def _on_exec_exited(event):
            result: dict[str, Any] = {"status": "exited", "frame": None, "thread": None}
            code = getattr(event, "exit_code", None)
            if code is not None:
                result["reason"] = {"kind": "exited", "code": code}
            result_box.append(result)
            completion.set()

        def _do_execute():
            try:
                # Snapshot watchpoint values before resuming so a watchpoint
                # hit during this run can report old -> new.
                self._snapshot_watchpoints()
                self._dispatch_op(op, params)
            except Exception as exc:
                error_box.append(exc)
                completion.set()

        if background:
            # Background mode: set up event handlers, post the command,
            # start a monitor thread, and return immediately.
            self._running = True
            self._background_completion = completion
            self._background_result = None
            gdb.events.stop.connect(_on_exec_stop)
            if hasattr(gdb.events, "exited"):
                gdb.events.exited.connect(_on_exec_exited)
            gdb.post_event(_do_execute)
            threading.Thread(
                target=self._background_monitor,
                args=(completion, result_box, error_box,
                      _on_exec_stop, _on_exec_exited),
                daemon=True,
            ).start()
            return _json_response(ok=True, result={"status": "running"})

        with self._lock.write():
            self._running = True
            gdb.events.stop.connect(_on_exec_stop)
            if hasattr(gdb.events, "exited"):
                gdb.events.exited.connect(_on_exec_exited)
            try:
                gdb.post_event(_do_execute)
                if not completion.wait(timeout=exec_timeout):
                    # Auto-interrupt the inferior and give it a short grace
                    # period to stop so we can return a usable response
                    # instead of leaving the bridge deadlocked.
                    gdb.post_event(
                        lambda: gdb.execute("interrupt", to_string=True)
                    )
                    if not completion.wait(timeout=5.0):
                        raise RuntimeError(
                            "Timed out waiting for inferior to stop, "
                            "and auto-interrupt did not succeed"
                        )
                    if result_box:
                        result_box[0]["timeout_interrupt"] = True
            finally:
                gdb.events.stop.disconnect(_on_exec_stop)
                if hasattr(gdb.events, "exited"):
                    gdb.events.exited.disconnect(_on_exec_exited)
                # Reset _running regardless of outcome: the global _on_stop /
                # _on_exited handlers only clear it when a stop/exit event
                # fires, so a command that fails before the inferior runs
                # (e.g. "continue" past exit) would otherwise leak True and
                # wedge the next exec with a spurious "already running".
                self._running = False

        if error_box:
            raise error_box[0]
        if not result_box:
            raise RuntimeError("Execution completed without stop or exit event")

        return _json_response(ok=True, result=result_box[0])

    @staticmethod
    def _parse_addr(addr) -> int:
        """Parse an address from int, hex string, or GDB expression.

        Always returns an unsigned 64-bit value: GDB renders a high-canonical
        address (e.g. a kernel-half pointer in $rax) as a *negative* Python int,
        which would never satisfy an unsigned `start <= addr < end` check.
        Function/array names that aren't convertible to a long are retried as
        ``&expr`` so a bare symbol resolves to its address.
        """
        mask = 0xFFFFFFFFFFFFFFFF
        if isinstance(addr, int):
            return addr & mask
        if isinstance(addr, str):
            addr = addr.strip().lstrip("*")
            try:
                return int(addr, 0) & mask
            except ValueError:
                val = gdb.parse_and_eval(addr)
                try:
                    return int(val) & mask
                except Exception:
                    return int(gdb.parse_and_eval(f"&({addr})")) & mask
        return int(addr) & mask

    def _dispatch_trace(self, params: dict[str, Any]) -> dict[str, Any]:
        """Trace memory accesses within a code range using hardware watchpoints.

        Sets up a hardware watchpoint (initially disabled) and boundary
        breakpoints.  The watchpoint is enabled when range_start is hit and
        disabled when range_end is reached.  Each watchpoint hit records the
        PC and instruction.  All automation runs inside GDB via
        ``Breakpoint.stop()`` callbacks at native speed.
        """
        watch_addr = self._parse_addr(params["watch_addr"])
        watch_size = int(params.get("watch_size", 4))
        range_start = self._parse_addr(params["range_start"])
        range_end = self._parse_addr(params["range_end"])
        watch_type = params.get("watch_type", "access")
        max_hits = int(params.get("max_hits", 10000))
        trace_timeout: float = params.pop("_timeout", 120.0)

        hits: list[dict[str, Any]] = []
        completion = threading.Event()
        result_box: list[dict[str, Any]] = []
        error_box: list[Exception] = []
        cleanup_bps: list[Any] = []

        # We build the custom Breakpoint subclasses inside a GDB-thread
        # callback so that gdb.Breakpoint() calls happen on the main thread.
        # A mutable holder lets the start-BP reference the watchpoint that
        # is created after it.
        wp_holder: list[Any] = []

        def _setup_and_continue():
            try:
                wp_class_map = {
                    "write": getattr(gdb, "WP_WRITE", 0),
                    "read": getattr(gdb, "WP_READ", 1),
                    "access": getattr(gdb, "WP_ACCESS", 2),
                }
                wp_class = wp_class_map.get(watch_type, wp_class_map["access"])
                watch_expr = f"*(char(*)[{watch_size}]){hex(watch_addr)}"

                class _RangeStartBP(gdb.Breakpoint):
                    def stop(self_bp):  # noqa: N805
                        if wp_holder:
                            wp_holder[0].enabled = True
                        return False  # auto-continue

                class _RangeEndBP(gdb.Breakpoint):
                    def stop(self_bp):  # noqa: N805
                        if wp_holder:
                            wp_holder[0].enabled = False
                        return True  # stop execution

                class _TraceWatchBP(gdb.Breakpoint):
                    def stop(self_bp):  # noqa: N805
                        if len(hits) >= max_hits:
                            return True  # stop, limit reached
                        try:
                            frame = gdb.selected_frame()
                            pc = hex(frame.pc())
                            arch = frame.architecture()
                            insns = arch.disassemble(frame.pc(), count=1)
                            asm = insns[0]["asm"] if insns else "<unknown>"
                        except Exception:
                            pc = "<unknown>"
                            asm = "<unknown>"
                        hits.append({"pc": pc, "asm": asm})
                        return False  # auto-continue

                start_bp = _RangeStartBP(f"*{hex(range_start)}")
                start_bp.silent = True
                cleanup_bps.append(start_bp)

                end_bp = _RangeEndBP(f"*{hex(range_end)}")
                end_bp.silent = True
                cleanup_bps.append(end_bp)

                trace_wp = _TraceWatchBP(
                    watch_expr,
                    type=gdb.BP_WATCHPOINT,
                    wp_class=wp_class,
                )
                trace_wp.silent = True
                trace_wp.enabled = False
                cleanup_bps.append(trace_wp)
                wp_holder.append(trace_wp)

                gdb.execute("continue", to_string=True)
            except Exception as exc:
                error_box.append(exc)
                completion.set()

        def _on_trace_stop(event):
            result = _stop_info()
            reason: dict[str, Any] = {}
            if hasattr(gdb, "BreakpointEvent") and isinstance(event, gdb.BreakpointEvent):
                bps = event.breakpoints
                if bps:
                    reason = self._bp_reason(bps[0])
            elif hasattr(gdb, "SignalEvent") and isinstance(event, gdb.SignalEvent):
                reason = {"kind": "signal", "signal": event.stop_signal}
            if reason:
                result["reason"] = reason
            result_box.append(result)
            completion.set()

        def _on_trace_exited(event):
            result: dict[str, Any] = {"status": "exited", "frame": None, "thread": None}
            code = getattr(event, "exit_code", None)
            if code is not None:
                result["reason"] = {"kind": "exited", "code": code}
            result_box.append(result)
            completion.set()

        with self._lock.write():
            gdb.events.stop.connect(_on_trace_stop)
            if hasattr(gdb.events, "exited"):
                gdb.events.exited.connect(_on_trace_exited)
            try:
                gdb.post_event(_setup_and_continue)
                if not completion.wait(timeout=trace_timeout):
                    gdb.post_event(
                        lambda: gdb.execute("interrupt", to_string=True)
                    )
                    completion.wait(timeout=5.0)
            finally:
                gdb.events.stop.disconnect(_on_trace_stop)
                if hasattr(gdb.events, "exited"):
                    gdb.events.exited.disconnect(_on_trace_exited)
                # Clean up internal breakpoints.
                def _cleanup():
                    for bp in cleanup_bps:
                        with contextlib.suppress(Exception):
                            bp.delete()
                gdb.post_event(_cleanup)

        if error_box:
            raise error_box[0]

        trace_result: dict[str, Any] = {
            "hits": hits,
            "hit_count": len(hits),
            "truncated": len(hits) >= max_hits,
            "watch_addr": hex(watch_addr),
            "watch_size": watch_size,
            "range_start": hex(range_start),
            "range_end": hex(range_end),
        }
        if result_box:
            trace_result["stop_info"] = result_box[0]

        return _json_response(ok=True, result=trace_result)

    # ------------------------------------------------------------------
    # Op dispatch
    # ------------------------------------------------------------------

    def _dispatch_op(self, op: str, params: dict[str, Any]) -> Any:
        # `--thread N` on an inspection command: run it against that thread,
        # then restore the previously selected thread so the choice is a
        # side-effect-free, per-command override (unlike `thread_select`).
        tid = params.pop("thread", None)
        if tid is None:
            return self._run_op(op, params)
        prev = None
        try:
            prev = gdb.selected_thread()
        except Exception:
            prev = None
        gdb.execute(f"thread {int(tid)}", to_string=True)
        try:
            return self._run_op(op, params)
        finally:
            if prev is not None:
                with contextlib.suppress(Exception):
                    prev.switch()

    def _run_op(self, op: str, params: dict[str, Any]) -> Any:
        if op == "doctor":
            return self._doctor()
        if op == "list_inferiors":
            return self._list_inferiors()
        if op == "list_threads":
            return self._list_threads(params)

        # Session
        if op == "load":
            return self._load(params)
        if op == "attach":
            return self._attach(params)
        if op == "connect":
            return self._connect(params)
        if op == "disconnect":
            return self._disconnect(params)
        if op == "target_info":
            return self._target_info(params)

        # Execution
        if op == "run":
            return self._run(params)
        if op == "continue":
            return self._continue(params)
        if op == "step":
            return self._step(params)
        if op == "next":
            return self._next(params)
        if op == "stepi":
            return self._stepi(params)
        if op == "nexti":
            return self._nexti(params)
        if op == "finish":
            return self._finish(params)
        if op == "until":
            return self._until(params)
        if op == "jump":
            return self._jump(params)
        if op == "interrupt":
            return self._interrupt(params)

        # Breakpoints
        if op == "break_set":
            return self._break_set(params)
        if op == "break_list":
            return self._break_list(params)
        if op == "break_delete":
            return self._break_delete(params)
        if op == "break_enable":
            return self._break_enable(params)
        if op == "break_disable":
            return self._break_disable(params)
        if op == "watch_set":
            return self._watch_set(params)

        # Threads
        if op == "thread_select":
            return self._thread_select(params)

        # Inspection
        if op == "backtrace":
            return self._backtrace(params)
        if op == "frame_info":
            return self._frame_info(params)
        if op == "frame_select":
            return self._frame_select(params)
        if op == "frame_up":
            return self._frame_up(params)
        if op == "frame_down":
            return self._frame_down(params)
        if op == "locals":
            return self._locals(params)
        if op == "args":
            return self._args(params)
        if op == "print":
            return self._print(params)
        if op == "call":
            return self._call(params)
        if op == "registers":
            return self._registers(params)
        if op == "register_write":
            return self._register_write(params)
        if op == "mappings":
            return self._mappings(params)
        if op == "memory_read":
            return self._memory_read(params)
        if op == "memory_write":
            return self._memory_write(params)
        if op == "disasm":
            return self._disasm(params)
        if op == "examine":
            return self._examine(params)

        # Auto-display
        if op == "display_add":
            return self._display_add(params)
        if op == "display_list":
            return self._display_list(params)
        if op == "display_remove":
            return self._display_remove(params)
        if op == "functions":
            return self._functions(params)
        if op == "symbols":
            return self._symbols(params)
        if op == "types_show":
            return self._types_show(params)
        if op == "info_files":
            return self._info_files(params)
        if op == "source_list":
            return self._source_list(params)

        # Python
        if op == "py_exec":
            return self._py_exec(params)

        # Raw GDB command passthrough
        if op == "gdb_exec":
            return self._gdb_exec(params)

        raise ValueError(f"Unknown op: {op!r}")

    # ------------------------------------------------------------------
    # Doctor
    # ------------------------------------------------------------------

    def _doctor(self) -> dict[str, Any]:
        return {
            "plugin_version": VERSION,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "pid": os.getpid(),
            "socket_path": str(self.socket_path),
            "gdb_version": gdb.VERSION,
            "inferiors": [self._inferior_dict(inf) for inf in gdb.inferiors()],
        }

    # ------------------------------------------------------------------
    # Inferiors
    # ------------------------------------------------------------------

    def _inferior_dict(self, inf) -> dict[str, Any]:
        result: dict[str, Any] = {
            "num": inf.num,
            "pid": inf.pid,
        }
        try:
            result["executable"] = inf.progspace.filename
        except Exception:
            result["executable"] = None
        try:
            result["selected"] = inf == gdb.selected_inferior()
        except Exception:
            result["selected"] = False
        return result

    def _list_inferiors(self) -> list[dict[str, Any]]:
        return [self._inferior_dict(inf) for inf in gdb.inferiors()]

    def _thread_dict(self, thread, *, selected_thread) -> dict[str, Any]:
        result: dict[str, Any] = {
            "num": getattr(thread, "num", None),
            "global_num": getattr(thread, "global_num", None),
            "name": getattr(thread, "name", None),
            "ptid": list(getattr(thread, "ptid", ())) if getattr(thread, "ptid", None) else None,
            "selected": thread == selected_thread,
        }
        try:
            result["inferior_num"] = thread.inferior.num
        except Exception:
            result["inferior_num"] = None
        try:
            result["status"] = (
                "exited" if thread.is_exited()
                else "running" if thread.is_running()
                else "stopped" if thread.is_stopped()
                else "unknown"
            )
        except Exception:
            result["status"] = "unknown"

        frame = None
        try:
            thread.switch()
            frame = gdb.selected_frame()
        except Exception:
            frame = None
        result["frame"] = _frame_to_dict(frame) if frame is not None else None
        return result

    def _list_threads(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        pc_filter = params.get("pc")
        function_filter = params.get("function")
        selected_thread = None
        try:
            selected_thread = gdb.selected_thread()
        except Exception:
            pass

        threads: list[dict[str, Any]] = []
        for inf in gdb.inferiors():
            try:
                inf_threads = inf.threads()
            except Exception:
                continue
            for thread in inf_threads:
                entry = self._thread_dict(thread, selected_thread=selected_thread)
                frame = entry.get("frame") if isinstance(entry.get("frame"), dict) else {}
                if pc_filter is not None and frame.get("address") != pc_filter:
                    continue
                if function_filter:
                    func = str(frame.get("function") or "")
                    if function_filter not in func:
                        continue
                threads.append(entry)

        if selected_thread is not None:
            try:
                selected_thread.switch()
            except Exception:
                pass
        return threads

    def _thread_select(self, params: dict[str, Any]) -> dict[str, Any]:
        """Make a thread the persistently selected one (GDB's `thread N`)."""
        num = int(params["num"])
        gdb.execute(f"thread {num}", to_string=True)
        selected = None
        try:
            selected = gdb.selected_thread()
        except Exception:
            selected = None
        if selected is None:
            return {"selected": num}
        return self._thread_dict(selected, selected_thread=selected)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    @staticmethod
    def _file_is_loaded(path: str) -> bool:
        """True if *path* is currently an objfile (primary or added)."""
        try:
            rp = os.path.realpath(path)
            for o in gdb.objfiles():
                fn = o.filename
                if fn and (fn == path or os.path.realpath(fn) == rp):
                    return True
        except Exception:
            pass
        return False

    def _load(self, params: dict[str, Any]) -> dict[str, Any]:
        path = params["path"]
        base = params.get("base")
        slide = params.get("slide")
        if base is None and slide is None:
            gdb.execute(f"file {path}", to_string=True)
            return {"loaded": path}
        if base is not None and slide is not None:
            raise ValueError("pass either --base or --slide, not both")
        # Load symbols at a runtime base (relocated/PIE/KASLR module). Two
        # traps this avoids: (1) GDB doesn't auto-relocate symbols for a remote
        # kernel stub, and pwndbg's `kbase -r` *adds* a copy without removing
        # the link-time one, so name->address resolves to the stale (unmapped)
        # copy; (2) `add-symbol-file FILE ADDR` only relocates .text, leaving
        # data symbols (jiffies, init_task, ...) at link addresses. So: drop any
        # prior copy, then add the file with ALL sections offset by a uniform
        # slide, giving exactly one table where both text AND data resolve.
        if slide is not None:
            slide_int = self._parse_addr(slide)
        else:
            text_vaddr = _elf_text_vaddr(path)
            if text_vaddr is None:
                raise ValueError(
                    f"could not read the .text address from {path} to compute "
                    "the relocation slide; pass --slide <offset> explicitly"
                )
            slide_int = self._parse_addr(base) - text_vaddr
        # Drop any existing copy so the relocated table is authoritative.
        # remove-symbol-file only removes add-symbol-file'd copies and fails
        # (raises or prints "No symbol file found") on the *primary* objfile
        # (a `file`/`pry load`/`pry launch <bin>` exec). If the file is STILL
        # loaded after the remove attempt, it's the primary — discard it via
        # `symbol-file` so the relocated table isn't shadowed by the stale
        # link-time one winning name->address.
        with contextlib.suppress(gdb.error):
            gdb.execute(f"remove-symbol-file {path}", to_string=True)
        if self._file_is_loaded(path):
            with contextlib.suppress(gdb.error):
                gdb.execute("symbol-file", to_string=True)  # discard primary symbols
        offset = f"-0x{-slide_int:x}" if slide_int < 0 else hex(slide_int)
        gdb.execute(f"add-symbol-file {path} -o {offset}", to_string=True)
        result: dict[str, Any] = {"loaded": path, "slide": hex(slide_int)}
        if base is not None:
            result["base"] = hex(self._parse_addr(base))
        return result

    def _attach(self, params: dict[str, Any]) -> dict[str, Any]:
        pid = int(params["pid"])
        self._last_stop_reason = None
        gdb.execute(f"attach {pid}", to_string=True)
        info = self._stop_info()
        info["attached"] = pid
        return info

    def _connect(self, params: dict[str, Any]) -> dict[str, Any]:
        target = params["target"]
        timeout = int(params.get("connect_timeout", 15))
        self._last_stop_reason = None
        gdb.execute(f"set tcp connect-timeout {timeout}", to_string=True)
        gdb.execute(f"target remote {target}", to_string=True)
        info = self._stop_info()
        info["connected"] = target
        return info

    def _disconnect(self, params: dict[str, Any]) -> dict[str, Any]:
        gdb.execute("disconnect", to_string=True)
        return {"disconnected": True}

    def _target_info(self, params: dict[str, Any]) -> dict[str, Any]:
        raw = gdb.execute("info target", to_string=True)
        connections = ""
        try:
            connections = gdb.execute("info connections", to_string=True)
        except Exception:
            pass
        return {"raw": raw, "connections": connections}

    # ------------------------------------------------------------------
    # Execution control
    # ------------------------------------------------------------------

    def _run(self, params: dict[str, Any]) -> dict[str, Any]:
        args = params.get("args")
        if args:
            if isinstance(args, list):
                arg_str = " ".join(str(a) for a in args)
            else:
                arg_str = str(args)
            gdb.execute(f"set args {arg_str}", to_string=True)
        return self._exec_and_stop("run")

    def _continue(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._exec_and_stop("continue")

    def _step(self, params: dict[str, Any]) -> dict[str, Any]:
        count = params.get("count")
        return self._exec_and_stop(f"step {count}" if count else "step")

    def _next(self, params: dict[str, Any]) -> dict[str, Any]:
        count = params.get("count")
        return self._exec_and_stop(f"next {count}" if count else "next")

    def _stepi(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._exec_and_stop("stepi")

    def _nexti(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._exec_and_stop("nexti")

    # Type codes whose return value lives in the integer ABI register and can
    # be cast straight from it (the common, useful cases).
    def _int_return_type_codes(self):
        codes = []
        for attr in ("TYPE_CODE_INT", "TYPE_CODE_PTR", "TYPE_CODE_ENUM",
                     "TYPE_CODE_BOOL", "TYPE_CODE_CHAR"):
            val = getattr(gdb, attr, None)
            if val is not None:
                codes.append(val)
        return tuple(codes)

    def _finish(self, params: dict[str, Any]) -> Any:
        # Record the finishing frame and its return type so the stop handler
        # can recover the return value (GDB's "Value returned is $N" text is
        # swallowed by to_string under some pretty-printers, and registers
        # can't be read until the inferior actually stops).
        self._finish_frame = None
        self._finish_ret_type = None
        try:
            frame = gdb.selected_frame()
            self._finish_frame = frame
            func = frame.function()
            if func is not None:
                self._finish_ret_type = func.type.target()
        except Exception:
            self._finish_frame = None
            self._finish_ret_type = None
        return self._exec_and_stop("finish")

    def _finish_return_value(self) -> str | None:
        """Recover the value the just-finished function returned.

        Called from the exec stop handler, where the inferior is stopped. Reads
        the integer ABI return register and casts it to the captured return
        type. Best-effort and x86-64-only for now; returns None for void,
        non-integer (float/struct) returns, unknown types, or other arches, or
        if the frame did not actually return (e.g. we stopped at an intervening
        breakpoint), so a bogus value is never reported.
        """
        frame = self._finish_frame
        ret_type = self._finish_ret_type
        self._finish_frame = None
        self._finish_ret_type = None
        if frame is None or ret_type is None:
            return None
        try:
            # If the finishing frame is still valid, it didn't actually return
            # (we stopped earlier) — don't fabricate a return value.
            if frame.is_valid():
                return None
        except Exception:
            return None
        try:
            stripped = ret_type.strip_typedefs()
            if stripped.code == getattr(gdb, "TYPE_CODE_VOID", object()):
                return None
            if stripped.code not in self._int_return_type_codes():
                return None  # float/struct returns need ABI-specific handling
            arch = gdb.selected_frame().architecture().name() or ""
            if "x86-64" not in arch:
                return None  # integer return register is arch-specific
            val = gdb.parse_and_eval("$rax").cast(ret_type)
            return str(val)
        except Exception:
            return None

    def _until(self, params: dict[str, Any]) -> dict[str, Any]:
        location = params["location"]
        return self._exec_and_stop(f"until {location}")

    def _jump(self, params: dict[str, Any]) -> dict[str, Any]:
        # Resume execution at *location* (GDB's `jump`), unlike a raw $pc write:
        # GDB sets up a proper transfer so the program keeps running from there.
        location = params["location"]
        return self._exec_and_stop(f"jump {location}")

    def _interrupt(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._exec_and_stop("interrupt")

    # ------------------------------------------------------------------
    # Breakpoints
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_module_base(module_name: str) -> int:
        """Find the runtime load base of a module via process mappings."""
        import re as _re

        # Try info proc mappings first (most reliable for local targets). The
        # lowest-addressed mapping for the module is its load base; the parser
        # preserves /proc ordering so the first match is the lowest.
        for mapping in GdbBridge._parse_proc_mappings():
            if module_name in (mapping.get("objfile") or ""):
                return int(mapping["start"], 16)

        # Fallback: search loaded objfiles.
        for objfile in gdb.objfiles():
            fname = objfile.filename or ""
            if module_name in fname:
                # Use the lowest section address as the load base.
                try:
                    out = gdb.execute(
                        f"info files", to_string=True
                    )
                    for fline in out.splitlines():
                        m = _re.match(
                            r"\s*(0x[0-9a-fA-F]+)\s*-\s*0x[0-9a-fA-F]+\s+is\s+\.text\s+in\s+",
                            fline,
                        )
                        if m and module_name in fline:
                            return int(m.group(1), 16)
                except gdb.error:
                    pass

        # No mappings means the inferior isn't running yet: PIE images don't
        # have a runtime base until after exec(). Tell the caller how to get
        # one instead of just blaming the module name.
        try:
            has_mappings = bool(gdb.execute("info proc mappings", to_string=True).strip())
        except gdb.error:
            has_mappings = False
        if not has_mappings:
            raise ValueError(
                f"Module {module_name!r} not found: the inferior has no memory "
                "mappings yet (PIE addresses aren't known until the program "
                "has exec'd). Set a breakpoint at main and run the program "
                "first, then retry --rebase."
            )
        raise ValueError(f"Module {module_name!r} not found in process mappings")

    def _break_set(self, params: dict[str, Any]) -> dict[str, Any]:
        location = params["location"]
        temporary = params.get("temporary", False)
        hardware = params.get("hardware", False)
        rebase_module = params.get("rebase_module")
        image_base = int(params.get("image_base", 0))

        rebased_meta: dict[str, Any] | None = None
        if rebase_module:
            offset_str = location.lstrip("*").strip()
            offset = int(offset_str, 0)
            module_base = self._resolve_module_base(rebase_module)
            runtime_addr = offset - image_base + module_base
            location = f"*{hex(runtime_addr)}"
            rebased_meta = {
                "module": rebase_module,
                "offset": hex(offset),
                "image_base": hex(image_base),
                "module_base": hex(module_base),
                "resolved": hex(runtime_addr),
            }
        else:
            # A bare hex string ("0x401f0e") is what most users mean when
            # they ask to break "at this address". GDB's command-line
            # syntax for a raw-address breakpoint is "*0x401f0e" — without
            # the asterisk, the bare hex is interpreted as a source line
            # number and the breakpoint silently goes pending. Auto-prefix
            # so the obvious form works.
            if _looks_like_bare_hex_address(location):
                location = f"*{location}"

        bp_type = gdb.BP_BREAKPOINT
        if hardware:
            bp_type = gdb.BP_HARDWARE_BREAKPOINT

        bp = gdb.Breakpoint(location, type=bp_type, temporary=temporary)

        condition = params.get("condition")
        if condition:
            bp.condition = condition

        result = _breakpoint_to_dict(bp)
        if rebased_meta:
            result["rebased"] = rebased_meta
        return result

    def _break_list(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        bps = gdb.breakpoints() or []
        result = [_breakpoint_to_dict(bp) for bp in bps]
        # The Python API exposes no detail for catchpoints (location/expression
        # are None), so a `catch syscall write` is indistinguishable from any
        # other catchpoint. Recover the "what" column from `info breakpoints`.
        if any(b.get("kind") == "catchpoint" for b in result):
            whats = self._catchpoint_whats()
            for b in result:
                if b.get("kind") == "catchpoint" and b["number"] in whats:
                    b["what"] = whats[b["number"]]
        return result

    @staticmethod
    def _catchpoint_whats() -> dict[int, str]:
        """Map catchpoint number -> its 'what' text from `info breakpoints`."""
        whats: dict[int, str] = {}
        try:
            out = gdb.execute("info breakpoints", to_string=True)
        except gdb.error:
            return whats
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+catchpoint\s+keep\s+[yn]\s+(.+?)\s*$", line)
            if m:
                whats[int(m.group(1))] = m.group(2).strip()
        return whats

    def _break_delete(self, params: dict[str, Any]) -> dict[str, Any]:
        # Batch form: {"numbers": [...]}. Single form {"number": N} is kept for
        # backward compatibility and returns the flat {"deleted": N} shape.
        if "numbers" in params:
            numbers = [int(n) for n in params["numbers"]]
        else:
            numbers = [int(params["number"])]

        by_number = {bp.number: bp for bp in (gdb.breakpoints() or [])}
        missing = [n for n in numbers if n not in by_number]
        if missing:
            raise ValueError(
                "No breakpoint " + ", ".join(f"#{n}" for n in missing)
            )

        items = []
        for n in numbers:
            bp = by_number[n]
            # Capture the kind before deleting so the response can name a
            # watchpoint a "watchpoint" (break/watch share a number space).
            kind = _bp_kind(bp.type)
            bp.delete()
            self._watchpoint_values.pop(n, None)
            items.append({"number": n, "kind": kind})

        if "numbers" not in params:
            return {"deleted": items[0]["number"], "kind": items[0]["kind"]}
        return {"deleted": [it["number"] for it in items], "items": items}

    def _break_enable(self, params: dict[str, Any]) -> dict[str, Any]:
        number = int(params["number"])
        for bp in (gdb.breakpoints() or []):
            if bp.number == number:
                bp.enabled = True
                return _breakpoint_to_dict(bp)
        raise ValueError(f"No breakpoint #{number}")

    def _break_disable(self, params: dict[str, Any]) -> dict[str, Any]:
        number = int(params["number"])
        for bp in (gdb.breakpoints() or []):
            if bp.number == number:
                bp.enabled = False
                return _breakpoint_to_dict(bp)
        raise ValueError(f"No breakpoint #{number}")

    def _watch_set(self, params: dict[str, Any]) -> dict[str, Any]:
        expression = params["expression"]
        watch_type = params.get("watch_type", "write")
        if watch_type == "read":
            wp_type = gdb.WP_READ
        elif watch_type == "access":
            wp_type = gdb.WP_ACCESS
        else:
            wp_type = gdb.WP_WRITE
        bp = gdb.Breakpoint(expression, type=gdb.BP_WATCHPOINT, wp_class=wp_type)
        # Seed the value cache so the first hit can report old -> new.
        initial = self._safe_eval_str(expression)
        if initial is not None:
            self._watchpoint_values[bp.number] = initial
        return _breakpoint_to_dict(bp)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def _backtrace(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        full = params.get("full", False)
        limit = params.get("limit")
        frames = []
        # gdb.newest_frame() raises gdb.error "No stack." when nothing is
        # running. Let it propagate so dispatch() attaches an actionable hint,
        # rather than returning [] (which an agent reads as "empty stack").
        frame = gdb.newest_frame()
        level = 0
        while frame is not None:
            if limit is not None and level >= limit:
                break
            entry = _frame_to_dict(frame)
            entry["level"] = level

            if full:
                try:
                    block = frame.block()
                    local_vars = []
                    while block is not None:
                        for sym in block:
                            if sym.is_variable or sym.is_argument:
                                try:
                                    val = str(frame.read_var(sym))
                                except Exception:
                                    val = "<unavailable>"
                                local_vars.append({
                                    "name": sym.name,
                                    "value": val,
                                    "is_argument": sym.is_argument,
                                })
                        if block.function is not None:
                            break
                        block = block.superblock
                    entry["locals"] = local_vars
                except Exception:
                    entry["locals"] = []

            # Collect argument values for the frame
            try:
                block = frame.block()
                arg_list = []
                while block is not None:
                    for sym in block:
                        if sym.is_argument:
                            try:
                                val = str(frame.read_var(sym))
                            except Exception:
                                val = "<unavailable>"
                            arg_list.append({"name": sym.name, "value": val})
                    if block.function is not None:
                        break
                    block = block.superblock
                entry["args"] = arg_list
            except Exception:
                entry["args"] = []

            frames.append(entry)
            try:
                frame = frame.older()
            except gdb.error:
                break
            level += 1
        return frames

    def _frame_info(self, params: dict[str, Any]) -> dict[str, Any]:
        frame = gdb.selected_frame()
        result = _frame_to_dict(frame)
        # Find the level by walking from newest
        level = 0
        try:
            f = gdb.newest_frame()
            while f is not None and f != frame:
                f = f.older()
                level += 1
        except gdb.error:
            pass
        result["level"] = level
        return result

    def _frame_select(self, params: dict[str, Any]) -> dict[str, Any]:
        level = int(params["level"])
        gdb.execute(f"frame {level}", to_string=True)
        return self._frame_info(params)

    def _frame_up(self, params: dict[str, Any]) -> dict[str, Any]:
        count = int(params.get("count", 1) or 1)
        gdb.execute(f"up {count}", to_string=True)
        return self._frame_info(params)

    def _frame_down(self, params: dict[str, Any]) -> dict[str, Any]:
        count = int(params.get("count", 1) or 1)
        gdb.execute(f"down {count}", to_string=True)
        return self._frame_info(params)

    def _locals(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        frame = gdb.selected_frame()
        result = []
        try:
            block = frame.block()
            while block is not None:
                for sym in block:
                    if sym.is_variable and not sym.is_argument:
                        try:
                            val = str(frame.read_var(sym))
                        except Exception:
                            val = "<unavailable>"
                        entry: dict[str, Any] = {
                            "name": sym.name,
                            "value": val,
                        }
                        try:
                            entry["type"] = str(sym.type)
                        except Exception:
                            pass
                        result.append(entry)
                if block.function is not None:
                    break
                block = block.superblock
        except Exception:
            pass
        return result

    def _args(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        frame = gdb.selected_frame()
        result = []
        try:
            block = frame.block()
            while block is not None:
                for sym in block:
                    if sym.is_argument:
                        try:
                            val = str(frame.read_var(sym))
                        except Exception:
                            val = "<unavailable>"
                        entry: dict[str, Any] = {
                            "name": sym.name,
                            "value": val,
                        }
                        try:
                            entry["type"] = str(sym.type)
                        except Exception:
                            pass
                        result.append(entry)
                if block.function is not None:
                    break
                block = block.superblock
        except Exception:
            pass
        return result

    @staticmethod
    def _inferior_is_live() -> bool:
        """True when an inferior process is actually running/stopped.

        ``pid`` is 0 both before the first run and after the inferior exits;
        in either case GDB resolves variable reads from the static binary
        image rather than live memory.
        """
        try:
            return bool(gdb.selected_inferior().pid)
        except Exception:
            return False

    def _print(self, params: dict[str, Any]) -> dict[str, Any]:
        expression = params["expression"]
        val = gdb.parse_and_eval(expression)
        result: dict[str, Any] = {"value": str(val)}
        try:
            result["type"] = str(val.type)
        except Exception:
            pass
        # Without a live inferior, a variable read comes from the static image
        # (e.g. a global's initializer), which can silently contradict the
        # value seen at the last stop. Flag it so the agent isn't misled.
        if not self._inferior_is_live():
            result["live"] = False
            result["note"] = (
                "no live inferior — value read from the static binary image, "
                "not live memory"
            )
        return result

    def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        # Call an inferior function and return its value. GDB's `call` is just
        # expression evaluation that invokes the function; reuse parse_and_eval
        # so string-literal args are auto-allocated in the target. A void
        # result surfaces as None rather than the literal "void".
        expression = params["expression"]
        val = gdb.parse_and_eval(expression)
        rendered = str(val)
        result: dict[str, Any] = {
            "value": None if rendered == "void" else rendered,
        }
        try:
            result["type"] = str(val.type)
        except Exception:
            pass
        return result

    def _registers(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        show_all = params.get("all", False)
        cmd = "info all-registers" if show_all else "info registers"
        output = gdb.execute(cmd, to_string=True)
        result = []
        for line in output.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                result.append({"name": parts[0], "value": " ".join(parts[1:])})
        return result

    def _register_write(self, params: dict[str, Any]) -> dict[str, Any]:
        name = str(params["name"]).lstrip("$")
        value = params["value"]
        # `set $name = ...` for an unknown name silently creates a GDB
        # convenience variable and writes no real register. Validate against
        # the live frame's register set so we don't report a misleading
        # success. read_register accepts aliases (pc/sp/fp) and sub-registers
        # (eax) and raises for unknown names.
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            # No frame: distinguish "running" (pid live) from "not started".
            if self._inferior_is_live():
                raise ValueError(
                    f"cannot write ${name}: the inferior is running — "
                    "`pry interrupt` (or `pry wait`) to stop it first"
                )
            raise ValueError(
                f"cannot write ${name}: the inferior is not running — "
                "use `pry run` or `pry continue` first"
            )
        try:
            frame.read_register(name)
        except (ValueError, gdb.error):
            raise ValueError(
                f"unknown register {name!r} — run `pry registers` "
                "(or `pry registers --all`) to see valid names"
            )
        try:
            gdb.execute(f"set ${name} = {value}", to_string=True)
        except gdb.error as exc:
            low = str(exc).lower()
            if "lvalue" in low:
                raise ValueError(
                    f"register {name!r} is a derived/read-only register and can't be "
                    f"assigned directly (e.g. write the underlying register like $rbp)"
                )
            if "cast" in low or "convert" in low:
                raise ValueError(
                    f"register {name!r} is a vector/typed register; set a typed sub-field "
                    f"via `pry gdb 'set ${name}.v2_int64[0] = ...'` instead of a scalar"
                )
            raise
        readback = self._safe_eval_str(f"${name}")
        result: dict[str, Any] = {"register": name, "value": str(value)}
        if readback is not None:
            result["readback"] = readback
        return result

    @staticmethod
    def _parse_proc_mappings() -> list[dict[str, Any]]:
        """Parse ``info proc mappings`` into structured entries.

        Returns [] when no process is mapped or the command is unavailable
        (e.g. some remote targets) — the caller decides how to surface that.
        """
        try:
            output = gdb.execute("info proc mappings", to_string=True)
        except gdb.error:
            return []
        maps: list[dict[str, Any]] = []
        for line in output.splitlines():
            parts = line.split()
            # Rows start with a hex Start Addr; the header and blank lines don't.
            if len(parts) < 4 or not parts[0].startswith("0x"):
                continue
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                size = int(parts[2], 16)
                offset = int(parts[3], 16)
            except ValueError:
                continue
            entry: dict[str, Any] = {
                "start": hex(start),
                "end": hex(end),
                "size": size,
                "offset": hex(offset),
            }
            rest = parts[4:]
            # Newer GDB includes a perms column (e.g. "r-xp"); older omits it.
            if rest and re.fullmatch(r"[rwxsp-]+", rest[0]):
                entry["perms"] = rest[0]
                rest = rest[1:]
            if rest:
                entry["objfile"] = " ".join(rest)
            maps.append(entry)
        return maps

    def _mappings(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        maps = self._parse_proc_mappings()
        contains = params.get("contains")
        name = params.get("name")
        if contains is not None:
            addr = self._parse_addr(contains)
            maps = [
                m for m in maps
                if int(m["start"], 16) <= addr < int(m["end"], 16)
            ]
        if name:
            maps = [m for m in maps if name in (m.get("objfile") or "")]
        return maps

    @staticmethod
    def _resolve_data_address(address) -> int:
        """Resolve a memory-read target to an address (unsigned).

        A literal (`0x...`/decimal) or a pointer/array expression is used as the
        address directly; any other lvalue (a global like `g`, a struct) uses
        its STORAGE address, so `memory read g` reads g's bytes instead of using
        g's *value* as the address (GDB's `x g` footgun).
        """
        mask = 0xFFFFFFFFFFFFFFFF
        if isinstance(address, int):
            return address & mask
        s = str(address).strip()
        try:
            return int(s, 0) & mask
        except ValueError:
            pass
        val = gdb.parse_and_eval(s)
        try:
            if val.type.strip_typedefs().code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                return int(val) & mask
        except Exception:
            pass
        try:
            if val.address is not None:
                return int(val.address) & mask
        except Exception:
            pass
        return int(val) & mask

    def _memory_read(self, params: dict[str, Any]) -> dict[str, Any]:
        address = params["address"]
        length = int(params["length"])
        fmt = params.get("format", "hex")

        addr_int = self._resolve_data_address(address)

        inf = gdb.selected_inferior()
        membuf = inf.read_memory(addr_int, length)
        data_bytes = bytes(membuf)

        result: dict[str, Any] = {"address": hex(addr_int), "length": length}
        if fmt == "string":
            result["format"] = "string"
            result["data"] = data_bytes.decode("utf-8", errors="replace")
        elif fmt == "bytes":
            result["format"] = "bytes"
            result["data"] = base64.b64encode(data_bytes).decode("ascii")
        else:
            result["format"] = "hex"
            result["data"] = data_bytes.hex()
        return result

    def _memory_write(self, params: dict[str, Any]) -> dict[str, Any]:
        address = params["address"]
        value = params["value"]

        if isinstance(address, str):
            addr_val = gdb.parse_and_eval(address)
            addr_int = int(addr_val)
        else:
            addr_int = int(address)

        data = bytes.fromhex(value)
        inf = gdb.selected_inferior()
        inf.write_memory(addr_int, data)
        return {"written": len(data), "address": hex(addr_int)}

    @staticmethod
    def _symbolize(addr_int: int) -> str | None:
        """Resolve an address to a compact ``func+off`` label, or None.

        Uses ``info symbol`` (works without a selected frame) and normalises
        GDB's "func + 4 in section .text" form to "func+4".
        """
        try:
            out = gdb.execute(f"info symbol {hex(addr_int)}", to_string=True).strip()
        except Exception:
            return None
        if not out or out.startswith("No symbol"):
            return None
        label = out.split(" in section", 1)[0].strip()
        return re.sub(r"\s*\+\s*", "+", label) or None

    def _disasm(self, params: dict[str, Any]) -> Any:
        location = params.get("location")
        count = params.get("count")
        start = params.get("start")
        end = params.get("end")
        source = params.get("source", False)

        # Source-interleaved disassembly: return GDB's raw text so the source
        # lines survive (the structured parser keeps only instruction lines).
        if source:
            if start is not None and end is not None:
                cmd = f"disassemble /s {start},{end}"
            else:
                cmd = f"disassemble /s {location or '$pc'}"
            return gdb.execute(cmd, to_string=True)

        # Explicit address range. GDB's `disassemble START,END` covers exactly
        # [START, END).
        if start is not None and end is not None:
            cmd = f"disassemble {start},{end}"
            return _parse_disassemble_output(gdb.execute(cmd, to_string=True))

        # Honor --count strictly: 0 or negative means "no instructions". Never
        # silently substitute the whole function (the old fallback did, so the
        # JSON shape/start address depended on the count value).
        if count is not None and count <= 0:
            return []
        n = count or 20

        # Default to $pc so --count is honored even without an explicit location.
        effective_location = location or "$pc"
        addr_int = _resolve_to_address(effective_location)

        if addr_int is not None:
            # Prefer the architecture API — it reports per-instruction length —
            # but it needs a live frame. Without one (static), x/Ni honors count.
            arch = None
            try:
                arch = gdb.selected_frame().architecture()
            except gdb.error:
                arch = None
            if arch is not None:
                try:
                    insns = arch.disassemble(addr_int, count=n)
                    result = []
                    for insn in insns:
                        entry = {
                            "address": hex(insn["addr"]),
                            "asm": insn["asm"],
                            "length": insn["length"],
                        }
                        symbol = self._symbolize(insn["addr"])
                        if symbol:
                            entry["symbol"] = symbol
                        result.append(entry)
                    return result
                except Exception:
                    # e.g. count runs off mapped memory — fall to x/Ni, which
                    # surfaces a clean error rather than a wrong whole-function.
                    pass
            out = gdb.execute(f"x/{n}i {hex(addr_int)}", to_string=True)
            return _parse_disassemble_output(out)

        # Unresolved location (range exprs like "main,+16"): GDB's disassemble
        # command. Parse to the same list shape (always a list, never a raw
        # string) so JSON output is structurally stable regardless of form.
        cmd = f"disassemble {location}" if location else "disassemble"
        return _parse_disassemble_output(gdb.execute(cmd, to_string=True))

    def _examine(self, params: dict[str, Any]) -> dict[str, Any]:
        """GDB-style memory examine (`x/NFU addr`).

        Accepts a raw GDB format spec (e.g. "8xw", "3i", "s") or individual
        count/format/size pieces. Returns the GDB text plus split lines — x/'s
        output (instructions, strings, multi-column words) has no single stable
        structure, so the raw text is the reliable artifact.
        """
        address = params["address"]
        spec = params.get("spec")
        if not spec:
            count = params.get("count")
            fmt = params.get("format", "")
            size = params.get("size", "")
            spec = f"{count if count is not None else ''}{fmt}{size}"
        spec = str(spec).strip()
        cmd = f"x/{spec} {address}" if spec else f"x {address}"
        out = gdb.execute(cmd, to_string=True)
        return {
            "command": cmd,
            "text": out,
            "lines": [ln for ln in out.splitlines() if ln.strip()],
        }

    # ------------------------------------------------------------------
    # Auto-display
    # ------------------------------------------------------------------

    def _display_add(self, params: dict[str, Any]) -> dict[str, Any]:
        expr = params["expression"]
        self._display_counter += 1
        entry = {"number": self._display_counter, "expr": expr}
        self._displays.append(entry)
        return dict(entry)

    def _display_list(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self._eval_displays()

    def _display_remove(self, params: dict[str, Any]) -> dict[str, Any]:
        number = int(params["number"])
        for i, d in enumerate(self._displays):
            if d["number"] == number:
                self._displays.pop(i)
                return {"removed": number}
        raise ValueError(f"No display #{number}")

    def _eval_displays(self) -> list[dict[str, Any]]:
        """Evaluate every registered display expression at the current stop."""
        out: list[dict[str, Any]] = []
        for d in self._displays:
            entry: dict[str, Any] = {"number": d["number"], "expr": d["expr"]}
            value = self._safe_eval_str(d["expr"])
            entry["value"] = value if value is not None else "<error>"
            out.append(entry)
        return out

    def _functions(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = params.get("query")
        offset = int(params.get("offset", 0))
        limit = params.get("limit")
        cmd = f"info functions {query}" if query else "info functions"
        output = gdb.execute(cmd, to_string=True)
        result = _parse_info_functions(output)
        if offset:
            result = result[offset:]
        if limit is not None:
            result = result[:int(limit)]
        return result

    def _symbols(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = params.get("query")
        offset = int(params.get("offset", 0))
        limit = params.get("limit")
        cmd = f"info variables {query}" if query else "info variables"
        output = gdb.execute(cmd, to_string=True)
        result = _parse_info_variables(output)
        if offset:
            result = result[offset:]
        if limit is not None:
            result = result[:int(limit)]
        return result

    def _types_show(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params["name"]
        try:
            t = gdb.lookup_type(name)
            result: dict[str, Any] = {
                "name": str(t),
                "sizeof": t.sizeof,
            }
            try:
                result["code"] = str(t.code)
            except Exception:
                pass
            # For struct/union, enumerate fields
            try:
                fields = []
                for f in t.fields():
                    field_info: dict[str, Any] = {"name": f.name}
                    try:
                        field_info["type"] = str(f.type)
                    except Exception:
                        pass
                    try:
                        field_info["bitpos"] = f.bitpos
                    except Exception:
                        pass
                    try:
                        field_info["bitsize"] = f.bitsize
                    except Exception:
                        pass
                    fields.append(field_info)
                if fields:
                    result["fields"] = fields
            except Exception:
                pass

            # Generate a C-style declaration
            try:
                decl = gdb.execute(f"ptype {name}", to_string=True)
                result["decl"] = decl.strip()
            except Exception:
                pass

            return result
        except Exception:
            # Fallback to ptype
            output = gdb.execute(f"ptype {name}", to_string=True)
            return {"decl": output.strip()}

    def _info_files(self, params: dict[str, Any]) -> dict[str, Any]:
        output = gdb.execute("info files", to_string=True)
        return {"raw": output}

    def _source_list(self, params: dict[str, Any]) -> dict[str, Any]:
        location = params.get("location")
        count = params.get("count")
        if location:
            cmd = f"list {location}"
        else:
            cmd = "list"
        if count:
            gdb.execute(f"set listsize {count}", to_string=True)
        output = gdb.execute(cmd, to_string=True)
        return {"source": output}

    # ------------------------------------------------------------------
    # Raw GDB command passthrough
    # ------------------------------------------------------------------

    def _gdb_exec(self, params: dict[str, Any]) -> dict[str, Any]:
        command = params["command"]
        output = gdb.execute(command, to_string=True)
        return {"output": output}

    # ------------------------------------------------------------------
    # Python escape hatch
    # ------------------------------------------------------------------

    def _py_exec(self, params: dict[str, Any]) -> dict[str, Any]:
        code = params["code"]

        # Capture stdout
        import io as _io
        captured = _io.StringIO()
        old_stdout = sys.stdout
        result_holder: dict[str, Any] = {}

        exec_globals = {
            "gdb": gdb,
            "result": result_holder,
        }

        try:
            sys.stdout = captured
            exec(code, exec_globals)
        except Exception as exc:
            # Surface the full traceback (file/line of the failing user code),
            # not just "Type: message" — multi-line scripts are otherwise very
            # hard to debug. format_exc() already ends with the type+message.
            raise RuntimeError(
                "py exec failed:\n" + traceback.format_exc().rstrip()
            ) from exc
        finally:
            sys.stdout = old_stdout

        # Return the whole `result` dict so scripts can set arbitrary keys.
        # Historically only `result["value"]` was surfaced, which silently
        # dropped anything else the user set. For back-compat, if the script
        # only set `value`, surface that under the top-level `result` key
        # (and also expose the full dict under `result_dict`).
        payload: dict[str, Any] = {"stdout": captured.getvalue()}
        if set(result_holder.keys()) == {"value"}:
            payload["result"] = result_holder["value"]
        elif result_holder:
            payload["result"] = dict(result_holder)
        else:
            payload["result"] = None
        return payload


# ---------------------------------------------------------------------------
# Module-level bridge management
# ---------------------------------------------------------------------------

_bridge: GdbBridge | None = None


def start_bridge():
    global _bridge
    if _bridge is not None:
        return
    _bridge = GdbBridge()
    _bridge.start()
    atexit.register(_stop_bridge)


def _stop_bridge():
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None
