from __future__ import annotations

import atexit
import base64
import contextlib
import errno
import json
import os
import re
import socketserver
import sys
import threading
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
    "locals",
    "args",
    "print",
    "registers",
    "memory_read",
    "disasm",
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
    "break_set",
    "break_delete",
    "break_enable",
    "break_disable",
    "watch_set",
    "memory_write",
    "register_write",
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

def _run_on_gdb_thread(func, *, timeout: float = 120.0):
    """Execute *func* on GDB's main thread via gdb.post_event and wait."""
    holder: dict[str, Any] = {}
    event = threading.Event()

    def _callback():
        try:
            holder["result"] = func()
        except Exception as exc:
            holder["error"] = exc
            holder["traceback"] = traceback.format_exc()
        event.set()

    gdb.post_event(_callback)
    event.wait(timeout=timeout)

    if not event.is_set():
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
        self._background_completion: threading.Event | None = None
        self._background_result: dict[str, Any] | None = None
        gdb.events.stop.connect(self._on_stop)
        if hasattr(gdb.events, "exited"):
            gdb.events.exited.connect(self._on_exited)

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
                if new_value is not None:
                    old_value = self._watchpoint_values.get(bp.number)
                    reason["new_value"] = new_value
                    if old_value is not None and old_value != new_value:
                        reason["old_value"] = old_value
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
        self._last_stop_reason = reason or None

    def _on_exited(self, event):
        """GDB exited-event callback — clears stale stop reason."""
        self._running = False
        self._last_stop_reason = None

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

    @staticmethod
    def _augment_error(exc: Exception) -> str:
        """Turn a raw GDB/Python error into an agent-actionable message.

        The bare ``type: message`` form (e.g. ``error: No symbol "foo" in
        current context.``) tells an agent what failed but not what to do.
        Append a concrete next step for the most common recoverable cases.
        """
        base = f"{type(exc).__name__}: {exc}"
        low = str(exc).lower()
        hint = None
        if "no frame is currently selected" in low or "no frame selected" in low:
            hint = (
                "no inferior is stopped at a frame — start the program "
                "(`pry run`) and stop at a breakpoint first"
            )
        elif "no symbol" in low and "context" in low:
            hint = (
                "symbol not in scope — check spelling; it may be a function "
                "(`pry functions --query NAME`), a global (`pry symbols "
                "--query NAME`), or live in another frame (`pry frame select N`)"
            )
        elif "no stack" in low:
            hint = "the inferior is not running — use `pry run` or `pry continue`"
        elif "cannot access memory" in low:
            hint = "address not mapped — check `pry mappings` for valid ranges"
        elif "the program is not being run" in low or "not being run" in low:
            hint = "the inferior is not running — `pry run` to start it"
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
        return _json_response(ok=True, result={"interrupted": True})

    def _dispatch_status(self) -> dict[str, Any]:
        """Return the inferior's current execution state (lock-free)."""
        result: dict[str, Any] = {}
        if self._running:
            result["state"] = "running"
        else:
            info = _stop_info()
            # Use the thread-level status ("exited" / "stopped" / ...) as the
            # authoritative state when available so callers don't see
            # `state: stopped` for an inferior that has already exited.
            thread_status = info.get("status")
            if thread_status == "exited":
                result["state"] = "exited"
            elif not gdb.selected_inferior().pid:
                # No thread has ever run (or the inferior has been unloaded).
                result["state"] = "not-started"
            else:
                result["state"] = "stopped"
            result.update(info)
            if self._last_stop_reason:
                result["reason"] = self._last_stop_reason
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
        """Parse an address from int, hex string, or GDB expression."""
        if isinstance(addr, int):
            return addr
        if isinstance(addr, str):
            addr = addr.strip().lstrip("*")
            try:
                return int(addr, 0)
            except ValueError:
                val = gdb.parse_and_eval(addr)
                return int(val)
        return int(addr)

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

        # Inspection
        if op == "backtrace":
            return self._backtrace(params)
        if op == "frame_info":
            return self._frame_info(params)
        if op == "frame_select":
            return self._frame_select(params)
        if op == "locals":
            return self._locals(params)
        if op == "args":
            return self._args(params)
        if op == "print":
            return self._print(params)
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

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _load(self, params: dict[str, Any]) -> dict[str, Any]:
        path = params["path"]
        gdb.execute(f"file {path}", to_string=True)
        return {"loaded": path}

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

    def _finish(self, params: dict[str, Any]) -> dict[str, Any]:
        return self._exec_and_stop("finish")

    def _until(self, params: dict[str, Any]) -> dict[str, Any]:
        location = params["location"]
        return self._exec_and_stop(f"until {location}")

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
        return [_breakpoint_to_dict(bp) for bp in bps]

    def _break_delete(self, params: dict[str, Any]) -> dict[str, Any]:
        number = int(params["number"])
        for bp in (gdb.breakpoints() or []):
            if bp.number == number:
                # Capture the kind before deleting so the response can name a
                # watchpoint a "watchpoint" (break/watch share a number space).
                kind = _bp_kind(bp.type)
                bp.delete()
                self._watchpoint_values.pop(number, None)
                return {"deleted": number, "kind": kind}
        raise ValueError(f"No breakpoint #{number}")

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
        gdb.execute(f"set ${name} = {value}", to_string=True)
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

    def _memory_read(self, params: dict[str, Any]) -> dict[str, Any]:
        address = params["address"]
        length = int(params["length"])
        fmt = params.get("format", "hex")

        # Parse address
        if isinstance(address, str):
            addr_val = gdb.parse_and_eval(address)
            addr_int = int(addr_val)
        else:
            addr_int = int(address)

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

        # Default to $pc so --count is honored even when the caller didn't
        # pass a location. Previously omitting location routed to GDB's
        # `disassemble` command (whole function), which silently ignored
        # --count.
        effective_location = location or "$pc"
        addr_int = _resolve_to_address(effective_location)

        if addr_int is not None:
            try:
                arch = gdb.selected_frame().architecture()
                insns = arch.disassemble(addr_int, count=count or 20)
                result = []
                for insn in insns:
                    entry = {
                        "address": hex(insn["addr"]),
                        "asm": insn["asm"],
                        "length": insn["length"],
                    }
                    # Annotate with the containing symbol+offset so an agent
                    # can locate each instruction (matches pwndbg/GDB context)
                    # without a separate `info symbol` round-trip.
                    symbol = self._symbolize(insn["addr"])
                    if symbol:
                        entry["symbol"] = symbol
                    result.append(entry)
                return result
            except Exception:
                pass

        # Fallback: GDB's disassemble command. This path ignores --count
        # because `disassemble FUNC` emits the whole function.
        cmd = f"disassemble {location}" if location else "disassemble"
        return gdb.execute(cmd, to_string=True)

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
