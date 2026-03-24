from __future__ import annotations

import atexit
import base64
import contextlib
import errno
import json
import os
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
    "target_info",
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
    "interrupt",
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
    "interrupt",
    "break_set",
    "break_delete",
    "break_enable",
    "break_disable",
    "watch_set",
    "memory_write",
    "py_exec",
    "gdb_exec",
}


# ---------------------------------------------------------------------------
# GDB thread safety: post work to GDB's event loop
# ---------------------------------------------------------------------------

def _run_on_gdb_thread(func):
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
    event.wait(timeout=120.0)

    if not event.is_set():
        raise RuntimeError("Timed out waiting for GDB main thread")
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
        result["function"] = str(frame.name())
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


def _breakpoint_to_dict(bp) -> dict[str, Any]:
    """Convert a gdb.Breakpoint to a JSON-friendly dict."""
    result: dict[str, Any] = {
        "number": bp.number,
        "type": bp.type,
        "enabled": bp.enabled,
        "location": getattr(bp, "location", None),
        "expression": getattr(bp, "expression", None),
        "condition": bp.condition,
        "hits": bp.hit_count,
        "temporary": bp.temporary,
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
    def _bp_reason(bp) -> dict[str, Any]:
        """Build a stop-reason dict for a breakpoint/watchpoint."""
        reason: dict[str, Any] = {}
        if GdbBridge._is_watchpoint_type(bp.type):
            reason["kind"] = "watchpoint-hit"
            reason["number"] = bp.number
            reason["expression"] = getattr(bp, "expression", None)
        else:
            reason["kind"] = "breakpoint-hit"
            reason["number"] = bp.number
            reason["location"] = getattr(bp, "location", None)
        if bp.temporary:
            reason["temporary"] = True
        return reason

    def _on_stop(self, event):
        """GDB stop-event callback — captures the stop reason."""
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
            if op in EXEC_OPS:
                return self._dispatch_exec(op, params)

            lock = contextlib.nullcontext()
            if op in WRITE_LOCKED_OPS:
                lock = self._lock.write()
            elif op in READ_LOCKED_OPS:
                lock = self._lock.read()
            with lock:
                result = _run_on_gdb_thread(lambda: self._dispatch_op(op, params))
            return _json_response(ok=True, result=result)
        except Exception as exc:
            return _json_response(ok=False, error=f"{type(exc).__name__}: {exc}")

    def _dispatch_exec(self, op: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dispatch an execution command and wait for the stop/exited event.

        Unlike normal dispatch which waits for the gdb.post_event callback
        to return, this waits for GDB's stop or exited event to fire — which
        happens AFTER the callback returns and GDB processes the stop.
        """
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
                self._dispatch_op(op, params)
            except Exception as exc:
                error_box.append(exc)
                completion.set()

        with self._lock.write():
            gdb.events.stop.connect(_on_exec_stop)
            if hasattr(gdb.events, "exited"):
                gdb.events.exited.connect(_on_exec_exited)
            try:
                gdb.post_event(_do_execute)
                if not completion.wait(timeout=120.0):
                    raise RuntimeError(
                        "Timed out waiting for inferior to stop"
                    )
            finally:
                gdb.events.stop.disconnect(_on_exec_stop)
                if hasattr(gdb.events, "exited"):
                    gdb.events.exited.disconnect(_on_exec_exited)

        if error_box:
            raise error_box[0]
        if not result_box:
            raise RuntimeError("Execution completed without stop or exit event")

        return _json_response(ok=True, result=result_box[0])

    # ------------------------------------------------------------------
    # Op dispatch
    # ------------------------------------------------------------------

    def _dispatch_op(self, op: str, params: dict[str, Any]) -> Any:
        if op == "doctor":
            return self._doctor()
        if op == "list_inferiors":
            return self._list_inferiors()

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

    def _break_set(self, params: dict[str, Any]) -> dict[str, Any]:
        location = params["location"]
        temporary = params.get("temporary", False)
        hardware = params.get("hardware", False)

        bp_type = gdb.BP_BREAKPOINT
        if hardware:
            bp_type = gdb.BP_HARDWARE_BREAKPOINT

        bp = gdb.Breakpoint(location, type=bp_type, temporary=temporary)

        condition = params.get("condition")
        if condition:
            bp.condition = condition

        return _breakpoint_to_dict(bp)

    def _break_list(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        bps = gdb.breakpoints() or []
        return [_breakpoint_to_dict(bp) for bp in bps]

    def _break_delete(self, params: dict[str, Any]) -> dict[str, Any]:
        number = int(params["number"])
        for bp in (gdb.breakpoints() or []):
            if bp.number == number:
                bp.delete()
                return {"deleted": number}
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
        return _breakpoint_to_dict(bp)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def _backtrace(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        full = params.get("full", False)
        limit = params.get("limit")
        frames = []
        try:
            frame = gdb.newest_frame()
        except gdb.error:
            return []
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

    def _print(self, params: dict[str, Any]) -> dict[str, Any]:
        expression = params["expression"]
        val = gdb.parse_and_eval(expression)
        result: dict[str, Any] = {"value": str(val)}
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

    def _disasm(self, params: dict[str, Any]) -> Any:
        location = params.get("location")
        count = params.get("count")

        if location:
            # Try to use Architecture.disassemble for structured output
            try:
                addr_val = gdb.parse_and_eval(location)
                addr_int = int(addr_val)
                arch = gdb.selected_frame().architecture()
                insns = arch.disassemble(addr_int, count=count or 20)
                return [
                    {"address": hex(insn["addr"]), "asm": insn["asm"], "length": insn["length"]}
                    for insn in insns
                ]
            except Exception:
                pass
            # Fallback to gdb.execute
            cmd = f"disassemble {location}"
        else:
            cmd = "disassemble"

        output = gdb.execute(cmd, to_string=True)
        return output

    def _functions(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = params.get("query")
        offset = int(params.get("offset", 0))
        limit = params.get("limit")

        if query:
            output = gdb.execute(f"info functions {query}", to_string=True)
        else:
            output = gdb.execute("info functions", to_string=True)

        result = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("All") or line.startswith("File") or line.startswith("Non-debugging"):
                continue
            # Lines look like: "0x00401000  function_name" or type signatures
            parts = line.split()
            if parts and parts[0].startswith("0x"):
                result.append({"address": parts[0], "name": " ".join(parts[1:])})
            elif line and not line.endswith(":"):
                result.append({"name": line})

        if offset:
            result = result[offset:]
        if limit is not None:
            result = result[:int(limit)]
        return result

    def _symbols(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        query = params.get("query")
        offset = int(params.get("offset", 0))
        limit = params.get("limit")

        if query:
            output = gdb.execute(f"info variables {query}", to_string=True)
        else:
            output = gdb.execute("info variables", to_string=True)

        result = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("All") or line.startswith("File") or line.startswith("Non-debugging"):
                continue
            parts = line.split()
            if parts and parts[0].startswith("0x"):
                result.append({"address": parts[0], "name": " ".join(parts[1:])})
            elif line and not line.endswith(":"):
                result.append({"name": line})

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

        return {
            "stdout": captured.getvalue(),
            "result": result_holder.get("value"),
        }


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
