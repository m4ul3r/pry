from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest


def _load_bridge(monkeypatch):
    """Load the bridge module with a fake gdb module injected."""
    fake_gdb = types.ModuleType("gdb")
    fake_gdb.VERSION = "15.1"

    # Fake breakpoints
    class _FakeBreakpoint:
        _counter = 0

        def __init__(self, location=None, type=1, temporary=False, wp_class=0):
            _FakeBreakpoint._counter += 1
            self.number = _FakeBreakpoint._counter
            self.location = location
            self.expression = location if type in (6, 7, 8, 9) else None  # Any watchpoint type
            self.type = type
            self.temporary = temporary
            self.enabled = True
            self.condition = None
            self.hit_count = 0
            _breakpoints.append(self)

        def delete(self):
            _breakpoints[:] = [bp for bp in _breakpoints if bp is not self]

    _breakpoints = []

    fake_gdb.Breakpoint = _FakeBreakpoint
    # Match real GDB 15.x constants
    fake_gdb.BP_BREAKPOINT = 1
    fake_gdb.BP_HARDWARE_BREAKPOINT = 2
    fake_gdb.BP_WATCHPOINT = 6
    fake_gdb.BP_HARDWARE_WATCHPOINT = 7
    fake_gdb.BP_READ_WATCHPOINT = 8
    fake_gdb.BP_ACCESS_WATCHPOINT = 9
    fake_gdb.WP_WRITE = 0
    fake_gdb.WP_READ = 1
    fake_gdb.WP_ACCESS = 2

    def _breakpoints_func():
        return list(_breakpoints)

    fake_gdb.breakpoints = _breakpoints_func

    # Fake frame
    class _FakeSAL:
        def __init__(self):
            self.symtab = types.SimpleNamespace(filename="test.c")
            self.line = 42

    class _FakeBlock:
        def __init__(self, symbols=None, function=True, superblock=None):
            self._symbols = list(symbols or [])
            self.function = function if function is True else function
            self.superblock = superblock

        def __iter__(self):
            return iter(self._symbols)

    class _FakeSymbol:
        def __init__(self, name, value="0", *, is_variable=False, is_argument=False, sym_type="int"):
            self.name = name
            self._value = value
            self.is_variable = is_variable
            self.is_argument = is_argument
            self.type = sym_type

    class _FakeFrame:
        def __init__(self, name="main", pc=0x401000, older=None):
            self._name = name
            self._pc = pc
            self._older = older
            self._symbols = []

        def pc(self):
            return self._pc

        def name(self):
            return self._name

        def find_sal(self):
            return _FakeSAL()

        def older(self):
            return self._older

        def block(self):
            syms = [
                _FakeSymbol("argc", "1", is_argument=True),
                _FakeSymbol("x", "42", is_variable=True),
            ]
            return _FakeBlock(symbols=syms, function=True)

        def read_var(self, sym):
            return sym._value

        def architecture(self):
            return _FakeArchitecture()

    class _FakeArchitecture:
        def disassemble(self, addr, count=20):
            return [
                {"addr": addr + i * 4, "asm": f"nop", "length": 4}
                for i in range(count)
            ]

        def registers(self):
            return []

    _current_frame = _FakeFrame(
        "main",
        0x401000,
        older=_FakeFrame("__libc_start_main", 0x7fff000),
    )

    fake_gdb.selected_frame = lambda: _current_frame
    fake_gdb.newest_frame = lambda: _current_frame

    # Fake thread
    class _FakeThread:
        def __init__(self):
            self.num = 1

        def is_exited(self):
            return False

        def is_running(self):
            return False

        def is_stopped(self):
            return True

    fake_gdb.selected_thread = lambda: _FakeThread()

    # Fake inferior
    class _FakeInferior:
        def __init__(self):
            self.num = 1
            self.pid = 12345
            self.progspace = types.SimpleNamespace(filename="/bin/test")

        def read_memory(self, addr, length):
            return bytes(range(length % 256)) * (length // 256 + 1)[:length]

        def write_memory(self, addr, data):
            pass

    _inferior = _FakeInferior()
    fake_gdb.inferiors = lambda: [_inferior]
    fake_gdb.selected_inferior = lambda: _inferior

    # Fake gdb.execute
    _execute_log = []

    _EXEC_CMDS = {"run", "continue", "step", "next", "stepi", "nexti", "finish", "until", "interrupt"}

    def _fake_execute(cmd, to_string=False):
        _execute_log.append(cmd)
        if cmd.startswith("info registers"):
            return "rax            0x0                 0\nrbx            0x7fff             32767\n"
        if cmd.startswith("info functions"):
            return "All defined functions:\n\nFile test.c:\n0x00401000  main\n0x00401100  helper\n"
        if cmd.startswith("info variables"):
            return "All defined variables:\n\n0x00601000  global_var\n"
        if cmd.startswith("info files"):
            return "Symbols from \"/bin/test\".\nLocal exec file:\n\t0x0000000000401000 - 0x0000000000401100 is .text\n"
        if cmd.startswith("list"):
            return "1\tint main(int argc, char **argv) {\n2\t    return 0;\n3\t}\n"
        if cmd.startswith("disassemble"):
            return "Dump of assembler code for function main:\n   0x0000000000401000 <+0>:\tpush   %rbp\nEnd of assembler dump.\n"
        if cmd.startswith("ptype"):
            return "type = struct foo {\n    int x;\n    int y;\n}\n"
        if cmd.startswith("target remote"):
            return "Remote debugging using " + cmd.split("target remote ", 1)[1] + "\n"
        if cmd == "disconnect":
            return "Ending remote debugging.\n"
        if cmd.startswith("info target"):
            return "Remote serial target in gdb-specific protocol:\nDebugging a target over a serial line.\n"
        if cmd.startswith("info connections"):
            return "  Num  What                        Description\n* 1    remote localhost:1234       Remote serial target\n"
        # For execution commands, fire the pending stop event (simulates
        # GDB processing the stop after gdb.execute returns).
        base_cmd = cmd.split()[0] if cmd else ""
        if base_cmd in _EXEC_CMDS and fake_gdb._pending_stop_event is not None:
            evt = fake_gdb._pending_stop_event
            fake_gdb._pending_stop_event = None
            _stop_registry.fire(evt)
        return ""

    fake_gdb.execute = _fake_execute
    fake_gdb._execute_log = _execute_log
    # Pending stop event: tests can set this to have gdb.execute fire a stop
    # event via gdb.post_event after the execute returns.
    fake_gdb._pending_stop_event = None

    # Fake gdb.parse_and_eval
    class _FakeValue:
        def __init__(self, val, typ="int"):
            self._val = val
            self.type = typ

        def __str__(self):
            return str(self._val)

        def __int__(self):
            return int(self._val)

    fake_gdb.parse_and_eval = lambda expr: _FakeValue(42)

    # Fake lookup_type
    class _FakeType:
        def __init__(self, name, sizeof=4):
            self._name = name
            self.sizeof = sizeof
            self.code = "TYPE_CODE_STRUCT"

        def __str__(self):
            return self._name

        def fields(self):
            return [
                types.SimpleNamespace(name="x", type="int", bitpos=0, bitsize=0),
                types.SimpleNamespace(name="y", type="int", bitpos=32, bitsize=0),
            ]

    fake_gdb.lookup_type = lambda name: _FakeType(name)

    # Fake error class
    class GdbError(Exception):
        pass

    fake_gdb.error = GdbError

    # Fake stop events
    class _FakeEventRegistry:
        def __init__(self):
            self._handlers = []

        def connect(self, handler):
            self._handlers.append(handler)

        def disconnect(self, handler):
            self._handlers[:] = [h for h in self._handlers if h is not handler]

        def fire(self, event):
            for handler in self._handlers:
                handler(event)

    class _FakeStopEvent:
        pass

    class _FakeBreakpointEvent(_FakeStopEvent):
        def __init__(self, breakpoints):
            self.breakpoints = tuple(breakpoints)

    class _FakeSignalEvent(_FakeStopEvent):
        def __init__(self, signal):
            self.stop_signal = signal

    class _FakeExitedEvent:
        def __init__(self, exit_code=0):
            self.exit_code = exit_code

    _stop_registry = _FakeEventRegistry()
    _exited_registry = _FakeEventRegistry()
    fake_gdb.events = types.SimpleNamespace(stop=_stop_registry, exited=_exited_registry)
    fake_gdb.BreakpointEvent = _FakeBreakpointEvent
    fake_gdb.SignalEvent = _FakeSignalEvent
    fake_gdb._FakeBreakpointEvent = _FakeBreakpointEvent
    fake_gdb._FakeSignalEvent = _FakeSignalEvent
    fake_gdb._FakeStopEvent = _FakeStopEvent
    fake_gdb._FakeExitedEvent = _FakeExitedEvent

    # gdb.post_event: run the callback immediately in test context
    fake_gdb.post_event = lambda cb: cb()

    # gdb.write: no-op in tests
    fake_gdb.write = lambda *a, **kw: None

    # Inject into sys.modules
    monkeypatch.setitem(sys.modules, "gdb", fake_gdb)

    # Load the bridge module under a test package name
    package_name = "pry_test_bridge"
    module_name = f"{package_name}.bridge"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    monkeypatch.delitem(sys.modules, package_name, raising=False)

    bridge_path = Path(__file__).resolve().parents[1] / "plugin" / "pry_agent_bridge" / "bridge.py"
    package = types.ModuleType(package_name)
    package.__path__ = [str(bridge_path.parent)]
    monkeypatch.setitem(sys.modules, package_name, package)
    spec = importlib.util.spec_from_file_location(module_name, bridge_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module, fake_gdb


def test_doctor_returns_version(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("doctor", {})
    assert result["plugin_version"] == "0.1.0"
    assert result["gdb_version"] == "15.1"
    assert result["inferiors"][0]["pid"] == 12345


def test_list_inferiors(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("list_inferiors", {})
    assert len(result) == 1
    assert result[0]["num"] == 1
    assert result[0]["pid"] == 12345


def test_break_set_and_list(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp_result = bridge._dispatch_op("break_set", {"location": "main"})
    assert bp_result["location"] == "main"
    assert bp_result["enabled"] is True

    bp_list = bridge._dispatch_op("break_list", {})
    assert len(bp_list) >= 1
    assert any(bp["location"] == "main" for bp in bp_list)


def test_break_delete(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "main"})
    number = bp["number"]

    result = bridge._dispatch_op("break_delete", {"number": number})
    assert result["deleted"] == number

    bp_list = bridge._dispatch_op("break_list", {})
    assert not any(b["number"] == number for b in bp_list)


def test_break_enable_disable(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "foo"})
    number = bp["number"]

    result = bridge._dispatch_op("break_disable", {"number": number})
    assert result["enabled"] is False

    result = bridge._dispatch_op("break_enable", {"number": number})
    assert result["enabled"] is True


def test_backtrace(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("backtrace", {})
    assert len(result) == 2
    assert result[0]["function"] == "main"
    assert result[0]["level"] == 0
    assert result[1]["function"] == "__libc_start_main"
    assert result[1]["level"] == 1


def test_frame_info(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("frame_info", {})
    assert result["function"] == "main"
    assert result["address"] == "0x401000"


def test_locals_and_args(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    local_result = bridge._dispatch_op("locals", {})
    assert any(v["name"] == "x" for v in local_result)

    args_result = bridge._dispatch_op("args", {})
    assert any(a["name"] == "argc" for a in args_result)


def test_print_expression(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("print", {"expression": "argc"})
    assert result["value"] == "42"
    assert result["type"] == "int"


def test_registers(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("registers", {})
    assert len(result) >= 2
    assert result[0]["name"] == "rax"


def test_functions(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("functions", {})
    assert any(f.get("name", "").strip().endswith("main") for f in result)


def test_types_show(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("types_show", {"name": "struct foo"})
    assert result["sizeof"] == 4
    assert "fields" in result


def test_info_files(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("info_files", {})
    assert "raw" in result
    assert ".text" in result["raw"]


def test_source_list(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("source_list", {})
    assert "source" in result


def test_py_exec(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("py_exec", {"code": "print('hello')"})
    assert result["stdout"] == "hello\n"


def test_py_exec_with_result(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("py_exec", {"code": "result['value'] = 42"})
    assert result["result"] == 42


def test_unknown_op_raises(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    with pytest.raises(ValueError, match="Unknown op"):
        bridge._dispatch_op("nonexistent_op", {})


def test_load_executes_file_command(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("load", {"path": "/bin/test"})
    assert result["loaded"] == "/bin/test"
    assert "file /bin/test" in fake_gdb._execute_log


def test_dispatch_wraps_errors(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    response = bridge.dispatch({"op": "nonexistent_op", "params": {}})
    assert response["ok"] is False
    assert "Unknown op" in response["error"]


def test_stop_reason_breakpoint_hit(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "main"})
    # Simulate GDB firing a breakpoint stop event before _stop_info is called
    bp_obj = fake_gdb.breakpoints()[0]
    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([bp_obj]))

    result = bridge._stop_info()
    assert result["status"] == "stopped"
    assert result["reason"]["kind"] == "breakpoint-hit"
    assert result["reason"]["number"] == bp["number"]
    assert result["reason"]["location"] == "main"


def test_stop_reason_signal(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    fake_gdb.events.stop.fire(fake_gdb._FakeSignalEvent("SIGSEGV"))

    result = bridge._stop_info()
    assert result["status"] == "stopped"
    assert result["reason"]["kind"] == "signal"
    assert result["reason"]["signal"] == "SIGSEGV"


def test_stop_reason_cleared_after_read(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    fake_gdb.events.stop.fire(fake_gdb._FakeSignalEvent("SIGINT"))
    result1 = bridge._stop_info()
    assert "reason" in result1

    result2 = bridge._stop_info()
    assert "reason" not in result2


def test_stale_stop_reason_cleared_by_exited_event(monkeypatch):
    """Program exit event clears stale stop reason."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Simulate a breakpoint-hit via the permanent handler
    bp = bridge._dispatch_op("break_set", {"location": "main"})
    bp_obj = fake_gdb.breakpoints()[0]
    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([bp_obj]))
    assert bridge._last_stop_reason is not None

    # Program exits
    fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(0))
    assert bridge._last_stop_reason is None


def test_stop_reason_hardware_watchpoint(monkeypatch):
    """Hardware watchpoint stop events are classified correctly."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("watch_set", {"expression": "myvar"})
    bp_obj = fake_gdb.breakpoints()[0]
    # Simulate GDB upgrading to hardware watchpoint (type 7)
    bp_obj.type = fake_gdb.BP_HARDWARE_WATCHPOINT

    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([bp_obj]))

    result = bridge._stop_info()
    assert result["reason"]["kind"] == "watchpoint-hit"
    assert result["reason"]["number"] == bp["number"]
    assert result["reason"]["expression"] == "myvar"


def test_dispatch_exec_breakpoint_stop(monkeypatch):
    """dispatch_exec captures breakpoint stop reason via event handler."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "main"})
    bp_obj = fake_gdb.breakpoints()[0]

    # Set pending stop event — fake_execute will fire it during "continue"
    fake_gdb._pending_stop_event = fake_gdb._FakeBreakpointEvent([bp_obj])

    response = bridge.dispatch({"op": "continue", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["status"] == "stopped"
    assert result["reason"]["kind"] == "breakpoint-hit"
    assert result["reason"]["number"] == bp["number"]


def test_dispatch_exec_watchpoint_stop(monkeypatch):
    """dispatch_exec captures watchpoint stop reason."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("watch_set", {"expression": "result"})
    bp_obj = fake_gdb.breakpoints()[0]
    bp_obj.type = fake_gdb.BP_HARDWARE_WATCHPOINT

    fake_gdb._pending_stop_event = fake_gdb._FakeBreakpointEvent([bp_obj])

    response = bridge.dispatch({"op": "continue", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["reason"]["kind"] == "watchpoint-hit"
    assert result["reason"]["number"] == bp["number"]
    assert result["reason"]["expression"] == "result"


def test_dispatch_exec_signal_stop(monkeypatch):
    """dispatch_exec captures signal stop reason."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGSEGV")

    response = bridge.dispatch({"op": "continue", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["reason"]["kind"] == "signal"
    assert result["reason"]["signal"] == "SIGSEGV"


def test_dispatch_exec_no_stop_event(monkeypatch):
    """dispatch_exec returns stopped status even without explicit stop event."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # No pending stop event — fire a generic stop to unblock completion
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()

    response = bridge.dispatch({"op": "step", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["status"] == "stopped"


def test_connect_executes_target_remote(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("connect", {"target": "localhost:1234"})
    assert result["connected"] == "localhost:1234"
    assert result["status"] == "stopped"
    assert "set tcp connect-timeout 15" in fake_gdb._execute_log
    assert "target remote localhost:1234" in fake_gdb._execute_log


def test_connect_custom_timeout(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("connect", {"target": "localhost:1234", "connect_timeout": 5})
    assert result["connected"] == "localhost:1234"
    assert "set tcp connect-timeout 5" in fake_gdb._execute_log


def test_connect_clears_stop_reason(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Set a stale stop reason
    fake_gdb.events.stop.fire(fake_gdb._FakeSignalEvent("SIGINT"))
    assert bridge._last_stop_reason is not None

    result = bridge._dispatch_op("connect", {"target": "localhost:1234"})
    # _last_stop_reason should have been cleared before the connect
    assert result["connected"] == "localhost:1234"


def test_disconnect_executes_disconnect_command(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("disconnect", {})
    assert result["disconnected"] is True
    assert "disconnect" in fake_gdb._execute_log


def test_target_info_returns_raw_output(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("target_info", {})
    assert "raw" in result
    assert "Remote serial target" in result["raw"]
    assert "connections" in result
    assert "localhost:1234" in result["connections"]


def test_gdb_exec_passthrough(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("gdb_exec", {"command": "info registers"})
    assert "output" in result
    assert "rax" in result["output"]
    assert "info registers" in fake_gdb._execute_log


# ---------------------------------------------------------------------------
# Feature 1: Lock-free interrupt
# ---------------------------------------------------------------------------

def test_interrupt_bypasses_exec_ops(monkeypatch):
    """interrupt is handled before EXEC_OPS check, without locks."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    response = bridge.dispatch({"op": "interrupt", "params": {}})
    assert response["ok"] is True
    assert response["result"]["interrupted"] is True
    assert "interrupt" in fake_gdb._execute_log


def test_dispatch_exec_respects_timeout_param(monkeypatch):
    """_dispatch_exec pops _timeout from params and uses it."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # With a stop event queued, the timeout shouldn't matter (it completes immediately)
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()
    response = bridge.dispatch({"op": "continue", "params": {"_timeout": 5.0}})
    assert response["ok"] is True


def test_dispatch_exec_auto_interrupt_on_timeout(monkeypatch):
    """When _dispatch_exec times out, it auto-interrupts and returns with timeout_interrupt."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Queue no stop event — the initial completion.wait will time out.
    # But the auto-interrupt fires another "interrupt" command, which we need
    # to produce a stop event.
    original_execute = fake_gdb.execute

    def _execute_with_interrupt_stop(cmd, to_string=False):
        result = original_execute(cmd, to_string)
        # When "interrupt" is called, fire a stop event
        if cmd.strip() == "interrupt":
            fake_gdb.events.stop.fire(fake_gdb._FakeStopEvent())
        return result

    fake_gdb.execute = _execute_with_interrupt_stop

    response = bridge.dispatch({"op": "continue", "params": {"_timeout": 0.01}})
    assert response["ok"] is True
    assert response["result"].get("timeout_interrupt") is True


# ---------------------------------------------------------------------------
# Feature 2: _run_on_gdb_thread timeout parameter
# ---------------------------------------------------------------------------

def test_run_on_gdb_thread_custom_timeout(monkeypatch):
    """_run_on_gdb_thread accepts a timeout parameter."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    # Just verify the function runs with a custom timeout
    result = bridge_mod._run_on_gdb_thread(lambda: 42, timeout=5.0)
    assert result == 42


def test_dispatch_passes_timeout_to_run_on_gdb_thread(monkeypatch):
    """Non-exec ops extract _timeout from params."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # py_exec is a WRITE_LOCKED_OP that goes through _run_on_gdb_thread
    response = bridge.dispatch({
        "op": "py_exec",
        "params": {"code": "pass", "_timeout": 5.0},
    })
    assert response["ok"] is True


# ---------------------------------------------------------------------------
# Feature 3: Background continue, status, wait
# ---------------------------------------------------------------------------

def test_background_continue_returns_running(monkeypatch):
    """Background continue returns immediately with status=running."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Don't queue a stop event — background should return immediately
    response = bridge.dispatch({
        "op": "continue",
        "params": {"_background": True},
    })
    assert response["ok"] is True
    assert response["result"]["status"] == "running"
    assert bridge._running is True


def test_status_returns_running_state(monkeypatch):
    """status op returns the running/stopped state."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Initially not running
    response = bridge.dispatch({"op": "status", "params": {}})
    assert response["ok"] is True
    assert response["result"]["state"] == "stopped"


def test_wait_when_not_running(monkeypatch):
    """wait when inferior is stopped returns immediately."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    response = bridge.dispatch({"op": "wait", "params": {}})
    assert response["ok"] is True
    assert response["result"]["state"] == "stopped"


def test_dispatch_exec_rejects_concurrent_background(monkeypatch):
    """A second exec op while background is running raises an error."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Start a background continue
    bridge.dispatch({"op": "continue", "params": {"_background": True}})
    assert bridge._running is True

    # A second foreground continue should fail
    response = bridge.dispatch({"op": "continue", "params": {}})
    assert response["ok"] is False
    assert "already running" in response["error"]


# ---------------------------------------------------------------------------
# Feature 4: PIE address rebasing
# ---------------------------------------------------------------------------

def test_break_set_with_rebase(monkeypatch):
    """break_set with rebase_module resolves address via info proc mappings."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    # Patch _fake_execute to handle info proc mappings
    original_execute = fake_gdb.execute

    def _execute_with_mappings(cmd, to_string=False):
        if cmd.startswith("info proc mappings"):
            return (
                "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                "      0x555555554000     0x555555555000     0x1000        0x0  r-xp   /usr/bin/lugosiii\n"
                "      0x555555555000     0x555555556000     0x1000     0x1000  rw-p   /usr/bin/lugosiii\n"
            )
        return original_execute(cmd, to_string)

    fake_gdb.execute = _execute_with_mappings

    result = bridge._dispatch_op("break_set", {
        "location": "*0x1234",
        "rebase_module": "lugosiii",
    })
    assert result["rebased"] is not None
    assert result["rebased"]["module"] == "lugosiii"
    assert result["rebased"]["module_base"] == hex(0x555555554000)
    # runtime_addr = 0x1234 - 0 + 0x555555554000
    assert result["rebased"]["resolved"] == hex(0x555555554000 + 0x1234)


def test_break_set_rebase_with_image_base(monkeypatch):
    """break_set with rebase_module and image_base subtracts static base."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    original_execute = fake_gdb.execute

    def _execute_with_mappings(cmd, to_string=False):
        if cmd.startswith("info proc mappings"):
            return (
                "      0x555555554000     0x555555600000     0xac000        0x0  r-xp   /usr/bin/target\n"
            )
        return original_execute(cmd, to_string)

    fake_gdb.execute = _execute_with_mappings

    result = bridge._dispatch_op("break_set", {
        "location": "*0x40656e",
        "rebase_module": "target",
        "image_base": 0x400000,
    })
    # runtime_addr = 0x40656e - 0x400000 + 0x555555554000 = 0x55555555a56e
    expected = 0x40656e - 0x400000 + 0x555555554000
    assert result["rebased"]["resolved"] == hex(expected)


def test_break_set_rebase_module_not_found(monkeypatch):
    """break_set with unknown module raises ValueError."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    original_execute = fake_gdb.execute

    def _execute_with_empty_mappings(cmd, to_string=False):
        if cmd.startswith("info proc mappings"):
            raise fake_gdb.error("No current process")
        return original_execute(cmd, to_string)

    fake_gdb.execute = _execute_with_empty_mappings
    fake_gdb.objfiles = lambda: []

    with pytest.raises(ValueError, match="not found"):
        bridge._dispatch_op("break_set", {
            "location": "*0x1234",
            "rebase_module": "nonexistent",
        })
