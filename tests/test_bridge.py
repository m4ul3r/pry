from __future__ import annotations

import importlib
import importlib.util
import struct
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

        def read_register(self, name):
            # Mirror real GDB: accept register names/aliases, raise for unknown.
            valid = {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "rip", "r15", "eax", "pc", "sp", "fp",
            }
            if name not in valid:
                raise ValueError(f"Invalid register `{name}'")
            return 0

        def architecture(self):
            return _FakeArchitecture()

        def select(self):
            nonlocal _current_frame
            _current_frame = self

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
        def __init__(self, num=1, frame=None, name=None):
            self.num = num
            self.global_num = num
            self.name = name
            self.ptid = (12345, num, 0)
            self._frame = frame or _FakeFrame("main", 0x401000)
            self.inferior = None

        def switch(self):
            nonlocal _current_frame
            _current_frame = self._frame

        def is_exited(self):
            return False

        def is_running(self):
            return False

        def is_stopped(self):
            return True

    _threads = [
        _FakeThread(1, _FakeFrame("main", 0x401000), "main-thread"),
        _FakeThread(2, _FakeFrame("worker", 0x401100), "worker"),
    ]
    fake_gdb.selected_thread = lambda: _threads[0]

    # Fake inferior
    class _FakeInferior:
        def __init__(self):
            self.num = 1
            self.pid = 12345
            self.progspace = types.SimpleNamespace(filename="/bin/test")
            for thread in _threads:
                thread.inferior = self

        def read_memory(self, addr, length):
            return bytes(range(length % 256)) * (length // 256 + 1)[:length]

        def write_memory(self, addr, data):
            pass

        def threads(self):
            return list(_threads)

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


def test_list_threads(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("list_threads", {})
    assert len(result) == 2
    assert result[0]["num"] == 1
    assert result[0]["selected"] is True
    assert result[0]["frame"]["function"] == "main"
    assert result[1]["num"] == 2
    assert result[1]["frame"]["address"] == "0x401100"


def test_list_threads_filters_by_pc(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("list_threads", {"pc": "0x401100"})
    assert len(result) == 1
    assert result[0]["num"] == 2


def test_list_threads_preserves_missing_function_as_null(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    fake_gdb.inferiors()[0].threads()[1]._frame._name = None
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("list_threads", {"pc": "0x401100"})

    assert result[0]["frame"]["function"] is None


def test_break_set_and_list(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp_result = bridge._dispatch_op("break_set", {"location": "main"})
    assert bp_result["location"] == "main"
    assert bp_result["enabled"] is True

    bp_list = bridge._dispatch_op("break_list", {})
    assert len(bp_list) >= 1
    assert any(bp["location"] == "main" for bp in bp_list)


def test_break_set_auto_prefixes_bare_hex_address(monkeypatch):
    """A bare hex literal like '0x401f0e' is what users mean when they
    say 'break at this address'. GDB's own syntax requires the '*'
    prefix; without it, the bare hex is interpreted as a source line
    number and the breakpoint silently goes pending. The bridge
    auto-prefixes so the obvious form just works."""
    bridge_mod, _ = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "0x401f0e"})
    assert bp["location"] == "*0x401f0e"

    # Already-prefixed addresses are left alone.
    bp2 = bridge._dispatch_op("break_set",
                              {"location": "*0x401f17"})
    assert bp2["location"] == "*0x401f17"

    # Symbolic locations (function names, file:line) are not touched.
    bp3 = bridge._dispatch_op("break_set", {"location": "main"})
    assert bp3["location"] == "main"


def test_looks_like_bare_hex_address(monkeypatch):
    """Helper precision matters — must not auto-prefix things that
    happen to start with '0x' but aren't pure hex addresses."""
    bridge_mod, _ = _load_bridge(monkeypatch)
    fn = bridge_mod._looks_like_bare_hex_address
    assert fn("0x401f0e")
    assert fn("0X401F0E")
    assert fn("0x0")
    assert not fn("")
    assert not fn("0x")            # no digits after prefix
    assert not fn("main")          # symbolic
    assert not fn("*0x401f0e")     # already prefixed
    assert not fn("0x401f0e foo")  # contains trailing garbage
    assert not fn("0xZZ")          # not hex


def test_break_delete(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "main"})
    number = bp["number"]

    result = bridge._dispatch_op("break_delete", {"number": number})
    assert result["deleted"] == number

    bp_list = bridge._dispatch_op("break_list", {})
    assert not any(b["number"] == number for b in bp_list)


def test_truncate_value(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    t = bridge_mod._truncate_value
    assert t("short") == "short"
    assert t("x" * 2048) == "x" * 2048  # exactly at the cap: untouched
    big = "x" * 10000
    out = t(big)
    assert len(out) < len(big)
    assert out.startswith("x" * 2048)
    assert "truncated" in out and "10000" in out


def test_print_format_letter(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    seen = {}

    class _V:
        type = "int"

        def __str__(self):
            return "255"

        def format_string(self, format=None):
            seen["fmt"] = format
            return {"x": "0xff", "t": "11111111"}.get(format, "?")

    def _eval(expr):
        seen["expr"] = expr
        return _V()

    monkeypatch.setattr(fake_gdb, "parse_and_eval", _eval)

    # Explicit --fmt param.
    r = bridge._print({"expression": "v", "format": "x"})
    assert r["value"] == "0xff"
    assert seen["fmt"] == "x"

    # GDB muscle-memory `print /t expr`: format extracted, expression stripped.
    r2 = bridge._print({"expression": "/t v"})
    assert r2["value"] == "11111111"
    assert seen["expr"] == "v"
    assert seen["fmt"] == "t"


def test_memory_write_bad_hex_is_actionable(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    with pytest.raises(ValueError, match="invalid hex bytes"):
        bridge._memory_write({"address": 0x1000, "value": "nothex"})


def test_memory_write_strips_0x_prefix(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    res = bridge._memory_write({"address": 0x1000, "value": "0xdeadbeef"})
    assert res["written"] == 4


def test_augment_error_ptrace_hint(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    out = bridge._augment_error(Exception("ptrace: Operation not permitted."))
    assert "ptrace not permitted" in out
    assert "CAP_SYS_PTRACE" in out


def test_augment_error_command_aborted_hint(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    out = bridge._augment_error(Exception("Command aborted."))
    assert "hardware watchpoints" in out
    assert "debug registers" in out


def test_attach_refuses_when_inferior_live(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=4321)  # live
    executed = []
    fake_gdb.execute = lambda cmd, to_string=False: executed.append(cmd)
    with pytest.raises(RuntimeError, match="already debugging"):
        bridge._attach({"pid": 999999})
    assert not executed  # never issued the destructive `attach`


def test_attach_rejects_dead_pid(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)  # no live inferior

    def _no_proc(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(bridge_mod.os, "kill", _no_proc)
    executed = []
    fake_gdb.execute = lambda cmd, to_string=False: executed.append(cmd)
    with pytest.raises(RuntimeError, match="no such process"):
        bridge._attach({"pid": 12345})
    assert not executed


def test_break_set_ignore_count(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("break_set", {"location": "main", "ignore": 3})
    assert result["ignore"] == 3


def test_breakpoint_dict_includes_resolved_location(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    loc = types.SimpleNamespace(
        address=0x401445, source=("workshop.c", 75), function="main", enabled=True
    )
    base = dict(
        number=1, enabled=True, location="main", expression=None, condition=None,
        hit_count=0, temporary=False, pending=False, thread=None, ignore_count=0,
        locations=[loc],
    )
    bp = types.SimpleNamespace(type=fake_gdb.BP_BREAKPOINT, **base)
    d = bridge_mod._breakpoint_to_dict(bp)
    assert d["address"] == "0x401445"
    assert d["file"] == "workshop.c"
    assert d["line"] == 75
    assert d["function"] == "main"
    assert d["location_count"] == 1
    assert d["locations"] == [
        {
            "address": "0x401445",
            "file": "workshop.c",
            "line": 75,
            "function": "main",
            "enabled": True,
        }
    ]

    # Watchpoints are not code locations — the resolved fields must be omitted
    # even if a location object is present.
    wp = types.SimpleNamespace(type=fake_gdb.BP_WATCHPOINT, **base)
    dw = bridge_mod._breakpoint_to_dict(wp)
    assert "address" not in dw
    assert "locations" not in dw


def test_breakpoint_dict_includes_all_multi_locations(monkeypatch):
    """Inlined / multi-location BPs must surface every site, not just the first.

    GDB often places free_msg-style symbols at an inlined site inside a caller
    *and* at the out-of-line body. Agents that only see locs[0] get the wrong
    address.
    """
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    locs = [
        types.SimpleNamespace(
            address=0x401100, source=("msg.c", 20), function="load_msg", enabled=True
        ),
        types.SimpleNamespace(
            address=0x401280, source=("msg.c", 55), function="free_msg", enabled=True
        ),
    ]
    bp = types.SimpleNamespace(
        type=fake_gdb.BP_BREAKPOINT,
        number=3,
        enabled=True,
        location="free_msg",
        expression=None,
        condition=None,
        hit_count=0,
        temporary=False,
        pending=False,
        thread=None,
        ignore_count=0,
        locations=locs,
    )
    d = bridge_mod._breakpoint_to_dict(bp)
    # Top-level fields stay on the first location for backward compatibility.
    assert d["address"] == "0x401100"
    assert d["function"] == "load_msg"
    assert d["file"] == "msg.c"
    assert d["line"] == 20
    assert d["location_count"] == 2
    assert len(d["locations"]) == 2
    assert d["locations"][0]["address"] == "0x401100"
    assert d["locations"][0]["function"] == "load_msg"
    assert d["locations"][1]["address"] == "0x401280"
    assert d["locations"][1]["function"] == "free_msg"
    assert d["locations"][1]["file"] == "msg.c"
    assert d["locations"][1]["line"] == 55


def test_break_delete_multiple(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    a = bridge._dispatch_op("break_set", {"location": "main"})["number"]
    b = bridge._dispatch_op("break_set", {"location": "foo"})["number"]

    result = bridge._dispatch_op("break_delete", {"numbers": [a, b]})
    assert result["deleted"] == [a, b]
    assert {it["number"] for it in result["items"]} == {a, b}

    bp_list = bridge._dispatch_op("break_list", {})
    assert not any(bp["number"] in (a, b) for bp in bp_list)


def test_break_delete_missing_number_reports_it(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    a = bridge._dispatch_op("break_set", {"location": "main"})["number"]
    with pytest.raises(ValueError, match="#999"):
        bridge._dispatch_op("break_delete", {"numbers": [a, 999]})
    # The valid breakpoint must survive a batch that names a missing one.
    bp_list = bridge._dispatch_op("break_list", {})
    assert any(bp["number"] == a for bp in bp_list)


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


def test_thread_override_restores_selected_frame(monkeypatch):
    # `--thread N` switches threads (which resets the frame to 0) and back; the
    # caller's previously-selected frame must be restored, not clobbered.
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    original = fake_gdb.selected_frame()
    bridge._dispatch_op("args", {"thread": 2})
    assert fake_gdb.selected_frame() is original


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
    # A plain step/next/until/finish completion reports reason: step in its own
    # result, consistent with the permanent handler and `status`/`wait`.
    assert result["reason"] == {"kind": "step"}


def test_dispatch_exec_rerun_ignores_restart_kill_exit(monkeypatch):
    """A `run` that restarts a live inferior must report the new run's stop,
    not the spurious code-less `exited` event GDB fires when it kills the
    previous process. Regression for the re-run race (run reported `exited`
    while the program was actually stopped at a breakpoint)."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("break_set", {"location": "main"})
    bp_obj = fake_gdb.breakpoints()[0]
    # The default fake inferior has a nonzero pid, so this `run` is a restart
    # of a live inferior and the swallow is armed.
    assert bridge._inferior_is_live() is True

    def _restart_execute(cmd, to_string=False):
        fake_gdb._execute_log.append(cmd)
        if (cmd.split()[0] if cmd else "") == "run":
            # GDB kills the prior inferior first: a code-less exited event...
            fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(None))
            # ...then the fresh run reaches its breakpoint.
            fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([bp_obj]))
        return ""

    fake_gdb.execute = _restart_execute

    response = bridge.dispatch({"op": "run", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["status"] == "stopped"
    assert result["reason"]["kind"] == "breakpoint-hit"
    assert result["reason"]["number"] == bp["number"]


def test_dispatch_exec_restart_still_reports_real_exit(monkeypatch):
    """The restart-kill swallow is one-shot and code-less only: the new run's
    genuine exit (which carries an exit_code) must still be reported."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    assert bridge._inferior_is_live() is True  # restart scenario

    def _restart_execute(cmd, to_string=False):
        fake_gdb._execute_log.append(cmd)
        if (cmd.split()[0] if cmd else "") == "run":
            fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(None))  # kill
            fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(0))     # real exit
        return ""

    fake_gdb.execute = _restart_execute

    response = bridge.dispatch({"op": "run", "params": {}})
    assert response["ok"] is True
    result = response["result"]
    assert result["status"] == "exited"
    assert result["reason"] == {"kind": "exited", "code": 0}


def test_dispatch_exec_first_run_reports_codeless_exit(monkeypatch):
    """When no inferior is live (first run / pid 0) the swallow stays disarmed,
    so a code-less exit is a genuine outcome and is reported, not eaten."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)  # not live
    assert bridge._inferior_is_live() is False

    def _execute(cmd, to_string=False):
        fake_gdb._execute_log.append(cmd)
        if (cmd.split()[0] if cmd else "") == "run":
            fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(None))
        return ""

    fake_gdb.execute = _execute

    response = bridge.dispatch({"op": "run", "params": {}})
    assert response["ok"] is True
    assert response["result"]["status"] == "exited"


def test_run_with_stdin_file_redirects_fd0(monkeypatch, tmp_path):
    """stdin_file opens the payload and temporarily dup2's it onto fd 0 so the
    inferior inherits a real file (not argv tokens, not a cooked PTY)."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"A" * 8 + b"\x00\x11END\n")

    seen_fd0: list[bytes] = []

    def _execute(cmd, to_string=False):
        fake_gdb._execute_log.append(cmd)
        if (cmd.split()[0] if cmd else "") == "run":
            # During run, fd 0 must be the payload file (raw bytes).
            import os
            data = os.read(0, 64)
            seen_fd0.append(data)
            # Rewind so a real consumer could re-read; tests only need the
            # snapshot. Also fire a stop so dispatch_exec completes.
            os.lseek(0, 0, os.SEEK_SET)
            fake_gdb.events.stop.fire(fake_gdb._FakeStopEvent())
        return ""

    fake_gdb.execute = _execute
    fake_gdb._pending_stop_event = None

    # Capture original stdin identity so we can confirm it is restored.
    import os
    orig_stat = os.fstat(0)

    response = bridge.dispatch({
        "op": "run",
        "params": {"stdin_file": str(payload), "args": ["foo"]},
    })
    assert response["ok"] is True
    assert response["result"]["status"] == "stopped"
    assert "set args foo" in fake_gdb._execute_log
    assert "run" in fake_gdb._execute_log
    assert seen_fd0 == [b"A" * 8 + b"\x00\x11END\n"]
    # GDB's original stdin must be restored after run (keepalive pipe under
    # pry launch; leaving a drained payload file would EOF the session).
    assert os.fstat(0).st_ino == orig_stat.st_ino
    assert os.fstat(0).st_dev == orig_stat.st_dev


def test_run_with_stdin_file_missing_errors(monkeypatch, tmp_path):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    missing = tmp_path / "nope.bin"

    response = bridge.dispatch({
        "op": "run",
        "params": {"stdin_file": str(missing)},
    })
    assert response["ok"] is False
    assert "stdin file not found" in response["error"]
    # Never reached run
    assert not any((c.split()[0] if c else "") == "run" for c in fake_gdb._execute_log)


def test_looks_like_function_name(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    f = bridge_mod.GdbBridge._looks_like_function_name
    assert f("main") is True
    assert f("sum_ids") is True
    assert f("file.c:42") is False   # file:line
    assert f("*0x401000") is False   # address
    assert f("42") is False          # bare line number
    assert f("") is False


def test_connect_executes_target_remote(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    # The remote workflow connects from a bare session (no live inferior).
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)

    result = bridge._dispatch_op("connect", {"target": "localhost:1234"})
    assert result["connected"] == "localhost:1234"
    assert result["status"] == "stopped"
    assert "set tcp connect-timeout 15" in fake_gdb._execute_log
    assert "target remote localhost:1234" in fake_gdb._execute_log


def test_connect_custom_timeout(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)

    result = bridge._dispatch_op("connect", {"target": "localhost:1234", "connect_timeout": 5})
    assert result["connected"] == "localhost:1234"
    assert "set tcp connect-timeout 5" in fake_gdb._execute_log


def test_connect_refuses_when_inferior_live(monkeypatch):
    # `target remote` discards the current inferior before connecting, so a
    # connect while debugging would destroy that session — refuse instead.
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=4321)
    executed = []
    fake_gdb.execute = lambda cmd, to_string=False: executed.append(cmd)
    with pytest.raises(RuntimeError, match="already debugging"):
        bridge._connect({"target": "localhost:1234"})
    assert not any("target remote" in c for c in executed)


def test_connect_clears_stop_reason(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)  # bare session

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


def test_disconnect_refuses_on_local_target(monkeypatch):
    # `disconnect` on a native (local) inferior would detach/kill it, silently
    # destroying the session. It must refuse without issuing the command.
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    native = types.SimpleNamespace(type="native")
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(connection=native)
    executed = []
    fake_gdb.execute = lambda cmd, to_string=False: executed.append(cmd)
    with pytest.raises(RuntimeError, match="not connected to a remote target"):
        bridge._disconnect({})
    assert "disconnect" not in executed


def test_disconnect_allowed_on_remote_target(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    remote = types.SimpleNamespace(type="remote")
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(connection=remote)
    executed = []
    fake_gdb.execute = lambda cmd, to_string=False: executed.append(cmd)
    res = bridge._disconnect({})
    assert res["disconnected"] is True
    assert "disconnect" in executed


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
# kbase helpers + fallback chain (issue #29)
# ---------------------------------------------------------------------------

def test_parse_pwndbg_kbase_output(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    parse = bridge_mod.parse_pwndbg_kbase_output
    assert parse("Found virtual text base address: 0xffffffffb0200000\n") == 0xFFFFFFFFB0200000
    # ANSI-colored
    colored = "\x1b[32mFound virtual text base address: 0xffffffff81000000\x1b[0m"
    assert parse(colored) == 0xFFFFFFFF81000000
    assert parse("Unable to locate the kernel base\n") is None
    assert parse("") is None


def test_parse_qemu_monitor_idt(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    parse = bridge_mod.parse_qemu_monitor_idt
    mon = (
        "RAX=0000000000000000 RBX=0000000000000000\n"
        "IDT=     fffffe0000000000 00000fff\n"
        "CR0=80050033 CR2=0000000000000000\n"
    )
    assert parse(mon) == (0xFFFFFE0000000000, 0xFFF)
    assert parse("no idt here") is None


def test_parse_idt_entry_offset(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    parse = bridge_mod.parse_idt_entry_offset
    # Build a 16-byte x86-64 gate for handler 0xffffffffb0212340
    handler = 0xFFFFFFFFB0212340
    off_lo = handler & 0xFFFF
    off_mid = (handler >> 16) & 0xFFFF
    off_hi = (handler >> 32) & 0xFFFFFFFF
    entry = struct.pack("<HHBBHII", off_lo, 0x10, 0, 0x8E, off_mid, off_hi, 0)
    assert parse(entry) == handler
    # 8-byte i386 gate
    h32 = 0xC0101030
    e32 = struct.pack("<HHBBH", h32 & 0xFFFF, 0x10, 0, 0x8E, (h32 >> 16) & 0xFFFF)
    assert parse(e32) == h32
    with pytest.raises(ValueError):
        parse(b"\x00" * 4)


def test_estimate_kbase_from_handler_align(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    est = bridge_mod.estimate_kbase_from_handler
    # Real Linux: asm_exc_divide_error is _text+0x1030
    handler = 0xFFFFFFFFB0201030
    assert est(handler) == 0xFFFFFFFFB0200000
    # Walk-down: readable region starts lower
    floor = 0xFFFFFFFFB0000000

    def readable(addr: int) -> bool:
        return addr >= floor

    assert est(handler, readable=readable) == floor


def test_kbase_via_pwndbg_success(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    real_exec = fake_gdb.execute

    def _exec(cmd, to_string=False):
        if cmd == "kbase":
            return "Found virtual text base address: 0xffffffffb0200000\n"
        return real_exec(cmd, to_string=to_string)

    fake_gdb.execute = _exec
    result = bridge._dispatch_op("kbase", {})
    assert result["base"] == "0xffffffffb0200000"
    assert result["method"] == "pwndbg"
    assert result["attempts"][0]["ok"] is True


def test_kbase_falls_back_to_idt_when_pwndbg_fails(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    idt_base = 0xFFFFFE0000000000
    handler = 0xFFFFFFFFB0201030  # _text + 0x1030
    text_base = 0xFFFFFFFFB0200000
    off_lo = handler & 0xFFFF
    off_mid = (handler >> 16) & 0xFFFF
    off_hi = (handler >> 32) & 0xFFFFFFFF
    idt_entry = struct.pack("<HHBBHII", off_lo, 0x10, 0, 0x8E, off_mid, off_hi, 0)

    mem: dict[int, bytes] = {idt_base: idt_entry}
    # Mark text region readable in 2MiB steps down to text_base
    for a in range(text_base, handler + 0x1000, 0x200000):
        mem.setdefault(a, b"\x90")

    real_exec = fake_gdb.execute

    def _exec(cmd, to_string=False):
        if cmd == "kbase":
            return (
                "Permission error when attempting to parse page tables with gdb-pt-dump.\n"
                "Unable to locate the kernel base\n"
            )
        if cmd == "monitor info registers":
            return f"IDT=     {idt_base:016x} 00000fff\n"
        return real_exec(cmd, to_string=to_string)

    def _read_memory(addr, length):
        # Exact page or any address in a mapped 2MiB window from text_base..handler
        if addr in mem:
            data = mem[addr]
            return data[:length] if len(data) >= length else data + bytes(length - len(data))
        if text_base <= addr < handler + 0x10000:
            return bytes(length)
        raise OSError(f"Cannot access memory at address {addr:#x}")

    fake_gdb.execute = _exec
    fake_gdb.selected_inferior().read_memory = _read_memory

    result = bridge._dispatch_op("kbase", {})
    assert result["base"] == hex(text_base)
    assert result["method"] == "idt"
    assert result["handler"] == hex(handler)
    assert result["attempts"][0]["method"] == "pwndbg"
    assert result["attempts"][0].get("ok") is not True
    assert result["attempts"][1]["ok"] is True


def test_kbase_all_methods_fail(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    real_exec = fake_gdb.execute

    def _exec(cmd, to_string=False):
        if cmd == "kbase":
            return "Unable to locate the kernel base\n"
        if cmd == "monitor info registers":
            raise fake_gdb.error("Monitor command failed")
        if cmd.startswith("info"):
            return ""
        return real_exec(cmd, to_string=to_string)

    fake_gdb.execute = _exec
    # parse_and_eval shouldn't yield a kernel idtr/vbar
    fake_gdb.parse_and_eval = lambda expr: (_ for _ in ()).throw(ValueError("nope"))

    with pytest.raises(RuntimeError, match="unable to locate kernel base"):
        bridge._dispatch_op("kbase", {})


# ---------------------------------------------------------------------------
# Feature 1: Lock-free interrupt
# ---------------------------------------------------------------------------

def test_interrupt_bypasses_exec_ops(monkeypatch):
    """interrupt is handled before EXEC_OPS check, without locks."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    bridge._running = True  # simulate a running foreground exec

    response = bridge.dispatch({"op": "interrupt", "params": {}})
    assert response["ok"] is True
    assert response["result"]["interrupted"] is True
    assert "interrupt" in fake_gdb._execute_log


def test_interrupt_when_idle_is_noop(monkeypatch):
    """interrupt on a stopped/exited inferior reports rather than lying."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    # Fresh bridge: _running is False.

    response = bridge.dispatch({"op": "interrupt", "params": {}})
    assert response["ok"] is True
    assert response["result"]["interrupted"] is False
    assert response["result"]["state"] == "stopped"
    assert "interrupt" not in fake_gdb._execute_log


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


def test_break_set_rebase_image_base_exceeds_offset(monkeypatch):
    # A wrong --image-base larger than the offset used to silently produce a
    # wrapped negative address and a breakpoint at garbage.
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    with pytest.raises(ValueError, match="exceeds the offset"):
        bridge._break_set({
            "location": "*0x100",
            "rebase_module": "workshop",
            "image_base": 0x401000,
        })


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


# ---------------------------------------------------------------------------
# Agent-usability improvements
# ---------------------------------------------------------------------------

def test_watchpoint_reason_reports_old_and_new_values(monkeypatch):
    """A watchpoint-hit reason carries old -> new values (re-evaluated)."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    seq = ["0x3", "0x4"]  # set-time seed, then the value at the hit
    state = {"i": 0}

    class _V:
        def __init__(self, s):
            self.s = s
            self.type = "int"

        def __str__(self):
            return self.s

        def __int__(self):
            return int(self.s, 16)

    def _eval(expr):
        s = seq[min(state["i"], len(seq) - 1)]
        state["i"] += 1
        return _V(s)

    fake_gdb.parse_and_eval = _eval

    bridge = bridge_mod.GdbBridge()
    bridge._dispatch_op("watch_set", {"expression": "counter"})  # seeds 0x3
    bp_obj = fake_gdb.breakpoints()[0]
    bp_obj.type = fake_gdb.BP_HARDWARE_WATCHPOINT

    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([bp_obj]))  # evals 0x4
    reason = bridge._stop_info()["reason"]
    assert reason["kind"] == "watchpoint-hit"
    assert reason["new_value"] == "0x4"
    assert reason["old_value"] == "0x3"


def test_break_delete_returns_kind(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("watch_set", {"expression": "buf"})
    result = bridge._dispatch_op("break_delete", {"number": bp["number"]})
    assert result["deleted"] == bp["number"]
    assert result["kind"] == "watchpoint"


def test_print_flags_static_read_without_live_inferior(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("print", {"expression": "counter"})
    assert result["live"] is False
    assert "static" in result["note"]


def test_print_no_note_when_inferior_live(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("print", {"expression": "argc"})
    assert "note" not in result
    assert "live" not in result


def test_register_write(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("register_write", {"name": "$rip", "value": "0x401234"})
    assert result["register"] == "rip"
    assert result["value"] == "0x401234"
    assert result["readback"] == "42"
    assert any("set $rip = 0x401234" in c for c in fake_gdb._execute_log)


def test_mappings_parses_and_filters(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    sample = (
        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
        "      0x555555554000     0x555555555000     0x1000        0x0  r-xp   /usr/bin/app\n"
        "      0x7ffff7d00000     0x7ffff7d22000    0x22000        0x0  r--p   /usr/lib/libc.so.6\n"
    )
    original = fake_gdb.execute

    def _exec(cmd, to_string=False):
        if cmd.startswith("info proc mappings"):
            return sample
        return original(cmd, to_string)

    fake_gdb.execute = _exec
    bridge = bridge_mod.GdbBridge()

    allm = bridge._dispatch_op("mappings", {})
    assert len(allm) == 2
    assert allm[0]["start"] == hex(0x555555554000)
    assert allm[0]["perms"] == "r-xp"
    assert allm[0]["objfile"] == "/usr/bin/app"
    assert allm[0]["size"] == 0x1000

    libc = bridge._dispatch_op("mappings", {"name": "libc"})
    assert len(libc) == 1 and "libc" in libc[0]["objfile"]

    one = bridge._dispatch_op("mappings", {"contains": "0x555555554500"})
    assert len(one) == 1 and one[0]["objfile"] == "/usr/bin/app"


def test_disasm_annotates_symbol(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    original = fake_gdb.execute

    def _exec(cmd, to_string=False):
        if cmd.startswith("info symbol"):
            return "main + 4 in section .text\n"
        return original(cmd, to_string)

    fake_gdb.execute = _exec
    bridge = bridge_mod.GdbBridge()

    insns = bridge._dispatch_op("disasm", {"location": "main", "count": 2})
    assert insns[0]["symbol"] == "main+4"


def test_disasm_bare_function_name_is_bounded_to_function(monkeypatch):
    """A bare function name with no --count disassembles the whole function via
    GDB's `disassemble <fn>` (which stops at the real end), not a fixed 20-instr
    count that bleeds past `ret` into the following function."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("disasm", {"location": "main"})
    # The fake `disassemble` returns a single bounded instruction; the fixed
    # count architecture path would have returned 20 "nop"s instead.
    assert [e["asm"] for e in result] == ["push   %rbp"]
    assert all(e["asm"] != "nop" for e in result)


def test_disasm_explicit_count_is_not_clamped(monkeypatch):
    """An explicit --count is honored verbatim via the architecture path even
    for a function name — the function-boundary clamp only applies when no
    count is given."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("disasm", {"location": "main", "count": 5})
    assert len(result) == 5
    assert all(e["asm"] == "nop" for e in result)  # the arch fast path, not disassemble


def test_is_bare_symbol_name(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    f = bridge_mod.GdbBridge._is_bare_symbol_name
    assert f("main") is True
    assert f("crash_path") is True
    assert f("_start") is True
    assert f("0x401000") is False      # address
    assert f("$pc") is False           # register
    assert f("*0x401000") is False     # deref expression
    assert f("main,+8") is False       # start,+len range
    assert f("a.c:42") is False        # file:line
    assert f("Animal::speak") is False # qualified name (falls back to count path)
    assert f("42") is False            # bare line number
    assert f("") is False


@pytest.mark.parametrize("gdb_msg", ["No registers.", "No stack."])
def test_backtrace_no_inferior_is_actionable(monkeypatch, gdb_msg):
    # GDB 17.2 raises "No registers." (not "No stack.") from newest_frame()
    # when nothing is running; both must surface the actionable hint.
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _boom():
        raise fake_gdb.error(gdb_msg)

    fake_gdb.newest_frame = _boom
    # No inferior -> pid 0, so the hint resolves to "not running".
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    bridge = bridge_mod.GdbBridge()

    resp = bridge.dispatch({"op": "backtrace", "params": {}})
    assert resp["ok"] is False
    assert "not running" in resp["error"]


def test_register_write_rejects_unknown_register(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    resp = bridge.dispatch(
        {"op": "register_write", "params": {"name": "bogus_reg", "value": "0x1"}}
    )
    assert resp["ok"] is False
    assert "unknown register" in resp["error"]
    # Must not have silently created a convenience variable.
    assert not any("set $bogus_reg" in c for c in fake_gdb._execute_log)


def test_register_write_requires_live_inferior(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _no_frame():
        raise fake_gdb.error("No frame selected.")

    fake_gdb.selected_frame = _no_frame
    # No inferior -> pid 0, so the error says "not running" (vs "running").
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    bridge = bridge_mod.GdbBridge()

    resp = bridge.dispatch(
        {"op": "register_write", "params": {"name": "rax", "value": "0x1"}}
    )
    assert resp["ok"] is False
    assert "not running" in resp["error"]


def test_snapshot_drops_unevaluable_watchpoint(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    bp = bridge._dispatch_op("watch_set", {"expression": "counter"})  # seeds value
    bp_obj = fake_gdb.breakpoints()[0]
    bp_obj.type = fake_gdb.BP_HARDWARE_WATCHPOINT
    assert bridge._watchpoint_values.get(bp["number"]) is not None

    def _boom(expr):
        raise fake_gdb.error("value optimized out")

    fake_gdb.parse_and_eval = _boom
    bridge._snapshot_watchpoints()
    # Stale snapshot dropped, so the next hit won't diff against a stale value.
    assert bp["number"] not in bridge._watchpoint_values


def test_dispatch_augments_no_symbol_error(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _boom(expr):
        raise fake_gdb.error('No symbol "foo" in current context.')

    fake_gdb.parse_and_eval = _boom
    bridge = bridge_mod.GdbBridge()

    resp = bridge.dispatch({"op": "print", "params": {"expression": "foo"}})
    assert resp["ok"] is False
    assert "functions --query" in resp["error"]


def _write_minimal_elf64(path: Path, text_vaddr: int) -> None:
    """Write a minimal valid ELF64-LE file with a .text section at text_vaddr."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"  # ".text"@1, ".shstrtab"@7
    text_name, str_name = 1, 7
    ehsize, shentsize, shnum, shstrndx = 64, 64, 3, 2
    shoff = ehsize + len(shstrtab)

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELFCLASS64
    ehdr[5] = 1  # ELFDATA2LSB
    ehdr[6] = 1  # version
    struct.pack_into("<H", ehdr, 16, 2)            # e_type ET_EXEC
    struct.pack_into("<H", ehdr, 18, 0x3E)         # e_machine x86-64
    struct.pack_into("<I", ehdr, 20, 1)            # e_version
    struct.pack_into("<Q", ehdr, 0x28, shoff)      # e_shoff
    struct.pack_into("<H", ehdr, 0x34, ehsize)     # e_ehsize
    struct.pack_into("<H", ehdr, 0x3A, shentsize)  # e_shentsize
    struct.pack_into("<H", ehdr, 0x3C, shnum)      # e_shnum
    struct.pack_into("<H", ehdr, 0x3E, shstrndx)   # e_shstrndx

    def shdr(name, sh_type, addr=0, off=0, size=0):
        b = bytearray(64)
        struct.pack_into("<I", b, 0, name)     # sh_name
        struct.pack_into("<I", b, 4, sh_type)  # sh_type
        struct.pack_into("<Q", b, 0x10, addr)  # sh_addr
        struct.pack_into("<Q", b, 0x18, off)   # sh_offset
        struct.pack_into("<Q", b, 0x20, size)  # sh_size
        return bytes(b)

    sections = (
        shdr(0, 0)                                            # null
        + shdr(text_name, 1, addr=text_vaddr)                 # .text (PROGBITS)
        + shdr(str_name, 3, off=ehsize, size=len(shstrtab))   # .shstrtab (STRTAB)
    )
    path.write_bytes(bytes(ehdr) + shstrtab + sections)


def test_elf_text_vaddr_reads_dot_text(monkeypatch, tmp_path):
    bridge_mod, _ = _load_bridge(monkeypatch)
    elf = tmp_path / "fake.elf"
    _write_minimal_elf64(elf, 0xFFFFFFFF81000000)
    assert bridge_mod._elf_text_vaddr(str(elf)) == 0xFFFFFFFF81000000
    assert bridge_mod._elf_text_vaddr(str(tmp_path / "missing")) is None


def test_load_without_base_uses_file(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("load", {"path": "/x/vmlinux"})
    assert result == {"loaded": "/x/vmlinux"}
    assert any(c == "file /x/vmlinux" for c in fake_gdb._execute_log)


def test_load_with_slide_offsets_all_sections(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("load", {"path": "/x/vmlinux", "slide": "0x7000000"})
    assert result["loaded"] == "/x/vmlinux"
    assert result["slide"] == hex(0x7000000)
    log = fake_gdb._execute_log
    # Drops any prior copy, then offsets EVERY section by the slide (-o) so both
    # text and data resolve — and never loads a link-time `file` primary.
    assert any(c == "remove-symbol-file /x/vmlinux" for c in log)
    assert any(c == "add-symbol-file /x/vmlinux -o 0x7000000" for c in log)
    assert not any(c.startswith("file ") for c in log)


def test_load_with_base_computes_slide_from_elf(monkeypatch, tmp_path):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    elf = tmp_path / "vmlinux"
    _write_minimal_elf64(elf, 0xFFFFFFFF81000000)

    base = 0xFFFFFFFF88000000
    result = bridge._dispatch_op("load", {"path": str(elf), "base": hex(base)})
    assert result["base"] == hex(base)
    assert result["slide"] == hex(0x7000000)  # base - link .text
    assert any(
        c == f"add-symbol-file {elf} -o 0x7000000" for c in fake_gdb._execute_log
    )


def test_load_with_base_errors_when_text_unreadable(monkeypatch, tmp_path):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    notelf = tmp_path / "notelf"
    notelf.write_bytes(b"not an elf")

    resp = bridge.dispatch(
        {"op": "load", "params": {"path": str(notelf), "base": "0xffffffff88000000"}}
    )
    assert resp["ok"] is False
    assert "--slide" in resp["error"]


def test_parse_disassemble_output(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    sample = (
        "Dump of assembler code for function main:\n"
        "   0x0000000000401136 <+0>:\tpush   %rbp\n"
        "=> 0x000000000040113a <main+4>:\tmov    %rsp,%rbp\n"
        "End of assembler dump.\n"
    )
    rows = bridge_mod._parse_disassemble_output(sample)
    assert len(rows) == 2
    assert rows[0] == {"address": "0x0000000000401136", "asm": "push   %rbp", "symbol": "+0"}
    assert rows[1]["address"] == "0x000000000040113a"
    assert rows[1]["symbol"] == "main+4"


def test_function_designator_and_qualified_name(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    des = bridge_mod._function_designator
    qn = bridge_mod._function_qualified_name
    assert des("static int add(int, int)") == "add(int, int)"
    assert des("static double add(double, double)") == "add(double, double)"
    assert des("int Animal::speak() const") == "Animal::speak() const"
    assert des("int main(int, char **)") == "main(int, char **)"
    assert qn("static int add(int, int)") == "add"
    assert qn("int Animal::speak() const") == "Animal::speak"
    assert qn("static char *greeting(const char *)") == "greeting"
    assert des("int data") is None  # no parameter list


def test_parse_info_functions_resolves_cpp_overloads(monkeypatch):
    """Each C++ overload resolves to its OWN address via the full signature,
    and a qualified member name resolves at all — instead of every same-named
    function collapsing onto the single address the bare name binds to."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    # Distinct address per resolvable designator. The bare overloaded name
    # binds to one overload (the double one here); the *unqualified* member
    # name `speak` does not resolve at all (mirrors real GDB).
    addrs = {
        "&'add(int, int)'": 0x23E9,
        "&'add(double, double)'": 0x2401,
        "&'add'": 0x2401,
        "&'Animal::speak() const'": 0x2380,
        "&'Animal::speak'": 0x2380,
        "&'Dog::speak() const'": 0x2440,
        "&'Dog::speak'": 0x2440,
        "&'main(int, char **)'": 0x24C8,
        "&'main'": 0x24C8,
    }

    class _V:
        def __init__(self, n):
            self._n = n

        def __int__(self):
            return self._n

    def _eval(expr):
        if expr in addrs:
            return _V(addrs[expr])
        raise fake_gdb.error(f"No symbol {expr!r} in current context.")

    fake_gdb.parse_and_eval = _eval

    output = (
        "All defined functions:\n\n"
        "File zoo.cpp:\n"
        "17:\tstatic int add(int, int);\n"
        "18:\tstatic double add(double, double);\n"
        "9:\tint Animal::speak() const;\n"
        "14:\tint Dog::speak() const;\n"
        "20:\tint main(int, char **);\n"
    )
    by_sig = {r["signature"]: r for r in bridge_mod._parse_info_functions(output)}
    assert by_sig["static int add(int, int)"]["address"] == "0x23e9"
    assert by_sig["static double add(double, double)"]["address"] == "0x2401"
    assert by_sig["int Animal::speak() const"]["address"] == "0x2380"
    assert by_sig["int Dog::speak() const"]["address"] == "0x2440"
    assert by_sig["int main(int, char **)"]["address"] == "0x24c8"


def test_trace_arms_when_pc_already_in_range(monkeypatch):
    """If the inferior is already stopped inside the code range when the trace
    starts, the watchpoint arms immediately — so a trace begun mid-run (e.g.
    after `pry interrupt`) isn't a silent no-op when range_start is a one-shot
    address that won't be hit again."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    # Fake selected frame PC is 0x401000; this range brackets it.
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()  # `continue` stops
    resp = bridge.dispatch({"op": "trace", "params": {
        "watch_addr": "0x404020", "range_start": "0x400000", "range_end": "0x402000",
    }})
    assert resp["ok"] is True
    result = resp["result"]
    assert result["armed"] is True
    assert "note" not in result  # armed -> no false-negative warning


def test_trace_reports_never_armed_when_range_not_entered(monkeypatch):
    """When execution never enters the range (range_start not on the path and
    the PC isn't already inside), the result is armed=False with an explanatory
    note instead of a silent, misleading '0 hits'."""
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    # Fake PC 0x401000 is outside this range, and the range_start breakpoint is
    # never hit, so the watchpoint stays disarmed.
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()
    resp = bridge.dispatch({"op": "trace", "params": {
        "watch_addr": "0x404020", "range_start": "0x500000", "range_end": "0x501000",
    }})
    assert resp["ok"] is True
    result = resp["result"]
    assert result["armed"] is False
    assert result["hit_count"] == 0
    assert "never armed" in result.get("note", "")


def test_finish_return_value_void_and_missing(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    # No finishing frame captured -> nothing to report.
    bridge._finish_frame = None
    bridge._finish_ret_type = None
    assert bridge._finish_return_value() is None


def test_finish_return_value_skips_when_frame_still_valid(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    class _Frame:
        def is_valid(self):
            return True  # frame didn't actually return (stopped early)

    class _Type:
        def strip_typedefs(self):
            return self

    bridge._finish_frame = _Frame()
    bridge._finish_ret_type = _Type()
    # Must not fabricate a value when the frame is still on the stack.
    assert bridge._finish_return_value() is None


def test_display_add_list_remove(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()

    a = bridge._display_add({"expression": "head"})
    assert a == {"number": 1, "expr": "head"}
    b = bridge._display_add({"expression": "argc"})
    assert b["number"] == 2

    listed = bridge._display_list({})
    # _safe_eval_str -> fake parse_and_eval returns 42 for any expr.
    assert listed == [
        {"number": 1, "expr": "head", "value": "42"},
        {"number": 2, "expr": "argc", "value": "42"},
    ]

    assert bridge._display_remove({"number": 1}) == {"removed": 1}
    assert [d["number"] for d in bridge._displays] == [2]
    with pytest.raises(ValueError):
        bridge._display_remove({"number": 99})


def test_display_add_with_format(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    entry = bridge._display_add({"expression": "head", "format": "x"})
    assert entry["format"] == "x"

    seen = {}

    class _V:
        def format_string(self, format=None):
            seen["fmt"] = format
            return "0x2a"

        def __str__(self):
            return "42"

    monkeypatch.setattr(fake_gdb, "parse_and_eval", lambda e: _V())
    listed = bridge._display_list({})
    assert listed[0]["value"] == "0x2a"
    assert seen["fmt"] == "x"


def test_display_eval_error_shows_reason(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    bridge._display_add({"expression": "argc"})

    def _boom(expr):
        raise Exception('No symbol "argc" in current context.')
    monkeypatch.setattr(fake_gdb, "parse_and_eval", _boom)

    value = bridge._display_list({})[0]["value"]
    assert value.startswith("<error:")
    assert "No symbol" in value


def test_examine_builds_command(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    out = bridge._examine({"address": "0x1000", "spec": "4xw"})
    assert out["command"] == "x/4xw 0x1000"
    # From parts:
    out = bridge._examine({"address": "$rsp", "count": 8, "format": "x", "size": "w"})
    assert out["command"] == "x/8xw $rsp"


def test_catchpoint_whats_parse(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    sample = (
        "Num     Type           Disp Enb Address            What\n"
        "1       breakpoint     keep y   0x0000000000401156 in make_node\n"
        "3       catchpoint     keep y                      syscall \"write\"\n"
    )
    fake_gdb.execute = lambda cmd, to_string=False: sample
    whats = bridge_mod.GdbBridge._catchpoint_whats()
    assert whats == {3: 'syscall "write"'}


def test_disasm_fallback_returns_list(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _unresolvable(expr):
        raise fake_gdb.error("not a single address")

    fake_gdb.parse_and_eval = _unresolvable  # force the range-expr fallback path
    bridge = bridge_mod.GdbBridge()
    result = bridge._dispatch_op("disasm", {"location": "main,+8"})
    assert isinstance(result, list)
    assert result[0]["address"].startswith("0x")
    assert "asm" in result[0]


# ---------------------------------------------------------------------------
# Edge-case hardening (adversarial hunt fixes)
# ---------------------------------------------------------------------------

def test_status_not_started_vs_exited(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    fake_gdb.selected_thread = lambda: None
    bridge = bridge_mod.GdbBridge()

    resp = bridge.dispatch({"op": "status", "params": {}})
    assert resp["result"]["state"] == "not-started"

    bridge._has_run = True  # simulate a run that has since exited
    resp2 = bridge.dispatch({"op": "status", "params": {}})
    assert resp2["result"]["state"] == "exited"


def test_status_reports_exit_code(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    fake_gdb.selected_inferior = lambda: types.SimpleNamespace(pid=0)
    fake_gdb.selected_thread = lambda: None
    bridge = bridge_mod.GdbBridge()
    bridge._has_run = True

    # The exited event records the code on the bridge.
    fake_gdb.events.exited.fire(fake_gdb._FakeExitedEvent(42))

    result = bridge.dispatch({"op": "status", "params": {}})["result"]
    assert result["state"] == "exited"
    assert result["exit_code"] == 42
    assert result["reason"] == {"kind": "exited", "code": 42}


def test_register_write_while_running_says_interrupt(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _no_frame():
        raise fake_gdb.error("No frame selected.")

    fake_gdb.selected_frame = _no_frame  # frame unavailable while running
    bridge = bridge_mod.GdbBridge()       # default fake pid is live (running)

    resp = bridge.dispatch({"op": "register_write", "params": {"name": "rax", "value": "0x1"}})
    assert resp["ok"] is False
    assert "running" in resp["error"] and "interrupt" in resp["error"].lower()


def test_augment_error_does_not_overmatch_substrings(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    def _boom(expr):
        raise fake_gdb.error("No registers available in my custom module")

    fake_gdb.parse_and_eval = _boom
    bridge = bridge_mod.GdbBridge()
    resp = bridge.dispatch({"op": "print", "params": {"expression": "x"}})
    assert resp["ok"] is False
    assert "not running" not in resp["error"]
    assert "interrupt" not in resp["error"].lower()


def test_load_rejects_base_and_slide_together(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    resp = bridge.dispatch({"op": "load", "params": {"path": "/x", "base": "0x1000", "slide": "0x10"}})
    assert resp["ok"] is False
    assert "both" in resp["error"]


def test_load_with_src_sets_directory_and_substitute_path(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    src = "/home/user/linux-src"
    result = bridge._dispatch_op(
        "load", {"path": "/x/vmlinux", "src": src}
    )
    assert result["loaded"] == "/x/vmlinux"
    assert result["src"] == src
    log = fake_gdb._execute_log
    assert any(c == f"directory {src}" for c in log)
    assert any(c == f"set substitute-path /src {src}" for c in log)


def test_load_with_gdb_scripts_sources_and_safe_path(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    scripts = "/home/user/linux/scripts/gdb/vmlinux-gdb.py"
    result = bridge._dispatch_op(
        "load",
        {
            "path": "/x/vmlinux",
            "slide": "0x1000",
            "src": "/home/user/linux",
            "gdb_scripts": scripts,
        },
    )
    assert result["gdb_scripts"] == scripts
    assert result["src"] == "/home/user/linux"
    log = fake_gdb._execute_log
    assert "add-auto-load-safe-path /home/user/linux/scripts/gdb" in log
    assert "add-auto-load-safe-path /home/user/linux/scripts" in log
    assert f"source {scripts}" in log
    assert "directory /home/user/linux" in log
    # add-auto-load-safe-path MUST precede `source`, or GDB refuses to auto-load
    # the script. This ordering is the whole point of the feature — pin it.
    assert log.index("add-auto-load-safe-path /home/user/linux/scripts/gdb") < log.index(
        f"source {scripts}"
    )
    # Relocated load still happens first.
    assert "add-symbol-file /x/vmlinux -o 0x1000" in log


def test_load_gdb_scripts_source_failure_raises(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    orig = fake_gdb.execute

    def _execute(cmd, to_string=False):
        if cmd.startswith("source "):
            raise fake_gdb.error("No such file or directory")
        return orig(cmd, to_string=to_string)

    fake_gdb.execute = _execute
    resp = bridge.dispatch(
        {
            "op": "load",
            "params": {
                "path": "/x/vmlinux",
                "gdb_scripts": "/missing/vmlinux-gdb.py",
            },
        }
    )
    assert resp["ok"] is False
    assert "failed to source" in resp["error"]
    assert "/missing/vmlinux-gdb.py" in resp["error"]


def test_disasm_count_zero_or_negative_returns_empty_list(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    assert bridge._dispatch_op("disasm", {"count": 0}) == []
    assert bridge._dispatch_op("disasm", {"count": -5}) == []


def test_parse_addr_masks_high_bit_to_unsigned(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)

    class _Neg:
        def __int__(self):
            return -10485760  # 0xffffffffff600000 interpreted signed

    fake_gdb.parse_and_eval = lambda e: _Neg()
    assert bridge_mod.GdbBridge._parse_addr("$rax") == 0xFFFFFFFFFF600000


def test_watchpoint_unreadable_new_value_keeps_old(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    bp = bridge._dispatch_op("watch_set", {"expression": "p"})  # seeds "42"
    bp_obj = fake_gdb.breakpoints()[0]
    bp_obj.type = fake_gdb.BP_HARDWARE_WATCHPOINT

    def _boom(expr):
        raise fake_gdb.error("Cannot access memory")

    fake_gdb.parse_and_eval = _boom
    reason = bridge._bp_reason(bp_obj)
    assert reason["old_value"] == "42"
    assert reason["new_value"] == "<unreadable>"
