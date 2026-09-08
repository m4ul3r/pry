from __future__ import annotations

from collections import deque
import types

import pytest

from tests.test_bridge import _load_bridge


def _trace_session(monkeypatch, instructions, *, pc=0x1000, scheduler="off"):
    """Execute one real-shaped instruction transition per fake GDB stepi.

    instructions maps PC to (successor, assembly, watched-access). Continue
    executes outside code until a breakpoint or exit, so leaked watchpoints
    observably stop on caller accesses instead of being silently ignored.
    Execution and stop delivery are queued until execute returns, matching
    GDB's event loop rather than firing a stop recursively inside execute.
    """
    bridge_mod, gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    frame = gdb.newest_frame()
    frame._pc = pc
    writes = []
    commands = []
    original_execute = gdb.execute
    state = {
        "scheduler": scheduler, "fail": None, "other_thread": False,
        "exited": False, "scheduler_after_exit": 0, "resume_schedulers": [],
    }
    gdb.parameter = lambda name: state["scheduler"]
    callbacks = deque()
    pumping = False

    def post_event(callback):
        nonlocal pumping
        callbacks.append(callback)
        if pumping:
            return
        pumping = True
        try:
            while callbacks:
                callbacks.popleft()()
        finally:
            pumping = False

    gdb.post_event = post_event

    def disassemble(addr, count=1):
        return [{"addr": addr, "asm": instructions[addr][1], "length": 1}]

    frame.architecture = lambda: types.SimpleNamespace(disassemble=disassemble)

    def deliver_execution(command):
        gdb.events.cont.fire(types.SimpleNamespace())
        while True:
            current = frame.pc()
            if current not in instructions:
                state["exited"] = True
                gdb.events.exited.fire(gdb._FakeExitedEvent(0))
                return ""
            successor, _, watched = instructions[current]
            wp = next((bp for bp in gdb.breakpoints() if bp.type == gdb.BP_WATCHPOINT), None)
            if watched:
                writes.append(current)
            frame._pc = successor
            bps = [bp for bp in gdb.breakpoints()
                   if bp.type == gdb.BP_BREAKPOINT and bp.enabled
                   and bp.location == f"*{hex(successor)}"]
            if watched and wp is not None and wp.enabled:
                bps.append(wp)
            if bps:
                event = gdb._FakeBreakpointEvent(bps)
                if state["other_thread"]:
                    event.inferior_thread = gdb.selected_inferior().threads()[1]
                gdb.events.stop.fire(event)
                return ""
            if command == "stepi":
                gdb.events.stop.fire(gdb._FakeStopEvent())
                return ""

    def execute(command, to_string=False):
        commands.append(command)
        if command.startswith("set scheduler-locking "):
            if state["exited"]:
                state["scheduler_after_exit"] += 1
                raise gdb.error("Target exec cannot support this command.")
            state["scheduler"] = command.rsplit(" ", 1)[1]
            return ""
        if command not in {"stepi", "continue"}:
            return original_execute(command, to_string=to_string)
        if state["fail"]:
            raise gdb.error(state["fail"])
        state["resume_schedulers"].append((command, state["scheduler"]))
        callbacks.append(lambda: deliver_execution(command))
        return ""

    gdb.execute = execute
    params = {"watch_addr": "0x4000", "range_start": "0x1000", "range_end": "0x1010"}
    return bridge, gdb, params, writes, commands, state


def test_trace_restores_scheduler_before_async_exit(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store watched", True),
        0x1001: (0x2000, "ret", False),
    }, scheduler="replay")
    result = bridge._dispatch_trace(params)["result"]
    assert result["hit_count"] == 1
    assert result["stop_info"]["status"] == "exited"
    assert state["scheduler"] == "replay"
    assert state["scheduler_after_exit"] == 0
    assert state["resume_schedulers"] == [
        ("stepi", "step"), ("stepi", "step"), ("continue", "replay"),
    ]
    assert gdb.breakpoints() == []


def test_trace_excludes_caller_access_after_return(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "ret", False),
        0x2000: (0x2001, "mov [watched], eax", True),
    })
    result = bridge._dispatch_trace(params)["result"]
    assert result["armed"] is True
    assert result["hits"] == []
    assert result["unattributed_count"] == 0
    assert writes == [0x2000]
    assert result["stop_info"]["status"] == "exited"
    assert gdb.breakpoints() == []
    assert state["scheduler"] == "off"


def test_trace_supersedes_completed_background_stop(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x900: (0x1000, "jmp entry", False),
        0x1000: (0x2000, "ret", False),
    }, pc=0x900)
    entry = gdb.Breakpoint("*0x1000")
    bridge._dispatch_exec("continue", {"_background": True})
    assert bridge._dispatch_wait({})["result"]["status"] == "stopped"
    entry.delete()

    bridge._dispatch_trace(params)
    result = bridge._dispatch_wait({})["result"]
    assert result["state"] == result["status"] == "exited"
    assert result["reason"]["code"] == 0


def test_trace_branch_exit_and_repeated_entry(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1004, "mov [watched], eax", True),
        0x1004: (0x2000, "jmp caller", False),
        0x2000: (0x2004, "mov [watched], ebx", True),
        0x2004: (0x1000, "jmp range_start", False),
    })
    params["max_hits"] = 3
    result = bridge._dispatch_trace(params)["result"]
    assert [hit["pc"] for hit in result["hits"]] == ["0x1000"] * 3
    assert writes == [0x1000, 0x2000, 0x1000, 0x2000, 0x1000]
    assert result["truncated"] is True
    assert gdb.newest_frame().pc() == 0x1004
    assert gdb.breakpoints() == []


def test_trace_retains_last_instruction_ending_at_range_end(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1010, "mov [watched], eax", True),
        0x1010: (0x2000, "mov eax, 42", False),
    })
    params["max_hits"] = 1
    result = bridge._dispatch_trace(params)["result"]
    assert result["hits"] == [{
        "pc": "0x1000", "asm": "mov [watched], eax",
        "stop_pc": "0x1010", "stop_asm": "mov eax, 42",
        "attribution": "instruction-step",
    }]
    assert gdb.newest_frame().pc() == 0x1010
    assert writes == [0x1000]
    assert commands.count("stepi") == 1
    assert result["stop_info"]["reason"] == {"kind": "trace-limit"}
    assert gdb.breakpoints() == []


@pytest.mark.parametrize("assembly,target", [("ret", 0x2000), ("call helper", 0x3000)])
def test_trace_control_transfer_access_uses_executed_instruction(monkeypatch, assembly, target):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (target, assembly, True),
        target: (target + 1, "nop", False),
    })
    params["max_hits"] = 1
    hit = bridge._dispatch_trace(params)["result"]["hits"][0]
    assert hit["pc"] == "0x1000"
    assert hit["asm"] == assembly
    assert hit["stop_pc"] == hex(target)
    assert hit["stop_asm"] == "nop"


def test_trace_resumes_midrange_after_outside_callee_returns(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "call helper", False),
        0x2000: (0x2001, "store outside", True),
        0x2001: (0x1001, "ret", False),
        0x1001: (0x1002, "store inside", True),
    })
    params["max_hits"] = 1
    result = bridge._dispatch_trace(params)["result"]
    assert writes == [0x2000, 0x1001]
    assert [hit["pc"] for hit in result["hits"]] == ["0x1001"]
    assert result["truncated"] is True
    assert gdb.newest_frame().pc() == 0x1002
    assert gdb.breakpoints() == []


def test_trace_does_not_need_post_instruction_pc(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1000, "access trapping before completion", True),
    })
    params["max_hits"] = 1
    hit = bridge._dispatch_trace(params)["result"]["hits"][0]
    assert hit["pc"] == "0x1000"
    assert hit["stop_pc"] == "0x1000"
    assert hit["asm"] == "access trapping before completion"
    assert writes == [0x1000]


def test_trace_reports_missing_decode_at_possible_call_exit(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "call helper", False),
        0x2000: (0x1001, "ret", False),
        0x1001: (0x1002, "store inside", True),
    })
    def unavailable(addr, count=1):
        raise gdb.error("Cannot access instruction memory")
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(disassemble=unavailable)
    result = bridge._dispatch_trace(params)["result"]
    assert result["hits"] == []
    assert result.get("note")
    assert result["stop_info"]["reason"] == {"kind": "trace-unattributed"}
    assert gdb.newest_frame().pc() == 0x2000
    assert writes == []
    assert gdb.breakpoints() == []


def test_trace_exact_cap_stops_before_second_write(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1004, "store first", True),
        0x1004: (0x1008, "store second", True),
    }, scheduler="on")
    params["max_hits"] = 1
    result = bridge._dispatch_trace(params)["result"]
    assert result["hit_count"] == 1
    assert writes == [0x1000]
    assert gdb.newest_frame().pc() == 0x1004
    assert state["scheduler"] == "on"
    assert gdb.breakpoints() == []


def test_trace_never_entered_is_not_entered_without_access(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x2000: (0x2004, "mov [watched], eax", True),
    }, pc=0x2000)
    result = bridge._dispatch_trace(params)["result"]
    assert result["armed"] is False
    assert result["hits"] == []
    assert result.get("note")
    assert gdb.breakpoints() == []


def test_trace_starts_already_inside_range(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1004: (0x2000, "ret", False),
    }, pc=0x1004)
    result = bridge._dispatch_trace(params)["result"]
    assert result["armed"] is True
    assert result["hits"] == []
    assert "note" not in result


def test_trace_entry_breakpoint_opens_window(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x2000: (0x1000, "jmp range_start", False),
        0x1000: (0x1004, "store watched", True),
    }, pc=0x2000)
    params["max_hits"] = 1
    result = bridge._dispatch_trace(params)["result"]
    assert result["armed"] is True
    assert [hit["pc"] for hit in result["hits"]] == ["0x1000"]


def test_trace_preserves_user_breakpoint_and_stops_on_it(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1004, "nop", False),
        0x1004: (0x1008, "store watched", True),
    })
    user_bp = gdb.Breakpoint("*0x1004")
    result = bridge._dispatch_trace(params)["result"]
    assert writes == []
    assert result["stop_info"]["reason"]["number"] == user_bp.number
    assert gdb.breakpoints() == [user_bp]


def test_trace_cleans_up_on_execution_error(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {})
    state["fail"] = "Cannot insert hardware watchpoint"
    with pytest.raises(gdb.error):
        bridge._dispatch_trace(params)
    assert gdb.breakpoints() == []
    assert state["scheduler"] == "off"


def test_trace_does_not_attribute_another_thread_access(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1004, "store watched", True),
    })
    state["other_thread"] = True
    result = bridge._dispatch_trace(params)["result"]
    assert result["hits"] == []
    assert result["unattributed_count"] == 1
    assert result["last_unattributed"]["pc"] is None
    assert result["last_unattributed"]["asm"] is None
    assert result["last_unattributed"]["stop_pc"] == "0x1004"
    assert result.get("note")
    assert gdb.breakpoints() == []


@pytest.mark.parametrize("overrides", [
    {"watch_size": 0}, {"watch_size": -1}, {"watch_size": 1.5},
    {"max_hits": 0}, {"max_hits": -1}, {"max_hits": True},
    {"range_end": "0x1000"}, {"range_end": "0xfff"},
    {"range_start": -1}, {"watch_addr": -1},
    {"watch_type": "invalid"}, {"_timeout": 0},
])
def test_trace_rejects_undefined_bounds_before_execution(monkeypatch, overrides):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {})
    params.update(overrides)
    with pytest.raises(ValueError):
        bridge._dispatch_trace(params)
    assert commands == []
    assert gdb.breakpoints() == []
