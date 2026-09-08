from __future__ import annotations

from collections import deque
import threading
import types

import pytest

from tests.test_bridge import _load_bridge


def _trace_session(monkeypatch, instructions, *, pc=0x1000, scheduler="off", remote=False):
    """Model execution before execute returns, with subsequent event delivery.

    Sparse instruction maps leave decodable padding in the range. Each stepi
    executes exactly one instruction, stepping over a breakpoint at its source;
    entry breakpoints stop before the destination instruction executes.
    """
    bridge_mod, gdb = _load_bridge(monkeypatch)
    inferior = gdb.selected_inferior()
    connection = types.SimpleNamespace(type="remote") if remote else None
    inferior.connection = connection
    bridge = bridge_mod.GdbBridge()
    frame = gdb.newest_frame()
    frame._pc = pc
    threads = inferior.threads()
    frames = [frame, threads[1]._frame]
    writes = []
    commands = []
    original_execute = gdb.execute
    original_breakpoint = gdb.Breakpoint
    state = {
        "scheduler": scheduler, "fail": None, "other_thread": False,
        "exited": False, "scheduler_after_exit": 0, "resume_schedulers": [],
        "terminal": "normal", "removed_first": False, "selected": 0,
        "continue_threads": deque(), "after_stop": None, "on_running": None,
        "hold_running": False, "before_execute_entry": False,
    }
    gdb.parameter = lambda name: state["scheduler"]
    gdb.selected_thread = lambda: threads[state["selected"]]
    gdb.newest_frame = lambda: frames[state["selected"]]
    gdb.selected_frame = gdb.newest_frame
    callbacks = deque()
    pumping = False

    class Breakpoint(original_breakpoint):
        def __init__(self, *args, internal=False, **kwargs):
            super().__init__(*args, **kwargs)
            self.internal = internal

    gdb.Breakpoint = Breakpoint

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
        asm = instructions.get(addr, (addr + 1, "nop padding", False))[1]
        return [{"addr": addr, "asm": asm, "length": 1}]

    for current_frame in frames:
        current_frame.architecture = lambda: types.SimpleNamespace(disassemble=disassemble)

    def deliver_stop(event):
        gdb.events.stop.fire(event)
        if state["after_stop"]:
            state["after_stop"]()

    def deliver_exit():
        state["exited"] = True
        if state["terminal"] == "signal":
            gdb.set_convenience_variable("_exitsignal", 15)
        if connection is not None and state["removed_first"]:
            inferior.connection = None
            gdb.events.connection_removed.fire(types.SimpleNamespace(connection=connection))
        gdb.events.exited.fire(gdb._FakeExitedEvent(
            7 if state["terminal"] == "normal-nonzero" else
            0 if state["terminal"] == "normal" else None
        ))
        inferior.pid = 0
        inferior.connection = None
        if connection is not None and not state["removed_first"]:
            gdb.events.connection_removed.fire(types.SimpleNamespace(connection=connection))

    def execute_instruction(command):
        if command == "continue" and state["continue_threads"]:
            state["selected"] = state["continue_threads"].popleft()
        current_frame = gdb.newest_frame()
        while True:
            current = current_frame.pc()
            if current not in instructions:
                callbacks.append(deliver_exit)
                return ""
            if state["before_execute_entry"]:
                state["before_execute_entry"] = False
                bps = [bp for bp in gdb.breakpoints()
                       if bp.type == gdb.BP_BREAKPOINT and bp.enabled
                       and bp.location == f"*{hex(current)}"]
                callbacks.append(lambda: deliver_stop(gdb._FakeBreakpointEvent(bps)))
                return ""
            successor, _, watched = instructions[current]
            wp = next((bp for bp in gdb.breakpoints() if bp.type == gdb.BP_WATCHPOINT), None)
            if watched:
                writes.append(current)
            current_frame._pc = successor
            bps = [bp for bp in gdb.breakpoints()
                   if bp.type == gdb.BP_BREAKPOINT and bp.enabled
                   and bp.location == f"*{hex(successor)}"]
            if watched and wp is not None and wp.enabled:
                bps.append(wp)
            if bps:
                event = gdb._FakeBreakpointEvent(bps)
                if state["other_thread"]:
                    event.inferior_thread = threads[1]
                callbacks.append(lambda: deliver_stop(event))
                return ""
            if command == "stepi":
                callbacks.append(lambda: deliver_stop(gdb._FakeStopEvent()))
                return ""

    def execute(command, to_string=False):
        commands.append(command)
        if command.startswith("set scheduler-locking "):
            if state["exited"]:
                state["scheduler_after_exit"] += 1
                raise gdb.error("Target exec cannot support this command.")
            state["scheduler"] = command.rsplit(" ", 1)[1]
            return ""
        if command == "interrupt":
            callbacks.append(lambda: deliver_stop(gdb._FakeSignalEvent("SIGINT")))
            return ""
        if command not in {"stepi", "continue"}:
            return original_execute(command, to_string=to_string)
        if state["fail"]:
            raise gdb.error(state["fail"])
        state["resume_schedulers"].append((command, state["scheduler"]))
        gdb.events.cont.fire(types.SimpleNamespace())
        if state["on_running"]:
            state["on_running"]()
        if not state["hold_running"]:
            return execute_instruction(command)
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


def test_trace_rejects_missing_decode_before_execution(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "call helper", False),
        0x2000: (0x1001, "ret", False),
        0x1001: (0x1002, "store inside", True),
    })
    def unavailable(addr, count=1):
        raise gdb.error("Cannot access instruction memory")
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(disassemble=unavailable)
    with pytest.raises(gdb.error, match="Cannot access instruction memory"):
        bridge._dispatch_trace(params)
    assert gdb.newest_frame().pc() == 0x1000
    assert writes == []
    assert not {"stepi", "continue"}.intersection(commands)
    assert gdb.breakpoints() == []
    assert bridge._active_trace is None


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


def test_trace_catches_non_fallthrough_midrange_reentry(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "jmp outside", False),
        0x2000: (0x1008, "jmp middle", False),
        0x1008: (0x3000, "store watched and branch", True),
    })
    result = bridge._dispatch_trace(params)["result"]
    assert [hit["pc"] for hit in result["hits"]] == ["0x1008"]
    assert result["hits"][0]["stop_pc"] == "0x3000"
    assert writes == [0x1008]
    assert result["stop_info"]["status"] == "exited"
    assert gdb.breakpoints() == []


def test_trace_keeps_shared_return_entry_for_both_threads(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "call helper", False),
        0x2000: (0x2001, "store outside", True),
        0x2001: (0x1001, "ret", False),
        0x1001: (0x1002, "store inside", True),
        0x1002: (0x3000, "ret caller", False),
    })
    gdb.selected_inferior().threads()[1]._frame._pc = 0x1000
    state["continue_threads"].extend([1, 0])
    params["max_hits"] = 2
    result = bridge._dispatch_trace(params)["result"]
    assert [hit["pc"] for hit in result["hits"]] == ["0x1001", "0x1001"]
    assert writes == [0x2000, 0x1001, 0x2000, 0x1001]
    assert gdb.newest_frame().pc() == 0x1002
    assert result["truncated"] is True
    assert state["scheduler"] == "off"
    assert gdb.breakpoints() == []


def test_trace_entry_stop_before_execution_does_not_count_access(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store watched", True),
        0x1001: (0x1002, "store again", True),
    })
    state["before_execute_entry"] = True
    params["max_hits"] = 1
    result = bridge._dispatch_trace(params)["result"]
    assert writes == [0x1000]
    assert result["hits"][0]["pc"] == "0x1000"
    assert result["hits"][0]["stop_pc"] == "0x1001"
    assert result["hit_count"] == 1
    assert gdb.breakpoints() == []


@pytest.mark.parametrize("terminal", ["normal-nonzero", "signal", "lost"])
@pytest.mark.parametrize("removed_first", [False, True])
def test_trace_defers_remote_terminal_classification(monkeypatch, terminal, removed_first):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "ret", False),
    }, remote=True)
    state.update(terminal=terminal, removed_first=removed_first)
    if terminal == "lost":
        with pytest.raises(RuntimeError, match="Remote"):
            bridge._dispatch_trace(params)
        with pytest.raises(RuntimeError, match="Remote"):
            bridge._dispatch_status()
    else:
        result = bridge._dispatch_trace(params)["result"]
        assert result["stop_info"]["status"] == "exited"
        reason = result["stop_info"]["reason"]
        if terminal == "signal":
            assert reason["signal"] == 15
        else:
            assert reason["code"] == 7
    assert gdb.breakpoints() == []
    assert bridge._active_trace is None


def test_trace_unconfirmed_remote_exit_without_connection_event(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x2000, "ret", False),
    }, remote=True)
    # Model an older backend with no notification, while keeping the registry
    # present so the fixture can fire its terminal sequence normally.
    gdb.events.connection_removed.fire = lambda event: None
    state["terminal"] = "lost"
    with pytest.raises(RuntimeError, match="Remote"):
        bridge._dispatch_trace(params)
    assert gdb.breakpoints() == []
    assert bridge._active_trace is None


@pytest.mark.parametrize("phase", ["between-steps", "running", "setup"])
@pytest.mark.parametrize("cleanup_error", [False, True])
def test_interrupt_cancels_trace_and_waits_for_cleanup(monkeypatch, phase, cleanup_error):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store first", True),
        0x1001: (0x1002, "store second", True),
    })
    responses = []
    workers = []
    user_bp = gdb.Breakpoint("*0x9000")
    original_delete = gdb.Breakpoint.delete

    def delete(bp):
        original_delete(bp)
        if cleanup_error and bp is not user_bp:
            raise gdb.error("trace cleanup failed")

    monkeypatch.setattr(gdb.Breakpoint, "delete", delete)

    def request_interrupt():
        if workers:
            return
        control = bridge._active_trace
        def interrupt():
            responses.append(bridge._dispatch_interrupt())
            # This is an externally visible cleanup barrier, not a check of
            # request submission or a transient running flag.
            assert gdb.breakpoints() == [user_bp]
        worker = threading.Thread(target=interrupt)
        workers.append(worker)
        worker.start()
        assert control["cancelled"].wait(2)

    if phase == "between-steps":
        state["after_stop"] = request_interrupt
    elif phase == "running":
        state["on_running"] = request_interrupt
        state["hold_running"] = True
    else:
        architecture = gdb.newest_frame().architecture()
        disassemble = architecture.disassemble
        def decode(addr, count=1):
            request_interrupt()
            return disassemble(addr, count=count)
        architecture.disassemble = decode
        gdb.newest_frame().architecture = lambda: architecture
    try:
        if cleanup_error:
            with pytest.raises(gdb.error, match="trace cleanup failed"):
                bridge._dispatch_trace(params)
        else:
            result = bridge._dispatch_trace(params)["result"]
            assert result["interrupted"] is True
            assert "timeout_interrupt" not in result
    finally:
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
    assert len(responses) == 1
    assert responses[0]["ok"] is not cleanup_error
    if not cleanup_error:
        assert responses[0]["result"]["interrupted"] is True
        assert responses[0]["result"]["stopped"] is True
    assert writes == ([0x1000] if phase == "between-steps" else [])
    assert state["scheduler"] == "off"
    assert bridge._active_trace is None
    assert gdb.breakpoints() == [user_bp]


def test_trace_timeout_uses_cleanup_barrier_without_user_interrupt_flag(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store watched", True),
    })
    state["hold_running"] = True
    params["_timeout"] = 0.001
    result = bridge._dispatch_trace(params)["result"]
    assert result["timeout_interrupt"] is True
    assert "interrupted" not in result
    assert result["stop_info"]["status"] == "stopped"
    assert writes == []
    assert commands.count("interrupt") == 1
    assert state["scheduler"] == "off"
    assert gdb.breakpoints() == []
    assert bridge._active_trace is None


@pytest.mark.parametrize("bad_decode", [
    [], [{"addr": 0x1000, "length": 0, "asm": "nop"}],
    [{"addr": 0x1001, "length": 1, "asm": "nop"}],
    [{"addr": 0x1000, "length": 1, "asm": "(bad)"}],
])
def test_trace_invalid_decoder_output_never_resumes(monkeypatch, bad_decode):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {})
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(
        disassemble=lambda addr, count=1: bad_decode,
    )
    with pytest.raises(RuntimeError, match="Cannot decode"):
        bridge._dispatch_trace(params)
    assert not {"stepi", "continue"}.intersection(commands)
    assert gdb.breakpoints() == []


def test_trace_rejects_stopped_pc_between_decoded_boundaries(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "branch into instruction", False),
    })
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(
        disassemble=lambda addr, count=1: [{"addr": addr, "length": 2, "asm": "branch"}],
    )
    with pytest.raises(RuntimeError, match="undecoded instruction boundary"):
        bridge._dispatch_trace(params)
    assert gdb.newest_frame().pc() == 0x1001
    assert commands.count("stepi") == 1
    assert gdb.breakpoints() == []


def test_trace_setup_failure_unblocks_interrupt(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {})
    responses = []
    workers = []
    def decode(addr, count=1):
        control = bridge._active_trace
        worker = threading.Thread(target=lambda: responses.append(bridge._dispatch_interrupt()))
        workers.append(worker)
        worker.start()
        assert control["cancelled"].wait(2)
        raise gdb.error("unreadable trace range")
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(disassemble=decode)
    try:
        with pytest.raises(gdb.error, match="unreadable trace range"):
            bridge._dispatch_trace(params)
    finally:
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
    assert responses[0]["ok"] is False
    assert "unreadable trace range" in responses[0]["error"]
    assert bridge._active_trace is None
    assert gdb.breakpoints() == []


def test_trace_interrupt_ack_does_not_claim_new_execution_is_stopped(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store watched", True),
    })
    state["hold_running"] = True
    workers = []
    responses = []

    def request_interrupt():
        state["on_running"] = None
        control = bridge._active_trace
        original_wait = control["completion"].wait
        def wait(timeout=None):
            done = original_wait(timeout)
            if done and threading.current_thread() is workers[0]:
                # A raw debugger resume is allowed after trace cleanup, even
                # if the interrupt requester has not yet sent its reply.
                gdb.execute("continue", to_string=True)
            return done
        monkeypatch.setattr(control["completion"], "wait", wait)
        worker = threading.Thread(target=lambda: responses.append(bridge._dispatch_interrupt()))
        workers.append(worker)
        worker.start()
        assert control["cancelled"].wait(2)

    state["on_running"] = request_interrupt
    try:
        result = bridge._dispatch_trace(params)["result"]
    finally:
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
    assert result["interrupted"] is True
    assert responses[0]["ok"] is True
    assert responses[0]["result"]["interrupted"] is True
    assert responses[0]["result"]["stopped"] is False
    assert responses[0]["result"]["status"] == "running"
    assert gdb.breakpoints() == []
    assert bridge._active_trace is None


def test_interrupt_does_not_acknowledge_without_a_stop_event(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {})
    bridge._running = True
    original_execute = gdb.execute
    original_event = threading.Event

    class NoStopEvent(original_event):
        def wait(self, timeout=None):
            # No terminal event will arrive in this fixture. Elide the real
            # ten-second deadline, without treating command return as a stop.
            return self.is_set()

    def execute(command, to_string=False):
        if command == "interrupt":
            bridge._running = False
            return ""
        return original_execute(command, to_string=to_string)

    monkeypatch.setattr(threading, "Event", NoStopEvent)
    gdb.execute = execute
    response = bridge._dispatch_interrupt()
    assert response["ok"] is False
    assert response["result"] is None
    assert gdb.events.stop._handlers == [bridge._on_stop]
    assert gdb.events.exited._handlers == [bridge._on_exited]


def test_trace_counts_instruction_starting_before_nonboundary_end(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1004, "store watched", True),
        0x1004: (0x2000, "ret", False),
    })
    gdb.newest_frame().architecture = lambda: types.SimpleNamespace(
        disassemble=lambda addr, count=1: [{
            "addr": addr, "length": 4, "asm": "store watched" if addr == 0x1000 else "ret",
        }],
    )
    params.update(range_end="0x1001", max_hits=1)
    result = bridge._dispatch_trace(params)["result"]
    assert result["hit_count"] == 1
    assert result["hits"][0]["pc"] == "0x1000"
    assert result["hits"][0]["stop_pc"] == "0x1004"
    assert writes == [0x1000]
    assert gdb.breakpoints() == []


def test_trace_resolves_symbolic_addresses_in_posted_gdb_callback(monkeypatch):
    bridge, gdb, params, writes, commands, state = _trace_session(monkeypatch, {
        0x1000: (0x1001, "store watched", True),
    })
    original_post = gdb.post_event
    original_eval = gdb.parse_and_eval
    in_callback = False

    def post_event(callback):
        def posted():
            nonlocal in_callback
            before = in_callback
            in_callback = True
            try:
                callback()
            finally:
                in_callback = before
        original_post(posted)

    def parse_and_eval(expression):
        if expression in {"watched", "entry", "limit"}:
            if not in_callback:
                raise gdb.error("GDB expression evaluation on worker thread")
            return {"watched": 0x4000, "entry": 0x1000, "limit": 0x1001}[expression]
        return original_eval(expression)

    gdb.post_event = post_event
    gdb.parse_and_eval = parse_and_eval
    params.update(watch_addr="watched", range_start="entry", range_end="limit", max_hits=1)
    result = bridge._dispatch_trace(params)["result"]
    assert result["watch_addr"] == "0x4000"
    assert result["hits"][0]["pc"] == "0x1000"
    assert writes == [0x1000]
    assert gdb.breakpoints() == []
