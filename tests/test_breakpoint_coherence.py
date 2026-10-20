"""Breakpoint and run-state coherence: running remote targets, <PENDING>
locations, baked traps, and resync."""
from __future__ import annotations

import re
import threading
import types

import pytest

import pry.cli
from tests.test_bridge import _load_bridge

TRAP_SITE = 0xFFFFFFFF810881D0
# `mov 0x70(%rdi),%rdi; jmp ...` as the ELF has it at the breakpoint site.
ELF_WINDOW = bytes.fromhex("488b7f70e9b7ebff")


class _Stub:
    """A remote stub's memory under a GDB-like breakpoint table.

    GDB inserts its breakpoints when the target resumes and removes them at
    every stop; with ``breakpoint always-inserted`` on it inserts them as soon
    as the table changes. Insertion saves the byte and writes int3, like
    QEMU's KVM gdbstub. Like QEMU it keeps records GDB may not know about:
    an orphan (its int3 still in memory) or a stale record (a removal that
    failed). With either, an insert at that address writes nothing until a
    raw ``z0`` drops the record (an orphan's saved byte is written back). A
    TCG-like stub (``writes=False``) never puts traps in memory.
    """

    type = "remote"

    def __init__(self, memory: dict[int, int], *, writes: bool = True):
        self.mem = dict(memory)
        self.writes = writes
        self.always_inserted = False
        self.inserted: dict[int, int] = {}
        self.stale: set[int] = set()
        self.orphans: dict[int, int] = {}
        self.bps: list[_Bp] = []

    def orphan(self, addr: int):
        """An int3 GDB lost track of: the stub still records it."""
        self.orphans[addr] = self.mem[addr]
        self.mem[addr] = 0xCC

    def send_packet(self, packet: str) -> bytes:
        z = re.fullmatch(r"z0,([0-9a-f]+),1", packet)
        if z:
            addr = int(z[1], 16)
            if addr in self.orphans:
                saved = self.orphans.pop(addr)
                if self.mem.get(addr) == 0xCC:
                    self.mem[addr] = saved
                return b"OK"
            if addr in self.stale:
                self.stale.discard(addr)
                return b"OK"
            return b"E22"
        m = re.fullmatch(r"m([0-9a-f]+),([0-9a-f]+)", packet)
        assert m, packet
        addr, length = int(m[1], 16), int(m[2], 16)
        if any(addr + i not in self.mem for i in range(length)):
            return b"E14"
        return bytes(self.mem[addr + i] for i in range(length)).hex().encode()

    def update(self):
        for bp in self.bps:
            for loc in bp.locations:
                wanted = bp.enabled and loc.enabled
                if not wanted and loc.address in self.inserted:
                    self.mem[loc.address] = self.inserted.pop(loc.address)
                elif wanted and self.always_inserted and loc.address not in self.inserted:
                    if loc.address not in self.mem:
                        raise _Stub.error(f"Cannot insert breakpoint {bp.number}.")
                    self.inserted[loc.address] = self.mem[loc.address]
                    recorded = loc.address in self.stale or loc.address in self.orphans
                    if self.writes and not recorded:
                        self.mem[loc.address] = 0xCC

    def resume(self):
        self.always_inserted, saved = True, self.always_inserted
        try:
            self.update()
        finally:
            self.always_inserted = saved


class _Loc:
    def __init__(self, address, function="__x64_sys_newuname"):
        self.address = address
        self.function = function
        self.source = None
        self.enabled = True


class _Bp:
    def __init__(self, stub, number, address, *, bp_type=1):
        self._stub = stub
        self.number = number
        self.type = bp_type
        self.location = "__x64_sys_newuname"
        self.expression = None
        self.condition = None
        self.hit_count = 0
        self.temporary = False
        self.pending = False
        self.thread = None
        self.ignore_count = 0
        self.locations = [_Loc(address)]
        self._enabled = True
        stub.bps.append(self)

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self._enabled = value
        self._stub.update()

    def is_valid(self):
        return True

    def delete(self):
        self._enabled = False
        self._stub.update()
        self._stub.bps.remove(self)


def _remote_target(monkeypatch, memory, *, maint_rows="", writes=True):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    stub = _Stub(memory, writes=writes)
    _Stub.error = fake_gdb.error
    inferior = fake_gdb.selected_inferior()
    inferior.connection = stub
    inferior.architecture = lambda: types.SimpleNamespace(name=lambda: "i386:x86-64")

    def write_memory(addr, data):
        for i, byte in enumerate(bytes(data)):
            stub.mem[addr + i] = byte

    inferior.write_memory = write_memory
    monkeypatch.setattr(fake_gdb, "breakpoints", lambda: list(stub.bps))
    params = {"args": "", "startup-with-shell": False}
    monkeypatch.setattr(fake_gdb, "parameter", lambda name: (
        stub.always_inserted if name == "breakpoint always-inserted" else params[name]
    ))
    execute = fake_gdb.execute

    def fake_execute(cmd, to_string=False):
        if cmd.startswith("set breakpoint always-inserted"):
            stub.always_inserted = cmd.endswith(" on")
            return ""
        if cmd == "maint info breakpoints":
            return maint_rows() if callable(maint_rows) else maint_rows
        if cmd == "monitor info kvm":
            return f"kvm support: {'enabled' if stub.writes else 'disabled'}\n"
        return execute(cmd, to_string=to_string)

    monkeypatch.setattr(fake_gdb, "execute", fake_execute)
    bridge = bridge_mod.GdbBridge()
    bridge._elf_bytes_at = lambda addr, length: ELF_WINDOW[:length] if addr == TRAP_SITE else None
    return bridge_mod, fake_gdb, bridge, stub


def _memory(window: bytes) -> dict[int, int]:
    return {TRAP_SITE + i: b for i, b in enumerate(window)}


def _start_background(bridge, fake_gdb, stub):
    """`pry continue --background`: GDB inserts its breakpoints and resumes."""
    original = fake_gdb.execute

    def execute(cmd, to_string=False):
        if cmd == "continue":
            try:
                stub.resume()
            except fake_gdb.error:
                # GDB prints the cause to its console and raises only this.
                raise fake_gdb.error("Command aborted.") from None
        if cmd == "interrupt":
            # GDB removes its breakpoints at the stop.
            for bp in stub.bps:
                for loc in bp.locations:
                    if loc.address in stub.inserted:
                        stub.mem[loc.address] = stub.inserted.pop(loc.address)
        return original(cmd, to_string=to_string)

    fake_gdb.execute = execute
    response = bridge.dispatch({"op": "continue", "params": {"_background": True}})
    assert response["result"]["state"] == "running"


# --- trap-site classification ------------------------------------------------

@pytest.mark.parametrize(
    ("guest", "elf", "baked", "elf_match"),
    [
        # int3 where the ELF has an instruction, everything after agrees: baked.
        (b"\xcc" + ELF_WINDOW[1:], ELF_WINDOW, True, True),
        # The ELF itself has int3 there (padding, a real int3): not ours to fix.
        (b"\xcc" + ELF_WINDOW[1:], b"\xcc" + ELF_WINDOW[1:], False, True),
        # Wrong symbols / unapplied slide: the following bytes disagree too.
        (b"\xcc\x90\x90\x90\x90\x90\x90\x90", ELF_WINDOW, False, False),
        # Clean site.
        (ELF_WINDOW, ELF_WINDOW, False, True),
        # Too few confirming bytes to trust the mapping.
        (b"\xcc\x8b\x7f", ELF_WINDOW[:3], False, False),
    ],
)
def test_classify_trap_site(monkeypatch, guest, elf, baked, elf_match):
    bridge_mod, _ = _load_bridge(monkeypatch)
    info = bridge_mod.classify_trap_site(guest, elf, b"\xcc")
    assert info["baked_trap"] is baked
    assert info["elf_match"] is elf_match


def test_classify_trap_site_without_elf_or_memory(monkeypatch):
    bridge_mod, _ = _load_bridge(monkeypatch)
    assert bridge_mod.classify_trap_site(None, ELF_WINDOW, b"\xcc") == {"readable": False}
    info = bridge_mod.classify_trap_site(b"\xcc" + ELF_WINDOW[1:], None, b"\xcc")
    assert info["trap_present"] is True
    assert info["baked_trap"] is False
    assert info["elf_bytes"] is None


# --- <PENDING> locations --------------------------------------------------------

def test_shlib_disabled_location_is_pending_without_an_address(monkeypatch):
    rows = (
        "Num     Type           Disp Enb Address            What\n"
        "1       breakpoint     keep y   <PENDING>          __x64_sys_newuname inf 1\n"
        "1.1                         y   <PENDING>          __x64_sys_newuname inf 1\n"
        "2       breakpoint     keep y   <MULTIPLE>\n"
        "2.1                         y   0xffffffff81000010 in a at a.c:1 inf 1\n"
        "2.2                         y   <PENDING>          b inf 1\n"
    )
    _, _, bridge, stub = _remote_target(monkeypatch, {}, maint_rows=rows)
    _Bp(stub, 1, TRAP_SITE)
    two = _Bp(stub, 2, 0xFFFFFFFF81000010)
    two.locations.append(_Loc(0xFFFFFFFF81000020, "b"))

    listed = {bp["number"]: bp for bp in bridge._dispatch_op("break_list", {})}

    assert listed[1]["pending"] is True
    assert "address" not in listed[1]
    assert listed[1]["locations"][0]["pending"] is True
    # One live location keeps the breakpoint itself non-pending.
    assert listed[2]["pending"] is False
    assert listed[2]["locations"][0]["address"] == "0xffffffff81000010"
    assert listed[2]["locations"][1] == {"function": "b", "enabled": True, "pending": True}


def test_pending_location_renders_without_its_stale_address(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "send_request", lambda *a, **k: {"ok": True, "result": [{
        "number": 2, "kind": "breakpoint", "location": "f", "enabled": True, "hits": 0,
        "location_count": 2, "pending": False,
        "locations": [
            {"address": "0x401000", "function": "f", "enabled": True},
            {"function": "f", "enabled": True, "pending": True},
        ],
    }]})
    assert pry.cli.main(["break", "list"]) == 0
    out = capsys.readouterr().out
    assert "0x401000" in out
    assert "<PENDING>" in out


# --- running remote target: stop, apply, resume -------------------------------

def test_delete_on_running_remote_target_removes_the_trap_and_resumes(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    assert stub.mem[TRAP_SITE] == 0xCC
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")
    fake_gdb._execute_log.clear()

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 1}})

    assert response["ok"] is True, response
    assert response["result"]["run_state"] == {
        "was_running": True, "interrupted": True, "resumed": True,
    }
    assert stub.bps == []
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]
    log = fake_gdb._execute_log
    assert log.index("interrupt") < log.index("continue")
    assert bridge.dispatch({"op": "status"})["result"]["state"] == "running"


def test_enable_on_running_remote_target_arms_after_resume(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    bp = _Bp(stub, 1, TRAP_SITE)
    bp.enabled = False
    _start_background(bridge, fake_gdb, stub)
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    response = bridge.dispatch({"op": "break_enable", "params": {"number": 1}})

    assert response["ok"] is True, response
    assert response["result"]["enabled"] is True
    assert response["result"]["run_state"]["resumed"] is True
    assert stub.mem[TRAP_SITE] == 0xCC


def test_target_stopping_on_its_own_is_not_resumed_over(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    bp = _Bp(stub, 1, TRAP_SITE)
    _Bp(stub, 2, TRAP_SITE + 4)
    _start_background(bridge, fake_gdb, stub)
    # The breakpoint hit beats the interrupt.
    fake_gdb._pending_stop_event = fake_gdb._FakeBreakpointEvent([bp])
    fake_gdb._execute_log.clear()

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 2}})

    run_state = response["result"]["run_state"]
    assert run_state["resumed"] is False
    assert run_state["stop"]["reason"]["kind"] == "breakpoint-hit"
    assert "continue" not in fake_gdb._execute_log
    status = bridge.dispatch({"op": "status"})["result"]
    assert status["state"] == "stopped"
    assert status["reason"]["number"] == 1


def test_unconfirmed_stop_changes_nothing(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    execute = fake_gdb.execute

    def refuse_interrupt(cmd, to_string=False):
        if cmd == "interrupt":
            raise fake_gdb.error("Remote failure reply: E01")
        return execute(cmd, to_string=to_string)

    fake_gdb.execute = refuse_interrupt

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 1}})

    assert response["ok"] is False
    assert "nothing was changed" in response["error"]
    assert [bp.number for bp in stub.bps] == [1]


def test_failed_resume_is_reported_and_leaves_no_trap_at_the_stop(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _Bp(stub, 2, TRAP_SITE + 4)
    _start_background(bridge, fake_gdb, stub)
    execute = fake_gdb.execute

    def refuse_resume(cmd, to_string=False):
        result = execute(cmd, to_string=to_string)
        if cmd == "continue":
            # GDB inserted what it could, then failed on another location.
            raise fake_gdb.error("Command aborted.")
        return result

    fake_gdb.execute = refuse_resume
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 2}})

    assert response["ok"] is True, response  # the delete itself was applied
    run_state = response["result"]["run_state"]
    assert run_state["resumed"] is False
    assert "Command aborted" in run_state["error"]
    assert [bp.number for bp in stub.bps] == [1]
    assert stub.inserted == {}
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]
    assert bridge.dispatch({"op": "status"})["result"]["state"] == "stopped"


def test_failed_continue_names_the_refused_breakpoint_and_leaves_no_trap(monkeypatch):
    """#69: a software breakpoint at unmapped memory is the cause, not debug registers."""
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _Bp(stub, 2, 0xFFFFFFFF00000000)  # nothing mapped there
    execute = fake_gdb.execute

    def resume(cmd, to_string=False):
        if cmd == "continue":
            try:
                stub.resume()
            except fake_gdb.error:
                # GDB prints the cause to its console and raises only this.
                raise fake_gdb.error("Command aborted.") from None
        return execute(cmd, to_string=to_string)

    fake_gdb.execute = resume

    response = bridge.dispatch({"op": "continue", "params": {}})

    assert response["ok"] is False
    assert "Cannot insert breakpoint 2." in response["error"]
    assert "debug registers" not in response["error"]
    # Breakpoint 1, which GDB inserted before it gave up, is out of memory.
    assert stub.inserted == {}
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]


def test_background_finish_is_not_cancelled_to_apply_a_change(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    response = bridge.dispatch({"op": "finish", "params": {"_background": True}})
    assert response["result"]["state"] == "running"
    fake_gdb._execute_log.clear()

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 1}})

    assert response["ok"] is False
    assert "nothing was changed" in response["error"]
    assert [bp.number for bp in stub.bps] == [1]
    assert "interrupt" not in fake_gdb._execute_log


def test_breakpoint_ops_still_work_after_the_remote_is_lost(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    bridge._remote_failure = "Remote connection lost without a confirmed inferior exit"

    response = bridge.dispatch({"op": "break_set", "params": {"location": "main"}})

    assert response["ok"] is True, response


def test_native_running_target_takes_the_change_live(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    bp = fake_gdb.Breakpoint("main")
    bridge.dispatch({"op": "continue", "params": {"_background": True}})
    fake_gdb._execute_log.clear()

    response = bridge.dispatch({"op": "break_disable", "params": {"number": bp.number}})

    assert response["ok"] is True
    assert response["result"]["enabled"] is False
    assert "run_state" not in response["result"]
    assert "interrupt" not in fake_gdb._execute_log


def test_waiter_follows_the_resumed_execution(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    hit = _Bp(stub, 1, TRAP_SITE)
    _Bp(stub, 2, TRAP_SITE + 4)
    _start_background(bridge, fake_gdb, stub)
    responses = []
    old_job = bridge._background_job
    waiter = threading.Thread(
        target=lambda: responses.append(bridge.dispatch({"op": "wait", "params": {"_timeout": 10}})),
        daemon=True,
    )
    waiter.start()
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    assert bridge.dispatch({"op": "break_delete", "params": {"number": 2}})["ok"] is True
    assert old_job["completion"].is_set()
    waiter.join(timeout=0.2)
    assert waiter.is_alive(), "the waiter returned the pause's own interrupt"

    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([hit]))
    waiter.join(timeout=5)
    assert responses[0]["result"]["reason"]["kind"] == "breakpoint-hit"
    assert responses[0]["result"]["reason"]["number"] == 1


def test_failed_op_while_running_keeps_the_run_state(monkeypatch):
    """#68: a read the running stub refuses does not make pry think it stopped,
    so the next breakpoint change still stops, applies and resumes."""
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    running = [True]
    execute = fake_gdb.execute

    def track(cmd, to_string=False):
        if cmd == "interrupt":
            running[0] = False
        result = execute(cmd, to_string=to_string)
        if cmd == "continue":
            running[0] = True
        return result

    def threads():
        # Listing threads asks the all-stop stub, which refuses while it runs.
        if running[0]:
            raise fake_gdb.error("Cannot execute this command while the target is running.")
        return [thread]

    def parse_and_eval(expression):
        if running[0]:
            raise fake_gdb.error("Selected thread is running.")
        return 0

    thread = fake_gdb.selected_thread()
    monkeypatch.setattr(thread, "is_running", lambda: running[0])
    monkeypatch.setattr(thread, "is_stopped", lambda: not running[0])
    monkeypatch.setattr(fake_gdb.selected_inferior(), "threads", threads)
    monkeypatch.setattr(fake_gdb, "parse_and_eval", parse_and_eval)
    fake_gdb.execute = track

    assert bridge.dispatch({"op": "print", "params": {"expression": "$pc"}})["ok"] is False
    assert bridge.dispatch({"op": "status"})["result"]["state"] == "running"
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 1}})

    assert response["ok"] is True, response
    assert response["result"]["run_state"] == {
        "was_running": True, "interrupted": True, "resumed": True,
    }
    assert stub.bps == []
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]
    assert running[0] is True
    assert bridge.dispatch({"op": "status"})["result"]["state"] == "running"


# --- baked traps ----------------------------------------------------------------

@pytest.mark.parametrize("op", ["break_delete", "break_disable", "break_enable"])
def test_baked_trap_at_a_breakpoint_site_is_restored(monkeypatch, op):
    _, fake_gdb, bridge, stub = _remote_target(
        monkeypatch, _memory(b"\xcc" + ELF_WINDOW[1:])
    )
    _Bp(stub, 1, TRAP_SITE)

    response = bridge.dispatch({"op": op, "params": {"number": 1}})

    assert response["ok"] is True, response
    assert response["result"]["baked_traps"] == [{
        "number": 1, "location": "1.1", "address": hex(TRAP_SITE),
        "function": "__x64_sys_newuname", "guest_bytes": "cc", "elf_bytes": "48",
        "repaired": True,
    }]
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]


def test_trap_that_does_not_match_the_elf_is_left_alone(monkeypatch):
    memory = _memory(b"\xcc\x90\x90\x90\x90\x90\x90\x90")
    _, _, bridge, stub = _remote_target(monkeypatch, memory)
    _Bp(stub, 1, TRAP_SITE)

    response = bridge.dispatch({"op": "break_delete", "params": {"number": 1}})

    assert "baked_traps" not in response["result"]
    assert stub.mem == memory


# --- unexplained stops -----------------------------------------------------------

@pytest.mark.parametrize(("op", "kind"), [("continue", "trap"), ("step", "step")])
def test_plain_stop_is_a_trap_only_when_nothing_was_stepping(monkeypatch, op, kind):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    bridge = bridge_mod.GdbBridge()
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()

    response = bridge.dispatch({"op": op, "params": {}})

    assert response["result"]["reason"]["kind"] == kind


@pytest.mark.parametrize("refused", [True, False])
def test_plain_continue_stop_fails_when_gdb_could_not_insert(monkeypatch, refused):
    """#65: GDB resumed (a step over the breakpoint at the PC), could not insert
    its breakpoints and stopped: the continue failed. With every breakpoint
    insertable the same plain stop is an unexplained trap."""
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    hw = _Bp(stub, 2, TRAP_SITE + 4, bp_type=fake_gdb.BP_HARDWARE_BREAKPOINT)
    update = stub.update

    def update_without_free_debug_registers():
        if refused and stub.always_inserted and hw.enabled:
            raise fake_gdb.error(
                "Warning:\nCannot insert hardware breakpoint 2:Remote failure reply: 01.\n"
            )
        update()

    stub.update = update_without_free_debug_registers
    fake_gdb._pending_stop_event = fake_gdb._FakeStopEvent()

    response = bridge.dispatch({"op": "continue", "params": {}})
    status = bridge.dispatch({"op": "status"})["result"]

    if refused:
        assert response["ok"] is False
        assert "Cannot insert hardware breakpoint 2" in response["error"]
        assert status["state"] == "stopped"
        assert status.get("reason", {}).get("kind") != "trap"
    else:
        assert response["result"]["reason"]["kind"] == "trap"
    # The trial insertion leaves no trap of GDB's in memory at the stop.
    assert stub.inserted == {}


# --- symbol reload ---------------------------------------------------------------

def test_rebasing_the_primary_symbol_file_keeps_breakpoints_enabled(monkeypatch, tmp_path):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    bp = fake_gdb.Breakpoint("__x64_sys_newuname")
    loaded = {str(vmlinux)}
    monkeypatch.setattr(fake_gdb, "objfiles", lambda: [
        types.SimpleNamespace(filename=f) for f in loaded
    ], raising=False)
    execute = fake_gdb.execute

    def fake_execute(cmd, to_string=False):
        if cmd == "symbol-file":
            # GDB disables a breakpoint it cannot re-resolve meanwhile.
            loaded.clear()
            bp.enabled = False
        return execute(cmd, to_string=to_string)

    monkeypatch.setattr(fake_gdb, "execute", fake_execute)
    bridge = bridge_mod.GdbBridge()

    result = bridge._dispatch_op("load", {"path": str(vmlinux), "slide": "0x20000000"})

    assert result["slide"] == "0x20000000"
    assert bp.enabled is True


# --- resync -----------------------------------------------------------------------

def test_resync_at_a_stop_replaces_the_stale_reason_and_verifies(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(b"\xcc" + ELF_WINDOW[1:]))
    _Bp(stub, 1, TRAP_SITE)
    bridge._last_stop_reason = {"kind": "breakpoint-hit", "number": 5}

    response = bridge.dispatch({"op": "resync", "params": {}})

    assert response["ok"] is True, response
    result = response["result"]
    assert result["state"] == "stopped"
    assert result["reason"] == {"kind": "resynced"}
    assert result["run_state"] == {"was_running": False, "interrupted": False, "resumed": False}
    [entry] = result["breakpoints"]
    assert entry["status"] == "armed"
    assert entry["trap_resident"] is True
    assert entry["baked_trap"] is True and entry["repaired"] is True
    assert result["summary"]["armed"] == 1 and result["summary"]["repaired"] == 1
    # Left stopped: nothing stays inserted (a snapshot here would be clean),
    # and the original instruction is back under the breakpoint.
    assert stub.inserted == {}
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]
    assert stub.always_inserted is False
    assert bridge.dispatch({"op": "status"})["result"]["reason"] == {"kind": "resynced"}


def test_resync_on_a_running_target_rearms_and_resumes(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    # A snapshot load replaced RAM: GDB still believes the trap is there.
    stub.mem[TRAP_SITE] = ELF_WINDOW[0]
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    response = bridge.dispatch({"op": "resync", "params": {}})

    result = response["result"]
    assert result["state"] == "running"
    assert "reason" not in result
    assert result["run_state"]["resumed"] is True
    assert result["breakpoints"][0]["status"] == "armed"
    assert result["breakpoints"][0]["trap_resident"] is True
    assert stub.mem[TRAP_SITE] == 0xCC
    assert stub.always_inserted is False


def test_resync_reports_unreadable_and_pending_locations_as_not_armed(monkeypatch):
    rows = "2.1                         y   <PENDING>          gone inf 1\n"
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW), maint_rows=rows)
    unreadable = _Bp(stub, 1, 0xFFFFFFFFAB000000)
    _Bp(stub, 2, TRAP_SITE)

    result = bridge.dispatch({"op": "resync", "params": {}})["result"]

    status = {e["location"]: e for e in result["breakpoints"]}
    assert status["1.1"]["status"] == "unreadable"
    assert status["1.1"]["trap_resident"] is None
    assert status["2.1"]["status"] == "pending"
    assert "address" not in status["2.1"]
    assert result["summary"]["not_armed"] == 2
    # Held out of the trial insertion, then handed back enabled.
    assert unreadable.locations[0].enabled is True


def test_resync_drops_a_stale_stub_record_before_arming(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    # The stub's removal failed at the first stop after a reset; its record
    # outlived it, so an insert at this address would write nothing.
    stub.stale.add(TRAP_SITE)

    result = bridge.dispatch({"op": "resync", "params": {}})["result"]

    [entry] = result["breakpoints"]
    assert entry["status"] == "armed"
    assert entry["trap_resident"] is True
    assert entry["stub_record"] is True
    assert stub.stale == set()


def test_resync_reseats_a_trap_the_stub_accepted_but_never_wrote(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    stub.stale.add(TRAP_SITE)
    # With the user's always-inserted mode GDB may hold its breakpoints at a
    # stop, so sites are not cleaned up front; the read-back catches it.
    stub.always_inserted = True

    result = bridge.dispatch({"op": "resync", "params": {}})["result"]

    [entry] = result["breakpoints"]
    assert entry["status"] == "armed"
    assert entry["trap_resident"] is True
    assert entry["reseated"] is True
    assert stub.mem[TRAP_SITE] == 0xCC


def test_resync_never_calls_a_watchpoint_armed(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    for with_code_breakpoint in (False, True):
        stub.bps.clear()
        watch = _Bp(stub, 5, TRAP_SITE + 4, bp_type=8)  # read watchpoint
        watch.locations = []
        watch.expression = "jiffies"
        if with_code_breakpoint:
            _Bp(stub, 6, TRAP_SITE)

        result = bridge.dispatch({"op": "resync", "params": {}})["result"]

        statuses = {e["number"]: e["status"] for e in result["breakpoints"]}
        assert statuses[5] == "unverified"


def test_wait_after_resync_reports_the_reread_state(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    hit = _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    fake_gdb.events.stop.fire(fake_gdb._FakeBreakpointEvent([hit]))
    assert bridge.dispatch({"op": "wait", "params": {}})["result"]["reason"]["kind"] == "breakpoint-hit"
    # A snapshot load replaced the machine; resync re-reads it.
    assert bridge.dispatch({"op": "resync", "params": {}})["result"]["reason"] == {"kind": "resynced"}

    for op in ("wait", "status"):
        response = bridge.dispatch({"op": op, "params": {}})
        assert response["result"]["reason"] == {"kind": "resynced"}, op
        assert "last_background_result" not in response["result"]


def test_arming_over_an_orphan_trap_drops_the_stub_record(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    # An int3 the stub still records but GDB does not own.
    stub.orphan(TRAP_SITE)
    _Bp(stub, 1, TRAP_SITE)

    result = bridge.dispatch({"op": "break_enable", "params": {"number": 1}})["result"]

    [trap] = result["baked_traps"]
    assert trap["stub_record"] is True and trap["repaired"] is True
    assert stub.orphans == {}
    assert stub.mem[TRAP_SITE] == ELF_WINDOW[0]
    _start_background(bridge, fake_gdb, stub)
    assert stub.mem[TRAP_SITE] == 0xCC  # GDB's insert really wrote its trap


@pytest.mark.parametrize("op", ["break_enable", "break_delete"])
def test_breakpoint_ops_drop_a_stale_stub_record(monkeypatch, op):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _Bp(stub, 2, TRAP_SITE)
    stub.stale.add(TRAP_SITE)

    response = bridge.dispatch({"op": op, "params": {"number": 1}})

    assert response["ok"] is True
    assert "baked_traps" not in response["result"]  # nothing was in memory
    assert stub.stale == set()
    _start_background(bridge, fake_gdb, stub)
    assert stub.mem[TRAP_SITE] == 0xCC


@pytest.mark.parametrize("op", ["load", "break_enable"])
def test_locations_gdb_gives_up_on_at_the_resume_are_reported(monkeypatch, tmp_path, op):
    rows = {"now": ""}
    _, fake_gdb, bridge, stub = _remote_target(
        monkeypatch, _memory(ELF_WINDOW), maint_rows=lambda: rows["now"]
    )
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    execute = fake_gdb.execute

    def give_up_at_resume(cmd, to_string=False):
        if cmd == "continue":
            rows["now"] = "1.1                         y   <PENDING>          f inf 1\n"
        return execute(cmd, to_string=to_string)

    fake_gdb.execute = give_up_at_resume
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")
    vmlinux = tmp_path / "vmlinux"
    vmlinux.write_bytes(b"")
    params = {"path": str(vmlinux), "slide": "0x0"} if op == "load" else {"number": 1}

    response = bridge.dispatch({"op": op, "params": params})

    result = response["result"]
    assert result["run_state"]["resumed"] is True
    assert result["run_state"]["pending_after_resume"] == ["1.1"]
    if op == "load":
        assert result["pending_breakpoints"] == [1]
    else:
        assert result["pending"] is True
        assert "address" not in result


def test_failed_resume_names_the_location_gdb_could_not_insert(monkeypatch):
    _, fake_gdb, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    _start_background(bridge, fake_gdb, stub)
    unmapped = _Bp(stub, 2, 0xFFFFFFFF91000000)
    unmapped.enabled = False
    fake_gdb._pending_stop_event = fake_gdb._FakeSignalEvent("SIGINT")

    response = bridge.dispatch({"op": "break_enable", "params": {"number": 2}})

    run_state = response["result"]["run_state"]
    assert run_state["resumed"] is False
    assert "Cannot insert breakpoint 2" in run_state["error"]
    assert stub.inserted == {}


def test_resync_reports_a_trap_that_never_lands_as_not_armed(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW))
    _Bp(stub, 1, TRAP_SITE)
    stub.stale.add(TRAP_SITE)
    stub.send_packet = lambda packet, _read=stub.send_packet: (
        b"E22" if packet.startswith("z0") else _read(packet)
    )

    result = bridge.dispatch({"op": "resync", "params": {}})["result"]

    [entry] = result["breakpoints"]
    assert entry["status"] == "not-resident"
    assert entry["trap_resident"] is False
    assert result["summary"]["armed"] == 0 and result["summary"]["not_armed"] == 1


def test_resync_does_not_judge_residency_where_the_stub_hides_traps(monkeypatch):
    _, _, bridge, stub = _remote_target(monkeypatch, _memory(ELF_WINDOW), writes=False)
    _Bp(stub, 1, TRAP_SITE)

    result = bridge.dispatch({"op": "resync", "params": {}})["result"]

    [entry] = result["breakpoints"]
    assert entry["status"] == "armed"
    assert entry["trap_resident"] is None
    assert "reseated" not in entry


def test_resync_refuses_without_a_live_target(monkeypatch):
    bridge_mod, fake_gdb = _load_bridge(monkeypatch)
    fake_gdb.selected_inferior().pid = 0
    response = bridge_mod.GdbBridge().dispatch({"op": "resync", "params": {}})
    assert response["ok"] is False


def test_resync_cli_sends_base_and_symbols(monkeypatch, tmp_path):
    captured = {}

    def fake_send_request(op, *, params=None, **kwargs):
        captured.update(op=op, params=params)
        return {"ok": True, "result": {"state": "running", "breakpoints": [], "summary": {}}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    assert pry.cli.main(["resync", "--base", "0xffffffff84600000", "--symbols", str(tmp_path / "vmlinux")]) == 0
    assert captured["op"] == "resync"
    assert captured["params"] == {
        "base": "0xffffffff84600000", "symbols": str((tmp_path / "vmlinux").resolve()),
    }


def test_resync_cli_rejects_symbols_without_base(monkeypatch):
    monkeypatch.setattr(pry.cli, "send_request", lambda *a, **k: pytest.fail("sent"))
    assert pry.cli.main(["resync", "--symbols", "/x/vmlinux"]) == 1
