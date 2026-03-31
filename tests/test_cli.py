from __future__ import annotations

import json
from pathlib import Path

import pry.cli
import pytest


def test_doctor_with_no_instances(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])

    rc = pry.cli.main(["doctor"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "cli version: 0.1.0" in output
    assert "instances:\n- none" in output


def test_doctor_json_format(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])

    rc = pry.cli.main(["doctor", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cli_version"] == "0.1.0"
    assert payload["instances"] == []


def test_load_sends_correct_op(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"loaded": params.get("path")}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["load", "/bin/ls"])

    assert rc == 0
    assert captured["op"] == "load"
    assert captured["params"]["path"].endswith("/bin/ls")


def test_break_set_sends_correct_params(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"number": 1, "type": 0, "location": "main", "enabled": True, "hits": 0}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "main", "--condition", "argc > 1", "--temporary"])

    assert rc == 0
    assert captured["op"] == "break_set"
    assert captured["params"]["location"] == "main"
    assert captured["params"]["condition"] == "argc > 1"
    assert captured["params"]["temporary"] is True


def test_break_list_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"number": 1, "type": "breakpoint", "location": "main", "enabled": True, "hits": 3, "condition": None, "temporary": False},
                {"number": 2, "type": "breakpoint", "location": "foo.c:42", "enabled": False, "hits": 0, "condition": "x > 5", "temporary": False},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "list"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "#1 breakpoint at main [enabled] hits=3" in output
    assert "#2 breakpoint at foo.c:42 [disabled] hits=0 if x > 5" in output


def test_break_set_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 1, "type": 0, "location": "main",
                "enabled": True, "hits": 0, "condition": None,
                "expression": None, "temporary": False,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "main"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "breakpoint #1 set at main [enabled]" in output


def test_break_set_text_with_condition_and_temporary(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 3, "type": 0, "location": "foo.c:10",
                "enabled": True, "hits": 0, "condition": "x > 5",
                "expression": None, "temporary": True,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "foo.c:10", "--condition", "x > 5", "--temporary"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "breakpoint #3 set at foo.c:10 [enabled] temporary if x > 5" in output


def test_break_delete_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"deleted": 3}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "delete", "3"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "breakpoint #3 deleted" in output


def test_break_enable_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 1, "type": 0, "location": "main",
                "enabled": True, "hits": 2, "condition": None,
                "expression": None, "temporary": False,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "enable", "1"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "breakpoint #1 at main [enabled]" in output


def test_break_disable_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 2, "type": 0, "location": "foo.c:42",
                "enabled": False, "hits": 0, "condition": None,
                "expression": None, "temporary": False,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "disable", "2"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "breakpoint #2 at foo.c:42 [disabled]" in output


def test_watch_set_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 4, "type": 2, "location": None,
                "enabled": True, "hits": 0, "condition": None,
                "expression": "buf", "temporary": False,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["watch", "set", "buf"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "watchpoint #4 on buf [enabled]" in output


def test_break_set_json_format_still_works(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "number": 1, "type": 0, "location": "main",
                "enabled": True, "hits": 0, "condition": None,
                "expression": None, "temporary": False,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "main", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["number"] == 1
    assert payload["location"] == "main"


def test_watch_delete_dispatches_to_break_delete(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"deleted": 5}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["watch", "delete", "5"])

    assert rc == 0
    assert captured["op"] == "break_delete"
    assert captured["params"]["number"] == 5
    output = capsys.readouterr().out
    assert "breakpoint #5 deleted" in output


def test_watch_list_dispatches_to_break_list(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        return {"ok": True, "result": []}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["watch", "list"])

    assert rc == 0
    assert captured["op"] == "break_list"


def test_info_files_text_rendering(monkeypatch, capsys):
    raw_output = 'Symbols from "/bin/test".\nLocal exec file:\n\t0x401000 - 0x401100 is .text\n'

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"raw": raw_output}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["info", "files"])

    assert rc == 0
    output = capsys.readouterr().out
    assert ".text" in output
    assert '"raw"' not in output  # should NOT be JSON-wrapped


def test_backtrace_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"level": 0, "function": "main", "address": "0x401000", "file": "main.c", "line": 42, "args": [{"name": "argc", "value": "1"}]},
                {"level": 1, "function": "__libc_start_main", "address": "0x7fff000", "args": []},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["backtrace"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "#0 0x401000 in main at main.c:42 (argc=1)" in output
    assert "#1 0x7fff000 in __libc_start_main" in output


def test_run_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "status": "stopped",
                "reason": {"kind": "breakpoint-hit", "number": 1, "location": "main"},
                "frame": {"function": "main", "file": "test.c", "line": 10, "address": "0x401000"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["run"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "status: stopped" in output
    assert "reason: breakpoint #1 hit" in output
    assert "frame: main at test.c:10 (0x401000)" in output


def test_run_text_rendering_signal(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "status": "stopped",
                "reason": {"kind": "signal", "signal": "SIGSEGV"},
                "frame": {"function": "main", "file": "test.c", "line": 10, "address": "0x401000"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["run"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "status: stopped" in output
    assert "reason: signal SIGSEGV" in output


def test_registers_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"name": "rax", "value": "0x0"},
                {"name": "rbx", "value": "0x7fffffffe000"},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["registers"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "rax" in output
    assert "0x0" in output
    assert "rbx" in output


def test_locals_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"name": "x", "value": "42", "type": "int"},
                {"name": "buf", "value": "\"hello\"", "type": "char *"},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["locals"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "int x = 42" in output
    assert 'char * buf = "hello"' in output


def test_functions_pagination(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        # Return more items than the limit to trigger truncation warning
        return {
            "ok": True,
            "result": [
                {"name": f"func_{i}", "address": hex(0x401000 + i * 0x100)}
                for i in range(11)
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["functions", "--limit", "10"])

    assert rc == 0
    assert captured["params"]["limit"] == 11  # limit+1 for truncation detection
    stderr = capsys.readouterr().err
    assert "truncated to 10" in stderr


def test_print_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"value": "42", "type": "int"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["print", "argc"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "(int) 42" in output


def test_bridge_error_reports_to_stderr(monkeypatch, capsys):
    import pry.transport
    # Don't mock send_request — let it try to connect and fail
    monkeypatch.setattr(pry.transport, "list_instances", lambda: [])

    # step/next/etc. all call send_request which calls choose_instance
    rc = pry.cli.main(["step"])

    assert rc == 0
    stderr = capsys.readouterr().err
    assert "No running GDB bridge" in stderr


def test_py_exec_sends_code(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"stdout": "hello\n", "result": None}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["py", "exec", "--code", "print('hello')"])

    assert rc == 0
    assert captured["op"] == "py_exec"
    assert captured["params"]["code"] == "print('hello')"
    output = capsys.readouterr().out
    assert "hello" in output


def test_inferior_list_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"num": 1, "pid": 1234, "executable": "/bin/ls", "selected": True},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["inferior", "list"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "1 *" in output
    assert "pid=1234" in output
    assert "/bin/ls" in output


def test_launch_gdb_not_found(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: None)

    rc = pry.cli.main(["launch"])

    assert rc == 0
    stderr = capsys.readouterr().err
    assert "gdb not found" in stderr.lower()


def test_kill_no_session(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])

    rc = pry.cli.main(["kill"])

    assert rc == 0
    stderr = capsys.readouterr().err
    assert "no running" in stderr.lower()


def test_kill_single_instance(monkeypatch, capsys, tmp_path):
    from pry.transport import BridgeInstance

    instance = BridgeInstance(
        pid=99999,
        socket_path=tmp_path / "99999.sock",
        registry_path=tmp_path / "99999.json",
        plugin_name="pry_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
    )
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [instance])
    # Simulate process already dead
    monkeypatch.setattr(pry.cli.os, "kill", lambda pid, sig: (_ for _ in ()).throw(ProcessLookupError()))

    rc = pry.cli.main(["kill"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "99999" in output


def test_kill_ambiguous_instances(monkeypatch, capsys, tmp_path):
    from pry.transport import BridgeInstance

    instances = [
        BridgeInstance(pid=111, socket_path=tmp_path / "a.sock", registry_path=tmp_path / "a.json",
                       plugin_name="pry_agent_bridge", plugin_version="0.1.0", started_at=None, meta={}),
        BridgeInstance(pid=222, socket_path=tmp_path / "b.sock", registry_path=tmp_path / "b.json",
                       plugin_name="pry_agent_bridge", plugin_version="0.1.0", started_at=None, meta={}),
    ]
    monkeypatch.setattr(pry.cli, "list_instances", lambda: instances)

    rc = pry.cli.main(["kill"])

    assert rc == 0
    stderr = capsys.readouterr().err
    assert "multiple" in stderr.lower()
    assert "111" in stderr
    assert "222" in stderr


def test_connect_sends_correct_op(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {
            "ok": True,
            "result": {
                "connected": "localhost:1234",
                "status": "stopped",
                "frame": {"function": "start_kernel", "address": "0xffffffff81000000"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["connect", "localhost:1234"])

    assert rc == 0
    assert captured["op"] == "connect"
    assert captured["params"]["target"] == "localhost:1234"
    assert captured["timeout"] == 20  # default 15s connect-timeout + 5s buffer


def test_connect_custom_timeout_propagates(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["params"] = params
        captured["timeout"] = timeout
        return {
            "ok": True,
            "result": {
                "connected": "localhost:1234",
                "status": "stopped",
                "frame": {"function": "start_kernel", "address": "0xffffffff81000000"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["connect", "--connect-timeout", "3", "localhost:1234"])

    assert rc == 0
    assert captured["params"]["connect_timeout"] == 3
    assert captured["timeout"] == 8  # 3s connect-timeout + 5s buffer


def test_connect_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "connected": "localhost:1234",
                "status": "stopped",
                "frame": {"function": "start_kernel", "address": "0xffffffff81000000"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["connect", "localhost:1234"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "connected: localhost:1234" in output
    assert "status: stopped" in output
    assert "start_kernel" in output


def test_disconnect_sends_correct_op(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        return {"ok": True, "result": {"disconnected": True}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["disconnect"])

    assert rc == 0
    assert captured["op"] == "disconnect"


def test_info_target_sends_correct_op(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        return {
            "ok": True,
            "result": {
                "raw": "Remote serial target in gdb-specific protocol:\n",
                "connections": "* 1    remote localhost:1234\n",
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["info", "target"])

    assert rc == 0
    assert captured["op"] == "target_info"
    output = capsys.readouterr().out
    assert "Remote serial target" in output
    assert "localhost:1234" in output


def test_gdb_exec_sends_correct_op(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"output": "rax  0x0  0\n"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["gdb", "info registers"])

    assert rc == 0
    assert captured["op"] == "gdb_exec"
    assert captured["params"]["command"] == "info registers"
    output = capsys.readouterr().out
    assert "rax" in output


def test_gdb_exec_json_format(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"output": "KBASE: 0xffffffff81000000\n"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["gdb", "--format", "json", "kbase"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["output"] == "KBASE: 0xffffffff81000000\n"


def test_gdb_exec_empty_output(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"output": ""}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["gdb", "set pagination off"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "(no output)" in output


# ---------------------------------------------------------------------------
# Feature 1: Timeout propagation to bridge
# ---------------------------------------------------------------------------

def test_continue_with_timeout_sends_timeout_param(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {
            "ok": True,
            "result": {"status": "stopped", "frame": {"function": "main"}, "thread": 1},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["continue", "--timeout", "45"])

    assert rc == 0
    assert captured["params"]["_timeout"] == 45.0
    assert captured["timeout"] == 55.0  # 45 + 10 buffer


def test_stop_text_shows_timeout_interrupt(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "status": "stopped",
                "timeout_interrupt": True,
                "frame": {"function": "loop"},
                "thread": 1,
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["continue", "--timeout", "5"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "interrupted due to timeout" in output


# ---------------------------------------------------------------------------
# Feature 2: py exec timeout
# ---------------------------------------------------------------------------

def test_py_exec_with_timeout(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {"ok": True, "result": {"stdout": "", "result": None}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["py", "exec", "--code", "pass", "--timeout", "60"])

    assert rc == 0
    assert captured["params"]["_timeout"] == 60.0
    assert captured["timeout"] == 60.0


# ---------------------------------------------------------------------------
# Feature 3: Background continue, status, wait
# ---------------------------------------------------------------------------

def test_continue_background_sends_param(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"status": "running"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["continue", "--background"])

    assert rc == 0
    assert captured["params"]["_background"] is True
    output = capsys.readouterr().out
    assert "running" in output


def test_status_command(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {"state": "stopped", "status": "stopped",
                        "frame": {"function": "main"}, "thread": 1},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["status"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "stopped" in output


def test_wait_command_with_timeout(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {
            "ok": True,
            "result": {"state": "stopped", "status": "stopped",
                        "frame": {"function": "main"}, "thread": 1},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["wait", "--timeout", "30"])

    assert rc == 0
    assert captured["op"] == "wait"
    assert captured["params"]["_timeout"] == 30.0
    assert captured["timeout"] == 40.0  # 30 + 10 buffer


# ---------------------------------------------------------------------------
# Feature 4: PIE rebasing params
# ---------------------------------------------------------------------------

def test_break_set_rebase_sends_params(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {
            "ok": True,
            "result": {
                "number": 1, "type": 0, "location": "*0x555555555234",
                "enabled": True, "hits": 0,
                "rebased": {
                    "module": "target",
                    "offset": "0x1234",
                    "image_base": "0x0",
                    "module_base": "0x555555554000",
                    "resolved": "0x555555555234",
                },
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "*0x1234", "--rebase", "target"])

    assert rc == 0
    assert captured["params"]["rebase_module"] == "target"
    output = capsys.readouterr().out
    assert "rebased from" in output
    assert "target" in output


def test_break_set_rebase_with_image_base_param(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["params"] = params
        return {
            "ok": True,
            "result": {"number": 1, "type": 0, "location": "*0x55555555a56e",
                        "enabled": True, "hits": 0},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["break", "set", "*0x40656e", "--rebase", "target", "--image-base", "0x400000"])

    assert rc == 0
    assert captured["params"]["rebase_module"] == "target"
    assert captured["params"]["image_base"] == 0x400000


# ---------------------------------------------------------------------------
# Feature 5: Trace command
# ---------------------------------------------------------------------------

def test_trace_sends_correct_params(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {
            "ok": True,
            "result": {
                "hits": [{"pc": "0x404610", "asm": "mov eax, [rbx]"}],
                "hit_count": 1,
                "truncated": False,
                "watch_addr": "0x7fffffffd5d4",
                "watch_size": 4,
                "range_start": "0x404610",
                "range_end": "0x405e30",
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main([
        "trace",
        "--watch", "0x7fffffffd5d4",
        "--range", "0x404610-0x405e30",
        "--type", "access",
        "--timeout", "60",
    ])

    assert rc == 0
    assert captured["op"] == "trace"
    assert captured["params"]["watch_addr"] == "0x7fffffffd5d4"
    assert captured["params"]["range_start"] == "0x404610"
    assert captured["params"]["range_end"] == "0x405e30"
    assert captured["params"]["watch_type"] == "access"
    assert captured["params"]["_timeout"] == 60.0
    assert captured["timeout"] == 70.0  # 60 + 10 buffer
    output = capsys.readouterr().out
    assert "1 hits" in output
    assert "0x404610" in output
    assert "mov eax" in output


def test_trace_text_truncated_warning(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "hits": [],
                "hit_count": 10000,
                "truncated": True,
                "watch_addr": "0x1000",
                "watch_size": 4,
                "range_start": "0x2000",
                "range_end": "0x3000",
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["trace", "--watch", "0x1000", "--range", "0x2000-0x3000"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "hit limit reached" in output
