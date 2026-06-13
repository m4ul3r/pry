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

    assert rc == 1
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


def test_threads_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        assert op == "list_threads"
        assert params == {}
        return {
            "ok": True,
            "result": [
                {
                    "num": 1,
                    "inferior_num": 1,
                    "selected": True,
                    "status": "stopped",
                    "name": "main-thread",
                    "frame": {"address": "0x401000", "function": "main"},
                },
                {
                    "num": 2,
                    "inferior_num": 1,
                    "selected": False,
                    "status": "stopped",
                    "frame": {"address": "0x401100", "function": "worker"},
                },
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["threads"])

    assert rc == 0
    output = capsys.readouterr().out
    assert "1 *  inferior=1  stopped  0x401000  main  (main-thread)" in output
    assert "2  inferior=1  stopped  0x401100  worker" in output


def test_threads_passes_filters(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        assert op == "list_threads"
        assert params == {"pc": "0x401100", "function": "worker"}
        return {"ok": True, "result": []}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["threads", "--pc", "0x401100", "--function", "worker"])

    assert rc == 0
    assert capsys.readouterr().out == "no threads\n"


def test_memory_read_text_includes_address_by_default(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        assert op == "memory_read"
        assert params == {"address": "0x401000", "length": 4}
        return {
            "ok": True,
            "result": {"address": "0x401000", "length": 4, "format": "hex", "data": "41424344"},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["memory", "read", "0x401000", "4"])

    assert rc == 0
    assert capsys.readouterr().out == "0x401000: 41424344\n"


def test_memory_read_plain_text_prints_data_only(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        assert op == "memory_read"
        assert params == {"address": "0x401000", "length": 4}
        return {
            "ok": True,
            "result": {"address": "0x401000", "length": 4, "format": "hex", "data": "41424344"},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["memory", "read", "0x401000", "4", "--display", "hex", "--plain"])

    assert rc == 0
    assert capsys.readouterr().out == "41424344\n"


def test_memory_read_plain_does_not_change_json_payload(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        assert op == "memory_read"
        return {
            "ok": True,
            "result": {"address": "0x401000", "length": 4, "format": "hex", "data": "41424344"},
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["memory", "read", "0x401000", "4", "--plain", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["address"] == "0x401000"
    assert payload["data"] == "41424344"


def test_install_tree_idempotent_symlink(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "marker").write_text("x")
    dest = tmp_path / "dest"

    created = pry.cli._install_tree(source, dest, mode="symlink", force=False)
    assert created is True
    assert dest.is_symlink()

    # Re-installing the exact same symlink is a no-op, not an error.
    again = pry.cli._install_tree(source, dest, mode="symlink", force=False)
    assert again is False
    assert dest.is_symlink()


def test_install_tree_conflicting_dest_errors(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    dest = tmp_path / "dest"
    dest.symlink_to(other)  # already points somewhere else

    with pytest.raises(pry.cli.BridgeError, match="already exists"):
        pry.cli._install_tree(source, dest, mode="symlink", force=False)


def test_skill_install_copy_mode(tmp_path):
    destination = tmp_path / "skill-copy"

    rc = pry.cli.main(["skill", "install", "--mode", "copy", "--dest", str(destination)])

    assert rc == 0
    assert (destination / "pry" / "SKILL.md").exists()
    assert (destination / "pry" / "agents" / "openai.yaml").exists()


def test_skill_install_defaults_to_claude_only_without_codex_home(tmp_path, monkeypatch):
    claude_root = tmp_path / "claude" / "skills"
    codex_home = tmp_path / "codex"
    codex_root = codex_home / "skills"
    monkeypatch.setattr(pry.cli, "claude_skills_dir", lambda: claude_root)
    monkeypatch.setattr(pry.cli, "codex_home", lambda: codex_home)
    monkeypatch.setattr(pry.cli, "codex_skills_dir", lambda: codex_root)

    rc = pry.cli.main(["skill", "install", "--mode", "copy"])

    assert rc == 0
    assert (claude_root / "pry" / "SKILL.md").exists()
    assert not codex_root.exists()


def test_skill_install_defaults_to_claude_and_codex_when_codex_home_exists(tmp_path, monkeypatch):
    claude_root = tmp_path / "claude" / "skills"
    codex_home = tmp_path / "codex"
    codex_root = codex_home / "skills"
    codex_home.mkdir()
    monkeypatch.setattr(pry.cli, "claude_skills_dir", lambda: claude_root)
    monkeypatch.setattr(pry.cli, "codex_home", lambda: codex_home)
    monkeypatch.setattr(pry.cli, "codex_skills_dir", lambda: codex_root)

    rc = pry.cli.main(["skill", "install", "--mode", "copy"])

    assert rc == 0
    assert (claude_root / "pry" / "SKILL.md").exists()
    assert (codex_root / "pry" / "SKILL.md").exists()


def test_skill_install_defaults_skip_existing_destinations(tmp_path, monkeypatch):
    claude_root = tmp_path / "claude" / "skills"
    codex_home = tmp_path / "codex"
    codex_root = codex_home / "skills"
    codex_home.mkdir()
    (claude_root / "pry").mkdir(parents=True)
    monkeypatch.setattr(pry.cli, "claude_skills_dir", lambda: claude_root)
    monkeypatch.setattr(pry.cli, "codex_home", lambda: codex_home)
    monkeypatch.setattr(pry.cli, "codex_skills_dir", lambda: codex_root)

    rc = pry.cli.main(["skill", "install", "--mode", "copy"])

    assert rc == 0
    assert (codex_root / "pry" / "SKILL.md").exists()


def test_skill_install_default_output_is_text(tmp_path, monkeypatch, capsys):
    claude_root = tmp_path / "claude" / "skills"
    codex_home = tmp_path / "codex"
    monkeypatch.setattr(pry.cli, "claude_skills_dir", lambda: claude_root)
    monkeypatch.setattr(pry.cli, "codex_home", lambda: codex_home)

    rc = pry.cli.main(["skill", "install", "--mode", "copy"])

    assert rc == 0
    output = capsys.readouterr().out
    assert output.startswith("Installed skills (copy):\n")
    assert "- " + str(claude_root / "pry") in output
    assert '"installed"' not in output


def test_skill_install_json_output_remains_available(tmp_path, monkeypatch, capsys):
    claude_root = tmp_path / "claude" / "skills"
    codex_home = tmp_path / "codex"
    monkeypatch.setattr(pry.cli, "claude_skills_dir", lambda: claude_root)
    monkeypatch.setattr(pry.cli, "codex_home", lambda: codex_home)

    rc = pry.cli.main(["skill", "install", "--mode", "copy", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["installed"] is True
    assert "installed_destinations" in payload


def test_skill_install_custom_dest_reports_error_when_destination_exists(tmp_path, capsys):
    destination = tmp_path / "skill-copy"
    (destination / "pry").mkdir(parents=True)

    rc = pry.cli.main(["skill", "install", "--mode", "copy", "--dest", str(destination)])

    assert rc == 1
    assert "Destination already exists" in capsys.readouterr().err


def test_launch_gdb_not_found(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: None)

    rc = pry.cli.main(["launch"])

    assert rc == 1
    stderr = capsys.readouterr().err
    assert "gdb not found" in stderr.lower()


def test_launch_pry_flag_after_binary_errors(monkeypatch, capsys, tmp_path):
    # gdb IS present, so we get past the which() check and into arg handling.
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: "/usr/bin/gdb")
    monkeypatch.setattr(pry.cli, "_resolve_plugin_path", lambda: pry.cli.Path("/tmp"))
    binary = tmp_path / "bin"  # real file so binary validation passes
    binary.write_text("")

    rc = pry.cli.main(["launch", str(binary), "--format", "json"])

    assert rc == 1
    stderr = capsys.readouterr().err.lower()
    assert "--format" in stderr
    assert "before the binary" in stderr


def test_launch_double_dash_passes_gdb_args(monkeypatch, capsys, tmp_path):
    # A leading `--` means everything after is a genuine GDB arg, not a pry
    # flag — the leaked-flag guard must not fire.
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: "/usr/bin/gdb")
    monkeypatch.setattr(pry.cli, "_resolve_plugin_path", lambda: pry.cli.Path("/tmp"))
    binary = tmp_path / "bin"  # real file so binary validation passes
    binary.write_text("")

    def _boom(*a, **k):
        raise AssertionError("reached subprocess.Popen — guard wrongly passed")

    # We only care that the guard doesn't raise; stop before actually spawning.
    monkeypatch.setattr(pry.cli.subprocess, "Popen", _boom)

    with pytest.raises(AssertionError, match="reached subprocess.Popen"):
        pry.cli.main(["launch", str(binary), "--", "--format", "json"])


def test_launch_missing_binary_errors(monkeypatch, capsys, tmp_path):
    # A non-existent binary must fail fast (before spawning GDB), not come up as
    # a dead session that reports success.
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: "/usr/bin/gdb")
    monkeypatch.setattr(pry.cli, "_resolve_plugin_path", lambda: pry.cli.Path("/tmp"))

    def _boom(*a, **k):
        raise AssertionError("should not spawn GDB for a missing binary")

    monkeypatch.setattr(pry.cli.subprocess, "Popen", _boom)

    rc = pry.cli.main(["launch", str(tmp_path / "does_not_exist")])

    assert rc == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_launch_binary_is_directory_errors(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(pry.cli.shutil, "which", lambda cmd: "/usr/bin/gdb")
    monkeypatch.setattr(pry.cli, "_resolve_plugin_path", lambda: pry.cli.Path("/tmp"))

    def _boom(*a, **k):
        raise AssertionError("should not spawn GDB for a directory")

    monkeypatch.setattr(pry.cli.subprocess, "Popen", _boom)

    rc = pry.cli.main(["launch", str(tmp_path)])  # a directory, not a file

    assert rc == 1
    assert "not a file" in capsys.readouterr().err.lower()


def test_kill_no_session(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])

    rc = pry.cli.main(["kill"])

    assert rc == 1
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

    assert rc == 1
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
    # The bridge-side timeout is exactly what the user asked for...
    assert captured["params"]["_timeout"] == 60.0
    # ...but the transport waits longer so the bridge has time to interrupt a
    # runaway script and return its structured error before the socket gives up.
    assert captured["timeout"] == 70.0


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


# ---------------------------------------------------------------------------
# Agent-usability improvements
# ---------------------------------------------------------------------------

def test_spill_writes_envelope_to_stdout(monkeypatch, capsys):
    from pry.output import OutputWriteResult

    artifact = {
        "artifact_path": "/tmp/pry/x.json",
        "format": "json",
        "bytes": 99999,
        "tokens": 12345,
        "tokenizer": "o200k_base",
        "sha256": "abc",
        "summary": {"kind": "array", "count": 500},
    }
    envelope = '{"artifact_path": "/tmp/pry/x.json"}\n'

    monkeypatch.setattr(
        pry.cli,
        "write_output_result",
        lambda *a, **k: OutputWriteResult(rendered=envelope, artifact=artifact, spilled=True),
    )

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"value": "42"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["print", "x"])
    assert rc == 0
    captured = capsys.readouterr()
    # The artifact envelope is the result and must land on stdout.
    assert envelope in captured.out
    # A concise note goes to stderr.
    assert "spilled to /tmp/pry/x.json" in captured.err
    assert "12345 tokens" in captured.err


def test_continue_renders_watchpoint_old_new(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "status": "stopped",
                "reason": {
                    "kind": "watchpoint-hit", "number": 2, "expression": "counter",
                    "old_value": "0x3", "new_value": "0x4",
                },
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["continue"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "watchpoint #2 (counter) hit: 0x3 -> 0x4" in output


def test_backtrace_renders_unresolved_frame_as_qq(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": [
                {"level": 0, "function": "vuln", "address": "0x401147"},
                {"level": 1, "function": None, "address": "0x4141414141414141"},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["backtrace"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "#1 0x4141414141414141 in ??" in output
    assert "None" not in output


def test_watch_delete_renders_watchpoint_noun(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"deleted": 2, "kind": "hw-watchpoint"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["watch", "delete", "2"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "watchpoint #2 deleted" in output


def test_gdb_exec_json_strips_ansi(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"output": "\x1b[33mPartial RELRO\x1b[0m\n"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["gdb", "--format", "json", "checksec"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["output"] == "Partial RELRO\n"
    assert "\x1b" not in out


def test_register_write_sends_op_and_renders(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"register": "rip", "value": "0x401234", "readback": "0x401234"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["registers", "write", "rip", "0x401234", "--format", "text"])
    assert rc == 0
    assert captured["op"] == "register_write"
    assert captured["params"] == {"name": "rip", "value": "0x401234"}
    output = capsys.readouterr().out
    assert "$rip = 0x401234" in output


def test_mappings_sends_op_and_renders(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {
            "ok": True,
            "result": [
                {"start": "0x555555554000", "end": "0x555555555000", "perms": "r-xp",
                 "offset": "0x0", "objfile": "/usr/bin/app", "size": 4096},
            ],
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["mappings", "--name", "app"])
    assert rc == 0
    assert captured["op"] == "mappings"
    assert captured["params"] == {"name": "app"}
    output = capsys.readouterr().out
    assert "/usr/bin/app" in output
    assert "r-xp" in output


def test_disasm_renders_symbol_annotation(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": [{"address": "0x401147", "asm": "ret", "symbol": "vuln+33"}]}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["disasm", "vuln"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "0x401147 <vuln+33>:  ret" in output


def test_args_empty_renders_no_args(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": []}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["args"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "no args" in output


def test_print_renders_stale_note(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {
            "ok": True,
            "result": {
                "value": "0x0", "type": "int", "live": False,
                "note": "no live inferior — value read from the static binary image, not live memory",
            },
        }

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["print", "counter"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "(int) 0x0" in output
    assert "note: no live inferior" in output


def test_load_base_sends_param(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"loaded": params["path"], "base": "0xffffffff84400000", "slide": "0x3400000"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["load", "/x/vmlinux", "--base", "0xffffffff84400000", "--format", "text"])
    assert rc == 0
    assert captured["op"] == "load"
    assert captured["params"]["base"] == "0xffffffff84400000"
    out = capsys.readouterr().out
    assert "loaded /x/vmlinux @ 0xffffffff84400000 (slide 0x3400000)" in out


def test_load_slide_sends_param(monkeypatch, capsys):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        return {"ok": True, "result": {"loaded": params["path"], "slide": params.get("slide")}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["load", "/x/vmlinux", "--slide", "0x7000000", "--format", "text"])
    assert rc == 0
    assert captured["params"]["slide"] == "0x7000000"
    out = capsys.readouterr().out
    assert "loaded /x/vmlinux (slide 0x7000000)" in out


# ---------------------------------------------------------------------------
# Agent-ease review fixes: kill --all, logs
# ---------------------------------------------------------------------------

def _mk_instance(tmp_path, pid):
    from pry.transport import BridgeInstance
    return BridgeInstance(
        pid=pid, socket_path=tmp_path / f"{pid}.sock", registry_path=tmp_path / f"{pid}.json",
        plugin_name="pry_agent_bridge", plugin_version="0.1.0", started_at=None, meta={},
    )


def test_kill_all(monkeypatch, capsys, tmp_path):
    instances = [_mk_instance(tmp_path, 111), _mk_instance(tmp_path, 222)]
    monkeypatch.setattr(pry.cli, "list_instances", lambda: instances)
    monkeypatch.setattr(pry.cli.os, "kill", lambda pid, sig: (_ for _ in ()).throw(ProcessLookupError()))

    rc = pry.cli.main(["kill", "--all"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "111" in out and "222" in out


def test_kill_all_none_running(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])
    rc = pry.cli.main(["kill", "--all"])
    assert rc == 0
    assert "No running GDB sessions" in capsys.readouterr().out


def test_logs_reads_instance_log(monkeypatch, capsys, tmp_path):
    inst = _mk_instance(tmp_path, 4242)
    logf = tmp_path / "4242.log"
    logf.write_text("starting\nWIN reached\ndone\n")
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    monkeypatch.setattr(pry.cli, "gdb_log_path", lambda pid=None: logf)

    rc = pry.cli.main(["logs"])
    assert rc == 0
    assert "WIN reached" in capsys.readouterr().out


def test_logs_tail_lines(monkeypatch, capsys, tmp_path):
    inst = _mk_instance(tmp_path, 4242)
    logf = tmp_path / "4242.log"
    logf.write_text("a\nb\nc\nd\n")
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    monkeypatch.setattr(pry.cli, "gdb_log_path", lambda pid=None: logf)

    rc = pry.cli.main(["logs", "-n", "2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "c\nd" in out and "a\n" not in out


def test_logs_json_envelope(monkeypatch, capsys, tmp_path):
    inst = _mk_instance(tmp_path, 4242)
    logf = tmp_path / "4242.log"
    logf.write_text("hello\n")
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    monkeypatch.setattr(pry.cli, "gdb_log_path", lambda pid=None: logf)

    rc = pry.cli.main(["logs", "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pid"] == 4242
    assert payload["content"] == "hello\n"


def test_logs_no_session(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])
    rc = pry.cli.main(["logs"])
    assert rc == 1
    assert "No running GDB session" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Review nice-to-haves: doctor binary, action text renderers, type offsets
# ---------------------------------------------------------------------------

def test_doctor_text_shows_binary(monkeypatch, capsys):
    inst = _mk_instance(__import__("pathlib").Path("/tmp"), 555)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])

    def fake_send(instance, op, params=None, **kw):
        return {"ok": True, "result": {
            "plugin_version": "0.1.0", "plugin_build_id": "abc", "gdb_version": "17.2",
            "inferiors": [{"num": 1, "pid": 777, "executable": "/tmp/target", "selected": True}],
        }}

    monkeypatch.setattr(pry.cli, "_send_request_to_instance", fake_send)
    rc = pry.cli.main(["doctor"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "binary: /tmp/target (inferior pid 777)" in out


def test_attach_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"attached": 1234, "status": "stopped",
                                       "frame": {"function": "main", "file": "a.c", "line": 5}}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["attach", "1234", "--format", "text"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "attached to pid 1234" in out
    assert "frame: main at a.c:5" in out


def test_interrupt_text_default(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"interrupted": True}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["interrupt"])  # default is now text
    assert rc == 0
    assert capsys.readouterr().out.strip() == "interrupted"


def test_interrupt_text_not_running(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"interrupted": False, "state": "stopped"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["interrupt"])
    assert rc == 0
    assert "not interrupted (inferior is stopped)" in capsys.readouterr().out


def test_memory_write_text_rendering(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {"written": 4, "address": "0x401000"}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["memory", "write", "0x401000", "deadbeef", "--format", "text"])
    assert rc == 0
    assert "wrote 4 bytes to 0x401000" in capsys.readouterr().out


def test_types_show_text_includes_offsets(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": {
            "name": "struct config", "sizeof": 24,
            "decl": "type = struct config {\n    int id;\n    char tag[8];\n    long flags;\n}",
            "fields": [
                {"name": "id", "type": "int", "bitpos": 0},
                {"name": "tag", "type": "char [8]", "bitpos": 32},
                {"name": "flags", "type": "long", "bitpos": 128},
            ],
        }}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["types", "show", "struct config"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "offsets (sizeof=24):" in out
    assert "+0" in out and "+4" in out and "+16" in out
    assert "flags" in out


# ---------------------------------------------------------------------------
# Edge-case hardening (adversarial hunt fixes)
# ---------------------------------------------------------------------------

def test_out_to_bad_path_exits_nonzero_with_error(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])
    rc = pry.cli.main(["doctor", "--out", str(tmp_path)])  # tmp_path is a directory
    assert rc == 1  # command failures exit non-zero so agents can gate on $?
    err = capsys.readouterr().err
    assert "cannot write output" in err


def test_mappings_filter_no_match_message(monkeypatch, capsys):
    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        return {"ok": True, "result": []}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    rc = pry.cli.main(["mappings", "--name", "libxyz"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no mappings match --name libxyz" in out


def test_render_backtrace_full_shows_locals():
    frames = [
        {
            "level": 0,
            "address": "0x401234",
            "function": "main",
            "file": "buffer_walk.c",
            "line": 22,
            "args": [{"name": "argc", "value": "0x1"}],
            "locals": [
                {"name": "argc", "value": "0x1", "is_argument": True},
                {"name": "i", "value": "0x0", "is_argument": False},
                {"name": "shared", "value": "0x9", "is_argument": False},
            ],
        }
    ]
    text = pry.cli._render_backtrace_text(frames)
    # Arguments stay in the (...) header; non-argument locals render beneath.
    assert "#0 0x401234 in main at buffer_walk.c:22 (argc=0x1)" in text
    assert "    i = 0x0" in text
    assert "    shared = 0x9" in text
    # argc appears once (as an arg in the header), not duplicated as a local.
    assert text.count("argc") == 1


def test_doctor_instance_not_found_exits_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [])
    rc = pry.cli.main(["--instance", "424242", "doctor"])
    assert rc == 1
    assert "424242" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Follow-up gap fixes: --thread, examine, disasm range/source, call, frame
# up/down, thread select, display, jump, break-list enrichment
# ---------------------------------------------------------------------------

def _capture_send(monkeypatch, result=None):
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["params"] = params
        captured["timeout"] = timeout
        return {"ok": True, "result": result if result is not None else {}}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)
    return captured


def test_thread_flag_plumbed_into_params(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result=[])
    rc = pry.cli.main(["backtrace", "--thread", "3"])
    assert rc == 0
    assert cap["op"] == "backtrace"
    assert cap["params"]["thread"] == 3


def test_no_thread_flag_omits_param(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result=[])
    pry.cli.main(["backtrace"])
    assert "thread" not in (cap["params"] or {})


def test_examine_builds_spec_from_parts(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"text": "", "lines": []})
    pry.cli.main(["examine", "$rsp", "--count", "8", "--fmt", "x", "--size", "w"])
    assert cap["op"] == "examine"
    assert cap["params"] == {"address": "$rsp", "count": 8, "format": "x", "size": "w"}


def test_examine_raw_spec(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"text": "", "lines": []})
    pry.cli.main(["examine", "0x1000", "--spec", "3i"])
    assert cap["params"] == {"address": "0x1000", "spec": "3i"}


def test_disasm_range_and_source_params(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result=[])
    pry.cli.main(["disasm", "--start", "main", "--end", "main+16", "--source"])
    assert cap["params"]["start"] == "main"
    assert cap["params"]["end"] == "main+16"
    assert cap["params"]["source"] is True


def test_call_sends_call_op(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"value": "0x5", "type": "int"})
    pry.cli.main(["call", '(int)strlen("hi")'])
    assert cap["op"] == "call"
    assert cap["params"]["expression"] == '(int)strlen("hi")'


def test_frame_up_down_send_ops(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"level": 1})
    pry.cli.main(["frame", "up", "2"])
    assert cap["op"] == "frame_up"
    assert cap["params"]["count"] == 2
    cap = _capture_send(monkeypatch, result={"level": 0})
    pry.cli.main(["frame", "down"])
    assert cap["op"] == "frame_down"


def test_thread_select_sends_op(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"num": 3})
    pry.cli.main(["thread", "select", "3"])
    assert cap["op"] == "thread_select"
    assert cap["params"]["num"] == 3


def test_display_add_list_remove_ops(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"number": 1, "expr": "head"})
    pry.cli.main(["display", "add", "head"])
    assert cap["op"] == "display_add"
    assert cap["params"]["expression"] == "head"

    cap = _capture_send(monkeypatch, result=[])
    pry.cli.main(["display", "list"])
    assert cap["op"] == "display_list"

    cap = _capture_send(monkeypatch, result={"removed": 2})
    pry.cli.main(["display", "remove", "2"])
    assert cap["op"] == "display_remove"
    assert cap["params"]["number"] == 2


def test_jump_sends_op(monkeypatch, capsys):
    cap = _capture_send(monkeypatch, result={"status": "stopped"})
    pry.cli.main(["jump", "file.c:42"])
    assert cap["op"] == "jump"
    assert cap["params"]["location"] == "file.c:42"


def test_render_breakpoint_list_thread_ignore_catch():
    value = [
        {"number": 1, "kind": "breakpoint", "location": "bump", "enabled": True,
         "hits": 0, "thread": 3, "ignore": 0},
        {"number": 2, "kind": "breakpoint", "location": "main", "enabled": True,
         "hits": 5, "thread": None, "ignore": 4},
        {"number": 3, "kind": "catchpoint", "location": None, "enabled": True,
         "hits": 0, "what": 'syscall "write"'},
    ]
    text = pry.cli._render_breakpoint_list_text(value)
    assert "thread 3" in text
    assert "ignore 4" in text
    assert 'catchpoint for syscall "write"' in text


def test_render_stop_text_shows_displays():
    value = {
        "status": "stopped",
        "frame": {"function": "main"},
        "displays": [{"number": 1, "expr": "head", "value": "0x405010"}],
    }
    text = pry.cli._render_stop_text(value)
    assert "display #1: head = 0x405010" in text


def test_render_display_list_text():
    text = pry.cli._render_display_list_text(
        [{"number": 2, "expr": "argc", "value": "0x1"}]
    )
    assert "#2: argc = 0x1" in text
    assert pry.cli._render_display_list_text([]) == "no displays"


def test_render_breakpoint_set_shows_resolved_location():
    value = {
        "number": 1, "kind": "breakpoint", "location": "main", "enabled": True,
        "address": "0x401445", "file": "workshop.c", "line": 75,
    }
    text = pry.cli._render_breakpoint_set_text(value)
    assert "@ 0x401445 workshop.c:75" in text


def test_render_breakpoint_set_without_resolved_location():
    # No address (e.g. older GDB or a pending bp) → no trailing "@ ...".
    value = {"number": 1, "kind": "breakpoint", "location": "main", "enabled": True}
    text = pry.cli._render_breakpoint_set_text(value)
    assert "@" not in text


def test_render_status_text_shows_displays():
    # Displays are attached to the status payload while stopped; the text
    # renderer must surface them too (not just JSON / the stop renderer).
    value = {
        "state": "stopped",
        "frame": {"function": "main"},
        "displays": [{"number": 1, "expr": "head->id", "value": "3"}],
    }
    text = pry.cli._render_status_text(value)
    assert "display #1: head->id = 3" in text


def test_format_stop_reason_exited_with_code():
    assert pry.cli._format_stop_reason({"kind": "exited", "code": 0}) == "exited (code 0)"
    assert pry.cli._format_stop_reason({"kind": "exited", "code": 42}) == "exited (code 42)"
    # exited via signal carries no code
    assert pry.cli._format_stop_reason({"kind": "exited"}) == "exited"


def test_render_status_text_shows_exit_code():
    value = {"state": "exited", "reason": {"kind": "exited", "code": 3}, "exit_code": 3}
    text = pry.cli._render_status_text(value)
    assert "state: exited" in text
    assert "exited (code 3)" in text


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        pry.cli.main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "pry" in out and pry.cli.VERSION in out


def test_break_delete_multiple(monkeypatch, capsys):
    cap = _capture_send(
        monkeypatch,
        result={"deleted": [3, 4], "items": [
            {"number": 3, "kind": "breakpoint"},
            {"number": 4, "kind": "hw-watchpoint"},
        ]},
    )
    rc = pry.cli.main(["break", "delete", "3", "4"])
    assert rc == 0
    assert cap["op"] == "break_delete"
    assert cap["params"]["numbers"] == [3, 4]
    out = capsys.readouterr().out
    assert "breakpoint #3 deleted" in out
    assert "watchpoint #4 deleted" in out


def test_break_delete_single_keeps_legacy_shape(monkeypatch, capsys):
    # A single id must still send {"number": N} (not a list) for backward compat.
    cap = _capture_send(monkeypatch, result={"deleted": 3})
    pry.cli.main(["break", "delete", "3"])
    assert cap["params"] == {"number": 3}
    assert "numbers" not in cap["params"]
