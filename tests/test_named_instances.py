"""Tests for named pry instances / stable IDs (issue #36).

Covers the registry round-trip of ``instance_id``, name/pid resolution in
``match_instance``/``choose_instance``, duplicate-name launch refusal,
``doctor``/launch JSON surfacing both fields, and ``kill --instance NAME``.

All tests use a temp ``PRY_CACHE_DIR`` and fakes — no live GDB.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
import uuid
from pathlib import Path

import pry.cli
import pytest

from pry.paths import bridge_registry_path
from pry.transport import (
    BridgeError,
    BridgeInstance,
    choose_instance,
    list_instances,
    match_instance,
)


def _inst(pid: int, name: str | None, tmp_path: Path) -> BridgeInstance:
    return BridgeInstance(
        pid=pid,
        socket_path=tmp_path / f"{pid}.sock",
        registry_path=tmp_path / f"{pid}.json",
        plugin_name="pry_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
        instance_id=name,
    )


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline()
        if not raw:
            return
        payload = json.loads(raw.decode("utf-8"))
        response = {"ok": True, "result": {"op": payload["op"]}}
        self.wfile.write(json.dumps(response).encode("utf-8"))


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


# ---------------------------------------------------------------------------
# Registry round-trip: a launched record persists instance_id.
# ---------------------------------------------------------------------------


def test_registry_round_trips_instance_id(tmp_path, monkeypatch):
    """A registry JSON carrying instance_id is surfaced by list_instances()."""
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    socket_path = Path("/tmp") / f"pry-name-{pid}-{uuid.uuid4().hex[:8]}.sock"
    registry_path = bridge_registry_path(pid)
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    server = _Server(str(socket_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "pry_agent_bridge",
                "plugin_version": "0.1.0",
                "instance_id": "kern-df2",
            }
        ),
        encoding="utf-8",
    )
    try:
        instances = list_instances()
        assert len(instances) == 1
        assert instances[0].instance_id == "kern-df2"
        # And choose_instance resolves that live name to the same pid.
        assert choose_instance("kern-df2").pid == pid
    finally:
        server.shutdown()
        server.server_close()
        socket_path.unlink(missing_ok=True)


def test_instance_id_absent_is_none(tmp_path, monkeypatch):
    """A registry without instance_id yields instance_id=None (back-compat)."""
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    socket_path = Path("/tmp") / f"pry-noname-{pid}-{uuid.uuid4().hex[:8]}.sock"
    registry_path = bridge_registry_path(pid)
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    server = _Server(str(socket_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "pry_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )
    try:
        instances = list_instances()
        assert len(instances) == 1
        assert instances[0].instance_id is None
    finally:
        server.shutdown()
        server.server_close()
        socket_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# match_instance resolution: by pid, by name, ambiguity, pid-wins.
# ---------------------------------------------------------------------------


def test_match_instance_by_pid(tmp_path):
    insts = [_inst(111, "alpha", tmp_path), _inst(222, "beta", tmp_path)]
    assert match_instance(insts, 222).pid == 222
    assert match_instance(insts, "111").pid == 111


def test_match_instance_by_unique_name(tmp_path):
    insts = [_inst(111, "alpha", tmp_path), _inst(222, "beta", tmp_path)]
    assert match_instance(insts, "beta").pid == 222


def test_match_instance_ambiguous_name_refused(tmp_path):
    insts = [_inst(111, "dup", tmp_path), _inst(222, "dup", tmp_path)]
    with pytest.raises(BridgeError, match="Multiple live instances named 'dup'"):
        match_instance(insts, "dup")


def test_match_instance_pid_wins_over_same_spelled_name(tmp_path):
    # instance A is named "222"; instance B has pid 222. Selector "222" must
    # resolve to the pid, not the name.
    insts = [_inst(111, "222", tmp_path), _inst(222, "alpha", tmp_path)]
    assert match_instance(insts, "222").pid == 222


def test_match_instance_unknown_pid_message(tmp_path):
    insts = [_inst(111, "alpha", tmp_path)]
    with pytest.raises(BridgeError, match="No running GDB bridge instance with pid 999"):
        match_instance(insts, "999")


def test_match_instance_unknown_name_message(tmp_path):
    insts = [_inst(111, "alpha", tmp_path)]
    with pytest.raises(BridgeError, match="No running GDB bridge instance named 'ghost'"):
        match_instance(insts, "ghost")


def test_choose_instance_resolves_name(tmp_path, monkeypatch):
    insts = [_inst(111, "alpha", tmp_path), _inst(222, "beta", tmp_path)]
    monkeypatch.setattr("pry.transport.list_instances", lambda: insts)
    assert choose_instance("alpha").pid == 111
    assert choose_instance(222).pid == 222


# ---------------------------------------------------------------------------
# Launch: instance_id persisted into the registry; duplicate name refused.
# ---------------------------------------------------------------------------


def test_annotate_registry_merges_instance_id(tmp_path, monkeypatch):
    """Launch merges the name into the plugin-written pid-keyed registry."""
    monkeypatch.setenv("PRY_CACHE_DIR", str(tmp_path))
    pid = 4242
    reg_path = bridge_registry_path(pid)
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    # Simulate the record the bridge plugin writes at startup (no name field).
    reg_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(tmp_path / "instances" / f"{pid}.sock"),
                "plugin_name": "pry_agent_bridge",
                "plugin_version": "0.1.0",
                "started_at": "2026-07-10T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )

    pry.cli._annotate_registry_instance_id(pid, "userland-vuln")

    payload = json.loads(reg_path.read_text(encoding="utf-8"))
    assert payload["instance_id"] == "userland-vuln"
    # Existing fields are preserved, not clobbered.
    assert payload["pid"] == pid
    assert payload["started_at"] == "2026-07-10T00:00:00+00:00"


def test_launch_refuses_duplicate_instance_id(monkeypatch, capsys, tmp_path):
    """Launching a name already held by a live instance is refused."""
    live = _inst(1234, "kern-df2", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [live])
    monkeypatch.setattr(pry.cli.shutil, "which", lambda name: "/usr/bin/gdb")
    # If the dedup guard fails we would proceed to spawn; make that observable.
    monkeypatch.setattr(
        pry.cli.subprocess,
        "Popen",
        lambda *a, **k: pytest.fail("must not spawn gdb on duplicate name"),
    )

    rc = pry.cli.main(["launch", "--instance-id", "kern-df2"])

    assert rc == 1
    err = capsys.readouterr().err.lower()
    assert "kern-df2" in err
    assert "already running" in err


# ---------------------------------------------------------------------------
# doctor: JSON output includes both pid and instance_id.
# ---------------------------------------------------------------------------


def test_doctor_json_includes_pid_and_instance_id(monkeypatch, capsys, tmp_path):
    inst = _inst(555, "kern-df2", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    monkeypatch.setattr(
        pry.cli,
        "_send_request_to_instance",
        lambda instance, op, **kw: {"result": {"plugin_version": "0.1.0"}},
    )

    rc = pry.cli.main(["doctor", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    entry = payload["instances"][0]
    assert entry["pid"] == 555
    assert entry["instance_id"] == "kern-df2"


def test_doctor_text_shows_name(monkeypatch, capsys, tmp_path):
    inst = _inst(555, "kern-df2", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    monkeypatch.setattr(
        pry.cli,
        "_send_request_to_instance",
        lambda instance, op, **kw: {"result": {"plugin_version": "0.1.0"}},
    )

    rc = pry.cli.main(["doctor"])

    assert rc == 0
    assert "name=kern-df2" in capsys.readouterr().out


def test_doctor_resolves_name_filter(monkeypatch, capsys, tmp_path):
    insts = [_inst(555, "kern-df2", tmp_path), _inst(666, "userland", tmp_path)]
    monkeypatch.setattr(pry.cli, "list_instances", lambda: insts)
    probed = []

    def fake_probe(instance, op, **kw):
        probed.append(instance.pid)
        return {"result": {"plugin_version": "0.1.0"}}

    monkeypatch.setattr(pry.cli, "_send_request_to_instance", fake_probe)

    rc = pry.cli.main(["--instance", "userland", "doctor", "--format", "json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [e["pid"] for e in payload["instances"]] == [666]
    assert probed == [666]


# ---------------------------------------------------------------------------
# kill --instance NAME targets the right record.
# ---------------------------------------------------------------------------


def test_kill_by_name(monkeypatch, capsys, tmp_path):
    inst = _inst(4321, "userland-vuln", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    killed = []
    monkeypatch.setattr(pry.cli, "_kill_instance", lambda pid: killed.append(pid))

    rc = pry.cli.main(["kill", "--instance", "userland-vuln"])

    assert rc == 0
    assert killed == [4321]
    assert "4321" in capsys.readouterr().out


def test_kill_unknown_name_errors(monkeypatch, capsys, tmp_path):
    inst = _inst(4321, "userland-vuln", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    killed = []
    monkeypatch.setattr(pry.cli, "_kill_instance", lambda pid: killed.append(pid))

    rc = pry.cli.main(["kill", "--instance", "ghost"])

    assert rc == 1
    assert "ghost" in capsys.readouterr().err
    assert killed == []


def test_kill_ambiguous_name_errors(monkeypatch, capsys, tmp_path):
    insts = [_inst(111, "dup", tmp_path), _inst(222, "dup", tmp_path)]
    monkeypatch.setattr(pry.cli, "list_instances", lambda: insts)
    killed = []
    monkeypatch.setattr(pry.cli, "_kill_instance", lambda pid: killed.append(pid))

    rc = pry.cli.main(["kill", "--instance", "dup"])

    assert rc == 1
    err = capsys.readouterr().err.lower()
    assert "multiple live instances named 'dup'" in err
    assert killed == []


# ---------------------------------------------------------------------------
# A bridge command routes to the pid resolved from a --instance name.
# ---------------------------------------------------------------------------


def test_bridge_command_resolves_name_to_pid(monkeypatch, capsys, tmp_path):
    inst = _inst(777, "kern-df2", tmp_path)
    monkeypatch.setattr(pry.cli, "list_instances", lambda: [inst])
    captured = {}

    def fake_send_request(op, *, params=None, timeout=30.0, connect_retries=4, instance_pid=None):
        captured["op"] = op
        captured["instance_pid"] = instance_pid
        return {"result": []}

    monkeypatch.setattr(pry.cli, "send_request", fake_send_request)

    rc = pry.cli.main(["--instance", "kern-df2", "backtrace"])

    assert rc == 0
    assert captured["op"] == "backtrace"
    assert captured["instance_pid"] == 777
