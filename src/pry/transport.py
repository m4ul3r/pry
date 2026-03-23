from __future__ import annotations

import contextlib
import errno
import json
import socket
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import bridge_registry_path, instances_dir


class BridgeError(RuntimeError):
    pass


TRANSIENT_SOCKET_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ENOENT,
}


@dataclass(slots=True)
class BridgeInstance:
    pid: int
    socket_path: Path
    registry_path: Path
    plugin_name: str
    plugin_version: str
    started_at: str | None
    meta: dict[str, Any]


def _purge_stale_registry(registry_path: Path) -> None:
    with contextlib.suppress(OSError):
        registry_path.unlink()


def _socket_is_live(socket_path: Path, timeout: float = 0.2) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(str(socket_path))
        return True
    except OSError:
        return False


def _load_instance(path: Path) -> BridgeInstance | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        socket_path = Path(payload["socket_path"])
        pid = int(payload["pid"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None

    if not socket_path.exists():
        _purge_stale_registry(path)
        return None

    if not _socket_is_live(socket_path):
        _purge_stale_registry(path)
        return None

    return BridgeInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=path,
        plugin_name=str(payload.get("plugin_name", PLUGIN_NAME)),
        plugin_version=str(payload.get("plugin_version", "0")),
        started_at=payload.get("started_at"),
        meta=payload,
    )


PLUGIN_NAME = "pry_agent_bridge"


def list_instances() -> list[BridgeInstance]:
    instances: list[BridgeInstance] = []

    # Check the per-instance directory first
    inst_dir = instances_dir()
    if inst_dir.is_dir():
        for reg_file in sorted(inst_dir.glob("*.json")):
            instance = _load_instance(reg_file)
            if instance is not None:
                instances.append(instance)

    # Also check legacy singleton registry for backwards compat
    if not instances:
        legacy = bridge_registry_path()
        if legacy.exists():
            instance = _load_instance(legacy)
            if instance is not None:
                instances.append(instance)

    return instances


def choose_instance(pid: int | None = None) -> BridgeInstance:
    instances = list_instances()
    if not instances:
        raise BridgeError("No running GDB bridge instances found")
    if pid is not None:
        for inst in instances:
            if inst.pid == pid:
                return inst
        raise BridgeError(f"No running GDB bridge instance with pid {pid}")
    if len(instances) > 1:
        pids = ", ".join(str(i.pid) for i in instances)
        raise BridgeError(
            f"Multiple bridge instances running (pids: {pids}). "
            f"Use --instance <pid> to select one."
        )
    return instances[0]


def _send_request_to_instance(
    instance: BridgeInstance,
    op: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: float = 30.0,
    connect_retries: int = 4,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "op": op,
        "params": params or {},
    }

    encoded = (json.dumps(payload) + "\n").encode("utf-8")

    chunks: list[bytes] = []
    last_error: OSError | None = None
    for attempt in range(connect_retries):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(instance.socket_path))
                sock.sendall(encoded)
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_WR)
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            break
        except OSError as exc:
            last_error = exc
            if exc.errno not in TRANSIENT_SOCKET_ERRNOS or attempt == connect_retries - 1:
                break
            time.sleep(0.05 * (attempt + 1))

    if last_error is not None and not chunks:
        if isinstance(last_error, TimeoutError):
            raise BridgeError(
                f"Timed out waiting for GDB bridge pid {instance.pid} at {instance.socket_path} "
                f"after {timeout:.1f}s"
            ) from last_error
        raise BridgeError(
            f"Failed to contact GDB bridge pid {instance.pid} at {instance.socket_path}: {last_error}"
        ) from last_error

    if not chunks:
        raise BridgeError("GDB bridge returned an empty response")

    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise BridgeError("GDB bridge returned invalid JSON") from exc

    if not isinstance(response, dict):
        raise BridgeError("GDB bridge returned a malformed response")

    if response.get("ok"):
        return response

    error = response.get("error") or "Unknown GDB bridge error"
    raise BridgeError(str(error))


def send_request(
    op: str,
    *,
    params: dict[str, Any] | None = None,
    timeout: float = 30.0,
    connect_retries: int = 4,
    instance_pid: int | None = None,
) -> dict[str, Any]:
    instance = choose_instance(pid=instance_pid)
    return _send_request_to_instance(
        instance,
        op,
        params=params,
        timeout=timeout,
        connect_retries=connect_retries,
    )
