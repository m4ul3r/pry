from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from .output import write_output_result
from .paths import (
    bridge_registry_path,
    bridge_socket_path,
    cache_home,
    gdb_log_path,
    gdb_pid_path,
    plugin_install_dir,
    plugin_source_dir,
    skill_install_dir,
    skill_source_dir,
)
from .transport import BridgeError, _send_request_to_instance, _socket_is_live, list_instances, send_request
from .version import VERSION, build_id_for_file


class _HelpFullAction(argparse.Action):
    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: str = argparse.SUPPRESS,
        help: str | None = None,
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | list[str] | None,
        option_string: str | None = None,
    ) -> None:
        if isinstance(parser, PryArgumentParser):
            parser.print_full_help()
        else:
            parser.print_help()
        parser.exit()


class PryArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.set_defaults(_parser=self)
        self.add_argument(
            "--help-full",
            action=_HelpFullAction,
            help="Show help for this command and all subcommands",
        )

    def _iter_full_help_parsers(self) -> list[argparse.ArgumentParser]:
        parsers: list[argparse.ArgumentParser] = [self]
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                for parser in action.choices.values():
                    if isinstance(parser, PryArgumentParser):
                        parsers.extend(parser._iter_full_help_parsers())
                    else:
                        parsers.append(parser)
        return parsers

    def _full_help_actions(self) -> tuple[type[argparse.Action], ...]:
        return (argparse._HelpAction, _HelpFullAction)

    def format_help_for_full(self) -> str:
        formatter = self._get_formatter()
        help_action_types = self._full_help_actions()
        actions = [action for action in self._actions if not isinstance(action, help_action_types)]

        formatter.add_usage(self.usage, actions, self._mutually_exclusive_groups)
        formatter.add_text(self.description)

        for action_group in self._action_groups:
            group_actions = [
                action
                for action in action_group._group_actions
                if not isinstance(action, help_action_types)
            ]
            if not group_actions:
                continue
            formatter.start_section(action_group.title)
            formatter.add_text(action_group.description)
            formatter.add_arguments(group_actions)
            formatter.end_section()

        formatter.add_text(self.epilog)
        return formatter.format_help()

    def format_full_help(self) -> str:
        sections: list[str] = []
        seen: set[int] = set()
        for parser in self._iter_full_help_parsers():
            parser_id = id(parser)
            if parser_id in seen:
                continue
            seen.add(parser_id)
            if isinstance(parser, PryArgumentParser):
                sections.append(parser.format_help_for_full().rstrip())
            else:
                sections.append(parser.format_help().rstrip())
        return "\n\n".join(sections) + "\n"

    def print_full_help(self, file: Any = None) -> None:
        if file is None:
            file = sys.stdout
        self._print_message(self.format_full_help(), file)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _package_version() -> str:
    return VERSION


def _common_io_options(
    parser: argparse.ArgumentParser,
    *,
    default_format: str = "text",
) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "text", "ndjson"),
        default=default_format,
        help="Output format",
    )
    parser.add_argument("--out", type=Path, help="Write output to a file instead of stdout")
    parser.add_argument(
        "--instance", type=int, default=None, metavar="PID",
        help="Target a specific bridge instance by GDB PID",
    )


def _add_paged_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=100)


def _render_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_label: str | None = None,
    spill_context: Any = None,
) -> None:
    result = write_output_result(value, fmt=fmt, out_path=out_path, stem=stem)
    if result.spilled and result.artifact:
        label = spill_label or stem.replace("_", " ")
        artifact = result.artifact
        lines = [
            f"warning: {label} output spilled",
            f"path: {artifact['artifact_path']}",
            f"format: {artifact['format']}",
            f"bytes: {artifact['bytes']}",
            f"tokens: {artifact['tokens']}",
            f"tokenizer: {artifact['tokenizer']}",
        ]
        if isinstance(artifact.get("sha256"), str):
            lines.append(f"sha256: {artifact['sha256']}")
        summary = artifact.get("summary")
        if isinstance(summary, dict):
            summary_parts = []
            kind = summary.get("kind")
            if kind is not None:
                summary_parts.append(f"kind={kind}")
            for key in sorted(summary):
                if key == "kind":
                    continue
                summary_parts.append(
                    f"{key}={json.dumps(summary[key], sort_keys=True, default=str)}"
                )
            if summary_parts:
                lines.append(f"summary: {', '.join(summary_parts)}")
        if isinstance(spill_context, list):
            lines.append(f"items: {len(spill_context)}")
        if isinstance(value, str):
            lines.append(f"lines: {len(value.splitlines())}")
        print("\n".join(lines), file=sys.stderr)
        return
    sys.stdout.write(result.rendered)


def _render_fallback_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def _call(
    args: argparse.Namespace,
    op: str,
    params: dict[str, Any] | None = None,
    *,
    text_renderer: Callable[[Any], str] | None = None,
    page_limit: int | None = None,
    page_offset: int = 0,
    page_label: str | None = None,
    stem: str,
    result_exit_code: Callable[[Any], int] | None = None,
    timeout: float | None = None,
) -> int:
    request_params = dict(params or {})
    effective_page_limit = None
    if page_limit is not None and page_limit >= 0:
        effective_page_limit = page_limit
        request_params["limit"] = page_limit + 1

    kw: dict[str, Any] = {}
    if timeout is not None:
        kw["timeout"] = timeout

    instance_pid = getattr(args, "instance", None)
    response = send_request(
        op,
        params=request_params,
        instance_pid=instance_pid,
        **kw,
    )
    result = response["result"]
    exit_code = result_exit_code(result) if result_exit_code is not None else 0
    if effective_page_limit is not None and isinstance(result, list) and len(result) > effective_page_limit:
        result = result[:effective_page_limit]
        label = page_label or op
        next_offset = page_offset + effective_page_limit
        print(
            f"warning: {label} output truncated to {effective_page_limit} items; rerun with --offset {next_offset} or a larger --limit",
            file=sys.stderr,
        )
    spill_context = result
    if text_renderer is not None and args.format == "text":
        result = text_renderer(result)
    _render_result(
        result,
        fmt=args.format,
        out_path=args.out,
        stem=stem,
        spill_label=page_label or op.replace("_", " "),
        spill_context=spill_context,
    )
    return exit_code


# ---------------------------------------------------------------------------
# Text renderers
# ---------------------------------------------------------------------------

def _render_doctor_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    lines = [
        f"cli version: {value.get('cli_version', '<unknown>')}",
        f"plugin source: {value.get('plugin_source_dir', '<unknown>')}",
        f"plugin install: {value.get('plugin_install_dir', '<unknown>')}",
        f"plugin source build: {value.get('plugin_source_build_id', '<unknown>')}",
        f"plugin install build: {value.get('plugin_install_build_id', '<unknown>')}",
        "",
        "instances:",
    ]
    instances = list(value.get("instances") or [])
    if not instances:
        lines.append("- none")
        return "\n".join(lines)

    for item in instances:
        if not isinstance(item, dict):
            lines.append("- " + _render_fallback_text(item))
            continue
        doctor = item.get("doctor") if isinstance(item.get("doctor"), dict) else {}
        status = "ok" if doctor and not doctor.get("error") else "error"
        lines.append(
            "- "
            + f"pid={item.get('pid', '<unknown>')} plugin={item.get('plugin_version', '<unknown>')} status={status}"
        )
        build_id = item.get("plugin_build_id")
        if build_id:
            lines.append(f"  build: {build_id}")
        if item.get("stale_plugin_version"):
            lines.append("  stale: loaded plugin version differs from CLI version")
        if item.get("stale_plugin_code"):
            lines.append("  stale: loaded plugin code does not match installed plugin file")
        if item.get("started_at"):
            lines.append(f"  started: {item['started_at']}")
        if item.get("socket_path"):
            lines.append(f"  socket: {item['socket_path']}")
        gdb_version = doctor.get("gdb_version")
        if gdb_version:
            lines.append(f"  gdb: {gdb_version}")
        error = doctor.get("error")
        if error:
            lines.append(f"  error: {error}")
    return "\n".join(lines)


def _format_stop_reason(reason: Any) -> str | None:
    """Format a structured stop-reason dict into a human-readable string."""
    if not isinstance(reason, dict):
        return str(reason) if reason else None
    kind = reason.get("kind", "")
    if kind == "breakpoint-hit":
        num = reason.get("number", "?")
        return f"breakpoint #{num} hit"
    if kind == "watchpoint-hit":
        num = reason.get("number", "?")
        expr = reason.get("expression")
        if expr:
            return f"watchpoint #{num} ({expr}) hit"
        return f"watchpoint #{num} hit"
    if kind == "signal":
        sig = reason.get("signal", "unknown")
        return f"signal {sig}"
    return kind or None


def _render_stop_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    status = value.get("status", "<unknown>")
    reason = _format_stop_reason(value.get("reason"))
    frame = value.get("frame") or {}
    parts = [f"status: {status}"]
    if value.get("timeout_interrupt"):
        parts.append("note: interrupted due to timeout")
    if reason:
        parts.append(f"reason: {reason}")
    func = frame.get("function")
    if func:
        loc = func
        f = frame.get("file")
        line = frame.get("line")
        if f:
            loc += f" at {f}"
            if line is not None:
                loc += f":{line}"
        addr = frame.get("address")
        if addr:
            loc += f" ({addr})"
        parts.append(f"frame: {loc}")
    thread = value.get("thread")
    if thread is not None:
        parts.append(f"thread: {thread}")
    return "\n".join(parts)


def _render_background_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return f"status: {value.get('status', '<unknown>')}"


def _render_status_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    state = value.get("state", "unknown")
    parts = [f"state: {state}"]
    if state == "stopped":
        reason = _format_stop_reason(value.get("reason"))
        if reason:
            parts.append(f"reason: {reason}")
        frame = value.get("frame") or {}
        func = frame.get("function")
        if func:
            loc = func
            f = frame.get("file")
            line = frame.get("line")
            if f:
                loc += f" at {f}"
                if line is not None:
                    loc += f":{line}"
            addr = frame.get("address")
            if addr:
                loc += f" ({addr})"
            parts.append(f"frame: {loc}")
        thread = value.get("thread")
        if thread is not None:
            parts.append(f"thread: {thread}")
    return "\n".join(parts)


def _render_connect_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    target = value.get("connected", "<unknown>")
    parts = [f"connected: {target}"]
    status = value.get("status", "<unknown>")
    parts.append(f"status: {status}")
    reason = _format_stop_reason(value.get("reason"))
    if reason:
        parts.append(f"reason: {reason}")
    frame = value.get("frame") or {}
    func = frame.get("function")
    if func:
        loc = func
        f = frame.get("file")
        line = frame.get("line")
        if f:
            loc += f" at {f}"
            if line is not None:
                loc += f":{line}"
        addr = frame.get("address")
        if addr:
            loc += f" ({addr})"
        parts.append(f"frame: {loc}")
    thread = value.get("thread")
    if thread is not None:
        parts.append(f"thread: {thread}")
    return "\n".join(parts)


def _render_disconnect_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return "disconnected"


def _render_target_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    parts = []
    raw = value.get("raw", "")
    if raw:
        parts.append(raw.rstrip())
    connections = value.get("connections", "")
    if connections:
        parts.append("Connections:")
        parts.append(connections.rstrip())
    return "\n".join(parts) if parts else "no target info"


def _render_breakpoint_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no breakpoints"
    lines = []
    for bp in value:
        if not isinstance(bp, dict):
            lines.append(str(bp))
            continue
        num = bp.get("number", "?")
        btype = bp.get("type", "breakpoint")
        location = bp.get("location", "<unknown>")
        enabled = "enabled" if bp.get("enabled") else "disabled"
        hits = bp.get("hits", 0)
        line = f"#{num} {btype} at {location} [{enabled}] hits={hits}"
        cond = bp.get("condition")
        if cond:
            line += f" if {cond}"
        lines.append(line)
    return "\n".join(lines)


def _render_breakpoint_set_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("number", "?")
    location = value.get("location") or value.get("expression") or "<unknown>"
    enabled = "enabled" if value.get("enabled") else "disabled"
    parts = [f"breakpoint #{num} set at {location} [{enabled}]"]
    if value.get("temporary"):
        parts.append("temporary")
    cond = value.get("condition")
    if cond:
        parts.append(f"if {cond}")
    rebased = value.get("rebased")
    if isinstance(rebased, dict):
        parts.append(f"(rebased from {rebased.get('offset', '?')} in {rebased.get('module', '?')})")
    return " ".join(parts)


def _render_breakpoint_delete_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("deleted", "?")
    return f"breakpoint #{num} deleted"


def _render_breakpoint_state_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("number", "?")
    location = value.get("location") or value.get("expression") or "<unknown>"
    enabled = "enabled" if value.get("enabled") else "disabled"
    return f"breakpoint #{num} at {location} [{enabled}]"


def _render_watch_set_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("number", "?")
    expression = value.get("expression") or "<unknown>"
    enabled = "enabled" if value.get("enabled") else "disabled"
    return f"watchpoint #{num} on {expression} [{enabled}]"


def _render_backtrace_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "empty backtrace"
    lines = []
    for frame in value:
        if not isinstance(frame, dict):
            lines.append(str(frame))
            continue
        level = frame.get("level", "?")
        func = frame.get("function", "<unknown>")
        addr = frame.get("address", "")
        entry = f"#{level} {addr} in {func}"
        f = frame.get("file")
        line_no = frame.get("line")
        if f:
            entry += f" at {f}"
            if line_no is not None:
                entry += f":{line_no}"
        args = frame.get("args")
        if args:
            arg_strs = [f"{a.get('name', '?')}={a.get('value', '?')}" for a in args if isinstance(a, dict)]
            if arg_strs:
                entry += f" ({', '.join(arg_strs)})"
        lines.append(entry)
    return "\n".join(lines)


def _render_frame_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    level = value.get("level", "?")
    func = value.get("function", "<unknown>")
    addr = value.get("address", "")
    entry = f"#{level} {addr} in {func}"
    f = value.get("file")
    line_no = value.get("line")
    if f:
        entry += f" at {f}"
        if line_no is not None:
            entry += f":{line_no}"
    return entry


def _render_locals_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no locals"
    lines = []
    for var in value:
        if not isinstance(var, dict):
            lines.append(str(var))
            continue
        name = var.get("name", "<unknown>")
        val = var.get("value", "<unknown>")
        typ = var.get("type")
        if typ:
            lines.append(f"{typ} {name} = {val}")
        else:
            lines.append(f"{name} = {val}")
    return "\n".join(lines)


def _render_registers_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no registers"
    lines = []
    for reg in value:
        if not isinstance(reg, dict):
            lines.append(str(reg))
            continue
        name = reg.get("name", "?")
        val = reg.get("value", "?")
        lines.append(f"{name:<12} {val}")
    return "\n".join(lines)


def _render_memory_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    fmt = value.get("format", "hex")
    if fmt == "string":
        return value.get("data", "")
    data = value.get("data", "")
    addr = value.get("address", "")
    if addr:
        return f"{addr}: {data}"
    return data


def _render_disasm_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return _render_fallback_text(value)
    lines = []
    for insn in value:
        if not isinstance(insn, dict):
            lines.append(str(insn))
            continue
        addr = insn.get("address", "")
        asm_text = insn.get("asm", "")
        lines.append(f"{addr}:  {asm_text}")
    return "\n".join(lines)


def _render_name_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"
    lines = []
    for item in value:
        if isinstance(item, dict):
            name = item.get("name", "<unknown>")
            addr = item.get("address", "")
            if addr:
                lines.append(f"{addr}  {name}")
            else:
                lines.append(name)
        else:
            lines.append(str(item))
    return "\n".join(lines)


def _render_type_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    layout = value.get("layout")
    if isinstance(layout, str) and layout:
        return layout
    decl = value.get("decl")
    if isinstance(decl, str) and decl:
        return decl
    return _render_fallback_text(value)


def _render_source_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return value.get("source", _render_fallback_text(value))


def _render_print_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    val = value.get("value", "<unknown>")
    typ = value.get("type")
    if typ:
        return f"({typ}) {val}"
    return str(val)


def _render_inferior_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no inferiors"
    lines = []
    for inf in value:
        if not isinstance(inf, dict):
            lines.append(str(inf))
            continue
        num = inf.get("num", "?")
        pid = inf.get("pid", 0)
        exe = inf.get("executable", "<none>")
        selected = " *" if inf.get("selected") else ""
        lines.append(f"  {num}{selected}  pid={pid}  {exe}")
    return "\n".join(lines)


def _render_py_exec_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    stdout = value.get("stdout", "")
    result_val = value.get("result")
    parts = []
    if stdout:
        parts.append(stdout)
    if result_val is not None:
        parts.append(str(result_val))
    return "\n".join(parts) if parts else "(no output)"


def _render_gdb_exec_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    output = value.get("output", "")
    return output.rstrip() if output else "(no output)"


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _doctor(args: argparse.Namespace) -> int:
    install_dir = plugin_install_dir()
    source_dir = plugin_source_dir()
    install_bridge = install_dir / "bridge.py"
    source_bridge = source_dir / "bridge.py"
    install_build_id = build_id_for_file(install_bridge)
    source_build_id = build_id_for_file(source_bridge)
    instances = []
    for instance in list_instances():
        ping: dict[str, Any]
        try:
            response = _send_request_to_instance(
                instance,
                "doctor",
                params={},
            )
            ping = response["result"]
        except Exception as exc:
            ping = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

        loaded_version = ping.get("plugin_version") if isinstance(ping, dict) else None
        loaded_build_id = ping.get("plugin_build_id") if isinstance(ping, dict) else None
        instances.append(
            {
                "pid": instance.pid,
                "socket_path": str(instance.socket_path),
                "plugin_version": instance.plugin_version,
                "plugin_build_id": loaded_build_id,
                "installed_plugin_build_id": install_build_id,
                "source_plugin_build_id": source_build_id,
                "stale_plugin_version": (
                    bool(loaded_version)
                    and str(loaded_version) != _package_version()
                ),
                "stale_plugin_code": (
                    bool(loaded_build_id)
                    and install_build_id is not None
                    and loaded_build_id != install_build_id
                ),
                "started_at": instance.started_at,
                "doctor": ping,
            }
        )

    result: Any = {
        "cli_version": _package_version(),
        "plugin_source_dir": str(source_dir),
        "plugin_install_dir": str(install_dir),
        "plugin_source_build_id": source_build_id,
        "plugin_install_build_id": install_build_id,
        "instances": instances,
    }
    if args.format == "text":
        result = _render_doctor_text(result)
    _render_result(result, fmt=args.format, out_path=args.out, stem="doctor")
    return 0


def _install_tree(source: Path, dest: Path, *, mode: str, force: bool) -> None:
    if not source.exists():
        raise BridgeError(f"Source directory is missing: {source}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() or dest.is_symlink():
        if not force:
            raise BridgeError(f"Destination already exists: {dest}")
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    if mode == "copy":
        shutil.copytree(source, dest)
    else:
        os.symlink(source, dest, target_is_directory=True)


def _plugin_install(args: argparse.Namespace) -> int:
    source = plugin_source_dir()
    dest = args.dest or plugin_install_dir()
    _install_tree(source, dest, mode=args.mode, force=args.force)

    gdbinit_snippet = (
        "python\n"
        "import sys\n"
        f"sys.path.insert(0, {str(dest.parent)!r})\n"
        "import pry_agent_bridge\n"
        "end\n"
    )

    result: dict[str, Any] = {
        "installed": True,
        "mode": args.mode,
        "source": str(source),
        "destination": str(dest),
        "gdbinit_snippet": gdbinit_snippet,
    }
    _render_result(result, fmt=args.format, out_path=args.out, stem="plugin-install")
    if args.format == "text":
        print(
            f"\nAdd the following to your ~/.gdbinit:\n\n{gdbinit_snippet}",
            file=sys.stderr,
        )
    return 0


def _skill_install(args: argparse.Namespace) -> int:
    source = skill_source_dir()
    dest = args.dest or skill_install_dir()
    _install_tree(source, dest, mode=args.mode, force=args.force)

    _render_result(
        {
            "installed": True,
            "mode": args.mode,
            "skill": source.name,
            "source": str(source),
            "destination": str(dest),
        },
        fmt=args.format,
        out_path=args.out,
        stem="skill-install",
    )
    return 0


# --- Launch / Kill ---

_LAUNCH_WAIT_TIMEOUT = 10.0
_LAUNCH_POLL_INTERVAL = 0.15


def _resolve_plugin_path() -> Path:
    """Return the parent directory to add to sys.path for the bridge plugin."""
    installed = plugin_install_dir()
    if installed.exists():
        return installed.parent
    source = plugin_source_dir()
    if source.exists():
        return source.parent
    raise BridgeError(
        "Cannot find the bridge plugin. Run 'pry plugin install' first, "
        f"or ensure the source directory exists: {source}"
    )


def _read_log_tail(log_path: Path, max_chars: int = 500) -> str:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if len(text) > max_chars:
            return "..." + text[-max_chars:]
        return text
    except OSError:
        return "(could not read log)"


def _render_launch_text(result: dict[str, Any]) -> str:
    lines = [f"GDB launched (pid={result['pid']})"]
    if result.get("binary"):
        lines.append(f"binary: {result['binary']}")
    if result.get("symbols"):
        lines.append(f"symbols: {result['symbols']}")
    if result.get("connected"):
        lines.append(f"connected: {result['connected']}")
        if result.get("target_status"):
            lines.append(f"target status: {result['target_status']}")
    lines.append(f"socket: {result['socket_path']}")
    lines.append(f"log: {result['log_path']}")
    if result.get("post_launch_error"):
        lines.append(f"error: {result['post_launch_error']}")
    return "\n".join(lines)


def _launch(args: argparse.Namespace) -> int:
    from .paths import instances_dir as _instances_dir

    if shutil.which("gdb") is None:
        raise BridgeError("gdb not found in PATH. Please install GDB.")

    plugin_parent = _resolve_plugin_path()

    gdb_cmd: list[str] = ["gdb", "-q"]
    if args.binary:
        gdb_cmd.append(str(Path(args.binary).expanduser().resolve()))

    # Self-pipe: GDB holds its own stdin writer open so it never sees EOF
    read_fd, write_fd = os.pipe()

    keepalive_ex = f"python import os as _os; __pry_stdin_writer = _os.fdopen({write_fd}, 'w')"
    bridge_ex = (
        f"python import sys; sys.path.insert(0, {str(plugin_parent)!r}); import pry_agent_bridge"
    )
    gdb_cmd.extend(["-ex", keepalive_ex, "-ex", bridge_ex])

    gdb_extra = args.gdb_args or []
    if gdb_extra and gdb_extra[0] == "--":
        gdb_extra = gdb_extra[1:]
    gdb_cmd.extend(gdb_extra)

    _instances_dir().mkdir(parents=True, exist_ok=True)
    log_path = gdb_log_path()  # temporary; we'll know the PID-based path after spawn
    log_file = open(log_path, "w")

    try:
        proc = subprocess.Popen(
            gdb_cmd,
            stdin=read_fd,
            stdout=log_file,
            stderr=log_file,
            pass_fds=(write_fd,),
            start_new_session=True,
        )
    except OSError as exc:
        os.close(read_fd)
        os.close(write_fd)
        log_file.close()
        raise BridgeError(f"Failed to start GDB: {exc}")

    os.close(read_fd)
    os.close(write_fd)

    # Now we know the PID — move log to the per-instance path
    pid = proc.pid
    pid_log_path = gdb_log_path(pid)
    log_file.close()
    with contextlib.suppress(OSError):
        Path(log_path).rename(pid_log_path)
    log_path = pid_log_path

    # The bridge will create its socket at instances/<pid>.sock
    socket_path = bridge_socket_path(pid)
    timeout = args.timeout or _LAUNCH_WAIT_TIMEOUT
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        ret = proc.poll()
        if ret is not None:
            log_tail = _read_log_tail(log_path)
            raise BridgeError(
                f"GDB exited with code {ret} before the bridge started.\n"
                f"Log ({log_path}):\n{log_tail}"
            )
        if socket_path.exists() and _socket_is_live(socket_path):
            break
        time.sleep(_LAUNCH_POLL_INTERVAL)
    else:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        log_tail = _read_log_tail(log_path)
        raise BridgeError(
            f"Timed out after {timeout:.1f}s waiting for bridge socket.\n"
            f"Log ({log_path}):\n{log_tail}"
        )

    result: dict[str, Any] = {
        "launched": True,
        "pid": pid,
        "socket_path": str(socket_path),
        "log_path": str(log_path),
    }
    if args.binary:
        result["binary"] = str(Path(args.binary).expanduser().resolve())

    # Post-launch: load symbols and/or connect to remote target
    from .transport import BridgeInstance
    _post_instance = BridgeInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=bridge_registry_path(pid),
        plugin_name="pry_agent_bridge",
        plugin_version="",
        started_at=None,
        meta={},
    )
    try:
        if getattr(args, "symbols", None):
            symbols_path = str(Path(args.symbols).expanduser().resolve())
            _send_request_to_instance(
                _post_instance, "load", params={"path": symbols_path},
            )
            result["symbols"] = symbols_path
        if getattr(args, "connect", None):
            connect_resp = _send_request_to_instance(
                _post_instance, "connect", params={"target": args.connect},
                timeout=20,
            )
            result["connected"] = args.connect
            connect_result = connect_resp.get("result")
            if isinstance(connect_result, dict):
                result["target_status"] = connect_result.get("status")
    except BridgeError as exc:
        result["post_launch_error"] = str(exc)

    if args.format == "text":
        _render_result(
            _render_launch_text(result), fmt="text", out_path=args.out, stem="launch"
        )
    else:
        _render_result(result, fmt=args.format, out_path=args.out, stem="launch")
    return 0


def _kill(args: argparse.Namespace) -> int:
    target_pid: int | None = getattr(args, "instance", None)

    if target_pid is None:
        instances = list_instances()
        if not instances:
            raise BridgeError("No running GDB session found to kill.")
        if len(instances) > 1:
            pids = ", ".join(str(i.pid) for i in instances)
            raise BridgeError(
                f"Multiple bridge instances running (pids: {pids}). "
                f"Use --instance <pid> to select one, or 'pry kill --all'."
            )
        target_pid = instances[0].pid

    _kill_instance(target_pid)

    result: dict[str, Any] = {"killed": True, "pid": target_pid}
    if args.format == "text":
        _render_result(f"Killed GDB (pid={target_pid})", fmt="text", out_path=args.out, stem="kill")
    else:
        _render_result(result, fmt=args.format, out_path=args.out, stem="kill")
    return 0


def _kill_instance(pid: int) -> None:
    """Kill a single GDB bridge instance by PID and clean up its files."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        raise BridgeError(f"Permission denied sending SIGTERM to pid {pid}")

    for _ in range(20):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)

    # Clean up per-instance files
    for path in (bridge_socket_path(pid), bridge_registry_path(pid), gdb_log_path(pid)):
        with contextlib.suppress(OSError):
            path.unlink()
    # Also clean legacy singleton files
    for path in (bridge_socket_path(), bridge_registry_path(), gdb_pid_path()):
        with contextlib.suppress(OSError):
            if path.exists():
                try:
                    stored_pid = int(path.read_text(encoding="utf-8").strip())
                    if stored_pid == pid:
                        path.unlink()
                except (ValueError, OSError):
                    pass


# --- Session management ---

def _load(args: argparse.Namespace) -> int:
    return _call(
        args,
        "load",
        {"path": str(Path(args.path).expanduser().resolve())},
        stem="load",
    )


def _attach(args: argparse.Namespace) -> int:
    return _call(
        args,
        "attach",
        {"pid": args.pid},
        stem="attach",
    )


def _connect(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"target": args.target}
    connect_timeout = getattr(args, "connect_timeout", None)
    if connect_timeout is not None:
        params["connect_timeout"] = connect_timeout
    # Use connect_timeout + buffer as the transport-level socket timeout so
    # the CLI fails at roughly the same time as GDB's tcp connect-timeout.
    transport_timeout = (connect_timeout or 15) + 5
    return _call(
        args,
        "connect",
        params,
        text_renderer=_render_connect_text,
        stem="connect",
        timeout=transport_timeout,
    )


def _disconnect(args: argparse.Namespace) -> int:
    return _call(
        args,
        "disconnect",
        text_renderer=_render_disconnect_text,
        stem="disconnect",
    )


def _target_info(args: argparse.Namespace) -> int:
    return _call(
        args,
        "target_info",
        text_renderer=_render_target_info_text,
        stem="target_info",
    )


def _inferior_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_inferiors",
        text_renderer=_render_inferior_list_text,
        stem="inferior_list",
    )


# --- Execution control ---

def _exec_timeout(args: argparse.Namespace) -> tuple[dict[str, Any], float | None]:
    """Extract --timeout from args and return (params_patch, transport_timeout).

    The bridge-side ``_timeout`` travels in params so ``_dispatch_exec`` can
    auto-interrupt.  The transport timeout is slightly longer to give the
    bridge time to interrupt and respond before the socket gives up.
    """
    timeout = getattr(args, "timeout", None)
    if timeout is None:
        return {}, None
    return {"_timeout": timeout}, timeout + 10


def _exec_params(args: argparse.Namespace) -> tuple[dict[str, Any], float | None]:
    """Build common exec params (timeout + background) from args."""
    params, tt = _exec_timeout(args)
    if getattr(args, "background", False):
        params["_background"] = True
    return params, tt


def _run(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.args:
        params["args"] = args.args
    ep, tt = _exec_params(args)
    params.update(ep)
    renderer = _render_background_text if params.get("_background") else _render_stop_text
    return _call(
        args,
        "run",
        params,
        text_renderer=renderer,
        stem="run",
        timeout=tt,
    )


def _continue(args: argparse.Namespace) -> int:
    ep, tt = _exec_params(args)
    renderer = _render_background_text if ep.get("_background") else _render_stop_text
    return _call(
        args,
        "continue",
        ep or None,
        text_renderer=renderer,
        stem="continue",
        timeout=tt,
    )


def _step(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    count = getattr(args, "count", None)
    if count is not None:
        params["count"] = count
    return _call(args, "step", params, text_renderer=_render_stop_text, stem="step")


def _next(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    count = getattr(args, "count", None)
    if count is not None:
        params["count"] = count
    return _call(args, "next", params, text_renderer=_render_stop_text, stem="next")


def _stepi(args: argparse.Namespace) -> int:
    return _call(args, "stepi", text_renderer=_render_stop_text, stem="stepi")


def _nexti(args: argparse.Namespace) -> int:
    return _call(args, "nexti", text_renderer=_render_stop_text, stem="nexti")


def _finish(args: argparse.Namespace) -> int:
    ep, tt = _exec_params(args)
    renderer = _render_background_text if ep.get("_background") else _render_stop_text
    return _call(args, "finish", ep or None, text_renderer=renderer, stem="finish", timeout=tt)


def _until(args: argparse.Namespace) -> int:
    ep, tt = _exec_params(args)
    params: dict[str, Any] = {"location": args.location}
    params.update(ep)
    renderer = _render_background_text if params.get("_background") else _render_stop_text
    return _call(
        args,
        "until",
        params,
        text_renderer=renderer,
        stem="until",
        timeout=tt,
    )


def _interrupt(args: argparse.Namespace) -> int:
    return _call(args, "interrupt", stem="interrupt")


def _status(args: argparse.Namespace) -> int:
    return _call(args, "status", text_renderer=_render_status_text, stem="status")


def _wait(args: argparse.Namespace) -> int:
    timeout = getattr(args, "timeout", None)
    params: dict[str, Any] = {}
    if timeout is not None:
        params["_timeout"] = timeout
    return _call(
        args,
        "wait",
        params or None,
        text_renderer=_render_stop_text,
        stem="wait",
        timeout=(timeout + 10) if timeout else None,
    )


# --- Breakpoints ---

def _break_set(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"location": args.location}
    if args.condition:
        params["condition"] = args.condition
    if args.temporary:
        params["temporary"] = True
    if args.hardware:
        params["hardware"] = True
    rebase = getattr(args, "rebase", None)
    if rebase:
        params["rebase_module"] = rebase
    image_base = getattr(args, "image_base", 0)
    if image_base:
        params["image_base"] = image_base
    return _call(args, "break_set", params, text_renderer=_render_breakpoint_set_text, stem="break_set")


def _break_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "break_list",
        text_renderer=_render_breakpoint_list_text,
        stem="break_list",
    )


def _break_delete(args: argparse.Namespace) -> int:
    return _call(args, "break_delete", {"number": args.number}, text_renderer=_render_breakpoint_delete_text, stem="break_delete")


def _break_enable(args: argparse.Namespace) -> int:
    return _call(args, "break_enable", {"number": args.number}, text_renderer=_render_breakpoint_state_text, stem="break_enable")


def _break_disable(args: argparse.Namespace) -> int:
    return _call(args, "break_disable", {"number": args.number}, text_renderer=_render_breakpoint_state_text, stem="break_disable")


def _watch_set(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"expression": args.expression}
    if args.type:
        params["watch_type"] = args.type
    return _call(args, "watch_set", params, text_renderer=_render_watch_set_text, stem="watch_set")


# --- Inspection ---

def _backtrace(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.full:
        params["full"] = True
    if args.limit is not None:
        params["limit"] = args.limit
    return _call(
        args,
        "backtrace",
        params,
        text_renderer=_render_backtrace_text,
        stem="backtrace",
    )


def _frame_select(args: argparse.Namespace) -> int:
    return _call(
        args,
        "frame_select",
        {"level": args.level},
        text_renderer=_render_frame_info_text,
        stem="frame_select",
    )


def _frame_info(args: argparse.Namespace) -> int:
    return _call(
        args,
        "frame_info",
        text_renderer=_render_frame_info_text,
        stem="frame_info",
    )


def _locals(args: argparse.Namespace) -> int:
    return _call(
        args,
        "locals",
        text_renderer=_render_locals_text,
        stem="locals",
    )


def _args(args: argparse.Namespace) -> int:
    return _call(
        args,
        "args",
        text_renderer=_render_locals_text,
        stem="args",
    )


def _print_expr(args: argparse.Namespace) -> int:
    return _call(
        args,
        "print",
        {"expression": args.expression},
        text_renderer=_render_print_text,
        stem="print",
    )


def _registers(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.all:
        params["all"] = True
    return _call(
        args,
        "registers",
        params,
        text_renderer=_render_registers_text,
        stem="registers",
    )


def _memory_read(args: argparse.Namespace) -> int:
    mem_fmt = getattr(args, "mem_format", "hex")
    params: dict[str, Any] = {
        "address": args.address,
        "length": args.length,
    }
    if mem_fmt != "hex":
        params["format"] = mem_fmt
    return _call(
        args,
        "memory_read",
        params,
        text_renderer=_render_memory_text,
        stem="memory_read",
    )


def _memory_write(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_write",
        {"address": args.address, "value": args.value},
        stem="memory_write",
    )


def _disasm(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.location:
        params["location"] = args.location
    if args.count is not None:
        params["count"] = args.count
    return _call(
        args,
        "disasm",
        params,
        text_renderer=_render_disasm_text,
        stem="disasm",
    )


def _functions(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    query = getattr(args, "query", None)
    if query:
        params["query"] = query
    offset = getattr(args, "offset", 0)
    limit = getattr(args, "limit", 100)
    if offset:
        params["offset"] = offset
    return _call(
        args,
        "functions",
        params,
        text_renderer=_render_name_list_text,
        page_limit=limit,
        page_offset=offset,
        page_label="functions",
        stem="functions",
    )


def _symbols(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    query = getattr(args, "query", None)
    if query:
        params["query"] = query
    offset = getattr(args, "offset", 0)
    limit = getattr(args, "limit", 100)
    if offset:
        params["offset"] = offset
    return _call(
        args,
        "symbols",
        params,
        text_renderer=_render_name_list_text,
        page_limit=limit,
        page_offset=offset,
        page_label="symbols",
        stem="symbols",
    )


def _types_show(args: argparse.Namespace) -> int:
    return _call(
        args,
        "types_show",
        {"name": args.name},
        text_renderer=_render_type_info_text,
        stem="types_show",
    )


def _render_info_files_text(value: Any) -> str:
    if isinstance(value, dict) and "raw" in value:
        return value["raw"].rstrip()
    return _render_fallback_text(value)


def _info_files(args: argparse.Namespace) -> int:
    return _call(
        args,
        "info_files",
        text_renderer=_render_info_files_text,
        stem="info_files",
    )


def _source_list(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.location:
        params["location"] = args.location
    if args.count is not None:
        params["count"] = args.count
    return _call(
        args,
        "source_list",
        params,
        text_renderer=_render_source_text,
        stem="source_list",
    )


# --- Raw GDB command passthrough ---

def _gdb_exec(args: argparse.Namespace) -> int:
    command = args.command
    timeout = getattr(args, "timeout", None)
    params: dict[str, Any] = {"command": command}
    if timeout is not None:
        params["_timeout"] = timeout
    return _call(
        args,
        "gdb_exec",
        params,
        text_renderer=_render_gdb_exec_text,
        stem="gdb_exec",
        timeout=timeout,
    )


# --- Python escape hatch ---

def _py_exec(args: argparse.Namespace) -> int:
    code: str | None = getattr(args, "code", None)
    script: str | None = getattr(args, "script", None)
    use_stdin: bool = getattr(args, "stdin", False)

    if code:
        source = code
    elif script:
        source = Path(script).expanduser().read_text(encoding="utf-8")
    elif use_stdin:
        source = sys.stdin.read()
    else:
        raise BridgeError("One of --code, --script, or --stdin is required")

    timeout = getattr(args, "timeout", None)
    params: dict[str, Any] = {"code": source}
    if timeout is not None:
        params["_timeout"] = timeout
    return _call(
        args,
        "py_exec",
        params,
        text_renderer=_render_py_exec_text,
        stem="py_exec",
        timeout=timeout,
    )


# --- Tracing ---

def _render_trace_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    watch = value.get("watch_addr", "?")
    rng = f"{value.get('range_start', '?')}-{value.get('range_end', '?')}"
    hit_count = value.get("hit_count", 0)
    lines = [f"trace: {hit_count} hits on {watch} in range {rng}"]
    if value.get("truncated"):
        lines.append("warning: hit limit reached, trace may be incomplete")
    for h in value.get("hits", []):
        pc = h.get("pc", "?")
        asm = h.get("asm", "?")
        lines.append(f"  {pc}: {asm}")
    stop = value.get("stop_info")
    if isinstance(stop, dict):
        status = stop.get("status", "unknown")
        lines.append(f"final status: {status}")
    return "\n".join(lines)


def _trace(args: argparse.Namespace) -> int:
    range_str: str = args.range
    # Split on the first '-' that is NOT inside a '0x' prefix.
    # E.g. "0x404610-0x405e30" → ("0x404610", "0x405e30")
    idx = range_str.find("-", 2)  # skip potential 0x prefix
    if idx == -1:
        print("error: --range must be in format START-END (e.g., 0x404610-0x405e30)",
              file=sys.stderr)
        return 1
    range_start = range_str[:idx].strip()
    range_end = range_str[idx + 1:].strip()

    timeout = getattr(args, "timeout", None) or 120.0
    params: dict[str, Any] = {
        "watch_addr": args.watch,
        "watch_size": args.watch_size,
        "range_start": range_start,
        "range_end": range_end,
        "watch_type": args.watch_type,
        "max_hits": args.max_hits,
        "_timeout": timeout,
    }
    return _call(
        args,
        "trace",
        params,
        text_renderer=_render_trace_text,
        stem="trace",
        timeout=timeout + 10,
    )


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _add_timeout_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Override transport timeout in seconds (default: 30)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = PryArgumentParser(prog="pry", description="Agent-friendly GDB CLI")
    parser.set_defaults(handler=None)

    subparsers = parser.add_subparsers(dest="command")

    # --- doctor ---
    doctor = subparsers.add_parser("doctor", help="Validate bridge discovery and installation")
    _common_io_options(doctor)
    doctor.set_defaults(handler=_doctor)

    # --- plugin install ---
    plugin = subparsers.add_parser("plugin", help="Install the GDB companion bridge")
    plugin_sub = plugin.add_subparsers(dest="plugin_command")
    plugin_install = plugin_sub.add_parser("install", help="Install the GDB bridge plugin")
    plugin_install.add_argument("--dest", type=Path, help="Custom install destination")
    plugin_install.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    plugin_install.add_argument("--force", action="store_true")
    _common_io_options(plugin_install, default_format="json")
    plugin_install.set_defaults(handler=_plugin_install)

    # --- skill install ---
    skill = subparsers.add_parser("skill", help="Install the bundled Claude Code skill")
    skill_sub = skill.add_subparsers(dest="skill_command")
    skill_install_cmd = skill_sub.add_parser("install", help="Install the bundled Claude Code skill")
    skill_install_cmd.add_argument("--dest", type=Path, help="Custom install destination")
    skill_install_cmd.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    skill_install_cmd.add_argument("--force", action="store_true")
    _common_io_options(skill_install_cmd, default_format="json")
    skill_install_cmd.set_defaults(handler=_skill_install)

    # --- launch ---
    launch = subparsers.add_parser("launch", help="Launch GDB headlessly with the bridge")
    _common_io_options(launch)
    launch.add_argument("binary", nargs="?", default=None, help="Path to binary to load")
    launch.add_argument("gdb_args", nargs=argparse.REMAINDER, help="Additional GDB arguments (after --)")
    launch.add_argument(
        "--timeout", type=float, default=_LAUNCH_WAIT_TIMEOUT,
        help=f"Seconds to wait for bridge to start (default: {_LAUNCH_WAIT_TIMEOUT})",
    )
    launch.add_argument(
        "--connect", metavar="HOST:PORT", default=None,
        help="Connect to a remote target after launch (e.g. localhost:1234)",
    )
    launch.add_argument(
        "--symbols", metavar="PATH", default=None,
        help="Load symbol file (e.g. vmlinux) before connecting",
    )
    launch.set_defaults(handler=_launch)

    # --- kill ---
    kill = subparsers.add_parser("kill", help="Kill a running GDB bridge session")
    _common_io_options(kill)
    kill.set_defaults(handler=_kill)

    # --- load ---
    load = subparsers.add_parser("load", help="Load a binary into GDB")
    _common_io_options(load, default_format="json")
    load.add_argument("path", help="Path to binary")
    load.set_defaults(handler=_load)

    # --- attach ---
    attach = subparsers.add_parser("attach", help="Attach to a running process")
    _common_io_options(attach, default_format="json")
    attach.add_argument("pid", type=int, help="Process ID to attach to")
    attach.set_defaults(handler=_attach)

    # --- connect ---
    connect = subparsers.add_parser("connect", help="Connect to a remote GDB target (QEMU, gdbserver)")
    _common_io_options(connect)
    connect.add_argument("target", help="Remote target (host:port, e.g. localhost:1234)")
    connect.add_argument(
        "--connect-timeout", type=int, default=15, dest="connect_timeout",
        help="TCP connect timeout in seconds (default: 15)",
    )
    connect.set_defaults(handler=_connect)

    # --- disconnect ---
    disconnect = subparsers.add_parser("disconnect", help="Disconnect from remote target")
    _common_io_options(disconnect, default_format="json")
    disconnect.set_defaults(handler=_disconnect)

    # --- inferior ---
    inferior = subparsers.add_parser("inferior", help="Inspect GDB inferiors")
    inferior_sub = inferior.add_subparsers(dest="inferior_command")
    inferior_list = inferior_sub.add_parser("list", help="List inferiors")
    _common_io_options(inferior_list)
    inferior_list.set_defaults(handler=_inferior_list)

    # --- run ---
    run = subparsers.add_parser("run", help="Run the loaded program")
    _common_io_options(run)
    _add_timeout_arg(run)
    run.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    run.add_argument("args", nargs="*", help="Program arguments")
    run.set_defaults(handler=_run)

    # --- continue ---
    cont = subparsers.add_parser("continue", help="Continue execution")
    _common_io_options(cont)
    _add_timeout_arg(cont)
    cont.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    cont.set_defaults(handler=_continue)

    # --- step ---
    step = subparsers.add_parser("step", help="Step into (source-level)")
    _common_io_options(step)
    step.add_argument("count", nargs="?", type=int, help="Number of steps")
    step.set_defaults(handler=_step)

    # --- next ---
    next_cmd = subparsers.add_parser("next", help="Step over (source-level)")
    _common_io_options(next_cmd)
    next_cmd.add_argument("count", nargs="?", type=int, help="Number of steps")
    next_cmd.set_defaults(handler=_next)

    # --- stepi ---
    stepi = subparsers.add_parser("stepi", help="Step into (instruction-level)")
    _common_io_options(stepi)
    stepi.set_defaults(handler=_stepi)

    # --- nexti ---
    nexti = subparsers.add_parser("nexti", help="Step over (instruction-level)")
    _common_io_options(nexti)
    nexti.set_defaults(handler=_nexti)

    # --- finish ---
    finish = subparsers.add_parser("finish", help="Run until current function returns")
    _common_io_options(finish)
    _add_timeout_arg(finish)
    finish.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    finish.set_defaults(handler=_finish)

    # --- until ---
    until = subparsers.add_parser("until", help="Run until a location is reached")
    _common_io_options(until)
    _add_timeout_arg(until)
    until.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    until.add_argument("location", help="Location to run until (function, file:line, or address)")
    until.set_defaults(handler=_until)

    # --- interrupt ---
    interrupt = subparsers.add_parser("interrupt", help="Interrupt the running inferior")
    _common_io_options(interrupt, default_format="json")
    interrupt.set_defaults(handler=_interrupt)

    # --- status ---
    status_cmd = subparsers.add_parser("status", help="Show inferior execution state")
    _common_io_options(status_cmd)
    status_cmd.set_defaults(handler=_status)

    # --- wait ---
    wait_cmd = subparsers.add_parser("wait", help="Wait for running inferior to stop")
    _common_io_options(wait_cmd)
    _add_timeout_arg(wait_cmd)
    wait_cmd.set_defaults(handler=_wait)

    # --- break ---
    brk = subparsers.add_parser("break", help="Breakpoint management")
    brk_sub = brk.add_subparsers(dest="break_command")

    brk_set = brk_sub.add_parser("set", help="Set a breakpoint")
    _common_io_options(brk_set)
    brk_set.add_argument("location", help="Breakpoint location (function, file:line, *address)")
    brk_set.add_argument("--condition", help="Conditional expression")
    brk_set.add_argument("--temporary", action="store_true", help="Temporary breakpoint (deleted on hit)")
    brk_set.add_argument("--hardware", action="store_true", help="Hardware breakpoint")
    brk_set.add_argument("--rebase", metavar="MODULE", help="Treat location as offset from MODULE's load base (PIE/ASLR rebasing)")
    brk_set.add_argument("--image-base", type=lambda x: int(x, 0), default=0, metavar="ADDR",
                          help="Static image base to subtract (default: 0x0)")
    brk_set.set_defaults(handler=_break_set)

    brk_list = brk_sub.add_parser("list", help="List breakpoints")
    _common_io_options(brk_list)
    brk_list.set_defaults(handler=_break_list)

    brk_delete = brk_sub.add_parser("delete", help="Delete a breakpoint")
    _common_io_options(brk_delete)
    brk_delete.add_argument("number", type=int, help="Breakpoint number")
    brk_delete.set_defaults(handler=_break_delete)

    brk_enable = brk_sub.add_parser("enable", help="Enable a breakpoint")
    _common_io_options(brk_enable)
    brk_enable.add_argument("number", type=int, help="Breakpoint number")
    brk_enable.set_defaults(handler=_break_enable)

    brk_disable = brk_sub.add_parser("disable", help="Disable a breakpoint")
    _common_io_options(brk_disable)
    brk_disable.add_argument("number", type=int, help="Breakpoint number")
    brk_disable.set_defaults(handler=_break_disable)

    # --- watch ---
    watch = subparsers.add_parser("watch", help="Watchpoint management")
    watch_sub = watch.add_subparsers(dest="watch_command")
    watch_set = watch_sub.add_parser("set", help="Set a watchpoint")
    _common_io_options(watch_set)
    watch_set.add_argument("expression", help="Expression to watch")
    watch_set.add_argument("--type", choices=("write", "read", "access"), default="write")
    watch_set.set_defaults(handler=_watch_set)

    watch_list = watch_sub.add_parser("list", help="List watchpoints and breakpoints")
    _common_io_options(watch_list)
    watch_list.set_defaults(handler=_break_list)

    watch_delete = watch_sub.add_parser("delete", help="Delete a watchpoint")
    _common_io_options(watch_delete)
    watch_delete.add_argument("number", type=int, help="Watchpoint number")
    watch_delete.set_defaults(handler=_break_delete)

    watch_enable = watch_sub.add_parser("enable", help="Enable a watchpoint")
    _common_io_options(watch_enable)
    watch_enable.add_argument("number", type=int, help="Watchpoint number")
    watch_enable.set_defaults(handler=_break_enable)

    watch_disable = watch_sub.add_parser("disable", help="Disable a watchpoint")
    _common_io_options(watch_disable)
    watch_disable.add_argument("number", type=int, help="Watchpoint number")
    watch_disable.set_defaults(handler=_break_disable)

    # --- backtrace ---
    bt = subparsers.add_parser("backtrace", help="Print stack backtrace")
    _common_io_options(bt)
    bt.add_argument("--full", action="store_true", help="Show local variables in each frame")
    bt.add_argument("--limit", type=int, help="Maximum number of frames")
    bt.set_defaults(handler=_backtrace)

    # --- frame ---
    frame = subparsers.add_parser("frame", help="Stack frame inspection")
    frame_sub = frame.add_subparsers(dest="frame_command")
    frame_sel = frame_sub.add_parser("select", help="Select a stack frame")
    _common_io_options(frame_sel)
    frame_sel.add_argument("level", type=int, help="Frame level (0 = innermost)")
    frame_sel.set_defaults(handler=_frame_select)
    frame_inf = frame_sub.add_parser("info", help="Show current frame info")
    _common_io_options(frame_inf)
    frame_inf.set_defaults(handler=_frame_info)

    # --- locals ---
    locals_cmd = subparsers.add_parser("locals", help="Show local variables")
    _common_io_options(locals_cmd)
    locals_cmd.set_defaults(handler=_locals)

    # --- args ---
    args_cmd = subparsers.add_parser("args", help="Show function arguments")
    _common_io_options(args_cmd)
    args_cmd.set_defaults(handler=_args)

    # --- print ---
    print_cmd = subparsers.add_parser("print", help="Evaluate an expression")
    _common_io_options(print_cmd)
    print_cmd.add_argument("expression", help="Expression to evaluate")
    print_cmd.set_defaults(handler=_print_expr)

    # --- registers ---
    regs = subparsers.add_parser("registers", help="Show register values")
    _common_io_options(regs)
    regs.add_argument("--all", action="store_true", help="Show all registers including floating-point")
    regs.set_defaults(handler=_registers)

    # --- memory ---
    mem = subparsers.add_parser("memory", help="Memory read/write")
    mem_sub = mem.add_subparsers(dest="memory_command")
    mem_read = mem_sub.add_parser("read", help="Read memory")
    _common_io_options(mem_read)
    mem_read.add_argument("address", help="Start address (hex or expression)")
    mem_read.add_argument("length", type=int, help="Number of bytes to read")
    mem_read.add_argument("--display", dest="mem_format", choices=("hex", "bytes", "string"), default="hex",
                          help="Memory display format")
    mem_read.set_defaults(handler=_memory_read)

    mem_write = mem_sub.add_parser("write", help="Write memory")
    _common_io_options(mem_write, default_format="json")
    mem_write.add_argument("address", help="Start address (hex or expression)")
    mem_write.add_argument("value", help="Value to write (hex string)")
    mem_write.set_defaults(handler=_memory_write)

    # --- disasm ---
    disasm = subparsers.add_parser("disasm", help="Disassemble instructions")
    _common_io_options(disasm)
    disasm.add_argument("location", nargs="?", help="Function name, address, or omit for current PC")
    disasm.add_argument("--count", type=int, help="Number of instructions")
    disasm.set_defaults(handler=_disasm)

    # --- functions ---
    funcs = subparsers.add_parser("functions", help="List or search functions")
    _common_io_options(funcs)
    _add_paged_args(funcs)
    funcs.add_argument("--query", help="Search pattern")
    funcs.set_defaults(handler=_functions)

    # --- symbols ---
    syms = subparsers.add_parser("symbols", help="List or search symbols")
    _common_io_options(syms)
    _add_paged_args(syms)
    syms.add_argument("--query", help="Search pattern")
    syms.set_defaults(handler=_symbols)

    # --- types ---
    types = subparsers.add_parser("types", help="Type inspection")
    types_sub = types.add_subparsers(dest="types_command")
    types_show = types_sub.add_parser("show", help="Show type definition")
    _common_io_options(types_show)
    types_show.add_argument("name", help="Type name")
    types_show.set_defaults(handler=_types_show)

    # --- info ---
    info = subparsers.add_parser("info", help="Miscellaneous info commands")
    info_sub = info.add_subparsers(dest="info_command")
    info_files_cmd = info_sub.add_parser("files", help="Show loaded files and sections")
    _common_io_options(info_files_cmd)
    info_files_cmd.set_defaults(handler=_info_files)
    info_target_cmd = info_sub.add_parser("target", help="Show target connection info")
    _common_io_options(info_target_cmd)
    info_target_cmd.set_defaults(handler=_target_info)

    # --- source ---
    source = subparsers.add_parser("source", help="Source code inspection")
    source_sub = source.add_subparsers(dest="source_command")
    source_list = source_sub.add_parser("list", help="Show source code")
    _common_io_options(source_list)
    source_list.add_argument("location", nargs="?", help="Function name or file:line")
    source_list.add_argument("--count", type=int, help="Number of lines")
    source_list.set_defaults(handler=_source_list)

    # --- py ---
    py = subparsers.add_parser("py", help="Execute Python code inside GDB")
    py_sub = py.add_subparsers(dest="py_command")
    py_exec = py_sub.add_parser("exec", help="Execute Python code")
    _common_io_options(py_exec)
    _add_timeout_arg(py_exec)
    py_code_group = py_exec.add_mutually_exclusive_group(required=True)
    py_code_group.add_argument("--code", help="Python code to execute")
    py_code_group.add_argument("--script", help="Path to Python script")
    py_code_group.add_argument("--stdin", action="store_true", help="Read code from stdin")
    py_exec.set_defaults(handler=_py_exec)

    # --- gdb ---
    gdb_cmd = subparsers.add_parser("gdb", help="Execute a raw GDB command (supports pwndbg, custom scripts, etc.)")
    _common_io_options(gdb_cmd)
    _add_timeout_arg(gdb_cmd)
    gdb_cmd.add_argument("command", help="GDB command to execute (e.g. 'kbase', 'info proc mappings')")
    gdb_cmd.set_defaults(handler=_gdb_exec)

    # --- trace ---
    trace_cmd = subparsers.add_parser("trace", help="Trace memory accesses within a code range")
    _common_io_options(trace_cmd)
    _add_timeout_arg(trace_cmd)
    trace_cmd.add_argument("--watch", required=True, metavar="ADDR",
                           help="Memory address to watch (hex)")
    trace_cmd.add_argument("--watch-size", type=int, default=4, metavar="N",
                           help="Number of bytes to watch (default: 4)")
    trace_cmd.add_argument("--range", required=True, metavar="START-END",
                           help="Code address range (e.g., 0x404610-0x405e30)")
    trace_cmd.add_argument("--type", choices=("write", "read", "access"), default="access",
                           dest="watch_type", help="Watch type (default: access)")
    trace_cmd.add_argument("--max-hits", type=int, default=10000, metavar="N",
                           help="Maximum number of hits to record (default: 10000)")
    trace_cmd.set_defaults(handler=_trace)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] | None = getattr(args, "handler", None)
    if handler is None:
        selected_parser = getattr(args, "_parser", parser)
        selected_parser.print_help()
        return 1

    try:
        return handler(args)
    except BridgeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
