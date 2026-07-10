from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
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
    claude_skills_dir,
    codex_home,
    codex_skills_dir,
    gdb_log_path,
    gdb_pid_path,
    plugin_install_dir,
    plugin_source_dir,
    repo_root,
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


def _add_thread_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--thread", type=int, metavar="N",
        help="Run against thread N (the prior thread selection is restored after)",
    )


def _add_output_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output", action="store_true",
        help="Also print new session output (inferior stdout/stderr and GDB "
             "messages) to stderr; note targets may buffer stdout until they "
             "flush or exit",
    )


def _positive_int(s: str) -> int:
    v = int(s)
    if v < 1:
        raise argparse.ArgumentTypeError(f"must be a positive integer (>= 1), got {v}")
    return v


def _nonneg_int(s: str) -> int:
    v = int(s)
    if v < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {v}")
    return v


def _positive_float(s: str) -> float:
    v = float(s)
    if v <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive number of seconds, got {v}")
    return v


def _add_paged_args(parser: argparse.ArgumentParser) -> None:
    # Non-positive values used to flow straight into Python slicing: `--limit
    # -1` became result[:-1] (dumped all-but-last → a huge spill) and `--limit
    # 0` produced a contradictory empty-but-"truncated" result. Reject them.
    parser.add_argument(
        "--offset", type=_nonneg_int, default=0,
        help="Skip this many results (for paging; default: 0)",
    )
    parser.add_argument(
        "--limit", type=_positive_int, default=100,
        help="Max results to return; on truncation a stderr note shows the next --offset (default: 100)",
    )


def _render_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_label: str | None = None,
    spill_context: Any = None,
) -> None:
    try:
        result = write_output_result(value, fmt=fmt, out_path=out_path, stem=stem)
    except OSError as exc:
        # A bad --out (or unwritable spill dir) must surface as the standard
        # exit-0 error envelope, not a raw traceback with exit 1.
        raise BridgeError(f"cannot write output to {out_path or '<spill dir>'}: {exc}")
    if result.spilled and result.artifact:
        label = spill_label or stem.replace("_", " ")
        artifact = result.artifact
        # The artifact envelope (path/tokens/summary/...) is the real result
        # once output spills, so it must go to STDOUT — agents that read
        # stdout as the result would otherwise see nothing and conclude the
        # command produced no data. A concise note also goes to stderr for
        # humans.
        summary = artifact.get("summary")
        summary_note = ""
        if isinstance(summary, dict):
            kind = summary.get("kind")
            count = summary.get("count")
            if kind is not None:
                summary_note = f", {kind}"
                if count is not None:
                    summary_note += f" of {count}"
        print(
            f"warning: {label} output spilled to {artifact['artifact_path']} "
            f"({artifact['tokens']} tokens{summary_note}); "
            f"full envelope on stdout",
            file=sys.stderr,
        )
        sys.stdout.write(result.rendered)
        return
    sys.stdout.write(result.rendered)


def _render_fallback_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def _resolve_instance_pid(instance_pid: int | None) -> int | None:
    """Best-effort: the pid of the targeted (or sole) running instance."""
    if instance_pid is not None:
        return instance_pid
    instances = list_instances()
    return instances[0].pid if len(instances) == 1 else None


def _inferior_log_size(instance_pid: int | None) -> int | None:
    """Current byte size of an instance's session log (None if unavailable)."""
    pid = _resolve_instance_pid(instance_pid)
    if pid is None:
        return None
    try:
        return gdb_log_path(pid).stat().st_size
    except OSError:
        return None


def _inferior_log_delta(instance_pid: int | None, since_size: int | None) -> str:
    """Read log bytes appended since *since_size* (the inferior's new output).

    Note: targets buffer stdout when it isn't a TTY, so output may not appear
    until the program flushes or exits — this surfaces whatever is available.
    """
    if since_size is None:
        return ""
    pid = _resolve_instance_pid(instance_pid)
    if pid is None:
        return ""
    try:
        with open(gdb_log_path(pid), "rb") as f:
            f.seek(since_size)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _call(
    args: argparse.Namespace,
    op: str,
    params: dict[str, Any] | None = None,
    *,
    text_renderer: Callable[[Any], str] | None = None,
    map_result: Callable[[Any], Any] | None = None,
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

    # `--thread N` on an inspection command runs it against that thread (the
    # bridge restores the prior selection afterward). Plumbed here so every
    # command that exposes --thread gets it without per-handler wiring.
    if getattr(args, "thread", None) is not None:
        request_params.setdefault("thread", args.thread)

    kw: dict[str, Any] = {}
    if timeout is not None:
        kw["timeout"] = timeout

    instance_pid = getattr(args, "instance", None)

    # `--output` (exec commands): capture the inferior's new stdout/stderr
    # produced during this command by diffing the session log around the call.
    want_output = getattr(args, "output", False)
    log_before = _inferior_log_size(instance_pid) if want_output else None

    response = send_request(
        op,
        params=request_params,
        instance_pid=instance_pid,
        **kw,
    )
    if want_output:
        new_output = _inferior_log_delta(instance_pid, log_before)
        if new_output:
            print(new_output, end="" if new_output.endswith("\n") else "\n",
                  file=sys.stderr)
    result = response["result"]
    # Normalise the raw result for ALL output formats (e.g. strip ANSI from
    # gdb passthrough) before exit-code/pagination/render decisions, so JSON
    # consumers get the same clean payload that text mode does.
    if map_result is not None:
        result = map_result(result)
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
        # Show the loaded binary so concurrent sessions are distinguishable
        # after the launch pid scrolls away.
        inferiors = doctor.get("inferiors") if isinstance(doctor.get("inferiors"), list) else []
        for inf in inferiors:
            if isinstance(inf, dict) and inf.get("executable"):
                ipid = inf.get("pid") or 0
                suffix = f" (inferior pid {ipid})" if ipid else ""
                lines.append(f"  binary: {inf['executable']}{suffix}")
                break
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
        base = f"watchpoint #{num} ({expr}) hit" if expr else f"watchpoint #{num} hit"
        old = reason.get("old_value")
        new = reason.get("new_value")
        if new is not None and old is not None:
            base += f": {old} -> {new}"
        elif new is not None:
            base += f": value = {new}"
        return base
    if kind == "signal":
        sig = reason.get("signal", "unknown")
        return f"signal {sig}"
    if kind == "exited":
        code = reason.get("code")
        return f"exited (code {code})" if code is not None else "exited"
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
    return_value = value.get("return_value")
    if return_value is not None:
        parts.append(f"return value: {return_value}")
    displays = value.get("displays")
    if isinstance(displays, list) and displays:
        for d in displays:
            if isinstance(d, dict):
                parts.append(f"  display #{d.get('number')}: {d.get('expr')} = {d.get('value')}")
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
    if state in ("stopped", "exited"):
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
        displays = value.get("displays")
        if isinstance(displays, list) and displays:
            for d in displays:
                if isinstance(d, dict):
                    parts.append(f"  display #{d.get('number')}: {d.get('expr')} = {d.get('value')}")
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


def _render_attach_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    parts = [f"attached to pid {value.get('attached', '?')}"]
    frame = value.get("frame") or {}
    func = frame.get("function")
    if func:
        loc = func
        f = frame.get("file")
        line = frame.get("line")
        if f:
            loc += f" at {f}" + (f":{line}" if line is not None else "")
        parts.append(f"frame: {loc}")
    return "\n".join(parts)


def _render_interrupt_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    if value.get("interrupted"):
        return "interrupted"
    state = value.get("state")
    return f"not interrupted (inferior is {state})" if state else "not interrupted (inferior was not running)"


def _render_memory_write_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return f"wrote {value.get('written', '?')} bytes to {value.get('address', '?')}"


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


def _bp_kind_label(bp: dict) -> str:
    """Return the human-friendly kind label for a breakpoint dict."""
    kind = bp.get("kind")
    if isinstance(kind, str):
        return kind
    # Legacy fallback: plugins without the kind field report only the
    # integer type code, or sometimes a pre-rendered string. Accept both.
    btype = bp.get("type")
    if isinstance(btype, str):
        return btype
    return "breakpoint" if btype in (None, 1) else f"type-{btype}"


def _bp_target_label(bp: dict) -> str:
    """Location string for watchpoints vs breakpoints."""
    expr = bp.get("expression")
    location = bp.get("location")
    if expr and (bp.get("kind") or "").endswith("watchpoint"):
        return expr
    if location:
        return location
    if expr:
        return expr
    return "<unknown>"


def _bp_target_preposition(bp: dict) -> str:
    """'at' for breakpoints, 'on' for watchpoints."""
    kind = bp.get("kind") or ""
    return "on" if "watchpoint" in kind else "at"


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
        kind = _bp_kind_label(bp)
        # Catchpoints carry no location/expression; show the "what" instead.
        if kind == "catchpoint" and bp.get("what"):
            target = bp["what"]
            prep = "for"
        else:
            target = _bp_target_label(bp)
            prep = _bp_target_preposition(bp)
        enabled = "enabled" if bp.get("enabled") else "disabled"
        hits = bp.get("hits", 0)
        line = f"#{num} {kind} {prep} {target} [{enabled}] hits={hits}"
        if bp.get("pending"):
            line += " (pending)"
        if bp.get("temporary"):
            line += " (temporary)"
        thread = bp.get("thread")
        if thread is not None:
            line += f" thread {thread}"
        ignore = bp.get("ignore")
        if ignore:
            line += f" ignore {ignore}"
        cond = bp.get("condition")
        if cond:
            line += f" if {cond}"
        lines.append(line)
    return "\n".join(lines)


def _render_breakpoint_set_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("number", "?")
    target = _bp_target_label(value)
    prep = _bp_target_preposition(value)
    kind = _bp_kind_label(value)
    noun = "watchpoint" if "watchpoint" in (value.get("kind") or "") else "breakpoint"
    enabled = "enabled" if value.get("enabled") else "disabled"
    parts = [f"{noun} #{num} set {prep} {target} [{enabled}]"]
    addr = value.get("address")
    if addr:
        where = f"@ {addr}"
        f = value.get("file")
        line = value.get("line")
        if f and line is not None:
            where += f" {f}:{line}"
        parts.append(where)
    if value.get("pending"):
        parts.append("(pending — location not yet resolved)")
    if value.get("temporary"):
        parts.append("temporary")
    cond = value.get("condition")
    if cond:
        parts.append(f"if {cond}")
    ignore = value.get("ignore")
    if ignore:
        parts.append(f"(ignore {ignore})")
    rebased = value.get("rebased")
    if isinstance(rebased, dict):
        parts.append(f"(rebased from {rebased.get('offset', '?')} in {rebased.get('module', '?')})")
    return " ".join(parts)


def _render_breakpoint_delete_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    def _noun(kind: Any) -> str:
        # break/watch share a number space; name the deleted object correctly.
        return "watchpoint" if "watchpoint" in (kind or "") else "breakpoint"

    items = value.get("items")
    if isinstance(items, list) and items:
        return "\n".join(
            f"{_noun(it.get('kind'))} #{it.get('number')} deleted"
            for it in items if isinstance(it, dict)
        )
    return f"{_noun(value.get('kind'))} #{value.get('deleted', '?')} deleted"


def _render_breakpoint_state_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    num = value.get("number", "?")
    target = _bp_target_label(value)
    prep = _bp_target_preposition(value)
    noun = "watchpoint" if "watchpoint" in (value.get("kind") or "") else "breakpoint"
    enabled = "enabled" if value.get("enabled") else "disabled"
    return f"{noun} #{num} {prep} {target} [{enabled}]"


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
        # An unresolved frame carries function=None (e.g. a smashed return
        # address); render GDB's "??" rather than the literal "None".
        func = frame.get("function") or "??"
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
        # With --full, each frame carries a "locals" list (which also includes
        # arguments, flagged is_argument). Render the non-argument locals
        # indented beneath the frame; arguments already appear in (...) above.
        locs = frame.get("locals")
        if locs:
            for loc in locs:
                if not isinstance(loc, dict) or loc.get("is_argument"):
                    continue
                lines.append(f"    {loc.get('name', '?')} = {loc.get('value', '?')}")
    return "\n".join(lines)


def _render_frame_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    level = value.get("level", "?")
    func = value.get("function") or "??"
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


def _render_args_text(value: Any) -> str:
    # Same formatting as locals, but the empty case is "no args" (a frame with
    # no parameters), not "no locals".
    if isinstance(value, list) and not value:
        return "no args"
    return _render_locals_text(value)


def _render_register_write_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    name = value.get("register", "?")
    readback = value.get("readback")
    if readback is not None:
        return f"${name} = {readback}"
    return f"${name} set to {value.get('value', '?')}"


def _render_mappings_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no mappings (inferior not running, or target has no proc maps)"
    lines = []
    for m in value:
        if not isinstance(m, dict):
            lines.append(str(m))
            continue
        start = m.get("start", "?")
        end = m.get("end", "?")
        perms = m.get("perms", "----")
        offset = m.get("offset", "")
        objfile = m.get("objfile", "")
        lines.append(f"{start}-{end}  {perms:<5} {offset:>12}  {objfile}".rstrip())
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
    if fmt == "pretty":
        return _render_memory_pretty(value)
    data = value.get("data", "")
    addr = value.get("address", "")
    if addr:
        return f"{addr}: {data}"
    return data


def _render_memory_pretty(value: dict) -> str:
    """Build an xxd-style dump from a hex payload."""
    hex_data = value.get("data", "")
    addr_str = value.get("address", "0x0")
    try:
        base = int(addr_str, 16) if isinstance(addr_str, str) else int(addr_str)
    except ValueError:
        base = 0
    try:
        raw = bytes.fromhex(hex_data)
    except ValueError:
        return hex_data
    lines = []
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to 16 bytes wide for alignment.
        hex_part = f"{hex_part:<47}"
        # Split into two 8-byte groups with a middle gap.
        left = hex_part[:23]
        right = hex_part[24:]
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"0x{base + offset:x}:  {left} {right}  |{ascii_part}|")
    return "\n".join(lines)


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
        symbol = insn.get("symbol")
        if symbol:
            lines.append(f"{addr} <{symbol}>:  {asm_text}")
        else:
            lines.append(f"{addr}:  {asm_text}")
    return "\n".join(lines)


def _render_examine_text(value: Any) -> str:
    if isinstance(value, dict):
        return value.get("text") or _render_fallback_text(value)
    return _render_fallback_text(value)


def _render_thread_select_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    if "selected" in value and "num" not in value:
        return f"selected thread {value['selected']}"
    num = value.get("num", "?")
    frame = value.get("frame") or {}
    func = frame.get("function")
    loc = f" in {func}" if func else ""
    return f"selected thread {num}{loc}"


def _render_display_add_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return f"display #{value.get('number')}: {value.get('expr')}"


def _render_display_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no displays"
    return "\n".join(
        f"#{d.get('number')}: {d.get('expr')} = {d.get('value')}"
        for d in value if isinstance(d, dict)
    )


def _render_name_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no matches"
    # Align the name column when addresses are present so the eye can scan
    # down. Trailing columns (file:line, signature/decl) fall where they may.
    rows: list[tuple[str, str, str]] = []
    name_width = 0
    for item in value:
        if not isinstance(item, dict):
            rows.append(("", str(item), ""))
            continue
        addr = item.get("address") or ""
        name = item.get("name") or "<unknown>"
        trailer_parts: list[str] = []
        file = item.get("file")
        line = item.get("line")
        if file and line is not None:
            trailer_parts.append(f"{file}:{line}")
        elif file:
            trailer_parts.append(str(file))
        detail = item.get("signature") or item.get("decl")
        if detail:
            trailer_parts.append(str(detail))
        rows.append((addr, name, "  ".join(trailer_parts)))
        name_width = max(name_width, len(name))
    lines: list[str] = []
    for addr, name, trailer in rows:
        parts = []
        if addr:
            parts.append(addr)
        if trailer:
            parts.append(f"{name:<{name_width}}")
        else:
            parts.append(name)
        if trailer:
            parts.append(trailer)
        lines.append("  ".join(parts))
    return "\n".join(lines)


def _render_type_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    layout = value.get("layout")
    base = layout if (isinstance(layout, str) and layout) else value.get("decl")
    if not (isinstance(base, str) and base):
        return _render_fallback_text(value)
    # ptype/decl omits byte offsets; append them from the field metadata the
    # bridge already computes, so an agent doesn't have to switch to JSON or
    # compute offsetof() by hand.
    fields = value.get("fields")
    rows = []
    if isinstance(fields, list):
        for f in fields:
            if not isinstance(f, dict) or f.get("name") is None:
                continue
            bitpos = f.get("bitpos")
            if not isinstance(bitpos, int):
                continue
            typ = f.get("type") or ""
            rows.append(f"  +{bitpos // 8:<5} {typ} {f['name']}".rstrip())
    if rows:
        sizeof = value.get("sizeof")
        header = f"offsets (sizeof={sizeof}):" if sizeof is not None else "offsets:"
        return base.rstrip() + "\n\n" + header + "\n" + "\n".join(rows)
    return base


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
    base = f"({typ}) {val}" if typ else str(val)
    note = value.get("note")
    if note:
        base += f"\nnote: {note}"
    return base


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


def _render_thread_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no threads"
    lines = []
    for thread in value:
        if not isinstance(thread, dict):
            lines.append(str(thread))
            continue
        num = thread.get("num", "?")
        selected = " *" if thread.get("selected") else ""
        status = thread.get("status") or "unknown"
        inf = thread.get("inferior_num")
        frame = thread.get("frame") if isinstance(thread.get("frame"), dict) else {}
        addr = frame.get("address") or "?"
        func = frame.get("function") or "?"
        name = thread.get("name")
        prefix = f"  {num}{selected}"
        if inf is not None:
            prefix += f"  inferior={inf}"
        line = f"{prefix}  {status:<7}  {addr}  {func}"
        if name:
            line += f"  ({name})"
        lines.append(line)
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


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _render_gdb_exec_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    output = value.get("output", "")
    if not output:
        return "(no output)"
    # pwndbg and friends emit ANSI colors even when stdout is a pipe. Strip
    # them when we're not printing to a real terminal so agents don't have
    # to filter escape codes out of tool results.
    if not sys.stdout.isatty():
        output = _ANSI_ESCAPE_RE.sub("", output)
    return output.rstrip()


def _render_plugin_install_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    mode = value.get("mode", "unknown")
    dest = value.get("destination", "<unknown>")
    verb = "already installed" if value.get("already_present") else "installed"
    return f"Plugin {verb} ({mode}): {dest}\n"


def _render_skill_install_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    installed = value.get("installed_destinations")
    skipped = value.get("skipped_destinations")
    lines = []

    if isinstance(installed, list) and installed:
        lines.append(f"Installed skills ({value.get('mode', 'unknown')}):")
        lines.extend(f"- {dest}" for dest in installed)
    else:
        lines.append("Skills already installed.")

    if isinstance(skipped, list) and skipped:
        lines.append("Skipped existing destinations:")
        lines.extend(f"- {dest}" for dest in skipped)

    return "\n".join(lines) + "\n"


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

    target_pid = getattr(args, "instance", None)
    discovered = list_instances()
    if target_pid is not None:
        discovered = [i for i in discovered if i.pid == target_pid]
        if not discovered:
            raise BridgeError(f"No running GDB bridge instance with pid {target_pid}")

    instances = []
    for instance in discovered:
        ping: dict[str, Any]
        try:
            # Bound the probe so one wedged/unresponsive bridge can't hang the
            # whole health check (the connect may succeed while the bridge's
            # GDB thread is stuck and never replies).
            response = _send_request_to_instance(
                instance,
                "doctor",
                params={},
                timeout=5.0,
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


def _install_tree(source: Path, dest: Path, *, mode: str, force: bool) -> bool:
    """Install *source* at *dest*. Returns True if it created the install, or
    False when the exact symlink already existed (an idempotent no-op)."""
    if not source.exists():
        raise BridgeError(f"Source directory is missing: {source}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() or dest.is_symlink():
        # Idempotent: re-installing the exact symlink we'd create is a no-op,
        # not an error — so `pry plugin install` can be re-run safely.
        if (mode == "symlink" and dest.is_symlink()
                and os.path.realpath(dest) == os.path.realpath(source)):
            return False
        if not force:
            raise BridgeError(
                f"Destination already exists: {dest}. Pass --force to replace it."
            )
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    if mode == "copy":
        shutil.copytree(source, dest)
    else:
        os.symlink(source, dest, target_is_directory=True)
    return True


def _check_install_destination(dest: Path, *, force: bool) -> None:
    if force:
        return
    if dest.exists() or dest.is_symlink():
        raise BridgeError(f"Destination already exists: {dest}")


def _plugin_install(args: argparse.Namespace) -> int:
    source = plugin_source_dir()
    dest = args.dest or plugin_install_dir()
    created = _install_tree(source, dest, mode=args.mode, force=args.force)

    gdbinit_snippet = (
        "python\n"
        "import sys\n"
        f"sys.path.insert(0, {str(dest.parent)!r})\n"
        "import pry_agent_bridge\n"
        "end\n"
    )

    result: dict[str, Any] = {
        "installed": True,
        "already_present": not created,
        "mode": args.mode,
        "source": str(source),
        "destination": str(dest),
        "gdbinit_snippet": gdbinit_snippet,
    }
    rendered: Any = result
    if args.format == "text":
        rendered = _render_plugin_install_text(result)
    _render_result(rendered, fmt=args.format, out_path=args.out, stem="plugin-install")
    if args.format == "text":
        print(
            f"\nAdd the following to your ~/.gdbinit:\n\n{gdbinit_snippet}",
            file=sys.stderr,
        )
    return 0


def _skill_install(args: argparse.Namespace) -> int:
    skills_root = repo_root() / "skills"
    explicit_dest = args.dest is not None
    target_roots = [args.dest] if explicit_dest else _default_skill_install_roots()
    install_plan = []
    results = []

    for source in sorted(skills_root.iterdir()):
        if not source.is_dir() or not (source / "SKILL.md").exists():
            continue
        destinations = []
        for target_root in target_roots:
            dest = target_root / source.name
            install_plan.append((source, dest))
            destinations.append(str(dest))
        results.append(
            {
                "skill": source.name,
                "source": str(source),
                "destination": destinations[0],
                "destinations": destinations,
            }
        )

    pending_installs = []
    skipped_destinations = []
    for source, dest in install_plan:
        if not explicit_dest and not args.force and (dest.exists() or dest.is_symlink()):
            skipped_destinations.append(str(dest))
            continue
        _check_install_destination(dest, force=args.force)
        pending_installs.append((source, dest))

    for source, dest in pending_installs:
        _install_tree(source, dest, mode=args.mode, force=args.force)

    result: Any = {
        "installed": True,
        "mode": args.mode,
        "installed_destinations": [str(dest) for _, dest in pending_installs],
        "skipped_destinations": skipped_destinations,
        "skills": results,
    }
    if args.format == "text":
        result = _render_skill_install_text(result)
    _render_result(result, fmt=args.format, out_path=args.out, stem="skill-install")
    return 0


def _default_skill_install_roots() -> list[Path]:
    roots = [claude_skills_dir()]
    if codex_home().is_dir():
        roots.append(codex_skills_dir())
    return roots


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
    resolved_binary: str | None = None
    if args.binary:
        binary_path = Path(args.binary).expanduser().resolve()
        # Validate before spawning: GDB happily starts with a missing/invalid
        # binary and lazily complains ("No executable file specified") only when
        # you try to run, so the bridge would come up and `launch` would report
        # success for a session that is actually dead. Fail fast instead.
        if not binary_path.exists():
            raise BridgeError(
                f"Binary not found: {args.binary} (resolved to {binary_path}). "
                f"The path is relative to the current directory ({Path.cwd()}); "
                f"pass an absolute path or check the spelling."
            )
        if not binary_path.is_file():
            raise BridgeError(
                f"Not a file: {args.binary} (resolved to {binary_path}). "
                f"Pass a path to an executable file, not a directory."
            )
        resolved_binary = str(binary_path)
        gdb_cmd.append(resolved_binary)

    # Self-pipe: GDB holds its own stdin writer open so it never sees EOF
    read_fd, write_fd = os.pipe()

    keepalive_ex = f"python import os as _os; __pry_stdin_writer = _os.fdopen({write_fd}, 'w')"
    bridge_ex = (
        f"python import sys; sys.path.insert(0, {str(plugin_parent)!r}); import pry_agent_bridge"
    )
    # Disable GDB's default behaviour of spawning the inferior via /bin/sh.
    # Programmatic debuggers want byte-precise argv: shell-routing mangles
    # quotes, backslashes, NULs, etc., and the inferior may never reach
    # the entry point (e.g. /bin/sh -c with unmatched quote → exit 1).
    # Anyone needing shell expansion can `set startup-with-shell on` from
    # their own session.
    shell_off_ex = "set startup-with-shell off"
    gdb_cmd.extend(["-ex", shell_off_ex, "-ex", keepalive_ex, "-ex", bridge_ex])

    gdb_extra = args.gdb_args or []
    explicit_separator = "--" in getattr(args, "_raw_argv", [])
    if gdb_extra and gdb_extra[0] == "--":
        gdb_extra = gdb_extra[1:]  # defensive: a second, literal `--`
    elif gdb_extra and not explicit_separator:
        # Without an explicit `--` separator, anything after the binary is
        # forwarded to GDB. A pry option placed there (e.g.
        # `pry launch ./bin --format json`) would silently leak to GDB and
        # break the launch. Catch the common case with an actionable message.
        _pry_flags = {
            "--format", "--out", "--instance", "--timeout",
            "--symbols", "--connect",
        }
        first = gdb_extra[0].split("=", 1)[0]
        if first in _pry_flags:
            raise BridgeError(
                f"'{gdb_extra[0]}' is a pry option but appears after the binary, "
                f"so it would be forwarded to GDB. Put pry options before the "
                f"binary (e.g. `pry launch {first} ... <binary>`), or separate "
                f"GDB args with `--` (e.g. `pry launch <binary> -- <gdb-args>`)."
            )
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
    if resolved_binary is not None:
        result["binary"] = resolved_binary

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
    if getattr(args, "all", False):
        killed = []
        for inst in list_instances():
            _kill_instance(inst.pid)
            killed.append(inst.pid)
        if args.format == "text":
            msg = (
                f"Killed {len(killed)} GDB session(s): {', '.join(map(str, killed))}"
                if killed else "No running GDB sessions to kill."
            )
            _render_result(msg, fmt="text", out_path=args.out, stem="kill")
        else:
            _render_result({"killed": True, "pids": killed}, fmt=args.format, out_path=args.out, stem="kill")
        return 0

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
    else:
        # Validate an explicit --instance so we don't falsely report "Killed"
        # for a pid that was never a pry instance (os.kill silently no-ops a
        # dead pid). Matches how every other command resolves --instance.
        if not any(i.pid == target_pid for i in list_instances()):
            raise BridgeError(f"No running GDB bridge instance with pid {target_pid}")

    _kill_instance(target_pid)

    result: dict[str, Any] = {"killed": True, "pid": target_pid}
    if args.format == "text":
        _render_result(f"Killed GDB (pid={target_pid})", fmt="text", out_path=args.out, stem="kill")
    else:
        _render_result(result, fmt=args.format, out_path=args.out, stem="kill")
    return 0


def _logs(args: argparse.Namespace) -> int:
    """Show a session's captured inferior stdout/stderr (and GDB's own output).

    The inferior's output is written to ~/.cache/pry/instances/<pid>.log; this
    is the only place an agent can see what the debugged program printed.
    """
    target_pid: int | None = getattr(args, "instance", None)
    if target_pid is None:
        instances = list_instances()
        if not instances:
            raise BridgeError("No running GDB session found. Launch one with 'pry launch <binary>'.")
        if len(instances) > 1:
            pids = ", ".join(str(i.pid) for i in instances)
            raise BridgeError(
                f"Multiple bridge instances running (pids: {pids}). Use --instance <pid>."
            )
        target_pid = instances[0].pid

    log_path = gdb_log_path(target_pid)
    if not log_path.exists():
        raise BridgeError(f"No log found for instance {target_pid} (expected {log_path}).")
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise BridgeError(f"Could not read log {log_path}: {exc}")

    lines = getattr(args, "lines", None)
    if lines is not None and lines > 0:
        tail = text.splitlines()[-lines:]
        text = ("\n".join(tail) + "\n") if tail else ""

    if args.format == "text":
        _render_result(text, fmt="text", out_path=args.out, stem="logs")
    else:
        _render_result(
            {"pid": target_pid, "log_path": str(log_path), "content": text},
            fmt=args.format, out_path=args.out, stem="logs",
        )
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

def _render_load_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    path = value.get("loaded", "<unknown>")
    base = value.get("base")
    slide = value.get("slide")
    if base:
        return f"loaded {path} @ {base} (slide {slide})"
    if slide:
        return f"loaded {path} (slide {slide})"
    return f"loaded {path}"


def _load(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"path": str(Path(args.path).expanduser().resolve())}
    base = getattr(args, "base", None)
    slide = getattr(args, "slide", None)
    if base:
        params["base"] = base
    if slide:
        params["slide"] = slide
    return _call(
        args,
        "load",
        params,
        text_renderer=_render_load_text,
        stem="load",
    )


def _attach(args: argparse.Namespace) -> int:
    return _call(
        args,
        "attach",
        {"pid": args.pid},
        text_renderer=_render_attach_text,
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


def _threads(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.pc:
        params["pc"] = args.pc
    if args.function:
        params["function"] = args.function
    return _call(
        args,
        "list_threads",
        params,
        text_renderer=_render_thread_list_text,
        stem="threads",
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


def _jump(args: argparse.Namespace) -> int:
    ep, tt = _exec_params(args)
    params: dict[str, Any] = {"location": args.location}
    params.update(ep)
    renderer = _render_background_text if params.get("_background") else _render_stop_text
    return _call(args, "jump", params, text_renderer=renderer, stem="jump", timeout=tt)


def _interrupt(args: argparse.Namespace) -> int:
    return _call(args, "interrupt", text_renderer=_render_interrupt_text, stem="interrupt")


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
    if getattr(args, "ignore", None) is not None:
        params["ignore"] = args.ignore
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
    numbers = args.number if isinstance(args.number, list) else [args.number]
    # Keep the single-delete wire shape ({"number": N}) for backward
    # compatibility; only switch to the batch shape when more than one is given.
    params = {"number": numbers[0]} if len(numbers) == 1 else {"numbers": numbers}
    return _call(args, "break_delete", params, text_renderer=_render_breakpoint_delete_text, stem="break_delete")


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


def _frame_up(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if getattr(args, "count", None) is not None:
        params["count"] = args.count
    return _call(args, "frame_up", params, text_renderer=_render_frame_info_text, stem="frame_up")


def _frame_down(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if getattr(args, "count", None) is not None:
        params["count"] = args.count
    return _call(args, "frame_down", params, text_renderer=_render_frame_info_text, stem="frame_down")


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
        text_renderer=_render_args_text,
        stem="args",
    )


def _print_expr(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"expression": args.expression}
    if getattr(args, "p_format", None):
        params["format"] = args.p_format
    return _call(
        args,
        "print",
        params,
        text_renderer=_render_print_text,
        stem="print",
    )


def _call_fn(args: argparse.Namespace) -> int:
    return _call(
        args,
        "call",
        {"expression": args.expression},
        text_renderer=_render_print_text,
        stem="call",
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


def _register_write(args: argparse.Namespace) -> int:
    return _call(
        args,
        "register_write",
        {"name": args.name, "value": args.value},
        text_renderer=_render_register_write_text,
        stem="register_write",
    )


def _mappings(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    contains = getattr(args, "contains", None)
    name = getattr(args, "name", None)
    if contains:
        params["contains"] = contains
    if name:
        params["name"] = name
    has_filter = bool(contains or name)

    def render(value: Any) -> str:
        # Distinguish "filter matched nothing" from "no mappings at all" so the
        # empty case doesn't always (falsely) claim the inferior isn't running.
        if isinstance(value, list) and not value and has_filter:
            filt = f"--contains {contains}" if contains else f"--name {name}"
            return f"no mappings match {filt}"
        return _render_mappings_text(value)

    return _call(
        args,
        "mappings",
        params or None,
        text_renderer=render,
        stem="mappings",
    )


def _memory_read(args: argparse.Namespace) -> int:
    # Guard non-positive counts here: GDB's read leaks a raw
    # "OverflowError: can't convert negative int to unsigned" for a negative
    # length and an opaque message for 0.
    if args.length <= 0:
        raise BridgeError(f"byte count must be a positive integer, got {args.length}")
    mem_fmt = getattr(args, "mem_format", "hex")
    plain = bool(getattr(args, "plain", False))
    params: dict[str, Any] = {
        "address": args.address,
        "length": args.length,
    }
    # "pretty" is a CLI-side presentation on top of the hex payload so the
    # wire format stays unchanged. Request hex from the bridge and let the
    # text renderer format the dump.
    wire_fmt = "hex" if mem_fmt == "pretty" else mem_fmt
    if wire_fmt != "hex":
        params["format"] = wire_fmt

    def _render(value: Any) -> str:
        if plain and isinstance(value, dict):
            return str(value.get("data", ""))
        if mem_fmt == "pretty" and isinstance(value, dict):
            value = dict(value)
            value["format"] = "pretty"
        return _render_memory_text(value)

    return _call(
        args,
        "memory_read",
        params,
        text_renderer=_render,
        stem="memory_read",
    )


def _memory_write(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_write",
        {"address": args.address, "value": args.value},
        text_renderer=_render_memory_write_text,
        stem="memory_write",
    )


def _disasm(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.location:
        params["location"] = args.location
    if args.count is not None:
        params["count"] = args.count
    if getattr(args, "start", None) is not None:
        params["start"] = args.start
    if getattr(args, "end", None) is not None:
        params["end"] = args.end
    if getattr(args, "source", False):
        params["source"] = True
    return _call(
        args,
        "disasm",
        params,
        text_renderer=_render_disasm_text,
        stem="disasm",
    )


_EXAMINE_SPEC_LETTERS = set("xduotacfsizbhwg")  # GDB x/ format + size letters


def _examine(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if getattr(args, "spec", None):
        # Catch a malformed --spec before GDB does — its raw error ("Undefined
        # output format 'e'" for `--spec garbage`) is baffling.
        letters = [c for c in args.spec.strip() if not c.isdigit()]
        if len(letters) > 2 or any(c not in _EXAMINE_SPEC_LETTERS for c in letters):
            raise BridgeError(
                f"invalid examine spec {args.spec!r} — expected [count][format][size] "
                f"like '8xw' or '3i' (format: x d u o t a c f s i z; size: b h w g)"
            )
        params["spec"] = args.spec
    else:
        if getattr(args, "count", None) is not None:
            params["count"] = args.count
        if getattr(args, "x_format", None):
            params["format"] = args.x_format
        if getattr(args, "size", None):
            params["size"] = args.size
    return _call(
        args,
        "examine",
        params,
        text_renderer=_render_examine_text,
        stem="examine",
    )


def _thread_select(args: argparse.Namespace) -> int:
    return _call(
        args,
        "thread_select",
        {"num": args.num},
        text_renderer=_render_thread_select_text,
        stem="thread_select",
    )


def _display_add(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"expression": args.expression}
    if getattr(args, "p_format", None):
        params["format"] = args.p_format
    return _call(
        args,
        "display_add",
        params,
        text_renderer=_render_display_add_text,
        stem="display_add",
    )


def _display_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "display_list",
        text_renderer=_render_display_list_text,
        stem="display_list",
    )


def _display_remove(args: argparse.Namespace) -> int:
    return _call(
        args,
        "display_remove",
        {"number": args.number},
        text_renderer=lambda v: f"removed display #{v.get('removed')}" if isinstance(v, dict) else str(v),
        stem="display_remove",
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

# pwndbg kernel helpers often print a failure string via gdb.execute(...,
# to_string=True) without raising, so the bridge returns ok:true with the
# error text as "output". Agents then treat exit 0 as a successful KASLR
# probe. Special-case the well-known helpers + phrases only — leave general
# `pry gdb` passthrough alone.
_KERNEL_HELPER_COMMANDS = frozenset({"kbase", "klookup"})
_KERNEL_HELPER_FAILURE_PHRASES = (
    "unable to locate the kernel base",
    "kernel memory mappings are missing",
    "kbase does not work when kernel-vmmap is set to none",
    # pwndbg `klookup` prints this on a lookup miss ("No symbol found at/for ...").
    # Safe to match broadly because detection is already scoped to the
    # kbase/klookup commands in _kernel_helper_failure_message().
    "no symbol found",
)


def _strip_gdb_exec_ansi(result: Any) -> Any:
    """Strip ANSI escapes from gdb passthrough output for non-TTY consumers.

    pwndbg emits color even over a pipe. The text renderer already strips for
    non-TTY stdout, but the JSON/ndjson paths bypass it — so do it on the raw
    result here, leaving color intact only for an interactive terminal.
    """
    if (
        isinstance(result, dict)
        and isinstance(result.get("output"), str)
        and not sys.stdout.isatty()
    ):
        result = dict(result)
        result["output"] = _ANSI_ESCAPE_RE.sub("", result["output"])
    return result


def _gdb_command_basename(command: str) -> str:
    """First whitespace-delimited token of a GDB command string."""
    parts = command.strip().split(None, 1)
    return parts[0] if parts else ""


def _kernel_helper_failure_message(command: str, output: str) -> str | None:
    """Return a user-facing error if a known pwndbg kernel helper soft-failed.

    Matches only ``kbase`` / ``klookup`` (with optional args) against clear
    failure phrases from pwndbg. Returns None for everything else so ordinary
    GDB output keeps exiting 0.
    """
    base = _gdb_command_basename(command).lower()
    if base not in _KERNEL_HELPER_COMMANDS:
        return None
    cleaned = _ANSI_ESCAPE_RE.sub("", output or "")
    lowered = cleaned.lower()
    if not any(phrase in lowered for phrase in _KERNEL_HELPER_FAILURE_PHRASES):
        return None
    for line in cleaned.splitlines():
        line = line.strip()
        if line:
            return line
    return cleaned.strip() or "kernel helper failed"


def _map_gdb_exec_result(command: str, result: Any) -> Any:
    """Strip ANSI, then hard-fail known kbase/klookup soft errors."""
    result = _strip_gdb_exec_ansi(result)
    if isinstance(result, dict):
        msg = _kernel_helper_failure_message(command, str(result.get("output") or ""))
        if msg is not None:
            raise BridgeError(msg)
    return result


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
        map_result=lambda result: _map_gdb_exec_result(command, result),
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
        try:
            source = Path(script).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            # Without this a missing/unreadable --script dumps a raw Python
            # traceback (FileNotFoundError) instead of a clean CLI error.
            raise BridgeError(f"cannot read --script {script}: {exc.strerror or exc}")
    elif use_stdin:
        source = sys.stdin.read()
    else:
        raise BridgeError("One of --code, --script, or --stdin is required")

    timeout = getattr(args, "timeout", None)
    params: dict[str, Any] = {"code": source}
    # Give the transport longer than the bridge-side timeout: on a runaway
    # script the bridge waits _timeout, then spends up to ~5s injecting an
    # interrupt and unwinding before it can send its structured error. If the
    # socket gave up at exactly _timeout the agent would see an opaque
    # transport timeout instead of the actionable bridge message.
    transport_timeout = (timeout + 10) if timeout is not None else None
    if timeout is not None:
        params["_timeout"] = timeout
    return _call(
        args,
        "py_exec",
        params,
        text_renderer=_render_py_exec_text,
        stem="py_exec",
        timeout=transport_timeout,
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
    note = value.get("note")
    if note:
        lines.append(f"warning: {note}")
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
        raise BridgeError("--range must be in format START-END (e.g., 0x404610-0x405e30)")
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
        type=_positive_float,
        default=None,
        help="Override transport timeout in seconds (default: 30)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = PryArgumentParser(prog="pry", description="Agent-friendly GDB CLI")
    parser.set_defaults(handler=None)
    parser.add_argument(
        "--version", action="version", version=f"pry {_package_version()}",
        help="Print the pry version and exit",
    )
    # Global --instance: accepted before the subcommand so `pry --instance PID
    # <cmd>` matches the form shown throughout the README/SKILL docs. The
    # subcommand-level --instance is still accepted and wins when both are set.
    parser.add_argument(
        "--instance", type=int, default=None, metavar="PID", dest="instance_global",
        help="Target a specific bridge instance by GDB PID (global form)",
    )

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
    _common_io_options(plugin_install)
    plugin_install.set_defaults(handler=_plugin_install)

    # --- skill install ---
    skill = subparsers.add_parser("skill", help="Install the bundled agent skills")
    skill_sub = skill.add_subparsers(dest="skill_command")
    skill_install_cmd = skill_sub.add_parser("install", help="Install the bundled agent skills")
    skill_install_cmd.add_argument("--dest", type=Path, help="Custom install destination")
    skill_install_cmd.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    skill_install_cmd.add_argument("--force", action="store_true")
    _common_io_options(skill_install_cmd)
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
    kill.add_argument("--all", action="store_true", help="Kill all running GDB bridge sessions")
    kill.set_defaults(handler=_kill)

    # --- logs ---
    logs = subparsers.add_parser("logs", help="Show a session's captured inferior stdout/stderr (and GDB output)")
    _common_io_options(logs)
    logs.add_argument("-n", "--lines", type=int, default=None, metavar="N", help="Show only the last N lines")
    logs.set_defaults(handler=_logs)

    # --- load ---
    load = subparsers.add_parser("load", help="Load a binary into GDB")
    _common_io_options(load)
    load.add_argument("path", help="Path to binary")
    load.add_argument(
        "--base", metavar="ADDR",
        help="Load symbols so .text lands at this runtime base, as the sole copy, "
             "offsetting ALL sections uniformly (text+data). For relocated/PIE/KASLR "
             "modules; avoids the duplicate-symbol and data-not-relocated traps of "
             '`kbase -r`. Get a kernel base from `pry gdb "kbase"`.',
    )
    load.add_argument(
        "--slide", metavar="OFFSET",
        help="Offset added to every section (alternative to --base when the file's "
             ".text address can't be read).",
    )
    load.set_defaults(handler=_load)

    # --- attach ---
    attach = subparsers.add_parser("attach", help="Attach to a running process")
    _common_io_options(attach)
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
    _common_io_options(disconnect)
    disconnect.set_defaults(handler=_disconnect)

    # --- inferior ---
    inferior = subparsers.add_parser("inferior", help="Inspect GDB inferiors")
    inferior_sub = inferior.add_subparsers(dest="inferior_command")
    inferior_list = inferior_sub.add_parser("list", help="List inferiors")
    _common_io_options(inferior_list)
    inferior_list.set_defaults(handler=_inferior_list)

    # --- threads ---
    threads = subparsers.add_parser("threads", help="List threads")
    _common_io_options(threads)
    threads.add_argument("--pc", help="Only show threads stopped at this exact PC")
    threads.add_argument("--function", help="Only show threads whose frame function contains this text")
    threads.set_defaults(handler=_threads)

    # --- thread (select) ---
    thread = subparsers.add_parser("thread", help="Thread selection")
    thread_sub = thread.add_subparsers(dest="thread_command")
    thread_select = thread_sub.add_parser("select", help="Make a thread the selected one")
    _common_io_options(thread_select)
    thread_select.add_argument("num", type=int, help="Thread number (from `pry threads`)")
    thread_select.set_defaults(handler=_thread_select)

    # --- display (auto-display expressions on each stop) ---
    display = subparsers.add_parser("display", help="Auto-display expressions on each stop")
    display_sub = display.add_subparsers(dest="display_command")
    display_add = display_sub.add_parser("add", help="Register an expression to show on every stop")
    _common_io_options(display_add)
    display_add.add_argument("expression", help="Expression to auto-display")
    display_add.add_argument("--fmt", dest="p_format", metavar="F",
                             choices=("x", "d", "u", "o", "t", "a", "c", "f", "s", "z"),
                             help="GDB format letter (x,d,u,o,t,a,c,f,s,z), like print/F")
    display_add.set_defaults(handler=_display_add)
    display_list = display_sub.add_parser("list", help="List (and evaluate) registered displays")
    _common_io_options(display_list)
    display_list.set_defaults(handler=_display_list)
    display_remove = display_sub.add_parser("remove", help="Remove a registered display")
    _common_io_options(display_remove)
    display_remove.add_argument("number", type=int, help="Display number to remove")
    display_remove.set_defaults(handler=_display_remove)

    # --- run ---
    run = subparsers.add_parser("run", help="Run the loaded program")
    _common_io_options(run)
    _add_timeout_arg(run)
    _add_output_arg(run)
    run.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    run.add_argument("args", nargs="*", help="Program arguments")
    run.set_defaults(handler=_run)

    # --- continue ---
    cont = subparsers.add_parser("continue", help="Continue execution")
    _common_io_options(cont)
    _add_timeout_arg(cont)
    _add_output_arg(cont)
    cont.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    cont.set_defaults(handler=_continue)

    # --- step ---
    step = subparsers.add_parser("step", help="Step into (source-level)")
    _common_io_options(step)
    _add_output_arg(step)
    step.add_argument("count", nargs="?", type=int, help="Number of steps")
    step.set_defaults(handler=_step)

    # --- next ---
    next_cmd = subparsers.add_parser("next", help="Step over (source-level)")
    _common_io_options(next_cmd)
    _add_output_arg(next_cmd)
    next_cmd.add_argument("count", nargs="?", type=int, help="Number of steps")
    next_cmd.set_defaults(handler=_next)

    # --- stepi ---
    stepi = subparsers.add_parser("stepi", help="Step into (instruction-level)")
    _common_io_options(stepi)
    _add_output_arg(stepi)
    stepi.set_defaults(handler=_stepi)

    # --- nexti ---
    nexti = subparsers.add_parser("nexti", help="Step over (instruction-level)")
    _common_io_options(nexti)
    _add_output_arg(nexti)
    nexti.set_defaults(handler=_nexti)

    # --- finish ---
    finish = subparsers.add_parser("finish", help="Run until current function returns")
    _common_io_options(finish)
    _add_timeout_arg(finish)
    _add_output_arg(finish)
    finish.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    finish.set_defaults(handler=_finish)

    # --- until ---
    until = subparsers.add_parser("until", help="Run until a location is reached")
    _common_io_options(until)
    _add_timeout_arg(until)
    _add_output_arg(until)
    until.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    until.add_argument("location", help="Location to run until (function, file:line, or address)")
    until.set_defaults(handler=_until)

    # --- jump ---
    jump = subparsers.add_parser("jump", help="Resume execution at a location (GDB jump)")
    _common_io_options(jump)
    _add_timeout_arg(jump)
    _add_output_arg(jump)
    jump.add_argument("--background", action="store_true", help="Return immediately while the inferior keeps running")
    jump.add_argument("location", help="Location to jump to (function, file:line, or *address)")
    jump.set_defaults(handler=_jump)

    # --- interrupt ---
    interrupt = subparsers.add_parser("interrupt", help="Interrupt the running inferior")
    _common_io_options(interrupt)
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
    brk_set.add_argument("--ignore", type=int, metavar="N", help="Skip the next N hits before stopping")
    brk_set.add_argument("--rebase", metavar="MODULE", help="Treat location as offset from MODULE's load base (PIE/ASLR rebasing)")
    brk_set.add_argument("--image-base", type=lambda x: int(x, 0), default=0, metavar="ADDR",
                          help="Static image base to subtract (default: 0x0)")
    brk_set.set_defaults(handler=_break_set)

    brk_list = brk_sub.add_parser("list", help="List breakpoints")
    _common_io_options(brk_list)
    brk_list.set_defaults(handler=_break_list)

    brk_delete = brk_sub.add_parser("delete", help="Delete one or more breakpoints")
    _common_io_options(brk_delete)
    brk_delete.add_argument("number", type=int, nargs="+", help="Breakpoint number(s)")
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

    watch_delete = watch_sub.add_parser("delete", help="Delete one or more watchpoints")
    _common_io_options(watch_delete)
    watch_delete.add_argument("number", type=int, nargs="+", help="Watchpoint number(s)")
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
    _add_thread_arg(bt)
    bt.add_argument("--full", action="store_true", help="Show local variables in each frame")
    bt.add_argument("--limit", type=_positive_int, help="Maximum number of frames")
    bt.set_defaults(handler=_backtrace)

    # --- frame ---
    frame = subparsers.add_parser("frame", help="Stack frame inspection")
    frame_sub = frame.add_subparsers(dest="frame_command")
    frame_sel = frame_sub.add_parser("select", help="Select a stack frame")
    _common_io_options(frame_sel)
    _add_thread_arg(frame_sel)
    frame_sel.add_argument("level", type=int, help="Frame level (0 = innermost)")
    frame_sel.set_defaults(handler=_frame_select)
    frame_inf = frame_sub.add_parser("info", help="Show current frame info")
    _common_io_options(frame_inf)
    _add_thread_arg(frame_inf)
    frame_inf.set_defaults(handler=_frame_info)
    frame_up = frame_sub.add_parser("up", help="Move up the stack toward callers")
    _common_io_options(frame_up)
    _add_thread_arg(frame_up)
    frame_up.add_argument("count", nargs="?", type=int, help="Number of frames (default 1)")
    frame_up.set_defaults(handler=_frame_up)
    frame_down = frame_sub.add_parser("down", help="Move down the stack toward callees")
    _common_io_options(frame_down)
    _add_thread_arg(frame_down)
    frame_down.add_argument("count", nargs="?", type=int, help="Number of frames (default 1)")
    frame_down.set_defaults(handler=_frame_down)

    # --- locals ---
    locals_cmd = subparsers.add_parser("locals", help="Show local variables")
    _common_io_options(locals_cmd)
    _add_thread_arg(locals_cmd)
    locals_cmd.set_defaults(handler=_locals)

    # --- args ---
    args_cmd = subparsers.add_parser("args", help="Show function arguments")
    _common_io_options(args_cmd)
    _add_thread_arg(args_cmd)
    args_cmd.set_defaults(handler=_args)

    # --- print ---
    print_cmd = subparsers.add_parser("print", help="Evaluate an expression")
    _common_io_options(print_cmd)
    _add_thread_arg(print_cmd)
    print_cmd.add_argument("expression", help="Expression to evaluate")
    print_cmd.add_argument("--fmt", dest="p_format", metavar="F",
                           choices=("x", "d", "u", "o", "t", "a", "c", "f", "s", "z"),
                           help="GDB print format letter (x,d,u,o,t,a,c,f,s,z), like print/F")
    print_cmd.set_defaults(handler=_print_expr)

    # --- call ---
    call_cmd = subparsers.add_parser("call", help="Call an inferior function and return its value")
    _common_io_options(call_cmd)
    _add_thread_arg(call_cmd)
    call_cmd.add_argument("expression", help="Call expression, e.g. 'func(1, \"x\")'")
    call_cmd.set_defaults(handler=_call_fn)

    # --- registers ---
    regs = subparsers.add_parser("registers", help="Show or write register values")
    _common_io_options(regs)
    _add_thread_arg(regs)
    regs.add_argument("--all", action="store_true", help="Show all registers including floating-point")
    regs.set_defaults(handler=_registers)
    regs_sub = regs.add_subparsers(dest="registers_command")
    regs_write = regs_sub.add_parser("write", help="Write a register value (e.g. registers write rip 0x401234)")
    _common_io_options(regs_write)
    regs_write.add_argument("name", help="Register name (rip, rax, pc, ...; leading $ optional)")
    regs_write.add_argument("value", help="Value to set (hex, decimal, or a GDB expression)")
    regs_write.set_defaults(handler=_register_write)

    # --- memory ---
    mem = subparsers.add_parser("memory", help="Memory read/write")
    mem_sub = mem.add_subparsers(dest="memory_command")
    mem_read = mem_sub.add_parser("read", help="Read memory")
    _common_io_options(mem_read)
    _add_thread_arg(mem_read)
    mem_read.add_argument("address", help="Start address (hex or expression)")
    mem_read.add_argument("length", type=int, help="Number of bytes to read")
    mem_read.add_argument("--display", dest="mem_format",
                          choices=("hex", "bytes", "string", "pretty"), default="hex",
                          help="Memory display format (pretty = xxd-style hex+ASCII)")
    mem_read.add_argument("--plain", action="store_true",
                          help="In text mode, print only the memory data payload")
    mem_read.set_defaults(handler=_memory_read)

    mem_write = mem_sub.add_parser("write", help="Write memory")
    _common_io_options(mem_write)
    mem_write.add_argument("address", help="Start address (hex or expression)")
    mem_write.add_argument("value", help="Value to write (hex string)")
    mem_write.set_defaults(handler=_memory_write)

    # --- mappings ---
    mappings = subparsers.add_parser("mappings", help="List process memory mappings (structured vmmap)")
    _common_io_options(mappings)
    mappings.add_argument("--contains", metavar="ADDR", help="Only the mapping containing this address (hex or expression)")
    mappings.add_argument("--name", help="Filter mappings whose objfile contains this substring")
    mappings.set_defaults(handler=_mappings)

    # --- disasm ---
    disasm = subparsers.add_parser("disasm", help="Disassemble instructions")
    _common_io_options(disasm)
    _add_thread_arg(disasm)
    disasm.add_argument("location", nargs="?", help="Function name, address, or omit for current PC")
    disasm.add_argument("--count", type=_positive_int, help="Number of instructions")
    disasm.add_argument("--start", help="Range start address (use with --end)")
    disasm.add_argument("--end", help="Range end address (exclusive; use with --start)")
    disasm.add_argument("--source", action="store_true", help="Interleave source lines (GDB /s)")
    disasm.set_defaults(handler=_disasm)

    # --- examine ---
    examine = subparsers.add_parser("examine", help="Examine memory GDB-style (x/NFU)")
    _common_io_options(examine)
    _add_thread_arg(examine)
    examine.add_argument("address", help="Address or expression to examine")
    examine.add_argument("--spec", help="Raw GDB format spec, e.g. '8xw', '3i', 's'")
    examine.add_argument("--count", type=_positive_int, help="Number of units")
    examine.add_argument("--fmt", dest="x_format", metavar="F",
                         choices=("x", "d", "u", "o", "t", "a", "c", "f", "s", "i", "z"),
                         help="GDB format letter (x,d,u,o,t,a,c,f,s,i,z)")
    examine.add_argument("--size", choices=("b", "h", "w", "g"), help="Unit size")
    examine.set_defaults(handler=_examine)

    # --- functions ---
    funcs = subparsers.add_parser("functions", help="List or search functions")
    _common_io_options(funcs)
    _add_paged_args(funcs)
    funcs.add_argument("--query", help="Search pattern (matches function names/signatures)")
    funcs.set_defaults(handler=_functions)

    # --- symbols ---
    syms = subparsers.add_parser("symbols", help="List or search symbols")
    _common_io_options(syms)
    _add_paged_args(syms)
    syms.add_argument("--query", help="Search pattern (data/variable symbols only — use `functions --query` for functions)")
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
    source_list.add_argument("--count", type=_positive_int, help="Number of lines")
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
    trace_cmd.add_argument("--watch-size", type=_positive_int, default=4, metavar="N",
                           help="Number of bytes to watch (default: 4)")
    trace_cmd.add_argument("--range", required=True, metavar="START-END",
                           help="Code range that gates recording (e.g., 0x404610-0x405e30): "
                                "the watch is active only while the PC is in [START, END). START "
                                "must lie on the execution path (e.g. inside the loop body) — or "
                                "the inferior must already be stopped inside the range — or nothing "
                                "is recorded (the result reports armed=false)")
    trace_cmd.add_argument("--type", choices=("write", "read", "access"), default="access",
                           dest="watch_type", help="Watch type (default: access)")
    trace_cmd.add_argument("--max-hits", type=_positive_int, default=10000, metavar="N",
                           help="Stop after recording this many hits (default: 10000). Hits "
                                "accumulate across repeated passes through the range")
    trace_cmd.set_defaults(handler=_trace)

    return parser


def _emit_error(args: argparse.Namespace, message: str) -> None:
    fmt = getattr(args, "format", "text")
    if fmt in ("json", "ndjson"):
        payload = json.dumps({"ok": False, "error": message}, sort_keys=True)
        print(payload, file=sys.stderr)
        return
    # Avoid double-prefixing when the underlying bridge or GDB already emitted
    # its own "error:"/"ErrorType:" lead-in.
    text = message if ":" in message.split(None, 1)[0] else f"error: {message}"
    print(text, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(argv)
    # argparse strips the first `--` separator, so by parse time we can no
    # longer tell `launch ./bin --format json` (a misplaced pry flag) from
    # `launch ./bin -- --format json` (a genuine GDB arg). Stash the raw argv
    # so _launch can check whether a `--` was actually given.
    args._raw_argv = raw_argv
    # Reconcile the two --instance positions: subcommand-level value wins when
    # set; otherwise fall back to the global one.
    if getattr(args, "instance", None) is None:
        global_instance = getattr(args, "instance_global", None)
        if global_instance is not None:
            args.instance = global_instance
    handler: Callable[[argparse.Namespace], int] | None = getattr(args, "handler", None)
    if handler is None:
        selected_parser = getattr(args, "_parser", parser)
        selected_parser.print_help()
        return 0

    try:
        rc = handler(args)
    except BridgeError as exc:
        _emit_error(args, str(exc))
        return 1
    except Exception as exc:
        # Backstop: a handler raised something other than BridgeError (e.g. an
        # OSError from file IO, a ValueError from parsing). An agent-facing CLI
        # must never dump a raw Python traceback — render it cleanly instead.
        _emit_error(args, f"{type(exc).__name__}: {exc}")
        return 1
    return rc if isinstance(rc, int) else 0
