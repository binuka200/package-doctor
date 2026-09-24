"""Coding-agent hook protocols.

The guard decides; this module only translates. Every agent hands a hook the
tool call it is about to make, or has just made, in its own JSON, and reads
the answer back in its own shape. A protocol turns the call into a
`HookEvent` the guard understands, and the guard's `HookResult` into the exit
code and output that agent acts on.

Nothing here looks anything up or decides anything, so adding an agent cannot
change what is blocked: only whether the agent hears about it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

#: What the agent is doing, in the guard's terms rather than the agent's.
#:
#: - `install`: a shell command is about to run; it may install something.
#: - `resolve`: a shell command has run; it may have written a lockfile.
#: - `edit`: a file has been written; it may be a dependency file.
Kind = Literal["install", "resolve", "edit"]


@dataclass(frozen=True)
class HookEvent:
    kind: Kind
    command: str = ""
    #: The files an `edit` wrote. One tool call can write several.
    paths: tuple[Path, ...] = ()
    cwd: Path | None = None
    session: str = ""


@dataclass(frozen=True)
class HookResult:
    """The guard's answer, before any agent's formatting.

    `block` refuses the call and is written for the model, which has to act
    on it. `context` is for the model too, but lets the call through.
    `notice` is for the person watching and never reaches the model.
    """

    block: str = ""
    context: str = ""
    notice: str = ""


SILENT = HookResult()


@dataclass(frozen=True)
class Reply:
    code: int
    stdout: str = ""
    stderr: str = ""


class AgentProtocol(Protocol):
    def parse(self, payload: dict) -> HookEvent | None:
        """The event this tool call is, or None when it is nothing to check."""

    def render(self, event: HookEvent, result: HookResult) -> Reply:
        """The guard's answer, in the shape this agent reads."""


def _path(value: object) -> Path | None:
    return Path(value).expanduser() if isinstance(value, str) and value else None


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


class ClaudeCode:
    """https://docs.claude.com/en/docs/claude-code/hooks

    Registered for `PreToolUse` on Bash, and `PostToolUse` on Bash and the
    file-writing tools. Exit 2 blocks the call and hands stderr to the model;
    `additionalContext` reaches the model without deciding anything, and
    `systemMessage` reaches only the user. A `permissionDecision` is never
    sent: the hook must not widen what the agent was already allowed to run.
    """

    _EDIT_TOOLS = ("Edit", "Write", "MultiEdit")

    def parse(self, payload: dict) -> HookEvent | None:
        tool = payload.get("tool_name")
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            return None
        cwd = _path(payload.get("cwd"))
        session = _text(payload.get("session_id"))
        if tool in self._EDIT_TOOLS:
            path = _path(tool_input.get("file_path"))
            if path is None:
                return None
            return HookEvent("edit", paths=(path,), cwd=cwd, session=session)
        if tool != "Bash":
            return None
        command = tool_input.get("command")
        if not isinstance(command, str):
            return None
        # After the command has run there is nothing left to block; what it
        # added can only be found in the lockfile.
        kind: Kind = "resolve" if payload.get("hook_event_name") == "PostToolUse" else "install"
        return HookEvent(kind, command=command, cwd=cwd, session=session)

    def render(self, event: HookEvent, result: HookResult) -> Reply:
        if result.block:
            return Reply(2, stderr=result.block)
        if result.context:
            payload = {
                "systemMessage": result.context,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse" if event.kind == "install" else "PostToolUse",
                    "additionalContext": result.context,
                },
            }
            return Reply(0, stdout=json.dumps(payload) + "\n")
        if result.notice:
            return Reply(0, stdout=json.dumps({"systemMessage": result.notice}) + "\n")
        return Reply(0)


class GeminiCli:
    """https://geminicli.com/docs/hooks/reference/

    Registered for `BeforeTool` on `run_shell_command`, and `AfterTool` on
    that and the file-writing tools. A `deny` decision's `reason` goes to
    the model as the tool's error, which is what lets it pick another
    package. `additionalContext` exists only after a tool has run, so a
    warning before an install can reach only the user, as `systemMessage`.
    `allow` is never sent, for the same reason as in Claude Code.
    """

    _SHELL = "run_shell_command"
    _EDIT_TOOLS = ("write_file", "replace")

    def parse(self, payload: dict) -> HookEvent | None:
        tool = payload.get("tool_name")
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            return None
        when = payload.get("hook_event_name")
        cwd = _path(payload.get("cwd"))
        session = _text(payload.get("session_id"))
        if tool in self._EDIT_TOOLS:
            # Before the write there is nothing on disk to compare against.
            path = _path(tool_input.get("file_path"))
            if when != "AfterTool" or path is None:
                return None
            return HookEvent("edit", paths=(_under(cwd, path),), cwd=cwd, session=session)
        if tool != self._SHELL:
            return None
        command = tool_input.get("command")
        if not isinstance(command, str):
            return None
        # `dir_path` is where the command runs, and so where its lockfile is.
        where = _path(tool_input.get("dir_path"))
        if where is not None:
            cwd = _under(cwd, where)
        kinds: dict[object, Kind] = {"BeforeTool": "install", "AfterTool": "resolve"}
        kind = kinds.get(when)
        if kind is None:
            return None
        return HookEvent(kind, command=command, cwd=cwd, session=session)

    def render(self, event: HookEvent, result: HookResult) -> Reply:
        if result.block and event.kind == "install":
            reply = {"decision": "deny", "reason": result.block}
            return Reply(0, stdout=json.dumps(reply) + "\n")
        # After a tool has run, `deny` would hide its result rather than stop
        # it, so anything the guard says there is context.
        context = result.context or result.block
        if context and event.kind != "install":
            reply = {
                "systemMessage": context,
                "hookSpecificOutput": {"hookEventName": "AfterTool", "additionalContext": context},
            }
            return Reply(0, stdout=json.dumps(reply) + "\n")
        message = context or result.notice
        if message:
            return Reply(0, stdout=json.dumps({"systemMessage": message}) + "\n")
        return Reply(0)


class Codex:
    """https://learn.chatgpt.com/docs/hooks

    Registered for `PreToolUse` on Bash, and `PostToolUse` on Bash and
    `apply_patch`. A `deny` reaches the model as the tool call's error
    ("Command blocked by PreToolUse hook: ..."), and `additionalContext` as
    developer context, before or after a tool. Codex rejects `allow` unless
    the hook rewrites the command, so there is no permission to widen; none
    is sent. After a tool, `decision: block` would replace the tool's output
    rather than stop anything, so it is never sent either.

    Codex hands a hook no working directory for a command, only the
    session's `cwd`, and edits arrive as the patch text rather than a path.
    """

    def parse(self, payload: dict) -> HookEvent | None:
        tool = payload.get("tool_name")
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            return None
        command = tool_input.get("command")
        if not isinstance(command, str):
            return None
        when = payload.get("hook_event_name")
        cwd = _path(payload.get("cwd"))
        session = _text(payload.get("session_id"))
        if tool == "apply_patch":
            # Before the patch is applied there is nothing on disk to compare.
            paths = tuple(_under(cwd, Path(name)) for name in patched_files(command))
            if when != "PostToolUse" or not paths:
                return None
            return HookEvent("edit", paths=paths, cwd=cwd, session=session)
        if tool != "Bash":
            return None
        kinds: dict[object, Kind] = {"PreToolUse": "install", "PostToolUse": "resolve"}
        kind = kinds.get(when)
        if kind is None:
            return None
        return HookEvent(kind, command=command, cwd=cwd, session=session)

    def render(self, event: HookEvent, result: HookResult) -> Reply:
        name = "PreToolUse" if event.kind == "install" else "PostToolUse"
        if result.block and event.kind == "install":
            # Codex appends ". Command: <the command>" to the reason.
            reason = result.block.rstrip().rstrip(".")
            reply = {"hookSpecificOutput": {
                "hookEventName": name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }}
            return Reply(0, stdout=json.dumps(reply) + "\n")
        context = result.context or result.block
        if context:
            reply = {
                "systemMessage": context,
                "hookSpecificOutput": {"hookEventName": name, "additionalContext": context},
            }
            return Reply(0, stdout=json.dumps(reply) + "\n")
        if result.notice:
            return Reply(0, stdout=json.dumps({"systemMessage": result.notice}) + "\n")
        return Reply(0)


_PATCH_HEADER = re.compile(r"^\*\*\* (Add File|Update File|Delete File|Move to): (.+?)\s*$")


def patched_files(patch: str) -> list[str]:
    """The files an `apply_patch` patch leaves behind, in the order it names them.

    A deleted file has nothing left to check, and a moved file is checked
    where it went, not where it was.
    """
    files: list[str] = []
    updating: str | None = None
    for line in patch.splitlines():
        match = _PATCH_HEADER.match(line)
        if match is None:
            continue
        action, name = match.groups()
        if action == "Move to" and updating in files:
            files.remove(updating)
        updating = name if action == "Update File" else None
        if action != "Delete File" and name not in files:
            files.append(name)
    return files


def _under(root: Path | None, path: Path) -> Path:
    """`path` as the agent meant it: relative paths are from its workspace."""
    return root / path if root is not None else path


#: Every agent `package-doctor hook` speaks to, by the name given on the
#: command line.
PROTOCOLS: dict[str, AgentProtocol] = {
    "claude-code": ClaudeCode(),
    "gemini": GeminiCli(),
    "codex": Codex(),
}
