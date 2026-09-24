"""Agent hook protocols: translation only.

Each protocol turns an agent's tool call into a `HookEvent` and the guard's
`HookResult` back into what that agent reads. What gets blocked is decided in
`cli` and tested in test_guard.py; what is pinned here is that every protocol
carries a block, a context and a notice to the right place, and that it
recognises nothing it should not.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from test_guard import finding, stub

from package_doctor import cli
from package_doctor.hooks import (
    PROTOCOLS,
    SILENT,
    ClaudeCode,
    Codex,
    GeminiCli,
    HookEvent,
    HookResult,
    patched_files,
)
from package_doctor.models import Verdict

INSTALL = HookEvent("install", command="pip install x")
RESOLVE = HookEvent("resolve", command="uv sync")
EDIT = HookEvent("edit", paths=(Path("pyproject.toml"),))


@pytest.mark.parametrize("name", sorted(PROTOCOLS))
def test_every_protocol_is_silent_when_the_guard_is(name):
    protocol = PROTOCOLS[name]
    for event in (INSTALL, RESOLVE, EDIT):
        reply = protocol.render(event, SILENT)
        assert (reply.code, reply.stdout, reply.stderr) == (0, "", "")


@pytest.mark.parametrize("name", sorted(PROTOCOLS))
def test_every_protocol_ignores_what_it_cannot_read(name):
    protocol = PROTOCOLS[name]
    for payload in ({}, {"tool_input": "nonsense"}, {"tool_name": 3}):
        assert protocol.parse(payload) is None


# --- Claude Code ------------------------------------------------------------

def claude(tool: str, tool_input: dict, event: str = "PreToolUse") -> dict:
    return {
        "session_id": "s", "cwd": "/work", "hook_event_name": event,
        "tool_name": tool, "tool_input": tool_input,
    }


def test_claude_code_reads_a_shell_command_before_and_after_it_runs():
    before = ClaudeCode().parse(claude("Bash", {"command": "uv add x"}))
    after = ClaudeCode().parse(claude("Bash", {"command": "uv add x"}, "PostToolUse"))
    assert before == HookEvent("install", command="uv add x", cwd=Path("/work"), session="s")
    assert after is not None and after.kind == "resolve"


@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit"])
def test_claude_code_reads_a_file_edit(tool):
    event = ClaudeCode().parse(claude(tool, {"file_path": "/work/pyproject.toml"}, "PostToolUse"))
    assert event == HookEvent(
        "edit", paths=(Path("/work/pyproject.toml"),), cwd=Path("/work"), session="s",
    )


def test_claude_code_ignores_other_tools_and_missing_fields():
    assert ClaudeCode().parse(claude("Read", {"file_path": "x"})) is None
    assert ClaudeCode().parse(claude("Bash", {})) is None
    assert ClaudeCode().parse(claude("Edit", {"file_path": ""})) is None


def test_claude_code_blocks_with_exit_2_and_the_reason_for_the_model():
    reply = ClaudeCode().render(INSTALL, HookResult(block="no\n"))
    assert (reply.code, reply.stdout, reply.stderr) == (2, "", "no\n")


def test_claude_code_puts_context_in_front_of_the_model_without_deciding():
    for event, name in ((INSTALL, "PreToolUse"), (RESOLVE, "PostToolUse"), (EDIT, "PostToolUse")):
        reply = ClaudeCode().render(event, HookResult(context="careful"))
        payload = json.loads(reply.stdout)
        assert reply.code == 0
        assert payload["hookSpecificOutput"] == {
            "hookEventName": name, "additionalContext": "careful",
        }
        assert "permissionDecision" not in payload["hookSpecificOutput"]


def test_claude_code_shows_a_notice_to_the_user_only():
    reply = ClaudeCode().render(INSTALL, HookResult(notice="unchecked"))
    assert json.loads(reply.stdout) == {"systemMessage": "unchecked"}


# --- Gemini CLI -------------------------------------------------------------

def gemini(tool: str, tool_input: dict, event: str = "BeforeTool") -> dict:
    return {
        "session_id": "s", "cwd": "/work", "hook_event_name": event,
        "timestamp": "2026-09-23T10:00:00Z", "tool_name": tool, "tool_input": tool_input,
    }


def test_gemini_reads_a_shell_command_before_and_after_it_runs():
    before = GeminiCli().parse(gemini("run_shell_command", {"command": "uv add x"}))
    after = GeminiCli().parse(gemini("run_shell_command", {"command": "uv sync"}, "AfterTool"))
    assert before == HookEvent("install", command="uv add x", cwd=Path("/work"), session="s")
    assert after == HookEvent("resolve", command="uv sync", cwd=Path("/work"), session="s")


def test_gemini_runs_the_command_where_dir_path_says():
    def run_in(where: str) -> HookEvent | None:
        tool_input = {"command": "uv sync", "dir_path": where}
        return GeminiCli().parse(gemini("run_shell_command", tool_input))

    relative, absolute = run_in("api"), run_in("/srv")
    assert relative is not None and relative.cwd == Path("/work/api")
    assert absolute is not None and absolute.cwd == Path("/srv")


@pytest.mark.parametrize("tool", ["write_file", "replace"])
def test_gemini_reads_a_file_edit_only_after_it_is_written(tool):
    after = GeminiCli().parse(gemini(tool, {"file_path": "pyproject.toml"}, "AfterTool"))
    assert after == HookEvent(
        "edit", paths=(Path("/work/pyproject.toml"),), cwd=Path("/work"), session="s",
    )
    assert GeminiCli().parse(gemini(tool, {"file_path": "pyproject.toml"})) is None


def test_gemini_ignores_other_tools_and_events():
    assert GeminiCli().parse(gemini("read_file", {"file_path": "x"}, "AfterTool")) is None
    assert GeminiCli().parse(gemini("run_shell_command", {"command": "ls"}, "BeforeModel")) is None
    assert GeminiCli().parse(gemini("run_shell_command", {})) is None


def test_gemini_denies_with_the_reason_for_the_model():
    reply = GeminiCli().render(INSTALL, HookResult(block="no"))
    assert reply.code == 0
    assert json.loads(reply.stdout) == {"decision": "deny", "reason": "no"}


def test_gemini_never_denies_after_a_tool_has_run():
    for event in (RESOLVE, EDIT):
        payload = json.loads(GeminiCli().render(event, HookResult(block="no")).stdout)
        assert "decision" not in payload
        assert payload["hookSpecificOutput"]["additionalContext"] == "no"


def test_gemini_puts_context_after_a_tool_in_front_of_the_model():
    for event in (RESOLVE, EDIT):
        payload = json.loads(GeminiCli().render(event, HookResult(context="careful")).stdout)
        assert payload["hookSpecificOutput"] == {
            "hookEventName": "AfterTool", "additionalContext": "careful",
        }


def test_gemini_warns_before_a_tool_to_the_user_without_deciding():
    # BeforeTool has no field that reaches the model without blocking.
    payload = json.loads(GeminiCli().render(INSTALL, HookResult(context="careful")).stdout)
    assert payload == {"systemMessage": "careful"}


def test_gemini_hook_blocks_an_install_end_to_end(monkeypatch, capsys):
    stub(monkeypatch, [finding("legacy-auth", Verdict.REPLACE, exposed=True,
                               reasons=["repository is archived"])])
    payload = gemini("run_shell_command", {"command": "pip install legacy-auth"})
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    code = cli.main(["hook", "gemini", "--no-cache"])
    out, err = capsys.readouterr()
    reply = json.loads(out)
    assert code == 0 and err == ""
    assert reply["decision"] == "deny"
    assert "legacy-auth" in reply["reason"] and "repository is archived" in reply["reason"]


# --- Codex ------------------------------------------------------------------

def codex(tool: str, command: str, event: str = "PreToolUse") -> dict:
    # The shape Codex's own hook tests assert on: `tool_input.command` for
    # both Bash and apply_patch, which carries the patch text.
    return {
        "session_id": "s", "transcript_path": None, "cwd": "/work", "hook_event_name": event,
        "model": "gpt-5", "turn_id": "t", "tool_name": tool, "tool_use_id": "call-1",
        "tool_input": {"command": command},
    }


PATCH = """*** Begin Patch
*** Add File: requirements.txt
+legacy-auth==2.1.0
*** Update File: pyproject.toml
@@
-dependencies = []
+dependencies = ["legacy-auth==2.1.0"]
*** Update File: old/setup.cfg
*** Move to: setup.cfg
@@
*** Delete File: Pipfile
*** End Patch"""


def test_patched_files_are_what_the_patch_leaves_behind():
    assert patched_files(PATCH) == ["requirements.txt", "pyproject.toml", "setup.cfg"]
    assert patched_files("not a patch") == []


def test_codex_reads_a_shell_command_before_and_after_it_runs():
    before = Codex().parse(codex("Bash", "uv add x"))
    after = Codex().parse(codex("Bash", "uv sync", "PostToolUse"))
    assert before == HookEvent("install", command="uv add x", cwd=Path("/work"), session="s")
    assert after == HookEvent("resolve", command="uv sync", cwd=Path("/work"), session="s")


def test_codex_reads_every_file_a_patch_wrote_once_it_is_applied():
    event = Codex().parse(codex("apply_patch", PATCH, "PostToolUse"))
    assert event is not None and event.kind == "edit"
    assert event.paths == (
        Path("/work/requirements.txt"), Path("/work/pyproject.toml"), Path("/work/setup.cfg"),
    )
    assert Codex().parse(codex("apply_patch", PATCH)) is None, "nothing on disk yet"


def test_codex_ignores_other_tools_and_events():
    assert Codex().parse(codex("mcp__fs__write", "x", "PostToolUse")) is None
    assert Codex().parse(codex("Bash", "ls", "SessionStart")) is None
    empty = "*** Begin Patch\n*** End Patch"
    assert Codex().parse(codex("apply_patch", empty, "PostToolUse")) is None


def test_codex_denies_with_the_reason_for_the_model():
    reply = Codex().render(INSTALL, HookResult(block="blocked legacy-auth. Try another.\n"))
    assert reply.code == 0 and reply.stderr == ""
    assert json.loads(reply.stdout) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        # Codex adds ". Command: ..." itself.
        "permissionDecisionReason": "blocked legacy-auth. Try another",
    }}


def test_codex_never_allows_and_never_blocks_after_a_tool():
    for event in (INSTALL, RESOLVE, EDIT):
        payload = json.loads(Codex().render(event, HookResult(context="careful")).stdout)
        assert "permissionDecision" not in payload["hookSpecificOutput"]
        assert "decision" not in payload
    for event in (RESOLVE, EDIT):
        payload = json.loads(Codex().render(event, HookResult(block="no")).stdout)
        assert "decision" not in payload and "permissionDecision" not in payload.get(
            "hookSpecificOutput", {})


def test_codex_puts_context_in_front_of_the_model_before_and_after():
    for event, name in ((INSTALL, "PreToolUse"), (RESOLVE, "PostToolUse"), (EDIT, "PostToolUse")):
        payload = json.loads(Codex().render(event, HookResult(context="careful")).stdout)
        assert payload["hookSpecificOutput"] == {
            "hookEventName": name, "additionalContext": "careful",
        }


def test_codex_hook_blocks_an_install_end_to_end(monkeypatch, capsys):
    stub(monkeypatch, [finding("legacy-auth", Verdict.REPLACE, exposed=True,
                               reasons=["repository is archived"])])
    payload = codex("Bash", "pip install legacy-auth")
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    code = cli.main(["hook", "codex", "--no-cache"])
    out, err = capsys.readouterr()
    output = json.loads(out)["hookSpecificOutput"]
    assert code == 0 and err == ""
    assert output["permissionDecision"] == "deny"
    assert "legacy-auth" in output["permissionDecisionReason"]


def test_codex_hook_checks_every_file_a_patch_touched(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("legacy-auth==2.1.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["legacy-auth==2.1.0", "six"]\n',
        encoding="utf-8",
    )
    stub(monkeypatch, [
        finding("legacy-auth", Verdict.REPLACE, exposed=True, reasons=["repository is archived"]),
        finding("six"),
    ])
    payload = codex("apply_patch", PATCH, "PostToolUse") | {"cwd": str(tmp_path)}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert cli.main(["hook", "codex", "--no-cache"]) == 0
    context = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]
    assert "requirements.txt, pyproject.toml" in context
    assert context.count("BLOCK legacy-auth") == 1, "a name added to two files is one finding"
