#!/usr/bin/env python3
"""Cedar & Vale "Agentic Colleague" demo client.

Connects Claude Haiku to Yuzu's embedded MCP server and runs an interactive
tool-use loop. Haiku's ONLY tools are the ones Yuzu exposes via MCP tools/list
(minus execute_instruction) — it has no shell, no internet, no other powers, so
"constrained to what Yuzu can do" is enforced at the tool layer, not just by the
system prompt.

Usage:
    python agent.py                      # interactive REPL
    python agent.py --once "question"    # single question, then exit
    python agent.py --list-tools         # print the Yuzu MCP tools (no Claude call, no cost)

Credentials (read from files, never hardcoded):
    Anthropic API key : $ANTHROPIC_API_KEY, else ~/.config/anthropic/key
    Yuzu MCP token    : $YUZU_MCP_TOKEN,    else ~/.config/anthropic/mcp-token
                        (an API token minted with an mcp_tier: readonly, operator or
                        supervised; /mcp/v1/ refuses a token without one)

The MCP endpoint defaults to the local viz-UAT server; override with --mcp-url
or $YUZU_MCP_URL.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import anthropic
import httpx

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_MCP_URL = "http://localhost:8080/mcp/v1/"
MAX_TOKENS = 4096
MAX_TOOL_ROUNDS = 12  # tool round-trips per operator turn, before we bail
# execute_instruction is the one write tool; we never expose it in this demo
# (the readonly MCP tier would reject it anyway — this is belt and suspenders).
EXCLUDED_TOOLS = {"execute_instruction"}

SCRIPT_DIR = Path(__file__).resolve().parent


def _read_secret(env_name: str, path: Path, label: str) -> str:
    import os
    val = os.environ.get(env_name)
    if val and val.strip():
        return val.strip()
    if path.exists():
        text = path.read_text().strip()
        if text:
            return text
    sys.exit(f"error: no {label} — set ${env_name} or write it to {path}")


def _dim(s: str) -> str:
    return f"\033[2m{s}\033[0m" if sys.stdout.isatty() else s


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m" if sys.stdout.isatty() else s


class YuzuMCP:
    """Minimal JSON-RPC 2.0 client for Yuzu's MCP endpoint (POST /mcp/v1/)."""

    def __init__(self, url: str, token: str):
        self.url = url
        self._headers = {"Content-Type": "application/json", "X-Yuzu-Token": token}
        self._id = 0
        self._http = httpx.Client(timeout=30.0)

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        payload: dict = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            payload["params"] = params
        resp = self._http.post(self.url, json=payload, headers=self._headers)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"MCP error on {method}: {data['error']}")
        return data.get("result", {})

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> tuple[str, bool]:
        """Returns (text, is_error). Renders the MCP content array to text."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        is_error = bool(result.get("isError", False))
        content = result.get("content")
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
                else:
                    parts.append(json.dumps(c))
            text = "\n".join(p for p in parts if p) or json.dumps(result)
        else:
            text = json.dumps(result)
        return text, is_error


def build_tools(mcp_tools: list[dict]) -> list[dict]:
    """MCP tool schemas -> Anthropic tool schemas, excluding the write tool.

    cache_control on the last tool caches the whole (stable) tool list; the
    system block adds the second breakpoint (tools render before system, so a
    system breakpoint caches tools+system together — both are stable here)."""
    tools: list[dict] = []
    for t in mcp_tools:
        if t["name"] in EXCLUDED_TOOLS:
            continue
        tools.append({
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t.get("inputSchema") or {"type": "object", "properties": {}},
        })
    if tools:
        tools[-1] = {**tools[-1], "cache_control": {"type": "ephemeral"}}
    return tools


def run_turn(client: anthropic.Anthropic, model: str, system: list, tools: list,
             mcp: YuzuMCP, messages: list) -> None:
    """Drive one operator turn to completion: model -> tools -> model -> ..."""
    for _ in range(MAX_TOOL_ROUNDS):
        resp = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system,
            tools=tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})

        for block in resp.content:
            if block.type == "text" and block.text.strip():
                print(block.text.strip())

        if resp.stop_reason != "tool_use":
            return

        tool_results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            args = json.dumps(block.input)
            print(_dim(f"  [yuzu] {block.name} {args[:140]}"))
            try:
                text, is_error = mcp.call_tool(block.name, dict(block.input))
            except Exception as e:  # surface tool failures to the model, don't crash
                text, is_error = f"tool call failed: {e}", True
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": text,
                "is_error": is_error,
            })
        messages.append({"role": "user", "content": tool_results})

    print(_dim("  (stopped: reached the tool-round limit for this turn)"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Cedar & Vale agentic-colleague demo client")
    ap.add_argument("--mcp-url", default=None, help="Yuzu MCP endpoint (default: $YUZU_MCP_URL or localhost)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model (default: {DEFAULT_MODEL})")
    ap.add_argument("--once", metavar="QUESTION", help="ask one question, print the answer, exit")
    ap.add_argument("--list-tools", action="store_true", help="print the Yuzu MCP tools and exit (no Claude call)")
    args = ap.parse_args()

    import os
    mcp_url = args.mcp_url or os.environ.get("YUZU_MCP_URL") or DEFAULT_MCP_URL
    home = Path.home()
    token = _read_secret("YUZU_MCP_TOKEN", home / ".config/anthropic/mcp-token", "Yuzu MCP token")
    mcp = YuzuMCP(mcp_url, token)

    try:
        mcp_tools = mcp.list_tools()
    except Exception as e:
        sys.exit(f"error: could not reach Yuzu MCP at {mcp_url}: {e}")

    if args.list_tools:
        usable = [t for t in mcp_tools if t["name"] not in EXCLUDED_TOOLS]
        print(_bold(f"Yuzu MCP tools at {mcp_url} ({len(usable)} usable, "
                    f"{len(mcp_tools) - len(usable)} excluded):"))
        for t in mcp_tools:
            mark = "  excluded" if t["name"] in EXCLUDED_TOOLS else ""
            desc = (t.get("description") or "").strip().splitlines()[0:1]
            print(f"  {t['name']:<26}{_dim(desc[0] if desc else '')}{_dim(mark)}")
        return

    tools = build_tools(mcp_tools)
    api_key = _read_secret("ANTHROPIC_API_KEY", home / ".config/anthropic/key", "Anthropic API key")
    client = anthropic.Anthropic(api_key=api_key)
    system_text = (SCRIPT_DIR / "system-prompt.md").read_text()
    system = [{"type": "text", "text": system_text, "cache_control": {"type": "ephemeral"}}]

    print(_bold("Cedar & Vale — Agentic Colleague (Yuzu)"))
    print(_dim(f"  model {args.model} | {len(tools)} read-only Yuzu tools | MCP {mcp_url}"))

    def ask(question: str) -> None:
        messages = [{"role": "user", "content": question}]
        try:
            run_turn(client, args.model, system, tools, mcp, messages)
        except anthropic.AuthenticationError:
            sys.exit("error: Anthropic API key rejected (invalid key or no credit).")
        except anthropic.APIStatusError as e:
            print(_dim(f"  (Anthropic API error {e.status_code}: {e.message})"))

    if args.once:
        ask(args.once)
        return

    print(_dim("  Type a question. Ctrl-D or 'exit' to quit.\n"))
    messages: list = []  # persists across the REPL so it's a real conversation
    while True:
        try:
            question = input(_bold("operator> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not question:
            continue
        if question.lower() in {"exit", "quit"}:
            break
        messages.append({"role": "user", "content": question})
        try:
            run_turn(client, args.model, system, tools, mcp, messages)
        except anthropic.AuthenticationError:
            sys.exit("error: Anthropic API key rejected (invalid key or no credit).")
        except anthropic.APIStatusError as e:
            print(_dim(f"  (Anthropic API error {e.status_code}: {e.message})"))
        print()


if __name__ == "__main__":
    main()
