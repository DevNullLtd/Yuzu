#!/usr/bin/env python3
"""Behavioural check of the MCP stdio-to-HTTP adapter (scripts/mcp-http-adapter.js).

The adapter is run for real under node against a stdlib HTTP stub bound to 127.0.0.1 on an
ephemeral port. Each case pipes one or more JSON-RPC lines to its stdin, closes stdin at once
(no trailing sleep), and checks what reaches stdout and stderr.

Rules under test:
  - a tiered-token request is forwarded with `Authorization: Bearer <token>` and no Cookie
    header, and a normal reply reaches stdout unchanged with nothing on stderr;
  - the server's refusal for a credential without an MCP tier is HTTP 403 with a JSON-RPC
    error whose id is null: the reply on stdout is re-addressed to the request's id with every
    other field kept, and stderr gets ONE line carrying the status, error code and remediation
    and never the token;
  - a notification (no id) refused with a 403 gets nothing on stdout;
  - an HTTP error whose body is not a JSON-RPC error (non-JSON 500, a JSON 429 without
    jsonrpc/error) is answered on stdout with a synthesized -32000 error carrying the request
    id, and stderr reports the body by size only, never echoing it;
  - control characters in a server message or remediation never reach stderr, which stays one
    line;
  - a stdin line that parses to `null` does not crash the adapter and does not stop the lines
    after it;
  - closing stdin does not drop a request still in flight (a slow stub proves the adapter
    waits), and a final line with no trailing newline is still processed.

Skips (77) when `node` is not on PATH. Stdlib only; no fixed ports.
"""
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

# YUZU_MCP_ADAPTER_JS may point at a mutated copy of the script (mutation checks).
ADAPTER = pathlib.Path(os.environ.get(
    "YUZU_MCP_ADAPTER_JS",
    str(pathlib.Path(__file__).resolve().parents[1] / "scripts/mcp-http-adapter.js")))
TOKEN = "yzt_SECRET_TOKEN_0123456789abcdef"

PING = {"jsonrpc": "2.0", "id": 7, "method": "ping"}
REFUSAL = {
    "jsonrpc": "2.0",
    "id": None,
    "error": {
        "code": -32003,
        "message": "/mcp/v1/ requires an MCP-tier bearer token",
        "data": {
            "correlation_id": "cid-1",
            "retry_after_ms": None,
            "remediation": "mint an API token with mcp_tier readonly, then send it as "
                           "Authorization: Bearer; do not send a session cookie with it",
        },
    },
}


class Stub:
    """A one-purpose HTTP server: replies (status, body bytes, delay s) from `plan`."""

    def __init__(self):
        self.seen = []
        self.plan = (200, b"{}", 0.0)
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the test output clean
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                stub.seen.append({"path": self.path, "headers": dict(self.headers.items()),
                                  "body": self.rfile.read(n)})
                status, body, delay = stub.plan
                if delay:
                    time.sleep(delay)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d/mcp/v1/" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def reply(self, status, body, delay=0.0):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.plan = (status, body, delay)
        self.seen.clear()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def lines(obj_list):
    return "".join(json.dumps(o) + "\n" for o in obj_list)


def run_adapter(node, stub, stdin_text):
    p = subprocess.run(
        [node, str(ADAPTER)], input=stdin_text, capture_output=True, text=True, timeout=20,
        env={"PATH": "/usr/bin:/bin", "YUZU_MCP_URL": stub.url, "YUZU_MCP_TOKEN": TOKEN})
    return p


def out_objs(p):
    return [json.loads(x) for x in p.stdout.splitlines() if x.strip()]


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("SKIP: node is not on PATH")
        return 77

    stub = Stub()
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def check_request(label, n=1):
        check(len(stub.seen) == n, "%s: stub saw %d requests, want %d" % (label, len(stub.seen), n))
        for s in stub.seen:
            h = {k.lower(): v for k, v in s["headers"].items()}
            check(h.get("authorization") == "Bearer " + TOKEN, label + ": Authorization header")
            check("cookie" not in h, label + ": no Cookie header is sent")
            check(s["path"] == "/mcp/v1/", label + ": path " + s["path"])

    def check_no_token(p, label):
        check(TOKEN not in p.stdout and TOKEN not in p.stderr, label + ": the token is never printed")

    try:
        # 1. a normal reply is passed through untouched and silently.
        ok = {"jsonrpc": "2.0", "id": 7, "result": {}}
        stub.reply(200, ok)
        p = run_adapter(node, stub, lines([PING]))
        check(p.returncode == 0, "ok: exit status %r" % p.returncode)
        check(out_objs(p) == [ok], "ok: stdout %r" % p.stdout)
        check(p.stderr == "", "ok: stderr is empty, got %r" % p.stderr)
        check_request("ok")
        check_no_token(p, "ok")

        # 2. the tier refusal (HTTP 403, id null) is re-addressed to the request id.
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub, lines([PING]))
        want = dict(REFUSAL, id=7)
        check(out_objs(p) == [want], "403: stdout %r" % p.stdout)
        errs = p.stderr.splitlines()
        check(len(errs) == 1, "403: stderr is one line, got %r" % p.stderr)
        line = errs[0] if errs else ""
        check("HTTP 403" in line and "-32003" in line and "remediation" in line
              and "do not send a session cookie" in line and "ping" in line,
              "403: stderr line lacks status/code/remediation/method: %r" % line)
        check_request("403")
        check_no_token(p, "403")

        # 3. a notification refused with a 403 gets nothing on stdout.
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub, lines([{"jsonrpc": "2.0", "method": "notifications/initialized"}]))
        check(p.stdout == "", "notification: stdout %r" % p.stdout)
        check(len(p.stderr.splitlines()) == 1 and "HTTP 403" in p.stderr,
              "notification: stderr %r" % p.stderr)
        check_request("notification")

        # 4. a non-JSON 500 is answered with a synthesized error; the body is not echoed.
        marker = "SECRET-BODY-MARKER"
        stub.reply(500, ("<html>%s</html>" % marker).encode())
        p = run_adapter(node, stub, lines([dict(PING, id=9)]))
        check(out_objs(p) == [{"jsonrpc": "2.0", "id": 9,
                               "error": {"code": -32000, "message": "HTTP 500 from MCP server",
                                         "data": {"http_status": 500}}}],
              "500: stdout %r" % p.stdout)
        check("non-JSON body (%d bytes)" % len(("<html>%s</html>" % marker)) in p.stderr
              and marker not in p.stderr and len(p.stderr.splitlines()) == 1,
              "500: stderr %r" % p.stderr)
        check_request("500")

        # 5. a JSON 429 that is not a JSON-RPC error is answered the same way.
        stub.reply(429, {"error": "rate_limited"})
        p = run_adapter(node, stub, lines([dict(PING, id="req-a")]))
        check(out_objs(p) == [{"jsonrpc": "2.0", "id": "req-a",
                               "error": {"code": -32000, "message": "HTTP 429 from MCP server",
                                         "data": {"http_status": 429}}}],
              "429: stdout %r" % p.stdout)
        check("rate_limited" not in p.stderr and "HTTP 429" in p.stderr
              and "non-JSON-RPC body" in p.stderr and len(p.stderr.splitlines()) == 1,
              "429: stderr %r" % p.stderr)
        check_request("429")

        # 6. control characters in the server's text never reach stderr.
        nasty = json.loads(json.dumps(REFUSAL))
        nasty["error"]["message"] = "bad\x1b[31mred\nFAKE LOG LINE\r"
        nasty["error"]["data"]["remediation"] = "fix\x00it\x7f\nFAKE2"
        stub.reply(403, nasty)
        p = run_adapter(node, stub, lines([PING]))
        bad = [c for c in p.stderr[:-1] if ord(c) < 0x20 or ord(c) == 0x7F]
        check(not bad and p.stderr.endswith("\n") and len(p.stderr.splitlines()) == 1,
              "control chars: stderr %r" % p.stderr)
        check("bad[31mredFAKE LOG LINE" in p.stderr and "fixitFAKE2" in p.stderr,
              "control chars: text kept, controls stripped: %r" % p.stderr)

        # 7. a `null` line does not crash the adapter or stop the lines after it.
        stub.reply(200, ok)
        p = run_adapter(node, stub, "null\n" + lines([PING]))
        check(p.returncode == 0 and "Traceback" not in p.stderr and "TypeError" not in p.stderr,
              "null line: exit %r stderr %r" % (p.returncode, p.stderr))
        check(ok in out_objs(p), "null line: the next request is still answered: %r" % p.stdout)
        check(len(stub.seen) == 2, "null line: stub saw %d requests, want 2" % len(stub.seen))
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub, "null\n")
        check(p.returncode == 0 and "TypeError" not in p.stderr,
              "null line refused: exit %r stderr %r" % (p.returncode, p.stderr))

        # 8. closing stdin does not drop a request in flight (the stub answers late).
        stub.reply(200, ok, delay=0.5)
        p = run_adapter(node, stub, lines([PING]))
        check(out_objs(p) == [ok], "in flight: stdout %r" % p.stdout)

        # 9. a final line with no trailing newline is processed.
        stub.reply(200, ok)
        p = run_adapter(node, stub, json.dumps(PING))
        check(out_objs(p) == [ok], "no trailing newline: stdout %r" % p.stdout)
    finally:
        stub.close()

    if fails:
        print("FAIL\n" + "\n".join(fails))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
