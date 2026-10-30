#!/usr/bin/env python3
"""Behavioural check of the MCP stdio-to-HTTP adapter (scripts/mcp-http-adapter.js).

The adapter is run for real under node against a stdlib HTTP stub bound to 127.0.0.1 (and, when
the host has IPv6 loopback, ::1) on an ephemeral port. Each case pipes JSON-RPC lines to its
stdin and closes stdin at once (no trailing sleep), then checks what reaches stdout and stderr.

Rules under test:
  - a request is forwarded byte for byte (an id above 2^53 and `1.0` round-trip) with
    `Authorization: Bearer <token>`, `Accept: application/json`, the URL's query string and no
    Cookie header, even when YUZU_MCP_COOKIE is set (which only earns one stderr warning); a
    normal reply reaches stdout unchanged with nothing on stderr;
  - the server's refusal for a credential without an MCP tier is HTTP 403 with a JSON-RPC error
    whose id is null: stdout carries it re-addressed to the request's id (0 and "" included,
    every other field kept) and stderr gets ONE line with the status, code and the WHOLE real
    remediation (the C++ constant, read from mcp_admission.hpp) and never the token;
  - a notification (no id) refused with an HTTP error gets nothing on stdout;
  - an HTTP error or redirect whose body is not a JSON-RPC error is answered with a synthesized
    -32000 error carrying the id; stderr reports the body by size only and never prints a
    Location header; an empty or non-JSON 2xx to a request is a -32603 that carries no raw server
    bytes, while an empty 2xx to a notification is silent;
  - control characters in a server message or remediation never reach stderr;
  - a stdin line that is `null`, a number or an array does not crash the adapter;
  - closing stdin does not drop a request in flight or queued, and a final line with no
    trailing newline is processed;
  - a server that never finishes (an SSE stream of keepalive comments) is cut off by the TOTAL
    per-request deadline with one -32603 carrying the id, and the process exits;
  - at most YUZU_MCP_MAX_INFLIGHT requests are on the wire at once, and all replies arrive;
  - an IPv6 literal URL works.

Skips (77) when `node` is not on PATH. Stdlib only; no fixed ports.
"""
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
# YUZU_MCP_ADAPTER_JS may point at a mutated copy of the script (mutation checks).
ADAPTER = pathlib.Path(os.environ.get("YUZU_MCP_ADAPTER_JS", str(ROOT / "scripts/mcp-http-adapter.js")))
ADMISSION_HPP = ROOT / "server/core/src/mcp_admission.hpp"
TOKEN = "yzt_SECRET_TOKEN_0123456789abcdef"

PING = {"jsonrpc": "2.0", "id": 7, "method": "ping"}


def real_remediation():
    """The kTierRequiredRemediation string: adjacent C++ string literals, concatenated."""
    text = ADMISSION_HPP.read_text(encoding="utf-8")
    # Only string literals and whitespace up to the terminating `;` (a `;` inside a literal is text).
    m = re.search(r'kTierRequiredRemediation\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*)+);', text)
    if not m:
        raise RuntimeError("kTierRequiredRemediation not found in mcp_admission.hpp")
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1))
    if not parts:
        raise RuntimeError("kTierRequiredRemediation has no string literals")
    return "".join(parts)


def refusal(remediation):
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32003,
            "message": "/mcp/v1/ requires an MCP-tier bearer token",
            "data": {"correlation_id": "cid-1", "retry_after_ms": None, "remediation": remediation},
        },
    }


class Stub:
    """A one-purpose HTTP server. `plan` is a dict: status, body (bytes), delay, headers, sse."""

    def __init__(self, host="127.0.0.1"):
        self.seen = []
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.plan = {}
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep the test output clean
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                with stub.lock:
                    stub.seen.append({"path": self.path, "headers": dict(self.headers.items()),
                                      "body": body})
                    stub.active += 1
                    stub.max_active = max(stub.max_active, stub.active)
                released = []

                def release():
                    # Counted as active until just BEFORE the reply goes out: the client
                    # frees its slot only once it has the reply, so a count taken after the
                    # write could overlap the next request and over-report.
                    if not released:
                        released.append(1)
                        with stub.lock:
                            stub.active -= 1

                try:
                    plan = stub.plan
                    if plan.get("delay"):
                        time.sleep(plan["delay"])
                    release()
                    if plan.get("sse"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.end_headers()
                        try:
                            for _ in range(150):  # ~30 s at most; the client hangs up first
                                self.wfile.write(b": keepalive\n\n")
                                self.wfile.flush()
                                time.sleep(0.2)
                        except OSError:
                            pass
                        return
                    payload = plan.get("body", b"{}")
                    self.send_response(plan.get("status", 200))
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    for k, v in plan.get("headers", {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    release()

        class Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ":" in host else socket.AF_INET

        self.server = Server((host, 0), Handler)
        port = self.server.server_address[1]
        self.url = "http://%s:%d/mcp/v1/" % (("[%s]" % host) if ":" in host else host, port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def reply(self, status=200, body=b"{}", delay=0.0, headers=None, sse=False):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.plan = {"status": status, "body": body, "delay": delay,
                     "headers": headers or {}, "sse": sse}
        with self.lock:
            self.seen.clear()
            self.max_active = 0

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def lines(obj_list):
    return "".join(json.dumps(o) + "\n" for o in obj_list)


def child_env(url, extra=None):
    """The caller's environment minus anything that could reroute or reconfigure node."""
    drop = {"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
            "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS"}
    env = {k: v for k, v in os.environ.items() if k not in drop and not k.startswith("YUZU_")}
    env["YUZU_MCP_URL"] = url
    env["YUZU_MCP_TOKEN"] = TOKEN
    env.update(extra or {})
    return env


def run_adapter(node, url, stdin_text, extra=None, timeout=40):
    try:
        return subprocess.run([node, str(ADAPTER)], input=stdin_text, capture_output=True, text=True,
                              timeout=timeout, env=child_env(url, extra))
    except subprocess.TimeoutExpired as e:
        # An adapter that never exits is a failure to report, not a crash of the test.
        return subprocess.CompletedProcess(e.cmd, 124, "", "adapter did not exit within %ss" % timeout)


def out_objs(p):
    return [json.loads(x) for x in p.stdout.splitlines() if x.strip()]


def synthesized(rid, status):
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32000, "message": "HTTP %d from MCP server" % status,
                      "data": {"http_status": status}}}


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("SKIP: node is not on PATH")
        return 77

    remediation = real_remediation()
    REFUSAL = refusal(remediation)
    stub = Stub()
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def check_request(label, n=1, path="/mcp/v1/"):
        check(len(stub.seen) == n, "%s: stub saw %d requests, want %d" % (label, len(stub.seen), n))
        for s in stub.seen:
            h = {k.lower(): v for k, v in s["headers"].items()}
            check(h.get("authorization") == "Bearer " + TOKEN, label + ": Authorization header")
            check(h.get("accept") == "application/json", label + ": Accept header %r" % h.get("accept"))
            check("cookie" not in h, label + ": no Cookie header is sent")
            check(s["path"] == path, label + ": path " + s["path"])

    def check_no_token(p, label):
        check(TOKEN not in p.stdout and TOKEN not in p.stderr, label + ": the token is never printed")

    try:
        # 1. a normal reply is passed through untouched and silently.
        ok = {"jsonrpc": "2.0", "id": 7, "result": {}}
        stub.reply(200, ok)
        p = run_adapter(node, stub.url, lines([PING]))
        check(p.returncode == 0, "ok: exit status %r" % p.returncode)
        check(out_objs(p) == [ok], "ok: stdout %r" % p.stdout)
        check(p.stderr == "", "ok: stderr is empty, got %r" % p.stderr)
        check_request("ok")
        check_no_token(p, "ok")

        # 1b. YUZU_MCP_COOKIE is never sent; it earns exactly one warning.
        stub.reply(200, ok)
        p = run_adapter(node, stub.url, lines([PING]), {"YUZU_MCP_COOKIE": "somecookie"})
        check(out_objs(p) == [ok], "cookie env: stdout %r" % p.stdout)
        errs = p.stderr.splitlines()
        check(len(errs) == 1 and "YUZU_MCP_COOKIE is ignored" in errs[0],
              "cookie env: stderr %r" % p.stderr)
        check("somecookie" not in p.stderr, "cookie env: the cookie value is not printed")
        check_request("cookie env")

        # 1c. the query string is preserved.
        stub.reply(200, ok)
        run_adapter(node, stub.url + "?tenant=a&x=1", lines([PING]))
        check_request("query", path="/mcp/v1/?tenant=a&x=1")

        # 2. the tier refusal (HTTP 403, id null) is re-addressed to the request id, and the
        #    whole real remediation (longer than 300 bytes) reaches stderr.
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub.url, lines([PING]))
        check(out_objs(p) == [dict(REFUSAL, id=7)], "403: stdout %r" % p.stdout)
        errs = p.stderr.splitlines()
        check(len(errs) == 1, "403: stderr is one line, got %r" % p.stderr)
        line = errs[0] if errs else ""
        check("HTTP 403" in line and "-32003" in line and "remediation" in line and "ping" in line,
              "403: stderr line lacks status/code/remediation/method: %r" % line)
        check(len(remediation) > 300, "403: the real remediation is longer than the old 300 clip")
        check("with no session cookie" in line and remediation in line,
              "403: the whole remediation reaches stderr (tail %r): %r" % (remediation[-30:], line))
        check_request("403")
        check_no_token(p, "403")

        # 2b. falsy-but-present ids are re-addressed too.
        for rid in (0, ""):
            stub.reply(403, REFUSAL)
            p = run_adapter(node, stub.url, lines([dict(PING, id=rid)]))
            check(out_objs(p) == [dict(REFUSAL, id=rid)], "id %r: stdout %r" % (rid, p.stdout))

        # 3. a notification refused with a 403 gets nothing on stdout.
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub.url, lines([{"jsonrpc": "2.0", "method": "notifications/initialized"}]))
        check(p.stdout == "", "notification: stdout %r" % p.stdout)
        check(len(p.stderr.splitlines()) == 1 and "HTTP 403" in p.stderr,
              "notification: stderr %r" % p.stderr)
        check_request("notification")

        # 4. a non-JSON 500 is answered with a synthesized error; the body is not echoed.
        marker = "SECRET-BODY-MARKER"
        html = "<html>%s</html>" % marker
        stub.reply(500, html.encode())
        p = run_adapter(node, stub.url, lines([dict(PING, id=9)]))
        check(out_objs(p) == [synthesized(9, 500)], "500: stdout %r" % p.stdout)
        check("non-JSON body (%d bytes)" % len(html) in p.stderr and marker not in p.stderr
              and len(p.stderr.splitlines()) == 1, "500: stderr %r" % p.stderr)
        check_request("500")

        # 5. a JSON 429 that is not a JSON-RPC error is answered the same way.
        stub.reply(429, {"error": "rate_limited"})
        p = run_adapter(node, stub.url, lines([dict(PING, id="req-a")]))
        check(out_objs(p) == [synthesized("req-a", 429)], "429: stdout %r" % p.stdout)
        check("rate_limited" not in p.stderr and "HTTP 429" in p.stderr
              and "non-JSON-RPC body" in p.stderr and len(p.stderr.splitlines()) == 1,
              "429: stderr %r" % p.stderr)

        # 5b. a 302 is not followed: one stderr status line, no Location, a synthesized reply.
        stub.reply(302, b"", headers={"Location": "http://evil.example/secret"})
        p = run_adapter(node, stub.url, lines([dict(PING, id=3)]))
        check(out_objs(p) == [synthesized(3, 302)], "302: stdout %r" % p.stdout)
        check(len(p.stderr.splitlines()) == 1 and "HTTP 302" in p.stderr
              and "redirect not followed" in p.stderr and "evil.example" not in p.stderr,
              "302: stderr %r" % p.stderr)
        check(len(stub.seen) == 1, "302: the redirect was not followed (%d requests)" % len(stub.seen))

        # 5c. an empty 2xx is a -32603 for a request (no raw bytes) and silent for a notification.
        stub.reply(200, b"")
        p = run_adapter(node, stub.url, lines([dict(PING, id=4)]))
        o = out_objs(p)
        check(len(o) == 1 and o[0]["id"] == 4 and o[0]["error"]["code"] == -32603
              and o[0]["error"]["message"] == "Invalid JSON from server (0 bytes)",
              "empty 2xx: stdout %r" % p.stdout)
        check("empty body" in p.stderr, "empty 2xx: stderr %r" % p.stderr)
        stub.reply(204, b"")
        p = run_adapter(node, stub.url, lines([{"jsonrpc": "2.0", "method": "notifications/initialized"}]))
        check(p.stdout == "" and p.stderr == "", "empty 2xx notification: %r / %r" % (p.stdout, p.stderr))

        # 5d. a non-JSON 2xx body never reaches stdout or stderr; only its size does.
        stub.reply(200, b"SECRET-2XX-BODY")
        p = run_adapter(node, stub.url, lines([dict(PING, id=5)]))
        o = out_objs(p)
        check(len(o) == 1 and o[0]["id"] == 5 and o[0]["error"]["code"] == -32603
              and o[0]["error"]["message"] == "Invalid JSON from server (15 bytes)",
              "non-JSON 2xx: stdout %r" % p.stdout)
        check("SECRET-2XX" not in p.stdout + p.stderr and "15 bytes" in p.stderr,
              "non-JSON 2xx: stderr %r" % p.stderr)

        # 6. control characters in the server's text never reach stderr.
        nasty = json.loads(json.dumps(REFUSAL))
        nasty["error"]["message"] = "bad\x1b[31mred\nFAKE LOG LINE\r"
        nasty["error"]["data"]["remediation"] = "fix\x00it\x7f\nFAKE2"
        stub.reply(403, nasty)
        p = run_adapter(node, stub.url, lines([PING]))
        bad = [c for c in p.stderr[:-1] if ord(c) < 0x20 or ord(c) == 0x7F]
        check(not bad and p.stderr.endswith("\n") and len(p.stderr.splitlines()) == 1,
              "control chars: stderr %r" % p.stderr)
        check("bad[31mredFAKE LOG LINE" in p.stderr and "fixitFAKE2" in p.stderr,
              "control chars: text kept, controls stripped: %r" % p.stderr)

        # 7. null, number and array lines do not crash the adapter or stop the lines after them.
        stub.reply(200, ok)
        p = run_adapter(node, stub.url, "null\n5\n[1,2]\n" + lines([PING]))
        check(p.returncode == 0 and "Traceback" not in p.stderr and "TypeError" not in p.stderr,
              "odd lines: exit %r stderr %r" % (p.returncode, p.stderr))
        check(ok in out_objs(p), "odd lines: the next request is still answered: %r" % p.stdout)
        check(len(stub.seen) == 4, "odd lines: stub saw %d requests, want 4" % len(stub.seen))
        stub.reply(403, REFUSAL)
        p = run_adapter(node, stub.url, "null\n5\n[1,2]\n")
        check(p.returncode == 0 and "TypeError" not in p.stderr and p.stdout == "",
              "odd lines refused: exit %r stdout %r stderr %r" % (p.returncode, p.stdout, p.stderr))

        # 8. closing stdin does not drop a request in flight (the stub answers late).
        stub.reply(200, ok, delay=0.5)
        p = run_adapter(node, stub.url, lines([PING]))
        check(out_objs(p) == [ok], "in flight: stdout %r" % p.stdout)

        # 9. a final line with no trailing newline is processed.
        stub.reply(200, ok)
        p = run_adapter(node, stub.url, json.dumps(PING))
        check(out_objs(p) == [ok], "no trailing newline: stdout %r" % p.stdout)

        # 10. the request body is the stdin line byte for byte (id above 2^53, 1.0).
        raw = '{"jsonrpc":"2.0","id":9007199254740993,"method":"ping","params":{"x":1.0}}'
        stub.reply(200, ok)
        run_adapter(node, stub.url, raw + "\n")
        check(len(stub.seen) == 1 and stub.seen[0]["body"] == raw.encode(),
              "raw body: stub saw %r" % (stub.seen[0]["body"] if stub.seen else None))

        # 11. a server that never finishes is cut off by the TOTAL deadline.
        stub.reply(sse=True)
        t0 = time.time()
        p = run_adapter(node, stub.url, lines([PING]), {"YUZU_MCP_TIMEOUT_MS": "1500"}, timeout=30)
        took = time.time() - t0
        o = out_objs(p)
        check(p.returncode == 0 and took < 10, "deadline: exit %r after %.1fs" % (p.returncode, took))
        check(len(o) == 1 and o[0].get("id") == 7 and o[0]["error"]["code"] == -32603
              and "timed out" in o[0]["error"]["message"],
              "deadline: stdout %r" % p.stdout)
        check(len(p.stderr.splitlines()) == 1, "deadline: stderr %r" % p.stderr)

        # 12. at most YUZU_MCP_MAX_INFLIGHT requests are on the wire at once; all replies arrive.
        stub.reply(200, ok, delay=0.3)
        reqs = [dict(PING, id=i) for i in range(1, 41)]
        p = run_adapter(node, stub.url, lines(reqs), {"YUZU_MCP_MAX_INFLIGHT": "4"}, timeout=60)
        check(len(p.stdout.splitlines()) == 40, "cap: %d replies, want 40" % len(p.stdout.splitlines()))
        check(len(stub.seen) == 40, "cap: stub saw %d requests, want 40" % len(stub.seen))
        check(1 <= stub.max_active <= 4, "cap: max concurrent connections %d, want <= 4" % stub.max_active)
        got_ids = sorted(json.loads(s["body"])["id"] for s in stub.seen)
        check(got_ids == list(range(1, 41)), "cap: every request reached the stub exactly once")
    finally:
        stub.close()

    # 13. an IPv6 literal URL works (skipped when the host has no IPv6 loopback).
    try:
        stub6 = Stub("::1")
    except OSError:
        stub6 = None
    if stub6 is not None:
        try:
            stub6.reply(200, {"jsonrpc": "2.0", "id": 7, "result": {}})
            p = run_adapter(node, stub6.url, lines([PING]))
            check(len(out_objs(p)) == 1 and len(stub6.seen) == 1,
                  "ipv6: stdout %r stderr %r" % (p.stdout, p.stderr))
        finally:
            stub6.close()

    if fails:
        print("FAIL\n" + "\n".join(fails))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
