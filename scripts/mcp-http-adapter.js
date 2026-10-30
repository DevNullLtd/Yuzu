#!/usr/bin/env node
// MCP stdio-to-HTTP adapter for Yuzu
//
// Bridges Claude Code's stdio MCP transport to Yuzu's HTTP JSON-RPC endpoint.
// Reads JSON-RPC requests from stdin, forwards to Yuzu's /mcp/v1/, writes
// responses to stdout. Requires Node 10 or newer (object spread, optional catch binding).
//
// Usage:
//   YUZU_MCP_URL=http://localhost:8080/mcp/v1/ YUZU_MCP_TOKEN=<token> node scripts/mcp-http-adapter.js
//
// Authentication is a bearer token that carries an MCP tier (readonly, operator
// or supervised): mint one with POST /api/v1/tokens (set mcp_tier and
// expires_at). The server refuses a session cookie, and an API token minted
// without mcp_tier, at /mcp/v1/ with HTTP 403 and JSON-RPC code -32003, so this
// adapter has no cookie mode. The adapter sends only the Authorization header.
//
// Request body: the stdin line is forwarded byte for byte (it is parsed only to
// read the id and method), so ids above 2^53 and numbers such as 1.0 round-trip.
// A reply the adapter has to write itself (a re-addressed or synthesized error)
// carries the id as JSON.parse read it, so an id above 2^53 loses precision there.
// Every POST sends `Accept: application/json`.
//
// Refusals: any HTTP status >= 400 writes one line to stderr (status, request
// method, JSON-RPC error code and message, remediation when present; never the
// token; control characters stripped; a body that is not a JSON-RPC error is
// reported by size only). A 3xx status writes one line (status only; redirects
// are not followed and Location is not printed). A stdio client matches replies
// on request id, so the adapter always answers a request that carried an id:
//   - a JSON-RPC error with a null id (the server's refusal for a missing MCP tier
//     is decided before the body is read) is re-addressed to the request's id;
//   - an HTTP error or redirect whose body is not a JSON-RPC error (non-JSON, or
//     JSON without jsonrpc/error) is answered with a synthesized -32000 error
//     carrying that id;
//   - an empty or non-JSON 2xx body, a network failure and a timeout are answered
//     with a -32603 error carrying that id (the stdout message never contains raw
//     server bytes, only their size).
// A notification (no id) refused or failed gets nothing on stdout. A JSON-RPC
// batch (an array) is forwarded as-is but is not supported: it has no id here, so
// a batch refused with an HTTP error produces only the stderr line.
//
// Limits: at most MAX_INFLIGHT (16) requests are in flight, the rest wait in a FIFO
// queue. Each request has a TOTAL deadline (default 120 s, env YUZU_MCP_TIMEOUT_MS)
// plus an idle timeout of the same length. A call that exceeds the deadline is
// reported as -32603 but is NOT cancelled on the server: it may still run, so a
// host must not blindly retry a mutating tool after a timeout.
//
// Shutdown: when stdin closes, queued and in-flight requests are still answered;
// the process exits once they have all been written (nothing else keeps it alive).

const http = require('http');
const https = require('https');
const { URL } = require('url');

function envInt(name, dflt) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : dflt;
}

const MCP_URL = process.env.YUZU_MCP_URL || 'http://localhost:8080/mcp/v1/';
const MCP_TOKEN = process.env.YUZU_MCP_TOKEN || '';
const REQUEST_TIMEOUT_MS = envInt('YUZU_MCP_TIMEOUT_MS', 120000);
const MAX_INFLIGHT = envInt('YUZU_MCP_MAX_INFLIGHT', 16);

if (process.env.YUZU_MCP_COOKIE) {
  process.stderr.write(
    '[mcp-adapter] YUZU_MCP_COOKIE is ignored: /mcp/v1/ refuses session cookies. ' +
    'Set YUZU_MCP_TOKEN to an API token minted with an mcp_tier.\n');
}

const url = new URL(MCP_URL);
const transport = url.protocol === 'https:' ? https : http;

// Strip control characters (C0 and DEL) so server- or client-supplied text cannot
// forge extra log lines or drive a terminal, then clip.
function clean(value, max) {
  const s = String(value).replace(/[\u0000-\u001f\u007f]/g, '');
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

function isObject(v) {
  return v !== null && typeof v === 'object';
}

// A JSON-RPC error response: an object with `jsonrpc` and an `error` object.
function isRpcError(body) {
  return isObject(body) && body.jsonrpc !== undefined && isObject(body.error);
}

// One stderr line for any HTTP status >= 400: the status, the request method, and
// the JSON-RPC error code, message and remediation when the body carries them.
// Any other body is reported by size only, never echoed.
// Never prints the token (it is only ever sent in the Authorization header).
function logHttpError(status, method, body, rawBody) {
  let detail;
  if (isRpcError(body)) {
    const err = body.error;
    detail = `JSON-RPC error ${clean(err.code, 20)}: ${clean(err.message, 200)}`;
    const remediation = isObject(err.data) ? err.data.remediation : undefined;
    if (remediation) detail += ` (remediation: ${clean(remediation, 600)})`;
  } else if (body === undefined) {
    detail = `non-JSON body (${Buffer.byteLength(rawBody)} bytes)`;
  } else {
    detail = `non-JSON-RPC body (${Buffer.byteLength(rawBody)} bytes)`;
  }
  process.stderr.write(`[mcp-adapter] HTTP ${status} for ${clean(method, 64)}: ${detail}\n`);
}

// Resolves { status, body, raw }: body is the parsed JSON, or undefined when the
// response is not JSON. `rawLine` is sent byte for byte.
function forward(rawLine) {
  return new Promise((resolve, reject) => {
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(rawLine),
      'Accept': 'application/json',
    };
    if (MCP_TOKEN) headers['Authorization'] = `Bearer ${MCP_TOKEN}`;

    const opts = {
      // An IPv6 literal URL carries its brackets in `hostname`; the socket wants none.
      hostname: url.hostname.replace(/^\[|\]$/g, ''),
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers,
      agent: false,  // no pooled socket outliving the exchange
    };

    let settled = false;
    let timedOut = false;
    let totalTimer;
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      fn(value);
    };
    const fail = (err) => {
      settle(reject, timedOut ? new Error('timed out waiting for the MCP server') : err);
    };

    const req = transport.request(opts, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let parsedBody;
        try {
          parsedBody = JSON.parse(data);
        } catch {
          parsedBody = undefined;
        }
        settle(resolve, { status: res.statusCode, body: parsedBody, raw: data });
      });
      res.on('error', fail);
      res.on('aborted', () => fail(new Error('connection closed before the response ended')));
      res.on('close', () => fail(new Error('connection closed before the response ended')));
    });

    // The idle timeout alone is defeated by a server that keeps sending (an SSE
    // stream of keepalive comments), so there is also a TOTAL deadline.
    const expire = () => {
      timedOut = true;
      req.destroy();
      fail(new Error('timed out'));
    };
    totalTimer = setTimeout(expire, REQUEST_TIMEOUT_MS);
    req.setTimeout(REQUEST_TIMEOUT_MS, expire);
    req.on('error', fail);
    req.write(rawLine);
    req.end();
  });
}

function writeReply(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// ── Request queue: at most MAX_INFLIGHT exchanges at once, the rest FIFO ──
const queue = [];
let inflight = 0;

function pump() {
  while (inflight < MAX_INFLIGHT && queue.length > 0) {
    const task = queue.shift();
    inflight++;
    // A queued task is only ever waiting behind a running one, so the event loop
    // stays alive until the queue drains.
    task().then(done, done);
  }
}

function done() {
  inflight--;
  pump();
}

function exchange(line, parsed) {
  // `null`, a number or an array parses fine but has no id; it is still forwarded.
  const hasObject = isObject(parsed) && !Array.isArray(parsed);
  const id = hasObject ? parsed.id : undefined;
  const hasId = id !== undefined && id !== null;
  const method = hasObject && typeof parsed.method === 'string' ? parsed.method : '?';

  return forward(line)
    .then(({ status, body, raw }) => {
      if (status >= 400) logHttpError(status, method, body, raw);
      else if (status >= 300) {
        process.stderr.write(
          `[mcp-adapter] HTTP ${status} for ${clean(method, 64)}: redirect not followed\n`);
      }

      // A refused or redirected notification has no client waiting on it: the
      // stderr line above is the whole report, and nothing goes to stdout.
      if (status >= 300 && !hasId) return;

      // An HTTP error or redirect whose body is not a JSON-RPC error (an HTML error
      // page, a proxy's text, a JSON object without jsonrpc/error): answer the
      // request so the client does not wait for its timeout.
      if (status >= 300 && !isRpcError(body)) {
        writeReply({ jsonrpc: '2.0', id,
                     error: { code: -32000, message: `HTTP ${status} from MCP server`,
                              data: { http_status: status } } });
        return;
      }

      if (body === undefined) {
        const n = Buffer.byteLength(raw);
        // An empty 2xx is a normal answer to a notification; for a request it is not.
        if (n === 0 && !hasId) return;
        if (n === 0) {
          process.stderr.write(
            `[mcp-adapter] HTTP ${status} for ${clean(method, 64)}: empty body\n`);
        }
        throw new Error(`Invalid JSON from server (${n} bytes)`);
      }

      // The server's pre-parse refusals (e.g. the 403 for a credential without an
      // MCP tier) are JSON-RPC errors with `id: null`, because they are decided
      // before the body is read. A stdio client matches replies on request id and
      // would wait for its timeout, so answer the in-flight request's id instead.
      let response = body;
      if (isObject(response) && isObject(response.error) && response.id === null && hasId) {
        response = { ...response, id };
      }
      writeReply(response);
    })
    .catch((err) => {
      process.stderr.write(`[mcp-adapter] Error: ${clean(err.message, 300)}\n`);
      // A notification has no client waiting; a request gets a JSON-RPC error so
      // the caller doesn't hang.
      if (!hasId) return;
      writeReply({
        jsonrpc: '2.0',
        error: { code: -32603, message: err.message },
        id,
      });
    });
}

function handleLine(rawLine) {
  const line = rawLine.trim();
  if (!line) return;

  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    process.stderr.write(`[mcp-adapter] Invalid JSON from stdin: ${clean(line.slice(0, 100), 100)}\n`);
    return;
  }

  queue.push(() => exchange(line, parsed));
  pump();
}

// Read newline-delimited JSON-RPC from stdin
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let newlineIdx;
  while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIdx);
    buffer = buffer.slice(newlineIdx + 1);
    handleLine(line);
  }
});

// No process.exit here: queued and in-flight requests keep the event loop alive, are
// answered, and the process ends on its own once the last reply is written.
process.stdin.on('end', () => {
  handleLine(buffer);  // a final line with no trailing newline
  buffer = '';
});

// Prevent unhandled rejection crashes
process.on('unhandledRejection', (err) => {
  process.stderr.write(`[mcp-adapter] Unhandled: ${clean(err && err.message, 300)}\n`);
});
