#!/usr/bin/env node
// MCP stdio-to-HTTP adapter for Yuzu
//
// Bridges Claude Code's stdio MCP transport to Yuzu's HTTP JSON-RPC endpoint.
// Reads JSON-RPC requests from stdin, forwards to Yuzu's /mcp/v1/, writes
// responses to stdout.
//
// Usage:
//   YUZU_MCP_URL=http://localhost:8080/mcp/v1/ YUZU_MCP_TOKEN=<token> node scripts/mcp-http-adapter.js
//
// Or with session cookie auth:
//   YUZU_MCP_COOKIE="yuzu_session=<cookie>" node scripts/mcp-http-adapter.js
//
// In cookie mode every request also sends a Referer naming the server's own
// origin (cookie-session writes send a same-site Origin/Referer). Token mode
// sends no Referer.

const http = require('http');
const https = require('https');
const { URL } = require('url');

const MCP_URL = process.env.YUZU_MCP_URL || 'http://localhost:8080/mcp/v1/';
const MCP_TOKEN = process.env.YUZU_MCP_TOKEN || '';
const MCP_COOKIE = process.env.YUZU_MCP_COOKIE || '';

const url = new URL(MCP_URL);
const transport = url.protocol === 'https:' ? https : http;

function forward(jsonRpcRequest) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(jsonRpcRequest);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    };
    if (MCP_TOKEN) headers['Authorization'] = `Bearer ${MCP_TOKEN}`;
    if (MCP_COOKIE) {
      headers['Cookie'] = MCP_COOKIE;
      headers['Referer'] = `${url.origin}/`;
    }

    const opts = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers,
    };

    const req = transport.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error(`Invalid JSON from server: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Read newline-delimited JSON-RPC from stdin
let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let newlineIdx;
  while ((newlineIdx = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIdx).trim();
    buffer = buffer.slice(newlineIdx + 1);
    if (!line) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      process.stderr.write(`[mcp-adapter] Invalid JSON from stdin: ${line.slice(0, 100)}\n`);
      continue;
    }

    forward(parsed)
      .then((response) => {
        process.stdout.write(JSON.stringify(response) + '\n');
      })
      .catch((err) => {
        process.stderr.write(`[mcp-adapter] Error: ${err.message}\n`);
        // Return a JSON-RPC error so the caller doesn't hang
        const errResp = {
          jsonrpc: '2.0',
          error: { code: -32603, message: err.message },
          id: parsed.id || null,
        };
        process.stdout.write(JSON.stringify(errResp) + '\n');
      });
  }
});

process.stdin.on('end', () => {
  process.exit(0);
});

// Prevent unhandled rejection crashes
process.on('unhandledRejection', (err) => {
  process.stderr.write(`[mcp-adapter] Unhandled: ${err.message}\n`);
});
