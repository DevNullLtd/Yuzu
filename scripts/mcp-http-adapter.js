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
// Authentication is a bearer token that carries an MCP tier (readonly, operator
// or supervised): mint one with POST /api/v1/tokens (set mcp_tier and
// expires_at). The server refuses a session cookie, and an API token minted
// without mcp_tier, at /mcp/v1/ with HTTP 403 and JSON-RPC code -32003, so this
// adapter has no cookie mode. The adapter sends only the Authorization header.

const http = require('http');
const https = require('https');
const { URL } = require('url');

const MCP_URL = process.env.YUZU_MCP_URL || 'http://localhost:8080/mcp/v1/';
const MCP_TOKEN = process.env.YUZU_MCP_TOKEN || '';

if (process.env.YUZU_MCP_COOKIE) {
  process.stderr.write(
    '[mcp-adapter] YUZU_MCP_COOKIE is ignored: /mcp/v1/ refuses session cookies. ' +
    'Set YUZU_MCP_TOKEN to an API token minted with an mcp_tier.\n');
}

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
