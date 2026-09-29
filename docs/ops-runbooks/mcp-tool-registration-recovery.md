# MCP Tool Registration Recovery Runbook

Operator runbook for a Yuzu server that refuses to boot with an MCP tool
security registration failure (#2383). Unlike `auth.db` corruption this is a
**code-table defect in the server binary itself, not local data corruption** —
there is nothing to repair on the host.

## Detection signal

`yuzu-server` exits non-zero at startup and `journalctl -u yuzu-server`
(Linux) or the Windows event log shows:

```
[error] Fatal exception: MCP tool security registration invalid (C8 fail-closed, #2383): <sorted list of offenders>
```

The offender list names each affected tool and which table disagrees (missing
or duplicate `kToolSecurity` row, `kWriteTools` mismatch, or an operation /
securable type outside the RBAC catalogue). Since #2405 the same validator
also compiles every served input schema, so the list can additionally carry
`tool '<name>' input schema: ...` offences — schema not valid JSON, root not
an object schema, an unsupported keyword or type, a malformed keyword operand
(e.g. `minimum` exceeding `maximum`, `minItems` exceeding `maxItems`, a
negative `maxLength`/`maxItems`), a keyword on the wrong type, a `pattern`
that does not compile as RE2, nesting beyond the supported depth, a
`required` name not declared in `properties`, or an approval-gated tool
setting `additionalProperties:false` without declaring `approval_id` (its
tickets would be unrecallable). The recovery procedure is identical — the
defect is compiled into the binary. If MCP itself is not needed while a
rolled-back binary is prepared, `--mcp-disable` skips the validator (and the
whole MCP surface) entirely and is the documented emergency bridge. If the shipped systemd unit
(`deploy/systemd/yuzu-server.service`) is in use, the unit retries up to
`StartLimitBurst=3` times within `StartLimitIntervalSec=60` and then enters
the `failed` state. Note: the gRPC agent listener opens briefly each attempt
before the check fires, so agents may show connect/drop cycles during the
retry window — this stops once the unit settles in `failed`.

## Recovery procedure

1. **Do not attempt local repair.** No on-host data (PostgreSQL, `auth.db`,
   config) is involved; the inconsistency is compiled into the binary.
2. **Roll back** to the previously deployed release binary/image and start it.
3. **Escalate to engineering** with the full fatal log line. A release binary
   can only reach this state if it shipped without its test suite passing
   (every CI fixture runs the same validator) or was locally patched/rebuilt.
4. If the binary is a local source build: revert the local modification to the
   MCP tool tables in `server/core/src/mcp_server.cpp` (see
   `docs/mcp-server.md` "Adding a tool" for the required table set) and
   rebuild.

## Related

- One runtime symptom if the check is ever bypassed: MCP `tools/call` on the
  affected tool returns `-32603` "tool security registration missing — denied
  fail-closed" and increments `yuzu_mcp_tool_security_misconfig_total`. That
  counter being non-zero is itself an incident signal — alert on it.
- The sibling `yuzu_mcp_tool_args_invalid_total{tool}` counter (#2405) counts
  schema-invalid approval-gated calls. Unlike the misconfig counter it is NOT
  an incident on its own (a worker with a typo trips it), but a sustained
  spike on one tool is a malformed integration or probing — suggested rule:
  `increase(yuzu_mcp_tool_args_invalid_total[15m]) > 20` per tool, tuned to
  your fleet's supervised-call volume.
- `docs/mcp-server.md` — Security Model, boot-time registration validator.
