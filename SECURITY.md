# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Yuzu, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Use [GitHub's private vulnerability reporting](https://github.com/DevNullLtd/Yuzu/security/advisories/new) to submit a report
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected components (agent, server, SDK, plugins)
   - Potential impact
   - Suggested fix (if any)

Public GitHub issues carrying the `security` label are for **hardening, defense-in-depth, and
reliability work only** — an exploitable vulnerability always goes through private reporting
above, never a public issue (`docs/agents/issue-standard.md`, section 6). Tracker automation
never closes a `security`-labelled issue; a human verifies the fix against the current `dev`
branch first.

## Response

- We aim to acknowledge reports within 48 hours
- We will work with reporters to understand and validate the issue
- Fixes will be prioritised based on severity

## Security Hardening Tracking

All planned security features are implemented:
- **#146** HTTPS for Web Dashboard — **Done** (HTTPS enabled by default, cert hot-reload)
- **#154** Granular RBAC System — **Done** (6 roles, 14 securable types, per-operation permissions)
- **#157** Token-Based API Authentication — **Done** (Bearer token, X-Yuzu-Token, MCP tokens)

A 52-finding RC security sprint was completed 2026-03-24, addressing 7 CRITICAL, 16 HIGH, 22 MEDIUM, and 7 LOW findings. See `SECURITY_REVIEW.md` for code-level findings and `Release-Candidate.local.MD` for the full assessment.
