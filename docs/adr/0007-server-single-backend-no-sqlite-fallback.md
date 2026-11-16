---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-09
scope: platform — the server storage layer architecture
builds-on: ADR-0006 (PostgreSQL is the server substrate)
related: 0035-server-is-linux-only-windows-is-agent-only (the server is now single-OS as well as single-backend)
---

# 0007 — The server is single-backend: PostgreSQL only, no SQLite fallback

## Context

ADR-0006 made PostgreSQL the server-side storage substrate. That leaves an immediate
architectural fork: do we *also* keep SQLite as a selectable single-node/dev fallback behind a
storage abstraction (dual-backend), or do we commit to one engine on the server (single-backend)?

The server runs ~29 concrete stores, each talking to `sqlite3*` directly with **no interface
abstraction** today. A dual-backend world would require introducing a real abstraction over
*both* engines and implementing every store twice. The pull toward keeping SQLite is the
zero-config, single-binary "just run the server" experience that is genuinely nice for evals,
demos, and tiny single-node installs.

## Decision

**The server is single-backend: PostgreSQL only. There is no server-side SQLite fallback.**
The storage layer abstracts over *one* engine, not two. The convenience of zero-config
single-node is recovered at the **deployment** layer instead of the **code** layer — a bundled
`yuzu-postgres` image in the composes and an install script that provisions a local Postgres
(ADR-0008 / the migration plan), not a second engine kept alive in C++.

The agent remains SQLite (ADR-0006) — this decision is about the *server* only.

## Considered and rejected

- **Dual-backend behind a storage seam.** Rejected. With ~29 stores and no existing
  abstraction, every store would be implemented twice, migrations would exist twice, and the
  server test matrix would roughly double — a permanent tax on every future store and every
  bug fix. The single-node convenience does not justify a forever-doubled maintenance and test
  surface, especially when deployment-layer bundling recovers most of it.
- **Hard-require Postgres but auto-provision an embedded Postgres inside the server binary.**
  Rejected for the foundation. It keeps one engine in the code (good) but loads the server
  process with embedded-distribution management and lifecycle burden; a bundled container +
  install-script provisioning achieves the same operator experience without that complexity.

## Consequences

- **The single-binary, zero-dependency server is gone.** Every server install now depends on a
  reachable Postgres. The server **fails closed** if no DSN is configured or the database is
  unreachable (`startup_failed()` → non-zero exit). This is a breaking deployment change.
- The storage abstraction stays thin: concrete store classes over a shared connection pool, no
  virtual backend interface (there is only one backend to dispatch to). See ADR-0008.
- Dev / demo / eval ergonomics are a **deployment** responsibility: the bundled `yuzu-postgres`
  image (compose) and `scripts/install-*.sh` local-Postgres provisioning must stay
  one-command, or the loss of single-binary convenience becomes real friction.
