# 🍊 Yuzu Compose Wizard

A browser-based wizard for generating customised Yuzu `docker-compose.yml` and `.env` files. Zero dependencies — just open `index.html` in a browser.

## Why?

The default `docker-compose.uat.yml` works, but it has:
- Hardcoded ports, passwords, and versions
- Several known gotchas that trip up new users
- Minimal comments explaining what each section does

This wizard walks you through a step-by-step configuration and generates a production-ready compose file with proper defaults, helpful comments, and a separate `.env` file for easy reconfiguration.

## Known Gotchas Addressed

| Issue | Fix |
|-------|-----|
| Missing PostgreSQL substrate | Wizard provisions a bundled `yuzu-postgres` service (or wires an external DSN) — the server has a substrate to talk to (ADR-0006/0008) |
| Postgres superuser == app password | Bundled mode enforces two distinct credentials; the image's first-boot init refuses equal passwords |
| Secrets baked into compose | Postgres credentials/DSN live in `.env`; the compose YAML only references `${...}` |
| Missing `--data-dir` flag | Always included — still needed for config, OTA binaries, and not-yet-migrated SQLite stores |
| RBAC config doesn't enforce | Comment added noting this is a known issue |
| Port conflicts detected | Wizard warns about common conflicts |
| Hardcoded passwords | All credentials configurable, with production warnings |
| No `.env` separation | Generated `.env` file separates config from compose |
| TLS was all-or-files | Three-way TLS mode: **Default certs** (server auto-generates a per-install CA + leaf certs on first boot — no files; needs the secure-by-default release, tracked by `latest`), **Operator certs** (`--cert`/`--key` + **required** `--ca-cert`, bind-mounted from `./certs`), or **Plaintext** (`--no-tls --no-https`, dev only) |
| Cert directory not persisted | Every mode except Operator mounts a volume at `/etc/yuzu/certs` (since 0.14.1, #5370). It holds the per-install CA and the secrets KEK registered in Postgres; without it a recreated server refuses to start (`kek_unresolvable`). Operator mode's read-only `./certs` mount is tracked in #5420 |
| Extra cert SANs (`--cert-san`) | Operator-entered DNS/IP names are validated (no breakout payloads) and added to the auto-generated leaves so they validate for the name/IP agents dial |
| Version pins an image that can't run the flags (#1488 review H1) | Default version is `latest` (tracks the secure-by-default builds); Default-certs/HTTPS-8443 don't exist in 0.12.0, so the TLS header banner says so and Plaintext is the fallback for older images |
| Gateway crash-loop on default cookie (#1483) | A unique `YUZU_GW_COOKIE` is generated into `.env` and referenced by the gateway service, so it doesn't fail-closed on the insecure default Erlang distribution cookie |
| HTTPS served on 8443, wizard used 8080 (#1484) | In TLS modes the dashboard/API is published and health-checked on container port **8443** (8080 is the HTTP→HTTPS redirect); plaintext stays on 8080 |
| Gateway↔server TLS not wired (#1485) | The secure gateway↔server topology (mutual-TLS upstream, shared certs) depends on server features still in flight (PKI go-live, #1314) that no current image ships. The wizard **blocks gateway + TLS** with guidance (use Plaintext for the gateway, or a server-only TLS stack) rather than emit a stack that crash-loops — re-enables once #1314 lands |
| `--cert-san` flag injection (#1485 review N1) | Each cert-SAN token is validated to DNS/IP shape client-side, so a quote+newline payload can't break out of the YAML list and inject standalone server flags (e.g. silent `--no-tls`) |
| Operator certs need a CA (#1485 review H2) | The CA path is required in operator mode (the server refuses to start with operator certs and no CA); the UI no longer says it's optional |
| Gateway healthcheck used bash `/dev/tcp` (#1486) | The gateway image ships busybox `wget` (no bash/curl), so the probe is now `wget --spider /healthz`, matching `docker-compose.uat.yml` |
| Server healthcheck used `curl` (#1487) | The server image ships no curl. Replaced with a bash `/dev/tcp` TCP-connect probe on the real serving port (8443/8080), matching `docker-compose.uat.yml` |
| Admin `admin:admin` hash didn't validate (#1488) | The admin credential row is now derived in-browser via SubtleCrypto **PBKDF2-HMAC-SHA256, 100k iters** for the password you enter — matching the server KDF, so login actually works (the old row put the password in the role field and shipped a stale hash) |
| Named-volumes off + Prometheus/Grafana/ClickHouse on (#1485 review M1) | Those services use anonymous volumes when named volumes are disabled, so `docker compose config` no longer fails on an undefined volume |

## Usage

```bash
# Just open it
open tools/compose-wizard/index.html

# Or serve it locally
cd tools/compose-wizard && python3 -m http.server 8000
```

Then open `http://localhost:8000` in your browser.

## Tech Stack

- **HTML** — Single page, no build step
- **HTMX** — Step navigation feel (loaded from CDN)
- **Vanilla JS** — YAML generation, no framework
- **CSS** — Yuzu-themed, responsive

## Development

No build tools needed. Edit files, refresh browser. That's it.

```bash
# Live reload (optional)
npx serve .
```

## Future Ideas

- [ ] Admin password hash generator (using Web Crypto API)
- [ ] Export/import wizard config as JSON
- [ ] Validate generated compose with `docker-compose config`
- [ ] Dark mode
- [ ] Embed in Yuzu docs site