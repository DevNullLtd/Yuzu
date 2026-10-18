# Instructions cross-platform validation — handover (2026-05-13)

**Branch**: `feat/viz-engine`
**HEAD (pushed)**: `1b20f6f` (one above the fix commit `1dd7624`)
**Status**: macOS green, Linux green, Windows build green + agent registers; live Instructions gate on Windows blocked on a one-line env install (`pacman -S python-yaml`) and a Tailscale-friendly network.

## Where we left off

| Host | Build | Instructions gate | Notes |
|---|---|---|---|
| **macOS** (this box) | clean | **161 pass / 0 fail / 9 pending / 15 skip** | Full `/test` PASS — 17/0/0/5, run `1778655973-2741`, 418s |
| **Linux** (OrbStack `yuzu` VM, arm64) | clean (gcc-15) | **161 pass / 0 fail / 9 pending / 15 skip** | Build-only validation, not full `/test` |
| **Windows** (Shulgi, MSVC 19.44) | clean (server+agent+4 modified plugin DLLs) | **pending** | Server up on :18080, agent registered in 7s; gate aborted at `error: PyYAML missing` |

The 15 skips on macOS/Linux are the same 15 Windows-only definitions: `windows.registry.*` (5), `windows.wmi.*` (2), `windows.software.msi.*` (2), `security.sccm.*` (2), `security.antivirus.defender_status`, `device.filesystem.get_signature`, `device.filesystem.get_version_info`, `workflow.version_compliance_check`. On Windows those should flip to pass.

## What landed in this session

Single commit on `feat/viz-engine`:

```
1dd7624 fix(instructions): clear 34 failing instructions across A/B/D/E/F + macOS C parity
```

Files touched:

| File | Bucket | Change |
|---|---|---|
| `scripts/test/instructions_runner.py` | A, B, F | Host-aware param synthesis; platform-aware SKIP before dispatch; trust agent rc/status, not body prefix |
| `content/definitions/discovery.yaml` | D | `type: query` → `question` for `device.discovery.scan_subnet` |
| `content/definitions/deployment.yaml` | D | `type: query` → `question` for `server.deployment.list_jobs` |
| `content/definitions/procfetch.yaml` | C | `platforms:` adds `darwin` |
| `agents/plugins/tar/src/tar_plugin.cpp` | E | `tar.export` UNION ALL projects uniform `(source, ts, snapshot_id, action, summary)` |
| `agents/plugins/agent_logging/src/agent_logging_plugin.cpp` | F | "no log file" → `status\|empty` rc=0 |
| `agents/plugins/procfetch/src/procfetch_plugin.cpp` | C | macOS branch via `libproc` + OpenSSL EVP |
| `agents/plugins/wifi/src/wifi_plugin.cpp` | C | macOS fallback to `system_profiler SPAirPortDataType` when `airport` is gone (Sonoma+) |
| `docs/plans/instructions-gate-34-fails.html` | — | Cross-platform parity browser report |

Plus one diagnostic-only CI workflow added at the tail end:

```
1b20f6f ci: one-shot workflow_dispatch to validate Instructions gate on Shulgi
```

Adds `.github/workflows/instructions-windows-validate.yml`. **Currently unusable** — GitHub requires `workflow_dispatch` workflow files to live on the default branch (`main`), but we work off `dev`/feature branches and don't PR direct to main. Two options on resume:
- **Delete the workflow** — it's dead weight if we never restore Tailscale before merging through `dev` → `main` (which would land it via the normal flow anyway).
- **Keep it** as a backup plan for a future session where Tailscale is also blocked.

The actual Windows validation does NOT depend on this workflow — see "Resume" below.

## Resume the Windows live run

When on a network that lets Tailscale reach Shulgi (anything that isn't HSBC guest WiFi — UDP and DERP both seem blocked there):

```bash
# Step 1 — confirm Shulgi is reachable
ssh -o ConnectTimeout=10 Shulgi 'echo alive'

# Step 2 — install PyYAML for MSYS2 python3 (one-time)
ssh Shulgi 'C:\msys64\usr\bin\bash.exe -lc "pacman -S --noconfirm --needed python-yaml && python3 -c \"import yaml; print(yaml.__version__)\""'

# Step 3 — rerun the orchestration. The exact heredoc that got us
# through 'agent registered at i=7' lives in the session transcript;
# the meaningful invariants for re-deriving it:
#   - taskkill /F /IM yuzu-{server,agent}.exe  (clean slate)
#   - source /c/Users/natha/Yuzu/setup_msvc_env.sh
#   - meson compile -C /c/Users/natha/Yuzu/build-windows  (if stale)
#   - generate PBKDF2 admin config:
#       python -c "..." > yuzu-server.cfg
#   - start yuzu-server.exe with --web-port 18080
#     (NOT :8080 — iphlpsvc owns it on Shulgi)
#     and --listen 127.0.0.1:50054 (NOT 0.0.0.0; firewall trips on 0.0.0.0)
#   - mint enrollment token via POST /api/settings/enrollment-tokens
#   - start yuzu-agent.exe --server 127.0.0.1:50054 with that token
#   - bash scripts/test/instructions-tests.sh --dashboard http://127.0.0.1:18080 ...
```

A reusable copy of the heredoc orchestration is preserved in
`docs/plans/instructions-cross-platform-handover-2026-05-13.shulgi.sh`
(see next section).

### Shulgi gotchas discovered today

1. **Port 8080 is owned by `iphlpsvc`** (IP Helper) on Shulgi. The yuzu-server `httplib` listener appears to bind 0.0.0.0:8080 (netstat shows LISTENING), but the OS-level accept queue belongs to iphlpsvc and your connections time out at 2s. Use `--web-port 18080`.
2. **Windows Defender Firewall blocks inbound TCP to fresh binaries.** You already added the allow rules for `yuzu-server.exe` and `yuzu-agent.exe` at `C:\Users\<user>\Yuzu\build-windows\...`. If we rebuild to a different path the rules don't apply (rules are keyed by exact program path).
3. **`set -e` + `curl -sf`** in the bash orchestration silently bails on connection-refused. Use `curl -s -o /dev/null -w "%{http_code}"` and check for 200 explicitly.
4. **MSYS2 bash's `cd` doesn't seem to propagate when literal in the `ssh Shulgi '…'` command string** for reasons we didn't fully diagnose. Use `cat <<'EOF' | ssh Shulgi 'C:\msys64\usr\bin\bash.exe -l'` heredoc form — it works reliably.
5. **OrbStack-mounts the Mac filesystem into the Linux VM** at the same `/Users/<user>/...` path. The git worktree at `/Users/<user>/Yuzu-viz` is reachable from the VM. The gateway release at `gateway/_build/prod/rel/yuzu_gw/` lives on this shared mount, so building it on the Linux VM with the standard `rebar3 as prod release` would clobber the Mac's Mach-O binaries. The workaround we used: `REBAR_BASE_DIR=~/yuzu-gw-linux rebar3 as prod release`, then `cp -a` the result into place before `start-UAT.sh`, then move the Mac backup back when done. The Linux gate completed; the Mac gateway was restored.

## Three unrelated CI-side findings worth follow-ups

1. **`ensure-erlang.sh` refuses to run inside `bash -c`** even when sourced. Detection mechanism trips when the parent shell is bash invoked by another bash. Works fine if `erl` is already on PATH (Homebrew on Mac, system on Ubuntu, chocolatey on Shulgi). Bypass: don't rely on it in scripted contexts; rely on the host's pre-installed Erlang.
2. **Gateway release is built into the shared `gateway/_build/`**, which is fine on a single host but breaks cross-host development where the same source tree is reached from multiple hosts (Mac + OrbStack VM in our case). A `REBAR_BASE_DIR` override flag in `start-UAT.sh` would be cleaner than the cp-around-on-the-mount dance we used.
3. **`scripts/test/test-db-write.sh` is invoked with a path that requires the CWD to be the repo root.** The Phase 5 `gate_run` shell function I wrote also bumped into a zsh-readonly-`status` variable name clash when the eval'd command leaked back into the outer shell context — renaming to `gate_status` was the fix. Filed as a session-internal observation; not yet an issue.

## Files

- `docs/plans/instructions-gate-34-fails-handover-2026-05-13.md` — original work-handover that kicked off the session
- `docs/plans/instructions-gate-34-fails.html` — browser-rendered cross-platform parity reference (Barony of Alyth livery)
- `docs/plans/instructions-cross-platform-handover-2026-05-13.md` — this file
- `~/.local/share/yuzu/test-runs.db` — full macOS `/test` run row at `RUN_ID=1778655973-2741`

## TL;DR for tomorrow

Two-thirds done. The cross-platform parity fixes are proven on macOS and Linux. Windows is one `pacman -S python-yaml` away from being fully proven; the only blocker is corporate WiFi blocking Tailscale to Shulgi. Resume by reaching Shulgi any way (different network, mobile hotspot, walking the box home), running the three-step recipe above, and confirming the 15 macOS/Linux platform-skips flip to PASS on Windows. Total resume effort: ~10 minutes.
