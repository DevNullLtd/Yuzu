#!/bin/bash
# register-bigmags-runner.sh — register ONE BigMags CI agent as a headless
# launchd service (system LaunchDaemon).
#
#   ./register-bigmags-runner.sh <index>        # index 0, 1, ...
#
# Run as an ADMIN user whose `gh` is authenticated with repo-admin rights (to
# mint the registration token). Runner file ops + config run as the dedicated
# non-admin `yuzuci`; the LaunchDaemon install needs root (via sudo).
#
# The service is a system LaunchDaemon, NOT the runner's own svc.sh: on macOS
# svc.sh installs a per-USER LaunchAgent that only runs while that user has an
# active GUI session, which the headless yuzuci account never has. A LaunchDaemon
# runs run.sh as yuzuci at boot with no login. (Phase B codesigning will need
# keychain access, which is fiddlier from a daemon — solve then.)
#
# Re-running for an existing index is safe: it refuses if a job is in flight
# (Runner.Worker live), otherwise boots out the idle daemon before reconfiguring.
# Validated end-to-end on BigMags (2026-08-17): both agents registered + online.
set -euo pipefail

REPO="DevNullLtd/Yuzu"
CI_USER="yuzuci"
CI_ROOT="/opt/ci"
POOL_LABELS="self-hosted,macOS,ARM64,yuzu-bigmags-macos"
# Latest actions/runner osx-arm64 release (override by exporting RUNNER_VERSION).
RUNNER_VERSION="${RUNNER_VERSION:-$(gh api repos/actions/runner/releases/latest --jq .tag_name | sed 's/^v//')}"

idx="${1:?usage: register-bigmags-runner.sh <index>}"
[[ "$idx" =~ ^[0-9]+$ ]] || { echo "index must be a non-negative integer (0, 1, ...)." >&2; exit 2; }
name="yuzu-bigmags-macos-${idx}"
rdir="${CI_ROOT}/actions-runner/r${idx}"
work="${CI_ROOT}/work-${idx}"
label="com.yuzu.ci-runner.r${idx}"

[ -n "$RUNNER_VERSION" ] || { echo "Could not resolve RUNNER_VERSION (gh api failed?)." >&2; exit 1; }

# --- drain gate: never reconfigure a runner mid-job --------------------------
# A live Runner.Worker means an active CI job — refuse (reconfiguring would kill
# it). A live-but-idle Runner.Listener (daemon up, no job) is fine: we boot the
# daemon out below before reconfiguring. Gating on the Listener instead would
# refuse EVERY re-run, since KeepAlive keeps a Listener alive whenever the
# service is up — the trap the earlier --force escape hatch fell into.
if pgrep -f "actions-runner/r${idx}/.*Runner.Worker" >/dev/null 2>&1; then
  echo "Agent r${idx} is running a job (Runner.Worker live) — refusing. Wait for it to finish." >&2
  exit 2
fi
# Stop an idle daemon so config.sh can reconfigure cleanly (no-op if not loaded).
sudo launchctl bootout "system/${label}" 2>/dev/null || true

# --- registration token (as the admin user with gh auth) ---------------------
echo "Minting registration token for ${REPO}…"
token="$(gh api -X POST "repos/${REPO}/actions/runners/registration-token" --jq .token)"
[ -n "$token" ] || { echo "Failed to mint registration token (is gh authed as a repo admin?)" >&2; exit 1; }

# --- lay down the runner (owned by yuzuci) -----------------------------------
sudo install -d -o "$CI_USER" -g staff "$rdir" "$work"
tarball="actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
url="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${tarball}"
echo "Downloading ${tarball}…"
sudo -u "$CI_USER" bash -c "cd '$rdir' && curl -fSL --retry 10 --retry-all-errors -o '$tarball' '$url' && tar xzf '$tarball' && rm -f '$tarball'"

# --- per-agent env / path (read by the runner at job start) ------------------
# RUNNER_TOOL_CACHE: shared vcpkg binary-cache root (also the telemetry root once
#   Phase 4 wires ci-telemetry into the macos job — not yet live).
# YUZU_BUILD_JOBS: per-agent build parallelism — tune against 24 GiB pressure;
#   drop to 4 if two concurrent cold builds swap.
# HOMEBREW_NO_AUTO_UPDATE: the "Install dependencies" step runs `brew` as yuzuci;
#   without this, brew git-pulls the prefix on every install (write access + a
#   network round-trip), so pin it off — steady-state installs are then a fast
#   no-op. (yuzuci must ALSO have write access to /opt/homebrew: see README §2.)
sudo -u "$CI_USER" tee "$rdir/.env" >/dev/null <<EOF
RUNNER_TOOL_CACHE=${CI_ROOT}/tool_cache
YUZU_BUILD_JOBS=6
HOMEBREW_NO_AUTO_UPDATE=1
EOF
# brew on PATH so the job's dependency-install step resolves brew/pipx/python3.
sudo -u "$CI_USER" tee "$rdir/.path" >/dev/null <<EOF
/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
EOF

# --- configure the runner with GitHub ----------------------------------------
echo "Configuring ${name}…"
sudo -u "$CI_USER" bash -c "cd '$rdir' && ./config.sh --unattended --replace \
  --url 'https://github.com/${REPO}' \
  --name '${name}' \
  --labels '${POOL_LABELS}' \
  --work '${work}' \
  --token '${token}'"

# From here the runner IS registered with GitHub. If the LaunchDaemon install
# fails, deregister so we don't leave a registered-but-offline runner that trips
# the inventory drift sentinel (strict_unknown_runners).
deregister_on_fail() {
  echo "LaunchDaemon install failed — deregistering ${name} to avoid a half-registered runner…" >&2
  # Tear the daemon + plist down too, or a reboot would crash-loop an unconfigured
  # run.sh (throttled to 30s but still spamming _diag).
  sudo launchctl bootout "system/${label}" 2>/dev/null || true
  sudo rm -f "${plist:-}" 2>/dev/null || true
  local rtok
  rtok="$(gh api -X POST "repos/${REPO}/actions/runners/remove-token" --jq .token 2>/dev/null || true)"
  [ -n "$rtok" ] && sudo -u "$CI_USER" bash -c "cd '$rdir' && ./config.sh remove --token '$rtok'" >/dev/null 2>&1 || true
}
trap deregister_on_fail ERR

# --- install the headless LaunchDaemon ---------------------------------------
echo "Installing LaunchDaemon ${label}…"
sudo -u "$CI_USER" mkdir -p "$rdir/_diag"
plist="/Library/LaunchDaemons/${label}.plist"
sudo tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <key>UserName</key><string>${CI_USER}</string>
  <key>WorkingDirectory</key><string>${rdir}</string>
  <key>ProgramArguments</key>
  <array><string>${rdir}/run.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <!-- Throttle respawns so a misconfig (bad .env, missing run.sh, perm flip)
       can't hot crash-loop and flood daemon.err.log / fill /opt/ci. -->
  <key>ThrottleInterval</key><integer>30</integer>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>${rdir}/_diag/daemon.out.log</string>
  <key>StandardErrorPath</key><string>${rdir}/_diag/daemon.err.log</string>
</dict>
</plist>
PLIST
sudo chown root:wheel "$plist"; sudo chmod 644 "$plist"
sudo launchctl bootstrap system "$plist"
trap - ERR
sleep 3
sudo launchctl print "system/${label}" | grep -iE 'state =|pid =' || true

echo "Registered ${name}. Confirm it reports 'online' with labels ${POOL_LABELS}"
echo "before merging the inventory rows (avoids sentinel UNKNOWN/OFFLINE drift)."
echo "Deregister:  sudo launchctl bootout system/${label} && \\"
echo "  (cd ${rdir} && sudo -u ${CI_USER} ./config.sh remove --token \"\$(gh api -X POST repos/${REPO}/actions/runners/remove-token --jq .token)\")"
