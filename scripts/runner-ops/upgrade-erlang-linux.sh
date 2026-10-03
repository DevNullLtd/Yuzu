#!/usr/bin/env bash
# upgrade-erlang-linux.sh — bring a self-hosted Linux GitHub Actions runner
# to a specified Erlang/OTP release globally.
#
# Written for runners installed via the standard /opt/actions-runner layout;
# it was last used on the retired yuzu-wsl2-linux runner and has not been
# checked against Big Tam's per-agent layout. Detects the runner directory,
# the systemd User=, and the runner home automatically.
#
# The runner-ops-upgrade-erlang.yml dispatch workflow that wrapped this script
# was removed when the Shulgi runners were retired (see #5300); run it by hand
# on the host.
#
# What it does:
#   1. Installs Erlang/OTP $OTP_VERSION + rebar3 $REBAR3_VERSION under the
#      runner user via kerl. Idempotent: skip-if-already-installed.
#   2. Rewrites <runner-dir>/.path so the systemd-launched runner picks up
#      the new toolchain. (The runner does NOT source ~/.bashrc; the .path
#      file is the only knob that lands in the runner's environment.)
#   3. Optionally restarts the runner systemd service. Skip with
#      --no-restart when running this script from inside a workflow on
#      the same runner — the restart would kill the running workflow;
#      the caller schedules a deferred restart instead.
#   4. Verifies erl + rebar3 versions resolve under the runner user.
#
# Why kerl (not apt / esl-erlang):
#   apt/esl tracks one version system-wide; kerl is per-user, version-
#   isolated, and matches what scripts/ensure-erlang.sh already probes
#   for. Bumping in the future is `./kerl build <newver> <newver>` plus
#   editing one PATH line.
#
# Usage:
#   bash scripts/runner-ops/upgrade-erlang-linux.sh [--yes] [--no-restart]
#
# Environment overrides:
#   OTP_VERSION       OTP release to install (default 28.4.2)
#   REBAR3_VERSION    rebar3 release to install (default 3.24.0)
#   RUNNER_DIR        runner install dir (default auto-detect, or
#                     /opt/actions-runner)
#
# Exit codes:
#   0  success
#   2  configuration error (no runner found, no User=, etc.)
#   3  runtime error (kerl build failed, service didn't come back, …)

set -euo pipefail

# ─── Argument parsing ─────────────────────────────────────────────────────
ASSUME_YES=0
DO_RESTART=1
for arg in "$@"; do
    case "$arg" in
        --yes|-y)         ASSUME_YES=1 ;;
        --no-restart)     DO_RESTART=0 ;;
        --help|-h)
            sed -n '/^#/,/^$/{/^#!/d; /^$/q; s/^# \?//; p}' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $arg" >&2
            echo "  See --help for usage." >&2
            exit 2
            ;;
    esac
done

# ─── Configuration ────────────────────────────────────────────────────────
OTP_VERSION="${OTP_VERSION:-28.4.2}"
REBAR3_VERSION="${REBAR3_VERSION:-3.24.0}"

# Runner discovery — try the canonical path first, fall back to a search.
RUNNER_DIR="${RUNNER_DIR:-/opt/actions-runner}"
if [[ ! -f "${RUNNER_DIR}/.runner" ]]; then
    found=$(find /opt /home /var -maxdepth 4 -name '.runner' -type f 2>/dev/null | head -1 || true)
    if [[ -z "$found" ]]; then
        echo "ERROR: cannot find an actions-runner installation. Set RUNNER_DIR= explicitly." >&2
        exit 2
    fi
    RUNNER_DIR=$(dirname "$found")
    echo "Auto-detected runner at: $RUNNER_DIR"
fi

# Find the systemd unit — pattern is actions.runner.<owner>-<repo>.<name>.service
SERVICE=$(systemctl list-units 'actions.runner.*.service' --all --no-legend 2>/dev/null \
            | awk '{print $1}' | head -1)
if [[ -z "$SERVICE" ]]; then
    echo "ERROR: no actions.runner.*.service found in systemd. Is the runner installed as a service?" >&2
    exit 2
fi

UNIT_FILE=$(systemctl show -p FragmentPath --value "$SERVICE")
if [[ -z "$UNIT_FILE" || ! -f "$UNIT_FILE" ]]; then
    echo "ERROR: cannot locate unit file for $SERVICE" >&2
    exit 2
fi
RUNNER_USER=$(awk -F= '/^User=/{print $2}' "$UNIT_FILE" | head -1)
if [[ -z "$RUNNER_USER" ]]; then
    echo "ERROR: $SERVICE has no User= directive (running as root?). Aborting; refuse to install kerl globally." >&2
    exit 2
fi
RUNNER_HOME=$(getent passwd "$RUNNER_USER" | cut -d: -f6)
if [[ -z "$RUNNER_HOME" || ! -d "$RUNNER_HOME" ]]; then
    echo "ERROR: cannot resolve home directory for user $RUNNER_USER" >&2
    exit 2
fi

# ─── Banner ───────────────────────────────────────────────────────────────
cat <<EOF

═══════════════════════════════════════════════════════════════════════════
  Upgrading runner to Erlang/OTP $OTP_VERSION
═══════════════════════════════════════════════════════════════════════════
  Hostname:     $(hostname)
  Runner dir:   $RUNNER_DIR
  Runner user:  $RUNNER_USER  (home: $RUNNER_HOME)
  Service:      $SERVICE
  rebar3:       $REBAR3_VERSION
  Restart:      $([[ $DO_RESTART -eq 1 ]] && echo "yes (in-script)" || echo "no (caller responsible)")

EOF

if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "Proceed? [y/N] " confirm
    [[ "$confirm" == "y" || "$confirm" == "Y" ]] || { echo "Aborted."; exit 0; }
fi

# ─── 1. Install OTP via kerl + rebar3 ─────────────────────────────────────
echo
echo "── Step 1/${DO_RESTART:+4}${DO_RESTART:-3}: installing OTP $OTP_VERSION + rebar3 $REBAR3_VERSION as $RUNNER_USER ──"
sudo -u "$RUNNER_USER" -H \
    OTP_VERSION="$OTP_VERSION" \
    REBAR3_VERSION="$REBAR3_VERSION" \
    bash -s <<'KERL'
set -euo pipefail

KERL_DIR="$HOME/.kerl"
INSTALL_DIR="$KERL_DIR/installs/$OTP_VERSION"
mkdir -p "$KERL_DIR"
cd "$KERL_DIR"

if [[ ! -x ./kerl ]]; then
    echo "  installing kerl ..."
    curl -fsSL -o kerl https://raw.githubusercontent.com/kerl/kerl/master/kerl
    chmod +x kerl
fi

if [[ ! -d "$INSTALL_DIR" ]]; then
    echo "  building OTP $OTP_VERSION (this is the slow part) ..."
    ./kerl update releases >/dev/null
    ./kerl build "$OTP_VERSION" "$OTP_VERSION"
    ./kerl install "$OTP_VERSION" "$INSTALL_DIR"
else
    echo "  OTP $OTP_VERSION already installed at $INSTALL_DIR — skipping build"
fi

mkdir -p "$HOME/.local/bin"
REBAR3="$HOME/.local/bin/rebar3"
if [[ ! -x "$REBAR3" ]]; then
    echo "  installing rebar3 $REBAR3_VERSION ..."
    curl -fsSL -o "$REBAR3" "https://github.com/erlang/rebar3/releases/download/${REBAR3_VERSION}/rebar3"
    chmod +x "$REBAR3"
else
    # Verify version through PATH-prepended OTP install (rebar3 is an
    # escript and needs `escript` discoverable on PATH).
    have=$(PATH="$INSTALL_DIR/bin:$PATH" "$REBAR3" --version 2>/dev/null \
             | grep -oE 'rebar [0-9]+\.[0-9]+\.[0-9]+' \
             | awk '{print $2}' || true)
    if [[ "$have" == "$REBAR3_VERSION" ]]; then
        echo "  rebar3 $REBAR3_VERSION already at $REBAR3 — skipping"
    else
        echo "  rebar3 $have at $REBAR3 — replacing with $REBAR3_VERSION"
        curl -fsSL -o "$REBAR3" "https://github.com/erlang/rebar3/releases/download/${REBAR3_VERSION}/rebar3"
        chmod +x "$REBAR3"
    fi
fi

echo "  done; installed:"
"$INSTALL_DIR/bin/erl" -eval 'io:format("    erl: OTP ~s~n", [erlang:system_info(otp_release)]), halt().' -noshell
echo "    $(PATH="$INSTALL_DIR/bin:$PATH" "$REBAR3" --version | head -1)"
KERL

# ─── 2. Rewrite .path so the systemd runner finds OTP $OTP_VERSION ────────
echo
echo "── Step 2/${DO_RESTART:+4}${DO_RESTART:-3}: updating $RUNNER_DIR/.path ──"
NEW_PATH="$RUNNER_HOME/.kerl/installs/$OTP_VERSION/bin:$RUNNER_HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
echo "  new PATH: $NEW_PATH"

if [[ -f "$RUNNER_DIR/.path" ]]; then
    sudo cp -a "$RUNNER_DIR/.path" "$RUNNER_DIR/.path.bak.$(date +%Y%m%d-%H%M%S)"
    echo "  backed up old .path"
fi

echo "PATH=$NEW_PATH" | sudo tee "$RUNNER_DIR/.path" >/dev/null
sudo chown --reference="$RUNNER_DIR/.runner" "$RUNNER_DIR/.path"

# ─── 3. Restart (or defer) ────────────────────────────────────────────────
if [[ $DO_RESTART -eq 1 ]]; then
    echo
    echo "── Step 3/4: restarting $SERVICE ──"
    sudo systemctl restart "$SERVICE"
    sleep 2
    if systemctl is-active --quiet "$SERVICE"; then
        echo "  service is active"
    else
        echo "ERROR: service failed to come back up. Check: sudo systemctl status $SERVICE" >&2
        exit 3
    fi
else
    echo
    echo "── Step 3/3: skipping restart (--no-restart) ──"
    echo "  Caller is responsible for restarting $SERVICE so the runner picks up"
    echo "  the new PATH. The new toolchain is staged but the running runner"
    echo "  process still has the OLD PATH in its environment."
    echo "  Recommended detached restart from a workflow:"
    echo "    sudo systemd-run --on-active=60s --no-block --quiet \\"
    echo "      /usr/bin/systemctl restart $SERVICE"
fi

# ─── 4. Verify ────────────────────────────────────────────────────────────
echo
echo "── Step ${DO_RESTART:+4/4}${DO_RESTART:-N/A}: verification ──"
ERL_BIN="$RUNNER_HOME/.kerl/installs/$OTP_VERSION/bin/erl"
REBAR3_BIN="$RUNNER_HOME/.local/bin/rebar3"

OTP_OUT=$(sudo -u "$RUNNER_USER" -H "$ERL_BIN" -eval \
    'io:format("OTP ~s~n", [erlang:system_info(otp_release)]), halt().' -noshell)
REBAR_OUT=$(sudo -u "$RUNNER_USER" -H \
    env "PATH=$RUNNER_HOME/.kerl/installs/$OTP_VERSION/bin:/usr/bin:/bin" \
    "$REBAR3_BIN" --version)

echo "  $OTP_OUT"
echo "  $REBAR_OUT"

ACTUAL_PATH=$(sudo cat "$RUNNER_DIR/.path")
if [[ "$ACTUAL_PATH" == "$NEW_PATH" ]]; then
    echo "  .path file: matches expected"
else
    echo "  WARNING: .path file content unexpected:"
    echo "  $ACTUAL_PATH"
fi

cat <<EOF

═══════════════════════════════════════════════════════════════════════════
  Done. Runner is staged for OTP $OTP_VERSION + rebar3 $REBAR3_VERSION.
═══════════════════════════════════════════════════════════════════════════

EOF
if [[ $DO_RESTART -eq 0 ]]; then
    echo "  ⚠️  Service NOT restarted — caller must restart $SERVICE for the"
    echo "     change to take effect. Old .path backup at:"
    echo "     $RUNNER_DIR/.path.bak.<timestamp>"
    echo
fi
