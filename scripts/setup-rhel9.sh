#!/usr/bin/env bash
#
# setup-rhel9.sh — bootstrap the Yuzu C++ build toolchain on RHEL 9 / Rocky 9 / AlmaLinux 9.
#
# The repo's CI only exercises Ubuntu, macOS and Windows; this script is the
# enterprise-Linux equivalent of the apt recipe in .github/workflows/ci.yml.
# It is idempotent: re-running it makes no changes on an already-provisioned box.
#
# Runbook + rationale:  docs/rhel9-build-setup.md
#
# Usage:
#   bash scripts/setup-rhel9.sh                    # toolchain + vcpkg
#   bash scripts/setup-rhel9.sh --with-postgres    # ... plus a local PG 18 for the server tests
#   bash scripts/setup-rhel9.sh --with-postgres --adopt-cluster   # ... managing a cluster it did not create
#   bash scripts/setup-rhel9.sh --with-epel        # ... plus EPEL, for the optional ccache
#   bash scripts/setup-rhel9.sh --check            # verify only, change nothing
#   bash scripts/setup-rhel9.sh --manifest out.json
#
# Other flags: --skip-vcpkg, --vcpkg-root DIR, --dry-run
#
set -euo pipefail

# --- Constants ---------------------------------------------------------------

# The vcpkg baseline is READ FROM vcpkg.json rather than duplicated here.
# Hardcoding it would (a) rot the moment the baseline is bumped and (b) add an
# untracked copy that .github/workflows/vcpkg-baseline-update.yml does not
# rewrite — which deploy/windows/Test-ToolchainContract.ps1 rightly fails on
# ("the baseline updater covers every active tracked SHA reference").
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolved lazily (needs python3 + a readable vcpkg.json): --help must work on
# a bare box before any dependency exists, and a failure here must be loud,
# never a silent set -e abort (that class shipped defects twice in review).
VCPKG_COMMIT=""
resolve_vcpkg_commit() {
  [ -n "${VCPKG_COMMIT}" ] && return 0
  VCPKG_COMMIT="$(python3 -c '
import json, sys
path = sys.argv[1]
try:
    print(json.load(open(path))["builtin-baseline"])
except Exception as exc:
    sys.exit(f"cannot read builtin-baseline from {path}: {exc}")
' "${REPO_ROOT}/vcpkg.json")" || VCPKG_COMMIT=""
  [ -n "${VCPKG_COMMIT}" ] || die "could not resolve the vcpkg baseline from ${REPO_ROOT}/vcpkg.json (python3 present? file readable?)"
}

# GCC 13+ is the documented floor (README "Prerequisites"). RHEL 9's system GCC
# is 11, so the compiler must come from a gcc-toolset Software Collection.
GCC_TOOLSET="gcc-toolset-14"

# Rocky's dnf meson is 0.63.3, below the meson_version '>=1.3.0' floor in
# meson.build, so meson comes from pip. CI pins meson in requirements-ci.txt;
# from 1.12.0 meson's Requires-Python is >=3.10 and RHEL 9's python3 is 3.9,
# so this recipe deliberately trails on the last release that installs under
# 3.9. The build is unaffected (the floor is 1.3.0). Step 3 warns while the
# two differ; following the CI pin via AppStream's python3.12 is issue #3696.
# PyYAML matches the CI pin.
MESON_VERSION="1.11.2"
PYYAML_VERSION="6.0.3"

# AppStream module stream. 18 matches the server substrate (ADR-0006).
PG_STREAM="18"
# Address/role/db match the native-cluster branch of scripts/ci/ensure-postgres.sh.
PG_DSN="postgresql://yuzu:yuzu@127.0.0.1:5432/yuzu_test"
PGDATA="/var/lib/pgsql/data"
# Ownership marker, deliberately OUTSIDE PGDATA (backups and replica bootstraps
# copy PGDATA). It holds the cluster's pg_control system identifier, so consent
# is bound to the CLUSTER, not the path: a cluster replaced at PGDATA does not
# inherit it. Written only after this script's own initdb completes, or on
# --adopt-cluster. The ident->scram flip, the role password and the
# pg_signal_backend grant are cluster-wide mutations: they happen only on a
# cluster whose identity matches this marker. Anything else is verified, never
# changed.
PG_MARK="/var/lib/pgsql/.yuzu-provisioned"
PG_OWNED=0
# Loopback `all all` lines still on ident. Anchored at the end so `ident map=x`
# is neither matched nor rewritten; shared by the grep and the sed below.
HBA_IDENT_RE='^(host[[:space:]]+all[[:space:]]+all[[:space:]]+(127\.0\.0\.1/32|::1/128)[[:space:]]+)ident[[:space:]]*$'

# ccache is deliberately NOT in PKGS: on the RHEL 9 family it exists only in
# EPEL (verified — it is in neither BaseOS, AppStream nor CRB), and enabling
# EPEL on a managed work machine is a policy decision, not a build requirement.
# It is optional: without it the env file falls back to plain gcc/g++.
CCACHE_PKG="ccache"

PKGS=(
  # C++23 compiler (GCC 14 + its own libstdc++ 14 headers)
  "${GCC_TOOLSET}"
  # build tooling
  cmake ninja-build pkgconf-pkg-config make
  # vcpkg port build prerequisites
  bison flex autoconf automake libtool
  perl perl-IPC-Cmd perl-FindBin perl-File-Compare perl-Pod-Html
  # headers the build links against. libblkid-devel: the bitlocker plugin takes
  # a required blkid dependency on Linux (agents/plugins/bitlocker/meson.build),
  # CI installs libblkid-dev; it is not pulled in transitively.
  systemd-devel glibc-devel kernel-headers libblkid-devel
  # python + archive tools vcpkg needs. curl is deliberately NOT listed: stock
  # images ship curl-minimal, which provides /usr/bin/curl but does not satisfy
  # `rpm -q curl`, and asking dnf for the full package on top of it is a
  # conflict that aborts the run. It is checked by capability below.
  python3-pip zip unzip tar git
)

ENV_FILE="${HOME}/.config/yuzu/toolchain-env.sh"

# --- Options -----------------------------------------------------------------

WITH_POSTGRES=0
ADOPT_CLUSTER=0
WITH_EPEL=0
SKIP_VCPKG=0
CHECK_ONLY=0
DRY_RUN=0
MANIFEST=""
VCPKG_ROOT_ARG="${VCPKG_ROOT:-${HOME}/vcpkg}"
VCPKG_ROOT_EXPLICIT=0

usage() {
  # The header comment up to (not including) the `set -euo pipefail` line.
  sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --with-postgres) WITH_POSTGRES=1 ;;
    --adopt-cluster) ADOPT_CLUSTER=1 ;;
    --with-epel)     WITH_EPEL=1 ;;
    --skip-vcpkg)    SKIP_VCPKG=1 ;;
    --check)         CHECK_ONLY=1 ;;
    --dry-run)       DRY_RUN=1 ;;
    --vcpkg-root)    VCPKG_ROOT_ARG="${2:?--vcpkg-root needs a path}"; VCPKG_ROOT_EXPLICIT=1; shift ;;
    --manifest)      MANIFEST="${2:?--manifest needs a path}"; shift ;;
    -h|--help)       usage ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

# --- Output helpers ----------------------------------------------------------

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else B=""; G=""; Y=""; R=""; N=""; fi

step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
# Under --dry-run the `run` wrapper prints and no-ops, so the success line
# that follows it must not claim the action happened; it says what a real run
# would then report. --check is read-only and reports real results.
ok() {
  if [ "$DRY_RUN" = 1 ] && [ "$CHECK_ONLY" = 0 ]; then
    printf '  (dry-run) would then report: %s\n' "$*"; return 0
  fi
  printf '  %s[ ok ]%s %s\n' "$G" "$N" "$*"
}
skip() { printf '  %s[skip]%s %s\n' "$Y" "$N" "$*"; }
warn() { printf '  %s[warn]%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '  %s[fail]%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" = 1 ]; then printf '  (dry-run) %s\n' "$*"; return 0; fi
  "$@"
}

# Privileged read-only predicates (sudo test/grep/psql) would prompt for a
# password under --dry-run, so they are not run: the dry run reports each one
# and assumes the step it guards is needed (--assume-true for the one site
# where a true predicate is the act arm). Reported on stderr because several
# callers pipe stdout into grep. Live runs drop the probe's stderr; a sudo
# prompt goes to the tty, not stderr, so it is never hidden.
probe() { # probe [--assume-true] <predicate-cmd...>
  local dry_status=1
  if [ "$1" = --assume-true ]; then dry_status=0; shift; fi
  if [ "$DRY_RUN" = 1 ]; then
    printf '  (dry-run) not probing, assuming the step is needed: %s\n' "$*" >&2
    return "$dry_status"
  fi
  "$@" 2>/dev/null
}

# True when the cluster answers on the DSN this script exports. It is the ONLY
# thing that puts YUZU_TEST_POSTGRES_DSN into the env file (via PG_VERIFIED):
# an exported-but-unreachable DSN turns every [pg] test from a clean skip into
# a hard failure (CLAUDE.md skip-vs-fail contract).
pg_answers() { psql "${PG_DSN}" -v ON_ERROR_STOP=1 -tAc 'SELECT 1' 2>/dev/null | grep -qx 1; }
# The durable identity of the cluster at PGDATA: survives restarts, changes on
# re-initdb. pg_controldata reads it from disk, so it works with the server
# stopped.
# LC_ALL=C pins the label this parses. In a rockylinux:9 container de/fr
# langpacks leave the output English, but container images may strip %lang
# catalogs via _install_langs, so a real host can carry translations - and
# sudoers env_keep passes LANG/LC_* through. Either way the pin makes the
# match immune.
pg_sysid() { sudo -u postgres env LC_ALL=C pg_controldata "${PGDATA}" 2>/dev/null | awk '/^Database system identifier:/ {print $NF}'; }
# Reachability is not identity: something else could be listening on
# 127.0.0.1:5432. Returns 0 when the DSN's listener is the cluster at PGDATA
# (same pg_control system identifier - a session-invariant bigint any role can
# read, unlike timestamp TEXT, which renders per-session), 1 when it is a
# different cluster, 2 when the local identity cannot be read (sudo or
# pg_controldata unavailable).
pg_same_cluster() {
  local a b
  a="$(pg_sysid)"
  [ -n "$a" ] || return 2
  b="$(psql "${PG_DSN}" -tAc 'SELECT system_identifier FROM pg_control_system()' 2>/dev/null)" || return 1
  [ "$a" = "$b" ]
}
PG_VERIFIED=0
PG_KEPT_UNVERIFIED=0

FAILURES=0
check() { # check <label> <condition-cmd...>
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$label"; else
    printf '  %s[fail]%s %s\n' "$R" "$N" "$label" >&2
    FAILURES=$((FAILURES + 1))
  fi
}

# The one check that proves the toolset's libstdc++ is in play rather than the
# system libstdc++ 11: <expected> is C++23, absent from 11 and present from 12
# on, so the documented GCC 13 floor passes too. (<print> is deliberately not
# used: the project does not use it and libstdc++ 13 lacks it.) Subshell body
# so the EXIT trap is scoped to this call; the status is the compile+run
# chain's, never the cleanup's.
cxx23_probe() (
  d="$(mktemp -d)" || exit 1
  # shellcheck disable=SC2154  # rc is assigned inside the trap string
  trap 'rc=$?; rm -rf -- "$d"; exit "$rc"' EXIT
  printf '#include <expected>\nint main(){std::expected<int,int> e{1}; return e.value() == 1 ? 0 : 1;}\n' > "$d/c23.cpp" \
    && g++ -std=c++23 "$d/c23.cpp" -o "$d/c23" \
    && "$d/c23"
)

if [ "$ADOPT_CLUSTER" = 1 ] && [ "$WITH_POSTGRES" = 0 ]; then
  die "--adopt-cluster does nothing without --with-postgres; pass both."
fi

# --- Distro gate -------------------------------------------------------------

[ -r /etc/os-release ] || die "no /etc/os-release — unsupported system"
# shellcheck disable=SC1091
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_MAJOR="${VERSION_ID:-}"; DISTRO_MAJOR="${DISTRO_MAJOR%%.*}"

case "${DISTRO_ID}" in
  rhel|rocky|almalinux) ;;
  *) die "unsupported distro '${DISTRO_ID}' — this script targets RHEL/Rocky/Alma 9. \
Ubuntu users: follow the apt recipe in .github/workflows/ci.yml." ;;
esac
[ "${DISTRO_MAJOR}" = "9" ] || die "unsupported release ${VERSION_ID:-?} — this script targets the 9.x line"

ARCH="$(uname -m)"
[ "${ARCH}" = "x86_64" ] || warn "arch ${ARCH}: only x86_64 has been verified (vcpkg.json filters catch2 to x64|arm64)"

step "Target: ${PRETTY_NAME:-${DISTRO_ID} ${VERSION_ID}} (${ARCH})"

# ============================================================================
#  --check : verify an already-provisioned box, change nothing
# ============================================================================

if [ "$CHECK_ONLY" = 1 ]; then
  step "Verifying toolchain (no changes will be made)"

  # shellcheck disable=SC1090
  [ -f "$ENV_FILE" ] && . "$ENV_FILE"
  # A custom root recorded in the env file beats the $HOME default; an explicit
  # --vcpkg-root beats both. Without this, --check silently verified ~/vcpkg.
  [ "$VCPKG_ROOT_EXPLICIT" = 1 ] || VCPKG_ROOT_ARG="${VCPKG_ROOT:-${HOME}/vcpkg}"

  check "${GCC_TOOLSET} present"           test -f "/opt/rh/${GCC_TOOLSET}/enable"
  check "g++ is GCC 13+"                   bash -c 'v=$(g++ -dumpfullversion -dumpversion 2>/dev/null | cut -d. -f1); [ -n "$v" ] && [ "$v" -ge 13 ]'
  check "C++23 <expected> compile"         cxx23_probe
  check "meson ${MESON_VERSION}"           bash -c "meson --version | grep -qx '${MESON_VERSION}'"
  check "ninja present"                    command -v ninja
  check "cmake present"                    command -v cmake
  check "pkg-config present"               command -v pkg-config
  check "bison present"                    command -v bison
  check "flex present"                     command -v flex
  check "perl present"                     command -v perl
  check "curl present"                     command -v curl
  check "pyyaml ${PYYAML_VERSION}"           python3 -c "import yaml, sys; sys.exit(yaml.__version__ != '${PYYAML_VERSION}')"
  # Every PKGS entry by rpm name (perl modules and header packages have no
  # binary for command -v): a green --check must not precede a vcpkg-port
  # failure on a missing autotool.
  MISSING_RPMS="$(for p in "${PKGS[@]}"; do rpm -q "$p" >/dev/null 2>&1 || printf '%s ' "$p"; done)"
  check "all ${#PKGS[@]} PKGS rpms installed"  test -z "${MISSING_RPMS}"
  [ -z "${MISSING_RPMS}" ] || printf '         missing: %s\n' "${MISSING_RPMS}" >&2
  check "libsystemd headers present"       pkg-config --exists libsystemd
  check "libblkid headers present"         pkg-config --exists blkid
  if [ "$SKIP_VCPKG" = 1 ]; then
    skip "vcpkg checks (--skip-vcpkg)"
  else
    resolve_vcpkg_commit
    check "VCPKG_ROOT set and bootstrapped"  test -x "${VCPKG_ROOT_ARG}/vcpkg"
    check "vcpkg pinned to baseline"         test "$(git -C "${VCPKG_ROOT_ARG}" rev-parse HEAD 2>/dev/null)" = "${VCPKG_COMMIT}"
  fi

  if [ "$WITH_POSTGRES" = 1 ]; then
    check "env file exports the DSN"       grep -qxF "export YUZU_TEST_POSTGRES_DSN=\"${PG_DSN}\"" "${ENV_FILE}"
    export YUZU_TEST_POSTGRES_DSN="${PG_DSN}"   # the checks below target the canonical DSN
    check "postgresql service active"      systemctl is-active --quiet postgresql
    check "DSN connects"                   bash -c 'psql "$YUZU_TEST_POSTGRES_DSN" -tAc "SELECT 1" | grep -qx 1'
    check "test role has CREATEDB"         bash -c 'psql "$YUZU_TEST_POSTGRES_DSN" -tAc "SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user" | grep -qx t'
    check "test role has pg_signal_backend" bash -c 'psql "$YUZU_TEST_POSTGRES_DSN" -tAc "SELECT pg_has_role(current_user, '"'"'pg_signal_backend'"'"', '"'"'member'"'"')" | grep -qx t'
    check "no leaked yuzu_test_* databases" bash -c 'psql "$YUZU_TEST_POSTGRES_DSN" -tAc "SELECT count(*) FROM pg_database WHERE datname LIKE '"'"'yuzu\_test\_%'"'"'" | grep -qx 0'
  fi

  if [ "$FAILURES" -gt 0 ]; then
    printf '\n%s%d check(s) failed.%s Re-run without --check to provision.\n' "$R" "$FAILURES" "$N" >&2
    exit 1
  fi
  printf '\n%sAll checks passed.%s\n' "$G" "$N"
  exit 0
fi

# ============================================================================
#  Provision
# ============================================================================

# Everything below escalates through sudo. A stock container image or a minimal
# install has none, and the failure would otherwise be a bare "command not
# found" several steps in. --dry-run never escalates, so it is exempt.
[ "$DRY_RUN" = 1 ] || command -v sudo >/dev/null 2>&1 || die "sudo is required (as root: dnf install -y sudo)"

# --- 1. Repositories ---------------------------------------------------------
#
# ninja-build lives in CRB (CodeReady Builder / PowerTools), which is
# shipped-but-disabled on Rocky/Alma and subscription-gated on RHEL. This is the
# single biggest RHEL-vs-Rocky divergence in the whole setup. (ccache is one
# repo further out - EPEL, not CRB; see CCACHE_PKG above.)

# Detected by effect as well as by repo id: a corporate mirror or Satellite
# names the repo whatever it likes, and what matters is that ninja-build
# resolves.
crb_enabled() {
  dnf repolist --enabled 2>/dev/null | grep -qiE '^(crb|codeready-builder)' \
    || dnf --quiet repoquery --qf '%{name}' ninja-build 2>/dev/null | grep -qx ninja-build
}
epel_enabled() {
  dnf repolist --enabled 2>/dev/null | grep -qE '^epel[[:space:]]' \
    || dnf --quiet repoquery --qf '%{name}' "${CCACHE_PKG}" 2>/dev/null | grep -qx "${CCACHE_PKG}"
}

step "Enabling repositories (CRB)"
if crb_enabled; then
  skip "CRB already enabled (ninja-build resolves)"
else
  run sudo dnf install -y dnf-plugins-core
  case "${DISTRO_ID}" in
    rhel)
      run sudo subscription-manager repos --enable "codeready-builder-for-rhel-9-${ARCH}-rpms" \
        || die "could not enable CRB. On RHEL this requires an active subscription; \
enable 'codeready-builder-for-rhel-9-${ARCH}-rpms' by hand and re-run."
      ;;
    rocky|almalinux)
      run sudo dnf config-manager --set-enabled crb
      ;;
  esac
  [ "$DRY_RUN" = 1 ] || crb_enabled \
    || die "CRB still not reachable: ninja-build does not resolve from any enabled repo. Enable CodeReady Builder (or your mirror of it) by hand and re-run."
  ok "CRB enabled"
fi

# EPEL is NOT required to build. Every mandatory package resolves from
# BaseOS/AppStream/CRB. It is needed only for optional extras: ccache (verified
# EPEL-only on this family), mold, and Erlang for the gateway.
if [ "$WITH_EPEL" = 1 ]; then
  step "Enabling EPEL (for ccache)"
  if epel_enabled; then
    skip "EPEL already enabled (${CCACHE_PKG} resolves)"
  else
    case "${DISTRO_ID}" in
      rhel) run sudo dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" ;;
      *)    run sudo dnf install -y epel-release ;;
    esac
    [ "$DRY_RUN" = 1 ] || epel_enabled \
      || die "EPEL still not reachable: ${CCACHE_PKG} does not resolve from any enabled repo. Enable EPEL (or your mirror of it) by hand and re-run."
    ok "EPEL enabled"
  fi
fi

# --- 2. System packages ------------------------------------------------------

step "Installing system packages"
MISSING=()
for p in "${PKGS[@]}"; do rpm -q "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
# curl by capability, not RPM name (curl-minimal satisfies it; see PKGS).
command -v curl >/dev/null 2>&1 || MISSING+=(curl)
if [ ${#MISSING[@]} -eq 0 ]; then
  skip "all ${#PKGS[@]} packages already installed"
else
  printf '  installing: %s\n' "${MISSING[*]}"
  run sudo dnf install -y "${MISSING[@]}"
  ok "installed ${#MISSING[@]} package(s)"
fi

TOOLSET_ENABLE="/opt/rh/${GCC_TOOLSET}/enable"
[ -f "${TOOLSET_ENABLE}" ] || [ "$DRY_RUN" = 1 ] || die "${TOOLSET_ENABLE} missing after install"

# ccache: optional, EPEL-only. Not a hard failure — the env file adapts.
if rpm -q "${CCACHE_PKG}" >/dev/null 2>&1; then
  skip "${CCACHE_PKG} already installed"
elif dnf --quiet repoquery --qf '%{name}' "${CCACHE_PKG}" 2>/dev/null | grep -qx "${CCACHE_PKG}"; then
  run sudo dnf install -y "${CCACHE_PKG}"
  ok "${CCACHE_PKG} installed (optional)"
else
  warn "${CCACHE_PKG} not available in any enabled repo — it lives in EPEL on this distro family."
  warn "  Building without it works fine, just slower on rebuilds. Re-run with --with-epel to get it."
fi

# --- 3. Python build tooling -------------------------------------------------
#
# PyYAML is a HARD configure-time dependency: server/core/meson.build runs
# `python3 -c 'import yaml'` and hard-errors if it fails (content embedding).

step "Installing Python build tooling (meson ${MESON_VERSION}, pyyaml ${PYYAML_VERSION})"
# Make the deviation from CI visible instead of silent (same awk as ci.yml).
CI_MESON=""
if [ -r "${REPO_ROOT}/requirements-ci.txt" ]; then
  CI_MESON="$(awk '/^meson==/ {print $1}' "${REPO_ROOT}/requirements-ci.txt")" || CI_MESON=""
  CI_MESON="${CI_MESON#meson==}"
fi
[ -z "${CI_MESON}" ] || [ "${CI_MESON}" = "${MESON_VERSION}" ] \
  || warn "CI pins meson ${CI_MESON}; this recipe installs ${MESON_VERSION} (RHEL 9 python3 is 3.9, see #3696)"
if python3 -c "
import sys
try:
    import mesonbuild, yaml
except ImportError:
    sys.exit(1)
sys.exit(yaml.__version__ != '${PYYAML_VERSION}')
" 2>/dev/null && "${HOME}/.local/bin/meson" --version 2>/dev/null | grep -qx "${MESON_VERSION}"; then
  skip "meson ${MESON_VERSION} and pyyaml ${PYYAML_VERSION} already present"
else
  run python3 -m pip install --user --upgrade pip
  run python3 -m pip install --user "meson==${MESON_VERSION}" "pyyaml==${PYYAML_VERSION}"
  ok "meson + pyyaml installed to ~/.local"
fi

# --- 4. Shell environment ----------------------------------------------------
#
# gcc-toolset is a Software Collection: it must be activated per shell. Inside
# the collection the binaries are plain `gcc`/`g++`, NOT `gcc-14`/`g++-14`.

step "Writing ${ENV_FILE}"
# The env file is sourced by every new shell, so a user-supplied path goes in
# shell-quoted (%q), never raw: a `"` or `$(` in --vcpkg-root would otherwise
# execute at every login.
VCPKG_ROOT_Q="$(printf '%q' "${VCPKG_ROOT_ARG}")"
render_env_file() {
  cat <<EOF
# Yuzu build toolchain environment (RHEL/Rocky/Alma 9).
# Generated by scripts/setup-rhel9.sh — safe to source repeatedly.
# Manual use:  source ${ENV_FILE}

# GCC 14 (Software Collection). Guarded so repeated sourcing does not stack PATH entries.
case ":\${PATH}:" in
  *:/opt/rh/${GCC_TOOLSET}/root/usr/bin:*) ;;
  *) [ -f ${TOOLSET_ENABLE} ] && . ${TOOLSET_ENABLE} ;;
esac

# meson (pip --user)
case ":\${PATH}:" in
  *:"\$HOME/.local/bin":*) ;;
  *) PATH="\$HOME/.local/bin:\$PATH" ;;
esac
export PATH

export VCPKG_ROOT=${VCPKG_ROOT_Q}

# ccache wrappers, matching .github/workflows/ci.yml. ccache is EPEL-only on
# RHEL/Rocky/Alma, so fall back to the bare compilers when it is absent.
if command -v ccache >/dev/null 2>&1; then
  export CC="ccache gcc"
  export CXX="ccache g++"
else
  export CC="gcc"
  export CXX="g++"
fi

# vcpkg's .pc files, for the repo checkout the build runs in. spdlog/fmt and
# friends resolve via pkg-config first (CLAUDE.md "Manual configure" marks both
# paths load-bearing); today the cmake fallback happens to chain them, but that
# is the port's courtesy, not a contract. yz_pkgconfig is a function so it
# tracks whichever repo you cd into; PREPENDED so vcpkg's .pc files win, with
# any existing entries kept (the gcc-toolset enable script exports its own
# PKG_CONFIG_PATH).
yz_pkgconfig() {
  local d="\$PWD/vcpkg_installed/x64-linux/lib/pkgconfig"
  [ -d "\$d" ] || { echo "no \$d - run vcpkg install (or scripts/setup.sh) from the repo root first" >&2; return 1; }
  case ":\${PKG_CONFIG_PATH:-}:" in
    *:"\$d":*) ;;
    *) export PKG_CONFIG_PATH="\$d\${PKG_CONFIG_PATH:+:\$PKG_CONFIG_PATH}" ;;
  esac
}
EOF
  if [ "$PG_VERIFIED" = 1 ]; then
    cat <<EOF

# PostgreSQL-backed server tests (--with-postgres). Unset DSN => those tests
# skip cleanly; set-but-broken => hard FAIL (CLAUDE.md contract). Written only
# after the cluster answered on this DSN; dropped again by a run without
# --with-postgres.
export YUZU_TEST_POSTGRES_DSN="${PG_DSN}"
EOF
  else
    cat <<EOF

# PostgreSQL: not configured by this run. --with-postgres provisions a local
# cluster and exports YUZU_TEST_POSTGRES_DSN here once it is verified reachable.
EOF
  fi
}

# Installs the rendered file only when its content changed (temp + cmp + mv):
# a re-run is a no-op, and a failed render never leaves a truncated file.
write_env_file() {
  local tmp
  mkdir -p "$(dirname "${ENV_FILE}")"
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  render_env_file > "$tmp" || { rm -f "$tmp"; die "could not render ${ENV_FILE}"; }
  if [ -f "${ENV_FILE}" ] && cmp -s "$tmp" "${ENV_FILE}"; then
    rm -f "$tmp"
    skip "environment file unchanged"
  else
    chmod 0644 "$tmp"
    mv -f "$tmp" "${ENV_FILE}"
    ok "environment file written"
  fi
}

if [ "$DRY_RUN" = 0 ]; then
  # Under --with-postgres the DSN line survives only if the cluster answers on
  # it right now AND is the cluster at PGDATA. When the identity cannot be
  # read (say, an expired sudo cache on a re-run), a previously verified
  # export is kept rather than withdrawn - but never a new one added.
  if [ "$WITH_POSTGRES" = 1 ] && pg_answers; then
    pg_same_cluster && SAME=0 || SAME=$?
    if [ "${SAME}" = 0 ]; then
      PG_VERIFIED=1
    elif [ "${SAME}" = 2 ] && grep -qxF "export YUZU_TEST_POSTGRES_DSN=\"${PG_DSN}\"" "${ENV_FILE}" 2>/dev/null; then
      warn "cannot re-verify the DSN's cluster identity (sudo or pg_controldata unavailable); the previously verified export is KEPT, not re-verified"
      PG_KEPT_UNVERIFIED=1
      PG_VERIFIED=1   # render keeps the existing line; the step-6 gate still reports honestly
    fi
  fi
  write_env_file

  if grep -q 'yuzu/toolchain-env.sh' "${HOME}/.bashrc" 2>/dev/null; then
    skip "~/.bashrc hook already present"
  else
    cat >> "${HOME}/.bashrc" <<EOF

# >>> yuzu toolchain >>>
[ -f "${ENV_FILE}" ] && . "${ENV_FILE}"
# <<< yuzu toolchain <<<
EOF
    ok "~/.bashrc hook added"
  fi
else
  printf '  (dry-run) write %s\n' "${ENV_FILE}"
fi

# --- 5. vcpkg ----------------------------------------------------------------

if [ "$SKIP_VCPKG" = 1 ]; then
  step "vcpkg: skipped (--skip-vcpkg)"
else
  step "Provisioning vcpkg at ${VCPKG_ROOT_ARG}"
  if [ -d "${VCPKG_ROOT_ARG}/.git" ]; then
    skip "clone already present"
  else
    run git clone https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT_ARG}"
  fi
  resolve_vcpkg_commit
  if [ "$(git -C "${VCPKG_ROOT_ARG}" rev-parse HEAD 2>/dev/null)" = "${VCPKG_COMMIT}" ]; then
    skip "already at pinned baseline ${VCPKG_COMMIT:0:12}"
  else
    run git -C "${VCPKG_ROOT_ARG}" fetch --quiet origin
    run git -C "${VCPKG_ROOT_ARG}" checkout --quiet "${VCPKG_COMMIT}"
    ok "checked out ${VCPKG_COMMIT:0:12}"
  fi
  if [ -x "${VCPKG_ROOT_ARG}/vcpkg" ]; then
    skip "already bootstrapped"
  else
    run "${VCPKG_ROOT_ARG}/bootstrap-vcpkg.sh" -disableMetrics
    ok "bootstrapped"
  fi
fi

# --- 6. PostgreSQL (optional) ------------------------------------------------
#
# Only needed to RUN the server test suite's [pg] tests. The address/role/db
# below match the native-cluster branch of scripts/ci/ensure-postgres.sh.

if [ "$WITH_POSTGRES" = 1 ]; then
  step "Provisioning PostgreSQL ${PG_STREAM} for the server test suite"

  if rpm -q postgresql-server >/dev/null 2>&1; then
    PG_INSTALLED="$(rpm -q --qf '%{VERSION}' postgresql-server)"
    # A server of another major (RHEL 9's AppStream default is 13) would
    # otherwise be accepted silently, breaking the "PostgreSQL 18" promise.
    [ "${PG_INSTALLED%%.*}" = "${PG_STREAM}" ] \
      || die "postgresql-server ${PG_INSTALLED} is installed; this recipe needs the postgresql:${PG_STREAM} stream (ADR-0006). Remove it, or enable the ${PG_STREAM} stream and upgrade, then re-run."
    skip "postgresql-server ${PG_INSTALLED} already installed"
    rpm -q postgresql-contrib >/dev/null 2>&1 || run sudo dnf install -y postgresql-contrib
  else
    run sudo dnf -qy module enable "postgresql:${PG_STREAM}"
    run sudo dnf install -y postgresql-server postgresql-contrib
    ok "postgresql ${PG_STREAM} installed"
  fi

  if [ "$DRY_RUN" = 1 ]; then
    printf '  (dry-run) %s cannot be inspected without sudo: the lines below describe a run on a box\n  with no existing cluster, which this script then owns. On any other cluster a real run\n  verifies, warns and stops - it changes nothing without --adopt-cluster.\n' "${PGDATA}"
  fi

  if probe sudo test -f "${PGDATA}/PG_VERSION"; then
    # initdb writes PG_VERSION and the config files BEFORE the bootstrap run
    # that creates global/pg_control, and pg_control cannot live outside
    # PGDATA - so its absence alone marks an interrupted initdb, while a
    # legitimately relocated postgresql.conf (-c config_file=) passes.
    probe sudo test -f "${PGDATA}/global/pg_control" \
      || die "${PGDATA} has PG_VERSION but no global/pg_control: an interrupted initdb. If this cluster is not yours, investigate by hand; if it was an interrupted initdb, clear the directory and re-run."
    skip "data directory already initialised"
  else
    run sudo /usr/bin/postgresql-setup --initdb
    if [ "$DRY_RUN" = 1 ]; then
      printf "  (dry-run) record the new cluster's identity in %s\n" "${PG_MARK}"
    else
      pg_sysid | sudo -u postgres tee "${PG_MARK}" >/dev/null || true
      sudo test -s "${PG_MARK}" || die "could not record the cluster identity in ${PG_MARK}"
    fi
    PG_OWNED=1
    ok "initdb complete (cluster created by this script; identity recorded in ${PG_MARK})"
  fi

  if [ "$PG_OWNED" = 1 ] || [ "$DRY_RUN" = 1 ]; then
    PG_OWNED=1   # dry-run narrates the fresh-box arm declared above
  else
    CUR_SYSID="$(pg_sysid)" || CUR_SYSID=""
    MARK_SYSID="$(sudo cat "${PG_MARK}" 2>/dev/null | tr -d '[:space:]')" || MARK_SYSID=""
    if [ -z "${CUR_SYSID}" ]; then
      warn "cannot read the cluster identity at ${PGDATA} (sudo or pg_controldata unavailable); treating it as not managed by this script"
    elif [ "${CUR_SYSID}" = "${MARK_SYSID}" ]; then
      PG_OWNED=1
    elif [ "$ADOPT_CLUSTER" = 1 ]; then
      warn "--adopt-cluster: taking over the cluster at ${PGDATA} (identity ${CUR_SYSID}); its loopback auth, role 'yuzu' and that role's password are managed by this script from now on"
      printf '%s\n' "${CUR_SYSID}" | sudo -u postgres tee "${PG_MARK}" >/dev/null \
        || die "could not record consent in ${PG_MARK}"
      PG_OWNED=1
    elif [ -n "${MARK_SYSID}" ]; then
      warn "${PG_MARK} names a different cluster (recorded ${MARK_SYSID}, found ${CUR_SYSID}): the cluster at ${PGDATA} was replaced since consent was given (a re-initdb, a restore, or a major-version upgrade). It is verified below, never changed (pass --adopt-cluster to manage THIS cluster)."
    else
      warn "${PGDATA} was not created by this script: it is verified below, never changed (pass --adopt-cluster to let this script manage it)"
    fi
  fi

  if probe systemctl is-active --quiet postgresql; then
    skip "postgresql already running"
  elif [ "$PG_OWNED" = 1 ]; then
    run sudo systemctl enable --now postgresql
    ok "postgresql started"
  else
    die "postgresql is installed but not running, and ${PGDATA} is not managed by this script. Start it yourself (sudo systemctl enable --now postgresql) or pass --adopt-cluster."
  fi

  # RHEL's initdb leaves host connections on `ident`, which rejects the
  # password auth the DSN uses. Report the change rather than doing it silently.
  if [ "$PG_OWNED" != 1 ]; then
    skip "pg_hba.conf not managed (cluster not created by this script)"
  elif probe --assume-true sudo grep -qE "${HBA_IDENT_RE}" "${PGDATA}/pg_hba.conf"; then
    warn "pg_hba.conf has host auth = ident; switching the two loopback 'all all' lines to scram-sha-256"
    warn "  (first pre-edit copy kept as ${PGDATA}/pg_hba.conf.yuzu-orig, owner and mode preserved; never overwritten on later runs)"
    run sudo cp -n -p "${PGDATA}/pg_hba.conf" "${PGDATA}/pg_hba.conf.yuzu-orig"
    run sudo sed -i -E "s@${HBA_IDENT_RE}@\\1scram-sha-256@" "${PGDATA}/pg_hba.conf"
    # The sed must have consumed every line the grep matched.
    if [ "$DRY_RUN" = 0 ] && sudo grep -qE "${HBA_IDENT_RE}" "${PGDATA}/pg_hba.conf" 2>/dev/null; then
      die "a loopback ident rule survived the edit of ${PGDATA}/pg_hba.conf; fix it by hand and re-run"
    fi
    run sudo systemctl reload postgresql
    ok "host auth set to scram-sha-256"
  else
    skip "no default ident rule in pg_hba.conf; left unchanged (the DSN check below decides)"
  fi

  # CREATEDB is REQUIRED: PostgresTestDb (tests/unit/test_helpers.hpp) creates
  # and drops an ephemeral yuzu_test_<epoch>_<salt>_<n> database per test. The
  # first probe logs in with exactly the credentials the env file will export
  # (against the always-present `postgres` db: yuzu_test may not exist yet).
  # On a cluster this script manages, an existing role that lost LOGIN,
  # CREATEDB or the password is repaired, not accepted on its name - the
  # password reset is deliberate, the DSN this script writes hardcodes it. On
  # any other cluster the role is somebody else's: each die below names only
  # what that branch found missing (run it as postgres, then re-run this
  # script - or pass --adopt-cluster).
  if probe psql "${PG_DSN%/*}/postgres" -tAc "SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user" | grep -qx t; then
    skip "role 'yuzu' logs in with CREATEDB"
  elif [ "$PG_OWNED" != 1 ]; then
    die "role 'yuzu' cannot log in on ${PG_DSN%/*}/postgres with the password this recipe exports, and ${PGDATA} is not managed by this script. As postgres, create or repair it (CREATE ROLE yuzu LOGIN CREATEDB PASSWORD 'yuzu'; or the matching ALTER ROLE), then re-run - or pass --adopt-cluster."
  elif probe sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='yuzu'" | grep -qx 1; then
    run sudo -u postgres psql -c "ALTER ROLE yuzu WITH LOGIN CREATEDB PASSWORD 'yuzu';"
    ok "role 'yuzu' repaired (LOGIN CREATEDB, password reset to match the DSN)"
  else
    run sudo -u postgres psql -c "CREATE ROLE yuzu LOGIN CREATEDB PASSWORD 'yuzu';"
    ok "role 'yuzu' created"
  fi

  # pg_signal_backend is REQUIRED too, and its absence is expensive rather than
  # obvious: PostgresTestDb drops each ephemeral database WITH (FORCE), which
  # terminates the backends still attached to it. Without membership in
  # pg_signal_backend that termination is denied (the attached backends are
  # typically autovacuum workers, which run under no role), a test whose drop
  # races one LEAKS its database, and the [pg] shard slows down until it blows
  # its meson timeout - with the real cause buried in per-test log noise.
  # GRANT is idempotent.
  if probe sudo -u postgres psql -tAc \
       "SELECT pg_has_role('yuzu','pg_signal_backend','member')" | grep -qx t; then
    skip "role 'yuzu' already has pg_signal_backend"
  elif [ "$PG_OWNED" != 1 ]; then
    die "role 'yuzu' lacks pg_signal_backend and ${PGDATA} is not managed by this script. As postgres: GRANT pg_signal_backend TO yuzu; then re-run - or pass --adopt-cluster."
  else
    run sudo -u postgres psql -c "GRANT pg_signal_backend TO yuzu;"
    ok "granted pg_signal_backend to 'yuzu'"
  fi
  if probe sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='yuzu_test'" | grep -qx 1; then
    skip "database 'yuzu_test' exists"
  elif [ "$PG_OWNED" != 1 ]; then
    die "database 'yuzu_test' is missing and ${PGDATA} is not managed by this script. As postgres: CREATE DATABASE yuzu_test OWNER yuzu; then re-run - or pass --adopt-cluster."
  else
    run sudo -u postgres psql -c "CREATE DATABASE yuzu_test OWNER yuzu;"
    ok "database 'yuzu_test' created"
  fi

  # Last word: the DSN goes into the env file only once the cluster answers on
  # it. Everything above already aborted under set -e if it failed.
  if [ "$DRY_RUN" = 1 ]; then
    printf '  (dry-run) verify %s answers and is this cluster, then add YUZU_TEST_POSTGRES_DSN to %s\n' "${PG_DSN}" "${ENV_FILE}"
  elif ! pg_answers; then
    die "PostgreSQL is provisioned but ${PG_DSN} does not answer, so YUZU_TEST_POSTGRES_DSN was NOT exported (exported-but-broken fails the [pg] tests instead of skipping them). Check 'systemctl status postgresql' and ${PGDATA}/pg_hba.conf, then re-run."
  else
    pg_same_cluster && SAME=0 || SAME=$?
    case "${SAME}" in
      0)
        ok "cluster answers on ${PG_DSN}"
        PG_VERIFIED=1
        write_env_file
        ;;
      2)
        if [ "${PG_KEPT_UNVERIFIED}" = 1 ]; then
          die "cannot re-verify that the listener on ${PG_DSN} is the cluster at ${PGDATA} (sudo or pg_controldata unavailable); the PREVIOUSLY verified export was left in place, but this run verified nothing - re-run once sudo/pg_controldata work."
        else
          die "cannot verify that the listener on ${PG_DSN} is the cluster at ${PGDATA} (sudo or pg_controldata unavailable), so YUZU_TEST_POSTGRES_DSN was NOT exported."
        fi ;;
      *) die "something answers on ${PG_DSN} but it is not the cluster at ${PGDATA} (another listener on 127.0.0.1:5432?), so YUZU_TEST_POSTGRES_DSN was NOT exported." ;;
    esac
  fi
fi

# --- 7. Manifest -------------------------------------------------------------

# JSON string literal (quotes included) for the free-text fields below. Called
# standalone between printfs, never inside a substitution, so set -e sees a
# failure.
jstr() { python3 -c 'import json, sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1"; }

if [ -n "${MANIFEST}" ] && [ "$DRY_RUN" = 1 ]; then
  step "Provenance manifest"
  printf '  (dry-run) write manifest %s\n' "${MANIFEST}"
elif [ -n "${MANIFEST}" ]; then
  step "Writing provenance manifest to ${MANIFEST}"
  resolve_vcpkg_commit
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  case "${ARCH}" in
    x86_64)  VCPKG_TRIPLET="x64-linux" ;;
    aarch64) VCPKG_TRIPLET="arm64-linux" ;;
    *)       VCPKG_TRIPLET="unknown-${ARCH}" ;;
  esac
  # curl is required but no longer in PKGS (curl-minimal satisfies it); record
  # whichever RPM actually provides the binary.
  CURL_PKG="$(rpm -qf --qf '%{NAME}' "$(command -v curl)" 2>/dev/null)" || CURL_PKG=""
  {
    printf '{\n'
    printf '  "generated_by": "scripts/setup-rhel9.sh",\n'
    printf '  "distro": '; jstr "${PRETTY_NAME:-${DISTRO_ID} ${VERSION_ID}}"; printf ',\n'
    printf '  "distro_id": "%s",\n' "${DISTRO_ID}"
    printf '  "kernel": "%s",\n' "$(uname -r)"
    printf '  "arch": "%s",\n' "${ARCH}"
    printf '  "vcpkg_triplet": "%s",\n' "${VCPKG_TRIPLET}"
    # Short SHA deliberately. This file is a historical record of what a given
    # run used, so it must NOT be rewritten when the baseline moves — unlike the
    # tracked copies in vcpkg.json/ci.yml/etc. A full 40-char SHA here would be
    # picked up by Test-ToolchainContract.ps1's repo-wide grep and demand exactly
    # that rewriting. 12 hex chars is unambiguous and is what git itself prints.
    printf '  "vcpkg_baseline_short": "%s",\n' "${VCPKG_COMMIT:0:12}"
    printf '  "vcpkg_baseline_authority": "vcpkg.json builtin-baseline",\n'
    printf '  "vcpkg_tool": "%s",\n' "$("${VCPKG_ROOT_ARG}/vcpkg" version 2>/dev/null | head -1 | sed 's/.*version //;s/[^0-9a-z.-]//g')"
    printf '  "compiler": '; jstr "$(g++ --version 2>/dev/null | head -1)"; printf ',\n'
    printf '  "cmake": "%s",\n' "$(cmake --version 2>/dev/null | head -1 | awk '{print $3}')"
    printf '  "ninja": "%s",\n' "$(ninja --version 2>/dev/null)"
    printf '  "meson": "%s",\n' "$(meson --version 2>/dev/null)"
    printf '  "python": "%s",\n' "$(python3 -c 'import platform; print(platform.python_version())')"
    printf '  "pyyaml": "%s",\n' "$(python3 -c 'import yaml; print(yaml.__version__)')"
    printf '  "postgresql": "%s",\n' "$(/usr/bin/postgres --version 2>/dev/null | awk '{print $3}')"
    printf '  "packages": {\n'
    first=1
    for p in "${PKGS[@]}" "${CCACHE_PKG}" ${CURL_PKG:+"${CURL_PKG}"} postgresql-server postgresql-contrib postgresql; do
      rpm -q "$p" >/dev/null 2>&1 || continue
      evr="$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$p")"
      # sed, not head: head closes the pipe early and pipefail would abort this assignment.
      repo="$(dnf --quiet repoquery --installed --qf '%{from_repo}' "$p" 2>/dev/null | sed -n 1p)"
      # Packages laid down by the installer carry an opaque hex repo id.
      case "$repo" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*[0-9a-f]) [ ${#repo} -eq 32 ] && repo="base-os-install" ;; esac
      [ "$first" = 1 ] || printf ',\n'
      printf '    "%s": {"version": "%s", "repo": ' "$p" "$evr"; jstr "${repo:-unknown}"; printf '}'
      first=0
    done
    printf '\n  }\n}\n'
  } > "${MANIFEST}"
  ok "manifest written"
fi

# --- Done --------------------------------------------------------------------

if [ "$DRY_RUN" = 1 ]; then
  step "Dry run complete - nothing was changed"
  printf '\n  Every "(dry-run)" line above is a command that was NOT executed or a result\n  that was NOT achieved; %s was not written.\n  Re-run without --dry-run to provision.\n\n' "${ENV_FILE}"
  exit 0
fi

step "Toolchain ready"
cat <<EOF

  Next:
    source ${ENV_FILE}
    cd <repo> && ./scripts/setup.sh --tests --native-file meson/native/linux-gcc13.ini
    yz_pkgconfig            # vcpkg .pc dir onto PKG_CONFIG_PATH (see the env file)
    meson configure build-linux --clearcache -Dpkg_config_path=\$PWD/vcpkg_installed/x64-linux/lib/pkgconfig
    meson compile -C build-linux

  Note: use linux-gcc13.ini (cpp_std only). linux-gcc14.ini hard-codes gcc-14/g++-14,
  which do not exist inside the Software Collection; the gcc15/clang21 files require mold.

  Verify anytime with:  bash scripts/setup-rhel9.sh --check$([ "$WITH_POSTGRES" = 1 ] && echo ' --with-postgres')

EOF
