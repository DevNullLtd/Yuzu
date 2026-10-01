#!/usr/bin/env bash
# Provision Big Tam's per-runner L3/CCD isolation, build parallelism cap,
# and persistent test-runs.db.
#
# Run from a Yuzu checkout on Big Tam:
#   sudo bash deploy/linux/Provision-BigTam-Runner-Telemetry.sh
#
# The script does not restart runners (which could kill an active CI job).
# Apply the generated systemd drop-ins at the next idle window using the restart
# command printed at the end. ci.yml derives the telemetry path immediately;
# CPU affinity and process environment require that planned restart.

set -euo pipefail

RUNNER_COUNT="${RUNNER_COUNT:-4}"
RUNNER_USER="${RUNNER_USER:-runner}"
RUNNER_ROOT_BASE="${RUNNER_ROOT_BASE:-/home/runner}"
BUILD_JOBS="${BUILD_JOBS:-16}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_DB="$REPO_ROOT/scripts/test/test_db.py"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Provision-BigTam-Runner-Telemetry.sh must run as root (use sudo)" >&2
  exit 1
fi
if [[ ! -f "$TEST_DB" ]]; then
  echo "test DB schema tool missing at $TEST_DB" >&2
  exit 1
fi
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  echo "runner user '$RUNNER_USER' does not exist" >&2
  exit 1
fi
if [[ ! "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "BUILD_JOBS must be a positive integer (got '$BUILD_JOBS')" >&2
  exit 1
fi

# Linux enumerates SMT siblings in a second block on this Threadripper: the
# first L3 domain is 0-7,32-39, not Windows' contiguous 0-15. Read the kernel's
# cache topology instead of copying Windows affinity masks or assuming CPU
# numbering. Each shared_cpu_list occurs once per logical CPU, so de-duplicate
# and sort by the first CPU to obtain the stable runner-index -> L3 mapping.
mapfile -t L3_CPU_SETS < <(
  for cache_file in /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list; do
    [[ -r "$cache_file" ]] && cat "$cache_file"
  done | sort -u | sort -n
)
if (( ${#L3_CPU_SETS[@]} != RUNNER_COUNT )); then
  echo "expected $RUNNER_COUNT L3 domains, found ${#L3_CPU_SETS[@]}: ${L3_CPU_SETS[*]:-none}" >&2
  exit 1
fi

cpu_list_count() {
  local list="$1" part first last total=0
  local -a parts
  IFS=',' read -r -a parts <<< "$list"
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      first="${BASH_REMATCH[1]}"
      last="${BASH_REMATCH[2]}"
      (( total += last - first + 1 ))
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      (( total += 1 ))
    else
      echo "invalid CPU list from sysfs: '$list'" >&2
      return 1
    fi
  done
  printf '%s\n' "$total"
}

# Validate the complete envelope before touching a database or drop-in. A typo
# in runner 3 must not leave runners 0-2 updated and waiting to activate on the
# next reboot.
declare -a RUNNER_NAMES DBS CPU_SETS SYSTEMD_CPU_SETS DROPINS
for ((index=0; index<RUNNER_COUNT; index++)); do
  runner_name="yuzu-bigtam-linux-$index"
  runner_root="$RUNNER_ROOT_BASE/r$index"
  runner_config="$runner_root/.runner"
  if [[ ! -r "$runner_config" ]]; then
    echo "runner configuration not readable: $runner_config" >&2
    exit 1
  fi
  # The work path becomes root-owned systemd configuration below. Treat the
  # runner-writable .runner file only as an assertion against the canonical
  # registration path; never interpolate its value into the drop-in.
  work_folder="/srv/ci/work-$index"
  if ! python3 -c \
    'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); sys.exit(0 if data.get("workFolder") == sys.argv[2] else 1)' \
    "$runner_config" "$work_folder"; then
    echo "runner workFolder does not match the canonical path for $runner_name" >&2
    exit 1
  fi
  if [[ ! -d "$work_folder/_tool" ]]; then
    echo "runner tool cache is missing for $runner_name: $work_folder/_tool" >&2
    exit 1
  fi
  db="$work_folder/_tool/yuzu-test-runs/$runner_name/test-runs.db"
  # NOT a typo after the DevNullLtd transfer, and NOT to be "corrected".
  # A runner's systemd unit name is fixed at REGISTRATION time from the repo
  # path it registered against; it is not re-derived from the repo's current
  # owner. The Big Tam agents registered against Tr3kkR/Yuzu and stayed online
  # through the 2026-09-28 org transfer without re-registering, so the units on
  # the box are still `actions.runner.Tr3kkR-Yuzu.*`. Renaming this string
  # would point the telemetry at units that do not exist.
  #
  # When an agent IS re-registered (register-bigmags-runner.sh now targets
  # DevNullLtd/Yuzu), its new unit becomes `actions.runner.DevNullLtd-Yuzu.*`
  # and this must be updated in the SAME change that re-registers it.
  unit="actions.runner.Tr3kkR-Yuzu.$runner_name.service"
  cpu_set="${L3_CPU_SETS[$index]}"
  cpu_count="$(cpu_list_count "$cpu_set")"
  if (( cpu_count != BUILD_JOBS )); then
    echo "$runner_name L3 domain '$cpu_set' has $cpu_count logical CPUs, expected BUILD_JOBS=$BUILD_JOBS" >&2
    exit 1
  fi
  # systemd accepts whitespace-separated CPU/range tokens. sysfs emits comma
  # separators, so normalize without changing the logical set.
  systemd_cpu_set="${cpu_set//,/ }"

  if ! systemctl cat "$unit" >/dev/null 2>&1; then
    echo "runner service not found: $unit" >&2
    exit 1
  fi

  RUNNER_NAMES[index]="$runner_name"
  DBS[index]="$db"
  CPU_SETS[index]="$cpu_set"
  SYSTEMD_CPU_SETS[index]="$systemd_cpu_set"
  DROPINS[index]="/etc/systemd/system/$unit.d"
done

# Database creation is idempotent and independent of systemd activation. Do it
# only after every runner has passed validation.
for ((index=0; index<RUNNER_COUNT; index++)); do
  db="${DBS[$index]}"
  install -d -o "$RUNNER_USER" -g "$RUNNER_USER" -m 0750 "$(dirname "$db")"
  sudo -u "$RUNNER_USER" env YUZU_TEST_DB="$db" python3 "$TEST_DB" init
  test -s "$db"
done

# Stage every file on its target filesystem, snapshot any prior target, then
# replace each target atomically. The EXIT trap restores the previous complete
# envelope if any rename or daemon-reload fails (or the operator interrupts the
# transaction); systemd never observes a validated half-update.
# CPUAffinity is inherited by runner children; AllowedCPUs prevents descendants
# from widening the cgroup boundary. The explicit Ninja cap controls how many
# compiler processes execute inside that placement boundary.
declare -a STAGED TARGETS BACKUPS APPLIED
for ((index=0; index<RUNNER_COUNT; index++)); do
  dropin="${DROPINS[$index]}"
  install -d -m 0755 "$dropin"

  telemetry_target="$dropin/yuzu-ci-telemetry.conf"
  telemetry_stage="$(mktemp "$dropin/.yuzu-ci-telemetry.conf.XXXXXX")"
  printf '[Service]\nEnvironment="YUZU_TEST_DB=%s"\n' "${DBS[$index]}" > "$telemetry_stage"
  chown root:root "$telemetry_stage"
  chmod 0644 "$telemetry_stage"

  resources_target="$dropin/yuzu-ci-resources.conf"
  resources_stage="$(mktemp "$dropin/.yuzu-ci-resources.conf.XXXXXX")"
  printf '[Service]\nAllowedCPUs=%s\nCPUAffinity=\nCPUAffinity=%s\nEnvironment="YUZU_BUILD_JOBS=%s"\n' \
    "${SYSTEMD_CPU_SETS[$index]}" "${SYSTEMD_CPU_SETS[$index]}" "$BUILD_JOBS" > "$resources_stage"
  chown root:root "$resources_stage"
  chmod 0644 "$resources_stage"

  for pair in "$telemetry_stage:$telemetry_target" "$resources_stage:$resources_target"; do
    stage="${pair%%:*}"
    target="${pair#*:}"
    slot="${#TARGETS[@]}"
    STAGED[slot]="$stage"
    TARGETS[slot]="$target"
    APPLIED[slot]=0
    if [[ -e "$target" ]]; then
      backup="$(mktemp "$dropin/.yuzu-ci-backup.XXXXXX")"
      cp -a -- "$target" "$backup"
      BACKUPS[slot]="$backup"
    else
      BACKUPS[slot]=""
    fi
  done
done

transaction_complete=0
rollback_envelope() {
  local status="$?" cleanup_failed=0 stage backup slot
  # Rollback must be best-effort across every slot. Do not let errexit or a
  # second operator signal stop restoration halfway through the envelope.
  trap '' INT TERM
  set +e
  if (( transaction_complete == 0 )); then
    for ((slot=${#TARGETS[@]}-1; slot>=0; slot--)); do
      if (( ${APPLIED[slot]:-0} == 1 )); then
        if [[ -n "${BACKUPS[slot]}" ]]; then
          if mv -f -- "${BACKUPS[slot]}" "${TARGETS[slot]}"; then
            BACKUPS[slot]=""
          else
            echo "failed to restore ${TARGETS[slot]}; recovery copy preserved at ${BACKUPS[slot]}" >&2
            cleanup_failed=1
          fi
        else
          if ! rm -f -- "${TARGETS[slot]}"; then
            echo "failed to remove newly-created ${TARGETS[slot]} during rollback" >&2
            cleanup_failed=1
          fi
        fi
      fi
    done
    if ! systemctl daemon-reload >/dev/null 2>&1; then
      echo "systemctl daemon-reload failed during rollback" >&2
      cleanup_failed=1
    fi
  fi
  for stage in "${STAGED[@]}"; do
    if [[ -n "$stage" ]] && ! rm -f -- "$stage"; then
      echo "failed to remove staged file $stage" >&2
      cleanup_failed=1
    fi
  done
  for ((slot=0; slot<${#BACKUPS[@]}; slot++)); do
    backup="${BACKUPS[slot]}"
    [[ -z "$backup" ]] && continue
    # On rollback, retain the only recovery copy when its restore failed.
    if (( transaction_complete == 0 && ${APPLIED[slot]:-0} == 1 )); then
      continue
    fi
    if ! rm -f -- "$backup"; then
      echo "failed to remove backup $backup" >&2
      cleanup_failed=1
    fi
  done
  if (( status == 0 && cleanup_failed != 0 )); then
    status=1
  fi
  return "$status"
}
trap rollback_envelope EXIT
transaction_signal=0
trap 'transaction_signal=130' INT
trap 'transaction_signal=143' TERM

for ((slot=0; slot<${#TARGETS[@]}; slot++)); do
  # Record the slot before mv. Bash dispatches a trapped signal between simple
  # commands, so bookkeeping after a successful rename leaves a race in which
  # EXIT rollback could otherwise mistake the replaced target for untouched.
  APPLIED[slot]=1
  mv -f -- "${STAGED[slot]}" "${TARGETS[slot]}"
  STAGED[slot]=""
  if (( transaction_signal != 0 )); then
    exit "$transaction_signal"
  fi
done
systemctl daemon-reload
if (( transaction_signal != 0 )); then
  exit "$transaction_signal"
fi
transaction_complete=1
trap 'exit 130' INT
trap 'exit 143' TERM
if (( transaction_signal != 0 )); then
  exit "$transaction_signal"
fi

for ((index=0; index<RUNNER_COUNT; index++)); do
  echo "${RUNNER_NAMES[$index]}: L3 CPUs ${CPU_SETS[$index]}; ninja -j$BUILD_JOBS; telemetry ${DBS[$index]}"
done

echo "Big Tam runner resources and telemetry provisioned. Apply at the next idle window:"
# Old-owner unit prefix is deliberate -- see the note at the `unit=` assignment.
echo "  sudo systemctl restart 'actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-*.service'"
