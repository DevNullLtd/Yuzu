# Big Tam runner provisioning

Big Tam hosts four native Ubuntu runner agents (`yuzu-bigtam-linux-{0..3}`).
Each agent is constrained to one complete Threadripper 9970X L3/CCD and exports
`YUZU_BUILD_JOBS=16`:

| Runner | Linux logical CPUs | L3 domain |
|---|---|---|
| `-0` | `0-7,32-39` | 0 |
| `-1` | `8-15,40-47` | 1 |
| `-2` | `16-23,48-55` | 2 |
| `-3` | `24-31,56-63` | 3 |

Linux numbers the second SMT sibling of each physical core in CPUs 32-63, so
the per-L3 sets are deliberately non-contiguous. A Windows-style `0-15` range
would span L3 domains 0 and 1. The provisioner reads and validates these sets
from `/sys/devices/system/cpu/*/cache/index3/shared_cpu_list`; the table records
the expected 9970X topology rather than supplying the configuration.

The generated systemd drop-in applies both `CPUAffinity` (inherited by
`Runner.Worker`, Ninja and compiler processes) and the matching cgroup
`AllowedCPUs` boundary. `YUZU_BUILD_JOBS=16` is consumed by the CI build steps
as an explicit `meson compile -j 16`; affinity alone does not change Ninja's
system-wide processor count, and `-j16` alone does not stop Linux migrating work
between CCDs.

Each agent also owns a persistent SQLite telemetry database at:

```text
/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db
```

The provisioner reads each runner's registered `workFolder` from
`/home/runner/rN/.runner` rather than assuming its location. On the live host
those work folders are `/srv/ci/work-N`. The database lives under that runner's
tool cache, outside its checkout, and is therefore unaffected by
`actions/checkout`, branch-switch wipes, or build-dir cleanup. Do not point two
runner agents at the same database: per-runner files avoid making telemetry
itself a shared-host SQLite contention source.

Provision or repair all four resource/telemetry drop-ins and databases from a
Yuzu checkout:

```bash
sudo bash deploy/linux/Provision-BigTam-Runner-Telemetry.sh
```

The script deliberately does not restart a runner that may be executing CI.
Apply the drop-ins during an idle window:

```bash
sudo systemctl restart 'actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-*.service'
```

Do not edit the generated `actions.runner.*.service` files directly: rerunning
the GitHub runner's `svc.sh install` can replace them. The provisioner writes
root-owned files below `<unit>.service.d/`, which is systemd's durable override
mechanism.

Verify the effective service and a live listener after restarting:

```bash
unit=actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-0.service
systemctl show "$unit" -p AllowedCPUs -p CPUAffinity -p Environment
pid=$(systemctl show "$unit" -p MainPID --value)
taskset -pc "$pid"
```

The main CI workflow does not wait for the initial provisioning restart for
telemetry: its start step derives the same per-runner path from
`RUNNER_TOOL_CACHE` and `RUNNER_NAME`, initializes the schema idempotently, and
exports `YUZU_TEST_DB` for the job. Resource settings do require a restart.

Verify a database locally on Big Tam:

```bash
YUZU_TEST_DB=/srv/ci/work-0/_tool/yuzu-test-runs/yuzu-bigtam-linux-0/test-runs.db \
  bash scripts/test/test-db-init.sh --check
YUZU_TEST_DB=/srv/ci/work-0/_tool/yuzu-test-runs/yuzu-bigtam-linux-0/test-runs.db \
  bash scripts/test/test-db-query.sh ci-suite-stats --since 30d
```

## Package pins and toolchain drift

Big Tam is a self-hosted host whose CI depends on exact tool behaviour, and an
unattended upgrade can change that behaviour without any repository change. On
2026-10-03 an unattended update moved coreutils to uutils 0.10.0 and the kernel
to 7.0.0-38, and every Linux job went red (#5298). The first-order trigger found
was `/usr/bin/yes`, which uutils 0.10.0 writes in 1 MiB units where 0.8.0 wrote
16 KiB; the tests that used it as a flood child have since stopped depending on
it. Other drift of the same kind can recur with any tool a test or script execs.

The pin below is applied by the operator on the host. The package names are
placeholders: find the real ones first, for example with
`dpkg -S "$(readlink -f /usr/bin/yes)"`, and repeat for each tool that matters.

```bash
sudo apt-mark hold <package> [<package> ...]
apt-mark showhold                      # list current holds
sudo apt-mark unhold <package>         # release one
```

Also keep the unattended-upgrades job from moving those packages, by listing
them in `/etc/apt/apt.conf.d/50unattended-upgrades`:

```
Unattended-Upgrade::Package-Blacklist {
    "<package>";
};
```

The exact option name, file layout and package list are to be confirmed by the
operator on the real box; none of this was run on Big Tam.

A held package misses security updates, so holds are a debt, not a fix. Review
every hold on a stated cadence (suggested: monthly): check what the held
package's newer versions changed, re-test against them, and release the hold
once CI is known to pass on the new version.

Suggestion only (no workflow change is made here): have CI log the versions of
the tools the suite depends on (coreutils flavour and version, kernel, compiler)
at the start of each job, so that drift shows up in the job log instead of
having to be inferred after a red run.
