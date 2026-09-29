# Linux autoruns fixtures (Wave 7 / A2)

Real captures from `docker run --rm ubuntu:24.04` (Docker Desktop on macOS,
2026-09-06), except one clearly labelled RECONSTRUCTION. See each file's
`.provenance.txt` sibling for the exact command.

## Files

| File | What it proves |
|---|---|
| `crontab` | System crontab (`/etc/crontab`), real. |
| `cron.d.anacron` | A real `/etc/cron.d/` drop-in file. |
| `anacrontab` | Real `/etc/anacrontab`. |
| `user_crontab.ubuntu` | A real per-user crontab, installed via `crontab -u ubuntu -` and read back from `/var/spool/cron/crontabs/ubuntu`. |
| `anacron.timer` / `anacron.service`, `apt-daily-upgrade.timer` / `.service`, `apt-daily.timer` / `.service`, `dpkg-db-backup.timer` / `.service`, `e2scrub_all.timer` / `.service` | 5 real systemd `.timer` units (≥3 required) from `/usr/lib/systemd/system`, each paired with its `.service`. |
| `timers.target.wants.listing.txt` | `ls -l /etc/systemd/system/timers.target.wants/` — the real symlink listing showing which timers are actually enabled. |
| `at-spi-dbus-bus.desktop` | A real `/etc/xdg/autostart/*.desktop` file (from the `at-spi2-core` package). Has `NoDisplay=true` but not `Hidden`/`OnlyShowIn`. |
| `reconstructed_hidden_onlyshowin.desktop` | **RECONSTRUCTION.** No captured `.desktop` file (in this image or otherwise available) carries both `Hidden` and `OnlyShowIn`, which the acceptance criteria require an example of. Built from the real `at-spi-dbus-bus.desktop` above with `Hidden=true` and `OnlyShowIn=GNOME;` added. |
| `user_autostart_example.desktop` | The real `at-spi-dbus-bus.desktop` copied verbatim into a per-user `~/.config/autostart/` directory, demonstrating the user-level autostart location. |
| `init.d.listing.txt` | `ls -l /etc/init.d/` — real, non-empty (legacy LSB init scripts still shipped alongside systemd on Ubuntu). |
| `rc.local.absent.txt` | Genuinely absent: `/etc/rc.local` does not exist on `ubuntu:24.04` (systemd-only image, no rc.local shipped by default). Recorded, not reconstructed. |

## Process-event capture

Linux process events are **not** in this directory — see
`tests/unit/fixtures/wave7/app_usage/process_events_linux.txt` and its
README for the pairing-shape breakdown.
