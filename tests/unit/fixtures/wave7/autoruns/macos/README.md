# macOS autoruns fixtures (Wave 7 / A2)

Real captures from this Mac (`braga.local`, macOS 26.5.1 / Darwin 25.5.0,
arm64), 2026-09-06. See each file's `.provenance.txt` sibling for the exact
command. No reconstructions in this directory — every fixture here is a real
capture, including the two documented absences.

## Files

| File | What it proves |
|---|---|
| `com.docker.socket.plist`, `com.docker.vmnetd.plist` | 2 real XML launchd plists from `/Library/LaunchDaemons/`. |
| `com.apple.AppleCredentialManagerDaemon.plist`, `com.apple.AssetCacheLocatorService.plist` | 2 real Apple **binary** plists (raw bytes, `bplist00` magic) from `/System/Library/LaunchDaemons/`. |
| `homebrew.mxcl.postgresql@18.plist` | The one real per-user LaunchAgent found on this host (`~/Library/LaunchAgents/`), installed by Homebrew's `postgresql@18` formula. |
| `listing_Library_LaunchDaemons.txt` | `ls -l /Library/LaunchDaemons/` |
| `listing_Library_LaunchAgents.txt` | `ls -l /Library/LaunchAgents/` — real, and the directory is genuinely empty on this host. |
| `listing_System_Library_LaunchDaemons.txt` | `ls -l /System/Library/LaunchDaemons/` |
| `listing_System_Library_LaunchAgents.txt` | `ls -l /System/Library/LaunchAgents/` |
| `listing_user_LaunchAgents.txt` | `ls -l ~/Library/LaunchAgents/` |
| `etc_periodic.absent.txt` | Genuinely absent: `/etc/periodic` does not exist on this macOS version — Apple removed the `periodic(8)` daily/weekly/monthly framework. Recorded, not reconstructed. |
| `etc_emond_rules.absent.txt` | Genuinely absent: `/etc/emond.d/rules` does not exist on this macOS version — Apple removed `emond(8)`. Recorded, not reconstructed. |

## Process-event capture

macOS process events are **not** in this directory — see
`tests/unit/fixtures/wave7/app_usage/process_events_macos.txt` and its
README for the pairing-shape breakdown.
