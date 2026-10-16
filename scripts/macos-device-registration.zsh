#!/bin/zsh -f
# Print Apple Developer registration fields; read-only, no sudo or upload.
# Never substitute Hardware UUID for Provisioning UDID.
set -euo pipefail
export LC_ALL=C

if [[ "$(/usr/bin/uname -s)" != Darwin ]]; then
    print -u2 -- 'Run this script on the Mac you want to register.'
    exit 1
fi
device_name=$(/usr/sbin/scutil --get ComputerName 2>/dev/null) || device_name='Yuzu Development Mac'
[[ -n "$device_name" ]] || device_name='Yuzu Development Mac'
if ! device_udid=$(/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/awk '
    /^[[:space:]]*Provisioning UDID:[[:space:]]*/ {
        sub(/^[[:space:]]*Provisioning UDID:[[:space:]]*/, "")
        sub(/[[:space:]]*$/, "")
        count++
        if ($0 ~ /^[[:xdigit:]]+(-[[:xdigit:]]+)+$/) { value=$0; valid++ }
    }
    END { if (count != 1 || valid != 1) exit 1; print value }
'); then
    print -u2 -- 'Could not read a unique Provisioning UDID. No identifier was substituted.'
    print -u2 -- 'Check System Information > Hardware > Provisioning UDID in your local login session.'
    exit 1
fi
printf 'Platform: macOS\nName: %s\nUDID (UUID field): %s\n' "$device_name" "$device_udid"
