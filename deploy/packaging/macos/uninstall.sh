#!/bin/bash
# Uninstall the Yuzu Agent from macOS.
# Run as: sudo bash /usr/local/lib/yuzu/uninstall.sh

set -e

echo "Uninstalling Yuzu Agent..."

# Stop and unload the launch daemon
if launchctl list com.yuzu.agent &>/dev/null; then
    launchctl unload /Library/LaunchDaemons/com.yuzu.agent.plist 2>/dev/null || true
    sleep 2
fi

# Remove files
rm -f /usr/local/bin/yuzu-agent
rm -f /usr/local/bin/libyuzu_agent_core.dylib
rm -f /usr/local/lib/libyuzu_agent_core.dylib   # location used by packages before #5144
rm -rf /usr/local/lib/yuzu/
rm -f /Library/LaunchDaemons/com.yuzu.agent.plist

# Forget the package receipt
pkgutil --forget com.yuzu.agent 2>/dev/null || true

echo "Yuzu Agent uninstalled."
echo ""
echo "Data directory preserved: /Library/Application Support/Yuzu"
echo "Log directory preserved:  /Library/Logs/Yuzu"
echo "Remove manually if no longer needed."
