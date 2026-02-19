#!/bin/bash
set -e

echo "🥷 Akali: Installing launchd services"

PLIST_DIR=~/Library/LaunchAgents
AKALI_DAEMON_DIR=~/akali/autonomous/daemons

# Create LaunchAgents directory if it doesn't exist
mkdir -p "$PLIST_DIR"

# Copy plist files
echo "📦 Installing launch agents..."
cp "$AKALI_DAEMON_DIR/com.akali.watch.plist" "$PLIST_DIR/"
cp "$AKALI_DAEMON_DIR/com.akali.health.plist" "$PLIST_DIR/"

# Load launch agents
echo "🔄 Loading launch agents..."
launchctl load "$PLIST_DIR/com.akali.watch.plist"
launchctl load "$PLIST_DIR/com.akali.health.plist"

echo ""
echo "✅ Launch agents installed and loaded"
echo ""
echo "Manage with:"
echo "  launchctl start com.akali.watch"
echo "  launchctl stop com.akali.watch"
echo "  launchctl start com.akali.health"
echo "  launchctl stop com.akali.health"
echo ""
echo "Uninstall with:"
echo "  launchctl unload ~/Library/LaunchAgents/com.akali.watch.plist"
echo "  launchctl unload ~/Library/LaunchAgents/com.akali.health.plist"
