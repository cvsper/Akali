#!/bin/bash
# Akali pre-commit security scan
# Runs fast security checks before allowing commit

set -e

# Performance target: < 5 seconds
SCAN_DIR="${1:-.}"

echo "🥷 Akali: Pre-commit security scan..."

# Check if akali CLI is available
if ! command -v akali &> /dev/null; then
    echo "⚠️  Akali CLI not found. Install: ln -s ~/akali/akali /usr/local/bin/akali"
    exit 0  # Don't block commit if akali not installed
fi

# Run secrets scanner only (fastest)
# Other scanners run in CI/CD
if ! akali scan "$SCAN_DIR" --secrets-only --quiet 2>/dev/null; then
    echo ""
    echo "❌ Security issues found! Fix before committing."
    echo "   Run 'akali findings list --open' to see details"
    echo ""
    exit 1
fi

echo "✅ Pre-commit scan passed"
exit 0
