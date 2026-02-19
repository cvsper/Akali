#!/bin/bash
# Install Akali git hooks in a repository

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <repo-path>"
    echo "Example: $0 ~/umuve-platform"
    exit 1
fi

REPO_PATH="$1"
HOOKS_DIR="$REPO_PATH/.git/hooks"

if [ ! -d "$REPO_PATH/.git" ]; then
    echo "❌ Not a git repository: $REPO_PATH"
    exit 1
fi

echo "🥷 Akali: Installing git hooks in $REPO_PATH..."

# Install pre-commit hook
PRE_COMMIT_HOOK="$HOOKS_DIR/pre-commit"
cat > "$PRE_COMMIT_HOOK" << 'EOF'
#!/bin/bash
# Akali pre-commit hook

~/akali/defensive/patrols/pre_commit_scan.sh
EOF

chmod +x "$PRE_COMMIT_HOOK"
echo "✅ Installed pre-commit hook"

echo ""
echo "Git hooks installed successfully!"
echo "Test: git commit (should run Akali scan)"
echo ""
