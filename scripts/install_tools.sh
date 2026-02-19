#!/bin/bash
set -e

echo "🥷 Akali: Installing Phase 1 security tools..."

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew not found. Install from https://brew.sh"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install Python 3.11+"
    exit 1
fi

# Check if Node.js is installed
if ! command -v npm &> /dev/null; then
    echo "❌ Node.js/npm not found. Install Node.js 18+"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Install secret scanning tools
echo "📦 Installing secret scanning tools..."
brew list gitleaks &>/dev/null || brew install gitleaks
brew list trufflehog &>/dev/null || brew install trufflehog
echo "✅ Secret scanning tools installed"
echo ""

# Install Python security tools
echo "📦 Installing Python security tools..."
pip3 install --quiet safety pip-audit bandit
echo "✅ Python security tools installed"
echo ""

# Install JavaScript security tools
echo "📦 Installing JavaScript security tools..."
npm install -g eslint eslint-plugin-security --silent
echo "✅ JavaScript security tools installed"
echo ""

# Install multi-language SAST
echo "📦 Installing Semgrep..."
brew list semgrep &>/dev/null || brew install semgrep
echo "✅ Semgrep installed"
echo ""

# Verify installations
echo "🔍 Verifying installations..."
gitleaks version
echo "trufflehog: $(trufflehog --version)"
echo "safety: $(safety --version)"
echo "bandit: $(bandit --version)"
echo "eslint: $(eslint --version)"
echo "semgrep: $(semgrep --version)"
echo ""

echo "✅ All Phase 1 security tools installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run: akali status (check tool availability)"
echo "  2. Run: akali scan <target> (run first scan)"
