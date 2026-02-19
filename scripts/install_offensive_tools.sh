#!/bin/bash
set -e

echo "🥷 Akali: Installing Phase 2 offensive security tools..."
echo ""
echo "⚠️  AUTHORIZATION NOTICE"
echo "These tools are for authorized penetration testing ONLY."
echo "Unauthorized use against systems you don't own or have permission"
echo "to test is ILLEGAL and may result in criminal prosecution."
echo ""
read -p "Do you understand and agree? (yes/no): " consent
if [[ "$consent" != "yes" ]]; then
    echo "❌ Installation cancelled."
    exit 1
fi
echo ""

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "❌ Homebrew not found. Install from https://brew.sh"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Install network scanning tools
echo "📦 Installing network scanning tools..."
brew list nmap &>/dev/null || brew install nmap
echo "✅ nmap installed"
echo ""

# Install web scanning tools
echo "📦 Installing web scanning tools..."
brew list nikto &>/dev/null || brew install nikto
brew list sqlmap &>/dev/null || brew install sqlmap
brew list gobuster &>/dev/null || brew install gobuster
echo "✅ Web scanning tools installed"
echo ""

# Install SSL/TLS testing
echo "📦 Installing SSL/TLS testing tools..."
if [ ! -f /usr/local/bin/testssl.sh ]; then
    echo "Downloading testssl.sh..."
    curl -L https://github.com/drwetter/testssl.sh/archive/refs/heads/3.0.tar.gz -o /tmp/testssl.tar.gz
    mkdir -p /tmp/testssl
    tar -xzf /tmp/testssl.tar.gz -C /tmp/testssl --strip-components=1
    sudo cp /tmp/testssl/testssl.sh /usr/local/bin/
    sudo chmod +x /usr/local/bin/testssl.sh
    rm -rf /tmp/testssl /tmp/testssl.tar.gz
fi
echo "✅ testssl.sh installed"
echo ""

# Install API testing tools
echo "📦 Installing API testing tools..."
brew list ffuf &>/dev/null || brew install ffuf
echo "✅ ffuf installed"
echo ""

# Optional: Metasploit (user confirmation)
echo "📦 Optional: Metasploit Framework"
echo "⚠️  Warning: Metasploit is ~500MB and requires PostgreSQL"
read -p "Install Metasploit? (yes/no): " install_msf
if [[ "$install_msf" == "yes" ]]; then
    brew list metasploit &>/dev/null || brew install metasploit
    echo "✅ Metasploit installed"
else
    echo "⏭️  Skipping Metasploit"
fi
echo ""

# Verify installations
echo "🔍 Verifying installations..."
echo "nmap: $(nmap --version | head -1)"
echo "nikto: $(nikto -Version 2>&1 | head -1)"
echo "sqlmap: $(sqlmap --version 2>&1 | head -1)"
echo "gobuster: $(gobuster version 2>&1 | head -1)"
echo "testssl.sh: $(testssl.sh --version 2>&1 | head -1)"
echo "ffuf: $(ffuf -V 2>&1)"
if command -v msfconsole &> /dev/null; then
    echo "metasploit: $(msfconsole --version 2>&1 | head -1)"
else
    echo "metasploit: not installed (optional)"
fi
echo ""

echo "✅ All Phase 2 offensive security tools installed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run: akali attack <target> --web (web vulnerability scan)"
echo "  2. Run: akali attack <target> --network (network scan)"
echo "  3. Run: akali exploit <cve-id> (lookup exploit for CVE)"
echo ""
echo "⚠️  REMEMBER: Only use these tools on systems you own or have"
echo "   explicit written permission to test."
