# Akali Ultimate Offensive Platform - Design Document

**Date:** 2026-02-20
**Phases:** 7-9 (Mobile, Wireless, Exploit Framework, Extended Targets)
**Approach:** Modular Arsenal + Best-of-Breed Integration
**Status:** APPROVED ✅

---

## Executive Summary

Transform Akali from defensive + basic offensive tool into the **ultimate offensive security platform** with red team operations, purple team validation, and comprehensive attack surface coverage.

### Vision
> "The sharpest blade in security testing - one platform to test everything from mobile apps to IoT devices to cloud infrastructure"

### Scope
**Primary Targets (Priority Order):**
1. 📱 Mobile (iOS/Android - complete attack surface)
2. 📻 Wireless (WiFi, Bluetooth, RF spectrum, IoT protocols)
3. 🔌 IoT/Embedded (smart home, firmware analysis, hardware)
4. 🌐 Cloud infrastructure (AWS/Azure/GCP)
5. 🖥️ Network infrastructure (AD, Kerberos, SMB)
6. 💻 Desktop/endpoint (Windows, Linux, macOS)

**Scenarios:**
- **Red Team Operations** (primary): Full attack chains, C2, persistence, evasion
- **Purple Team Testing** (primary): Validate defenses, safe repeatable tests
- **Bug Bounty** (secondary): Fast vulnerability discovery
- **Security Research** (secondary): Protocol analysis, 0-day discovery

**Automation:**
- **Adaptive Mix**: Full auto for purple team (safe), semi-auto with checkpoints for red team (controlled)

---

## Architecture Overview

### Core Principle
> **"Modular architecture, leverage existing tools where excellent, build custom where needed"**

### Directory Structure
```
akali/
├── mobile/              # Phase 7A: iOS/Android pentesting
│   ├── static/         # Integrate: apktool, class-dump, jtool, MobSF
│   ├── dynamic/        # Integrate: Frida, Objection, mitmproxy
│   ├── device/         # Custom: exploit library (jailbreak, root)
│   └── api/            # Custom: mobile API scanner
├── wireless/            # Phase 8: RF attack surface
│   ├── wifi/           # Integrate: aircrack-ng, wifite, Bettercap
│   ├── bluetooth/      # Integrate: Bettercap, gatttool, bluez
│   ├── sdr/            # Integrate: HackRF, RTL-SDR, GNU Radio, URH
│   └── iot/            # Custom: Zigbee, Z-Wave, RFID/NFC, Matter/Thread
├── redteam/             # Phase 7B: Attack orchestration
│   ├── c2/             # Custom: Go agents + ZimMemory coordination
│   ├── payloads/       # Integrate: msfvenom + custom generators
│   └── campaigns/      # Custom: multi-stage orchestration
├── exploits/            # Phase 9A: Tiered exploit framework
│   ├── database/       # Integrate: ExploitDB, GitHub PoCs, Metasploit
│   ├── generator/      # Custom: payload builder, ROP chains
│   └── fuzzer/         # Integrate: AFL++, Radamsa, Boofuzz
├── purple/              # Phase 9C: Safe testing mode
│   ├── sandbox/        # Docker isolated environments
│   └── validation/     # Custom: defense checks, MTTD/MTTR
└── extended/            # Phase 9B: Extended targets
    ├── cloud/          # AWS/Azure/GCP scanners
    ├── network/        # AD/Kerberos attacks
    └── desktop/        # Priv esc, persistence, cred dumping
```

### Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Core Platform** | Python | Orchestration, CLI, database, existing Akali |
| **C2 Agents** | Go | Small binaries (5-10MB), cross-platform, fast |
| **Performance-Critical** | Rust | Fuzzing, RF processing where speed matters |
| **Tool Wrappers** | Shell | Integrate existing tools (aircrack, frida) |
| **Mobile Static** | Java/Kotlin | APK analysis tools |
| **Mobile Dynamic** | JavaScript | Frida scripts |
| **RF Processing** | C++ | GNU Radio, SDR drivers |

### Integration Strategy

**Decision Tree:**
1. **Excellent tool exists?** → Integrate (e.g., aircrack-ng, Frida, Metasploit)
2. **Good but needs adaptation?** → Wrap + enhance
3. **No good tool?** → Build custom (e.g., C2 agents, campaign orchestration)

**Examples:**
- ✅ Integrate: aircrack-ng (WiFi), Frida (mobile), Metasploit (exploits)
- 🔧 Wrap: MobSF (add custom checks), Bettercap (add IoT protocols)
- 🆕 Build: C2 agents (ZimMemory coordination), Campaign orchestrator

---

## Phase 7: Mobile + C2 Infrastructure

### Phase 7A: Mobile Pentesting

#### 1. Static Analysis (`mobile/static/`)

**Purpose:** Analyze mobile apps without running them

**Tools Integrated:**
- **apktool** - APK decompilation
- **dex2jar + jd-gui** - Java bytecode to source
- **class-dump / jtool2** - iOS binary analysis
- **MobSF** - Automated static analysis framework

**Custom Components:**
```python
# mobile/static/analyzer.py
class MobileStaticAnalyzer:
    """Static analysis engine for mobile apps"""

    def analyze_apk(self, path: str) -> StaticReport:
        """Analyze Android APK"""
        - Decompile with apktool
        - Extract AndroidManifest.xml
        - Parse permissions (dangerous permissions flagged)
        - Find hardcoded secrets (regex patterns for API keys, tokens)
        - Identify insecure storage (SQLite, SharedPreferences)
        - Check certificate pinning implementation
        - Detect debuggable flags
        - Extract URLs/endpoints
        - Check for root detection

    def analyze_ipa(self, path: str) -> StaticReport:
        """Analyze iOS IPA"""
        - Extract IPA archive
        - Parse Info.plist
        - Check App Transport Security (ATS) settings
        - Find hardcoded credentials (keychain usage)
        - Identify insecure data storage
        - Check jailbreak detection mechanisms
        - Extract URLs/endpoints
        - Analyze entitlements

    def find_vulnerabilities(self, code_path: str) -> List[Finding]:
        """Scan for common mobile vulnerabilities"""
        - SQL injection (ContentProvider queries)
        - Hardcoded crypto keys
        - Insecure random number generation
        - SSL/TLS validation issues
        - WebView vulnerabilities (addJavascriptInterface)
        - Intent injection
        - Path traversal
```

**CLI:**
```bash
akali mobile static myapp.apk
akali mobile static --platform ios myapp.ipa
akali mobile static --full-report --output html
akali mobile static --export-endpoints endpoints.json
```

**Output:**
- Markdown report with severity scores
- JSON export for CI/CD integration
- HTML report with code snippets

---

#### 2. Dynamic Analysis (`mobile/dynamic/`)

**Purpose:** Runtime instrumentation and testing

**Tools Integrated:**
- **Frida** - Dynamic instrumentation toolkit
- **Objection** - Frida-based mobile pentesting framework
- **mitmproxy** - SSL interception proxy

**Custom Components:**
```python
# mobile/dynamic/instrumentor.py
class MobileInstrumentor:
    """Runtime instrumentation for mobile apps"""

    def bypass_ssl_pinning(self, app_id: str):
        """Auto-load SSL pinning bypass scripts"""
        - Detect pinning library (TrustKit, AFNetworking, OkHttp)
        - Load appropriate Frida script
        - Hook SSL/TLS validation functions
        - Intercept certificate validation
        - Log bypassed connections

    def hook_crypto(self, app_id: str):
        """Intercept cryptographic operations"""
        - Hook encryption/decryption functions
        - Log keys and plaintext
        - Detect weak algorithms (DES, MD5)
        - Check for hardcoded keys

    def extract_runtime_data(self, app_id: str):
        """Extract sensitive runtime data"""
        - Dump memory regions
        - Extract session tokens from memory
        - Capture API requests/responses
        - Log authentication tokens

    def bypass_root_detection(self, app_id: str):
        """Hook root/jailbreak detection"""
        - Identify root check functions
        - Hook and return false positives
        - Log detection attempts

    def modify_behavior(self, app_id: str, hooks: List[Hook]):
        """Modify app behavior at runtime"""
        - Method hooking
        - Return value manipulation
        - Argument modification
```

**Frida Script Library:**
```javascript
// mobile/dynamic/scripts/ssl-bypass.js
// Universal SSL pinning bypass for Android

// mobile/dynamic/scripts/keychain-dump.js
// Extract iOS keychain items

// mobile/dynamic/scripts/crypto-hook.js
// Log all crypto operations
```

**CLI:**
```bash
akali mobile frida --app com.example.app
akali mobile frida --script ssl-bypass
akali mobile frida --script keychain-dump --device iPhone12
akali mobile proxy --intercept  # Start mitmproxy
akali mobile proxy --export-har traffic.har
```

---

#### 3. Device Exploitation (`mobile/device/`)

**Purpose:** Full device compromise for deep testing

**Exploit Library:**
```
mobile/device/exploits/
├── ios/
│   ├── checkra1n/      # iOS 12-14 jailbreak
│   ├── unc0ver/        # iOS 11-14.8 jailbreak
│   ├── palera1n/       # iOS 15-16 jailbreak
│   └── custom/         # Custom kernel exploits
├── android/
│   ├── dirtycow/       # Linux kernel exploit
│   ├── towelroot/      # Qualcomm exploit
│   ├── kingroot/       # Universal root
│   └── custom/         # Custom exploits
└── bootloaders/
    ├── fastboot/       # Android bootloader unlock
    └── odin/           # Samsung bootloader
```

**Custom Components:**
```python
# mobile/device/exploiter.py
class DeviceExploiter:
    """Automated device exploitation"""

    def auto_jailbreak_ios(self, device_info: DeviceInfo):
        """Automatic iOS jailbreak"""
        - Detect iOS version (usbmuxd)
        - Select compatible jailbreak
        - Execute jailbreak process
        - Install Cydia/Sileo
        - Install Frida + OpenSSH
        - Configure for remote access

    def auto_root_android(self, device_info: DeviceInfo):
        """Automatic Android root"""
        - Detect Android version/kernel
        - Check bootloader status
        - Try exploit chain:
          1. Bootloader unlock (if possible)
          2. Kernel exploits (DirtyCow, etc.)
          3. Userland exploits
        - Install su binary
        - Install Magisk (systemless root)
        - Setup ADB over network
        - Install Frida server

    def setup_persistence(self, device: Device):
        """Install backdoors/persistence"""
        - Install SSH server
        - Create hidden user account
        - Install reverse shell
        - Setup C2 agent
```

**CLI:**
```bash
akali mobile jailbreak --device iPhone12 --auto
akali mobile root --device Pixel6 --method dirtycow
akali mobile exploit --device Samsung --bootloader-unlock
akali mobile persistence --device iPhone12 --install-agent
```

---

#### 4. Mobile API Testing (`mobile/api/`)

**Purpose:** Test mobile backend APIs

**Custom Components:**
```python
# mobile/api/scanner.py
class MobileAPIScanner:
    """Mobile-specific API testing"""

    def extract_endpoints(self, apk_or_ipa: str):
        """Extract API endpoints from app"""
        - Decompile app
        - Parse network configuration
        - Extract base URLs
        - Find API endpoints in code
        - Identify GraphQL schemas
        - Map API structure
        - Export to Postman/OpenAPI

    def test_auth(self, api_base: str):
        """Test mobile authentication"""
        - JWT token manipulation (exp, aud, iss)
        - Session hijacking
        - Token replay attacks
        - Refresh token abuse
        - mTLS certificate extraction + bypass
        - Biometric bypass (TouchID/FaceID)

    def test_mobile_specific(self, api: MobileAPI):
        """Mobile-specific vulnerabilities"""
        - Excessive data exposure (mobile apps often over-fetch)
        - Missing rate limiting (assume mobile = trusted)
        - IDOR via device/user IDs
        - Device binding bypass
        - Push notification manipulation
        - Deep link hijacking
        - Intent scheme vulnerabilities

    def test_backend_security(self, api: MobileAPI):
        """Standard API security"""
        - SQL injection
        - XSS in API responses
        - CSRF on state-changing operations
        - Mass assignment
        - Business logic flaws
```

**CLI:**
```bash
akali mobile api-scan app.apk --extract-endpoints
akali mobile api-test --base-url https://api.example.com
akali mobile api-test --auth-bypass
akali mobile api-fuzz --endpoints endpoints.json
```

---

### Phase 7B: C2 Infrastructure

#### 1. Hybrid Agent System (`redteam/c2/`)

**Purpose:** Command & control for compromised systems

**Go Agent Architecture:**
```go
// redteam/c2/agents/agent.go
package main

type AkaliAgent struct {
    ID           string
    Hostname     string
    Platform     string  // mobile, desktop, iot
    Mode         string  // standalone, zim, metasploit
    Capabilities []string
    BeaconInterval time.Duration
}

func (a *AkaliAgent) Run() {
    for {
        // Check for commands
        tasks := a.GetTasks()
        for _, task := range tasks {
            result := a.ExecuteTask(task)
            a.ReportResult(result)
        }
        time.Sleep(a.BeaconInterval)
    }
}

func (a *AkaliAgent) GetTasks() []Task {
    switch a.Mode {
    case "zim":
        return a.CheckZimMemory()
    case "http":
        return a.CheckHTTPC2()
    case "metasploit":
        return a.CheckMetasploit()
    }
}
```

**Coordination Modes:**

1. **ZimMemory Mode** (Unique to Akali)
   ```
   Agent → ZimMemory API → Akali Commander
   ```
   - Agent checks ZimMemory inbox for commands
   - Posts results to ZimMemory
   - Other agents (Zim, Dommo, Banksy) can coordinate
   - Leverages existing agent ecosystem

2. **Direct HTTP C2**
   ```
   Agent → HTTPS → Akali C2 Server
   ```
   - Traditional C2 over HTTPS
   - Domain fronting support
   - Encrypted channels

3. **External C2 Integration**
   ```
   Agent → Metasploit/Sliver/Covenant
   ```
   - Compatible with existing C2 frameworks
   - Akali generates payloads for external C2s

**Python Orchestrator:**
```python
# redteam/c2/commander.py
class C2Commander:
    """C2 orchestration and agent management"""

    def deploy_agent(self, target: Target, mode='zim'):
        """Deploy agent to target"""
        - Select agent type (mobile, desktop, iot)
        - Generate agent binary for platform
        - Encode/obfuscate agent
        - Deploy via:
          * Exploit (auto-deploy post-exploit)
          * Social engineering (phishing)
          * Physical access (USB drop)
        - Register agent in database + ZimMemory
        - Wait for first beacon

    def send_task(self, agent_id: str, task: Task):
        """Queue task for agent"""
        - Validate task for agent capabilities
        - Queue in ZimMemory or HTTP queue
        - Set timeout
        - Track execution status
        - Collect results
        - Store in database

    def agent_to_agent_relay(self, route: List[str], command: str):
        """Multi-hop pivoting"""
        - Route command through compromised hosts
        - Encrypt at each hop
        - Traverse network segments
        - Return results via same path

    def listen_mode(self, port=443):
        """Start HTTP C2 listener"""
        - HTTPS server
        - Agent registration
        - Task distribution
        - Result collection
```

**Agent Capabilities:**
```python
CAPABILITIES = {
    'mobile': [
        'screenshot', 'keylog', 'location', 'contacts',
        'sms', 'call_logs', 'camera', 'microphone',
        'app_data', 'credentials'
    ],
    'desktop': [
        'shell', 'upload', 'download', 'screenshot',
        'keylog', 'credential_dump', 'persistence'
    ],
    'iot': [
        'reboot', 'firmware_dump', 'network_scan',
        'config_extract'
    ]
}
```

**CLI:**
```bash
akali c2 agent generate --platform mobile --mode zim
akali c2 agent generate --platform desktop --mode http --obfuscate
akali c2 agent list
akali c2 agent info <agent-id>
akali c2 task send <agent-id> screenshot
akali c2 task send <agent-id> "shell:ls -la"
akali c2 listen --port 443 --cert letsencrypt
```

---

#### 2. Payload Generation (`redteam/payloads/`)

**Purpose:** Generate attack payloads

**Tools Integrated:**
- **msfvenom** - Metasploit payload generator
- **Donut** - In-memory .NET execution
- **Veil** - Payload obfuscation

**Custom Components:**
```python
# redteam/payloads/generator.py
class PayloadGenerator:
    """Multi-platform payload generation"""

    def mobile_payload(self, platform: str, exploit: str):
        """Generate mobile payload"""
        if platform == 'ios':
            - Frida gadget injection
            - Or Go agent as .dylib
            - Sign with enterprise cert
        elif platform == 'android':
            - APK with agent embedded
            - Or native .so library
            - Sign with debug cert

    def iot_payload(self, arch: str):
        """Generate IoT payload"""
        - Cross-compile Go agent
        - Supported: ARM, MIPS, PowerPC
        - Minimal dependencies (static binary)
        - Busybox-compatible

    def polymorphic_payload(self, base_payload):
        """Generate polymorphic variant"""
        - Randomize function names
        - Change code structure
        - Encrypt strings
        - Change signatures
        - Evade AV/EDR

    def staged_payload(self, stage1_size_limit: int):
        """Generate staged payload"""
        - Stage 1: Small dropper (<100KB)
        - Stage 2: Full agent (fetched from C2)
        - Reduces initial detection surface
```

**CLI:**
```bash
akali payload generate --platform mobile --type ios
akali payload generate --platform iot --arch arm --format elf
akali payload generate --msf --payload windows/meterpreter/reverse_https
akali payload obfuscate agent.exe --evasion high
```

---

#### 3. Campaign Orchestration (`redteam/campaigns/`)

**Purpose:** Multi-stage attack automation

**Custom Components:**
```python
# redteam/campaigns/orchestrator.py
class CampaignOrchestrator:
    """Orchestrate complex multi-stage attacks"""

    def create_campaign(self, name: str, target: str, mode: str):
        """Create new campaign"""
        - Define target (mobile app, network, cloud)
        - Set mode (red team = manual checkpoints, purple = auto)
        - Define objectives
        - Select attack modules
        - Create campaign database entry

    def run_campaign(self, campaign_id: str):
        """Execute campaign"""
        stages = [
            'recon',        # OSINT, network discovery
            'weaponize',    # Generate payloads
            'deliver',      # Social engineering, exploit
            'exploit',      # Deploy agents
            'install',      # Persistence
            'c2',           # Establish C2 channel
            'lateral',      # Move to other devices
            'collect',      # Gather sensitive data
            'exfil'         # Extract data
        ]

        for stage in stages:
            print(f"[*] Stage: {stage}")

            if self.mode == 'red':
                # Manual checkpoint
                print(f"[?] Ready to proceed with {stage}?")
                approval = self.ask_user_approval(stage)
                if not approval:
                    print(f"[!] Campaign halted at {stage}")
                    break

            # Execute stage
            result = self.execute_stage(stage, campaign_id)

            # Log results
            self.log_stage_result(campaign_id, stage, result)

            # Update ZimMemory
            self.notify_agents(campaign_id, stage, result)
```

**Campaign Templates:**
```yaml
# redteam/campaigns/templates/mobile-app-test.yaml
name: "Mobile App Security Test"
target_type: mobile
stages:
  - recon:
      - download_app
      - static_analysis
      - extract_endpoints
  - exploit:
      - test_mobile_api
      - bypass_ssl_pinning
      - extract_tokens
  - lateral:
      - test_backend_api
      - cloud_misconfiguration
```

**CLI:**
```bash
akali redteam campaign create "mobile-test" --target "com.example.app"
akali redteam campaign run "mobile-test" --mode purple  # Full auto
akali redteam campaign run "mobile-test" --mode red     # Manual checkpoints
akali redteam campaign status "mobile-test"
akali redteam campaign report "mobile-test" --format html
```

---

## Phase 8: Wireless + IoT

### Phase 8A: WiFi Attacks (`wireless/wifi/`)

**Purpose:** WiFi penetration testing

**Tools Integrated:**
- **aircrack-ng suite** - airmon-ng, airodump-ng, aireplay-ng, aircrack-ng
- **wifite** - Automated WiFi attacks
- **Bettercap** - MITM, evil twin, credential harvesting
- **hashcat** - GPU password cracking

**Custom Components:**
```python
# wireless/wifi/attacker.py
class WiFiAttacker:
    """WiFi penetration testing"""

    def scan_networks(self, interface='wlan0'):
        """Scan for WiFi networks"""
        - Enable monitor mode (airmon-ng)
        - Scan for networks (airodump-ng)
        - List SSIDs, BSSIDs, channels, encryption
        - Identify clients per network
        - Sort by signal strength

    def capture_handshake(self, ssid: str, bssid: str):
        """Capture WPA handshake"""
        - Target specific network
        - Deauthenticate clients (aireplay-ng)
        - Capture 4-way handshake
        - Verify handshake quality
        - Save for offline cracking

    def crack_wpa(self, handshake_file: str, wordlist: str):
        """Crack WPA/WPA2 password"""
        - Try common passwords first (top 1000)
        - Use aircrack-ng or hashcat
        - GPU acceleration if available
        - Report progress
        - Save cracked passwords

    def evil_twin(self, ssid: str, channel: int):
        """Create rogue access point"""
        - Clone target network (same SSID)
        - Deauth clients from real AP
        - Capture credentials via captive portal
        - MITM traffic
        - Downgrade HTTPS to HTTP

    def wpa3_downgrade(self, ssid: str):
        """Exploit WPA3 transition mode"""
        - Force clients to use WPA2
        - Capture WPA2 handshake
        - Standard WPA2 attacks apply
```

**Wordlist Management:**
```python
WORDLISTS = {
    'common': '/usr/share/wordlists/rockyou.txt',
    'wifi-specific': '/opt/akali/wordlists/wifi-common.txt',
    'custom': '~/.akali/wordlists/'
}
```

**CLI:**
```bash
akali wifi scan
akali wifi scan --interface wlan0 --channel 6
akali wifi handshake "Home WiFi" --deauth-clients
akali wifi crack handshake.cap --wordlist rockyou.txt
akali wifi crack handshake.cap --wordlist rockyou.txt --gpu
akali wifi evil-twin "Starbucks WiFi" --channel 6
akali wifi wpa3-downgrade "Home WiFi"
```

---

### Phase 8B: Bluetooth/BLE (`wireless/bluetooth/`)

**Purpose:** Bluetooth/BLE penetration testing

**Tools Integrated:**
- **Bettercap** - BLE spoofing and MITM
- **gatttool / bluetoothctl** - BLE interaction
- **bluez** - Bluetooth stack
- **ubertooth** - Bluetooth sniffing (if hardware available)

**Custom Components:**
```python
# wireless/bluetooth/ble_attacker.py
class BLEAttacker:
    """Bluetooth Low Energy attacks"""

    def scan_devices(self, duration=10):
        """Scan for BLE devices"""
        - Discover BLE devices in range
        - Extract MAC addresses
        - Read device names
        - Enumerate services (GATT)
        - List characteristics
        - Identify common devices (fitness trackers, locks, etc.)

    def hijack_connection(self, mac: str):
        """MITM BLE connection"""
        - Jam legitimate connection (if close enough)
        - Impersonate peripheral device
        - Intercept BLE traffic
        - Read/write characteristics
        - Log sensitive data

    def exploit_pairing(self, mac: str):
        """Exploit BLE pairing weaknesses"""
        - "Just Works" pairing bypass (no PIN)
        - Passkey brute force (6-digit PINs)
        - Legacy pairing attacks
        - Downgrade to insecure mode

    def beacon_spam(self, count=1000):
        """Flood area with fake BLE devices"""
        - Advertise fake devices
        - Denial of service
        - Confuse BLE scanners

    def smart_lock_attack(self, mac: str):
        """Target BLE smart locks"""
        - Replay attack (capture unlock packets)
        - Brute force unlock codes
        - Exploit app vulnerabilities
```

**CLI:**
```bash
akali bluetooth scan
akali bluetooth scan --services
akali bluetooth hijack AA:BB:CC:DD:EE:FF
akali bluetooth pair-crack AA:BB:CC:DD:EE:FF
akali bluetooth beacon-spam --count 1000
akali bluetooth smart-lock AA:BB:CC:DD:EE:FF --attack replay
```

---

### Phase 8C: SDR / RF Spectrum (`wireless/sdr/`)

**Purpose:** Software Defined Radio attacks

**Tools Integrated:**
- **HackRF / RTL-SDR** - SDR hardware
- **GNU Radio** - RF signal processing
- **Universal Radio Hacker (URH)** - Protocol reverse engineering
- **gr-gsm** - GSM analysis
- **inspectrum** - Signal visualization

**Custom Components:**
```python
# wireless/sdr/rf_analyzer.py
class RFAnalyzer:
    """RF spectrum analysis and attacks"""

    def scan_spectrum(self, freq_min: float, freq_max: float):
        """Sweep frequency range"""
        - Scan range (e.g., 300MHz-900MHz)
        - Identify active signals
        - Measure signal strength
        - Classify protocols (FM, AM, ASK, FSK, etc.)
        - Export waterfall plot

    def replay_attack(self, recording_file: str):
        """Replay RF signal"""
        - Load recorded signal
        - Transmit exactly as captured
        - Use cases:
          * Car key fobs (315MHz, 433MHz)
          * Garage door openers
          * Wireless doorbells
          * RF remotes
        - CAUTION: Illegal in many jurisdictions

    def protocol_analysis(self, frequency: float):
        """Reverse engineer RF protocol"""
        - Capture signal
        - Demodulate (AM/FM/ASK/FSK/PSK)
        - Extract bit stream
        - Identify protocol structure
        - Decode messages
        - Generate custom packets

    def jamming(self, frequency: float, bandwidth: float):
        """RF jamming (DoS)"""
        - Transmit noise on target frequency
        - Deny service to wireless devices
        - CAUTION: Illegal without authorization
```

**Frequency Bands:**
```python
COMMON_FREQUENCIES = {
    '315MHz': 'Car keys, garage doors (US)',
    '433MHz': 'Car keys, garage doors, IoT (EU)',
    '868MHz': 'LoRa, Zigbee (EU)',
    '915MHz': 'LoRa, Zigbee (US)',
    '2.4GHz': 'WiFi, Bluetooth, Zigbee',
    '5.8GHz': 'WiFi, drone controllers'
}
```

**CLI:**
```bash
akali sdr scan 300MHz-900MHz
akali sdr scan 300MHz-900MHz --device hackrf
akali sdr capture 433.92MHz --duration 30s --output signal.raw
akali sdr replay garage_door.raw
akali sdr analyze 433.92MHz --demodulate ASK
akali sdr jam 2.4GHz --bandwidth 20MHz  # CAUTION: Illegal
```

---

### Phase 8D: IoT Protocols (`wireless/iot/`)

**Purpose:** IoT protocol security testing

**Protocols Supported:**
- **Zigbee** - Smart home (Philips Hue, etc.)
- **Z-Wave** - Home automation
- **RFID/NFC** - Access cards, payments
- **LoRa/LoRaWAN** - Long-range IoT
- **Matter/Thread** - New smart home standards

**Custom Components:**
```python
# wireless/iot/iot_attacker.py
class IoTAttacker:
    """IoT protocol attacks"""

    def zigbee_attack(self):
        """Zigbee network attacks"""
        - Scan for Zigbee networks (channel 11-26, 2.4GHz)
        - Sniff Zigbee traffic (CC2531 USB dongle)
        - Decrypt network key (if weak)
        - Inject malicious commands
        - Take over smart bulbs, locks, sensors

    def zwave_attack(self):
        """Z-Wave network attacks"""
        - Capture Z-Wave frames (908.42MHz US, 868.42MHz EU)
        - Replay or craft commands
        - Control thermostats, locks, switches
        - Exploit S0 security (weak encryption)

    def rfid_clone(self, frequency: str):
        """Clone RFID/NFC card"""
        - Read RFID card (Proxmark3)
        - Identify card type (Mifare, HID, etc.)
        - Clone to blank card or Proxmark
        - Emulate card
        - Test against reader

    def lora_attack(self):
        """LoRa/LoRaWAN attacks"""
        - Scan for LoRa devices
        - Capture LoRaWAN join requests
        - Replay attacks
        - Jamming (868MHz EU, 915MHz US)

    def matter_exploit(self):
        """Matter/Thread protocol testing"""
        - Scan for Matter devices
        - Test commissioning process
        - Check for insecure defaults
        - Exploit misconfigurations
        - Test Thread network security
```

**Hardware Requirements:**
```python
HARDWARE_SUPPORT = {
    'zigbee': 'CC2531 USB dongle + Wireshark',
    'zwave': 'HackRF or RTL-SDR',
    'rfid_nfc': 'Proxmark3 RDV4 or ACR122U',
    'lora': 'HackRF or LoRa dongle',
    'matter': 'Matter-compatible hub or ESP32'
}
```

**CLI:**
```bash
akali iot scan --protocol zigbee
akali iot scan --protocol zwave
akali iot attack zigbee --device "Living Room Light" --command off
akali iot attack zwave --device "Front Door Lock" --unlock
akali iot rfid clone --frequency 125kHz
akali iot rfid emulate --card-id 12345 --format HID
akali iot lora scan --frequency 915MHz
akali iot matter scan
akali iot matter test-commission --device "Smart Plug"
```

---

## Phase 9: Exploit Framework + Extended Targets + Purple Team

### Phase 9A: Tiered Exploit Framework (`exploits/`)

**Purpose:** Three-tier exploit system

#### Tier 1: Exploit Database (`exploits/database/`)

**Tools Integrated:**
- **ExploitDB** - Exploit database (searchsploit)
- **GitHub PoCs** - Public proof-of-concepts
- **Metasploit** - MSF modules

**Custom Components:**
```python
# exploits/database/search.py
class ExploitDatabase:
    """Search and retrieve public exploits"""

    def search(self, query: str):
        """Search across multiple sources"""
        results = []

        # ExploitDB
        results += self.search_exploitdb(query)

        # GitHub
        results += self.search_github(query)

        # Metasploit
        results += self.search_metasploit(query)

        # Rank by:
        - Exploit reliability
        - Recency
        - Maturity (PoC vs weaponized)
        - Supported platforms

        return sorted_results

    def download_exploit(self, exploit_id: str):
        """Download exploit code"""
        - Fetch from source
        - Verify integrity (checksum)
        - Categorize by type
        - Store in local cache
        - Parse metadata
```

**CLI:**
```bash
akali exploit search CVE-2023-12345
akali exploit search "wordpress rce"
akali exploit search --platform linux --type kernel
akali exploit download EDB-50123
akali exploit list --recent --critical
```

---

#### Tier 2: Custom Exploit Generator (`exploits/generator/`)

**Purpose:** Generate custom exploits when public ones don't work

**Custom Components:**
```python
# exploits/generator/builder.py
class ExploitGenerator:
    """Custom exploit generation"""

    def generate_buffer_overflow(self, binary: str, offset: int):
        """Generate buffer overflow exploit"""
        - Create cyclic pattern (De Bruijn sequence)
        - Find offset to return address
        - Build ROP chain (if NX enabled)
        - Generate shellcode
        - Assemble exploit
        - Test against binary

    def generate_sqli_payload(self, injection_point: str, target_db: str):
        """Generate SQL injection payload"""
        - Test injection type (union, blind, time-based)
        - Fingerprint database (MySQL, PostgreSQL, MSSQL, Oracle)
        - Generate extraction payload
        - Optimize for speed
        - Generate tamper scripts (bypass WAF)

    def generate_xss_payload(self, context: str, filters: List[str]):
        """Generate XSS payload"""
        - Detect context (HTML, JS, attribute, etc.)
        - Identify active filters
        - Generate bypass payload
        - Test against common filters
        - Optimize for stealth vs impact

    def generate_deserialization_exploit(self, framework: str):
        """Generate deserialization exploit"""
        - Java: ysoserial gadget chains
        - .NET: YSoSerial.Net gadget chains
        - Python: pickle exploits
        - Encode payload
        - Test against target

    def generate_xxe_payload(self, target: str):
        """Generate XXE payload"""
        - External entity injection
        - File disclosure
        - SSRF via XXE
        - Blind XXE with out-of-band
```

**CLI:**
```bash
akali exploit generate --type bof --binary ./vuln_app --offset 112
akali exploit generate --type sqli --url "https://site.com/page?id=1"
akali exploit generate --type xss --url "https://site.com/search?q="
akali exploit generate --type deserial --framework java
```

---

#### Tier 3: Fuzzing & 0-Day Discovery (`exploits/fuzzer/`)

**Tools Integrated:**
- **AFL++** - Coverage-guided fuzzing
- **Radamsa** - General-purpose fuzzer
- **Boofuzz** - Network protocol fuzzing

**Custom Components:**
```python
# exploits/fuzzer/fuzzer.py
class Fuzzer:
    """Automated vulnerability discovery"""

    def fuzz_binary(self, target: str, inputs: List[str]):
        """Fuzz local binary"""
        - Compile with AFL++ instrumentation
        - Generate initial corpus
        - Run fuzzing campaign
        - Monitor crashes
        - Triage crashes (exploitable vs not)
        - Generate PoCs

    def fuzz_network_protocol(self, host: str, port: int, spec: str):
        """Fuzz network service"""
        - Load protocol specification (Boofuzz)
        - Generate malformed packets
        - Monitor service for crashes/hangs
        - Log crash inputs
        - Replay crashes

    def analyze_crash(self, crash_file: str):
        """Automated crash analysis"""
        - Run in GDB
        - Analyze register state
        - Check exploitability:
          * Control of RIP/EIP?
          * Stack smashing?
          * Heap corruption?
        - Generate exploitability score
        - Create PoC template
```

**CLI:**
```bash
akali fuzz binary ./target --input-dir seeds/ --duration 24h
akali fuzz network 192.168.1.1:9000 --protocol ftp
akali fuzz api https://api.example.com --openapi swagger.json
akali fuzz analyze crash.bin --binary ./target
```

---

### Phase 9B: Extended Targets

#### Cloud (`extended/cloud/`)

**Purpose:** Cloud infrastructure pentesting

**Custom Components:**
```python
# extended/cloud/cloud_attacker.py
class CloudAttacker:
    """Cloud security testing"""

    def scan_s3_buckets(self, keyword: str):
        """Enumerate AWS S3 buckets"""
        - Generate bucket names (keyword + common patterns)
        - Test for existence
        - Test permissions (read, write, list)
        - Download exposed data
        - Flag sensitive files

    def scan_azure_blobs(self, keyword: str):
        """Enumerate Azure Blob Storage"""
        - Generate storage names
        - Test public access
        - Download exposed data

    def test_cloud_metadata(self, target: str):
        """Test cloud metadata endpoints"""
        - Try 169.254.169.254 (AWS)
        - Try 169.254.169.254 (Azure)
        - Try metadata.google.internal (GCP)
        - Extract IAM credentials
        - Test SSRF to metadata

    def test_lambda_functions(self, region: str):
        """Test AWS Lambda security"""
        - Enumerate functions (if creds available)
        - Test function injection
        - Check for secrets in environment
        - Test privilege escalation

    def test_kubernetes(self, cluster_url: str):
        """Test Kubernetes security"""
        - Test anonymous access
        - Check RBAC misconfigurations
        - Test pod escape
        - Scan for exposed secrets
```

**CLI:**
```bash
akali cloud s3-scan company-name
akali cloud azure-scan company-name
akali cloud metadata --target https://api.example.com --ssrf-param url
akali cloud lambda-scan --region us-east-1
akali cloud k8s-scan https://cluster.example.com:6443
```

---

#### Network Infrastructure (`extended/network/`)

**Purpose:** Active Directory / Kerberos attacks

**Custom Components:**
```python
# extended/network/network_attacker.py
class NetworkAttacker:
    """Network infrastructure attacks"""

    def kerberoast(self, domain: str):
        """Kerberoasting attack"""
        - Extract service tickets (TGS)
        - Crack tickets offline (hashcat)
        - Target high-privilege accounts

    def asreproast(self, domain: str):
        """AS-REP Roasting"""
        - Find users without Kerberos pre-auth
        - Extract AS-REP hashes
        - Crack offline

    def smb_relay(self, target: str):
        """SMB relay attack"""
        - Capture NTLM hashes
        - Relay to other systems
        - Gain code execution

    def ldap_injection(self, ldap_url: str):
        """LDAP injection"""
        - Test LDAP queries
        - Inject filters
        - Extract domain info
        - Enumerate users/groups

    def zerologon(self, dc: str):
        """Zerologon exploit (CVE-2020-1472)"""
        - Test for vulnerability
        - Reset DC machine account password
        - Gain domain admin
```

**CLI:**
```bash
akali network kerberoast --domain corp.local
akali network asreproast --domain corp.local
akali network smb-relay --target 192.168.1.10
akali network ldap-inject --url ldap://dc.corp.local
akali network zerologon --dc dc.corp.local
```

---

#### Desktop/Endpoint (`extended/desktop/`)

**Purpose:** Privilege escalation and persistence

**Custom Components:**
```python
# extended/desktop/desktop_attacker.py
class DesktopAttacker:
    """Endpoint security testing"""

    def privilege_escalation(self, os: str):
        """Automated privesc"""
        if os == 'windows':
            - Check for unquoted service paths
            - Test AlwaysInstallElevated
            - Check for weak service permissions
            - Test DLL hijacking
            - Kernel exploits (CVE database)
        elif os == 'linux':
            - Find SUID binaries
            - Check sudo permissions
            - Test for kernel exploits
            - Check cron jobs
        elif os == 'macos':
            - TCC bypass techniques
            - Check sudo permissions
            - Test for SUID binaries

    def persistence(self, os: str):
        """Install persistence"""
        if os == 'windows':
            - Registry Run keys
            - Scheduled tasks
            - WMI event subscriptions
            - Service creation
        elif os == 'linux':
            - Cron jobs
            - systemd services
            - .bashrc/.profile
            - SSH authorized_keys
        elif os == 'macos':
            - LaunchDaemons/LaunchAgents
            - Login items
            - Startup scripts

    def credential_dumping(self, os: str):
        """Extract credentials"""
        if os == 'windows':
            - Mimikatz (LSASS dump)
            - SAM database
            - Credential Manager
        elif os == 'linux':
            - /etc/shadow
            - SSH keys
            - Browser passwords
        elif os == 'macos':
            - Keychain extraction
            - Safari passwords
            - SSH keys
```

**CLI:**
```bash
akali desktop privesc --os windows
akali desktop privesc --os linux --suggest-exploits
akali desktop persist --os windows --method registry
akali desktop creds --os windows --method mimikatz
akali desktop creds --os linux --method shadow
```

---

### Phase 9C: Purple Team Mode (`purple/`)

**Purpose:** Safe, automated testing of own defenses

#### Sandbox Environment (`purple/sandbox/`)

**Custom Components:**
```python
# purple/sandbox/environment.py
class PurpleTeamSandbox:
    """Isolated testing environment"""

    def create_test_env(self, target_type: str):
        """Create sandbox"""
        - Spin up Docker containers
        - Isolated network (docker network)
        - Deploy vulnerable test apps:
          * DVWA (web app)
          * Juice Shop (web app)
          * Metasploitable (vulnerable OS)
          * Custom vulnerable mobile app
        - Configure monitoring (logs, alerts)

    def run_full_auto_attack(self):
        """Run automated attacks (safe mode)"""
        - No manual checkpoints
        - Run all attack modules
        - Test detection capabilities
        - Measure MTTD (Mean Time To Detect)
        - No actual data exfiltration
        - Generate detailed report

    def cleanup(self):
        """Cleanup sandbox"""
        - Stop all containers
        - Remove networks
        - Clear logs
        - Archive results
```

**CLI:**
```bash
akali purple create-env --target web-app
akali purple create-env --target mobile-api
akali purple run-attack --env web-app --full-auto
akali purple cleanup
```

---

#### Defense Validation (`purple/validation/`)

**Custom Components:**
```python
# purple/validation/validator.py
class DefenseValidator:
    """Validate security controls"""

    def test_detections(self):
        """Test detection capabilities"""
        - Run known attack patterns
        - Check if WAF triggered
        - Check if IDS/IPS triggered
        - Check if SIEM alerted
        - Measure detection rate
        - Identify blind spots

    def test_response(self):
        """Test incident response"""
        - Trigger security incident
        - Measure MTTD (Mean Time To Detect)
        - Measure MTTR (Mean Time To Respond)
        - Validate playbook execution
        - Check alert escalation

    def test_prevention(self):
        """Test preventive controls"""
        - Test firewall rules
        - Test input validation
        - Test authentication controls
        - Test authorization checks

    def generate_purple_report(self):
        """Generate purple team report"""
        - Attack success rate
        - Detection coverage (% of attacks detected)
        - Response effectiveness
        - Control gaps
        - Remediation recommendations
```

**CLI:**
```bash
akali purple test-detections --run-all
akali purple test-response --scenario ransomware
akali purple test-prevention --controls firewall,waf,authentication
akali purple report --format html
akali purple report --compare-with previous-scan.json
```

---

## Implementation Phases

### Phase 7: Mobile + C2 (Est. 6-8 weeks)
**Priority:** HIGH (Mobile is #1 target)

**Tasks:**
1. Mobile static analysis (2 weeks)
   - Integrate apktool, class-dump, MobSF
   - Build custom analyzer
   - CLI interface

2. Mobile dynamic analysis (2 weeks)
   - Integrate Frida, Objection
   - Build instrumentor
   - SSL pinning bypass scripts

3. Device exploitation (1 week)
   - Build exploit library
   - Auto-jailbreak/root
   - Persistence installation

4. Mobile API testing (1 week)
   - Endpoint extraction
   - Mobile-specific tests

5. C2 infrastructure (2 weeks)
   - Go agents (mobile, desktop, IoT)
   - Python orchestrator
   - ZimMemory integration

6. Payload generation (1 week)
   - Mobile payloads
   - IoT payloads
   - Obfuscation

7. Campaign orchestration (1 week)
   - Multi-stage attacks
   - Red team vs purple team modes

**Deliverables:**
- `akali mobile` commands working
- `akali c2` commands working
- `akali redteam campaign` orchestration
- Documentation + examples

---

### Phase 8: Wireless + IoT (Est. 4-6 weeks)
**Priority:** HIGH (Wireless is #2 target)

**Tasks:**
1. WiFi attacks (1.5 weeks)
   - Integrate aircrack-ng, wifite, Bettercap
   - Build custom attacker
   - Evil twin, handshake capture, cracking

2. Bluetooth/BLE (1 week)
   - BLE scanning, hijacking
   - Pairing exploitation

3. SDR / RF spectrum (1.5 weeks)
   - Integrate HackRF, GNU Radio
   - Replay attacks
   - Protocol analysis

4. IoT protocols (2 weeks)
   - Zigbee attacks (CC2531)
   - Z-Wave attacks
   - RFID/NFC cloning (Proxmark3)
   - LoRa attacks
   - Matter/Thread testing

**Deliverables:**
- `akali wifi` commands working
- `akali bluetooth` commands working
- `akali sdr` commands working
- `akali iot` commands working
- Hardware setup guides

---

### Phase 9: Exploit Framework + Extended + Purple (Est. 6-8 weeks)
**Priority:** MEDIUM (Enhance existing capabilities)

**Tasks:**
1. Exploit database (1 week)
   - ExploitDB integration
   - GitHub PoC search
   - Metasploit integration

2. Custom exploit generator (2 weeks)
   - Buffer overflow exploits
   - SQL injection payloads
   - XSS payloads
   - Deserialization exploits

3. Fuzzing (1.5 weeks)
   - AFL++ integration
   - Network fuzzing
   - Crash analysis

4. Cloud attacks (1 week)
   - S3/Azure blob enumeration
   - Cloud metadata attacks
   - Lambda/container testing

5. Network infrastructure (1 week)
   - Kerberoast, AS-REP roast
   - SMB relay
   - LDAP injection

6. Desktop attacks (1 week)
   - Privilege escalation
   - Persistence
   - Credential dumping

7. Purple team mode (1.5 weeks)
   - Sandbox environment
   - Defense validation
   - Purple team reports

**Deliverables:**
- `akali exploit` commands working
- `akali cloud` commands working
- `akali network` commands working
- `akali desktop` commands working
- `akali purple` commands working
- Purple team automation

---

## Success Criteria

### Phase 7 Success:
- ✅ Can analyze Android APK and iOS IPA
- ✅ Can instrument mobile apps with Frida
- ✅ Can jailbreak iOS and root Android
- ✅ Can deploy Go agents to compromised devices
- ✅ C2 agents communicate via ZimMemory
- ✅ Can run multi-stage campaigns with checkpoints

### Phase 8 Success:
- ✅ Can scan and crack WPA2 WiFi
- ✅ Can create evil twin access points
- ✅ Can scan and hijack BLE devices
- ✅ Can capture and replay RF signals
- ✅ Can attack Zigbee/Z-Wave networks
- ✅ Can clone RFID cards

### Phase 9 Success:
- ✅ Can search and download public exploits
- ✅ Can generate custom exploits
- ✅ Can fuzz binaries and network protocols
- ✅ Can enumerate cloud resources
- ✅ Can perform AD attacks (Kerberoast, etc.)
- ✅ Can escalate privileges on Windows/Linux/macOS
- ✅ Purple team mode runs fully automated tests
- ✅ Defense validation generates actionable reports

---

## Security & Legal Considerations

### Authorization Framework
```python
# Strict authorization checks
AUTHORIZATION_REQUIRED = [
    'attack', 'exploit', 'redteam', 'purple'
]

def require_authorization(func):
    """Decorator for authorization checks"""
    def wrapper(*args, **kwargs):
        target = kwargs.get('target')

        # Check authorization database
        if not is_authorized(target):
            print("❌ Target not authorized")
            print("Run: akali authorize add <target>")
            return None

        # Log operation
        log_operation(func.__name__, target)

        return func(*args, **kwargs)
    return wrapper
```

### Audit Logging
```python
# All offensive operations logged
AUDIT_LOG = '~/.akali/audit.log'

def log_operation(operation, target, result):
    entry = {
        'timestamp': datetime.now(),
        'operation': operation,
        'target': target,
        'result': result,
        'user': os.getenv('USER'),
        'hostname': socket.gethostname()
    }
    append_to_audit_log(entry)
```

### Legal Disclaimer
```
⚠️  WARNING: Offensive security testing

Akali includes powerful offensive capabilities that MUST only
be used on systems you own or have explicit written permission
to test.

Unauthorized access to computer systems is illegal under:
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

By using Akali's offensive features, you agree that:
1. You have proper authorization for all targets
2. You will comply with all applicable laws
3. You accept full responsibility for your actions
4. The authors are not liable for misuse

Use responsibly. Always get permission in writing.
```

---

## Dependencies

### Python Packages
```
# requirements.txt
frida-tools>=12.0
objection>=1.11
mitmproxy>=9.0
scapy>=2.5
pycryptodome>=3.19
requests>=2.31
```

### External Tools (Phase 7-8)
```bash
# Mobile
apt install apktool dex2jar
brew install class-dump jtool2

# Wireless
apt install aircrack-ng hashcat bettercap
apt install bluez bluez-tools

# SDR
apt install hackrf gnuradio gr-gsm
```

### Hardware (Optional but Recommended)
- **Mobile:** Android device + iOS device for testing
- **WiFi:** USB WiFi adapter with monitor mode (Alfa AWUS036ACH)
- **BLE:** USB Bluetooth 5.0+ adapter
- **RF:** HackRF One or RTL-SDR
- **Zigbee:** CC2531 USB dongle
- **RFID:** Proxmark3 RDV4

---

## CLI Interface Design

### Command Structure
```bash
akali <module> <action> [options]

Modules:
  mobile      - Mobile pentesting
  wifi        - WiFi attacks
  bluetooth   - Bluetooth/BLE attacks
  sdr         - Software Defined Radio
  iot         - IoT protocol attacks
  c2          - Command & Control
  redteam     - Red team campaigns
  exploit     - Exploit framework
  cloud       - Cloud security
  network     - Network infrastructure
  desktop     - Endpoint security
  purple      - Purple team mode
```

### Consistent Options
```bash
# Common flags across all modules
--verbose, -v        # Verbose output
--quiet, -q          # Minimal output
--output, -o FILE    # Save results to file
--format FORMAT      # Output format (json, html, markdown)
--target, -t TARGET  # Target specification
--help, -h           # Show help
```

### Progressive Disclosure
```bash
# Simple mode (guided)
akali mobile static app.apk

# Advanced mode (full control)
akali mobile static app.apk \
  --check-permissions \
  --check-secrets \
  --check-crypto \
  --output-format html \
  --export-endpoints endpoints.json
```

---

## Testing Strategy

### Unit Tests
- Test each scanner module independently
- Mock external tool calls
- Verify output formats

### Integration Tests
- Test tool integration (aircrack-ng, Frida, etc.)
- Test end-to-end workflows
- Test error handling

### Red Team Validation
- Run against intentionally vulnerable targets
- Verify exploits work
- Measure false positive rate

### Purple Team Validation
- Test against own infrastructure
- Verify detection capabilities
- Measure MTTD/MTTR

---

## Documentation

### User Guides
- Getting started guide
- Module-specific guides
- Hardware setup guides
- Legal and ethical guidelines

### Developer Docs
- Architecture overview
- Adding new modules
- Tool integration guide
- Agent development guide

### Cheat Sheets
- Command reference
- Common workflows
- Troubleshooting guide

---

## Future Enhancements (Post Phase 9)

### Potential Phase 10+
- **AI-Powered Attacks** - LLM-assisted exploitation
- **Zero-Click Exploits** - Browser, mobile, IoT
- **Supply Chain** - Package/dependency attacks
- **Social Engineering** - Phishing automation enhancements
- **Physical Security** - Badge cloning, lock picking tools
- **Vehicle Security** - CAN bus, OBD-II attacks
- **Industrial Systems** - SCADA, Modbus, PLC testing

---

## Appendix: Tool Comparison

### Why Build vs Buy/Integrate

| Capability | Akali Approach | Alternative | Rationale |
|------------|----------------|-------------|-----------|
| **Mobile Static** | Integrate MobSF + custom | Mobile Security Framework | MobSF is excellent, add custom checks |
| **Mobile Dynamic** | Integrate Frida + custom | Objection | Frida is industry standard |
| **C2 Infrastructure** | Build custom Go agents | Metasploit/Sliver | ZimMemory integration unique to us |
| **WiFi Attacks** | Integrate aircrack-ng | Wifite | aircrack-ng is mature, reliable |
| **BLE Attacks** | Integrate Bettercap + custom | Bluefruit, nRF Connect | Bettercap is powerful |
| **RF Analysis** | Integrate GNU Radio | Universal Radio Hacker | GNU Radio is industry standard |
| **Exploit Database** | Integrate ExploitDB + GitHub | Metasploit only | Broader coverage |
| **Fuzzing** | Integrate AFL++ | Build from scratch | AFL++ is best-in-class |

---

## Design Approval Sign-Off

**Approved By:** Dommo (User)
**Date:** 2026-02-20
**Next Step:** Create implementation plan with writing-plans skill

---

*This design document represents the complete architecture for Akali Phases 7-9, transforming it into the ultimate offensive security platform with red team operations, purple team validation, and comprehensive multi-platform attack capabilities.*
