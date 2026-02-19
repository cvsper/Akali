#!/bin/bash
# Test script for Akali daemons

echo "================================================"
echo "Akali Daemons Test Suite"
echo "================================================"
echo ""

cd /Users/sevs/akali

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((FAILED++))
    fi
}

echo "Test 1: Watch Daemon - Status Command"
python3 autonomous/daemons/watch_daemon.py status > /dev/null 2>&1
test_result $? "Watch daemon status command"

echo ""
echo "Test 2: Health Daemon - Status Command"
python3 autonomous/daemons/health_daemon.py status > /dev/null 2>&1
test_result $? "Health daemon status command"

echo ""
echo "Test 3: Health Daemon - Report Command"
python3 autonomous/daemons/health_daemon.py report > /dev/null 2>&1
test_result $? "Health daemon report command"

echo ""
echo "Test 4: File Existence - daemon_base.py"
[ -f autonomous/daemons/daemon_base.py ]
test_result $? "daemon_base.py exists"

echo ""
echo "Test 5: File Existence - watch_daemon.py"
[ -f autonomous/daemons/watch_daemon.py ]
test_result $? "watch_daemon.py exists"

echo ""
echo "Test 6: File Existence - health_daemon.py"
[ -f autonomous/daemons/health_daemon.py ]
test_result $? "health_daemon.py exists"

echo ""
echo "Test 7: Executable Permissions - watch_daemon.py"
[ -x autonomous/daemons/watch_daemon.py ]
test_result $? "watch_daemon.py is executable"

echo ""
echo "Test 8: Executable Permissions - health_daemon.py"
[ -x autonomous/daemons/health_daemon.py ]
test_result $? "health_daemon.py is executable"

echo ""
echo "Test 9: Python Import - DaemonBase"
python3 -c "from autonomous.daemons.daemon_base import DaemonBase" 2>/dev/null
test_result $? "DaemonBase can be imported"

echo ""
echo "Test 10: Python Import - WatchDaemon"
python3 -c "from autonomous.daemons.watch_daemon import WatchDaemon" 2>/dev/null
test_result $? "WatchDaemon can be imported"

echo ""
echo "Test 11: Python Import - HealthDaemon"
python3 -c "from autonomous.daemons.health_daemon import HealthDaemon" 2>/dev/null
test_result $? "HealthDaemon can be imported"

echo ""
echo "Test 12: Health Status File Generation"
if [ -f autonomous/daemons/health_status.json ]; then
    python3 -c "import json; json.load(open('autonomous/daemons/health_status.json'))" 2>/dev/null
    test_result $? "health_status.json is valid JSON"
else
    echo -e "${YELLOW}⊘ SKIP${NC}: health_status.json not generated yet (run health daemon first)"
fi

echo ""
echo "================================================"
echo "Test Results"
echo "================================================"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✅${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed! ❌${NC}"
    exit 1
fi
