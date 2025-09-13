# Usage Guide

## 🚀 Basic Execution

### Manual Execution

```bash
# Standard execution
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py

# With verbose output
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py 2>&1 | tee -a /tmp/debug.log
```

### Automatic Execution

The script runs automatically every hour via crontab:
```
0 * * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py
```

---

## 📊 Monitoring

### Real-Time Log Monitoring

```bash
# Follow log in real-time
tail -f /var/log/fortigate_quarantine.log

# Filter errors only
tail -f /var/log/fortigate_quarantine.log | grep ERROR

# Filter for specific FortiGate
tail -f /var/log/fortigate_quarantine.log | grep "fortigate01"

# View only reported IPs
tail -f /var/log/fortigate_quarantine.log | grep "reported for"
```

### System Status Check

```bash
# Check last execution
grep "All FortiGate devices processed" /var/log/fortigate_quarantine.log | tail -1

# Count IPs processed today
grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "Successfully reported"

# Check recent errors
grep "ERROR" /var/log/fortigate_quarantine.log | tail -20

# Quick statistics
echo "=== DAILY STATISTICS ==="
echo "Reported IPs: $(grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "reported for")"
echo "IP DOS: $(grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "DOS attempt")"
echo "IP Admin: $(grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "brute-force")"
echo "Errors: $(grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "ERROR")"
```

---

## 📈 Reports and Statistics

### Manual Report Generation

```bash
# Generate statistics report
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB_stats.py

# Report is saved to
/tmp/fortigate_report_outlook.html
```

### Report Viewing

```bash
# On server with GUI
firefox /tmp/fortigate_report_outlook.html

# On server without GUI - local copy
scp user@server:/tmp/fortigate_report_outlook.html ./report.html
```

---

## 🔧 Maintenance Operations

### Manual Quarantine Cleanup

```bash
# Connect to FortiGate
ssh AbuseIPDB@10.0.1.1

# Clear all banned IPs
diagnose user banned-ip clear

# Clear firewall groups
config firewall addrgrp
edit Banned_Admin_Failed
unset member
end

config firewall addrgrp6
edit Banned_Admin_Failed_v6
unset member
end
```

### Single FortiGate Test

```python
#!/usr/bin/env python3
# test_single.py
import sys
sys.path.insert(0, '/opt/FortiGateToAbuseIPDB')
from fortigate2AbuseIPDB import *

# Override FortiGate list
test_list = "fortigate01.example.com 10.0.1.1"
with open('/tmp/test.list', 'w') as f:
    f.write(test_list)

CONFIG['fortigate_list_path'] = '/tmp/test.list'

# Execute
app = FortiGateAbuseIPDB()
app.run()
```

### Manual Log Rotation

```bash
# Immediate rotation
logrotate -f /etc/logrotate.d/fortigate-abuseipdb

# Compress old logs
gzip /var/log/fortigate_quarantine.log.1

# Clean old logs (over 30 days)
find /var/log -name "fortigate_quarantine.log*" -mtime +30 -delete
```

---

## 🔍 Functionality Verification

### Quick Check

```bash
# Verification script
cat > /tmp/check_system.sh << 'EOF'
#!/bin/bash
echo "=== FortiGate to AbuseIPDB SYSTEM CHECK ==="
echo ""

# Check crontab
echo "1. Crontab:"
crontab -l | grep fortigate2AbuseIPDB || echo "   ❌ NOT CONFIGURED!"
echo ""

# Check ultima esecuzione
echo "2. Last execution:"
grep "All FortiGate devices processed" /var/log/fortigate_quarantine.log | tail -1
echo ""

# Check processi
echo "3. Active processes:"
ps aux | grep -v grep | grep fortigate2AbuseIPDB || echo "   No active processes"
echo ""

# Check spazio disco
echo "4. Log disk space:"
du -sh /var/log/fortigate_quarantine.log 2>/dev/null
echo ""

# Check connettività FortiGate
echo "5. Main FortiGate connectivity test:"
timeout 2 nc -zv 10.0.1.1 22 2>&1 | grep -o "succeeded\|refused\|timed out"
echo ""

echo "=== END CHECK ==="
EOF

chmod +x /tmp/check_system.sh
/tmp/check_system.sh
```

### Complete Test

```bash
# Complete system test
cat > /tmp/full_test.py << 'EOF'
#!/usr/bin/env python3
import sys
import subprocess

print("=== COMPLETE SYSTEM TEST ===\n")

# Test import moduli
print("1. Testing module imports...")
try:
    import paramiko
    import requests
    import ipaddress
    print("   ✅ Python modules OK")
except ImportError as e:
    print(f"   ❌ Error: {e}")

# Test file configurazione
print("\n2. Testing configuration files...")
import os
files = [
    '/opt/FortiGateToAbuseIPDB/fortigate.list',
    '/opt/FortiGateToAbuseIPDB/fortigate_creds.dat',
    '/opt/FortiGateToAbuseIPDB/config_local.py'
]
for f in files:
    if os.path.exists(f):
        print(f"   ✅ {f}")
    else:
        print(f"   ❌ {f} MISSING!")

# Test API AbuseIPDB
print("\n3. Testing AbuseIPDB API...")
try:
    sys.path.insert(0, '/opt/FortiGateToAbuseIPDB')
    from config_local import ABUSEIPDB_API_KEY
    import requests
    
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    r = requests.get('https://api.abuseipdb.com/api/v2/check',
                     headers=headers,
                     params={'ipAddress': '8.8.8.8'},
                     timeout=5)
    if r.status_code == 200:
        print("   ✅ API AbuseIPDB OK")
    else:
        print(f"   ❌ API Error: {r.status_code}")
except Exception as e:
    print(f"   ❌ Error: {e}")

print("\n=== END TEST ===")
EOF

python3 /tmp/full_test.py
```

---

## 📝 Useful Commands

### FortiGate Commands

```bash
# List banned IPs
diagnose user banned-ip list

# Count banned IPs
diagnose user banned-ip list | grep -c DOS

# Remove single IP
diagnose user banned-ip delete src4 1.2.3.4

# Clear all
diagnose user banned-ip clear

# Show groups
show firewall addrgrp Banned_Admin_Failed
show firewall addrgrp6 Banned_Admin_Failed_v6
```

### Useful One-Liners

```bash
# Top 10 attacking IPs
grep "reported for" /var/log/fortigate_quarantine.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -10

# FortiGates with most attacks
grep "Processing FortiGate" /var/log/fortigate_quarantine.log | awk '{print $6}' | sort | uniq -c | sort -rn

# Attack distribution by type
grep "reported for" /var/log/fortigate_quarantine.log | grep -o "DOS\|Administrative\|IPS" | sort | uniq -c

# Whitelisted IPs that attempted attacks
grep "whitelisted" /var/log/fortigate_quarantine.log | awk '{print $4}' | sort -u
```

---

## 🚨 Quick Troubleshooting

### Script won't start
```bash
# Check permissions
ls -la /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py
chmod 755 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py

# Manual test
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py
```

### No IPs processed
```bash
# Check FortiGate connection
ssh AbuseIPDB@10.0.1.1 "diagnose user banned-ip list | head -5"

# Check log for errors
grep ERROR /var/log/fortigate_quarantine.log | tail -20
```

### Too many 429 errors
```bash
# Normal if same IP reported multiple times
# Wait 15 minutes between reports of the same IP
```

---

*Last updated: September 13, 2025*