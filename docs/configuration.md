# Configuration

## 📁 Configuration Files

### 1. `config_local.py`

API key for AbuseIPDB:

```python
# /opt/FortiGateToAbuseIPDB/config_local.py
ABUSEIPDB_API_KEY = 'your-api-key-here'
```

**How to get the API key:**
1. Register at https://www.abuseipdb.com
2. Go to Account → API
3. Generate a new key
4. Free limits: 1000 reports/day

---

### 2. `fortigate.list`

List of FortiGates to monitor:

```
# /opt/FortiGateToAbuseIPDB/fortigate.list
# Format: fqdn_name ip_address
fortigate01.example.com 10.0.1.1
restaurant-italy.example.com 10.69.30.1
maha-office.example.com 10.69.40.1
maha-restaurant.example.com 10.69.46.1
customer1.example.com 10.0.2.1
bridge.example.com 10.0.3.2
wallisellen.example.com 10.0.4.1
shop.example.com 10.0.5.1
tschingg1.example.com 10.0.6.1
tschingg2.example.com 10.0.7.1
tschingg3.example.com 10.0.8.1
```

---

### 3. `fortigate_creds.dat`

SSH credentials in base64:

```bash
# Create file
echo -n "AbuseIPDB" | base64 > fortigate_creds.dat
echo -n "Stabio555*" | base64 >> fortigate_creds.dat

# Result:
# QWJ1c2VJUGRC
# U3RhYmlvNTU1Kg==

# Secure permissions
chmod 600 fortigate_creds.dat
```

---

### 4. `ip_whitelist.txt`

Networks to exclude from reporting:

```
# /opt/FortiGateToAbuseIPDB/ip_whitelist.txt
# Company networks
203.0.113.0/24
2001:db8::/32

# Example other networks
192.168.0.0/16    # Private network
10.0.0.0/8        # Private network
172.16.0.0/12     # Private network
```

---

## ⚙️ Configurable Parameters

### In the `fortigate2AbuseIPDB.py` file:

```python
CONFIG = {
    'fortigate_list_path': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'creds_file_path': '/opt/FortiGateToAbuseIPDB/fortigate_creds.dat',
    'ip_whitelist_path': '/opt/FortiGateToAbuseIPDB/ip_whitelist.txt',
    'abuseipdb_api_key': ABUSEIPDB_API_KEY,
    'abuseipdb_check_url': 'https://api.abuseipdb.com/api/v2/check',
    'abuseipdb_report_url': 'https://api.abuseipdb.com/api/v2/report',
    'log_file': '/var/log/fortigate_quarantine.log',
    'ssh_timeout': 30,
    'command_timeout': 60,
    'delay_between_fortigates': 5,
    'ssh_keepalive_interval': 10,
    'max_retries': 3,
    'retry_delay': 2
}
```

### Predefined DNS Whitelist:

```python
IP_WHITELIST = {
    # Google DNS
    '8.8.8.8', '8.8.4.4',
    '2001:4860:4860::8888', '2001:4860:4860::8844',
    
    # CloudFlare DNS
    '1.1.1.1', '1.0.0.1',
    '2606:4700:4700::1111', '2606:4700:4700::1001',
    
    # Quad9 DNS
    '9.9.9.9', '149.112.112.112',
    '2620:fe::fe', '2620:fe::9',
    
    # OpenDNS
    '208.67.222.222', '208.67.220.220',
    '2620:119:35::35', '2620:119:53::53'
}
```

---

## 🔐 FortiGate Configuration

### Optimized DoS Policy for NTP

```bash
config firewall DoS-policy
    edit 8
        set name "Enhanced Protection NTP Server IPv4"
        set interface "port2"
        set srcaddr "all"
        set dstaddr "Time Server V4"
        set service "NTP"
        config anomaly
            edit "udp_flood"
                set status enable
                set threshold 200000  # Increased for NTP
            next
            edit "udp_scan"
                set status disable    # Disabled for NTP
            next
            edit "udp_src_session"
                set threshold 100000  # Increased
            next
            edit "udp_dst_session"
                set threshold 150000  # Increased
            next
        end
    next
end
```

### Automation for Failed Logins

```bash
# Trigger
config system automation-trigger
    edit "Admin_Login_Failed"
        set event-type event-log
        set logid 32002
    next
end

# Action
config system automation-action
    edit "Add_IP_to_Group"
        set action-type cli-script
        set script "
            diagnose user banned-ip add src4 %%log.srcip%% 7200 admin
            config firewall address
                edit %%log.srcip%%
                set subnet %%log.srcip%%/32
                set comment 'AbuseIPDB'
                set color 6
            next
            end
            config firewall addrgrp
                edit Banned_Admin_Failed
                append member %%log.srcip%%
            next
            end
        "
        set accprofile "super_admin"
    next
end

# Stitch
config system automation-stitch
    edit "Quarantine_Admin_Login_Failed"
        set trigger "Admin_Login_Failed"
        config actions
            edit 1
                set action "Add_IP_to_Group"
            next
        end
    next
end
```

---

## 📧 Email Configuration (Statistics Script)

In the `fortigate2AbuseIPDB_stats.py` file:

```python
# Email configuration
EMAIL_CONFIG = {
    'smtp_server': 'localhost',
    'smtp_port': 25,
    'from_email': 'fortigate@example.com',
    'to_emails': ['soc@example.com'],
    'subject': 'FortiGate Security Report - {date}'
}
```

---

## ⏰ Crontab Scheduling

```bash
# Edit crontab
crontab -e

# Main script - every hour
0 * * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py >/dev/null 2>&1

# Statistics report - daily at 23:58
58 23 * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB_stats.py >/dev/null 2>&1

# Log cleanup - every Sunday at 3:00
0 3 * * 0 /usr/bin/logrotate -f /etc/logrotate.d/fortigate-abuseipdb
```

---

## 🔧 Performance Tuning

### For environments with many banned IPs:

```python
# Reduce delay between API calls (default 0.5s)
time.sleep(0.2)  # Min recommended to avoid rate limiting

# Increase SSH timeout for slow FortiGates
CONFIG['ssh_timeout'] = 60
CONFIG['command_timeout'] = 120

# Reduce delay between FortiGates
CONFIG['delay_between_fortigates'] = 2  # From 5 to 2 seconds
```

### To reduce load:

```python
# Increase delay between API calls
time.sleep(1.0)  # More conservative

# Process fewer FortiGates per execution
# Split fortigate.list into multiple files
```

---

## 🎯 Best Practices

1. **Security:**
   - Always use 600 permissions for credential files
   - Rotate API key periodically
   - Use a dedicated user on FortiGates

2. **Performance:**
   - Monitor logs to identify patterns
   - Optimize DoS policies to reduce false positives
   - Use whitelist to exclude legitimate services

3. **Maintenance:**
   - Check logs weekly
   - Verify crontab is active
   - Update whitelist as needed

---

*Last updated: September 13, 2025*