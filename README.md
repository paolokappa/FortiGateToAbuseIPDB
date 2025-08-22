# FortiGate to AbuseIPDB Integration Suite v2.1

[![Python](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API%20v2-orange)](https://www.abuseipdb.com/)
[![FortiGate](https://img.shields.io/badge/FortiGate-7.0%2B-red)](https://www.fortinet.com/)

A comprehensive security intelligence automation suite that bridges FortiGate firewalls with the AbuseIPDB threat intelligence platform. This enterprise-grade solution monitors, analyzes, and reports malicious activities across multiple FortiGate devices while maintaining detailed statistics and generating professional security reports.

## 🌟 What's New in v2.1

- **Complete Architecture Rewrite**: Enhanced performance and reliability
- **Multi-FortiGate Processing**: Handle entire infrastructure in a single run
- **Advanced Statistics Engine**: Comprehensive analytics and reporting
- **Email Report Generator**: Professional HTML reports with embedded branding
- **Intelligent IP Filtering**: Private IP detection and custom whitelisting
- **SSH Connection Pooling**: Optimized connection management with retry logic
- **WHOIS Integration**: Automatic threat actor identification with caching

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Reports & Analytics](#-reports--analytics)
- [Security Features](#-security-features)
- [API Documentation](#-api-documentation)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Overview

FortiGate to AbuseIPDB Integration Suite is an enterprise security automation platform that:

1. **Monitors** multiple FortiGate firewalls for banned/quarantined IP addresses
2. **Analyzes** attack patterns and categorizes threats (IPS, DoS, Brute Force)
3. **Reports** malicious IPs to AbuseIPDB's global threat intelligence database
4. **Generates** comprehensive security reports with statistics and visualizations
5. **Maintains** clean firewall states by managing quarantine lists and address groups

This solution helps security teams automate threat intelligence sharing while maintaining visibility into their network's security posture.

## ✨ Features

### Core Functionality

#### 🔧 Main Processing Engine (`fortigate2AbuseIPDB.py`)
- **Multi-FortiGate Support**: Process unlimited FortiGate devices sequentially
- **Dual IP Protocol**: Full IPv4 and IPv6 support with proper categorization
- **Smart Detection**: Automatic FortiGate version detection (7.0.x, 7.4.x)
- **Automated Reporting**: Real-time submission to AbuseIPDB with rate limit handling
- **Comprehensive Filtering**:
  - RFC1918 private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - RFC4193 IPv6 ULA (fc00::/7, fd00::/8)
  - Link-local addresses (169.254.0.0/16, fe80::/10)
  - Loopback, multicast, and reserved ranges
  - Custom user-defined whitelist support
  - Known DNS server protection (Google, Cloudflare, Quad9, OpenDNS)

#### 📊 Statistics & Analytics (`generate_stats_report.py`)
- **Terminal Dashboard**: Beautiful console output with color-coded statistics
- **Attack Categorization**: IPS, DoS, and Brute Force classification
- **Network Analysis**: Automatic /24 (IPv4) and /64 (IPv6) network grouping
- **Timeline Tracking**: 7-day attack pattern analysis
- **Export Formats**:
  - JSON for programmatic access
  - CSV for spreadsheet analysis
  - Terminal for quick viewing

#### 📧 Email Report Generator (`fortigate2AbuseIPDB_stats.py`)
- **HTML Reports**: Outlook-compatible responsive design
- **Embedded Branding**: Logo integration for professional appearance
- **WHOIS Integration**: Automatic threat actor identification
- **Visual Statistics**: Color-coded severity indicators
- **Caching System**: 7-day WHOIS cache for performance
- **SMTP Support**: Compatible with Exchange, Office 365, and standard SMTP

### Advanced Features

#### 🔒 Security & Compliance
- **Credential Encryption**: Base64 encoded storage (upgradeable to stronger encryption)
- **Audit Logging**: Comprehensive activity logging to `/var/log/fortigate_quarantine.log`
- **IP Privacy**: Automatic filtering of internal and private IP ranges
- **Rate Limit Compliance**: Respects AbuseIPDB's 15-minute reporting window

#### 🚀 Performance & Reliability
- **Connection Pooling**: Reuses SSH connections across operations
- **Retry Logic**: Automatic retry on connection failures (configurable)
- **Broken Pipe Handling**: Graceful recovery from SSH interruptions
- **Parallel Processing**: Efficient batch operations where applicable
- **Memory Management**: Chunked reading for large outputs

#### 🛠️ Maintenance & Cleanup
- **Quarantine Management**: Automatic clearing after processing
- **Address Group Cleanup**: Removes Banned_Admin_Failed groups (IPv4/IPv6)
- **Firewall Object Removal**: Deletes AbuseIPDB-tagged addresses
- **State Synchronization**: Ensures clean FortiGate state after each run

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FortiGate Infrastructure                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │   FG1    │  │   FG2    │  │   FG3    │  │   FGn    │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
└───────┼─────────────┼─────────────┼─────────────┼─────────┘
        │             │             │             │
        └─────────────┴──────┬──────┴─────────────┘
                             │ SSH
                    ┌────────▼────────┐
                    │   Main Engine   │
                    │ fortigate2Abuse │
                    │     IPDB.py     │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
    ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │   Filtering  │ │   Reporting │ │   Cleanup   │
    │    Engine    │ │   to Abuse  │ │  Operations │
    │              │ │     IPDB    │ │             │
    └──────────────┘ └──────┬──────┘ └──────────────┘
                             │
                    ┌────────▼────────┐
                    │   Statistics    │
                    │    Generator    │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐      ┌──────▼──────┐    ┌──────▼──────┐
    │Terminal │      │    Email    │    │  JSON/CSV   │
    │ Report  │      │   Report    │    │   Export    │
    └─────────┘      └─────────────┘    └─────────────┘
```

## 💻 Requirements

### System Requirements
- **Operating System**: Linux/Unix (tested on Ubuntu 20.04+, CentOS 7+, Debian 10+)
- **Python**: 3.6 or higher
- **Memory**: Minimum 512MB RAM
- **Storage**: 100MB for application + log space
- **Network**: SSH access to FortiGate devices

### FortiGate Requirements
- **FortiOS Version**: 7.0.0 or higher (7.4.x fully supported)
- **Access Level**: Admin or super_admin privileges
- **SSH**: Enabled on management interface
- **Commands Required**:
  - `get system status`
  - `diagnose user quarantine list` (v7.0)
  - `diagnose user banned-ip list` (v7.4)
  - `diagnose user quarantine clear` / `diagnose user banned-ip clear`
  - `config firewall address` / `config firewall address6`
  - `config firewall addrgrp` / `config firewall addrgrp6`

### Python Dependencies
```python
paramiko>=2.7.2  # SSH connections
requests>=2.25.1  # API interactions
```

### External Services
- **AbuseIPDB Account**: Free or paid API key from [https://www.abuseipdb.com](https://www.abuseipdb.com)
- **SMTP Server** (optional): For email reports

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/paolokappa/FortiGateToAbuseIPDB.git
cd FortiGateToAbuseIPDB
```

### 2. Install Python Dependencies

```bash
# Using pip
pip3 install paramiko requests

# Or using requirements file (if provided)
pip3 install -r requirements.txt
```

### 3. Set Up Credentials

```bash
# Use the provided setup script
chmod +x setup_credentials.sh
./setup_credentials.sh

# Or manually create credentials file
echo -n "your_fortigate_username" | base64 > fortigate_creds.dat
echo -n "your_fortigate_password" | base64 >> fortigate_creds.dat
chmod 600 fortigate_creds.dat
```

### 4. Configure FortiGate List

```bash
# Copy and edit the example file
cp fortigate.list.example fortigate.list
nano fortigate.list

# Format: IP_ADDRESS HOSTNAME
# Example:
# 192.168.1.1 firewall01.company.com
# 10.0.0.1 firewall02.company.com
```

### 5. Set Up IP Whitelist (Optional)

```bash
# Copy and customize the whitelist
cp ip_whitelist.txt.example ip_whitelist.txt
nano ip_whitelist.txt

# Add your organization's public IP ranges
# Example:
# 203.0.113.0/24
# 2001:db8::/32
```

### 6. Configure API Keys and Settings

Edit the main script to add your AbuseIPDB API key:

```python
# In fortigate2AbuseIPDB.py
'abuseipdb_api_key': 'YOUR_API_KEY_HERE',
```

For email reports, update SMTP settings in `fortigate2AbuseIPDB_stats.py`:

```python
'smtp_server': 'your.mail.server',
'smtp_port': 587,
'smtp_user': 'username@domain.com',
'smtp_pass': 'password',
'sender': 'fortigate@domain.com',
'recipient': 'security@domain.com',
```

### 7. Verify Installation

```bash
# Test connectivity to FortiGates
python3 fortigate2AbuseIPDB.py --test

# Check log file creation
tail -f /var/log/fortigate_quarantine.log
```

## ⚙️ Configuration

### Configuration Files

#### `fortigate.list`
Lists all FortiGate devices to monitor:
```
192.168.1.1 fw-headquarters.company.com
10.0.0.1 fw-branch01.company.com
172.16.0.1 fw-datacenter.company.com
```

#### `ip_whitelist.txt`
Custom IP ranges to exclude from reporting:
```
# Company Public IP Ranges
203.0.113.0/24
198.51.100.0/24
2001:db8:1234::/48

# Partner Networks
192.0.2.0/24
```

#### `fortigate_creds.dat`
Base64 encoded credentials (created by setup script):
```
dXNlcm5hbWU=
cGFzc3dvcmQ=
```

### Environment Variables (Optional)

```bash
export ABUSEIPDB_KEY="your_api_key"
export FORTIGATE_USER="admin"
export FORTIGATE_PASS="password"
export SMTP_SERVER="mail.company.com"
```

### Advanced Configuration

Edit CONFIG dictionary in scripts for fine-tuning:

```python
CONFIG = {
    'ssh_timeout': 30,           # SSH connection timeout
    'command_timeout': 60,       # Command execution timeout
    'delay_between_fortigates': 5,  # Seconds between devices
    'ssh_keepalive_interval': 10,   # SSH keepalive interval
    'max_retries': 3,            # Retry attempts on failure
    'retry_delay': 2,            # Seconds between retries
}
```

## 📖 Usage

### Basic Operations

#### Process All FortiGates and Report to AbuseIPDB
```bash
python3 fortigate2AbuseIPDB.py
```

#### Generate Terminal Statistics Report
```bash
python3 generate_stats_report.py
```

#### Send Email Report
```bash
python3 fortigate2AbuseIPDB_stats.py
```

### Advanced Usage

#### Export Statistics to JSON/CSV
```bash
# Export both formats
python3 generate_stats_report.py --json --csv

# Specify output location
python3 generate_stats_report.py --json --output /path/to/report.json

# Quiet mode (no terminal output)
python3 generate_stats_report.py --json --csv --quiet
```

#### Automation with Cron

```bash
# Edit crontab
crontab -e

# Run every 4 hours
0 */4 * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py

# Daily statistics report at 8 AM
0 8 * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB_stats.py

# Weekly CSV export on Mondays
0 9 * * 1 /usr/bin/python3 /opt/FortiGateToAbuseIPDB/generate_stats_report.py --csv --output /reports/weekly_$(date +\%Y\%m\%d).csv
```

#### Systemd Service (Optional)

Create `/etc/systemd/system/fortigate-abuseipdb.service`:

```ini
[Unit]
Description=FortiGate to AbuseIPDB Integration
After=network.target

[Service]
Type=oneshot
User=security
ExecStart=/usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable timer `/etc/systemd/system/fortigate-abuseipdb.timer`:

```ini
[Unit]
Description=Run FortiGate to AbuseIPDB every 4 hours

[Timer]
OnBootSec=10min
OnUnitActiveSec=4h

[Install]
WantedBy=timers.target
```

## 📊 Reports & Analytics

### Terminal Report Output

```
================================================================================
                         FORTIGATE SECURITY REPORT
================================================================================

📊 ATTACK OVERVIEW
----------------------------------------
Total Attacks Blocked:     1,245
Unique Attacking IPs:      387
IPv4 Attacks:              1,180
IPv6 Attacks:              65

🎯 ATTACK CATEGORIES
----------------------------------------
Brute Force          890 ( 71.5%) ████████████████████████████████████
IPS                  275 ( 22.1%) ███████████
DoS                   80 (  6.4%) ███

🔝 TOP 5 FORTIGATES BY ACTIVITY
----------------------------------------
1. fw-headquarters         456 attacks
   └─ IPS: 125 | DoS: 31 | Auth: 300
2. fw-datacenter          389 attacks
   └─ IPS: 98 | DoS: 41 | Auth: 250
```

### Email Report Features

- **Executive Summary**: High-level attack statistics
- **Visual Indicators**: Color-coded severity levels
- **Top Threats Table**: Attacking networks with WHOIS data
- **FortiGate Status**: Device-by-device breakdown
- **Embedded Logo**: Professional branding
- **Mobile Responsive**: Optimized for all devices

### JSON Export Schema

```json
{
  "generated": "2024-01-15T10:30:00",
  "summary": {
    "total_attacks": 1245,
    "unique_attackers": 387,
    "attack_types": {
      "Brute Force": 890,
      "IPS": 275,
      "DoS": 80
    }
  },
  "top_attackers": [
    {
      "cidr": "185.230.13.0/24",
      "count": 125,
      "ips": ["185.230.13.5", "185.230.13.7"],
      "whois": {
        "country": "NL",
        "organization": "BadActor Corp",
        "asn": "AS12345"
      }
    }
  ],
  "timeline": {
    "2024-01-15": {"IPS": 45, "DoS": 12, "Brute Force": 78}
  }
}
```

## 🔐 Security Features

### IP Filtering System

#### Automatically Filtered (Never Reported)

**Private IPv4 Ranges:**
- `10.0.0.0/8` - Class A private
- `172.16.0.0/12` - Class B private
- `192.168.0.0/16` - Class C private
- `100.64.0.0/10` - Carrier-grade NAT
- `127.0.0.0/8` - Loopback
- `169.254.0.0/16` - Link-local

**Private IPv6 Ranges:**
- `fc00::/7` - Unique local addresses
- `fe80::/10` - Link-local
- `::1/128` - Loopback
- `ff00::/8` - Multicast
- `fec0::/10` - Site-local (deprecated)

**Protected DNS Servers:**
- Google: 8.8.8.8, 8.8.4.4, 2001:4860:4860::8888
- Cloudflare: 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111
- Quad9: 9.9.9.9, 2620:fe::fe
- OpenDNS: 208.67.222.222, 208.67.220.220

### Attack Classification

| Cause | Category | AbuseIPDB Categories |
|-------|----------|---------------------|
| IPS | Intrusion Prevention | 15 (Hacking) |
| DOS/DoS | Denial of Service | 4 (DDoS Attack) |
| Administrative | Authentication | 18 (Brute Force) |

### Compliance & Privacy

- **GDPR Compliant**: No personal data collection
- **IP Privacy**: Internal IPs never leave your network
- **Audit Trail**: Complete logging of all operations
- **Credential Security**: Encrypted storage (upgradeable)

## 🔌 API Documentation

### AbuseIPDB Integration

#### Report Endpoint
```python
POST https://api.abuseipdb.com/api/v2/report

Headers:
  Key: YOUR_API_KEY
  Accept: application/json

Data:
  ip: "192.0.2.1"
  categories: "18,22"  # Brute Force, SSH
  comment: "FortiGate detected brute force login attempt"
```

#### Check Endpoint
```python
GET https://api.abuseipdb.com/api/v2/check

Parameters:
  ipAddress: "192.0.2.1"
  maxAgeInDays: 90
  verbose: true
```

### Rate Limits

- **Reporting**: Same IP once per 15 minutes
- **Checking**: 1000 requests per day (free tier)
- **Bulk Report**: 10000 IPs per request (paid tier)

## 🔧 Troubleshooting

### Common Issues

#### SSH Connection Failed
```bash
# Test SSH connectivity
ssh admin@192.168.1.1

# Check FortiGate SSH settings
config system global
  set admin-ssh-port 22
  set admin-ssh-grace-period 120
end
```

#### API Rate Limit (429 Error)
- Normal behavior when IP was reported < 15 minutes ago
- Script continues processing other IPs
- Consider implementing local cache

#### No Banned IPs Found
```bash
# Verify FortiGate command
ssh admin@fortigate
diagnose user banned-ip list  # FortiOS 7.4
diagnose user quarantine list # FortiOS 7.0
```

#### Email Not Received
1. Check spam/junk folders
2. Verify SMTP credentials
3. Test with telnet: `telnet smtp.server 587`
4. Check firewall rules for SMTP

### Debug Mode

Enable verbose logging:
```python
# In scripts, set debug level
logging.basicConfig(level=logging.DEBUG)
```

### Log Analysis

```bash
# View recent errors
grep ERROR /var/log/fortigate_quarantine.log | tail -20

# Check processing status
grep "Processing FortiGate" /var/log/fortigate_quarantine.log

# Monitor in real-time
tail -f /var/log/fortigate_quarantine.log
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup

```bash
# Fork and clone
git clone https://github.com/yourusername/FortiGateToAbuseIPDB.git
cd FortiGateToAbuseIPDB

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .
```

### Code Style

- Follow PEP 8
- Use type hints where applicable
- Add docstrings to functions
- Maximum line length: 100 characters

### Testing

```bash
# Run tests
python -m pytest tests/

# Check code style
flake8 *.py

# Type checking
mypy *.py
```

### Pull Request Process

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [AbuseIPDB](https://www.abuseipdb.com) for their threat intelligence platform
- [Fortinet](https://www.fortinet.com) for FortiGate firewalls
- The Python community for excellent libraries
- All contributors and users of this project

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/paolokappa/FortiGateToAbuseIPDB/issues)
- **Discussions**: [GitHub Discussions](https://github.com/paolokappa/FortiGateToAbuseIPDB/discussions)
- **Security**: Report vulnerabilities privately via GitHub Security Advisories

## 🚦 Project Status

![Status](https://img.shields.io/badge/status-active-success)
![Maintenance](https://img.shields.io/badge/maintained-yes-green)
![Version](https://img.shields.io/badge/version-2.1.0-blue)

---

**Disclaimer**: This tool is provided for defensive security operations only. Users are responsible for complying with all applicable laws and regulations. Always ensure you have proper authorization before scanning or reporting IP addresses.

---

Made with ❤️ for the security community