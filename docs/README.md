# FortiGate to AbuseIPDB Integration Suite - Documentation

## 📚 Documentation Index

### 1. [Architecture](architecture.md)
- System overview
- Main components
- Data flow
- FortiGate integration

### 2. [Installation](installation.md)
- System requirements
- Dependencies installation
- Initial configuration
- Crontab setup

### 3. [Configuration](configuration.md)
- Configuration files
- FortiGate credentials
- AbuseIPDB API
- IP whitelist

### 4. [Usage](usage.md)
- Manual execution
- Log monitoring
- Statistics scripts
- Maintenance

### 5. [Workflow](workflow.md)
- Complete processing cycle
- Banned IP management
- Automatic removal
- FortiGate automation integration

### 6. [Troubleshooting](troubleshooting.md)
- Common issues
- Frequent errors
- Debug and diagnostics
- FAQ

### 7. [API Reference](api-reference.md)
- Main classes
- Public methods
- Data structures
- Code examples

### 8. [Changelog](changelog.md)
- Change history
- Released versions
- Bug fixes
- Improvements

---

## 🚀 Quick Start

```bash
# Manual execution
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py

# Check logs
tail -f /var/log/fortigate_quarantine.log

# Generate statistics report
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB_stats.py
```

## 📊 System Status

- **Version**: 2.1.0
- **Last Update**: September 2025
- **Schedule**: Hourly via crontab
- **Supported FortiGates**: 11+
- **Compatibility**: FortiOS 7.0 - 7.4

## 📞 Support

For issues or questions:
- Email: soc@example.com
- Repository: https://github.com/paolokappa/FortiGateToAbuseIPDB

---

*Documentation generated September 2025*