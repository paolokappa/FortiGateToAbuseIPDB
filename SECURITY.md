# Security Policy

## ⚠️ IMPORTANT SECURITY NOTICE

**NEVER commit sensitive information to this repository!**

### Sensitive Data That Must Be Kept Private:
- API keys (AbuseIPDB or any other service)
- SMTP passwords and credentials
- FortiGate usernames and passwords
- IP addresses of your FortiGate devices
- Your organization's IP ranges (unless intentionally public)
- Email addresses used for notifications

### How to Keep Your Credentials Safe:

1. **API Keys**: 
   - Store in environment variables or separate config files
   - Never hardcode in scripts
   - Use placeholders in committed code

2. **SMTP Credentials**:
   - Use environment variables
   - Or use a separate, non-committed config file
   - Consider using OAuth2 or app passwords

3. **FortiGate Credentials**:
   - Use the `fortigate_creds.dat` file (excluded in .gitignore)
   - Consider using SSH keys instead of passwords
   - Use a secrets management system in production

### If You Accidentally Exposed Secrets:

1. **Immediately rotate all exposed credentials**
2. **Remove secrets from code**
3. **Force push to overwrite history**
4. **Review GitHub's secret scanning alerts**
5. **Enable GitHub secret scanning on your repository**

### Recommended Setup:

```python
# Use environment variables
import os

CONFIG = {
    'abuseipdb_api_key': os.getenv('ABUSEIPDB_API_KEY'),
    'smtp_pass': os.getenv('SMTP_PASSWORD'),
    # ... other configs
}
```

Or use a separate config file:

```python
# config_local.py (add to .gitignore)
ABUSEIPDB_API_KEY = 'your-actual-key'
SMTP_PASSWORD = 'your-actual-password'

# main script
try:
    from config_local import *
except ImportError:
    from config_example import *  # Use example config as fallback
```

## Reporting Security Vulnerabilities

Please report security vulnerabilities privately through GitHub Security Advisories.

Do NOT create public issues for security problems.