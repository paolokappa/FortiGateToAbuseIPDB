"""
Configuration template for FortiGate to AbuseIPDB Integration
Copy this file to config.py and update with your values
"""

# AbuseIPDB Configuration
ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_API_KEY_HERE'

# Email Configuration (for stats reports)
SMTP_CONFIG = {
    'smtp_server': 'your.smtp.server',
    'smtp_port': 587,
    'smtp_user': 'your-smtp-user@example.com',
    'smtp_pass': 'your-smtp-password',
    'sender': 'fortigate@example.com',
    'recipient': 'security@example.com',
}

# Paths Configuration
PATHS = {
    'fortigate_list': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'creds_file': '/opt/FortiGateToAbuseIPDB/fortigate_creds.dat',
    'ip_whitelist': '/opt/FortiGateToAbuseIPDB/ip_whitelist.txt',
    'log_file': '/var/log/fortigate_quarantine.log',
    'whois_cache': '/tmp/fortigate_whois_cache.pkl',
}

# SSH Configuration
SSH_CONFIG = {
    'timeout': 30,
    'command_timeout': 60,
    'keepalive_interval': 10,
    'max_retries': 3,
    'retry_delay': 2,
}

# Processing Configuration
PROCESSING = {
    'delay_between_fortigates': 5,  # seconds
    'api_call_delay': 0.5,  # seconds between AbuseIPDB API calls
}