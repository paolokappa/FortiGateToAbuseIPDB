import paramiko
import requests
import base64
from datetime import datetime

# Configuration
fortigate_ip = 'YOUR_FORTIGATE_IP'  # Replace with your Fortigate IP/hostname
abuseipdb_api_key = 'YOUR_ABUSEIPDB_API_KEY'  # Replace with your AbuseIPDB API key
abuseipdb_check_url = 'https://api.abuseipdb.com/api/v2/check'
abuseipdb_report_url = 'https://api.abuseipdb.com/api/v2/report'
log_file = '/var/log/fortigate_quarantine.log'

# Read and decode the SSH credentials from the configuration file
with open('/opt/FortiGateToAbuseIPDB/fortigate_creds.dat', 'r') as f:
    encoded_username = f.readline().strip()
    encoded_password = f.readline().strip()

ssh_username = base64.b64decode(encoded_username).decode()
ssh_password = base64.b64decode(encoded_password).decode()

# Commands to execute
command_list_ips = 'diagnose user banned-ip list'
command_clear_ips = 'diagnose user banned-ip clear'

def run_ssh_command(host, username, password, command):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            print(f"Error: {error}")
        
        return output, error
    except Exception as e:
        print(f"Error executing SSH command: {e}")
        return None, str(e)
    finally:
        ssh.close()

def query_abuseipdb(ip):
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    response = requests.get(abuseipdb_check_url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error querying AbuseIPDB for {ip}: {response.status_code} - {response.text}")
        return None

def report_abuseipdb(ip, categories, comment):
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    data = {
        'ip': ip,
        'categories': categories,
        'comment': comment
    }
    response = requests.post(abuseipdb_report_url, headers=headers, data=data)
    if response.status_code == 200:
        return f"IP {ip} successfully reported for {comment}."
    else:
        return f"Error reporting {ip} for {comment}: {response.status_code} - {response.text}"

def log_event(message, log_file):
    timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    with open(log_file, 'a') as log:
        log.write(f"{timestamp} - {message}\n")

def parse_output(output, log_file):
    lines = output.strip().split('\n')
    ip_count = 0
    for line in lines[1:]:  # Skip the header
        line = line.strip()
        if line:  # Ignore empty lines
            parts = line.split()
            if len(parts) >= 5:  # Ensure there are enough columns
                ip = parts[0]
                cause = parts[-1]
                log_event(f"{ip} {cause}", log_file)
                ip_count += 1

                # Reporting to AbuseIPDB
                if cause == 'IPS':
                    categories = '15'  # Category 15: Hacking
                    comment = "FortiGate detected IPS attempt"
                elif cause == 'DOS':
                    categories = '4'  # Category 4: DDoS Attack
                    comment = "FortiGate detected DOS attempt"
                elif cause == 'Administrative':
                    categories = '18'  # Category 18: Other
                    comment = "FortiGate administrative action"
                else:
                    categories = '18'  # Category 18: Other
                    comment = f"FortiGate detected {cause} attempt"
                
                report_result = report_abuseipdb(ip, categories, comment)
                log_event(report_result, log_file)

                # Additional information from AbuseIPDB
                abuse_info = query_abuseipdb(ip)
                if abuse_info:
                    log_event(f"AbuseIPDB Info for {ip}:", log_file)
                    log_event(f" - Score: {abuse_info['data']['abuseConfidenceScore']}", log_file)
                    log_event(f" - Domain: {abuse_info['data']['domain']}", log_file)
                    log_event(f" - ISP: {abuse_info['data']['isp']}", log_file)
                    log_event(f" - Country: {abuse_info['data']['countryCode']}", log_file)

    return ip_count

# Log the script execution
log_event("---------------------------------------", log_file)
log_event("Script execution started.", log_file)

# Execute the command and write the result to the log file
output, error = run_ssh_command(fortigate_ip, ssh_username, ssh_password, command_list_ips)
if error:
    log_event(f"Failed to list banned IPs: {error}", log_file)
else:
    ip_count = parse_output(output, log_file)
    if ip_count > 0:
        # Clear the list of banned IPs
        clear_output, clear_error = run_ssh_command(fortigate_ip, ssh_username, ssh_password, command_clear_ips)
        if clear_error:
            log_event(f"Failed to clear banned IPs: {clear_error}", log_file)
        else:
            log_event("Successfully cleared banned IPs.", log_file)
    log_event(f"Found {ip_count} IPs in the quarantine list.", log_file)
