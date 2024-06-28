# FortiGateToAbuseIPDB
FortiGateToAbuseIPDB is a Python script that allows you to read all IPv4/IPv6 addresses from the FortiGate quarantine list, forward the malicious IPs to the AbuseIPDB service, and then clear the list.

Sure, I can help you create a detailed description for your GitHub project. Below is a comprehensive description of the FortiGateToAbuseIPDB script, covering its functionality, requirements, installation, and usage.

---

## FortiGateToAbuseIPDB

### Overview

**FortiGateToAbuseIPDB** is a Python script designed to automate the process of managing the quarantine list on FortiGate devices. It reads all IPv4/IPv6 addresses from the FortiGate quarantine list, forwards the malicious IPs to the AbuseIPDB service, and then clears the list. This helps in maintaining a clean quarantine list while contributing to a global database of malicious IP addresses.

### Features

- **Automated Reading**: Retrieves all IP addresses from the FortiGate quarantine list.
- **Reporting**: Submits malicious IP addresses to the AbuseIPDB service for global sharing.
- **Cleanup**: Clears the quarantine list after reporting, ensuring no duplication of effort.
- **IPv4/IPv6 Support**: Handles both IPv4 and IPv6 addresses.
- **Logging**: Provides detailed logging for monitoring and troubleshooting.

### Requirements

- Python 3.x
- FortiGate device with quarantine list access
- AbuseIPDB API key

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/FortiGateToAbuseIPDB.git
   cd FortiGateToAbuseIPDB
   ```

2. **Install Dependencies**:
   Ensure you have the necessary Python libraries installed:
   ```bash
   pip install requests
   ```

3. **Configure API Keys**:
   Edit the script to include your AbuseIPDB API key and FortiGate device credentials.

### Usage

1. **Run the Script**:
   ```bash
   python3 fortigate_quarantine.py
   ```

2. **Automation with Cron**:
   To automate the execution, you can set up a cron job. For example, to run the script every hour, add the following line to your crontab:
   ```bash
   0 * * * * /usr/bin/python3 /path/to/fortigate_quarantine.py
   ```

### Script Functionality

1. **Initialization**:
   The script starts by importing necessary libraries and setting up configuration variables, including the API keys and FortiGate device details.

2. **Fetching Quarantine List**:
   The script connects to the FortiGate device using the provided credentials and retrieves the quarantine list. This includes both IPv4 and IPv6 addresses.

3. **Reporting to AbuseIPDB**:
   For each IP address in the quarantine list, the script sends a report to AbuseIPDB using their API. This helps in contributing to a global repository of malicious IP addresses.

4. **Clearing the Quarantine List**:
   After successfully reporting the IPs, the script clears the quarantine list on the FortiGate device to ensure no duplication of reports.

5. **Logging**:
   Detailed logs are maintained throughout the process, capturing successful reports, any errors encountered, and actions taken to clear the quarantine list.

### Logging and Troubleshooting

Logs are stored in `/var/log/fortigate_quarantine.log` by default. You can review these logs to ensure the script is functioning correctly or to diagnose any issues.

### Example Log Entry

```
2024-06-28 12:00:00 - INFO - Retrieved 5 IP addresses from the FortiGate quarantine list.
2024-06-28 12:00:05 - INFO - Successfully reported IP 192.168.1.1 to AbuseIPDB.
2024-06-28 12:00:06 - INFO - Successfully reported IP 2001:0db8::1 to AbuseIPDB.
2024-06-28 12:00:07 - INFO - Cleared 5 IP addresses from the FortiGate quarantine list.
```

### Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any enhancements or bug fixes.

### License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

With this description, users visiting your GitHub repository will have a clear and comprehensive understanding of what the FortiGateToAbuseIPDB script does, how to install and use it, and how they can contribute to the project.
