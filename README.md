# FortiGateToAbuseIPDB
FortiGateToAbuseIPDB is a Python script that allows you to read all IPv4/IPv6 addresses from the FortiGate quarantine list, forward the malicious IPs to the AbuseIPDB service, and then clear the list.

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

### Setup Guide

#### Step 1: Create an Administrator User on FortiGate

1. **Log in to your FortiGate device**: Access the FortiGate web interface using your administrator credentials.
2. **Create a New User**:
   - Go to **User & Device** > **User** > **User Definition**.
   - Click **Create New** and select **Local User**.
   - Enter a username and password for the new user.
   - Assign the necessary permissions to read and modify the quarantine list.
3. **Restrict Access (Optional)**:
   - You can restrict access to this user account from a specific host where the script will be run.
   - Go to **System** > **Administrators**.
   - Edit the user you just created and set the trusted hosts to the IP address of the machine where the script will be executed.

#### Step 2: Encode the Username and Password

1. **Create Credentials File**: Create a file named `fortigate_creds.dat` to store your FortiGate credentials.
2. **Encode Credentials**:
   - Use a base64 encoder to encode your username and password to avoid storing them in plain text.
   - You can use a Python script or an online tool to encode the credentials:

     ```python
     import base64

     username = "your_username"
     password = "your_password"

     creds = f"{username}:{password}"
     encoded_creds = base64.b64encode(creds.encode()).decode()

     with open("fortigate_creds.dat", "w") as f:
         f.write(encoded_creds)
     ```

Or just use those cli commands to do the same :)

     
     echo -n 'YourAdminUserName' | base64 > /opt/FortiGateToAbuseIPDB/fortigate_creds.dat
     echo -n 'YourPassword' | base64 >> /opt/FortiGateToAbuseIPDB/fortigate_creds.dat
     
     
3. **Set Appropriate Permissions**:
   - To ensure the security of your credentials, set the file permissions to `640`:

     ```bash
     chmod 640 fortigate_creds.dat
     ```

#### Step 3: Obtain an AbuseIPDB API Key

1. **Create an AbuseIPDB Account**:
   - Go to the [AbuseIPDB website](https://www.abuseipdb.com/) and create an account.
2. **Generate an API Key**:
   - Once logged in, navigate to the **API** section.
   - Create a new API key that will be used by the script to identify who is submitting the malicious IP addresses.

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
   pip install paramiko
   ```

3. **Configure API Keys and FortiGate Details**:
   Edit the script `fortigate_quarantine.py` to include your AbuseIPDB API key and FortiGate device details:
   ```python
   FORTIGATE_IP = "your_fortigate_ip_or_hostname"
   ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
   ```

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
2024-06-27 15:42:22 - ---------------------------------------
2024-06-27 15:42:22 - Script execution started.
2024-06-27 15:42:22 - Debug: Processing line: 192.168.1.10     Thu Jun 27 15:32:33 2024 Fri Jun 28 15:32:33 2024 IPS
2024-06-27 15:42:22 - 192.168.1.10 IPS
2024-06-27 15:42:23 - IP 192.168.1.10 successfully reported for IPS.
2024-06-27 15:42:23 - AbuseIPDB Info for 192.168.1.10:
2024-06-27 15:42:23 -  - Score: 83
2024-06-27 15:42:23 -  - Domain: localdomain
2024-06-27 15:42:23 -  - ISP: Local ISP
2024-06-27 15:42:23 -  - Country: US
2024-06-27 15:42:23 - Debug: Processing line: 192.168.1.20    Thu Jun 27 15:30:06 2024 Tue Jul  2 15:30:06 2024 IPS
2024-06-27 15:42:23 - 192.168.1.20 IPS
2024-06-27 15:42:23 - IP 192.168.1.20 successfully reported for IPS.
2024-06-27 15:42:23 - AbuseIPDB Info for 192.168.1.20:
2024-06-27 15:42:23 -  - Score: 100
2024-06-27 15:42:23 -  - Domain: localdomain
2024-06-27 15:42:23 -  - ISP: Local ISP
2024-06-27 15:42:23 -  - Country: US
2024-06-27 15:42:23 - Debug: Processing line: 192.168.1.30   Thu Jun 27 15:36:49 2024 Tue Jul  2 15:36:49 2024 IPS
2024-06-27 15:42:23 - 192.168.1.30 IPS
2024-06-27 15:42:24 - IP 192.168.1.30 successfully reported for IPS.
2024-06-27 15:42:24 - AbuseIPDB Info for 192.168.1.30:
2024-06-27 15:42:24 -  - Score: 100
2024-06-27 15:42:24 -  - Domain: localdomain
2024-06-27 15:42:24 -  - ISP: Local ISP
2024-06-27 15:42:24 -  - Country: US
2024-06-27 15:42:24 - Debug: Processing line: fortigate01 #
2024-06-27 15:42:25 - Successfully cleared banned IPs.
2024-06-27 15:42:25 - Found 3 IPs in the quarantine list.
2024-06-27 15:51:12 - ---------------------------------------
```

### Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any enhancements or bug fixes.

### License

This project is open source and available for anyone to modify and distribute.
Feel free to contribute, improve, and adapt this code to suit your needs.
