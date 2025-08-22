#!/bin/bash
# Script to set up FortiGate credentials

echo "FortiGate Credentials Setup"
echo "============================"

# Get username
read -p "Enter FortiGate SSH username: " username

# Get password (hidden input)
read -s -p "Enter FortiGate SSH password: " password
echo

# Encode and save
echo -n "$username" | base64 > fortigate_creds.dat
echo -n "$password" | base64 >> fortigate_creds.dat

echo "Credentials saved to fortigate_creds.dat (base64 encoded)"
chmod 600 fortigate_creds.dat
echo "File permissions set to 600 (owner read/write only)"