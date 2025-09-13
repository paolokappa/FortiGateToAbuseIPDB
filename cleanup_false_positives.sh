#!/bin/bash
# Script per pulire i falsi positivi NTP

echo "Pulizia falsi positivi NTP in corso..."

# Connetti al FortiGate e pulisci
ssh AbuseIPDB@192.168.220.15 << 'ENDSSH'
# Pulisci tutti i ban DOS (la maggior parte sono falsi positivi NTP)
diagnose user banned-ip clear

# Pulisci i gruppi
config firewall addrgrp
edit Banned_Admin_Failed
unset member
end

config firewall addrgrp6
edit Banned_Admin_Failed_v6
unset member
end

# Mostra stato
diagnose user banned-ip list | head -5
ENDSSH

echo "Pulizia completata!"
