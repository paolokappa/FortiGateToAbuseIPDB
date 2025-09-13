# Guida all'Installazione

## 📋 Requisiti di Sistema

### Sistema Operativo
- Ubuntu 20.04+ / Debian 10+
- Python 3.8 o superiore
- Accesso SSH ai FortiGate

### Pacchetti Python Richiesti
```bash
paramiko>=2.7.2      # Connessioni SSH
requests>=2.25.1     # API HTTP
ipaddress           # Gestione IP
```

## 🛠️ Installazione Step-by-Step

### 1. Clonazione Repository

```bash
cd /opt
git clone https://github.com/paolokappa/FortiGateToAbuseIPDB.git
cd FortiGateToAbuseIPDB
```

### 2. Installazione Dipendenze

```bash
# Aggiorna sistema
apt update && apt upgrade -y

# Installa Python e pip
apt install python3 python3-pip -y

# Installa dipendenze Python
pip3 install paramiko requests ipaddress
```

### 3. Configurazione Credenziali FortiGate

```bash
# Crea file credenziali (username e password in base64)
echo -n "username" | base64 > fortigate_creds.dat
echo -n "password" | base64 >> fortigate_creds.dat

# Imposta permessi sicuri
chmod 600 fortigate_creds.dat
```

### 4. Configurazione API AbuseIPDB

```bash
# Crea file configurazione locale
cat > config_local.py << EOF
# AbuseIPDB API Configuration
ABUSEIPDB_API_KEY = 'your-api-key-here'
EOF

chmod 600 config_local.py
```

### 5. Lista FortiGate

```bash
# Crea lista FortiGate (nome FQDN e IP)
cat > fortigate.list << EOF
fortigate01.example.com 192.168.1.1
fortigate02.example.com 192.168.1.2
EOF
```

### 6. Whitelist IP (Opzionale)

```bash
# Crea whitelist per reti da escludere
cat > ip_whitelist.txt << EOF
# Reti aziendali da escludere
192.168.0.0/16
10.0.0.0/8

# Provider trusted
185.54.80.0/22
EOF
```

## ⏰ Configurazione Crontab

### Esecuzione Oraria Script Principale

```bash
# Modifica crontab
crontab -e

# Aggiungi (esecuzione ogni ora)
0 * * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py >/dev/null 2>&1

# Report statistiche giornaliero (alle 23:58)
58 23 * * * /usr/bin/python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB_stats.py >/dev/null 2>&1
```

## 🔐 Configurazione FortiGate

### Creazione Utente Dedicato

Sul FortiGate, crea un utente per lo script:

```bash
config system admin
    edit "AbuseIPDB"
        set accprofile "super_admin"
        set password "password-sicura"
    next
end
```

### Configurazione SSH

```bash
config system interface
    edit "mgmt"
        set allowaccess ping https ssh
    next
end

config system ssh-config
    set ssh-enc-algo aes128-ctr aes192-ctr aes256-ctr
    set ssh-mac-algo hmac-sha2-256 hmac-sha2-512
end
```

## ✅ Verifica Installazione

### 1. Test Connessione SSH

```bash
python3 -c "
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.1.1', username='AbuseIPDB', password='password')
stdin, stdout, stderr = ssh.exec_command('get system status')
print(stdout.read().decode())
ssh.close()
"
```

### 2. Test API AbuseIPDB

```bash
python3 -c "
import requests
from config_local import ABUSEIPDB_API_KEY

headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                        headers=headers, 
                        params={'ipAddress': '8.8.8.8'})
print(f'API Status: {response.status_code}')
"
```

### 3. Esecuzione Test

```bash
# Test manuale dello script
python3 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py

# Verifica log
tail -f /var/log/fortigate_quarantine.log
```

## 🔧 Post-Installazione

### Creazione Directory Log

```bash
# Crea directory per i log
mkdir -p /var/log
touch /var/log/fortigate_quarantine.log
chmod 644 /var/log/fortigate_quarantine.log
```

### Rotazione Log

```bash
# Configura logrotate
cat > /etc/logrotate.d/fortigate-abuseipdb << EOF
/var/log/fortigate_quarantine.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
```

## 🚨 Troubleshooting Installazione

### Errore: ModuleNotFoundError

```bash
# Reinstalla dipendenze
pip3 install --upgrade paramiko requests ipaddress
```

### Errore: Permission denied

```bash
# Verifica permessi
chmod 755 /opt/FortiGateToAbuseIPDB/fortigate2AbuseIPDB.py
chmod 600 /opt/FortiGateToAbuseIPDB/fortigate_creds.dat
chmod 600 /opt/FortiGateToAbuseIPDB/config_local.py
```

### Errore: Connection refused

```bash
# Verifica connettività
ping <fortigate-ip>
telnet <fortigate-ip> 22

# Verifica firewall
iptables -L -n
```

---

*Ultimo aggiornamento: 13/09/2025*