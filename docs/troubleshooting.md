# Troubleshooting e FAQ

## 🚨 Problemi Comuni e Soluzioni

### 1. Errore 429: Rate Limiting AbuseIPDB

**Sintomo:**
```
[ERROR] - Failed to report X.X.X.X: 429 - {"detail":"You can only report the same IP address once in 15 minutes."}
```

**Causa:** IP già segnalato negli ultimi 15 minuti

**Soluzione:** 
- Normale comportamento, lo script continuerà con gli altri IP
- L'IP verrà comunque rimosso dal FortiGate se già segnalato in precedenza

---

### 2. Troppi IP Bannati per DOS

**Sintomo:**
```
Found 400+ banned IPs (mostly DOS)
```

**Causa:** Policy DoS troppo restrittiva (specialmente per NTP)

**Soluzione:**
```bash
# Sul FortiGate, modifica la policy DoS per NTP:
config firewall DoS-policy
    edit <policy-id>
        config anomaly
            edit "udp_flood"
                set threshold 200000  # Aumenta da 50000
            next
            edit "udp_scan"
                set status disable    # Disabilita per NTP
            next
        end
    next
end
```

---

### 3. Connection Refused SSH

**Sintomo:**
```
[ERROR] - Failed to connect to X.X.X.X: Connection refused
```

**Causa:** SSH non abilitato o firewall blocca

**Soluzione:**
```bash
# Sul FortiGate:
config system interface
    edit "mgmt"
        set allowaccess ping https ssh
    next
end

# Verifica connettività:
telnet <fortigate-ip> 22
```

---

### 4. Command Failed on FortiGate

**Sintomo:**
```
Command fail. Return code -61
```

**Causa:** Comando non supportato nella versione FortiOS

**Soluzione:** Verifica versione e comandi:
```python
# FortiOS 7.4: diagnose user banned-ip
# FortiOS 7.0: diagnose user quarantine
```

---

### 5. IP Non Rimossi dai Gruppi

**Sintomo:** IP rimangono nei gruppi `Banned_Admin_Failed`

**Causa:** L'automation FortiGate aggiunge a entrambi i gruppi (IPv4 e IPv6)

**Soluzione:** Lo script ora rimuove da entrambi automaticamente

---

### 6. ModuleNotFoundError

**Sintomo:**
```
ModuleNotFoundError: No module named 'paramiko'
```

**Soluzione:**
```bash
pip3 install paramiko requests ipaddress
```

---

### 7. Log File Troppo Grande

**Sintomo:** `/var/log/fortigate_quarantine.log` supera 1GB

**Soluzione:**
```bash
# Configura logrotate
cat > /etc/logrotate.d/fortigate-abuseipdb << EOF
/var/log/fortigate_quarantine.log {
    daily
    rotate 30
    compress
    maxsize 100M
}
EOF

# Rotazione manuale immediata
logrotate -f /etc/logrotate.d/fortigate-abuseipdb
```

---

## 🔍 Debug e Diagnostica

### Abilitare Debug Dettagliato

```python
# Modifica fortigate2AbuseIPDB.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Test Connessione FortiGate

```bash
python3 -c "
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.220.15', username='AbuseIPDB', password='password')
stdin, stdout, stderr = ssh.exec_command('diagnose user banned-ip list | head -5')
print(stdout.read().decode())
ssh.close()
"
```

### Verifica API AbuseIPDB

```bash
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: YOUR_API_KEY" \
  -H "Accept: application/json"
```

### Controllo Stato Sistema

```bash
# Verifica crontab
crontab -l | grep fortigate

# Verifica processi in esecuzione
ps aux | grep fortigate2AbuseIPDB

# Ultimi log
tail -100 /var/log/fortigate_quarantine.log

# Conta IP processati oggi
grep "$(date +%d-%m-%Y)" /var/log/fortigate_quarantine.log | grep -c "reported for"
```

---

## ❓ FAQ

### Q: Quanto tempo impiega lo script?
**A:** Circa 2-5 minuti per 11 FortiGate, dipende dal numero di IP bannati

### Q: Posso eseguirlo più spesso di ogni ora?
**A:** Sì, ma attenzione al rate limiting di AbuseIPDB (1 report per IP ogni 15 minuti)

### Q: Gli IP vengono rimossi permanentemente?
**A:** Sì, dopo la segnalazione vengono rimossi. Se l'attacco continua, il FortiGate li bannerà di nuovo

### Q: Cosa succede se AbuseIPDB è offline?
**A:** Gli IP non vengono segnalati né rimossi, verranno processati alla prossima esecuzione

### Q: Posso escludere alcuni IP dalla segnalazione?
**A:** Sì, aggiungi le reti in `ip_whitelist.txt`

### Q: Lo script supporta IPv6?
**A:** Sì, completamente supportato

### Q: Cosa significa "cause: Administrative"?
**A:** Login falliti (brute-force SSH/HTTPS), bannati dall'automation FortiGate

### Q: Cosa significa "cause: DOS"?
**A:** Attacchi Denial of Service rilevati dalle policy DoS

### Q: Come verifico che lo script stia funzionando?
**A:** 
```bash
# Controlla log recenti
tail -f /var/log/fortigate_quarantine.log

# Verifica IP bannati su FortiGate
ssh admin@fortigate "diagnose user banned-ip list | head -10"
```

### Q: Posso testare su un singolo FortiGate?
**A:** Sì, crea un file temporaneo con solo quel FortiGate:
```bash
echo "fortigate01.example.com 192.168.1.1" > /tmp/single.list
python3 fortigate2AbuseIPDB.py  # modifica CONFIG['fortigate_list_path']
```

---

## 📞 Supporto

Per problemi non risolti:
1. Controlla i log: `/var/log/fortigate_quarantine.log`
2. Verifica la documentazione GitHub
3. Contatta: soc@goline.ch

---

*Ultimo aggiornamento: 13/09/2025*