# Flusso Operativo

## 🔄 Ciclo Completo di Elaborazione

### Panoramica del Processo

```
[START] → [LOAD CONFIG] → [FOREACH FORTIGATE] → [GET BANNED IPS] → 
→ [FILTER & VALIDATE] → [REPORT TO ABUSEIPDB] → [REMOVE FROM FORTIGATE] → 
→ [CLEANUP GROUPS] → [LOG RESULTS] → [END]
```

## 📝 Dettaglio Fasi

### Fase 1: Inizializzazione

```python
# 1. Caricamento configurazione
CONFIG = {
    'fortigate_list_path': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'creds_file_path': '/opt/FortiGateToAbuseIPDB/fortigate_creds.dat',
    'abuseipdb_api_key': ABUSEIPDB_API_KEY,
    'log_file': '/var/log/fortigate_quarantine.log'
}

# 2. Caricamento whitelist
IP_WHITELIST = {
    '8.8.8.8',        # Google DNS
    '1.1.1.1',        # CloudFlare DNS
    # ... altri DNS pubblici
}

# 3. Caricamento whitelist utente
user_whitelist = load_file('ip_whitelist.txt')
```

### Fase 2: Elaborazione FortiGate

Per ogni FortiGate nella lista:

#### 2.1 Connessione SSH
```python
# Stabilisce connessione SSH con pooling
ssh = SSHManager.get_connection(host, username, password)
```

#### 2.2 Rilevamento Versione
```python
# Determina versione FortiOS
output = exec_command("get system status")
version = detect_version(output)  # Es: "7.4"
```

#### 2.3 Recupero IP Bannati
```python
# Comando basato sulla versione
if version == "7.4":
    command = "diagnose user banned-ip list"
else:  # 7.0
    command = "diagnose user quarantine list"

# Output esempio:
# src-ip-addr       created                  expires                  cause
# 178.198.25.109    Sat Sep 13 14:38:36 2025 Sun Sep 14 14:38:36 2025 DOS
```

### Fase 3: Elaborazione IP

#### 3.1 Parsing Output
```python
banned_ips = IPParser.parse_banned_ips(output)
# Risultato: List[BannedIP(ip, cause, is_ipv6, description)]
```

#### 3.2 Filtraggio Whitelist
```python
for banned_ip in banned_ips:
    if is_whitelisted(banned_ip.ip):
        continue  # Skip DNS pubblici, IP privati, reti utente
```

#### 3.3 Segnalazione ad AbuseIPDB
```python
# Mappatura categorie
categories = {
    'DOS': [4],           # DDoS Attack
    'Administrative': [22], # SSH Brute-Force
    'IPS': [15],          # Hacking
    'Port Scan': [14]     # Port Scan
}

# Invio report
response = abuseipdb.report_ip(
    ip=banned_ip.ip,
    categories=categories[banned_ip.cause],
    comment=f"FortiGate detected {cause} attack"
)
```

### Fase 4: Rimozione IP

⚠️ **IMPORTANTE**: Gli IP vengono rimossi SOLO dopo segnalazione riuscita!

#### 4.1 Rimozione da Banned List
```python
# FortiOS 7.4
diagnose user banned-ip delete src4 <IP>  # IPv4
diagnose user banned-ip delete src6 <IP>  # IPv6

# FortiOS 7.0
diagnose user quarantine delete src4 <IP>
diagnose user quarantine delete src6 <IP>
```

#### 4.2 Rimozione dai Gruppi Firewall

L'automation FortiGate aggiunge gli IP a ENTRAMBI i gruppi (bug):

```python
# Rimuove da gruppo IPv4
config firewall addrgrp
edit Banned_Admin_Failed
unselect member "<IP>"
end

# Rimuove da gruppo IPv6
config firewall addrgrp6
edit Banned_Admin_Failed_v6
unselect member "<IP>"
end
```

#### 4.3 Eliminazione Oggetti Address

L'automation crea ENTRAMBI gli oggetti (IPv4 e IPv6):

```python
# Elimina oggetto IPv4
config firewall address
delete "<IP>"
end

# Elimina oggetto IPv6
config firewall address6
delete "<IP>"
end
```

### Fase 5: Cleanup (Solo se non ci sono IP bannati)

Se un FortiGate non ha IP bannati, esegue pulizia completa:

```python
if not banned_ips:
    # 1. Pulisce quarantena
    diagnose user banned-ip clear
    
    # 2. Svuota gruppi
    config firewall addrgrp
    edit Banned_Admin_Failed
    unset member
    end
    
    # 3. Rimuove tutti gli address con commento "AbuseIPDB"
    clean_abuseipdb_addresses()
```

## 📊 Logging

Ogni operazione viene loggata:

```
13-09-2025 15:30:33 - [INFO] - Processing FortiGate: fortigate01.goline.ch
13-09-2025 15:30:33 - [INFO] - Found banned IP: 109.60.80.9 (cause: DOS)
13-09-2025 15:30:35 - [SUCCESS] - Successfully reported 109.60.80.9 to AbuseIPDB
13-09-2025 15:30:35 - [INFO] - Removed 109.60.80.9 from banned list
13-09-2025 15:30:35 - [INFO] - Removed 109.60.80.9 from Banned_Admin_Failed (IPv4 group)
13-09-2025 15:30:35 - [INFO] - Removed 109.60.80.9 from Banned_Admin_Failed_v6 (IPv6 group)
13-09-2025 15:30:35 - [INFO] - Deleted IPv4 firewall address object 109.60.80.9
13-09-2025 15:30:35 - [INFO] - Deleted IPv6 firewall address object 109.60.80.9
```

## 🔄 Integrazione con Automation FortiGate

### Automation Trigger (Login Falliti)

```
config system automation-trigger
    edit "Admin_Login_Failed"
        set event-type event-log
        set logid 32002  # Admin login failed
    next
end
```

### Automation Action

```
config system automation-action
    edit "Add_IP_to_Group"
        set action-type cli-script
        set script "
            # Ban IPv4
            diagnose user banned-ip add src4 %%log.srcip%% 7200 admin
            config firewall address
                edit %%log.srcip%%
                set subnet %%log.srcip%%/32
                set comment 'AbuseIPDB'
            next
            end
            config firewall addrgrp
                edit Banned_Admin_Failed
                append member %%log.srcip%%
            next
            end
            
            # Ban IPv6 (anche per IPv4!)
            diagnose user banned-ip add src6 %%log.srcip%% 7200 admin
            config firewall address6
                edit %%log.srcip%%
                set ip6 %%log.srcip%%/128
                set comment 'AbuseIPDB'
            next
            end
            config firewall addrgrp6
                edit Banned_Admin_Failed_v6
                append member %%log.srcip%%
            next
            end
        "
    next
end
```

## ⏱️ Timing e Performance

- **Esecuzione**: Ogni ora via crontab
- **Durata media**: 2-5 minuti per 11 FortiGate
- **Throughput**: ~100 IP/minuto
- **Delay tra API call**: 0.5 secondi
- **Delay tra FortiGate**: 5 secondi

## 🚨 Gestione Errori

### Rate Limiting AbuseIPDB
- Errore 429: IP già segnalato negli ultimi 15 minuti
- Lo script continua con il prossimo IP

### Errori SSH
- Retry automatico (max 3 tentativi)
- Connection pooling per riutilizzo

### IP Non Rimovibili
- Log warning ma continua elaborazione
- Scadranno automaticamente dopo timeout

---

*Ultimo aggiornamento: 13/09/2025*