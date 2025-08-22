#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate to AbuseIPDB v2.1
Complete rewrite with full IPv4/IPv6 support and improved architecture
Fixed: Broken pipe errors and improved SSH connection handling
"""

import paramiko
import requests
import base64
import json
import re
import time
import ipaddress
import socket
import errno
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import logging
from pathlib import Path


# Configuration
CONFIG = {
    'fortigate_list_path': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'creds_file_path': '/opt/FortiGateToAbuseIPDB/fortigate_creds.dat',
    'ip_whitelist_path': '/opt/FortiGateToAbuseIPDB/ip_whitelist.txt',
    'abuseipdb_api_key': 'YOUR_ABUSEIPDB_API_KEY_HERE',  # Get your key from https://www.abuseipdb.com/
    'abuseipdb_check_url': 'https://api.abuseipdb.com/api/v2/check',
    'abuseipdb_report_url': 'https://api.abuseipdb.com/api/v2/report',
    'log_file': '/var/log/fortigate_quarantine.log',
    'ssh_timeout': 30,
    'command_timeout': 60,
    'delay_between_fortigates': 5,
    'ssh_keepalive_interval': 10,  # Aggiunto per mantenere viva la connessione
    'max_retries': 3,  # Numero massimo di tentativi per comando
    'retry_delay': 2   # Secondi tra i tentativi
}

# Whitelist di IP che non devono essere riportati ad AbuseIPDB
IP_WHITELIST = {
    # Google DNS
    '8.8.8.8',
    '8.8.4.4',
    '2001:4860:4860::8888',
    '2001:4860:4860::8844',
    
    # CloudFlare DNS
    '1.1.1.1',
    '1.0.0.1',
    '2606:4700:4700::1111',
    '2606:4700:4700::1001',
    '2606:4700:4700::1064',
    '2606:4700:4700::6400',
    
    # Quad9 DNS (opzionale, ma utile)
    '9.9.9.9',
    '149.112.112.112',
    '2620:fe::fe',
    '2620:fe::9',
    
    # OpenDNS (opzionale)
    '208.67.222.222',
    '208.67.220.220',
    '2620:119:35::35',
    '2620:119:53::53'
}


# Setup logging
class DualLogger:
    """Logger that writes to both console and file"""
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        # Create log directory if it doesn't exist
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        
    def log(self, message: str, level: str = "INFO"):
        """Write log message to file and console"""
        timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        formatted_msg = f"{timestamp} - [{level}] - {message}"
        
        # Console output
        if level == "ERROR":
            print(f"\033[91m{formatted_msg}\033[0m")  # Red
        elif level == "WARNING":
            print(f"\033[93m{formatted_msg}\033[0m")  # Yellow
        elif level == "SUCCESS":
            print(f"\033[92m{formatted_msg}\033[0m")  # Green
        else:
            print(formatted_msg)
        
        # File output
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{formatted_msg}\n")
        except IOError:
            print(f"Warning: Could not write to log file {self.log_file}")
    
    def info(self, message: str):
        self.log(message, "INFO")
    
    def error(self, message: str):
        self.log(message, "ERROR")
    
    def warning(self, message: str):
        self.log(message, "WARNING")
    
    def success(self, message: str):
        self.log(message, "SUCCESS")


# Initialize logger
logger = DualLogger(CONFIG['log_file'])


# Data structures
@dataclass
class FortiGate:
    """FortiGate device information"""
    ip: str
    name: str
    version: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class BannedIP:
    """Banned IP information"""
    ip: str
    cause: str
    is_ipv6: bool = False
    
    def __post_init__(self):
        """Validate and set IP type"""
        try:
            ip_obj = ipaddress.ip_address(self.ip)
            self.is_ipv6 = isinstance(ip_obj, ipaddress.IPv6Address)
        except ValueError:
            logger.error(f"Invalid IP address: {self.ip}")


class AttackCategory(Enum):
    """AbuseIPDB attack categories"""
    DDOS = 4
    FTP_BRUTE_FORCE = 5
    SSH_BRUTE_FORCE = 11
    PORT_SCAN = 14
    HACKING = 15
    SQL_INJECTION = 16
    SPOOFING = 17
    BRUTE_FORCE = 18
    BAD_WEB_BOT = 19
    EXPLOITED_HOST = 20
    WEB_APP_ATTACK = 21
    SSH = 22
    IOT_TARGETED = 23


# SSH Management
class SSHManager:
    """Manages SSH connections to FortiGate devices"""
    
    def __init__(self):
        self._connections = {}  # Cache delle connessioni
    
    @staticmethod
    def load_credentials(creds_file: str) -> Tuple[str, str]:
        """Load SSH credentials from file"""
        try:
            with open(creds_file, 'r') as f:
                encoded_username = f.readline().strip()
                encoded_password = f.readline().strip()
            
            username = base64.b64decode(encoded_username).decode()
            password = base64.b64decode(encoded_password).decode()
            
            return username, password
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            raise
    
    def get_connection(self, host: str, username: str, password: str) -> Optional[paramiko.SSHClient]:
        """Get or create SSH connection with proper error handling"""
        conn_key = f"{host}:{username}"
        
        # Verifica se abbiamo gi� una connessione attiva
        if conn_key in self._connections:
            ssh = self._connections[conn_key]
            # Verifica se la connessione � ancora attiva
            try:
                transport = ssh.get_transport()
                if transport and transport.is_active():
                    return ssh
                else:
                    # Connessione morta, rimuovila
                    del self._connections[conn_key]
            except:
                # Connessione problematica, rimuovila
                if conn_key in self._connections:
                    del self._connections[conn_key]
        
        # Crea nuova connessione
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Creating new SSH connection to {host}...")
            ssh.connect(
                host, 
                username=username, 
                password=password, 
                timeout=CONFIG['ssh_timeout'],
                banner_timeout=CONFIG['ssh_timeout'],
                auth_timeout=CONFIG['ssh_timeout']
            )
            
            # Abilita keepalive
            transport = ssh.get_transport()
            transport.set_keepalive(CONFIG['ssh_keepalive_interval'])
            
            # Salva la connessione
            self._connections[conn_key] = ssh
            return ssh
            
        except Exception as e:
            logger.error(f"Failed to create SSH connection to {host}: {e}")
            return None
    
    def close_connection(self, host: str, username: str):
        """Close specific SSH connection"""
        conn_key = f"{host}:{username}"
        if conn_key in self._connections:
            try:
                self._connections[conn_key].close()
            except:
                pass
            del self._connections[conn_key]
    
    def close_all_connections(self):
        """Close all SSH connections"""
        for conn_key in list(self._connections.keys()):
            try:
                self._connections[conn_key].close()
            except:
                pass
        self._connections.clear()
    
    def execute_command_with_retry(self, host: str, username: str, password: str, 
                                  command: str, max_retries: int = None) -> Tuple[Optional[str], Optional[str]]:
        """Execute command with automatic retry on failure"""
        if max_retries is None:
            max_retries = CONFIG['max_retries']
        
        last_error = None
        
        for attempt in range(max_retries):
            try:
                output, error = self._execute_command_internal(host, username, password, command)
                
                # Se il comando � riuscito, ritorna il risultato
                if output is not None or (error and "Command fail" in error):
                    return output, error
                    
            except (socket.error, paramiko.SSHException, EOFError, OSError) as e:
                last_error = str(e)
                
                # Controlla se � un broken pipe error
                if isinstance(e, OSError) and e.errno == errno.EPIPE:
                    logger.warning(f"Broken pipe detected on {host}, attempt {attempt + 1}/{max_retries}")
                else:
                    logger.warning(f"SSH error on {host}, attempt {attempt + 1}/{max_retries}: {e}")
                
                # Chiudi la connessione problematica
                self.close_connection(host, username)
                
                # Aspetta prima di riprovare
                if attempt < max_retries - 1:
                    time.sleep(CONFIG['retry_delay'])
            
            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error on {host}: {e}")
                break
        
        return None, f"Failed after {max_retries} attempts. Last error: {last_error}"
    
    def _execute_command_internal(self, host: str, username: str, password: str, 
                                command: str) -> Tuple[Optional[str], Optional[str]]:
        """Internal method to execute SSH command"""
        ssh = self.get_connection(host, username, password)
        if not ssh:
            return None, "Failed to establish SSH connection"
        
        try:
            # Usa un channel invece di exec_command per maggior controllo
            channel = ssh.get_transport().open_session()
            channel.settimeout(CONFIG['command_timeout'])
            channel.exec_command(command)
            
            # Leggi l'output in chunks per evitare buffer overflow
            output_chunks = []
            error_chunks = []
            
            # Leggi stdout
            while True:
                chunk = channel.recv(4096)
                if not chunk:
                    break
                output_chunks.append(chunk)
            
            # Leggi stderr
            while True:
                chunk = channel.recv_stderr(4096)
                if not chunk:
                    break
                error_chunks.append(chunk)
            
            # Attendi che il comando finisca
            exit_status = channel.recv_exit_status()
            channel.close()
            
            output = b''.join(output_chunks).decode('utf-8', errors='ignore')
            error = b''.join(error_chunks).decode('utf-8', errors='ignore')
            
            if error and "Command fail" not in error:
                logger.warning(f"Command warning on {host}: {error}")
            
            return output, error
            
        except socket.timeout:
            logger.error(f"Command timeout on {host}")
            raise
        except (socket.error, paramiko.SSHException) as e:
            logger.error(f"SSH error during command execution on {host}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during command execution on {host}: {e}")
            raise
    
    def execute_command(self, host: str, username: str, password: str, 
                       command: str) -> Tuple[Optional[str], Optional[str]]:
        """Execute SSH command on FortiGate (backward compatibility wrapper)"""
        return self.execute_command_with_retry(host, username, password, command)


# FortiGate Version Detection
class FortiGateVersion:
    """Handles FortiGate version detection and command mapping"""
    
    COMMAND_MAP = {
        '7.0': {
            'list': 'diagnose user quarantine list',
            'clear': 'diagnose user quarantine clear'
        },
        '7.4': {
            'list': 'diagnose user banned-ip list',
            'clear': 'diagnose user banned-ip clear'
        },
        'default': {
            'list': 'diagnose user banned-ip list',
            'clear': 'diagnose user banned-ip clear'
        }
    }
    
    @staticmethod
    def detect_version(output: str) -> Optional[str]:
        """Extract FortiGate version from system status output"""
        if not output:
            return None
        
        # Try multiple patterns
        patterns = [
            r'Version:\s+FortiGate-\S+\s+v(\d+\.\d+\.\d+)',
            r'Version:.*v(\d+\.\d+\.\d+)',
            r'Version:\s+(\d+\.\d+\.\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        
        logger.warning(f"Could not extract version from output: {output[:200]}...")
        return None
    
    @staticmethod
    def get_commands(version: Optional[str]) -> Dict[str, str]:
        """Get appropriate commands based on FortiGate version"""
        if not version:
            return FortiGateVersion.COMMAND_MAP['default']
        
        # Check major.minor version
        for ver_prefix, commands in FortiGateVersion.COMMAND_MAP.items():
            if version.startswith(ver_prefix):
                logger.info(f"Using commands for FortiGate v{ver_prefix}")
                return commands
        
        return FortiGateVersion.COMMAND_MAP['default']


# IP Parsing and Processing
class IPParser:
    """Parses banned IPs from FortiGate output"""
    
    @staticmethod
    def parse_banned_ips(output: str) -> List[BannedIP]:
        """Parse banned IPs from FortiGate command output"""
        banned_ips = []
        
        if not output:
            return banned_ips
        
        lines = output.strip().split('\n')
        
        # Skip header lines
        start_idx = 0
        for i, line in enumerate(lines):
            if 'IP' in line and ('reason' in line.lower() or 'trigger' in line.lower()):
                start_idx = i + 1
                break
        
        # Parse IP entries
        # Patterns for both IPv4 and IPv6
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        for line in lines[start_idx:]:
            line = line.strip()
            if not line or line.startswith('-'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                potential_ip = parts[0]
                
                # Validate IP
                try:
                    ip_obj = ipaddress.ip_address(potential_ip)
                    # Cause is typically the second field, not the last
                    cause = parts[1] if len(parts) > 1 else "Unknown"
                    banned_ip = BannedIP(ip=potential_ip, cause=cause)
                    banned_ips.append(banned_ip)
                    logger.info(f"Found banned IP: {potential_ip} (cause: {cause})")
                except ValueError:
                    # Not a valid IP, skip
                    continue
        
        return banned_ips


# AbuseIPDB Integration
class AbuseIPDB:
    """Handles all AbuseIPDB API interactions"""
    
    CATEGORY_MAP = {
        'IPS': [AttackCategory.HACKING.value],
        'DOS': [AttackCategory.DDOS.value],
        'DoS': [AttackCategory.DDOS.value],
        'brute force login': [AttackCategory.BRUTE_FORCE.value],
        'Administrative': [AttackCategory.BRUTE_FORCE.value, AttackCategory.SSH.value],
        'SQL': [AttackCategory.SQL_INJECTION.value],
        'port scan': [AttackCategory.PORT_SCAN.value],
        'web attack': [AttackCategory.WEB_APP_ATTACK.value]
    }
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            'Accept': 'application/json',
            'Key': api_key  # Note: using 'Key' not 'Api-Key' as per original
        }
        # Load user-defined IP whitelist
        self.user_ip_networks = self._load_ip_whitelist()
    
    def _load_ip_whitelist(self) -> List[ipaddress.ip_network]:
        """Load IP whitelist from file"""
        networks = []
        whitelist_path = CONFIG.get('ip_whitelist_path')
        
        if not whitelist_path or not Path(whitelist_path).exists():
            return networks
        
        try:
            with open(whitelist_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        # Parse as network (handles both individual IPs and CIDR ranges)
                        network = ipaddress.ip_network(line, strict=False)
                        networks.append(network)
                        logger.info(f"Loaded whitelist network: {network}")
                    except ValueError as e:
                        logger.warning(f"Invalid IP/network in whitelist: {line} - {e}")
            
            if networks:
                logger.success(f"Loaded {len(networks)} networks from IP whitelist")
        except Exception as e:
            logger.error(f"Failed to load IP whitelist: {e}")
        
        return networks
    
    def is_in_user_whitelist(self, ip: str) -> bool:
        """Check if IP is in user-defined whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.user_ip_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private/LAN address (RFC 1918, RFC 4193, etc.)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check standard private ranges
            if ip_obj.is_private:
                return True
            
            # Additional checks for special-use addresses
            if ip_obj.is_loopback:  # 127.0.0.0/8 or ::1
                return True
            if ip_obj.is_link_local:  # 169.254.0.0/16 or fe80::/10
                return True
            if ip_obj.is_multicast:  # 224.0.0.0/4 or ff00::/8
                return True
            if ip_obj.is_reserved:  # Various reserved ranges
                return True
            if ip_obj.is_unspecified:  # 0.0.0.0 or ::
                return True
            
            # Check if it's IPv6 site-local (deprecated but still might be used)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                # Site-local addresses (fec0::/10) - deprecated but check anyway
                if ip_obj.packed[0] == 0xfe and (ip_obj.packed[1] & 0xc0) == 0xc0:
                    return True
                # Teredo tunneling (2001::/32)
                if str(ip_obj).startswith('2001:0:'):
                    return True
                # 6to4 addresses (2002::/16)
                if str(ip_obj).startswith('2002:'):
                    return True
                    
            # Check if it's IPv4 special ranges
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Carrier-grade NAT (100.64.0.0/10)
                if ip_obj in ipaddress.ip_network('100.64.0.0/10'):
                    return True
                # Broadcast address
                if str(ip_obj) == '255.255.255.255':
                    return True
                    
            return False
        except ValueError:
            return False
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist or is a private IP"""
        # Check explicit whitelist (DNS servers, etc.)
        if ip in IP_WHITELIST:
            return True
        
        # Check user-defined whitelist
        if self.is_in_user_whitelist(ip):
            return True
        
        # Check if it's a private/LAN IP
        if self.is_private_ip(ip):
            return True
            
        return False
    
    def report_ip(self, banned_ip: BannedIP) -> bool:
        """Report an IP to AbuseIPDB"""
        # Check whitelist first
        if self.is_whitelisted(banned_ip.ip):
            if banned_ip.ip in IP_WHITELIST:
                logger.warning(f"IP {banned_ip.ip} is whitelisted (known DNS server), skipping report")
            elif self.is_in_user_whitelist(banned_ip.ip):
                logger.warning(f"IP {banned_ip.ip} is in user whitelist, skipping report")
            else:
                # Provide more detailed reason for skipping private IPs
                try:
                    ip_obj = ipaddress.ip_address(banned_ip.ip)
                    if ip_obj.is_private:
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            logger.warning(f"IP {banned_ip.ip} is private IPv4 (RFC 1918), skipping report")
                        else:
                            logger.warning(f"IP {banned_ip.ip} is private IPv6 (RFC 4193/ULA), skipping report")
                    elif ip_obj.is_loopback:
                        logger.warning(f"IP {banned_ip.ip} is loopback address, skipping report")
                    elif ip_obj.is_link_local:
                        logger.warning(f"IP {banned_ip.ip} is link-local address, skipping report")
                    elif ip_obj.is_multicast:
                        logger.warning(f"IP {banned_ip.ip} is multicast address, skipping report")
                    elif ip_obj.is_reserved:
                        logger.warning(f"IP {banned_ip.ip} is reserved address, skipping report")
                    else:
                        logger.warning(f"IP {banned_ip.ip} is special-use address, skipping report")
                except:
                    logger.warning(f"IP {banned_ip.ip} is private/special address, skipping report")
            return False
        
        categories = self._determine_categories(banned_ip.cause)
        comment = self._generate_comment(banned_ip)
        
        data = {
            'ip': banned_ip.ip,
            'categories': ','.join(map(str, categories)),
            'comment': comment
        }
        
        try:
            response = requests.post(
                CONFIG['abuseipdb_report_url'],
                headers=self.headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.success(f"Successfully reported {banned_ip.ip} to AbuseIPDB")
                return True
            else:
                logger.error(f"Failed to report {banned_ip.ip}: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Exception reporting {banned_ip.ip}: {e}")
            return False
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        """Query AbuseIPDB for IP information"""
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        try:
            response = requests.get(
                CONFIG['abuseipdb_check_url'],
                headers=self.headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to check {ip}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Exception checking {ip}: {e}")
            return None
    
    def _determine_categories(self, cause: str) -> List[int]:
        """Determine AbuseIPDB categories based on attack cause"""
        cause_lower = cause.lower()
        
        for key, categories in self.CATEGORY_MAP.items():
            if key.lower() in cause_lower:
                return categories
        
        # Default to brute force
        return [AttackCategory.BRUTE_FORCE.value]
    
    def _generate_comment(self, banned_ip: BannedIP) -> str:
        """Generate comment for AbuseIPDB report"""
        ip_type = "IPv6" if banned_ip.is_ipv6 else "IPv4"
        
        if banned_ip.cause.lower() == "administrative":
            return f"FortiGate detected brute force login attempt from {ip_type} address {banned_ip.ip}"
        else:
            return f"FortiGate detected {banned_ip.cause} attack from {ip_type} address {banned_ip.ip}"


# FortiGate Cleanup Operations
class FortiGateCleaner:
    """Handles cleanup operations on FortiGate"""
    
    def __init__(self, fortigate: FortiGate, ssh_manager: SSHManager):
        self.fortigate = fortigate
        self.ssh = ssh_manager
    
    def clear_quarantine(self, commands: Dict[str, str]) -> bool:
        """Clear quarantine/banned IPs"""
        clear_command = commands.get('clear', 'diagnose user banned-ip clear')
        
        logger.info(f"Clearing quarantine on {self.fortigate.name} with: {clear_command}")
        
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            clear_command
        )
        
        if error and "Command fail" in error:
            # Try alternative command
            alt_command = 'diagnose user quarantine clear' if 'banned-ip' in clear_command else 'diagnose user banned-ip clear'
            logger.warning(f"First command failed, trying: {alt_command}")
            
            output, error = self.ssh.execute_command(
                self.fortigate.ip,
                self.fortigate.username,
                self.fortigate.password,
                alt_command
            )
        
        if error and "Command fail" not in error:
            logger.error(f"Failed to clear quarantine: {error}")
            return False
        
        logger.success(f"Quarantine cleared successfully")
        return True
    
    def clear_address_groups(self) -> None:
        """Clear banned address groups (IPv4 and IPv6)"""
        self._clear_ipv4_address_group()
        self._clear_ipv6_address_group()
    
    def _clear_ipv4_address_group(self) -> None:
        """Clear IPv4 banned address group"""
        commands = '''config firewall addrgrp
edit Banned_Admin_Failed
unset member
end'''
        
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            commands
        )
        
        if error and "object does not exist" in error.lower():
            logger.info("IPv4 address group Banned_Admin_Failed does not exist")
        elif error and "Command fail" not in error:
            logger.error(f"Error clearing IPv4 address group: {error}")
        else:
            logger.success("IPv4 address group cleared successfully")
    
    def _clear_ipv6_address_group(self) -> None:
        """Clear IPv6 banned address group"""
        # First check if group exists
        check_cmd = '''config firewall addrgrp6
show
end'''
        
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            check_cmd
        )
        
        if error or "Banned_Admin_Failed_v6" not in (output or ""):
            logger.info("IPv6 address group Banned_Admin_Failed_v6 does not exist")
            return
        
        # Clear the group
        clear_cmd = '''config firewall addrgrp6
edit Banned_Admin_Failed_v6
unset member
end'''
        
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            clear_cmd
        )
        
        if error and "attribute can't be empty" in error.lower():
            logger.info("IPv6 address group is already empty")
        elif error and "Command fail" not in error:
            logger.error(f"Error clearing IPv6 address group: {error}")
        else:
            logger.success("IPv6 address group cleared successfully")
    
    def clean_abuseipdb_addresses(self) -> None:
        """Remove all addresses with AbuseIPDB comment"""
        self._clean_ipv4_addresses()
        self._clean_ipv6_addresses()
    
    def _clean_ipv4_addresses(self) -> None:
        """Clean IPv4 addresses with AbuseIPDB comment"""
        # Find addresses
        cmd = 'show firewall address | grep -B 3 -A 3 "AbuseIPDB"'
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            cmd
        )
        
        if error or not output:
            logger.info("No IPv4 AbuseIPDB addresses found")
            return
        
        # Parse addresses
        addresses = set()
        for line in output.splitlines():
            if 'edit "' in line:
                match = re.search(r'edit "([^"]+)"', line)
                if match:
                    addresses.add(match.group(1))
        
        # Delete addresses
        for addr in addresses:
            delete_cmd = f'''config firewall address
delete "{addr}"
end'''
            output, error = self.ssh.execute_command(
                self.fortigate.ip,
                self.fortigate.username,
                self.fortigate.password,
                delete_cmd
            )
            
            if error and "Command fail" not in error:
                logger.error(f"Failed to delete IPv4 address {addr}: {error}")
            else:
                logger.success(f"Deleted IPv4 address: {addr}")
    
    def _clean_ipv6_addresses(self) -> None:
        """Clean IPv6 addresses with AbuseIPDB comment"""
        # Find addresses
        cmd = 'show firewall address6 | grep -B 3 -A 3 "AbuseIPDB"'
        output, error = self.ssh.execute_command(
            self.fortigate.ip,
            self.fortigate.username,
            self.fortigate.password,
            cmd
        )
        
        if error or not output:
            logger.info("No IPv6 AbuseIPDB addresses found")
            return
        
        # Parse addresses
        addresses = set()
        for line in output.splitlines():
            if 'edit "' in line:
                match = re.search(r'edit "([^"]+)"', line)
                if match:
                    addresses.add(match.group(1))
        
        # Delete addresses
        for addr in addresses:
            delete_cmd = f'''config firewall address6
delete "{addr}"
end'''
            output, error = self.ssh.execute_command(
                self.fortigate.ip,
                self.fortigate.username,
                self.fortigate.password,
                delete_cmd
            )
            
            if error and "Command fail" not in error:
                logger.error(f"Failed to delete IPv6 address {addr}: {error}")
            else:
                logger.success(f"Deleted IPv6 address: {addr}")


# Main Application
class FortiGateAbuseIPDB:
    """Main application class"""
    
    def __init__(self):
        self.ssh_manager = SSHManager()
        self.abuseipdb = AbuseIPDB(CONFIG['abuseipdb_api_key'])
        self.fortigates = []
    
    def __del__(self):
        """Cleanup on destruction"""
        try:
            self.ssh_manager.close_all_connections()
        except:
            pass
    
    def load_fortigates(self) -> None:
        """Load FortiGate list from file"""
        try:
            with open(CONFIG['fortigate_list_path'], 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, name = parts[0], parts[1]
                        self.fortigates.append(FortiGate(ip=ip, name=name))
                        logger.info(f"Loaded FortiGate: {name} ({ip})")
            
            logger.success(f"Loaded {len(self.fortigates)} FortiGate devices")
            
        except Exception as e:
            logger.error(f"Failed to load FortiGate list: {e}")
            raise
    
    def process_fortigate(self, fortigate: FortiGate) -> None:
        """Process a single FortiGate device"""
        logger.info("=" * 75)
        logger.info(f"Processing FortiGate: {fortigate.name} ({fortigate.ip})")
        
        try:
            # Load credentials
            username, password = self.ssh_manager.load_credentials(CONFIG['creds_file_path'])
            fortigate.username = username
            fortigate.password = password
            
            # Get FortiGate version
            self._detect_fortigate_version(fortigate)
            
            # Get appropriate commands
            commands = FortiGateVersion.get_commands(fortigate.version)
            
            # Get banned IPs
            banned_ips = self._get_banned_ips(fortigate, commands)
            
            if banned_ips:
                logger.info(f"Found {len(banned_ips)} banned IPs")
                
                # Count IPv4 vs IPv6
                ipv4_count = sum(1 for ip in banned_ips if not ip.is_ipv6)
                ipv6_count = sum(1 for ip in banned_ips if ip.is_ipv6)
                logger.info(f"  - IPv4: {ipv4_count}")
                logger.info(f"  - IPv6: {ipv6_count}")
                
                # Count whitelisted IPs
                whitelisted_count = sum(1 for ip in banned_ips if self.abuseipdb.is_whitelisted(ip.ip))
                if whitelisted_count > 0:
                    logger.warning(f"  - Whitelisted IPs (DNS servers): {whitelisted_count}")
                
                # Process each IP
                self._process_banned_ips(banned_ips)
            else:
                logger.info("No banned IPs found")
            
            # Cleanup operations
            cleaner = FortiGateCleaner(fortigate, self.ssh_manager)
            cleaner.clear_quarantine(commands)
            cleaner.clear_address_groups()
            cleaner.clean_abuseipdb_addresses()
            
        except Exception as e:
            logger.error(f"Error processing FortiGate {fortigate.name}: {e}")
        finally:
            # Chiudi la connessione SSH per questo FortiGate
            if fortigate.username:
                self.ssh_manager.close_connection(fortigate.ip, fortigate.username)
    
    def _detect_fortigate_version(self, fortigate: FortiGate) -> None:
        """Detect FortiGate version"""
        output, error = self.ssh_manager.execute_command(
            fortigate.ip,
            fortigate.username,
            fortigate.password,
            'get system status'
        )
        
        if output:
            fortigate.version = FortiGateVersion.detect_version(output)
            if fortigate.version:
                logger.info(f"Detected FortiGate version: {fortigate.version}")
            else:
                logger.warning("Could not detect FortiGate version")
    
    def _get_banned_ips(self, fortigate: FortiGate, commands: Dict[str, str]) -> List[BannedIP]:
        """Get list of banned IPs from FortiGate"""
        list_command = commands.get('list', 'diagnose user banned-ip list')
        
        output, error = self.ssh_manager.execute_command(
            fortigate.ip,
            fortigate.username,
            fortigate.password,
            list_command
        )
        
        if error and "Command fail" in error:
            # Try alternative command
            alt_command = 'diagnose user quarantine list' if 'banned-ip' in list_command else 'diagnose user banned-ip list'
            logger.warning(f"First command failed, trying: {alt_command}")
            
            output, error = self.ssh_manager.execute_command(
                fortigate.ip,
                fortigate.username,
                fortigate.password,
                alt_command
            )
        
        if error and "Command fail" not in error:
            logger.error(f"Failed to get banned IPs: {error}")
            return []
        
        return IPParser.parse_banned_ips(output)
    
    def _process_banned_ips(self, banned_ips: List[BannedIP]) -> None:
        """Process and report banned IPs to AbuseIPDB"""
        # Remove duplicates
        unique_ips = list({(ip.ip, ip.cause): ip for ip in banned_ips}.values())
        
        for banned_ip in unique_ips:
            # Small delay between API calls to avoid rate limiting
            time.sleep(0.5)
            
            # Report to AbuseIPDB (whitelist check is done inside report_ip)
            if self.abuseipdb.report_ip(banned_ip):
                ip_type = "IPv6" if banned_ip.is_ipv6 else "IPv4"
                if banned_ip.cause.lower() == "administrative":
                    logger.info(f"{ip_type} {banned_ip.ip} reported for brute-force login attempt")
                else:
                    logger.info(f"{ip_type} {banned_ip.ip} reported for {banned_ip.cause} attempt")
                
                # Get additional info
                info = self.abuseipdb.check_ip(banned_ip.ip)
                if info and 'data' in info:
                    data = info['data']
                    logger.info(f"  - Abuse Score: {data.get('abuseConfidenceScore', 'N/A')}")
                    logger.info(f"  - ISP: {data.get('isp', 'N/A')}")
                    logger.info(f"  - Country: {data.get('countryCode', 'N/A')}")
                    logger.info(f"  - Usage Type: {data.get('usageType', 'N/A')}")
    
    def run(self) -> None:
        """Run the main application"""
        logger.info("=" * 75)
        logger.info("FortiGate to AbuseIPDB v2.1 Started")
        logger.info("=" * 75)
        logger.info(f"DNS whitelist enabled with {len(IP_WHITELIST)} IPs")
        if self.abuseipdb.user_ip_networks:
            logger.info(f"User whitelist loaded with {len(self.abuseipdb.user_ip_networks)} networks")
        
        try:
            # Load FortiGates
            self.load_fortigates()
            
            # Process each FortiGate
            for i, fortigate in enumerate(self.fortigates):
                try:
                    self.process_fortigate(fortigate)
                except Exception as e:
                    logger.error(f"Failed to process {fortigate.name}: {e}")
                    continue
                
                # Delay between FortiGates
                if i < len(self.fortigates) - 1:
                    logger.info(f"Waiting {CONFIG['delay_between_fortigates']} seconds before next FortiGate...")
                    time.sleep(CONFIG['delay_between_fortigates'])
            
            logger.info("=" * 75)
            logger.success("All FortiGate devices processed successfully")
            logger.info("=" * 75)
            
        except Exception as e:
            logger.error(f"Fatal error: {e}")
            raise
        finally:
            # Ensure all connections are closed
            self.ssh_manager.close_all_connections()


def main():
    """Main entry point"""
    try:
        app = FortiGateAbuseIPDB()
        app.run()
    except KeyboardInterrupt:
        logger.warning("Script interrupted by user")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        raise


if __name__ == "__main__":
    main()
