#!/usr/bin/env python3
import psutil
import socket
import requests
import time
from datetime import datetime

API_BASE = "http://localhost:18000"

# Known malicious IPs
MALICIOUS_IPS = [
    "185.220.101.1", "185.220.101.2",
    "45.155.205.230", "45.155.205.231",
    "193.32.162.159", "23.129.64.100",
]

# Suspicious ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 31337, 12345, 1337]

def get_active_connections():
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "process": get_process_name(conn.pid),
                    "timestamp": datetime.now().isoformat()
                })
    except (psutil.AccessDenied, Exception) as e:
        pass
    return connections

def get_process_name(pid):
    try:
        if pid:
            return psutil.Process(pid).name()
    except:
        pass
    return "unknown"

def check_ip_reputation(ip):
    try:
        response = requests.get(f"{API_BASE}/ioc/check-ip/{ip}", timeout=5)
        return response.json()
    except:
        return {"is_malicious": False, "confidence": 0}

def send_alert(reason, severity="high"):
    try:
        requests.post(f"{API_BASE}/alerts", json={
            "user_id": 1,
            "severity": severity,
            "reason": reason,
            "status": "open"
        }, timeout=5)
    except:
        pass

def log_connection(conn):
    try:
        requests.post(f"{API_BASE}/events", json={
            "user_id": 1,
            "event_type": "network_connection",
            "payload": conn
        }, timeout=5)
    except:
        pass

def monitor():
    print("🔍 Network Monitor Started...")
    print(f"Monitoring connections every 5 seconds...")
    print(f"API Base: {API_BASE}")
    
    seen_connections = set()
    
    while True:
        try:
            connections = get_active_connections()
            
            for conn in connections:
                conn_key = f"{conn['remote_ip']}:{conn['remote_port']}"
                
                if conn_key not in seen_connections:
                    seen_connections.add(conn_key)
                    print(f"📡 New connection: {conn['remote_ip']}:{conn['remote_port']} ({conn['process']})")
                    
                    log_connection(conn)
                    
                    ip_check = check_ip_reputation(conn['remote_ip'])
                    
                    if ip_check.get('is_malicious'):
                        print(f"⚠️ MALICIOUS IP DETECTED: {conn['remote_ip']}")
                        send_alert(
                            f"Network: Connection to malicious IP {conn['remote_ip']} "
                            f"(confidence: {ip_check.get('confidence', 0)}%) "
                            f"by process {conn['process']}",
                            "high"
                        )
                    
                    if conn['remote_port'] in SUSPICIOUS_PORTS:
                        print(f"⚠️ SUSPICIOUS PORT: {conn['remote_port']}")
                        send_alert(
                            f"Network: Connection to suspicious port {conn['remote_port']} "
                            f"by process {conn['process']}",
                            "medium"
                        )
            
            current_keys = {f"{c['remote_ip']}:{c['remote_port']}" for c in connections}
            seen_connections = seen_connections.intersection(current_keys)
            
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(5)

if __name__ == "__main__":
    monitor()
