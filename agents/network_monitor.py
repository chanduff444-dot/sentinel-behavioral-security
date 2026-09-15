#!/usr/bin/env python3
"""
Smart Network Monitor - SIH 2026
Only reports SUSPICIOUS connections, not every connection
"""

import socket
import psutil
import requests
import time
from datetime import datetime

API_BASE = "http://localhost:18000"

# Known safe ports (don't report these)
SAFE_PORTS = {
    80, 443,  # HTTP/HTTPS (normal web)
    53,       # DNS
    123,      # NTP
    443,      # HTTPS
    993, 995, # Email
    587, 465, # SMTP
    22,       # SSH (if you use it)
    8501,     # Streamlit
    18000,    # Backend
}

# Suspicious ports (always report)
SUSPICIOUS_PORTS = {
    4444, 5555, 6666,  # Common malware ports
    31337,             # Backdoor
    12345, 54321,      # Common trojans
}

# Known bad IPs (example threat intel)
BAD_IPS = {
    'testvirus.org',
    'malware.com',
    'evil.com',
}

def get_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            connections.append({
                'local_ip': conn.laddr.ip if conn.laddr else 'unknown',
                'local_port': conn.laddr.port if conn.laddr else 0,
                'remote_ip': conn.raddr.ip if conn.raddr else 'unknown',
                'remote_port': conn.raddr.port if conn.raddr else 0,
                'process': conn.pid,
            })
    return connections

def is_suspicious(conn):
    """Check if connection is suspicious"""
    
    # Skip localhost
    if conn['local_ip'] in ['127.0.0.1', '::1', 'localhost']:
        return False
    if conn['remote_ip'] in ['127.0.0.1', '::1', 'localhost']:
        return False
    
    # Skip private IPs
    if conn['remote_ip'].startswith('192.168.') or conn['remote_ip'].startswith('10.'):
        return False
    
    # Always report suspicious ports
    if conn['remote_port'] in SUSPICIOUS_PORTS:
        return True
    
    # Don't report safe ports
    if conn['remote_port'] in SAFE_PORTS:
        return False
    
    # Report everything else as potentially interesting
    return True

def send_event(event_type, payload, risk_score=1.0):
    try:
        response = requests.post(f"{API_BASE}/events", json={
            "user_id": 1,
            "event_type": event_type,
            "payload": payload,
            "risk_score": risk_score,
        }, timeout=3)
        return response.status_code == 200
    except:
        return False

def main():
    print("🔍 Smart Network Monitor Started...")
    print("Monitoring suspicious connections every 10 seconds...")
    print(f"API Base: {API_BASE}")
    print("")
    
    reported = set()  # Track reported connections
    
    while True:
        try:
            connections = get_connections()
            
            for conn in connections:
                # Create unique key
                conn_key = f"{conn['local_ip']}:{conn['local_port']}->{conn['remote_ip']}:{conn['remote_port']}"
                
                # Skip if already reported
                if conn_key in reported:
                    continue
                
                # Check if suspicious
                if is_suspicious(conn):
                    payload = {
                        "local_ip": conn['local_ip'],
                        "local_port": conn['local_port'],
                        "remote_ip": conn['remote_ip'],
                        "remote_port": conn['remote_port'],
                        "process": str(conn['process']),
                        "timestamp": datetime.now().isoformat(),
                    }
                    
                    # Higher risk for suspicious ports
                    risk = 5.0 if conn['remote_port'] in SUSPICIOUS_PORTS else 2.0
                    
                    if send_event("suspicious_connection", payload, risk_score=risk):
                        print(f"🚨 Suspicious: {conn['remote_ip']}:{conn['remote_port']}")
                        reported.add(conn_key)
            
            # Clean old reports (keep last 100)
            if len(reported) > 100:
                reported = set(list(reported)[-50:])
            
            time.sleep(10)  # Check every 10 seconds
            
        except KeyboardInterrupt:
            print("\n⛔ Stopped by user")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
