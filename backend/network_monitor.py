import socket
import psutil
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.connection_history = defaultdict(list)
        self.baseline = {}
        self.anomalies = []
    
    def get_active_connections(self) -> list:
        """Get current network connections"""
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
                        "process_name": self._get_process_name(conn.pid),
                        "timestamp": datetime.now().isoformat()
                    })
        except (psutil.AccessDenied, Exception) as e:
            # Need admin/root privileges for some connections
            pass
        
        return connections
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            if pid:
                return psutil.Process(pid).name()
        except:
            pass
        return "unknown"
    
    def detect_network_anomalies(self, connections: list) -> list:
        """Detect network-based anomalies"""
        anomalies = []
        
        # Check for unusual ports
        suspicious_ports = [4444, 5555, 6666, 31337, 12345]  # Common malware ports
        for conn in connections:
            if conn["remote_port"] in suspicious_ports:
                anomalies.append({
                    "type": "suspicious_port",
                    "severity": "high",
                    "details": f"Connection to suspicious port {conn['remote_port']}",
                    "remote_ip": conn["remote_ip"],
                    "process": conn["process_name"]
                })
        
        # Check for high number of connections (potential C2 or scanning)
        ip_counts = defaultdict(int)
        for conn in connections:
            ip_counts[conn["remote_ip"]] += 1
        
        for ip, count in ip_counts.items():
            if count > 20:  # More than 20 connections to same IP
                anomalies.append({
                    "type": "high_connection_count",
                    "severity": "medium",
                    "details": f"High number of connections ({count}) to {ip}",
                    "remote_ip": ip
                })
        
        # Check for data exfiltration patterns (large outbound data)
        # This would require monitoring bytes sent over time
        
        return anomalies
    
    def calculate_network_risk_score(self, connections: list, ioc_results: list) -> float:
        """Calculate risk score based on network activity"""
        risk_score = 0.0
        
        # Base risk for each connection
        risk_score += len(connections) * 0.1
        
        # Add risk for IoC matches
        for ioc in ioc_results:
            if ioc.get("is_malicious"):
                risk_score += ioc.get("confidence", 50) / 10
        
        # Add risk for anomalies
        anomalies = self.detect_network_anomalies(connections)
        for anomaly in anomalies:
            if anomaly["severity"] == "high":
                risk_score += 3.0
            elif anomaly["severity"] == "medium":
                risk_score += 1.5
            else:
                risk_score += 0.5
        
        return min(risk_score, 10.0)  # Cap at 10
    
    def get_network_summary(self) -> dict:
        """Get network monitoring summary"""
        connections = self.get_active_connections()
        return {
            "active_connections": len(connections),
            "unique_remote_ips": len(set([c["remote_ip"] for c in connections])),
            "protocols": {
                "tcp": len([c for c in connections if c["protocol"] == "tcp"]),
                "udp": len([c for c in connections if c["protocol"] == "udp"])
            }
        }

# Global instance
network_monitor = NetworkMonitor()
