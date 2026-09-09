import requests
from datetime import datetime, timedelta
import base64
import re

# ============ YOUR API KEYS ============
ABUSEIPDB_API_KEY = "60456b9ff78f6eed5c87b1cb24e90ce1585914751a42424db9d4270db6509cf95f34bf0bc0a8d0ed"
VIRUSTOTAL_API_KEY = "9904cdbbed27dcced275f98c02ce2b1c35e07bff7cfe7d8d5aa98cd0e56a0b8a"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyAOpQ4jTsesyrvhMOdYKPK5W4sWjEDJ9X0"

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
GOOGLE_SB_BASE = "https://safebrowsing.googleapis.com/v4"

class ThreatIntelligence:
    def __init__(self):
        self.abuseipdb_key = ABUSEIPDB_API_KEY
        self.virustotal_key = VIRUSTOTAL_API_KEY
        self.google_sb_key = GOOGLE_SAFE_BROWSING_API_KEY
        self.cache = {}
        self.cache_expiry = {}
    
    def check_ip_reputation(self, ip: str) -> dict:
        """Check IP against real threat databases"""
        cache_key = f"ip:{ip}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key].copy()
        
        result = {
            "ip": ip,
            "is_malicious": False,
            "confidence": 0,
            "categories": [],
            "reports": 0,
            "source": "none"
        }
        
        # Check AbuseIPDB (REAL API)
        if self.abuseipdb_key:
            try:
                response = requests.get(
                    f"{ABUSEIPDB_BASE}/check",
                    params={"ipAddress": ip},
                    headers={"Key": self.abuseipdb_key},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data'):
                        ip_data = data['data'][0]
                        confidence = ip_data.get('abuseConfidenceScore', 0)
                        result.update({
                            "is_malicious": confidence > 50,
                            "confidence": confidence,
                            "categories": ip_data.get('categories', []),
                            "reports": ip_data.get('totalReports', 0),
                            "source": "abuseipdb"
                        })
            except Exception as e:
                result["error"] = str(e)
        
        # Local blocklist
        known_bad_ips = [
            "185.220.101.1", "185.220.101.2",
            "45.155.205.230", "45.155.205.231",
            "193.32.162.159", "23.129.64.100",
        ]
        
        if ip in known_bad_ips:
            result.update({
                "is_malicious": True,
                "confidence": 100,
                "categories": ["known_malicious"],
                "source": "local_blocklist"
            })
        
        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        
        return result
    
    def check_url_threat(self, url: str) -> dict:
        """Check URL against real threat databases"""
        cache_key = f"url:{url}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key].copy()
        
        result = {
            "url": url,
            "is_malicious": False,
            "threat_type": None,
            "confidence": 0,
            "source": "none"
        }
        
        # Check VirusTotal (REAL API)
        if self.virustotal_key:
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                response = requests.get(
                    f"{VIRUSTOTAL_BASE}/urls/{url_id}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}):
                        stats = data['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        if malicious > 0 or suspicious > 0:
                            result.update({
                                "is_malicious": True,
                                "threat_type": "malware/phishing",
                                "confidence": min((malicious + suspicious) * 10, 100),
                                "source": "virustotal"
                            })
            except Exception as e:
                pass
        
        # Check Google Safe Browsing (REAL API)
        if self.google_sb_key:
            try:
                response = requests.post(
                    f"{GOOGLE_SB_BASE}/threatMatches:find",
                    params={"key": self.google_sb_key},
                    json={
                        "client": {"clientId": "cyber-threat-detector", "clientVersion": "1.0.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}]
                        }
                    },
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('matches'):
                        threat_type = data['matches'][0].get('threatType', 'UNKNOWN')
                        result.update({
                            "is_malicious": True,
                            "threat_type": f"google_{threat_type.lower()}",
                            "confidence": 90,
                            "source": "google_safe_browsing"
                        })
            except Exception as e:
                pass
        
        # Pattern-based detection
        suspicious_patterns = [
            r"bit\.ly", r"tinyurl\.com",
            r"\.xyz$", r"\.top$", r"\.tk$", r"\.ml$",
            r"login.*verify", r"account.*update", r"secure.*login",
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                if not result["is_malicious"]:
                    result.update({
                        "is_malicious": True,
                        "threat_type": "suspicious_pattern",
                        "confidence": 60,
                        "source": "pattern_detection"
                    })
                break
        
        # Known malicious domains
        malicious_domains = [
            "testvirus.org", "wicar.org", "malware.com",
            "phishing-site.xyz", "evil-domain.top", "badsite.tk"
        ]
        
        for domain in malicious_domains:
            if domain in url.lower():
                result.update({
                    "is_malicious": True,
                    "threat_type": "known_malicious_domain",
                    "confidence": 95,
                    "source": "local_blocklist"
                })
                break
        
        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        
        return result
    
    def check_file_hash(self, file_hash: str) -> dict:
        """Check file hash against VirusTotal"""
        cache_key = f"hash:{file_hash}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key].copy()
        
        result = {
            "hash": file_hash,
            "is_malicious": False,
            "malware_family": None,
            "confidence": 0,
            "source": "none"
        }
        
        # Check VirusTotal (REAL API)
        if self.virustotal_key:
            try:
                response = requests.get(
                    f"{VIRUSTOTAL_BASE}/files/{file_hash}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}):
                        stats = data['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        
                        if malicious > 0:
                            result.update({
                                "is_malicious": True,
                                "malware_family": f"Detected by {malicious} engines",
                                "confidence": min(malicious * 5, 100),
                                "source": "virustotal"
                            })
            except:
                pass
        
        # Known malware hashes
        known_malware = {
            "44d88612fea8a8f36de82e1278abb02f": {"family": "EICAR_Test_Virus", "confidence": 100},
            "e99a18c428cb38d5f260853678922e03": {"family": "Test_Malware", "confidence": 100},
        }
        
        if file_hash.lower() in known_malware:
            info = known_malware[file_hash.lower()]
            result.update({
                "is_malicious": True,
                "malware_family": info["family"],
                "confidence": info["confidence"],
                "source": "local_database"
            })
        
        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        
        return result
    
    def get_summary(self) -> dict:
        return {
            "apis_configured": True,
            "abuseipdb_configured": bool(self.abuseipdb_key),
            "virustotal_configured": bool(self.virustotal_key),
            "google_sb_configured": bool(self.google_sb_key),
            "cache_size": len(self.cache)
        }

threat_intel = ThreatIntelligence()
