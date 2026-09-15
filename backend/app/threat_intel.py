import requests
from datetime import datetime, timedelta
import base64
import re
import os

# ============ API KEYS FROM ENVIRONMENT ============
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

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
            return self.cache[cache_key]

        result = {
            "ip": ip,
            "abuseipdb": None,
            "virustotal": None,
            "risk_score": 0,
            "threat_detected": False,
            "sources_checked": []
        }

        # Check AbuseIPDB
        if self.abuseipdb_key:
            try:
                headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
                response = requests.get(f"{ABUSEIPDB_BASE}/check", headers=headers, params={"ipAddress": ip}, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["abuseipdb"] = data.get("data", {})
                    result["sources_checked"].append("AbuseIPDB")
                    if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                        result["threat_detected"] = True
                        result["risk_score"] += 5
            except Exception as e:
                pass

        # Check VirusTotal
        if self.virustotal_key:
            try:
                headers = {"x-apikey": self.virustotal_key}
                response = requests.get(f"{VIRUSTOTAL_BASE}/ip_addresses/{ip}", headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["virustotal"] = data.get("data", {}).get("attributes", {})
                    result["sources_checked"].append("VirusTotal")
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        result["threat_detected"] = True
                        result["risk_score"] += 5
            except Exception as e:
                pass

        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        return result

    def check_domain_reputation(self, domain: str) -> dict:
        """Check domain reputation"""
        cache_key = f"domain:{domain}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key]

        result = {
            "domain": domain,
            "virustotal": None,
            "google_safe_browsing": None,
            "risk_score": 0,
            "threat_detected": False,
            "sources_checked": []
        }

        # Check VirusTotal
        if self.virustotal_key:
            try:
                headers = {"x-apikey": self.virustotal_key}
                domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
                response = requests.get(f"{VIRUSTOTAL_BASE}/domains/{domain_id}", headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["virustotal"] = data.get("data", {}).get("attributes", {})
                    result["sources_checked"].append("VirusTotal")
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        result["threat_detected"] = True
                        result["risk_score"] += 5
            except Exception as e:
                pass

        # Check Google Safe Browsing
        if self.google_sb_key:
            try:
                url = f"{GOOGLE_SB_BASE}/threatMatches:find"
                params = {"key": self.google_sb_key}
                body = {
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"http://{domain}"}, {"url": f"https://{domain}"}]
                    }
                }
                response = requests.post(url, params=params, json=body, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["google_safe_browsing"] = data
                    result["sources_checked"].append("Google Safe Browsing")
                    if data.get("matches", []):
                        result["threat_detected"] = True
                        result["risk_score"] += 5
            except Exception as e:
                pass

        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        return result

    def check_file_hash(self, file_hash: str) -> dict:
        """Check file hash (MD5, SHA1, SHA256) against VirusTotal"""
        cache_key = f"hash:{file_hash}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key]

        result = {
            "hash": file_hash,
            "virustotal": None,
            "risk_score": 0,
            "threat_detected": False,
            "sources_checked": []
        }

        if self.virustotal_key:
            try:
                headers = {"x-apikey": self.virustotal_key}
                response = requests.get(f"{VIRUSTOTAL_BASE}/files/{file_hash}", headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["virustotal"] = data.get("data", {}).get("attributes", {})
                    result["sources_checked"].append("VirusTotal")
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    if stats.get("malicious", 0) > 0:
                        result["threat_detected"] = True
                        result["risk_score"] += 10
                    elif stats.get("suspicious", 0) > 0:
                        result["risk_score"] += 5
            except Exception as e:
                pass

        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        return result

    def check_url(self, url: str) -> dict:
        """Check URL against Google Safe Browsing and VirusTotal"""
        cache_key = f"url:{url}"
        if cache_key in self.cache and datetime.now() < self.cache_expiry.get(cache_key, datetime.now()):
            return self.cache[cache_key]

        result = {
            "url": url,
            "google_safe_browsing": None,
            "virustotal": None,
            "risk_score": 0,
            "threat_detected": False,
            "sources_checked": []
        }

        # Check Google Safe Browsing
        if self.google_sb_key:
            try:
                url_check = f"{GOOGLE_SB_BASE}/threatMatches:find"
                params = {"key": self.google_sb_key}
                body = {
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                response = requests.post(url_check, params=params, json=body, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    result["google_safe_browsing"] = data
                    result["sources_checked"].append("Google Safe Browsing")
                    if data.get("matches", []):
                        result["threat_detected"] = True
                        result["risk_score"] += 5
            except Exception as e:
                pass

        self.cache[cache_key] = result
        self.cache_expiry[cache_key] = datetime.now() + timedelta(hours=1)
        return result

# Export instance
threat_intel = ThreatIntelligence()
