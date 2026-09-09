#!/usr/bin/env python3
import os
import hashlib
import requests
import time
from datetime import datetime
from pathlib import Path

API_BASE = "http://localhost:18000"
DOWNLOADS_FOLDER = Path.home() / "Downloads"

# Known malware hashes
KNOWN_MALWARE = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_Test_Virus",
    "e99a18c428cb38d5f260853678922e03": "Test_Malware",
}

def calculate_file_hash(filepath):
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None

def check_file_hash(file_hash):
    try:
        response = requests.get(f"{API_BASE}/ioc/check-file/{file_hash}", timeout=5)
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

def log_file_event(filepath, file_hash):
    try:
        requests.post(f"{API_BASE}/events", json={
            "user_id": 1,
            "event_type": "file_download",
            "payload": {
                "filepath": str(filepath),
                "filename": os.path.basename(filepath),
                "hash": file_hash,
                "timestamp": datetime.now().isoformat()
            }
        }, timeout=5)
    except:
        pass

def monitor():
    print("🔍 File Monitor Started...")
    print(f"Monitoring folder: {DOWNLOADS_FOLDER}")
    print(f"API Base: {API_BASE}")
    
    DOWNLOADS_FOLDER.mkdir(exist_ok=True)
    
    existing_files = set()
    if DOWNLOADS_FOLDER.exists():
        existing_files = {f.name for f in DOWNLOADS_FOLDER.iterdir() if f.is_file()}
    
    print(f"Existing files: {len(existing_files)}")
    
    while True:
        try:
            if DOWNLOADS_FOLDER.exists():
                current_files = {f.name for f in DOWNLOADS_FOLDER.iterdir() if f.is_file()}
                new_files = current_files - existing_files
                
                for filename in new_files:
                    filepath = DOWNLOADS_FOLDER / filename
                    print(f"📁 New file detected: {filename}")
                    
                    file_hash = calculate_file_hash(filepath)
                    
                    if file_hash:
                        print(f"  Hash: {file_hash}")
                        log_file_event(filepath, file_hash)
                        
                        if file_hash.lower() in KNOWN_MALWARE:
                            malware_name = KNOWN_MALWARE[file_hash.lower()]
                            print(f"⚠️ KNOWN MALWARE: {malware_name}")
                            send_alert(f"File: Malware detected - {filename} (family: {malware_name})", "high")
                        else:
                            hash_check = check_file_hash(file_hash)
                            if hash_check.get('is_malicious'):
                                print(f"⚠️ MALICIOUS FILE DETECTED!")
                                send_alert(f"File: Malicious file downloaded - {filename} (confidence: {hash_check.get('confidence', 0)}%)", "high")
                
                existing_files = current_files
            
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(3)

if __name__ == "__main__":
    monitor()
