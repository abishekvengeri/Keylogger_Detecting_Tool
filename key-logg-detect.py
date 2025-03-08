#!/usr/bin/env python3

import os
import psutil
import hashlib
import requests
import subprocess
import magic

# Configuration
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SUSPICIOUS_PROCESSES = ["logkeys", "pykeylogger", "khd", "lkl", "keylogger"]
SUSPICIOUS_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/home"]  # Focus on user-writable areas
WHITELIST_PATHS = [
    "/usr/bin/logger",
    "/lib/modules/",
    "/sys/",
    "/proc/",
    "/dev/input/by-path/"  # Legitimate input devices
]
SUSPICIOUS_PATTERNS = [
    "keylogger", "klog", "keylog",
    "keystroke", "logkeys", "khd"
]

def is_whitelisted(path):
    """Check if file is in safe locations"""
    return any(whitelisted in path for whitelisted in WHITELIST_PATHS)

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return None

def virustotal_check(file_hash):
    """Check file hash against VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"<https://www.virustotal.com/api/v3/files/{file_hash}>"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()["data"]["attributes"]["last_analysis_stats"]
        return None
    except Exception as e:
        return None

def check_processes():
    """Detect suspicious running processes"""
    for proc in psutil.process_iter(['name', 'exe']):
        proc_name = proc.info['name'].lower()
        if any(name in proc_name for name in SUSPICIOUS_PROCESSES):
            exe_path = proc.info['exe']
            if exe_path and not is_whitelisted(exe_path):
                print(f"\\n[!] Suspicious process: {proc_name} (PID: {proc.pid})")
                file_hash = get_file_hash(exe_path)
                if file_hash:
                    vt_result = virustotal_check(file_hash)
                    if vt_result:
                        print(f"  ├─ Malicious: {vt_result['malicious']}/94 AV engines")
                        if vt_result['malicious'] > 3:
                            print("  └─ ✗ HIGH RISK: Known malicious process!")

def check_filesystem():
    """Scan for suspicious files with advanced filtering"""
    file_checker = magic.Magic(mime=True)

    for path in SUSPICIOUS_PATHS:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)

                if is_whitelisted(full_path):
                    continue

                # Check filename patterns and file type
                if (any(patt in file.lower() for patt in SUSPICIOUS_PATTERNS)
                    and "text" not in file_checker.from_file(full_path)):

                    print(f"\\n[!] Scanning suspicious file: {full_path}")
                    file_hash = get_file_hash(full_path)

                    if file_hash:
                        vt_result = virustotal_check(file_hash)
                        if vt_result:
                            print(f"  ├─ SHA-256: {file_hash}")
                            print(f"  ├─ Detections: {vt_result['malicious']}/94")
                            if vt_result['malicious'] > 0:
                                print("  └─ ✗ MALWARE DETECTED!")

def check_keyboard_access():
    """Detect processes accessing keyboard devices"""
    try:
        print("\\n[*] Checking keyboard device access...")
        lsof = subprocess.check_output(
            ["lsof", "-n", "/dev/input/by-path/*kbd*"],
            text=True,
            stderr=subprocess.DEVNULL
        )
        print("  [!] Processes accessing keyboard devices:")
        print("  ┌─" + "\\n  ├─".join(lsof.split('\\n')[:3]))  # Show top 3
        print("  └─ ... (truncated)")
    except Exception:
        pass

def main():
    print("[*] Starting enhanced keylogger detection")
    print("[*] VirusTotal integration active\\n")

    check_processes()
    check_filesystem()
    check_keyboard_access()

    print("\\n[*] Scan complete. Investigate flagged items!")

if __name__ == "__main__":
    main()
