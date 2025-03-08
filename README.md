# Keylogger Detector with VirusTotal Integration

## Overview
This script enhances keylogger detection by scanning processes, filesystems, and keyboard access logs for suspicious activity. It integrates with [VirusTotal](https://www.virustotal.com/) to verify potential threats.

## Features
- **Process Scanning:** Detects known keyloggers running in memory.
- **Filesystem Analysis:** Scans common attack locations (`/tmp`, `/dev/shm`, `/home`).
- **VirusTotal API Integration:** Checks suspicious files against VirusTotal.
- **Keyboard Monitoring:** Identifies processes accessing keyboard input devices.
- **Whitelisting System Files:** Ignores safe files and directories.
- **Formatted Output:** Provides clear, structured reports.

## Installation
Ensure you have Python 3 installed, then install the required dependencies:

```bash
sudo apt install python3-psutil python3-requests python3-magic
```

## Setup
1. **Obtain a VirusTotal API Key:**  
   - Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us).
   - Retrieve your API key from your profile.
2. **Modify the script:**  
   - Replace `YOUR_VIRUSTOTAL_API_KEY` in the script with your API key.

## Usage
Run the script with elevated privileges:

```bash
sudo python3 keylogger_detector.py
```

## Sample Output
```
[*] Starting enhanced keylogger detection
[*] VirusTotal integration active

[!] Scanning suspicious file: /tmp/.X11-unix/x0-logkeys
  ├─ SHA-256: a1b2c3...d4e5
  ├─ Detections: 32/94
  └─ ✗ MALWARE DETECTED!

[*] Checking keyboard device access...
  [!] Processes accessing keyboard devic
