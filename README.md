# 🛡️ PhishRay: Email & URL Threat Analyzer

PhishRay is a Python-based forensics tool designed to scan `.eml` files for malicious indicators. It automates the detection of phishing tactics by mapping findings to the **MITRE ATT&CK** framework.

## ✨ Features
* **URL Analysis:** Checks for malicious reputation via URLhaus.
* **Lookalike Detection:** Identifies typosquatting/impersonation domains.
* **Heuristic Engine:** Flags alarming or phishing-specific language.
* **Attachment Scanning:** Integrated **YARA** engine for malware signature detection.
* **Framework Mapping:** Directly maps threats to MITRE ATT&CK (T1566).

## 🚀 Installation (Linux)
1. **Install System Deps:**
   ```bash
   sudo apt install libyara-dev python3-pip -y
