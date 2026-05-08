import os
import re
import email
import yara
import requests
import tldextract
from urllib.parse import urlparse
from difflib import SequenceMatcher

# MITRE ATT&CK Framework Mapping
MITRE_MAPPING = {
    "phishing_tactic": "T1566 (Phishing)",
    "malicious_link": "T1566.002 (Spearphishing Link)",
    "malicious_file": "T1204.002 (User Execution: Malicious File)",
    "lookalike": "T1566.002 (Spearphishing Link - Typosquatting)"
}

class PhishRay:
    def __init__(self, rules_path="rules/malware_rules.yar"):
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
        # Domains commonly impersonated
        self.trusted_domains = ["google", "microsoft", "paypal", "apple", "amazon", "netflix"]
        
        # Initialize YARA
        if os.path.exists(rules_path):
            try:
                self.rules = yara.compile(filepath=rules_path)
                print(f"[*] YARA rules loaded successfully from {rules_path}")
            except yara.SyntaxError as e:
                print(f"[!] YARA Syntax Error: {e}")
                self.rules = None
        else:
            self.rules = None
            print(f"[!] Warning: YARA rules not found at {rules_path}. Attachment scanning will be limited.")

    def analyze_email(self, eml_path):
        """Extracts and analyzes components of an .eml file."""
        if not os.path.exists(eml_path):
            print(f"[!] Error: File {eml_path} not found.")
            return

        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f)

        body = ""
        attachments = []

        # Parse Email Structure
        for part in msg.walk():
            content_type = part.get_content_type()
            # Extract Text Body
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors='ignore')
            
            # Extract Attachments
            if part.get('Content-Disposition'):
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        "name": filename,
                        "data": part.get_payload(decode=True)
                    })

        # --- Output Report ---
        print(f"\n{'='*60}")
        print(f"🔍 PHISHRAY ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"Subject: {msg['Subject']}")
        print(f"From:    {msg['From']}")
        print(f"To:      {msg['To']}")
        print(f"{'-'*60}")
        
        self._check_body_language(body)
        self._scan_urls(body)
        self._scan_attachments(attachments)
        print(f"{'='*60}\n")

    def _check_body_language(self, body):
        """Heuristic check for phishing keywords."""
        suspicious_terms = ["urgent", "suspended", "login required", "security alert", "action needed", "unauthorized"]
        found = [term for term in suspicious_terms if term in body.lower()]
        if found:
            print(f"[!] Flag: Alarming Language Detected: {', '.join(found)}")
            print(f"    └─ MITRE ATT&CK: {MITRE_MAPPING['phishing_tactic']}")

    def _scan_urls(self, body):
        """Scans URLs for lookalikes and blacklisted reputations."""
        urls = list(set(re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', body)))
        if not urls: 
            return

        print(f"[+] Found {len(urls)} unique URLs. Checking reputation...")
        for url in urls:
            # 1. Lookalike Domain Check (Typosquatting)
            extracted = tldextract.extract(url)
            domain = extracted.domain
            for trusted in self.trusted_domains:
                similarity = SequenceMatcher(None, domain, trusted).ratio()
                # If domain is similar but not exactly the same
                if 0.75 <= similarity < 1.0:
                    print(f"  - WARNING: Possible Lookalike! '{domain}' resembles '{trusted}'")
                    print(f"    └─ MITRE ATT&CK: {MITRE_MAPPING['lookalike']}")

            # 2. URLhaus Threat Intel Check
            try:
                resp = requests.post(self.urlhaus_api, data={'url': url}, timeout=3)
                if resp.status_code == 200:
                    result = resp.json()
                    if result.get('query_status') == 'ok':
                        print(f"  - CRITICAL: URL is BLACKLISTED on URLhaus! ({url})")
                        print(f"    └─ MITRE ATT&CK: {MITRE_MAPPING['malicious_link']}")
            except Exception:
                pass # Fail silently if API is down

    def _scan_attachments(self, attachments):
        """Scans attachments using YARA rules."""
        if not attachments: 
            print("[i] No attachments found.")
            return
        
        print(f"[+] Scanning {len(attachments)} attachment(s)...")
        for att in attachments:
            print(f"  - Analyzing file: {att['name']}")
            if self.rules and att['data']:
                matches = self.rules.match(data=att['data'])
                if matches:
                    print(f"    [!] CRITICAL: Malware signature match: {[str(m) for m in matches]}")
                    print(f"    └─ MITRE ATT&CK: {MITRE_MAPPING['malicious_file']}")
                else:
                    print(f"    [✓] Signature scan clear.")
            else:
                if not self.rules:
                    print("    [?] Skip: No YARA rules loaded.")

if __name__ == "__main__":
    # To use: 
    # 1. Create a folder named 'rules' and add a .yar file.
    # 2. Provide the path to a .eml file below.
    scanner = PhishRay()
    
    # Example: Change this to your actual .eml file path
    target_email = "test_email.eml" 
    
    if os.path.exists(target_email):
        scanner.analyze_email(target_email)
    else:
        print(f"Please place a file named '{target_email}' in this directory to test.")
