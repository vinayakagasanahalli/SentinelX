import re
from typing import Optional, Dict, Any, List

# In-memory tracking for rate limiting & brute force detection
IP_FAILED_LOGINS = {}
BRUTE_FORCE_THRESHOLD = 3

SQLI_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"('|\"|\bOR\b|\bAND\b)\s*(=|>|<|\bLIKE\b)\s*('|\"|\d)",
    r"(DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+.*SET)",
    r"(--|#|/\*|\*/)"
]

XSS_PATTERNS = [
    r"<script\b[^>]*>(.*?)</script>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<iframe\b"
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"/etc/passwd",
    r"c:\\windows\\system32"
]

def analyze_log(source_ip: str, service: str, message: str, raw_payload: str = "") -> Optional[Dict[str, Any]]:
    combined_text = f"{message} {raw_payload}"
    
    # 1. SQL Injection Check
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return {
                "title": f"SQL Injection Attempt Detected from {source_ip}",
                "category": "SQL Injection (SQLi)",
                "severity": "CRITICAL",
                "risk_score": 9.2,
                "raw_logs": [f"[{service}] {message}"],
                "recommended_action": f"Block IP {source_ip} immediately and inspect SQL query parameter sanitization in service {service}."
            }
            
    # 2. XSS Attempt Check
    for pattern in XSS_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return {
                "title": f"Cross-Site Scripting (XSS) Attack Detected",
                "category": "XSS Vulnerability Attempt",
                "severity": "HIGH",
                "risk_score": 7.8,
                "raw_logs": [f"[{service}] {message}"],
                "recommended_action": f"Sanitize HTML/script payloads on endpoint {service} and apply Content Security Policy (CSP)."
            }

    # 3. Path Traversal Check
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return {
                "title": f"Directory Traversal & Unauthorized Access Attempt",
                "category": "Path Traversal / Local File Inclusion",
                "severity": "CRITICAL",
                "risk_score": 8.9,
                "raw_logs": [f"[{service}] {message}"],
                "recommended_action": f"Block IP {source_ip} and restrict file system permissions for service {service}."
            }

    # 4. Brute Force Login Check
    if "failed login" in message.lower() or "authentication failure" in message.lower() or "invalid password" in message.lower():
        IP_FAILED_LOGINS[source_ip] = IP_FAILED_LOGINS.get(source_ip, 0) + 1
        if IP_FAILED_LOGINS[source_ip] >= BRUTE_FORCE_THRESHOLD:
            count = IP_FAILED_LOGINS[source_ip]
            return {
                "title": f"Brute-Force Credential Attack from {source_ip}",
                "category": "Brute Force Authentication",
                "severity": "HIGH",
                "risk_score": 8.1,
                "raw_logs": [f"[{service}] {count} consecutive authentication failures recorded from {source_ip}"],
                "recommended_action": f"Automated response triggered: Block IP {source_ip} and enforce CAPTCHA / rate limiting."
            }

    # 5. Ransomware / Suspicious Encryption Activity
    if "bulk extension change" in message.lower() or ".locked" in message.lower() or "ransom" in message.lower():
        return {
            "title": f"Potential Ransomware File Activity Detected on {service}",
            "category": "Ransomware / Malicious Encryption",
            "severity": "CRITICAL",
            "risk_score": 9.9,
            "raw_logs": [f"[{service}] {message}"],
            "recommended_action": "Isolate endpoint immediately, take volume snapshot, and disconnect active network shares."
        }

    return None
