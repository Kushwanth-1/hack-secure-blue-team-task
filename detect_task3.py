
import re
from collections import Counter

LOG_FILE = "dvwa_task3_logs.txt"

with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
    logs = file.readlines()

alerts = []

# 1. Brute-force indicators: count requests to the DVWA brute-force page
brute_requests = [
    line for line in logs
    if re.search(r'"(?:GET|POST) /vulnerabilities/brute/', line, re.I)
]

if len(brute_requests) >= 5:
    alerts.append({
        "severity": "HIGH",
        "type": "Repeated login attempts",
        "count": len(brute_requests),
        "details": "Multiple requests to the DVWA brute-force endpoint"
    })

# 2. Directory enumeration indicators
probed_paths = [
    line for line in logs
    if re.search(r'"(?:GET|HEAD) /(admin|config|backup|robots\.txt)(/|\?| )', line, re.I)
]

if probed_paths:
    alerts.append({
        "severity": "MEDIUM",
        "type": "Directory/path probing",
        "count": len(probed_paths),
        "details": "Requests to common paths such as /admin, /config, or /robots.txt"
    })

# 3. SQL injection indicators
sqli_requests = [
    line for line in logs
    if re.search(r'vulnerabilities/sqli/.*(?:%27|%3D|%20OR|union|select)', line, re.I)
]

if sqli_requests:
    alerts.append({
        "severity": "HIGH",
        "type": "Possible SQL injection test",
        "count": len(sqli_requests),
        "details": "SQL-like patterns detected in requests to the DVWA SQLi endpoint"
    })

# 4. Reflected XSS indicators
xss_requests = [
    line for line in logs
    if re.search(r'vulnerabilities/xss_r/.*(?:%3Cscript|<script|alert%28)', line, re.I)
]

if xss_requests:
    alerts.append({
        "severity": "HIGH",
        "type": "Possible reflected XSS test",
        "count": len(xss_requests),
        "details": "Script-like test patterns detected in requests to the DVWA reflected XSS endpoint"
    })

print("DVWA TASK 3 - PYTHON LOG DETECTION REPORT")
print("=" * 48)
print(f"Log file: {LOG_FILE}")
print(f"Total log lines analyzed: {len(logs)}")
print()

if not alerts:
    print("No matching patterns found. Check the log file and detection rules.")
else:
    for number, alert in enumerate(alerts, start=1):
        print(f"ALERT {number}")
        print(f"Severity: {alert['severity']}")
        print(f"Detection: {alert['type']}")
        print(f"Matching log entries: {alert['count']}")
        print(f"Details: {alert['details']}")
        print("-" * 48)

with open("task3_detection_alerts.txt", "w", encoding="utf-8") as output:
    output.write("DVWA TASK 3 - PYTHON LOG DETECTION REPORT\n")
    output.write(f"Total log lines analyzed: {len(logs)}\n\n")
    for alert in alerts:
        output.write(
            f"[{alert['severity']}] {alert['type']} | "
            f"Count: {alert['count']} | {alert['details']}\n"
        )

print("\nSaved results to task3_detection_alerts.txt")

