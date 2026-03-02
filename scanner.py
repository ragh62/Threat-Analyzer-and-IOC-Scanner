import json
import re
from vt_checker import check_ip_virustotal

# Load IOC DB
with open("ioc_db.json") as f:
    iocs = json.load(f)

malicious_ips = set(iocs["malicious_ips"])
malicious_domains = set(iocs["malicious_domains"])

# Read logs
with open("sample_logs.txt") as f:
    logs = f.read()

# Extract IPs & domains
found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", logs)
found_domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", logs)

print("🔍 Scanning logs...\n")

# --- Static IOC Check ---
for ip in found_ips:
    if ip in malicious_ips:
        print(f"⚠️ STATIC ALERT: Malicious IP -> {ip}")

for domain in found_domains:
    if domain in malicious_domains:
        print(f"⚠️ STATIC ALERT: Malicious Domain -> {domain}")

# --- Dynamic VirusTotal Check ---
print("\n🌐 Checking with VirusTotal...\n")

for ip in found_ips:
    result, score = check_ip_virustotal(ip)

    if result is True:
        print(f"🚨 VT ALERT: {ip} flagged malicious by {score} engines")
    elif result is False:
        print(f"✅ VT CLEAN: {ip} not flagged")
    else:
        print(f"⚠️ VT ERROR checking {ip}")

print("\n✅ Scan Completed.")