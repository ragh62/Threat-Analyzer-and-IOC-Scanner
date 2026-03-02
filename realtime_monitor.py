import time
import json
import re
from vt_checker import check_ip_virustotal, check_hash_virustotal

LOG_FILE = "sample_logs.txt"

# Load IOC database
with open("ioc_db.json") as f:
    iocs = json.load(f)

malicious_ips = set(iocs["malicious_ips"])
malicious_domains = set(iocs["malicious_domains"])

print("👀 Real-Time Log Monitoring Started...\n")


def scan_line(line):
    # Extract IOCs from log line
    found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    found_domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", line)
    found_hashes = re.findall(r"\b[a-fA-F0-9]{32}\b", line)  # MD5 hashes

    # ---- Static IOC Checks ----
    for ip in found_ips:
        if ip in malicious_ips:
            print(f"⚠️ STATIC ALERT: Malicious IP -> {ip}")

    for domain in found_domains:
        if domain in malicious_domains:
            print(f"⚠️ STATIC ALERT: Malicious Domain -> {domain}")

    # ---- VirusTotal IP Checks ----
    for ip in found_ips:
        result, score = check_ip_virustotal(ip)

        if result is True:
            print(f"🚨 VT ALERT: {ip} flagged malicious by {score} engines")
        elif result is False:
            print(f"✅ VT CLEAN: {ip} not flagged")

    # ---- VirusTotal Hash Checks ----
    for file_hash in found_hashes:
        print(f"🧬 Detected File Hash: {file_hash}")
        result, score = check_hash_virustotal(file_hash)

        if result is True:
            print(f"🚨 MALWARE HASH DETECTED: flagged by {score} engines")
        elif result is False:
            print(f"✅ File hash clean")


# ---- Real-Time Monitoring Loop ----
with open(LOG_FILE, "r") as file:
    file.seek(0, 2)  # move to end of file

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        print(f"\n📥 New Log: {line.strip()}")
        scan_line(line)