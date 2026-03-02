import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import threading
import time
import json
import re
import csv
from datetime import datetime
from vt_checker import check_ip_virustotal, check_hash_virustotal

LOG_FILE = "sample_logs.txt"

# Load IOC DB
with open("ioc_db.json") as f:
    iocs = json.load(f)

malicious_ips = set(iocs["malicious_ips"])
malicious_domains = set(iocs["malicious_domains"])

# Alert storage
alerts = []
ip_alert_count = 0
domain_alert_count = 0
hash_alert_count = 0

# -------- GUI SETUP --------
root = tk.Tk()
root.title("🛡️ SOC Threat Monitoring Dashboard")
root.geometry("1000x650")

title = tk.Label(root, text="Real-Time Threat Intelligence Dashboard", font=("Arial", 18, "bold"))
title.pack(pady=10)

# Counters Frame
counter_frame = tk.Frame(root)
counter_frame.pack(pady=5)

ip_label = tk.Label(counter_frame, text="IP Alerts: 0", fg="red", font=("Arial", 12, "bold"))
ip_label.grid(row=0, column=0, padx=20)

domain_label = tk.Label(counter_frame, text="Domain Alerts: 0", fg="orange", font=("Arial", 12, "bold"))
domain_label.grid(row=0, column=1, padx=20)

hash_label = tk.Label(counter_frame, text="Hash Alerts: 0", fg="purple", font=("Arial", 12, "bold"))
hash_label.grid(row=0, column=2, padx=20)

# Log Display
log_box = ScrolledText(root, width=120, height=25, bg="black", fg="white")
log_box.pack(padx=10, pady=10)

# Chart Canvas
canvas = tk.Canvas(root, width=600, height=150, bg="white")
canvas.pack(pady=10)

def log_message(message, color="white"):
    log_box.insert(tk.END, message + "\n", color)
    log_box.tag_config(color, foreground=color)
    log_box.see(tk.END)

def update_counters():
    ip_label.config(text=f"IP Alerts: {ip_alert_count}")
    domain_label.config(text=f"Domain Alerts: {domain_alert_count}")
    hash_label.config(text=f"Hash Alerts: {hash_alert_count}")
    draw_chart()

def draw_chart():
    canvas.delete("all")
    canvas.create_text(300, 10, text="Alert Counts", font=("Arial", 12, "bold"))

    # Bars
    canvas.create_rectangle(100, 130, 150, 130 - ip_alert_count * 10, fill="red")
    canvas.create_text(125, 140, text="IP")

    canvas.create_rectangle(250, 130, 300, 130 - domain_alert_count * 10, fill="orange")
    canvas.create_text(275, 140, text="Domain")

    canvas.create_rectangle(400, 130, 450, 130 - hash_alert_count * 10, fill="purple")
    canvas.create_text(425, 140, text="Hash")

def save_alert(alert_type, value):
    alerts.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "value": value
    })

# -------- EXPORT FUNCTIONS --------
def export_csv():
    with open("alerts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["time", "type", "value"])
        writer.writeheader()
        writer.writerows(alerts)
    log_message("📁 Alerts exported to alerts.csv", "cyan")

def export_json():
    with open("alerts.json", "w") as f:
        json.dump(alerts, f, indent=4)
    log_message("📁 Alerts exported to alerts.json", "cyan")

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="Export CSV", command=export_csv).grid(row=0, column=0, padx=10)
tk.Button(btn_frame, text="Export JSON", command=export_json).grid(row=0, column=1, padx=10)

# -------- SCAN LOGIC --------
def scan_line(line):
    global ip_alert_count, domain_alert_count, hash_alert_count

    found_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    found_domains = re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", line)
    found_hashes = re.findall(r"\b[a-fA-F0-9]{32}\b", line)

    # ---- IP Checks ----
    for ip in found_ips:
        if ip in malicious_ips:
            ip_alert_count += 1
            log_message(f"⚠️ STATIC ALERT: Malicious IP -> {ip}", "red")
            save_alert("IP", ip)

        result, score = check_ip_virustotal(ip)
        if result is True:
            ip_alert_count += 1
            log_message(f"🚨 VT ALERT: {ip} flagged by {score} engines", "red")
            save_alert("IP", ip)
        elif result is False:
            log_message(f"✅ VT CLEAN: {ip}", "green")

    # ---- Domain Checks ----
    for domain in found_domains:
        if domain in malicious_domains:
            domain_alert_count += 1
            log_message(f"⚠️ STATIC ALERT: Malicious Domain -> {domain}", "orange")
            save_alert("Domain", domain)

    # ---- Hash Checks ----
    for file_hash in found_hashes:
        log_message(f"🧬 Hash Detected: {file_hash}", "purple")
        result, score = check_hash_virustotal(file_hash)

        if result is True:
            hash_alert_count += 1
            log_message(f"🚨 MALWARE HASH DETECTED: flagged by {score} engines", "purple")
            save_alert("Hash", file_hash)
        elif result is False:
            log_message("✅ File hash clean", "green")

    update_counters()

# -------- REAL-TIME MONITOR --------
def monitor_logs():
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue
            log_message(f"\n📥 New Log: {line.strip()}", "cyan")
            scan_line(line)

thread = threading.Thread(target=monitor_logs, daemon=True)
thread.start()

log_message("👀 Monitoring started... Waiting for new logs...\n", "cyan")

root.mainloop()