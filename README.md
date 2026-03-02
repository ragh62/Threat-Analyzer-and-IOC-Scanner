# 🛡️ Threat Analyzer and IOC Scanner

A comprehensive cybersecurity tool that analyzes logs, scans Indicators of Compromise (IOCs), and performs real-time threat monitoring.  
This project is designed to simulate SOC Analyst workflows for detecting suspicious activities and potential security threats.

---

## 🚀 Features
- Analyze system and application logs for suspicious patterns
- Scan Indicators of Compromise (IOCs) from logs
- VirusTotal-based threat reputation checking
- Real-time monitoring for continuous threat detection
- GUI dashboard for visualization and interaction
- Sample logs included for testing and demonstration

---

## 🧠 Tech Stack
- Python
- JSON-based IOC database
- VirusTotal API integration
- Log parsing & pattern matching
- Tkinter GUI Dashboard

---

## 📂 Project Structure

Threat-Analyzer-and-IOC-Scanner/
│── scanner.py # IOC scanning and log analysis logic
│── vt_checker.py # VirusTotal threat reputation checker
│── realtime_monitor.py # Real-time monitoring module
│── gui_dashboard.py # GUI dashboard interface
│── ioc_db.json # IOC database (malicious indicators)
│── sample_logs.txt # Sample log file for testing
│── .gitignore
│── README.md


---

## ⚙️ Installation
```bash
git clone https://github.com/ragh62/Threat-Analyzer-and-IOC-Scanner.git
cd Threat-Analyzer-and-IOC-Scanner
pip install requests
▶️ Usage
1️⃣ Run IOC Scanner
python scanner.py
2️⃣ Run Real-Time Monitor
python realtime_monitor.py
3️⃣ Launch GUI Dashboard
python gui_dashboard.py
🔍 How It Works

Reads log data from files or real-time input

Extracts suspicious patterns and IOCs

Matches indicators against IOC database

Optionally checks reputation using VirusTotal API

Displays results via CLI or GUI dashboard

🛡️ Use Cases

SOC Analyst log investigation practice

Threat hunting and IOC detection

Malware / suspicious activity analysis

Security monitoring demonstration project

👨‍💻 Author

Raghav Negi
Cybersecurity Enthusiast | SOC Analyst Aspirant
GitHub: https://github.com/ragh62

⭐ Future Improvements

Integrate with SIEM tools (Splunk/ELK)

Add automated alerting system

Enhance GUI visualization with charts

Support live network traffic analysis


---

# 📤 After Pasting README
Run:
```bash
git add README.md
git commit -m "Added professional README for Threat Analyzer & IOC Scanner"
git push