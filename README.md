<img width="1536" height="1024" alt="Splunk" src="https://github.com/user-attachments/assets/1d90ac72-a755-48d2-9bec-4b551aaa3797" />

# ++++++++++ Splunk-query-assistant ++++++++++
# 🛡️ Splunk Query Assistant

A Python-based **SOC Analyst tool** that recommends **Splunk SPL queries** based on attack types and maps detections to **MITRE ATT&CK techniques**.

Designed to help SOC analysts quickly find useful SPL queries for security monitoring, threat detection, and investigation.

## 🚀 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/amedrouabhi33/splunk-query-assistant.git
cd splunk-query-assistant
```

### 2️⃣ Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3️⃣ Install Required Dependencies

```bash
python -m pip install -r requirements.txt
```

## 💻 Usage

Start the **Splunk Query Assistant**:

```bash
python main.py
```

## 🧭 Available Commands

| Command       | Description                    |
| ------------- | ------------------------------ |
| 🔢 `1-110`    | Open a Splunk query by number  |
| 🔎 `search`   | Search the query library       |
| 🔑 `keywords` | Display common search keywords |
| 📚 `list`     | Display the full query library |
| 🚪 `exit`     | Exit the application           |

## 🔍 Search by Keyword

You can also search directly by typing security-related keywords such as:

```text
⚡ powershell
🔐 ssh
🖥️ rdp
🔨 brute force
🌐 dns
💉 sql
🦠 ransomware
🎣 phishing
↔️ lateral movement
```

The assistant searches its detection library and returns relevant **Splunk SPL queries** along with security context and associated **MITRE ATT&CK techniques**.

## 🎯 Project Purpose

This project is designed to demonstrate practical **SOC Analyst**, **SIEM**, and **threat detection** skills, including:

* 🔎 Security event investigation
* 📊 Splunk SPL query development
* 🛡️ Threat detection
* 🧠 MITRE ATT&CK mapping
* 🚨 Incident investigation
* 📋 SOC workflow automation
* 🐍 Python development

## 🛡️ Security Focus

**Splunk • SIEM • SOC Analysis • MITRE ATT&CK • Threat Detection • Incident Investigation • Python**


