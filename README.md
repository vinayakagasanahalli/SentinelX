# 🛡️ SentinelX — Autonomous SIEM Log Engine & AI Threat Triage Platform

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)
![Groq AI](https://img.shields.io/badge/AI-Groq%20%2F%20LLM%20Triage-F34B7D)

> **SentinelX** is an enterprise-grade Security Information & Event Management (SIEM) log collection engine, real-time threat detector, AI incident triage assistant, and automated response platform.

---

## ✨ Features

- 📥 **Real-Time Syslog & Log Ingestion Pipeline**: REST API endpoint (`/api/v1/logs/ingest`) receiving auth logs, API gateways, web requests, and server events.
- ⚡ **Rule-Based Threat Detection Engine**: Instantly flags:
  - 💥 SQL Injection (SQLi) attacks
  - 🔓 Brute-Force Credential Stuffing (rate & failure thresholding)
  - 📜 Cross-Site Scripting (XSS) payload injection
  - 📂 Path Traversal & Unauthorized Access attempts
  - ☣️ Ransomware / Malicious Bulk File Encryption
- 🧠 **AI Threat Triage Engine (Groq / Built-in LLM)**: Automatically evaluates raw log traces, assigns CVSS-style risk scores (1-10), generates MITRE ATT&CK explanations, and provides actionable mitigation steps.
- 🤖 **Automated Incident Response Playbooks**: Automatically blocks malicious source IPs on the firewall, revokes compromised OAuth tokens, and logs audit traces.
- 🖥️ **Cyber SOC Dashboard**: Dark glassmorphism dashboard featuring real-time metric counters, attack simulator, incident timeline feed, and firewall block manager.

---

## 🏗️ Architecture

```
                       ┌─────────────────────────┐
                       │  Security Log Ingestor  │
                       │   (REST / Syslog API)   │
                       └────────────┬────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │ Threat Detection Engine │
                       │  (SQLi, XSS, Brute-F)   │
                       └────────────┬────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
      ┌──────────────────────┐             ┌──────────────────────┐
      │   AI Triage Engine   │             │ Automated Response   │
      │(Groq LLM / AI Engine)│             │ (Firewall IP Block)  │
      └───────────┬──────────┘             └──────────┬───────────┘
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    │
                                    ▼
                       ┌─────────────────────────┐
                       │   Cyber SOC Dashboard   │
                       │   (Glassmorphism UI)    │
                       └─────────────────────────┘
```

---

## ⚡ Quick Start

### Option 1: Run Locally with Python

```bash
# Clone the repository
git clone https://github.com/vinayakagasanahalli/SentinelX.git
cd SentinelX

# Install dependencies
pip install -r backend/requirements.txt

# Start the server
python -m uvicorn backend.main:app --reload --port 8000
```

Open your browser and navigate to **`http://localhost:8000`** to access the live SOC dashboard!

---

### Option 2: Run with Docker Compose

```bash
docker-compose up --build
```

---

## 🔌 API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/health` | `GET` | Health check & system version |
| `/api/v1/stats` | `GET` | Live dashboard metrics (Total Logs, Incidents, Blocked IPs) |
| `/api/v1/logs/ingest` | `POST` | Ingest raw log payload for threat analysis |
| `/api/v1/incidents` | `GET` | List all flagged security incidents |
| `/api/v1/incidents/{id}/remediate` | `POST` | Execute manual incident response playbook |
| `/api/v1/blocked-ips` | `GET` | List active firewall blocked IP addresses |
| `/api/v1/simulate-attack` | `POST` | Trigger test attack (SQLi, Brute Force, XSS, Ransomware) |

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
