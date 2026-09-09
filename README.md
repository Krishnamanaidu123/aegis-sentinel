# 🛡️ Aegis Sentinel

**AI‑Powered SOC Log Analyzer** – Automate threat detection, MITRE ATT&CK mapping, and response recommendations using Google Gemini.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.25-ff4b4b.svg)](https://streamlit.io/)
[![Flask](https://img.shields.io/badge/Flask-2.3-black)](https://flask.palletsprojects.com/)

---

## 📖 Overview

Aegis Sentinel is a **production‑ready security log analysis pipeline** that:

- Ingests logs from any source (syslog, CloudTrail, Windows Event Log, JSON, …).
- Uses **Google Gemini** (LLM) to detect suspicious activity with natural‑language explanations.
- Maps threats to the **MITRE ATT&CK® framework** (technique IDs, tactics, and descriptions).
- Recommends concrete **SOC response actions** (containment, eradication, recovery).
- Stores all alerts in a database for post‑analysis.
- Provides a **Streamlit dashboard** for real‑time log submission and historical review.

It bridges the gap between raw logs and actionable intelligence, reducing Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR).

---

## ✨ Features

- ✅ **AI‑Driven Analysis** – Leverages Gemini 1.5 Pro for anomaly detection, threat explanation, and response generation.
- ✅ **MITRE ATT&CK Enrichment** – Automatically maps techniques to tactics with human‑readable names.
- ✅ **Multi‑Format Log Ingestion** – Supports raw syslog lines and structured JSON (CloudTrail, etc.).
- ✅ **Persistent Storage** – SQLite (or PostgreSQL) stores every alert with full context.
- ✅ **Interactive Dashboard** – Submit logs, view AI verdicts, explore MITRE mapping, and browse alert history.
- ✅ **Dockerised** – Run the API and dashboard together with Docker Compose.
- ✅ **Extensible** – Easily add new log parsers, modify Gemini prompts, or connect to SIEMs.

---

## 🧱 Architecture

```text
┌─────────────────┐
│   Log Source    │
│ (Syslog / JSON) │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│              Flask API (app.py)             │
│  - Parses log (syslog or JSON)             │
│  - Calls Gemini via gemini_analyzer.py     │
│  - Enriches with MITRE (mitre_mapper.py)   │
│  - Saves to database (SQLAlchemy)          │
│  - Returns JSON result                      │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│        Google Gemini 1.5 Pro (LLM)         │
│  - Detects suspicious activity             │
│  - Generates explanation, MITRE IDs,       │
│    and recommended response                │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│        MITRE ATT&CK Local Cache            │
│        (mitre_attack.json)                 │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│     SQLite / PostgreSQL Database           │
│     (alerts table)                         │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│      Streamlit Dashboard                    │
│  - Log submission form                     │
│  - Real‑time analysis display              │
│  - Alert history with search/filter        │
└─────────────────────────────────────────────┘
🚀 Getting Started
Prerequisites
Python 3.9+

A Google Gemini API key (free tier available)

Docker (optional, for containerised deployment)

1. Clone the Repository
bash
git clone https://github.com/yourusername/aegis-sentinel.git
cd aegis-sentinel
2. Set Up Environment
Create a .env file in the project root:

env
GEMINI_API_KEY=your_google_gemini_api_key_here
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///aegis.db
3. Install Dependencies (Local)
bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
4. Run the Application
Terminal 1 – Flask API

bash
python app.py
Terminal 2 – Streamlit Dashboard

bash
streamlit run streamlit_app.py
Open your browser to http://localhost:8501 to access the dashboard.

5. (Optional) Run with Docker
bash
docker-compose up --build
This starts both the API (port 5000) and the Streamlit dashboard (port 8501) in separate containers.

🧪 Usage
Via the Dashboard
Select log format (Syslog raw or JSON).

Paste your log line into the text area.

Click Analyze.

View the AI verdict, MITRE mapping, and recommended response.

Check the Alert History tab to see all past analyses.

Via API (cURL)
bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"raw": "Oct 11 22:14:15 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.100"}'
Example response:

json
{
  "log": {
    "timestamp": "Oct 11 22:14:15",
    "source_ip": "192.168.1.100",
    "user": "admin",
    "event_type": "authentication_failure",
    "raw": "Oct 11 22:14:15 ..."
  },
  "analysis": {
    "suspicious": true,
    "confidence": 92,
    "explanation": "Repeated failed login attempts from a single IP indicate a brute force attack.",
    "mitre_ids": ["T1110"],
    "mitre_details": [
      {
        "id": "T1110",
        "tactic": "Credential Access",
        "technique": "Brute Force"
      }
    ],
    "response": "Block the source IP at the firewall, reset affected user credentials, and enable MFA."
  },
  "alert_id": 42
}
API Endpoints
Endpoint	Method	Description
/health	GET	Health check.
/analyze	POST	Submit a log and get an AI analysis.
/alerts	GET	Retrieve the last 100 alerts.
/alerts/<id>	GET	Get full details of a specific alert by ID.
🗺️ MITRE ATT&CK Integration
Aegis Sentinel includes a local MITRE ATT&CK cache (mitre_attack.json) pre‑populated with the most common enterprise techniques. When Gemini returns one or more technique IDs, the system enriches them with:

Tactic (e.g., Credential Access)

Technique Name (e.g., Brute Force)

This makes the output immediately understandable to SOC analysts. You can extend the cache by adding more techniques from the official MITRE CTI repository.

📁 Project Structure
text
aegis-sentinel/
├── .env                    # Environment variables (API keys, DB URL)
├── .gitignore
├── Dockerfile              # Docker image for the Flask API
├── docker-compose.yml      # Orchestrates API + Streamlit
├── requirements.txt        # Python dependencies
├── config.py               # Loads configuration from .env
├── log_parser.py           # Converts raw logs into structured JSON
├── gemini_analyzer.py      # Sends logs to Gemini and parses responses
├── mitre_mapper.py         # Enriches MITRE IDs with tactic/technique names
├── mitre_attack.json       # Local MITRE ATT&CK cache (auto‑generated if missing)
├── app.py                  # Flask API (endpoints, DB, orchestration)
├── streamlit_app.py        # Interactive dashboard
└── aegis.db                # SQLite database (auto‑created)
🔧 Configuration
The .env file controls:

Variable	Description	Default
GEMINI_API_KEY	Your Google Gemini API key. Required.	(none)
LOG_LEVEL	Logging level (DEBUG, INFO, WARNING, ERROR)	INFO
DATABASE_URL	Database connection string.	sqlite:///aegis.db
For PostgreSQL, use: postgresql://user:password@host:port/dbname

🤝 Contributing
Contributions are welcome! Here’s how you can help:

Fork the repository.

Create a feature branch (git checkout -b feature/amazing-feature).

Commit your changes (git commit -m 'Add some amazing feature').

Push to the branch (git push origin feature/amazing-feature).

Open a Pull Request.

Please ensure your code is well‑documented and passes basic tests.

📄 License
Distributed under the MIT License. See LICENSE for more information.

🙏 Acknowledgements
Google Gemini for the powerful LLM API.

MITRE ATT&CK® for the industry‑standard knowledge base.

Streamlit for the beautiful dashboard framework.

Flask for the lightweight API backend.

📬 Contact
Project Link: https://github.com/yourusername/aegis-sentinel

For questions or suggestions, please open an issue on GitHub.

Built with ❤️ for the SOC community.
