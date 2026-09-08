SentinelSOC

Real-Time Security Event Detection & SOC Monitoring Platform
SentinelSOC is a full-stack SOC monitoring platform that collects security events, detects common cyber threats, calculates risk scores, and displays security alerts through a web dashboard.


Key Features

- REST API for security event ingestion
- PostgreSQL storage for security events and alerts
- Rule-based threat detection
- Brute-force attack detection
- SQL injection detection
- Cross-Site Scripting (XSS) detection
- Port scan detection
- Risk scoring from 0–100
- Alert severity classification
- Alert status management
- React-based SOC dashboard



Architecture

Security Events
      |
      v
   FastAPI
      |
      v
 PostgreSQL
      |
      v
Detection Engine
      |
      +-- Brute Force
      +-- SQL Injection
      +-- XSS
      +-- Port Scan
      |
      v
 Risk Scoring
   (0–100)
      |
      v
Alert Management
      |
      v
 React Dashboard


Threat Detection

- Brute Force = 5+ failed logins from the same IP within 60 seconds
- SQL Injection = Detection of common SQL injection patterns
- XSS = Detection of common XSS payload indicators
- Port Scan = 10+ unique destination ports from the same IP within 60 seconds


Risk Scoring 

Risk scores range from 0–100 and determine alert severity.
- 0–29 = LOW
- 30–59 = MEDIUM
- 60–79 = HIGH
- 80–100 = CRITICAL
Brute-force risk increases based on attack frequency and privileged usernames.


Tech Stack

- Backend: Python, FastAPI, SQLAlchemy, Pydantic, Uvicorn
- Database: PostgreSQL, SQL Indexing
- Frontend: React, TypeScript, Vite, Recharts, Lucide React
- Tools: Git, GitHub, REST API



Project Structure

SentinelSOC/
│
├── backend/
│   ├── app/
│   │   ├── detection/
│   │   │   ├── __init__.py
│   │   │   └── rules.py
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   └── risk_scoring.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── api.ts
│   │   ├── components/
│   │   │   ├── AlertTable.tsx
│   │   │   └── StatCard.tsx
│   │   ├── App.tsx
│   │   └── index.css
│   └── package.json
│
├── .gitignore
└── README.md



API Endpoints

- POST -> /events - Submit a security event
- GET -> /events - Retrieve security events
- GET -> /alerts - Retrieve security alerts
- PATCH -> /alerts/{alert_id} - Update alert status
- GET -> /dashboard/stats - Retrieve dashboard statistics



API Documentation

FastAPI Swagger documentation:
http://127.0.0.1:8000/docs



Setup

Prerequisites:
- Python 3.11+
- PostgreSQL
- Node.js and npm
- Git



Backend

- Clone the repository:
git clone https://github.com/YOUR_USERNAME/SentinelSOC.git
cd SentinelSOC
- Create and activate a virtual environment:
python -m venv venv
- Windows PowerShell:
.\venv\Scripts\Activate.ps1
- Install dependencies:
pip install -r backend/requirements.txt
- Create a .env file in the project root:
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/sentinelsoc
- Create the PostgreSQL database:
CREATE DATABASE sentinelsoc;
- Start the backend:
uvicorn backend.app.main:app --reload



Frontend

- Open another terminal:
cd frontend
npm install
npm run dev
- Create frontend/.env:
VITE_API_URL=http://127.0.0.1:8000



Future Improvements

- WebSocket-based real-time alerts
- Redis/Kafka event pipeline
- Machine-learning anomaly detection
- Authentication and role-based access control
- MITRE ATT&CK mapping
- Docker and cloud deployment
- CI/CD pipeline

Disclaimer

SentinelSOC is an educational cybersecurity project demonstrating SOC monitoring and threat detection concepts. It is not intended to replace production-grade SIEM or security monitoring solutions.
