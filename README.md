# Secure File Exchange Portal
 
API-first service for temporary file sharing. A user uploads a file, creates a time-limited download link, and a recipient uses that link to retrieve the file before it expires. The project demonstrates STRIDE threat modeling, security testing, compliance analysis, and live incident simulation with automated alerting via Grafana and Discord.
 
---
 
## Stack
 
| Layer | Technology |
|-------|------------|
| Backend | Python 3.12 / FastAPI |
| Database | SQLite |
| Monitoring | Grafana |
| Deployment | Docker Compose |
| CI/CD | GitHub Actions |
 
---
 
## Quick Start
 
```bash
# Clone the repository
git clone https://github.com/sherkhanz/secure-file-exchange-portal.git
cd secure-file-exchange-portal
 
# Configure environment
cp .env.example .env
# Edit .env and set API_TOKEN
 
# Start all services
docker compose up -d
 
# Verify
curl http://localhost:8000/health
# → {"status": "ok", "version": "0.1.0"}
 
# Import OE Dashboard into Grafana at http://localhost:3000
# Dashboard → Import → upload dashboard/OE_Dashboard.json
```
 
---
 
## API Endpoints
 
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/upload` | Upload a file |
| POST | `/links` | Create a download link |
| GET | `/download/{token}` | Download a file |
| POST | `/revoke/{token}` | Revoke a download link |
| POST | `/block/{ip}` | Block an IP address |
| POST | `/unblock/{ip}` | Unblock an IP address |
  
---
 
## Documentation
 
| Document | Description |
|----------|-------------|
| [Threat Modeling](docs/Threat_Modeling.md) | STRIDE threat analysis |
| [Security Testing](docs/Security_Testing.md) | Security test cases and results |
| [Compliance Audit](docs/Compliance_Audit.md) | FTC, GDPR, NIST CSF 2.0 compliance audit |
| [Incident Runbook](docs/Incident_Runbook.md) | Incident detection, response, and recovery procedures |
| [Simulated Incident](docs/Simulated_Incident.md) | IDOR brute-force attack simulation and walkthrough |
| [OE Dashboard](docs/OE_Dashboard.md) | Grafana dashboard documentation |
 
---
 
## Demo Videos
 
| Phase | Recording |
|-------|-----------|
| Attack Simulation | [Watch on YouTube](https://www.youtube.com/watch?v=dxSZ-suSpBw) |
| Defensive Response | [Watch on YouTube](https://www.youtube.com/watch?v=c7CGrKayAS4) |
