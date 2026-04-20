# Secure File Exchange Portal

API-first service for temporary file sharing. A user uploads a file, creates a time-limited download link, and a recipient uses that link to retrieve the file before it expires.

## Stack

- **Backend:** Python / FastAPI  
- **Database:** SQLite  
- **Deployment:** Docker Compose

## Project Files

| File | Description |
|------|-------------|
| [`app/main.py`](app/main.py) | FastAPI application |
| [`app/Dockerfile`](app/Dockerfile) | Container definition |
| [`docker-compose.yml`](docker-compose.yml) | Service configuration |
| [`Threat_Model.md`](Threat_Model.md) | STRIDE threat analysis |
| [`Security_Testing.md`](Security_Testing.md) | Test cases |
| [`OE_Dashboard.md`](OE_Dashboard.md) | Grafana OE Dashboard |
