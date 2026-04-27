# Operational Runbook: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** Threat Model, Security Testing

---

## Overview

This runbook defines how an on-call engineer responds when automated security or functional tests fail. Each section follows the structure: **Investigate → Mitigate → Recover**.

Run tests first:
```bash
chmod +x automate_tests.sh
./automate_tests.sh
```

---

## Incident 1 - SEC-IDOR-001 FAIL: Unauthenticated Download Returns 200

**Test failure signal:**
```
[FAIL] SEC-IDOR-001: /download/{token} returned 200 with NO auth header — VULNERABILITY CONFIRMED
```

**Threat Model Reference:** T-1: Broken Access Control / IDOR

### Investigate

```bash
# Check how many unauthenticated downloads occurred
docker logs sfep_api 2>&1 | grep "successful_download" | tail -20

# Check for enumeration pattern - many failed_download in short time
docker logs sfep_api 2>&1 | grep "failed_download" | tail -50

# Query SQLite directly for recent download activity
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT event, detail, ts FROM audit_log WHERE event IN ('successful_download','failed_download') ORDER BY ts DESC LIMIT 20\").fetchall()
for r in rows: print(r)
"
```

Check Grafana dashboard at `http://localhost:3000`:
- **Failed Downloads:** If this panel shows a massive spike, an attacker is actively brute-forcing the `/download/` endpoint with invalid tokens.
- **Successful Downloads:** Cross-reference this panel with expected user activity. If one specific token is downloaded hundreds of times within minutes, the file has been compromised.

### Mitigate

```bash
# Revoke all active tokens immediately
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
tokens = conn.execute(\"SELECT token FROM links WHERE revoked=0\").fetchall()
for t in tokens: print(t[0])
" | while read token; do
  curl -s -X POST http://localhost:8000/revoke/$token \
    -H "x-api-token: supersecret-mock-token"
done

# If attack is ongoing - stop the container
docker compose stop api

# Restart after mitigation
docker compose start api
```

### Recover

Add authentication to the download endpoint in `app/main.py`:

```python
# BEFORE (vulnerable)
@app.get("/download/{token}")
def download_file(token: str):

# AFTER (fixed)
@app.get("/download/{token}")
def download_file(token: str, _auth: str = Depends(require_auth)):
```

Add rate limiting - install `slowapi`:
```bash
pip install slowapi
```

Rebuild and restart:
```bash
docker compose build --no-cache
docker compose up -d
./automate_tests.sh  # confirm PASS
```

---

## Incident 2 - SEC-AUTH-001 FAIL: Upload Without Token Returns Non-401

**Test failure signal:**
```
[FAIL] SEC-AUTH-001: POST /upload without token returned 200 (expected 401)
```

**Threat Model Reference:** T-2: Hardcoded API Token

### Investigate

```bash
# Check for unauthorized_request events
docker logs sfep_api 2>&1 | grep "unauthorized_request" | tail -20

# Check if API_TOKEN env var is set correctly
docker exec sfep_api env | grep API_TOKEN

# Verify require_auth is applied to upload endpoint
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT * FROM audit_log WHERE event='unauthorized_request' ORDER BY ts DESC LIMIT 10\").fetchall()
for r in rows: print(r)
"
```

### Mitigate

```bash
# Rotate the API token immediately
# Edit docker-compose.yml: API_TOKEN → new value
# Then restart
docker compose up -d --force-recreate api
```

### Recover

Move token out of `docker-compose.yml` into Docker Secrets.

```bash
# Verify token is not in git history
git log --all --full-history -- docker-compose.yml | head -5
```

---

## Incident 3 - SEC-UPLOAD-001 FAIL: PHP Webshell Accepted

**Test failure signal:**
```
[FAIL] SEC-UPLOAD-001: PHP webshell accepted with HTTP 200 — no file type validation
```

**Threat Model Reference:** T-3: Unrestricted File Upload

### Investigate

```bash
# Find all suspicious files on disk
docker exec sfep_api find /data/files -name "*.php" -o -name "*.sh" -o -name "*.exe"

# Check audit log for malicious uploads
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT detail, ts FROM audit_log WHERE event='upload_created' AND (detail LIKE '%.php%' OR detail LIKE '%.sh%' OR detail LIKE '%.exe%') ORDER BY ts DESC\").fetchall()
for r in rows: print(r)
"
```

Check Grafana dashboard at `http://localhost:3000`:
- **Suspicious Uploads:** Examine the entries in this table to identify any unauthorized file types. The table displays the exact filenames and extensions of all uploads.
### Mitigate

```bash
# Revoke all download links for suspicious files
# Get file_id from audit log detail field, then find its token
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT token FROM links WHERE revoked=0\").fetchall()
for r in rows: print(r[0])
" | while read token; do
  curl -s -X POST http://localhost:8000/revoke/$token \
    -H "x-api-token: supersecret-mock-token"
done

# Remove malicious files from disk
docker exec sfep_api find /data/files -name "*.php" -delete
docker exec sfep_api find /data/files -name "*.sh" -delete
docker exec sfep_api find /data/files -name "*.exe" -delete
```

### Recover

Add MIME-type validation to `app/main.py`. Install `python-magic`:

```bash
pip install python-magic
```

Add to `upload_file()` in `main.py`:

```python
import magic

ALLOWED_MIME_TYPES = ["text/plain", "application/pdf", "image/png", "image/jpeg"]

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), _auth: str = Depends(require_auth)):
    contents = await file.read()
    mime = magic.from_buffer(contents[:512], mime=True)
    if mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=422, detail=f"File type not allowed: {mime}")
    ...
```

Rebuild and retest:
```bash
docker compose build --no-cache
docker compose up -d
./automate_tests.sh
```

---

## Incident 4 - Functional Test FAIL: Health Check Returns Non-200

**Test failure signal:**
```
[FAIL] GET /health returned 000 (expected 200)
```

### Investigate

```bash
docker compose ps          # check container status
docker compose logs api    # check startup errors
docker inspect sfep_api    # check container state
```

### Mitigate

```bash
docker compose down
docker compose up -d
```

### Recover

If container fails to start repeatedly - check volume permissions:
```bash
sudo ls -la /var/lib/docker/volumes/sfep_db/
sudo ls -la /var/lib/docker/volumes/sfep_files/
```

Rebuild from scratch if needed:
```bash
docker compose down -v
docker compose build --no-cache
docker compose up -d
```
