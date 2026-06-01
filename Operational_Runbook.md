# Operational Runbook: Secure File Exchange Portal

**Version:** 2.0  
**Linked Documents:** Threat Model, Security Testing

---

## Overview

This runbook defines how an on-call engineer detects, responds to, and recovers from security incidents and operational failures in the Secure File Exchange Portal. Every incident follows a strict three-phase structure:

- **Detection** - How to identify the incident using monitoring, alerting, and log analysis
- **Response** - Immediate containment actions to stop the attack or failure
- **Recovery** - Steps to restore service integrity and verify normal operation

---

## Incident 1: IDOR Brute-Force Attack

**Threat Model Reference:** T-1 - Broken Access Control / IDOR  
**Severity:** Critical  
**Signal:** Spike in Failed Downloads panel in Grafana or Discord alert firing in `🚨-security-alerts`  

---

### Detection

**Automated Alerting:**
- Monitor Discord channel `🚨-security-alerts` for real-time Grafana alert notifications
- Grafana dashboard → **Failed Downloads** panel - red threshold fires at 10+ failed attempts within 5 minutes

**Log Analysis - identify malicious IPs and failed attempts:**
```bash
sudo cat $(docker inspect --format='{{.LogPath}}' sfep_api) | grep -E "failed_download|404"
```

**Forensic Check - identify compromised tokens and successful downloads:**
```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT event, detail, ts FROM audit_log WHERE event='successful_download' ORDER BY ts DESC LIMIT 10\").fetchall()
for r in rows: print(r)
"
```

**Confirm file exposure for a specific token:**
```bash
curl -si http://localhost:8000/download/TOKEN
```

---

### Response

**Step 1 - Revoke the compromised token immediately:**
```bash
curl -s -X POST http://localhost:8000/revoke/TOKEN \
  -H "x-api-token: supersecret-mock-token" | python3 -m json.tool
```

**Step 2 - Block the source IP at application level:**
```bash
curl -s -X POST http://localhost:8000/block/ATTACKER_IP \
  -H "x-api-token: supersecret-mock-token"
```

**Step 3 - Confirm the IP is in the blacklist:**
```bash
curl -s http://localhost:8000/blocked \
  -H "x-api-token: supersecret-mock-token" | python3 -m json.tool
```

**Step 4 - If service is down, restart the container:**
```bash
docker restart sfep_api
```

---

### Recovery

**Step 1 - Verify the compromised token is now blocked:**
```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
  http://localhost:8000/download/TOKEN
# Expected: HTTP Status: 410
```

**Step 2 - Confirm service health:**
```bash
curl -s http://localhost:8000/health
# Expected: {"status": "ok", "version": "0.1.0"}
```

**Step 3 - Restart container if it was stopped:**
```bash
docker compose start api
```

**Step 4 - Long-term fix: add authentication to download endpoint in `app/main.py`:**
```python
# BEFORE (vulnerable)
@app.get("/download/{token}")
def download_file(token: str):

# AFTER (fixed)
@app.get("/download/{token}")
def download_file(token: str, _auth: str = Depends(require_auth)):
```

---

## Incident 2: API Token Brute-Force

**Threat Model Reference:** T-2 - Hardcoded API Token  
**Severity:** High  
**Signal:** Spike in Unauthorized Requests (401) panel in Grafana - red threshold at 5+  

---

### Detection

**Automated Alerting:**
- Grafana dashboard → **Unauthorized Requests (401)** panel spike
- Discord channel `🚨-security-alerts` notification if alert rule is configured

**Log Analysis - identify brute-force attempts:**
```bash
docker logs sfep_api 2>&1 | grep "unauthorized_request" | tail -20
```

**Audit log query:**
```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT COUNT(*) as count, MAX(ts) as last_seen FROM audit_log WHERE event='unauthorized_request'\").fetchone()
print(f'Unauthorized attempts: {rows[0]}, Last seen: {rows[1]}')
"
```

**Verify current token configuration:**
```bash
docker exec sfep_api env | grep API_TOKEN
```

---

### Response

**Step 1 - Rotate the API token immediately:**
```bash
# Edit docker-compose.yml - change API_TOKEN to a new value
# Then force-recreate the container
docker compose up -d --force-recreate api
```

**Step 2 - Block the source IP if identified:**
```bash
curl -s -X POST http://localhost:8000/block/ATTACKER_IP \
  -H "x-api-token: NEW_TOKEN"
```

---

### Recovery

**Step 1 - Verify new token is enforced:**
```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
  -X POST http://localhost:8000/upload \
  -H "x-api-token: old-token" \
  -F "file=@/tmp/test.txt"
# Expected: HTTP Status: 401
```

**Step 2 - Verify legitimate access works with new token:**
```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
  -X POST http://localhost:8000/upload \
  -H "x-api-token: NEW_TOKEN" \
  -F "file=@/tmp/test.txt"
# Expected: HTTP Status: 200
```

**Step 3 - Long-term fix: migrate token to `.env` file:**
```bash
# Create .env file
echo "API_TOKEN=new-secure-random-token" > .env
echo ".env" >> .gitignore

# Verify token is not exposed in git history
git log --all --full-history -- docker-compose.yml | head -5
```

---

## Incident 3: Malicious File Upload  

**Threat Model Reference:** T-3 - Unrestricted File Upload  
**Severity:** High  
**Signal:** Any row in Grafana **Suspicious Uploads** table or failed CI/CD security test

---

### Detection

**Grafana Dashboard:**
- **Suspicious Uploads** table - displays filenames with `.php`, `.sh`, `.exe` extensions uploaded in real time

**Log Analysis - identify malicious uploads:**
```bash
sudo cat $(docker inspect --format='{{.LogPath}}' sfep_api) | grep -E "\.php|\.sh|\.exe"
```

**Audit log query:**
```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT detail, ts FROM audit_log WHERE event='upload_created' AND (detail LIKE '%.php%' OR detail LIKE '%.sh%' OR detail LIKE '%.exe%') ORDER BY ts DESC\").fetchall()
for r in rows: print(r)
"
```

**Find malicious files on disk:**
```bash
docker exec sfep_api find /data/files -name "*.php" -o -name "*.sh" -o -name "*.exe"
```

---

### Response

**Step 1 - Revoke all download links for malicious files:**
```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT token FROM links WHERE revoked=0\").fetchall()
for r in rows: print(r[0])
" | while read token; do
  curl -s -X POST http://localhost:8000/revoke/$token \
    -H "x-api-token: supersecret-mock-token"
done
```

**Step 2 - Delete malicious files from disk:**
```bash
docker exec sfep_api find /data/files -name "*.php" -delete
docker exec sfep_api find /data/files -name "*.sh" -delete
docker exec sfep_api find /data/files -name "*.exe" -delete
```

**Step 3 - Block attacker IP if identified:**
```bash
curl -s -X POST http://localhost:8000/block/ATTACKER_IP \
  -H "x-api-token: supersecret-mock-token"
```

---

### Recovery

**Step 1 - Verify malicious files are removed:**
```bash
docker exec sfep_api find /data/files -name "*.php" -o -name "*.sh" -o -name "*.exe"
# Expected: no output
```

**Step 2 - Verify file type validation is active:**
```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
  -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/shell.php"
# Expected: HTTP Status: 422
```

**Step 3 - Run full test suite:**
```bash
./automate_tests.sh
```

---

## Incident 4: Service Unavailable / Health Check Failure

**Severity:** Critical  
**Signal:** `GET /health` returns non-200 or connection refused

---

### Detection

**Direct health check:**
```bash
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:8000/health
# Incident confirmed if not: HTTP Status: 200
```

**Check container status:**
```bash
docker compose ps
docker compose logs api | tail -30
```

**Check for OOM kill:**
```bash
docker inspect sfep_api | grep -i oom
dmesg | grep -i "killed process" | tail -5
```

---

### Response

**Step 1 - Restart the container:**
```bash
docker compose down
docker compose up -d
```

**Step 2 - If startup fails, check volume permissions:**
```bash
sudo ls -la /var/lib/docker/volumes/sfep_db/
sudo ls -la /var/lib/docker/volumes/sfep_files/
```

**Step 3 - Check for disk exhaustion:**
```bash
df -h /var/lib/docker/volumes/
```

---

### Recovery

**Step 1 - Verify service is restored:**
```bash
curl -s http://localhost:8000/health
# Expected: {"status": "ok", "version": "0.1.0"}
```

**Step 2 - If container repeatedly fails, rebuild from scratch:**
```bash
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

**Step 3 - Run full test suite to confirm all endpoints operational:**
```bash
./automate_tests.sh
```
