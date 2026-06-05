# Security Testing: Secure File Exchange Portal

## 1. Scope and Objectives

This document records the practical security test execution performed against the Secure File Exchange Portal. Each test case directly targets a vulnerability identified in the Threat Model and provides reproducible attack steps, observed terminal output, and mapped remediation. All tests were executed locally against `http://localhost:8000` with the container running via `docker compose up -d`.

---

## 2. Test Environment Setup

```bash
# Start the container stack
docker compose up -d

# Seed baseline test data - upload a sensitive file and create a download link
echo "CONFIDENTIAL: Salary data Q1 2026" > /tmp/sensitive.txt

export FILE_ID=$(curl -s -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/sensitive.txt" | python3 -c "import sys,json; print(json.load(sys.stdin)['file_id'])")

export TOKEN=$(curl -s -X POST http://localhost:8000/links \
  -H "x-api-token: supersecret-mock-token" \
  -H "Content-Type: application/json" \
  -d "{\"file_id\": \"$FILE_ID\", \"expires_in_minutes\": 120}" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "FILE_ID: $FILE_ID"
echo "TOKEN:   $TOKEN"
```

---

## 3. Security Test Cases

---

### SEC-IDOR-001 - Unauthenticated File Download via Known Token

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-IDOR-001 |
| **Threat Ref** | T-1 - Broken Access Control / IDOR |
| **STRIDE Category** | Elevation of Privilege |
| **OWASP API** | API1:2023 - Broken Object Level Authorization |
| **NIST CSF** | Protect (PR.AC) - Access Control |
| **Severity** | Critical |
| **Status** | Remediated |

**Objective:** Verify that `/download/{token}` requires authentication and returns 401 to unauthenticated callers.

**Attack Steps:**

```bash
# Step 1: Confirm TOKEN is set from environment setup above
echo $TOKEN

# Step 2: Attempt download with zero authentication
curl -si http://localhost:8000/download/$TOKEN
```

**Observed Terminal Output:**

```
HTTP/1.1 401 Unauthorized
content-length: 42
content-type: application/json

{"detail":"Missing or invalid API token."}
```

**Analysis:** The server returns HTTP 401. `Depends(require_auth)` is now applied to `GET /download/{token}`. Unauthenticated callers receive no file content.

**Pass Criteria:** HTTP 401 without authentication - **PASS**.

**Code Reference:**

```python
# main.py - Depends(require_auth) added to endpoint
@app.get("/download/{token}")
@limiter.limit("5/minute")
def download_file(request: Request, token: str, _auth: str = Depends(require_auth)):
    ...
```

---

### SEC-IDOR-002 - UUID Token Enumeration via `ffuf`

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-IDOR-002 |
| **Threat Ref** | T-1 - IDOR / Token Enumeration |
| **STRIDE Category** | Elevation of Privilege |
| **OWASP API** | API4:2023 - Unrestricted Resource Consumption |
| **NIST CSF** | Detect (DE.CM) - Continuous Monitoring |
| **Severity** | High |
| **Status** | Remediated |

**Objective:** Verify that rate limiting on `/download` returns HTTP 429 after 5 requests per minute per IP, making automated token enumeration impractical.

**Attack Steps:**

```bash
# Step 1: Generate a UUID wordlist
python3 -c "
import uuid
with open('/tmp/uuid_wordlist.txt', 'w') as f:
    f.write('$TOKEN\n')
    for _ in range(500):
        f.write(str(uuid.uuid4()) + '\n')
"

# Step 2: Run ffuf - now expects 429 responses after threshold
ffuf -u http://localhost:8000/download/FUZZ \
     -w /tmp/uuid_wordlist.txt \
     -H "x-api-token: supersecret-mock-token" \
     -mc 200,429 \
     -v \
     -t 10
```

**Observed Terminal Output:**

```
[Status: 429, Size: 35, Words: 3, Lines: 2, Duration: 12ms]
| URL | http://localhost:8000/download/FUZZ
:: Progress: [501/501] :: Job [1/1] :: 549 req/sec :: Errors: 0 ::
```

**Analysis:** Rate limiting via `slowapi` returns HTTP 429 after 5 requests per minute per IP. Enumeration at scale is blocked.

**Pass Criteria:** HTTP 429 responses after threshold - **PASS**.

---

### SEC-AUTH-001 - API Token Exposed in Plaintext Configuration

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-AUTH-001 |
| **Threat Ref** | T-2 - Static Hardcoded API Token |
| **STRIDE Category** | Spoofing |
| **OWASP API** | API8:2023 - Security Misconfiguration |
| **NIST CSF** | Protect (PR.DS) - Data Security |
| **Severity** | High |
| **Status** | Remediated |

**Objective:** Verify that `API_TOKEN` is absent from `docker-compose.yml` and loaded from `.env` which is excluded from version control.

**Attack Steps:**

```bash
# Step 1: Confirm token is absent from docker-compose.yml
grep API_TOKEN docker-compose.yml

# Step 2: Confirm .env exists and is in .gitignore
cat .env
grep ".env" .gitignore

# Step 3: Confirm container reads token from environment
docker exec sfep_api env | grep API_TOKEN
```

**Observed Terminal Output:**

```
# Step 1 - no output, token absent from docker-compose.yml

# Step 2
API_TOKEN=supersecret-mock-token
.env

# Step 3
API_TOKEN=supersecret-mock-token
```

**Analysis:** `API_TOKEN` is no longer committed to version control. Token is loaded from `.env` via `python-dotenv`. `.env` is listed in `.gitignore`.

**Pass Criteria:** Token absent from `docker-compose.yml`, present in `.env`, `.env` in `.gitignore` - **PASS**.

---

### SEC-AUTH-002 - Rate Limiting on Upload Endpoint

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-AUTH-002 |
| **Threat Ref** | T-1, T-3 - Rate Limiting |
| **STRIDE Category** | Elevation of Privilege / Tampering |
| **OWASP API** | API4:2023 - Unrestricted Resource Consumption |
| **NIST CSF** | Protect (PR.AC)** - Access Control |
| **Severity** | High |
| **Status** | Remediated |

**Objective:** Verify that `/upload` returns HTTP 429 after 5 requests per minute per IP.

**Attack Steps:**

```bash
# Send 6 consecutive upload requests - 6th should return 429
for i in {1..6}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:8000/upload \
    -H "x-api-token: supersecret-mock-token" \
    -F "file=@/tmp/sensitive.txt")
  echo "Request $i: $CODE"
done
```

**Observed Terminal Output:**

```
Request 1: 200
Request 2: 200
Request 3: 200
Request 4: 200
Request 5: 200
Request 6: 429
```

**Analysis:** `slowapi` rate limiting returns HTTP 429 on the 6th request within a one-minute window per IP.

**Pass Criteria:** HTTP 429 on 6th request - **PASS**.

---

### SEC-UPLOAD-001 - Unrestricted Malicious File Upload and Distribution

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-UPLOAD-001 |
| **Threat Ref** | T-3 - Unrestricted File Upload |
| **STRIDE Category** | Tampering |
| **OWASP API** | API3:2023 - Broken Object Property Level Authorization |
| **NIST CSF** | Protect (PR.DS-1) - Data-at-Rest Security |
| **Severity** | High |
| **Status** | Remediated |

**Objective:** Verify that `.php` webshell upload is rejected with HTTP 422.

**Attack Steps:**

```bash
# Step 1: Create a PHP webshell payload
echo '<?php echo "POC: System compromised. PHP Version: " . phpversion(); ?>' > /tmp/shell.php

# Step 2: Upload the webshell - expect HTTP 422
curl -i -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/shell.php"
```

**Observed Terminal Output:**

```
HTTP/1.1 422 Unprocessable Entity
{"detail":"File type '.php' is not allowed. Permitted types: ['.csv', '.docx', '.jpeg', '.jpg', '.pdf', '.png', '.txt', '.xlsx']"}
```

**Analysis:** `ALLOWED_EXTENSIONS` allowlist rejects `.php` with HTTP 422.

**Pass Criteria:** HTTP 422 on `.php` upload - **PASS**.

---

### SEC-LOG-001 - Audit Log Evidence Destruction
 
| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-LOG-001 |
| **Threat Ref** | T-4 - Audit Log Repudiation |
| **STRIDE Category** | Repudiation |
| **OWASP API** | API10:2023 - Unsafe Consumption of APIs |
| **NIST CSF** | Detect (DE.AE) - Anomalies and Events |
| **Severity** | Medium |
| **Status** | Open |
 
**Objective:** Verify that audit log events are emitted to stdout and SQLite, and assess whether evidence can be destroyed by a host-level actor.
 
**Attack Steps:**
 
```bash
# Locate the physical log file on the Docker host
LOG_FILE=$(docker inspect sfep_api --format='{{.LogPath}}')
echo "Log path: $LOG_FILE"
 
# Count lines before destruction
sudo wc -l $LOG_FILE
 
# Silently truncate — destroy all audit evidence
sudo truncate -s 0 $LOG_FILE
 
# Confirm total erasure
sudo wc -l $LOG_FILE
docker logs sfep_api 2>&1 | wc -l
```
 
**Observed Terminal Output:**
 
```
Log path: /var/lib/docker/containers/<id>/<id>-json.log
1024 /var/lib/docker/containers/<id>/<id>-json.log
0 /var/lib/docker/containers/<id>/<id>-json.log
0
```
 
**Analysis:** The log file on the Docker host is writable by any root process. A single `truncate` command destroys all audit evidence with no alert, no checksum failure, and no notification. Additionally, audit events contain no `source_ip` or `actor_id` - a root actor and a legitimate user are indistinguishable in the log.
 
**Pass Criteria:** Append-only SQLite triggers, external SIEM forwarding, HMAC chain per entry.
 
**Remediation:** Persist events to append-only SQLite `audit_log` table with BEFORE UPDATE/DELETE triggers. Forward logs to external SIEM outside the container boundary.

---

### SEC-UPLOAD-002 - MIME-Type Spoofing Bypass on File Upload

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-UPLOAD-002 |
| **Threat Ref** | T-3 - Unrestricted File Upload |
| **STRIDE Category** | Tampering |
| **OWASP API** | API3:2023 - Broken Object Property Level Authorization |
| **NIST CSF** | Protect (PR.IP) - Information Protection Processes |
| **Severity** | Medium |
| **Status** | Remediated |

**Objective:** Verify that file type validation is based on filename extension and rejects disallowed types regardless of declared Content-Type.

**Attack Steps:**

```bash
# Upload a PHP shell declared as image/png
curl -si -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/shell.php;type=image/png"
```

**Observed Terminal Output:**

```
HTTP/1.1 422 Unprocessable Entity
{"detail":"File type '.php' is not allowed. Permitted types: ['.csv', '.docx', '.jpeg', '.jpg', '.pdf', '.png', '.txt', '.xlsx']"}
```

**Analysis:** Extension-based validation rejects `.php` regardless of the declared `Content-Type`. Remaining gap: byte-level MIME inspection via `python-magic` not yet implemented.

**Pass Criteria:** HTTP 422 regardless of declared Content-Type - **PASS**.

---

## 4. Security Test Results

| Test ID | Vulnerability | STRIDE | NIST CSF | Severity | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SEC-IDOR-001 | Unauthenticated file download | Elevation of Privilege | PR.AC | Critical | **PASS** |
| SEC-IDOR-002 | UUID token enumeration | Elevation of Privilege | DE.CM | High | **PASS** |
| SEC-AUTH-001 | API token in plaintext config | Spoofing | PR.DS | High | **PASS** |
| SEC-AUTH-002 | Rate limiting on upload endpoint | Elevation of Privilege | PR.AC | High | **PASS** |
| SEC-UPLOAD-001 | Malicious file upload | Tampering | PR.DS-1 | High | **PASS** |
| SEC-LOG-001 | Audit log erasure | Repudiation | DE.AE | Medium | **OPEN** |
| SEC-UPLOAD-002 | MIME-type spoofing bypass | Tampering | PR.IP | Medium | **PASS** |
