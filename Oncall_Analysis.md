# On-Call Analysis: Secure File Exchange Portal

---

## Scenario A - Token Enumeration Attack (T-1: IDOR)

**Trigger:** Failed Downloads panel turns red (10+ events).

---

### 1. Dashboard Signal

| Panel | What the engineer sees |
|-------|----------------------|
| **Failed Downloads** | Count spiking rapidly - red background |
| **Successful Downloads** | Stable or also increasing - indicates hits |
| **Revoked / Expired Token Access** | May also spike if attacker hits old tokens |
| **Unauthorized Requests** | Flat - attacker has a valid API token or is only hitting `/download` |

High `failed_download` events without 401 errors signify an unauthenticated IDOR (Insecure Direct Object Reference) attack, where an adversary is attempting to brute-force or enumerate `/download/{token}` URLs at scale.

---

### 2. Immediate Analysis

Check the audit log directly to confirm enumeration pattern:

```bash
docker logs sfep_api 2>&1 | grep failed_download | tail -30
```

Look for:
- Same timestamp burst (automated tool like `ffuf`)
- Sequential or random UUIDs in the token field
- `reason=token_not_found` on every entry - no legitimate user generates this at volume

Cross-check in SQLite to see if any tokens were successfully hit:

```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT event, detail, ts FROM audit_log WHERE event='successful_download' ORDER BY ts DESC LIMIT 10\").fetchall()
for r in rows: print(r)
"
```

---

### 3. Mitigation Action

**Immediate:**
- Revoke all currently active tokens to stop any in-flight access:

```bash
# Get all active tokens
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT token FROM links WHERE revoked=0\").fetchall()
for r in rows: print(r[0])
" | xargs -I{} curl -s -X POST http://localhost:8000/revoke/{} \
  -H "x-api-token: supersecret-mock-token"
```

**Short-term:**
- Add `slowapi` rate limiting to `/download/{token}` - 5 requests/min per IP
- Add `Depends(require_auth)` to the download endpoint

**Root cause:** T-1 - `/download/{token}` has no authentication guard. See Threat Model for full remediation roadmap.

---

## Scenario B - Storage Capacity Approaching Hard Limit

**Trigger:** Storage Used panel turns orange (15 MB+) or red (19 MB+).

---

### 1. Dashboard Signal

| Panel | What the engineer sees |
|-------|----------------------|
| **Storage Used** | Orange or red background - approaching 20 MB cap |
| **Total Files** | Unusually high file count |
| **Recent Uploads** | Large file visible - check `Size Bytes` column |
| **Suspicious Uploads** | May show `.exe` or large binary uploads |

At 19 MB the system has 1 MB of headroom. Any upload above that size will fail with HTTP 413. If this is unexpected, it may indicate deliberate storage exhaustion or a single large legitimate file.

---

### 2. Immediate Analysis

Identify what is consuming the space:

```bash
docker exec sfep_api python3 -c "
import sqlite3
conn = sqlite3.connect('/data/db/portal.db')
rows = conn.execute(\"SELECT filename, size_bytes, created_at FROM files ORDER BY size_bytes DESC LIMIT 10\").fetchall()
for r in rows: print(r)
"
```

Check if a single file dominates or if it is a high volume of small files - the two cases have different causes.

Also verify actual disk usage matches DB records:

```bash
docker exec sfep_api du -sh /data/files/
```

---

### 3. Mitigation Action

**If a single large legitimate file:**
- No action required if expected. Communicate to uploader to clean up after use.
- Consider raising `MAX_UPLOAD_MB` in `docker-compose.yml` if the limit is too low for the use case.

**If upload flooding (many small files rapidly):**
- Identify the upload pattern in audit log:

```bash
docker logs sfep_api 2>&1 | grep upload_created | tail -50
```

- Rotate the API token immediately to cut off the attacker:

```bash
# Edit docker-compose.yml: API_TOKEN → new value
docker compose up -d --force-recreate
```

- Remove orphaned or malicious files from the volume:

```bash
docker exec sfep_api find /data/files -name "*.exe" -o -name "*.php" -o -name "*.sh"
# Then remove identified files
```

**Root cause:** No per-user upload quota and no rate limiting on `POST /upload`. See Threat Model T-3 remediation for permanent fix.
