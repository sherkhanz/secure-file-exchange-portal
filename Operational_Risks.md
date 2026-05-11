# Operational Risks: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** Threat Model, OE Dashboard  

---

## 1. Overview

This document identifies the highest risks to disruption of customer use of the Secure File Exchange Portal. Unlike the Threat Model which focuses on security attack vectors, this document focuses on operational failures that prevent customers from uploading files, creating links, or downloading files.

Customer-facing workflows at risk:

- `POST /upload` - customer uploads a file
- `POST /links` - customer creates a download link
- `GET /download/{token}` - recipient downloads the file
- `POST /revoke/{token}` - customer revokes access

---

## 2. Risk Summary Table

| ID | Risk | Workflow | Likelihood | Impact | Priority |
|----|------|-------------------|------------|--------|----------|
| OR&#8209;1 | Storage volume exhaustion | Upload | High | Critical | P0 |
| OR&#8209;2 | <nobr>SQLite database lock and corruption</nobr> | All | Medium | Critical | P0 |
| OR&#8209;3 | Container Out-Of-Memory crash | All | Medium | Critical | P0 |
| OR&#8209;4 | API slow response and timeouts | All | Medium | High | P1 |

---

## 3. Risk Details

### OR-1 - Storage Volume Exhaustion

| Field | Detail |
|-------|--------|
| **Component** | `sfep_files` Docker volume, `POST /upload` |
| **Hard Limit** | `MAX_UPLOAD_MB: 20` per file, no total volume cap |
| **Failure&nbsp;Mode** | Once the host filesystem fills up, all uploads return HTTP 500. Existing download links remain functional but no new files can be shared. |
| **Root Cause** | No per-user quota, no total storage cap, no automatic cleanup of expired file data. Files are never deleted even after their download token expires. |
| **Impact** | Customers cannot upload files. Core workflow is completely unavailable. |
| **Detection** | Grafana Storage Used panel - red threshold at 19 MB. |
| **Mitigation** | Add a cleanup job to delete files whose links have expired. Implement a hard cap on total volume usage with HTTP 507 response before exhaustion. |

---

### OR-2 - SQLite Concurrency Lock and Corruption

| Field | Detail |
|-------|--------|
| **Component** | `portal.db` on `sfep_db` volume, all endpoints |
| **Failure&nbsp;Mode** | SQLite allows only one concurrent writer. Under simultaneous upload and audit log write load, requests queue or fail with `database is locked`. Corruption can occur if the container is killed mid-write. |
| **Root Cause** | No WAL mode enabled. No connection pooling. Each request opens a new `sqlite3.connect()`. |
| **Impact** | Intermittent 500 errors on upload, link creation, and download across all customers simultaneously. |
| **Detection** | Spike in HTTP 500 responses. `docker logs sfep_api` shows `OperationalError: database is locked`. |
| **Mitigation** | Enable WAL mode: `PRAGMA journal_mode=WAL`. Add `PRAGMA integrity_check` on startup. Implement periodic SQLite backup. |

---

### OR-3 - Container Out-Of-Memory Crash

| Field | Detail |
|-------|--------|
| **Component** | `sfep_api` container |
| **Failure&nbsp;Mode** | If the container runs out of memory or crashes, all endpoints return connection refused. Docker `restart: unless-stopped` will restart the container but there is a gap in availability. |
| **Root Cause** | No memory limits set in `docker-compose.yml`. A large file upload reads the entire content into memory (`contents = await file.read()`). A 20 MB file upload allocates 20 MB in-process. |
| **Impact** | Complete service unavailability until container restarts. All active download links temporarily unreachable. |
| **Detection** | `GET /health` returns connection refused. Grafana API Status panel shows non-OK. |
| **Mitigation** | Set memory limits in `docker-compose.yml`. Stream large file uploads instead of reading entirely into memory. Add external health check alerting. |

---

### OR-4 - API Slow Response and Timeouts

| Field | Detail |
|-------|--------|
| **Component** | All endpoints, SQLite queries |
| **Failure&nbsp;Mode** | As the `files`, `links`, and `audit_log` tables grow, unindexed queries slow down. Download requests that involve multiple sequential SQLite queries may timeout under load. |
| **Root Cause** | No indexes on `links.token` or `files.id` beyond the primary key. No query timeout configured in FastAPI or uvicorn. No request concurrency limit. |
| **Impact** | Slow downloads and uploads. Customers experience timeouts especially during peak usage. |
| **Detection** | No response time metric currently in OE Dashboard. Needs to be added. |
| **Mitigation** | Add database indexes. Add uvicorn worker timeout configuration. Add avg response time panel to Grafana. |
