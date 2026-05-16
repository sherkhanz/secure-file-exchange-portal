# Operational Questions and Dashboard Gaps: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** OE Dashboard, Operational Risks

---

## 1. Overview

This document outlines the operational questions the OE Dashboard should be able to answer for an on-call engineer during normal operations and incident response. Each question is mapped to its current dashboard coverage and any remaining gap.

---

## 2. Operational Questions

### 2.1 System Health

| Question | Dashboard Panel | Answered? | Gap |
|----------|----------------|-----------|-----|
| Is the API currently running and healthy? | API Status (Table) | Partial | Panel shows static "OK" - not a live HTTP probe. Grafana cannot ping the API directly via SQLite datasource. True liveness requires Prometheus + HTTP exporter. |
| How many files are stored in the system? | Total Files (Stat) | Yes | None |
| Are large files being uploaded at a rate that could cause memory pressure? | Large File Upload (Stat) | Yes | Threshold is count-based, not rate-based. Does not detect a single very large file upload in progress. |
| How much storage is currently consumed? | Storage Used (Gauge) | Yes | Measures cumulative bytes in `files` table - includes files whose tokens have expired. Does not reflect actual disk usage if files were manually deleted. |

---

### 2.2 Security and Threat Detection

| Question | Dashboard Panel | Answered? | Gap |
|----------|----------------|-----------|-----|
| Are there signs of token enumeration or IDOR attacks? | Failed Downloads (Stat) | Yes | None |
| Is the API token being brute-forced? | Unauthorized Requests 401 (Stat) | Yes | None |
| Have any revoked or expired tokens been accessed? | Revoked / Expired Token Access (Stat) | Yes | None |
| Have any malicious file types been uploaded? | Suspicious Uploads (Table) | Yes | Detection is filename-based (`.php`, `.sh`, `.exe`). A renamed webshell (e.g., `shell.jpg`) would not appear in this table. |
| What is the ratio of successful to failed downloads? | Failed Downloads + Successful Downloads | Partial | No combined ratio panel. Engineer must manually compare two stat values. |

---

### 2.3 Link Lifecycle

| Question | Dashboard Panel | Answered? | Gap |
|----------|----------------|-----------|-----|
| How many download links are currently active? | Active Links (Stat) | Yes | None |
| How many links have been revoked? | Revoked Links (Stat) | Yes | None |
| How many files have no active download link (orphaned)? | Unreferenced Files (Stat) | Yes | None |
| Are orphaned files accumulating faster than expected? | Unreferenced Files (Stat) | Partial | Shows current count only - no trend or growth rate over time. |

---

### 2.4 Storage and Capacity

| Question | Dashboard Panel | Answered? | Gap |
|----------|----------------|-----------|-----|
| Is total storage approaching the upload limit? | Storage Used (Gauge) | Yes | None |
| Will storage be exhausted soon if current upload rate continues? | None | No | No trend or projection panel exists. Would require time-series data - blocked by ISO timestamp format in SQLite. |
| Which files are consuming the most storage? | None | No | No per-file breakdown panel. Would require a table sorted by `size_bytes DESC`. |

---

### 2.5 Operational Risks

| Question | Dashboard Panel | Answered? | Gap |
|----------|----------------|-----------|-----|
| Is there concurrent write pressure on the SQLite database? | DB Write Contention (Table) | Yes | None |
| Has write contention exceeded safe thresholds in the last hour? | DB Write Contention (Table) | Partial | Table shows all historical contention rows, not scoped to a time window. |
| Is the API experiencing response time degradation? | None | No | No latency panel. `main.py` does not emit `duration_ms` data. |
| Is the container consuming unsafe amounts of memory? | None | No | Container memory not queryable from SQLite datasource. Requires cAdvisor + Prometheus. |

---

## 3. Summary of Gaps

| Gap | Category | Root Cause | Effort to Close |
|-----|----------|------------|----------------|
| API liveness check is not real | System Health | SQLite datasource cannot probe HTTP endpoints | Medium - requires Prometheus HTTP exporter |
| No time-windowed failed download rate | Security | Cumulative count only | Low - add `WHERE ts > datetime('now', '-1 hour')` |
| Renamed malicious files not detected | Security | Detection is extension-based only | Medium - requires MIME type checking in `main.py` |
| No storage growth rate or projection | Capacity | ISO timestamp incompatible with time series | Medium - requires `ts_unix` column in schema |
| No per-file storage breakdown | Capacity | Panel not implemented | Low - simple SQL table |
| No API response time metric | Ops Risks | `main.py` does not emit timing data | Medium - requires instrumentation in `main.py` |
| No container memory metric | Ops Risks | SQLite has no access to Docker daemon metrics | High - requires cAdvisor + Prometheus |
