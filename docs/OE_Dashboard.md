# OE Dashboard: Secure File Exchange Portal

## 1. Overview

This document describes the Operational Excellence Dashboard for the Secure File Exchange Portal. The dashboard provides real-time visibility into system health, security events, link lifecycle, storage capacity, and operational risks.

---

## 2. Dashboard Architecture

```
[ FastAPI app: main.py ]
         │
         │  Every audit event written to both:
         │  1. stdout (docker logs)
         │  2. SQLite audit_log table
         ▼
[ SQLite: portal.db ]
   ├── files table         ← upload metadata
   ├── links table         ← token lifecycle
   └── audit_log table     ← all security events
         │
         │  frser-sqlite-datasource plugin
         ▼
[ Grafana :3000 ]
   └── OE Dashboard
         ├── System Health
         ├── Link Lifecycle
         ├── Security
         └── Operational Risks
```

---

## 3. Key Telemetry Metrics

### 3.1 System Health

| Panel | Type | Query | Normal State |
|-------|------|-------|-------------|
| API Status | Table | `SELECT 'OK' as status` | Green "OK" |
| Total Files | Stat | `SELECT COUNT(*) as total_files FROM files` | Any&nbsp;positive&nbsp;number |
| Large&nbsp;File&nbsp;Upload | Stat | `SELECT COUNT(*) as large_uploads FROM files WHERE size_bytes > 5242880 AND created_at > datetime('now', '-1 hour')` | Green: 0–1 |
| Storage Used | Gauge | `SELECT SUM(size_bytes) as storage_used FROM files` | Green: &lt;15 MB |

**Storage Used thresholds:**

| Color | Threshold | Meaning |
|-------|-----------|---------|
| Green | &lt; 15 MB | Normal |
| Orange | 15 MB | Warning - approaching limit |
| Red | 19 MB | Critical - 1 MB buffer before HTTP 413 |

**Large File Upload thresholds:**

| Color | Threshold | Meaning |
|-------|-----------|---------|
| Green | 0–1 | Normal |
| Orange | 2+ | Warning - memory pressure risk |
| Red | 3+ | Critical - OOM risk |

---

### 3.2 Security and Threat Detection

| Panel | Type | Threat Ref | Query | Threshold |
|-------|------|-----------|-------|----------------|
| Failed Downloads | Stat | T-1 (IDOR) | `SELECT COUNT(*) as failed FROM audit_log WHERE event='failed_download'` | Red: 10+ |
| Successful Downloads | Stat | T-1 (IDOR) | `SELECT COUNT(*) as success FROM audit_log WHERE event='successful_download'` | Compare to active |
| Unauthorized Requests (401) | Stat | T&#8209;2&nbsp;(Spoofing) | `SELECT COUNT(*) as unauthorized FROM audit_log WHERE event='unauthorized_request'` | Red: 5+ |
| Revoked / Expired Token Access | Stat | T-1 (IDOR) | `SELECT COUNT(*) as suspicious FROM audit_log WHERE event IN ('revoked_link_access','expired_link_access')` | Yellow: 1+ <br> Red: 3+ |
| Suspicious Uploads | Table | T&#8209;3&nbsp;(Tampering) | `SELECT filename, size_bytes, ts as "Uploaded At" FROM audit_log WHERE event='upload_created' AND (detail LIKE '%.php%' OR detail LIKE '%.sh%' OR detail LIKE '%.exe%') ORDER BY ts DESC` | Any row = immediate review |

---

### 3.3 Link Lifecycle

| Panel | Type | Query | Normal State |
|-------|------|-------|-------------|
| Active Links | Stat | `SELECT COUNT(*) as active FROM links WHERE revoked=0 AND expires_at > datetime('now')` | Matches expected active sessions |
| Revoked Links | Stat | `SELECT COUNT(*) as revoked FROM links WHERE revoked=1` | Low - spikes may indicate incident response in progress |
| Unreferenced Files | Stat | `SELECT COUNT(*) as orphaned FROM files WHERE id NOT IN (SELECT file_id FROM links WHERE revoked=0 AND expires_at > datetime('now'))` | Green: &lt;10 |

**Unreferenced Files thresholds:**

| Color | Threshold | Meaning |
|-------|-----------|---------|
| Green | &lt; 10 | Normal |
| Orange | 10+ | Warning - storage waste accumulating |
| Red | 50+ | Critical - cleanup required immediately |

---

### 3.4 Storage and Capacity

| Panel | Type | Query | Threshold |
|-------|------|-------|----------------|
| Storage Used | Gauge | `SELECT SUM(size_bytes) as storage_used FROM files` | Orange: 15 MB <br> Red: 19 MB |

**Notes:**
- Storage limit is set by `MAX_UPLOAD_MB: 20` in `docker-compose.yml`.
- Red threshold at 19 MB gives a 1 MB buffer before uploads start failing with HTTP 413.

---

### 3.5 Operational Risks

| Panel | Type | Query | Threshold |
|-------|------|-------|----------------|
| DB Write Contention | Table | `SELECT STRFTIME('%Y-%m-%d %H:%M', ts) as "Time (minute)", COUNT(*) as write_intensity FROM audit_log WHERE event IN ('upload_created', 'link_generated') GROUP BY "Time (minute)" HAVING write_intensity > 3` | Orange: 5+, Red: 10+ |

**DB Write Contention panel notes:**
- Empty table - normal state. Rows appear only when write intensity exceeds threshold.
- A value of 15+ in a single minute indicates high SQLite lock contention risk.

---

## 4. Dashboard Screenshot

![OE Dashboard](../screenshots/OE_Dashboard.png)
