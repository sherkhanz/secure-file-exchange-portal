# Required Metrics: Secure File Exchange Portal

---

## Metrics Collection Map

| Metric Name | Source | Logged When | Purpose |
|---------------------|--------|-------------|---------|
| `upload_created` | `audit_log` table | File successfully written to `/data/files` | Track upload activity, detect abuse, feed Suspicious Uploads panel |
| `upload_size_bytes` | `files` table (`size_bytes` column) | On every upload | Calculate total storage used, trigger capacity alerts |
| `link_generated` | `audit_log` table | `POST /links` succeeds | Track link creation rate, correlate with download events |
| `successful_download` | `audit_log` table | `GET /download/{token}` returns file | Measure legitimate usage, cross-reference against active links |
| `failed_download` | `audit_log` table | Token not found or file missing on disk | Primary signal for T-1 IDOR / token enumeration detection |
| `revoked_link_access` | `audit_log` table | Download attempted on a revoked token | Detect replay attacks, signal leaked or intercepted tokens |
| `expired_link_access` | `audit_log` table | Download attempted after `expires_at` | Detect stale token reuse, operational noise vs. attack signal |
| `link_revoked` | `audit_log` table | `POST /revoke/{token}` succeeds | Track manual revocation rate, correlate with incident response |
| `unauthorized_request` | `audit_log` table | `require_auth()` rejects invalid `x-api-token` | Primary signal for T-2 credential brute-force detection |
| `filename` (in detail) | `audit_log` table (`detail` column) | Stored as part of `upload_created` event | Enable Suspicious Uploads panel to filter by extension |

---

## Database Tables Required

| Table | Columns | Used By |
|-------|-----------------|---------|
| `files` | `id`, `filename`, `size_bytes`, `created_at` | Recent Uploads, Total Files, Storage Used panels |
| `links` | `token`, `file_id`, `expires_at`, `revoked`, `created_at` | Active Links, Revoked Links panels |
| `audit_log` | `id`, `event`, `detail`, `ts` | All Security & Threat Detection panels |
