# Manual Tests and Monitoring Gaps: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** OE Dashboard, Automate Tests

---

## 1. Overview

This document identifies two categories of gaps in the current operational observability and test coverage of the Secure File Exchange Portal:

1. **Manual tests** - operational risk scenarios that cannot be reliably automated in the current CI/CD pipeline.
2. **Monitoring gaps** - proactive alert metrics that are not yet present in the OE Dashboard due to technical constraints of the SQLite datasource.

---

## 2. Manual Tests

### 2.1 API Response Time Under Load

| Field | Detail |
|-------|--------|
| **Risk** | OR-4 - API slow response and timeouts |
| **Why not automated** | `automate_tests.sh` uses `curl` sequentially. There is no reliable baseline response time to assert against, as a threshold like "under 500ms" would be environment-dependent and produce false positives in CI runners. Measuring P95 latency requires a load generation tool and statistical aggregation. |
| **Manual procedure** | 1. Start all containers: `docker compose up -d` <br> 2. Send 50 sequential upload requests and record response times: `for i in {1..50}; do curl -s -w "%{time_total}\n" -o /dev/null -X POST http://localhost:8000/upload -H "x-api-token: supersecret-mock-token" -F "file=@/tmp/test.txt"; done` <br> 3. Calculate average and P95 from output <br> 4. Acceptable threshold: average under 500ms, P95 under 1000ms |
| **Expected result** | All requests complete under 1 second. Degradation indicates table growth causing unindexed query slowdown. |

---

### 2.2 Container Memory Saturation

| Field | Detail |
|-------|--------|
| **Risk** | OR-3 - Container Out-Of-Memory crash |
| **Why not automated** | Memory consumption during file upload is not observable via the API or SQLite. The automated OR-3 test in `automate_tests.sh` only checks that the API is healthy after concurrent uploads - it does not measure actual RAM usage. An OOM kill by the kernel happens silently from the API's perspective until the container restarts. |
| **Manual procedure** | 1. Open a second terminal and run: `watch -n 1 docker stats sfep_api --no-stream` <br> 2. In the first terminal, upload 5 simultaneous 15 MB files: `for i in {1..5}; do dd if=/dev/urandom of=/tmp/large_$i.bin bs=1M count=15 2>/dev/null; curl -s -X POST http://localhost:8000/upload -H "x-api-token: supersecret-mock-token" -F "file=@/tmp/large_$i.bin" & done; wait` <br> 3. Observe `MEM USAGE` in docker stats during uploads |
| **Expected result** | Memory stays below host limit. If memory spikes to 100% and the container restarts, OOM risk is confirmed. |

---

### 2.3 SQLite Database Integrity After Crash

| Field | Detail |
|-------|--------|
| **Risk** | OR-2 - SQLite concurrency lock and corruption |
| **Why not automated** | Simulating a mid-write crash requires killing the container at a precise moment during a database write. This is a timing-dependent operation that is not reliably reproducible in CI. Asserting database integrity requires running `PRAGMA integrity_check` inside the container after recovery. |
| **Manual procedure** | 1. Start an upload in the background: `curl -s -X POST http://localhost:8000/upload -H "x-api-token: supersecret-mock-token" -F "file=@/tmp/large.bin" &` <br> 2. Immediately kill the container: `docker kill sfep_api` <br> 3. Restart: `docker compose start api` <br> 4. Run integrity check: `docker exec sfep_api python3 -c "import sqlite3; conn = sqlite3.connect('/data/db/portal.db'); print(conn.execute('PRAGMA integrity_check').fetchone())"` |
| **Expected result** | `('ok',)` - database survived the crash. Any other result indicates corruption. |

---

### 2.4 Volume Data Persistence After Restart

| Field | Detail |
|-------|--------|
| **Risk** | OR-1, OR-2 - data loss risk on volume operations |
| **Why not automated** | Verifying that data persists across `docker compose down` and `docker compose up` requires human judgment to confirm that previously uploaded files and their tokens are still accessible. Automating this would require storing file IDs and tokens across test runs, which is outside the scope of the current stateless bash test suite. |
| **Manual procedure** | 1. Upload a file and create a download link, note the token <br> 2. Stop containers: `docker compose down` (without `-v`) <br> 3. Restart: `docker compose up -d` <br> 4. Attempt download: `curl -v http://localhost:8000/download/{token}` |
| **Expected result** | HTTP 200 and correct file content returned. If 404 is returned, volume data was lost. |

---

## 3. Monitoring Gaps

### 3.1 API Response Time P95

| Field | Detail |
|-------|--------|
| **Risk** | OR-4 - API slow response and timeouts |
| **Ideal panel** | Line chart showing rolling P95 response time per endpoint over time |
| **Why not in dashboard** | FastAPI's `main.py` does not emit request timing data. The `audit_log` table contains only `event`, `detail`, and `ts` columns - there is no `duration_ms` or `response_time_ms` field. Grafana cannot calculate latency from event timestamps alone without request start and end events. |
| **What would be needed** | Add timing instrumentation to `main.py`: record `start = time.time()` before processing and `duration_ms = (time.time() - start) * 1000` after, then write to `audit_log`. Alternatively, deploy a Prometheus + FastAPI middleware integration using `prometheus-fastapi-instrumentator`. |

---

### 3.2 Container Memory Usage

| Field | Detail |
|-------|--------|
| **Risk** | OR-3 - Container Out-Of-Memory crash |
| **Ideal panel** | Gauge showing current container memory usage as a percentage of limit, with threshold at 80% |
| **Why not in dashboard** | Grafana's SQLite datasource (`frser-sqlite-datasource`) queries `portal.db` only. Container memory metrics are not stored in SQLite - they are exposed by the Docker daemon via `docker stats` and the cgroups filesystem. There is no way to query host-level memory from within a SQLite datasource panel. |
| **What would be needed** | Deploy cAdvisor as an additional container to expose container metrics in Prometheus format, then add a Prometheus datasource to Grafana and query `container_memory_usage_bytes{name="sfep_api"}`. |

---

### 3.3 Audit Log Table Size Growth Rate

| Field | Detail |
|-------|--------|
| **Risk** | OR-4 - API slow response and timeouts |
| **Ideal panel** | Time series showing row count growth rate of `audit_log` per hour, with alert at 1000+ new rows per hour |
| **Why not in dashboard** | The SQLite datasource cannot produce reliable time series without Unix millisecond timestamps. The `ts` column stores ISO 8601 strings which `frser-sqlite-datasource` cannot automatically parse as a time axis without additional transformation. Attempts to use `julianday()` or `strftime('%s')` produce incorrect epoch values due to SQLite's UTC handling. |
| **What would be needed** | Store `ts` as Unix integer (`INTEGER DEFAULT (strftime('%s','now'))`) instead of ISO string, or add a `ts_unix` column. This would allow correct time series rendering in Grafana. |
