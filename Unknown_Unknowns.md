# Unknown Unknowns: Secure File Exchange Portal

**Version:** 1.0  
**Purpose:** Identify potential risks NOT covered in the current Threat Model.

---

## Overview

The current Threat Model analyzes risks within the application boundary - IDOR, hardcoded credentials, unrestricted uploads, audit log repudiation, and cleartext transport. This document identifies risks that exist outside that boundary: upstream dependencies, infrastructure, and supply chain threats that could compromise the system without any application-level vulnerability.

---

## UU-1 - Vulnerable Upstream Dependencies 

| Field | Detail |
|-------|--------|
| **Category** | Upstream Dependencies |
| **Components** | `fastapi==0.111.0`, `uvicorn==0.30.1`, `python:3.12-slim` |
| **Risk** | A CVE in FastAPI, Uvicorn, or the Python base image could allow remote code execution, request smuggling, or authentication bypass |
| **Why Unknown** | `requirements.txt` pins exact versions but no automated CVE scanning is configured. The base image `python:3.12-slim` is pulled at build time with no digest pinning. |
| **Detection Gap** | No SBOM (Software Bill of Materials) generated. No Dependabot or similar alerting. |

**Mitigation path:**
- Pin Docker base image by digest: `FROM python:3.12-slim@sha256:...`
- Add `pip audit` to CI pipeline
- Enable GitHub Dependabot on `requirements.txt`

---

## UU-2 - Docker Daemon Privilege Escalation

| Field | Detail |
|-------|--------|
| **Category** | Infrastructure |
| **Components** | Docker daemon on host, named volumes `sfep_db` and `sfep_files` |
| **Risk** | Any process running as root on the Docker host has direct access to all named volumes including the SQLite database and uploaded files. |
| **Why Unknown** | The Threat Model addresses volume encryption but does not consider the Docker daemon itself as an attack surface. The daemon socket (`/var/run/docker.sock`) grants root-equivalent access to any process that can reach it. |
| **Detection Gap** | No container security scanning (e.g., Falco, Trivy). No Docker socket access controls. |

**Mitigation path:**
- Never mount `/var/run/docker.sock` into containers
- Run Docker in rootless mode
- Enable Docker Content Trust for image verification

---

## UU-3 - Supply Chain Attack via Compromised PyPI Package

| Field | Detail |
|-------|--------|
| **Category** | Supply Chain |
| **Components** | `requirements.txt` |
| **Risk** | A typosquatting attack or a compromised maintainer account on PyPI could inject malicious code into `fastapi`, `uvicorn`, `pydantic`, `python-multipart`, or `aiofiles`. The malicious version would be installed silently during `docker compose build`. |
| **Why Unknown** | `pip install` does not verify package signatures by default. There is no hash verification (`--require-hashes`) in the current `requirements.txt`. |
| **Detection Gap** | No `pip install --require-hashes`. No private package mirror. No build-time integrity check. |

**Mitigation path:**
- Add hash verification to `requirements.txt`:
```
fastapi==0.111.0 --hash=sha256:...
```
- Use `pip audit` to scan for known CVEs after install
- Consider a private PyPI mirror for production builds

---

## UU-4 - SQLite Concurrent Write Corruption

| Field | Detail |
|-------|--------|
| **Category** | Infrastructure |
| **Components** | `portal.db` on `sfep_db` volume, `audit_log` table |
| **Risk** | SQLite has limited support for concurrent writes. Under heavy load, such as multiple simultaneous uploads or audit log writes, the database can become locked or corrupted. A corrupted `portal.db` means loss of all file metadata, link state, and audit history. |
| **Why Unknown** | The application uses a new SQLite connection per request (`sqlite3.connect(DB_PATH)`) with no connection pooling or WAL mode enabled. |
| **Detection Gap** | No database integrity checks. No backup mechanism. No WAL mode configured. |

**Mitigation path:**
- Enable WAL mode: `conn.execute("PRAGMA journal_mode=WAL")`
- Add a scheduled `PRAGMA integrity_check` via cron
- Implement volume-level backup to a second location

---

## UU-5 - Container Image Tampering

| Field | Detail |
|-------|--------|
| **Category** | Supply Chain |
| **Components** | `grafana/grafana:10.4.2` pulled from Docker Hub |
| **Risk** | Docker Hub images are pulled by tag, not by digest. A tag can be silently overwritten with a malicious image. If `grafana/grafana:10.4.2` is ever re-tagged with a compromised build, the next `docker compose pull` would install it without any warning. |
| **Why Unknown** | The current `docker-compose.yml` references images by tag only. Docker Content Trust is not enabled. This affects the Grafana container, which has read-only access to the SQLite database. If compromised, it could exfiltrate all audit data and file metadata. |
| **Detection Gap** | No image digest pinning. No Docker Content Trust (`DOCKER_CONTENT_TRUST=1`). |

**Mitigation path:**
- Pin by digest in `docker-compose.yml`:
```yaml
image: grafana/grafana@sha256:...
```
- Enable `DOCKER_CONTENT_TRUST=1` in CI environment
- Scan images with `trivy image grafana/grafana:10.4.2` before deployment

---

## Summary

| ID | Risk | Category | Current Coverage |
|----|------|----------|-----------------|
| 1 | CVE in FastAPI / Uvicorn / Python base image | Upstream Dependencies | Not covered |
| 2 | Docker daemon privilege escalation via host | Infrastructure | Partially |
| 3 | Compromised PyPI package in requirements.txt | Supply Chain | Not covered |
| 4 | SQLite concurrent write corruption / data loss | Infrastructure | Not covered |
| 5 | Docker Hub image tag tampering | Supply Chain | Not covered |
