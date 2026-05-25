# Compliance Audit: Mock Product Implementation

**Version:** 1.0
**Linked Documents:** Compliance Requirements, Threat Model

---

## 1. Audit Scope

- **Backend code:** `app/main.py` - FastAPI endpoints, authentication logic, file handling, audit logging
- **Storage layer:** SQLite `portal.db` and Docker volume `sfep_files` (physical file storage)

---

## 2. Compliant Baseline

Items already compliant prior to remediation:

- **Audit logging:** All security-relevant events (`upload_created`, `failed_download`, `unauthorized_request`, `link_revoked`) are written to both stdout and `audit_log` table in SQLite - satisfies FTC Section 5 and GDPR Article 32
- **Authentication on write endpoints:** `POST /upload`, `POST /links`, and `POST /revoke/{token}` all require a valid API token via `Depends(require_auth)` - satisfies NIST Protect and FTC access control requirements

---

## 3. Audit Findings

| Gap | Compliance Violation | Framework | Severity |
|-----|---------------------|-----------|---------|
| **Gap 1 - No file type validation** | `POST /upload` accepted any file type including `.php`, `.sh`, `.exe` - constitutes an unreasonable security practice and fails to protect the system from malicious file storage | FTC Section 5 (unreasonable security)<br>NIST CSF 2.0 Protect function | High |
| **Gap 2 - Expired files never deleted** | Files with expired or revoked download tokens remained permanently on disk and in the `files` table - violates storage limitation principle and data retention policy | GDPR Article 5(1)(e) (storage limitation)<br>FTC Section 5 (data retention)<br>Compliance_Requirements.md Section 3.1 | High |
| **Gap 3 - Unauthenticated download endpoint (IDOR)** | `GET /download/{token}` requires no authentication - any party with a token can access files without authorization | FTC Section 5 (unreasonable security)<br>GDPR Article 32 (security of processing) | Critical |
| **Gap 4 - Hardcoded API token** | `API_TOKEN` is hardcoded in `docker-compose.yml` and committed to version control - constitutes a deceptive security practice if the product claims data is protected | FTC Section 5 (deceptive practice)<br>Compliance_Requirements.md Section 3.2 | High |

---

## 4. Remediation Actions

### Gap 1 - File Type Validation

- Added `ALLOWED_EXTENSIONS` constant after config block in `main.py`:
  ```python
  ALLOWED_EXTENSIONS = {".txt", ".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".csv"}
  ```
- Added extension check in `upload_file()` immediately after `contents = await file.read()`:
  ```python
  file_ext = os.path.splitext(file.filename)[1].lower()
  if file_ext not in ALLOWED_EXTENSIONS:
      raise HTTPException(
          status_code=422,
          detail=f"File type '{file_ext}' is not allowed. Permitted types: {sorted(ALLOWED_EXTENSIONS)}"
      )
  ```
- **Verification:** `POST /upload` with `shell.php` returns HTTP 422. `POST /upload` with `test.txt` returns HTTP 200 and `file_id`.

---

### Gap 2 - Data Retention Enforcement

- Added `cleanup_expired_files()` function after `init_db()` in `main.py`:
  - Queries `files` table for records with no active, unexpired, non-revoked links
  - Deletes physical file from disk using `os.remove()`
  - Emits `event=file_deleted` to stdout audit log
  - Deletes associated records from `links` and `files` tables
- Integrated cleanup into `GET /health` endpoint - runs on every health check call:
  ```python
  @app.get("/health")
  def health():
      cleanup_expired_files()
      return {"status": "ok", "version": "0.1.0"}
  ```
- **Verification:** File uploaded with `expires_in_minutes=1`, after 120 seconds `/health` called, `docker logs sfep_api | grep file_deleted` confirms deletion, `SELECT * FROM files` returns 0 rows for expired file.

---

### Gap 3 - Unauthenticated Download (IDOR)

- **Status: Deferred**
- `GET /download/{token}` currently requires no authentication - any party with a valid token can access files
- Remediation requires adding `Depends(require_auth)` to the download endpoint and updating all integration tests in `automate_tests.sh` that currently document this as a known `[VULN]`
- Deferred to final submission to avoid breaking existing CI/CD test suite and automated security test documentation
- Documented as T-1 in `Threat_Model.md` with planned remediation

---

### Gap 4 - Hardcoded API Token

- **Status: Deferred**
- `API_TOKEN` is currently hardcoded in `docker-compose.yml` and committed to version control
- Remediation requires migrating to a `.env` file excluded via `.gitignore`, or Docker Secrets for production-grade deployment
- Deferred because it is an architectural change affecting `docker-compose.yml`, `Dockerfile`, and deployment documentation - requires coordinated update across multiple files
- Documented as T-2 in `Threat_Model.md` with planned remediation

---

## 5. Audit Summary

| Item | Status |
|------|--------|
| Audit logging - FTC Section 5, GDPR Art. 32 | Compliant |
| Authentication on write endpoints - NIST Protect | Compliant |
| File type validation - FTC Section 5, NIST Protect | Remediated |
| Data retention enforcement - GDPR Art. 5(1)(e), FTC | Remediated |
| Unauthenticated download (IDOR) - FTC, GDPR Art. 32 | Known - deferred |
| Hardcoded API token - FTC Section 5 | Known - deferred |

The two identified non-compliant gaps have been remediated with verifiable code changes. The two remaining known vulnerabilities (IDOR, hardcoded token) are intentional design decisions for this mock implementation, documented in the Threat Model with planned remediation prior to final submission.
