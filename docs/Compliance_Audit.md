# Compliance Audit: Secure File Exchange Portal

## 1. Scope and Compliance Landscape

SFEP is a FastAPI file-sharing service handling sensitive corporate and personal data - uploaded files, access tokens, and audit logs. This document covers compliance requirements, non-compliance consequences, and audit findings against the following frameworks.

| Framework | Type | Applicability |
|-----------|------|--------------|
| FTC Act Section 5 | Federal law | All US-based commercial data handlers |
| GDPR | EU regulation | Any EU residents uploading or accessing files |
| NIST CSF 2.0 | Federal framework | Industry-standard security controls reference |

**Audit scope:**
- **Backend code:** `app/main.py` - FastAPI endpoints, authentication logic, file handling, audit logging
- **Storage layer:** SQLite `portal.db` and Docker volume `sfep_files` (physical file storage)

---

## 2. Compliance Requirements

### 2.1 FTC Act Section 5

**Source:** 15 U.S.C. § 45; FTC enforcement guidance (2023).

| Requirement | Description |
|-------------|-------------|
| Reasonable security | Security measures appropriate to data sensitivity. Unauthenticated download endpoints violate FTC precedent. |
| Data retention | Documented retention policies enforced. Indefinite retention is unreasonable per FTC v. Blackbaud (2024). |
| Incident response | Documented process for identification, containment, and notification. |
| Access control | Authenticated access required on all endpoints exposing sensitive data. |

### 2.2 GDPR

**Source:** Regulation (EU) 2016/679.

| Requirement | Description |
|-------------|-------------|
| Data minimization | Collect only what is strictly necessary for the stated purpose. |
| Storage limitation | Personal data must not be retained beyond its stated purpose. Tokens must expire and associated data must be deleted. |
| Right to erasure | Mechanism to delete EU user data on request - files, links, and audit log entries. |
| Security of processing | Access controls, encryption at rest and in transit, and audit logging required. |

### 2.3 NIST CSF 2.0

**Source:** NIST CSWP 29, February 2024.

| Function | Requirement |
|----------|-------------|
| Govern | Document security policies and compliance obligations. |
| Identify | Maintain asset inventory. Document risks via Threat Model. |
| Protect | Enforce access controls, validate file types, implement least privilege. |
| Detect | Monitor for unauthorized access and anomalous activity via OE Dashboard. |
| Respond | Operational runbook covering each identified threat scenario. |
| Recover | Documented recovery procedures for data loss and container failure. |

### 2.4 Corporate Policy Requirements

**Data Retention:**

| Data Type | Maximum Retention | Basis |
|-----------|------------------|-------|
| Uploaded files | Duration of active download link + 24 hours | GDPR, FTC |
| Download tokens | Until expiry or revocation, then immediate deletion | GDPR, FTC |
| Audit log entries | 90 days | FTC, NIST |

**Access Control:**

| Control | Requirement |
|---------|-------------|
| Authentication | All write operations require a valid API token |
| Download authentication | Download endpoints require authentication |
| Token rotation | API tokens must not be hardcoded in version-controlled files |

**Audit Logging**:

| Event | Must Be Logged |
|-------|---------------|
| File upload | File ID, filename, size, timestamp |
| Download link creation | Token, file ID, expiry, timestamp |
| Successful download | Token, file ID, timestamp |
| Failed download attempt | Token, reason, timestamp |
| Unauthorized request | Reason, timestamp |

---

## 3. Non-Compliance Consequences

### 3.1 FTC Act Section 5

Consent decree violations expose the operator to:
- Civil penalties up to $51,744 per violation per day
- Mandatory third-party security assessments every 2 years for up to 20 years
- Annual FTC compliance certification

**Reference:** FTC v. Blackbaud (2024) - first standalone Section 5 claim for unreasonable data retention and inaccurate breach notification.

### 3.2 GDPR

| Tier | Maximum Fine | Applies To |
|------|-------------|-----------|
| Standard | €10M or 2% turnover | Technical failures (Article 32) |
| Severe | €20M or 4% turnover | Core principle violations - storage limitation, lawfulness |

Additional enforcement: binding processing orders, mandatory public disclosure, transfer suspension.

**Context:** DLA Piper GDPR Survey (2024) - total GDPR fines in 2023 reached €1.78 billion.

### 3.3 Civil Litigation

| Liability Type | Trigger | Exposure |
|---------------|---------|---------|
| Class action | Data breach exposing user files | Legal fees, settlement, reputational damage |
| Individual GDPR claims | EU user files accessed without authorization | Compensatory damages per Article 82 |
| State breach notification | Failure to notify WA State residents within 30 days | RCW 19.255.010 violation |

**IBM Cost of a Data Breach Report 2025:** global average breach cost USD 4.4 million.

---

## 4. Audit Findings

### 4.1 Compliant Baseline

| Item | Basis |
|------|-------|
| Audit logging - all security events written to stdout and SQLite `audit_log` | FTC Section 5, GDPR Article 32 |
| Authentication on write endpoints - `POST /upload`, `POST /links`, `POST /revoke/{token}` | NIST Protect, FTC |

### 4.2 Gaps Identified and Remediation Status

| Gap | Compliance Violation | Framework | Severity | Status |
|-----|---------------------|-----------|---------|--------|
| **Gap 1 - No file type validation** | `POST /upload` accepted `.php`, `.sh`, `.exe` - unreasonable security practice | FTC Section 5<br>NIST Protect | High | **Remediated** |
| **Gap 2 - Expired files never deleted** | Files retained indefinitely after token expiry - violates storage limitation | GDPR Art. 5(1)(e)<br>FTC Section 5 | High | **Remediated** |
| **Gap 3 - Unauthenticated download (IDOR)** | `GET /download/{token}` required no authentication | FTC Section 5<br>GDPR Art. 32 | Critical | **Remediated** |
| **Gap 4 - Hardcoded API token** | `API_TOKEN` hardcoded in `docker-compose.yml` and committed to version control | FTC Section 5 | High | **Remediated** |

### 4.3 Remediation Details

**Gap 1 - File Type Validation**
- `ALLOWED_EXTENSIONS` set added to `main.py` - permits `.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.docx`, `.xlsx`, `.csv`
- Extension check on every upload - rejected files return HTTP 422
- Verification: `POST /upload` with `shell.php` returns 422

**Gap 2 - Data Retention Enforcement**
- `cleanup_expired_files()` added to `main.py` - deletes files with no active unexpired links
- Runs on every `GET /health` call
- Verification: file uploaded with 1-minute expiry deleted after `/health` call

**Gap 3 - Download Authentication**
- `Depends(require_auth)` added to `GET /download/{token}`
- `slowapi` rate limiting at 5 req/min per IP
- Verification: unauthenticated request returns HTTP 401

**Gap 4 - API Token Externalization**
- `API_TOKEN` removed from `docker-compose.yml`
- Token loaded from `.env` via `python-dotenv`
- `.env` added to `.gitignore`
- Verification: `grep API_TOKEN docker-compose.yml` returns no output

---

## 5. Audit Summary

| Item | Framework | Status |
|------|-----------|--------|
| Audit logging | FTC Section 5, GDPR Art. 32 | Compliant |
| Authentication on write endpoints | NIST Protect, FTC | Compliant |
| File type validation | FTC Section 5, NIST Protect | Compliant |
| Data retention enforcement | GDPR Art. 5(1)(e), FTC | Compliant |
| Unauthenticated download (IDOR) | FTC Section 5, GDPR Art. 32 | Compliant |
| Hardcoded API token | FTC Section 5 | Compliant |

---

## 6. References

1. Federal Trade Commission Act, 15 U.S.C. § 45.
   https://www.ftc.gov/legal-library/browse/statutes/federal-trade-commission-act

2. FTC, "Start with Security: A Guide for Business" (2023).
   https://www.ftc.gov/business-guidance/resources/start-security-guide-business

3. FTC v. Blackbaud, Inc. - FTC Order (February 2024).
   https://www.ftc.gov/news-events/news/press-releases/2024/02/ftc-order-will-require-blackbaud-delete-unnecessary-data-boost-safeguards-settle-charges-its-lax

4. FTC Privacy and Security Enforcement.
   https://www.ftc.gov/news-events/topics/protecting-consumer-privacy-security/privacy-security-enforcement

5. General Data Protection Regulation (GDPR), Regulation (EU) 2016/679.
   https://gdpr-info.eu/

6. GDPR, Article 32 - Security of Processing.
   https://gdpr-info.eu/art-32-gdpr/

7. GDPR, Article 82 - Right to Compensation and Liability.
   https://gdpr-info.eu/art-82-gdpr/

8. GDPR, Article 83 - General Conditions for Imposing Administrative Fines.
   https://gdpr-info.eu/art-83-gdpr/

9. NIST Cybersecurity Framework 2.0 (CSWP 29), February 2024.
   https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final

10. DLA Piper, "GDPR Fines and Data Breach Survey: January 2024."
    https://www.dlapiper.com/en/insights/publications/2024/01/dla-piper-gdpr-fines-and-data-breach-survey-january-2024

11. IBM Security, "Cost of a Data Breach Report 2025."
    https://www.ibm.com/reports/data-breach

12. Washington State Breach Notification Law, RCW 19.255.010.
    https://app.leg.wa.gov/rcw/default.aspx?cite=19.255.010

13. Atlantic Council, "Reasonable Cybersecurity in Forty-Seven Cases" (2025).
    https://www.atlanticcouncil.org/in-depth-research-reports/report/reasonable-cybersecurity-in-forty-seven-cases-the-federal-trade-commissions-enforcement-actions-against-unfair-and-deceptive-cyber-practices/
