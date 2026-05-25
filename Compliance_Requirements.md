# Compliance Requirements: Secure File Exchange Portal

**Version:** 1.0
**Linked Documents:** Threat Model, Operational Risks

---

## 1. Introduction

The Secure File Exchange Portal (SFEP) is a file-sharing API that allows authenticated users to upload files and generate time-limited download links. Because the system handles potentially sensitive corporate and personal data - including uploaded documents, access tokens, and audit logs - it falls within the scope of multiple US federal compliance frameworks and international regulations. This document defines the compliance requirements that apply to SFEP at the legal, regulatory, and corporate policy levels.

**Compliance landscape summary:**

| Framework | Type | Applicability |
|-----------|------|--------------|
| FTC Act Section 5 | Federal law | Applies to all US-based commercial data handlers |
| GDPR | EU regulation | Applies if any EU residents upload or access files |
| NIST CSF 2.0 | Federal framework | Voluntary but industry-standard for security controls |

---

## 2. Government and Legal Requirements

### 2.1 FTC Act Section 5 - Unfair or Deceptive Acts or Practices

**Source:** 15 U.S.C. § 45; FTC enforcement guidance on data security (2023).

Section 5 of the FTC Act prohibits unfair or deceptive acts or practices in commerce. The FTC applies this authority to data security - any company that fails to implement reasonable security for consumer data can be found to have engaged in an unfair practice. This applies to all US-based commercial systems that handle consumer data, including file-sharing platforms.

**What SFEP must do:**

| Requirement | Description |
|-------------|-------------|
| Reasonable security | Implement and maintain security measures appropriate to the sensitivity of data handled. Lack of access controls on download endpoints is an unfair practice under FTC precedent. |
| Accurate privacy representations | Do not make security claims that are not implemented. If a privacy policy or terms of service state that files are protected, the technical controls must reflect that. |
| Data retention practices | Implement and enforce documented data retention policies. Retaining data indefinitely without purpose is considered unreasonable under FTC enforcement actions (e.g., FTC v. Blackbaud, 2024). |
| Incident response | Have a documented process for identifying, containing, and notifying affected parties of a data security incident. |
| Access control | Restrict access to sensitive data to authorized parties only. Endpoints that allow unauthenticated access to user files are inconsistent with reasonable security standards. |

**FTC "Start with Security" principles applicable to SFEP:**
- Limit access to sensitive data on a need-to-know basis
- Require secure authentication before data access
- Store sensitive data only as long as there is a legitimate business need
- Monitor systems for unauthorized access attempts

---

### 2.2 General Data Protection Regulation (GDPR) - International Users

**Source:** Regulation (EU) 2016/679; applicable to any system processing personal data of EU residents regardless of where the system is operated. If any EU resident uploads a file to SFEP or accesses a download link, GDPR applies to the processing of their personal data.

**What SFEP must do:**

| Requirement | Description |
|-------------|-------------|
| Lawful basis for processing | Identify and document the legal basis for processing each category of personal data (e.g., legitimate interest, contract performance). |
| Data minimization | Collect only what is strictly necessary. Audit log entries should not capture more metadata than required for security monitoring. |
| Storage limitation | Personal data must not be kept longer than necessary for the stated purpose. Download tokens must expire and associated data must be deleted. |
| Right to erasure | Provide a mechanism to delete an EU user's data on request, including uploaded files, links, and audit log entries referencing that user. |
| Security of processing | Implement appropriate technical measures including access controls, encryption at rest and in transit, and audit logging. |

---

### 2.3 NIST Cybersecurity Framework 2.0

**Source:** NIST CSWP 29, February 2024. Voluntary framework; adopted as industry standard by FTC and many regulators as a reference for "reasonable security."

NIST CSF 2.0 organizes cybersecurity requirements across six functions: Govern, Identify, Protect, Detect, Respond, Recover.

**What SFEP must do by function:**

| Function | Requirement for SFEP |
|----------|----------------------|
| Govern | Document security policies, risk tolerance, and compliance obligations. Assign ownership of security controls. |
| Identify | Maintain an inventory of assets (files, tokens, database tables, containers). Identify and document risks (Threat Model, Operational Risks). |
| Protect | Enforce access controls on all write endpoints. Validate file types on upload. Encrypt data at rest and in transit. Implement least-privilege access. |
| Detect | Monitor for unauthorized access attempts, anomalous download patterns, and malicious file uploads via OE Dashboard. |
| Respond | Maintain an operational runbook for incident response covering each identified threat scenario. |
| Recover | Document recovery procedures for data loss, container crash, and database corruption scenarios. |

---

## 3. Corporate Policy Requirements

Internal policies translate legal requirements into enforceable operational controls. The following policies are required for SFEP to operate in compliance with the frameworks above.

### 3.1 Data Retention Policy

| Data Type | Maximum Retention | Basis |
|-----------|------------------|-------|
| Uploaded files | Duration of active download link + 24 hours | GDPR, FTC |
| Download tokens | Until expiry or revocation, then immediate deletion | GDPR, FTC |
| Audit log entries | 90 days | FTC, NIST |

---

### 3.2 Access Control Policy

| Control | Requirement |
|---------|-------------|
| Authentication | All write operations (upload, link creation, revocation) must require a valid API token |
| Download authentication | Download endpoints must require authentication - unauthenticated access is inconsistent with FTC reasonable security and NIST Protect function |
| Token rotation | API tokens must have a defined rotation schedule and must not be hardcoded in version-controlled files |
| Least privilege | The Grafana container has read-only access to the database - this must be maintained |

---

### 3.3 Audit Logging Policy

Audit logs are required under FTC Section 5, NIST Detect, and GDPR Article 32.

| Event | Must Be Logged |
|-------|---------------|
| File upload (created) | File ID, filename, size, timestamp |
| Download link creation | Token, file ID, expiry, timestamp |
| Successful download | Token, file ID, timestamp |
| Failed download attempt | Token, reason, timestamp |
| Revoked / expired link access | Token, timestamp |
| Unauthorized request (401) | Reason, timestamp |

---

### 3.4 Incident Response Policy

Required under FTC Act Section 5 and NIST Respond function.

- A documented runbook must exist for each identified threat scenario
- Security incidents involving personal data must be assessed for notification obligations under applicable state breach notification laws
- The on-call engineer must have clear escalation paths documented

---

### 3.5 Data Subject Rights Policy

Required under GDPR.

| Right | Required Action |
|-------|----------------|
| Right to know | Provide a list of data categories collected on request |
| Right to delete | Delete uploaded files, tokens, and audit log entries linked to the requestor |
| Right to erasure | Full deletion of all personal data linked to an EU user on request |

---

## 4. References

1. Federal Trade Commission Act, 15 U.S.C. § 45 - Unfair or Deceptive Acts or Practices.
   https://www.ftc.gov/legal-library/browse/statutes/federal-trade-commission-act

2. FTC, "Start with Security: A Guide for Business" (2023).
   https://www.ftc.gov/business-guidance/resources/start-security-guide-business

3. FTC Privacy and Security Enforcement. Federal Trade Commission.
   https://www.ftc.gov/news-events/topics/protecting-consumer-privacy-security/privacy-security-enforcement

4. General Data Protection Regulation (GDPR), Regulation (EU) 2016/679.
   https://gdpr-info.eu/

5. GDPR, Article 32 - Security of Processing.
   https://gdpr-info.eu/art-32-gdpr/

6. NIST Cybersecurity Framework 2.0 (CSWP 29), National Institute of Standards and Technology, February 2024.
   https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final

7. NIST, "Cybersecurity Framework 2.0: Resource and Overview Guide" (SP 1299).
   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1299.pdf

8. FTC v. Blackbaud, Inc. — FTC Order (February 2024).
   https://www.ftc.gov/news-events/news/press-releases/2024/02/ftc-order-will-require-blackbaud-delete-unnecessary-data-boost-safeguards-settle-charges-its-lax