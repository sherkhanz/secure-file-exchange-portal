# Technical Design Document: Secure File Exchange Portal

**Status:** Initial Architecture  
**Version:** 0.1.0  
**Repository:** https://github.com/sherkhanz/secure-file-exchange-portal  

---

## 1. Overview
**Secure File Exchange Portal** is an API-first service for temporary file sharing. A user uploads a file, creates a time-limited download link, and a recipient uses that link to retrieve the file before it expires. The system logs key events for security and operational visibility. The focus is on secure sharing behavior, controlled link lifecycle, and observability.

## 2. Motivation
Internal teams often share files using convenient methods that are hard to monitor or revoke. Long-lived links and limited visibility into access events increase the risk of unauthorized downloads and slow response when a link is leaked.

This project uses a controlled model for file sharing:
*   **Temporary access:** Shared links should expire automatically and support manual revocation.
*   **Auditability:** Uploads, link creation, downloads, and revocation events should be recorded.

## 3. Project Components & Requirements

### 3.1 File Sharing API
*   **Framework:** FastAPI (Python).
*   **Purpose:** Handles upload, link creation, download requests, revocation, and health checks.
*   **Endpoints:** Baseline endpoints include `/upload`, `/links`, `/download/{token}`, `/revoke/{token}`, and `/health`.
*   **Requirement:** Core endpoints must return clear responses for common invalid cases.

### 3.2 Link Expiration and Revocation Logic
*   **Purpose:** Enforces the lifecycle of temporary sharing links.
*   **Requirement:** Expired, revoked, or invalid links must return clear error responses and generate audit events.

### 3.3 Audit Logging
*   **Purpose:** Records security-relevant and operationally useful events.
*   **Events:** Upload created, link generated, successful download, failed download, revoked link access, and expired link access.
*   **Requirement:** Logs must be structured enough to support dashboard summaries and simple incident review.

### 3.4 Basic Access Control
*   **Purpose:** Limits who can upload files, create links, revoke links, and access protected operations.
*   **Requirement:** The baseline version may use simple token-based or hardcoded user access.

### 3.5 Persistence and Storage
*   **Purpose:** Stores file metadata, link state, expiration time, and audit events.
*   **Requirement:** The baseline version must use lightweight persistence through SQLite and local file storage.

### 3.6 OE Dashboard
*   **Purpose:** Provides basic operational and security visibility.
*   **Requirement:** Must run in a separate container and show basic metrics such as link status and download activity.

### 3.7 Service Health Checks
*   **Purpose:** Exposes simple readiness and health indicators for the API.
*   **Requirement:** A `/health` endpoint must confirm that the application is running and return a simple status response.

### 3.8 Infrastructure
*   **Deployment:** Docker + Docker Compose.
*   **Containers:** At minimum, one container for the file-sharing API and one for the OE dashboard.
*   **CI:** A basic CI pipeline must run automated tests for core workflows and validation logic.
*   **Dependency:** The baseline uses external dependencies such as FastAPI and SQLite.

### 3.9 Key Workflows
*   **Workflow 1:** A user uploads a file, creates a temporary link, and a recipient downloads the file successfully before expiration.
*   **Workflow 2:** A recipient attempts to use an expired or revoked link and receives a denied response.
*   **Workflow 3:** A recipient makes repeated failed download attempts, and the events are recorded for operational review.

## 4. Out of Scope
To keep the baseline implementation small and operationally focused, the following are intentionally excluded:
*   **Full user management platform:** No self-service registration, profile management, or account recovery flows.
*   **Enterprise SSO/IAM integration:** No SAML, OIDC, LDAP, or external identity provider integration.
*   **Cloud object storage integration:** No S3, GCS, or other external storage backends in the initial design.

## 5. Practical Technical Decisions

### 5.1 Technology Stack & Rationale
| Decision | Choice | Rationale |
| :--- | :--- | :--- |
| **Backend** | Python / FastAPI | Simple API development, good testing support, and clean handling of request validation. |
| **Database** | SQLite | Low overhead persistence for metadata, link state, and audit events. |
| **File Storage** | Local volume-backed storage | Easy to run in Docker and sufficient for a controlled baseline implementation. |


### 5.2 Tradeoff Decisions
1.  **API-first vs. full web application:**
    *   *Decision:* Build the baseline around an API and minimal dashboard.
    *   *Reason:* This keeps the scope small and makes testing and operational review easier.
2.  **Local storage vs. cloud storage:**
    *   *Decision:* Use local storage in the initial version.
    *   *Reason:* Simpler to deploy, inspect, and test in a course project.
3.  **Simple access control vs. full identity integration:**
    *   *Decision:* Use basic access control only.
    *   *Reason:* The goal is to focus on secure sharing and monitoring, not full IAM.


## 6. Architecture Diagram
```text
[ Uploader / Recipient ]
          |
          v
[ File Sharing API ] <----> [ SQLite Metadata / Audit Logs ]
          |
          +----> [ Local File Storage ]
          |
          +----> [ OE Dashboard ]
```
