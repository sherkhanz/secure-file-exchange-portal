# Dashboard Coverage vs Business Impact Analysis: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** OE Dashboard, Operational Risks, Threat Model

---

## 1. Overview

This document compares what the OE Dashboard is currently able to answer against the business impact and continuity analysis established in the Threat Model and Operational Risks documents. The goal is to identify whether the monitoring in place is sufficient to detect and respond to the risks that were identified as most damaging to customers and business operations.

---

## 2. Business Impact Analysis

The business impact analysis identified two categories of risk:

**Security risks** (from Threat_Model.md):
- T-1: Unauthenticated file download / IDOR - confidential data exposure
- T-2: Hardcoded static API token - unauthorized write access
- T-3: Unrestricted file upload - malware delivery, server compromise

**Operational risks** (from Operational_Risks.md):
- OR-1: Storage volume filling up - upload workflow unavailable
- OR-2: SQLite concurrency lock - all endpoints intermittently failing
- OR-3: Container OOM crash - complete service unavailability
- OR-4: API response time degradation - customer-facing slowdowns

---

## 3. Security Threat Coverage Comparison

| Threat | Business Impact | Dashboard Coverage | Coverage Level |
|--------|----------------|--------------------|---------------|
| T-1 IDOR - unauthenticated download | Confidential file exposure, reputational damage, regulatory liability | Failed Downloads (Stat), Revoked/Expired Token Access (Stat), Successful Downloads (Stat) | Partial - detects after the fact. No real-time blocking signal. |
| T-2 Hardcoded token - brute force | Unauthorized uploads, link creation, revocation by attacker | Unauthorized Requests 401 (Stat) - red at 5+ | Good - spike in 401s is a clear early signal. |
| T-3 Unrestricted upload - malware | Malware stored on server, distributed to recipients via download links | Suspicious Uploads (Table) - detects `.php`, `.sh`, `.exe` extensions | Partial - extension-based detection only. Renamed files bypass this panel entirely. |

---

## 4. Operational Risk Coverage Comparison

| Risk | Business Impact | Dashboard Coverage | Coverage Level |
|------|----------------|--------------------|---------------|
| OR-1 Storage filling up | Core upload workflow unavailable - customers cannot share files | Storage Used (Gauge) with orange/red thresholds + Unreferenced Files (Stat) | Good - proactive warning at 15 MB, critical at 19 MB. Unreferenced Files detects accumulation before exhaustion. |
| OR-2 SQLite lock contention | All endpoints return 500 errors - full service degradation | DB Write Contention (Table) - shows minutes with high write intensity | Partial - detects high write concurrency as a leading indicator. Cannot detect an actual lock error because `main.py` does not emit a `db_error` event. |
| OR-3 Container OOM crash | Complete unavailability until restart - active downloads interrupted | Large File Upload (Stat) as proxy + API Status (Table) as static indicator | Partial - Large File Upload is a leading indicator only. API Status panel does not reflect real liveness. Container memory is not measurable from SQLite datasource. |
| OR-4 API latency degradation | Customers experience slow uploads and downloads, potential timeouts | DB Write Contention (Table) + Unreferenced Files (Stat) as indirect proxies | Partial - no direct latency measurement. `main.py` does not emit timing data. Proxies give a general signal but cannot confirm actual response time degradation. |

---

## 5. Overall Assessment

| Category | Business Risk Identified | Dashboard Coverage | Assessment |
|----------|--------------------------|--------------------|------------|
| Security - IDOR | High | Partial | Reactive only - detected after downloads occur |
| Security - token abuse | High | Good | 401 spike is a reliable early signal |
| Security - malicious upload | High | Partial | Extension filter misses renamed files |
| Operations - storage | Critical | Good | Proactive thresholds in place |
| Operations - database lock | Critical | Partial | Leading indicator only, no error event |
| Operations - OOM crash | Critical | Partial | No direct memory metric available |
| Operations - API latency | High | Partial | No timing data emitted by product |

The dashboard provides solid coverage for storage risks and token abuse. The most significant gap relative to the business impact analysis is OR-3 (OOM crash) and OR-4 (API latency), both of which were identified as high-impact but remain without direct monitoring due to SQLite datasource limitations.
