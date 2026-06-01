# Runbook Reflection: Secure File Exchange Portal

**Version:** 1.0  
**Linked Documents:** Operational Runbook, Simulated Incident

---

## 1. Were the steps easy to follow and understand?

Overall yes - the three-phase structure (Detection → Response → Recovery) made navigation straightforward during the simulation. Each phase had specific commands that could be copy-pasted directly into the terminal without interpretation.

---

## 2. Can the runbook be simplified further?

Yes - three specific simplifications:

| Current State | Simplified Version |
|--------------|-------------------|
| Manual SQLite query to find compromised tokens | Single script that queries audit_log and auto-revokes all tokens from a specific IP |
| Separate commands for revoke and block IP | Combined incident response script: `./respond.sh <IP> <TOKEN>` |
| Manual health check after recovery | Health check embedded at end of every response script as automatic verification step |

The most impactful simplification would be a single `incident_response.sh` script that accepts an attacker IP as an argument and executes revocation, blocking, and verification in sequence.

---

## 3. Steps that should be automated further

**Token revocation on threshold breach:**
Currently the on-call engineer must manually identify and revoke tokens after receiving a Discord alert. This should be automated - when the Failed Downloads alert fires, a webhook could trigger an auto-revocation script via Grafana's webhook contact point.

**IP blocking on spike detection:**
Blocking the attacker IP requires manual identification from logs and a manual `curl` command. This should be triggered automatically when the brute-force threshold is exceeded, with the identified IP extracted from the audit log and blocked via the `/block/{ip}` endpoint without human intervention.

**Post-incident audit log export:**
After recovery, the engineer should export a snapshot of the audit_log for documentation. This step is currently fully manual and should be scripted to run automatically as the final recovery step.

---

## 4. Automated steps that need manual supplementation

**Grafana alerting - threshold tuning:**
The alert fires at 10 failed downloads in 5 minutes. In a real environment, legitimate users may also generate failed downloads from typos or expired links. The threshold needs manual tuning based on observed baseline traffic - automation alone cannot determine the right value without human review of normal usage patterns.

**IP blocking - false positive risk:**
The `/block/{ip}` endpoint blocks at the application level in-memory. Because `172.22.0.1` is the Docker gateway IP, automatically blocking it would cut off all traffic from the host machine. Any automated IP blocking logic requires a manual whitelist of known safe IPs to be maintained - automation cannot safely operate without this human-defined exclusion list.

**Recovery verification:**
The automated health check (`GET /health`) confirms the API is running but does not verify data integrity - it cannot confirm whether any files were exfiltrated before tokens were revoked. A manual review of `successful_download` events in the audit log is always required post-incident to assess the full scope of exposure.
