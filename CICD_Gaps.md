# CI/CD Gaps: Path to Full Automation

**Version:** 1.0  
**Linked Documents:** Threat Model, Security Testing

---

## Current State

| Step | Status |
|------|--------|
| Code checkout on push/PR | Implemented |
| Unit tests via pytest  | Implemented |
| Code coverage reporting | Implemented |
| Docker image build | Implemented |
| Container startup and health check | Implemented |
| Integration tests via bash + curl | Implemented |
| Security finding documentation in CI output | Implemented |
| Fail-fast on functional test failure | Implemented |
| Container teardown after run | Implemented |

The pipeline runs two sequential jobs: `unit-tests` and `integration-tests`. Integration tests only run if unit tests pass.

---

## Gap 1 - No Continuous Deployment (CD)

**Current state:** The pipeline builds and tests but never deploys. There is no automated path from a passing CI run to a running environment.

**What full CD requires:**
- A target deployment environment (staging, production)
- Automated image push to a container registry (Docker Hub, ECR, GHCR)
- Deployment step that pulls the new image and restarts the service
- Environment-specific configuration management

---

## Gap 2 - No Secret Management in CI

**Current state:** `API_TOKEN` is hardcoded in `docker-compose.yml` and passed as a plaintext environment variable in the workflow. 

**What full CI/CD requires:**
- Secrets stored in GitHub Actions Secrets
- Workflow references secrets via `${{ secrets.API_TOKEN }}`
- No credentials in any committed file

**Immediate fix:**
```yaml
env:
  API_TOKEN: ${{ secrets.API_TOKEN }}
```


---

## Gap 3 - No Static Analysis or Dependency Scanning

**Current state:** The pipeline runs no static analysis on Python code and no vulnerability scanning on dependencies or Docker images. A CVE in `fastapi`, `uvicorn`, or the base image would not be detected.

**What full CI/CD requires:**
- `pip audit` on `requirements.txt` at build time
- `trivy` image scanning after Docker build
- `bandit` for Python static security analysis

**Example additions to `ci.yml`:**
```yaml
- name: Scan dependencies
  run: pip install pip-audit && pip-audit -r app/requirements.txt

- name: Scan Docker image
  run: trivy image sfep_api:latest --exit-code 1 --severity HIGH,CRITICAL
```

---

## Gap 4 - Security Findings Do Not Block CI

**Current state:** Security tests in `automate_tests.sh` document known vulnerabilities but do not block CI. This is intentional for v0.1.0 since the vulnerabilities are documented in the Threat Model.

**What full CI/CD requires:**
- Security tests become blocking once vulnerabilities are remediated
- Separate `security` job that fails on regression
- Integration with a vulnerability tracking tool

---

## Gap 5 - No Automated Rollback

**Current state:** No automated rollback if a deployment fails. Recovery is manual per the Operational Runbook.

**What full CI/CD requires:**
- Health check after deployment with automatic rollback
- Docker Compose or Kubernetes rolling update strategy
