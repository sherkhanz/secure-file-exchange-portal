#!/bin/bash
# =============================================================================
# SFEP Automated Test Suite
# =============================================================================

BASE_URL="${BASE_URL:-http://localhost:8000}"
API_TOKEN="${API_TOKEN:-supersecret-mock-token}"
TEST_FILE="/tmp/sfep_test_file.txt"
PASS=0
FAIL=0
SECURITY_FINDINGS=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass()    { echo -e "${GREEN}[PASS]${NC} $1";  ((PASS++)); }
fail()    { echo -e "${RED}[FAIL]${NC} $1";    ((FAIL++)); }
finding() { echo -e "${YELLOW}[VULN]${NC} $1"; ((SECURITY_FINDINGS++)); }

echo "=================================================="
echo " SFEP Automated Test Suite"
echo " Target: $BASE_URL"
echo "=================================================="

# --- Preflight: verify API is reachable ---
echo ""
echo "[ Preflight ] API reachability check"
if ! curl -s --max-time 5 "$BASE_URL/health" > /dev/null; then
  echo -e "${RED}[ERROR]${NC} API not reachable at $BASE_URL — is docker compose running?"
  exit 2
fi
echo "API is reachable."

# --- Setup ---
echo "sfep test file content $(date)" > "$TEST_FILE"

# ==============================================================================
# FUNCTIONAL TEST 1: Health Check
# ==============================================================================
echo ""
echo "[ Functional Test 1 ] Health Check"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
if [ "$RESPONSE" == "200" ]; then
  pass "GET /health returned 200 OK"
else
  fail "GET /health returned $RESPONSE (expected 200)"
fi

# ==============================================================================
# FUNCTIONAL TEST 2: Upload file
# ==============================================================================
echo ""
echo "[ Functional Test 2 ] Upload file and get 200 OK"
UPLOAD_RESPONSE=$(curl -s -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@$TEST_FILE")

FILE_ID=$(echo "$UPLOAD_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['file_id'])" 2>/dev/null)

if [ -n "$FILE_ID" ]; then
  pass "POST /upload returned file_id: $FILE_ID"
else
  fail "POST /upload failed — no file_id returned. Response: $UPLOAD_RESPONSE"
fi

# ==============================================================================
# FUNCTIONAL TEST 3: Create download link
# ==============================================================================
echo ""
echo "[ Functional Test 3 ] Create download link"
LINK_RESPONSE=$(curl -s -X POST "$BASE_URL/links" \
  -H "x-api-token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"file_id\": \"$FILE_ID\", \"expires_in_minutes\": 60}")

TOKEN=$(echo "$LINK_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

if [ -n "$TOKEN" ]; then
  pass "POST /links returned token: $TOKEN"
else
  fail "POST /links failed — no token returned. Response: $LINK_RESPONSE"
fi

# ==============================================================================
# FUNCTIONAL TEST 4: Auth enforcement
# ==============================================================================
echo ""
echo "[ Functional Test 4 ] Auth — Upload without token returns 401"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -F "file=@$TEST_FILE")

if [ "$HTTP_CODE" == "401" ]; then
  pass "POST /upload without token returned 401 — auth is enforced"
else
  fail "POST /upload without token returned $HTTP_CODE (expected 401)"
fi

# ==============================================================================
# FUNCTIONAL TEST 5: Revoke token and verify 410
# ==============================================================================
echo ""
echo "[ Functional Test 5 ] Revoke token — verify 410 on download"
curl -s -X POST "$BASE_URL/revoke/$TOKEN" \
  -H "x-api-token: $API_TOKEN" > /dev/null

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "x-api-token: $API_TOKEN" \
  "$BASE_URL/download/$TOKEN")

if [ "$HTTP_CODE" == "410" ]; then
  pass "Revoked token returned 410 Gone — revocation works"
else
  fail "Revoked token returned $HTTP_CODE (expected 410)"
fi

# ==============================================================================
# SECURITY TEST 1: SEC-IDOR-001 — Download requires authentication
# ==============================================================================
echo ""
echo "[ Security Test 1 ] SEC-IDOR-001 — Download without token returns 401"

UPLOAD2=$(curl -s -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@$TEST_FILE")
FILE_ID2=$(echo "$UPLOAD2" | python3 -c "import sys,json; print(json.load(sys.stdin)['file_id'])" 2>/dev/null)
LINK2=$(curl -s -X POST "$BASE_URL/links" \
  -H "x-api-token: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"file_id\": \"$FILE_ID2\", \"expires_in_minutes\": 60}")
TOKEN2=$(echo "$LINK2" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/$TOKEN2")
if [ "$HTTP_CODE" == "401" ]; then
  pass "SEC-IDOR-001: /download/{token} returned 401 without auth — endpoint is protected"
else
  fail "SEC-IDOR-001: /download/{token} returned $HTTP_CODE (expected 401) — endpoint is not protected"
fi

# ==============================================================================
# SECURITY TEST 2: SEC-UPLOAD-001 — PHP webshell rejected
# ==============================================================================
echo ""
echo "[ Security Test 2 ] SEC-UPLOAD-001 — PHP webshell rejected with 422"
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@/tmp/shell.php")

if [ "$UPLOAD_CODE" == "422" ]; then
  pass "SEC-UPLOAD-001: PHP webshell rejected with 422 — file type validation is working"
else
  fail "SEC-UPLOAD-001: PHP webshell returned $UPLOAD_CODE (expected 422) — validation missing"
fi

# ==============================================================================
# SECURITY TEST 3: SEC-AUTH-001 — API token absent from docker-compose.yml
# ==============================================================================
echo ""
echo "[ Security Test 3 ] SEC-AUTH-001 — API token not hardcoded in docker-compose.yml"

if grep -q "API_TOKEN:.*[a-zA-Z0-9]" docker-compose.yml 2>/dev/null; then
  fail "SEC-AUTH-001: API_TOKEN found in docker-compose.yml — token is hardcoded"
else
  pass "SEC-AUTH-001: API_TOKEN absent from docker-compose.yml — token is externalized"
fi

# ==============================================================================
# SECURITY TEST 4: SEC-AUTH-001 — .env in .gitignore
# ==============================================================================
echo ""
echo "[ Security Test 4 ] SEC-AUTH-001 — .env listed in .gitignore"

if grep -q "\.env" .gitignore 2>/dev/null; then
  pass "SEC-AUTH-001: .env is listed in .gitignore — token excluded from version control"
else
  fail "SEC-AUTH-001: .env not found in .gitignore — token may be committed to repository"
fi

# ==============================================================================
# SECURITY TEST 5: SEC-AUTH-002 — Rate limiting on /upload returns 429
# ==============================================================================
echo ""
echo "[ Security Test 5 ] SEC-AUTH-002 — Rate limiting on /upload returns 429"

RATE_HIT=0
for i in {1..6}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/upload" \
    -H "x-api-token: $API_TOKEN" \
    -F "file=@$TEST_FILE")
  if [ "$CODE" == "429" ]; then
    RATE_HIT=1
    break
  fi
done

if [ "$RATE_HIT" == "1" ]; then
  pass "SEC-AUTH-002: Rate limit triggered — 429 returned after threshold on /upload"
else
  fail "SEC-AUTH-002: No 429 returned after 6 requests — rate limiting not working on /upload"
fi

# ==============================================================================
# SECURITY TEST 6: SEC-IDOR-002 — Rate limiting on /download returns 429
# ==============================================================================
echo ""
echo "[ Security Test 6 ] SEC-IDOR-002 — Rate limiting on /download returns 429"

RATE_HIT_DL=0
for i in {1..6}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-api-token: $API_TOKEN" \
    "$BASE_URL/download/$TOKEN2")
  if [ "$CODE" == "429" ]; then
    RATE_HIT_DL=1
    break
  fi
done

if [ "$RATE_HIT_DL" == "1" ]; then
  pass "SEC-IDOR-002: Rate limit triggered — 429 returned after threshold on /download"
else
  fail "SEC-IDOR-002: No 429 returned after 6 requests — rate limiting not working on /download"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=================================================="
echo " Functional Tests : $PASS passed, $FAIL failed"
echo " Security Findings: $SECURITY_FINDINGS known vulnerabilities documented"
echo "=================================================="

if [ "$FAIL" -gt 0 ]; then
  echo " CI STATUS: FAILED — fix functional test failures before merging"
  exit 1
else
  echo " CI STATUS: PASSED"
  exit 0
fi
