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

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/$TOKEN")

if [ "$HTTP_CODE" == "410" ]; then
  pass "Revoked token returned 410 Gone — revocation works"
else
  fail "Revoked token returned $HTTP_CODE (expected 410)"
fi

# ==============================================================================
# SECURITY TEST 1: IDOR — Unauthenticated Download (known vulnerability)
# ==============================================================================
echo ""
echo "[ Security Test 1 ] IDOR — Unauthenticated download (known vulnerability)"

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
if [ "$HTTP_CODE" == "200" ]; then
  finding "SEC-IDOR-001: /download/{token} returned 200 with NO auth — VULNERABILITY CONFIRMED (T-1)"
else
  pass "SEC-IDOR-001: /download/{token} returned $HTTP_CODE — endpoint is protected"
fi

# ==============================================================================
# SECURITY TEST 2: Unrestricted Upload — PHP webshell (known vulnerability)
# ==============================================================================
echo ""
echo "[ Security Test 2 ] Unrestricted Upload — PHP webshell (known vulnerability)"
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@/tmp/shell.php")

if [ "$UPLOAD_CODE" == "200" ]; then
  finding "SEC-UPLOAD-001: PHP webshell accepted with HTTP 200 — no file type validation (T-3)"
else
  pass "SEC-UPLOAD-001: PHP webshell rejected with $UPLOAD_CODE — validation is working"
fi

# ==============================================================================
# OPERATIONAL RISK TEST 1: Storage Threshold Check (OR-1)
# ==============================================================================
echo ""
echo "[ OR-1 Test ] Storage threshold — oversized file rejected with 413"
dd if=/dev/urandom of=/tmp/oversized_test.txt bs=1M count=21 2>/dev/null

OVERSIZE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@/tmp/oversized_test.txt")

if [ "$OVERSIZE_CODE" == "413" ]; then
  pass "OR-1: 21 MB file rejected with 413 — storage guard is active"
else
  fail "OR-1: 21 MB file returned $OVERSIZE_CODE (expected 413) — storage guard is missing"
fi
rm -f /tmp/oversized_test.txt

# ==============================================================================
# OPERATIONAL RISK TEST 2: Concurrent Upload Load Test (OR-2 / OR-3)
# ==============================================================================
echo ""
echo "[ OR-2/OR-3 Test ] Concurrent uploads — 5 parallel requests"
echo "concurrent load test content" > /tmp/concurrent_test.txt

CONCURRENT_RESULTS=()
for i in {1..5}; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/upload" \
    -H "x-api-token: $API_TOKEN" \
    -F "file=@/tmp/concurrent_test.txt") &
  CONCURRENT_RESULTS+=($!)
done

CONCURRENT_FAIL=0
for pid in "${CONCURRENT_RESULTS[@]}"; do
  wait "$pid"
done

HEALTH_AFTER=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health")
if [ "$HEALTH_AFTER" == "200" ]; then
  pass "OR-2/OR-3: API healthy after 5 concurrent uploads — no lock or OOM crash"
else
  fail "OR-2/OR-3: API returned $HEALTH_AFTER after concurrent load — possible lock or crash"
  ((FAIL++))
fi
rm -f /tmp/concurrent_test.txt

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
