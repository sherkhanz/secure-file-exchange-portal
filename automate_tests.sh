#!/bin/bash
# =============================================================================
# SFEP Automated Test
# =============================================================================

BASE_URL="http://localhost:8000"
API_TOKEN="supersecret-mock-token"
TEST_FILE="/tmp/sfep_test_file.txt"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }

echo "=================================================="
echo " SFEP Automated Test Suite"
echo " Target: $BASE_URL"
echo "=================================================="

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
# FUNCTIONAL TEST 2: Upload + Download full workflow
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
# SECURITY TEST 1: IDOR — Unauthenticated Download
# ==============================================================================
echo ""
echo "[ Security Test 1 ] IDOR — Unauthenticated download via known token"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/$TOKEN")

if [ "$HTTP_CODE" == "200" ]; then
  fail "SEC-IDOR-001: /download/$TOKEN returned 200 with NO auth header — VULNERABILITY CONFIRMED"
else
  pass "SEC-IDOR-001: /download/$TOKEN returned $HTTP_CODE — endpoint is protected"
fi

# ==============================================================================
# SECURITY TEST 2: Auth — Missing token returns 401
# ==============================================================================
echo ""
echo "[ Security Test 2 ] Auth — Upload without token returns 401"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -F "file=@$TEST_FILE")

if [ "$HTTP_CODE" == "401" ]; then
  pass "SEC-AUTH-001: POST /upload without token returned 401 — auth is enforced"
else
  fail "SEC-AUTH-001: POST /upload without token returned $HTTP_CODE (expected 401)"
fi

# ==============================================================================
# SECURITY TEST 3: Unrestricted Upload — PHP webshell accepted
# ==============================================================================
echo ""
echo "[ Security Test 3 ] Unrestricted Upload — PHP webshell accepted"
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

UPLOAD_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$BASE_URL/upload" \
  -H "x-api-token: $API_TOKEN" \
  -F "file=@/tmp/shell.php")

if [ "$UPLOAD_CODE" == "200" ]; then
  fail "SEC-UPLOAD-001: PHP webshell accepted with HTTP 200 — no file type validation"
else
  pass "SEC-UPLOAD-001: PHP webshell rejected with $UPLOAD_CODE — validation is working"
fi

# ==============================================================================
# SECURITY TEST 4: Revoke token and verify access denied
# ==============================================================================
echo ""
echo "[ Security Test 4 ] Revoke token — verify 410 on download"
curl -s -X POST "$BASE_URL/revoke/$TOKEN" \
  -H "x-api-token: $API_TOKEN" > /dev/null

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/download/$TOKEN")

if [ "$HTTP_CODE" == "410" ]; then
  pass "Revoked token returned 410 Gone — revocation works"
else
  fail "Revoked token returned $HTTP_CODE (expected 410)"
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=================================================="
echo " Results: $PASS passed, $FAIL failed"
echo "=================================================="

if [ "$FAIL" -gt 0 ]; then
  exit 1
else
  exit 0
fi
