#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# compare_backends.sh — Verify Go backend matches Python backend responses
# ══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/compare_backends.sh <JWT_TOKEN>
#   ./scripts/compare_backends.sh <JWT_TOKEN> [PYTHON_URL] [GO_URL]
#   ./scripts/compare_backends.sh <JWT_TOKEN> --body   # compare JSON keys too
#
# Compares HTTP status codes (and optionally JSON shapes) for both backends.

set -euo pipefail

TOKEN=""
PYTHON_URL="http://localhost:8000"
GO_URL="http://localhost:8001"
CHECK_BODY=false

# Parse args
for arg in "$@"; do
  case "$arg" in
    --body) CHECK_BODY=true ;;
    http://*|https://*)
      if [ -z "$TOKEN" ]; then TOKEN="$arg"
      elif [ "$PYTHON_URL" = "http://localhost:8000" ]; then PYTHON_URL="$arg"
      else GO_URL="$arg"
      fi
      ;;
    *)
      if [ -z "$TOKEN" ]; then TOKEN="$arg"; fi
      ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "Usage: $0 <JWT_TOKEN> [PYTHON_URL] [GO_URL] [--body]"
  exit 1
fi

ENDPOINTS=(
  "GET /api/health"
  "GET /api/auth/me"
  "GET /api/analyses?limit=3"
  "GET /api/live-events?limit=3"
  "GET /api/live-events/stats"
  "GET /api/live-flows?limit=3"
  "GET /api/live-flows/stats"
  "GET /api/live-incidents?limit=3"
  "GET /api/notifications?limit=3"
  "GET /api/notifications/unread-count"
  "GET /api/suppressions"
  "GET /api/work-queue"
  "GET /api/dashboard/summary"
  "GET /api/correlation-rules"
  "GET /api/threat-feeds"
  "GET /api/threat-indicators?limit=3"
  "GET /api/baselines"
  "GET /api/geo/cache-stats"
  "GET /api/users"
  "GET /api/attack-sessions?limit=3"
  "GET /api/path-analysis/saved-queries"
  "GET /api/path-analysis/presets"
  "GET /api/path-monitors"
)

# JSON keys that must be present in Go response (for --body mode)
declare -A EXPECTED_KEYS
EXPECTED_KEYS["/api/health"]="status,version"
EXPECTED_KEYS["/api/live-events?limit=3"]="total,offset,limit,events"
EXPECTED_KEYS["/api/live-flows?limit=3"]="total,offset,limit,flows"
EXPECTED_KEYS["/api/live-incidents?limit=3"]="total,incidents"
EXPECTED_KEYS["/api/notifications/unread-count"]="unread"
EXPECTED_KEYS["/api/work-queue"]="sections,total_open,counts"
EXPECTED_KEYS["/api/dashboard/summary"]="collector,live_events,risk_scores,auto_detections,work_queue,analyses"
EXPECTED_KEYS["/api/threat-indicators?limit=3"]="total,items"

PASS=0
FAIL=0
SKIP=0
BODY_FAIL=0

echo "═══════════════════════════════════════════════════════════════"
echo " Backend Comparison: Python vs Go"
echo " Python: $PYTHON_URL"
echo " Go:     $GO_URL"
echo " Body:   $CHECK_BODY"
echo "═══════════════════════════════════════════════════════════════"
echo ""

for ep in "${ENDPOINTS[@]}"; do
  METHOD=$(echo "$ep" | cut -d' ' -f1)
  EPATH=$(echo "$ep" | cut -d' ' -f2)

  PY_RESP=$(curl -s -w "\n%{http_code}" \
    -X "$METHOD" -H "Authorization: Bearer $TOKEN" \
    "${PYTHON_URL}${EPATH}" 2>/dev/null || echo -e "\nERR")
  PY_BODY=$(echo "$PY_RESP" | head -n -1)
  PY_STATUS=$(echo "$PY_RESP" | tail -1)

  GO_RESP=$(curl -s -w "\n%{http_code}" \
    -X "$METHOD" -H "Authorization: Bearer $TOKEN" \
    "${GO_URL}${EPATH}" 2>/dev/null || echo -e "\nERR")
  GO_BODY=$(echo "$GO_RESP" | head -n -1)
  GO_STATUS=$(echo "$GO_RESP" | tail -1)

  if [ "$PY_STATUS" = "ERR" ] || [ "$GO_STATUS" = "ERR" ]; then
    printf "  SKIP  %-50s  Py=%-4s  Go=%-4s\n" "$METHOD $EPATH" "$PY_STATUS" "$GO_STATUS"
    SKIP=$((SKIP+1))
    continue
  fi

  STATUS_OK=true
  if [ "$PY_STATUS" != "$GO_STATUS" ]; then
    STATUS_OK=false
  fi

  # Body key comparison (if enabled)
  BODY_OK=true
  BODY_NOTE=""
  if [ "$CHECK_BODY" = true ] && [ "$GO_STATUS" = "200" ]; then
    KEYS_SPEC="${EXPECTED_KEYS[$EPATH]:-}"
    if [ -n "$KEYS_SPEC" ]; then
      IFS=',' read -ra KEYS <<< "$KEYS_SPEC"
      for key in "${KEYS[@]}"; do
        if ! echo "$GO_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert '$key' in d" 2>/dev/null; then
          BODY_OK=false
          BODY_NOTE="missing key: $key"
          break
        fi
      done
    fi
  fi

  if $STATUS_OK && $BODY_OK; then
    printf "  PASS  %-50s  Py=%-4s  Go=%-4s\n" "$METHOD $EPATH" "$PY_STATUS" "$GO_STATUS"
    PASS=$((PASS+1))
  elif ! $STATUS_OK; then
    printf "  FAIL  %-50s  Py=%-4s  Go=%-4s  STATUS MISMATCH\n" "$METHOD $EPATH" "$PY_STATUS" "$GO_STATUS"
    FAIL=$((FAIL+1))
  else
    printf "  FAIL  %-50s  Py=%-4s  Go=%-4s  %s\n" "$METHOD $EPATH" "$PY_STATUS" "$GO_STATUS" "$BODY_NOTE"
    BODY_FAIL=$((BODY_FAIL+1))
    FAIL=$((FAIL+1))
  fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$CHECK_BODY" = true ]; then
  echo " Body mismatches: $BODY_FAIL"
fi
echo "═══════════════════════════════════════════════════════════════"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
