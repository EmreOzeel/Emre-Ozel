#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# validate_collector_switch.sh — Verify Go collector is running and accepting logs
# ══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/validate_collector_switch.sh <JWT_TOKEN>

set -euo pipefail

TOKEN="${1:-}"
if [ -z "$TOKEN" ]; then
  echo "Usage: $0 <JWT_TOKEN>"
  exit 1
fi

BASE_URL="${2:-http://localhost:8001}"

echo "═══════════════════════════════════════════════════════════════"
echo " Collector Switch Validation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

echo "1. Checking Go collector status..."
STATUS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/api/collector/status" 2>/dev/null || echo '{"error":"unreachable"}')
echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"
echo ""

# Check running field
RUNNING=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('running', False))" 2>/dev/null || echo "unknown")
if [ "$RUNNING" != "True" ]; then
  echo "  WARNING: Collector is not running (running=$RUNNING)"
fi

echo "2. Checking syslog port binding..."
ss -ulnp 2>/dev/null | grep 5514 || echo "  (ss not available or port not bound on host)"
echo ""

echo "3. Sending test syslog line (PaloAlto TRAFFIC)..."
echo '<134>1,2026/04/17 10:00:00,0009C100001,TRAFFIC,end,2049,2026/04/17 10:00:00,10.0.0.5,8.8.8.8,0.0.0.0,0.0.0.0,test-rule,,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,syslog-profile,2026/04/17 10:00:00,12345,1,54321,53,0,0,0x400000,udp,allow,100,80,20,2,2026/04/17 09:59:58,2,any,0,123456789,0x0,10.0.0.0-10.255.255.255,United States,0,1,1' \
  | nc -u -w1 localhost 5514 2>/dev/null || echo "  (nc not available, trying with bash)"
echo ""

echo "4. Waiting 3 seconds for processing..."
sleep 3

echo "5. Checking collector stats after ingestion..."
STATUS2=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/api/collector/status" 2>/dev/null || echo '{"error":"unreachable"}')
echo "$STATUS2" | python3 -m json.tool 2>/dev/null || echo "$STATUS2"
echo ""

echo "6. Checking if event was ingested..."
EVENTS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/api/live-events?limit=1&source_ip=10.0.0.5" 2>/dev/null || echo '{"error":"unreachable"}')
echo "$EVENTS" | python3 -m json.tool 2>/dev/null || echo "$EVENTS"
echo ""

echo "═══════════════════════════════════════════════════════════════"
echo " Done"
echo "═══════════════════════════════════════════════════════════════"
