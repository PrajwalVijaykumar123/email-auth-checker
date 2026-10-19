#!/bin/sh
# Starts a real local DNS server with fixed records (good/partial/bad/none
# posture domains), then runs the real checker.py against it over real
# UDP DNS queries to 127.0.0.1 - no mocked resolver.
set -e
cd "$(dirname "$0")/.."

python3 -c "
import sys
sys.path.insert(0, 'test_fixtures')
from test_dns_server import start_server
srv = start_server(port=15353)
import time
time.sleep(60)
" &
SERVER_PID=$!
sleep 1

echo "== good-domain.test: expect grade A =="
python3 checker.py good-domain.test --nameserver 127.0.0.1 --port 15353 --dkim-selectors selector1 > /tmp/eac_good.txt 2>&1 || true
cat /tmp/eac_good.txt
grep -q "Overall grade: A" /tmp/eac_good.txt && echo "PASS: good-domain graded A" || { echo "FAIL: expected grade A"; kill $SERVER_PID; exit 1; }

echo
echo "== bad-domain.test: expect grade F (and '+all' flagged) =="
python3 checker.py bad-domain.test --nameserver 127.0.0.1 --port 15353 > /tmp/eac_bad.txt 2>&1 || true
cat /tmp/eac_bad.txt
grep -q "Overall grade: F" /tmp/eac_bad.txt && echo "PASS: bad-domain graded F" || { echo "FAIL: expected grade F"; kill $SERVER_PID; exit 1; }
grep -q "+all" /tmp/eac_bad.txt && echo "PASS: '+all' misconfiguration flagged" || { echo "FAIL: expected +all to be flagged"; kill $SERVER_PID; exit 1; }

echo
echo "== none-domain.test: expect all three checks to fail (no records at all) =="
python3 checker.py none-domain.test --nameserver 127.0.0.1 --port 15353 > /tmp/eac_none.txt 2>&1 || true
cat /tmp/eac_none.txt
grep -q "No SPF record found" /tmp/eac_none.txt && echo "PASS: missing SPF correctly reported" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "No DMARC record found" /tmp/eac_none.txt && echo "PASS: missing DMARC correctly reported" || { echo "FAIL"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/eac_good.txt /tmp/eac_bad.txt /tmp/eac_none.txt
echo
echo "All tests passed."
