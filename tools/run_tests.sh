#!/bin/bash
# Runs the unit suites in parallel from a source checkout (needs: python 3.12+, cryptography; `tor` only for the real-Tor tests, which skip without it).
# Usage: tools/run_tests.sh [python]      (default python: python3). Logs: /tmp/sigilnet_suite_<dir>.log
cd "$(dirname "$0")/.." || exit 1
PY="${1:-python3}"
export SIGIL_PARALLEL=1
dirs=$(cd sigilnet && ls -d tests tests_adv* | sort)
rm -f /tmp/sigilnet_suite_*.log
for d in $dirs; do
  "$PY" -m unittest discover -s "sigilnet/$d" -t . -p "test*.py" > "/tmp/sigilnet_suite_$d.log" 2>&1 &
done
wait
fail=0
for d in $dirs; do
  line="$(grep -E '^Ran|^OK|^FAILED' "/tmp/sigilnet_suite_$d.log" | tr '\n' ' ')"
  echo "$d: $line"
  case "$line" in *FAILED*|"") fail=1;; esac
done
exit $fail
