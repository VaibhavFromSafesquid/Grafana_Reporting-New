#!/bin/bash
set -u
SECRETS=(
  "SqKnv1M=kuZkOyJjgY78"
  "Sarva@1234"
  "10.200.2.141"
  "10.200.2.137"
  "10.200.2.133"
  "10.200.2.132"
  "10.200.2.126"
)
FAIL=0
for s in "${SECRETS[@]}"; do
  hits=$(grep -rn --binary-files=without-match --exclude-dir=.git --exclude=sanitize.py --exclude=prepush-verify.sh -F "$s" . 2>/dev/null)
  if [ -n "$hits" ]; then
    echo "SECRET LEAK: found '$s' in:"
    echo "$hits" | sed 's/^/    /'
    FAIL=1
  fi
done
if [ $FAIL -ne 0 ]; then
  echo ""
  echo "REFUSING TO PUSH. Fix sanitize.py, re-run: python3 scripts/sanitize.py"
  exit 1
fi
echo "prepush-verify: clean, safe to push."
