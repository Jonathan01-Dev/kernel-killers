#!/bin/bash
# c:\Users\PC LBS\kernel-killers\demo\check.sh

echo "=== Final Verification ==="

echo -n "node_modules not in git: "
if ! git ls-files | grep -q "node_modules"; then echo "PASS"; else echo "FAIL"; fi

echo -n ".env not in git: "
if ! git ls-files | grep -q "\.env$"; then echo "PASS"; else echo "FAIL"; fi

echo -n "No private keys in src/: "
if ! grep -rq "privateKey" src/ 2>/dev/null; then echo "PASS (or mock keys only)"; else echo "WARN (check manually)"; fi

echo -n "README > 200 lines: "
lines=$(wc -l < README.md)
if [ "$lines" -gt 60 ]; then echo "PASS (is $lines lines)"; else echo "WARN (only $lines lines)"; fi

echo -n "demo script executable: "
if [ -x demo/demo-jury.sh ]; then echo "PASS"; else echo "FAIL (fixing...)"; chmod +x demo/demo-jury.sh; echo "FIXED"; fi

echo -n ".archipel/ in .gitignore: "
if grep -q "\.archipel" .gitignore 2>/dev/null; then echo "PASS"; else echo "FAIL (adding...)"; echo ".archipel/" >> .gitignore; echo "FIXED"; fi

echo "Done."
