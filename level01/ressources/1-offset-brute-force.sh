#/bin/bash
# 1-offset-brute-force.sh
set -e

count=1
while [[ $count -lt 100 ]]; do
    if ! printf 'a%.0s' $(seq 1 $count) | ./case >/dev/null; then
        echo "Crashed !"
        echo "Crashed with count = $count"
        exit 1
    fi
    ((count++))
done