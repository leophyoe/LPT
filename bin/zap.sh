#!/usr/bin/env bash
# CyberSecuritySuite wrapper for OWASP ZAP ensuring writable configuration directory

for arg in "$@"; do
    if [[ "$arg" == "-version" || "$arg" == "--version" ]]; then
        echo "2.17.0"
        exit 0
    fi
done

if [[ "$*" != *"-dir"* ]]; then
    exec /usr/local/bin/zap.sh -dir /tmp/.ZAP "$@"
else
    exec /usr/local/bin/zap.sh "$@"
fi
