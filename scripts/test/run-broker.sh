#!/bin/bash

cd "$(dirname "$0")/../../src"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Starting KEMTLS Broker                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [ ! -f "kemtls_broker_enhanced" ]; then
    echo "❌ Broker not found. Run: make all"
    exit 1
fi

./kemtls_broker_enhanced
