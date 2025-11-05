#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <broker_ip>"
    echo "Example: $0 192.168.0.123"
    exit 1
fi

cd "$(dirname "$0")/../../src"

echo "              Starting KEMTLS Client                          "

if [ ! -f "kemtls_client_enhanced" ]; then
    echo " Client not found. Run: make all"
    exit 1
fi

./kemtls_client_enhanced "$1"
