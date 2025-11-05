# Installation Guide

## Quick Install
```bash
git clone https://github.com/MoazElssayed/PQ-RGuard-Phase1.git
cd PQ-RGuard-Phase1
./scripts/install/setup-all.sh
```

## Manual Installation

See full instructions in repository README.md

## Verification
```bash
# Run loopback test
./scripts/test/run-broker.sh &
sleep 2
./scripts/test/run-client.sh 127.0.0.1
```

Expected output:
```
✓ KEMTLS handshake complete
✓ MQTT CONNECTED
📤 Published sensor data
```
