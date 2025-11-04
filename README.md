# PQ-RGuard+: Post-Quantum Replay-Safe TLS for IoMT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Raspberry Pi](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)](https://www.raspberrypi.org/)
[![Crypto: Kyber-512](https://img.shields.io/badge/Crypto-ML--KEM--512-blue)](https://pq-crystals.org/kyber/)

> **Phase 1:** Post-Quantum KEMTLS with MQTT for Resource-Constrained IoMT Devices

A lightweight, quantum-resistant communication protocol for Internet of Medical Things (IoMT) combining:
- 🔐 **ML-KEM-512** (NIST-standardized post-quantum cryptography)
- ⚡ **KEMTLS-PDK** (signature-free authentication)
- 📡 **MQTT-over-TLS** (IoT messaging protocol)
- 🏥 **IoMT-optimized** (low latency, energy-efficient)

---

## 📊 **Performance Highlights**

| Metric | Value | Comparison |
|--------|-------|------------|
| **Handshake** | 9 ms | 32% faster than regular PQCTLS |
| **Pure Crypto** | 1.2 ms | Competitive with embedded systems |
| **Memory** | 22 KB | Suitable for constrained devices |
| **Energy** | 0.36 mJ | Ultra-low power |

---

## 🏗️ **System Topology**
```
┌─────────────────────────────────────────────────────────────┐
│                      IoMT Network                           │
│                                                             │
│   ┌──────────────┐         KEMTLS         ┌──────────────┐  │
│   │ IoMT Client  │◄────────(8884)────────►│    Broker    │  │
│   │ (Pi Client)  │  Post-Quantum TLS      │   (Pi 5)     │  │
│   │              │   ML-KEM-512           │              │  │
│   └──────────────┘                        └──────┬───────┘  │
│        │                                         │          │
│        │ Sensor Data:                            │ Plain    │
│        │ {"hr":85, "temp":36.3}                  │ MQTT     │
│        │ (Encrypted!)                            ↓          │
│        │                                  ┌──────────────┐  │
│        └─────────────────────────────────►│  Mosquitto   │  │
│          Encrypted MQTT Channel           │    Broker    │  │
│                                           └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 **Quick Start**

### **Prerequisites**
- Raspberry Pi 5 (or Pi 4)
- Raspberry Pi OS (64-bit, Bookworm)
- 2 Pis for full test (or 1 Pi + VM)

### **Installation**
```bash
git clone https://github.com/MoazElssayed/PQ-RGuard-Phase1.git
cd PQ-RGuard-Phase1
chmod +x scripts/install/*.sh
./scripts/install/setup-all.sh
```

### **Run Demo**
```bash
# Terminal 1 - Broker
./scripts/test/run-broker.sh

# Terminal 2 - Client
./scripts/test/run-client.sh broker_ip
```

---

## 📚 **Documentation**

- 📖 [Installation Guide](docs/setup/INSTALL.md)
- 🏗️ [Architecture Overview](docs/architecture/ARCHITECTURE.md)
- 🔐 [Protocol Specification](docs/architecture/PROTOCOL.md)
- 📊 [Performance Analysis](docs/PERFORMANCE.md)

---

## 📁 **Repository Structure**
```
PQ-RGuard-Phase1/
├── src/                      # Source code
│   ├── kemtls.c/h           # Core KEMTLS
│   ├── kemtls_metrics.c/h   # Performance metrics
│   ├── mqtt_protocol.c/h    # MQTT framing
│   ├── kemtls_client_enhanced.c
│   └── kemtls_broker_enhanced.c
├── docs/                     # Documentation
├── diagrams/                 # Visual docs
├── benchmarks/              # Benchmark scripts
├── scripts/                 # Automation
└── results/                 # Benchmark data
```

---

## 🛠️ **Technology Stack**

- **PQC:** liboqs 0.15.0-rc1 (NEON optimized)
- **TLS:** OpenSSL 3.5.1
- **MQTT:** Mosquitto 2.x
- **Compiler:** GCC 14.2 -O3 -march=native
- **Platform:** ARM64 Raspberry Pi OS

---

## 📄 **License**

MIT License - See [LICENSE](LICENSE)

---
