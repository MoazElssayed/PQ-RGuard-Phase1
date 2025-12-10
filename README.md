# PQ-RGuard: Post-Quantum KEMTLS for IoMT

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Raspberry Pi](https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red)](https://www.raspberrypi.org/)
[![Crypto: ML-KEM-512](https://img.shields.io/badge/Crypto-ML--KEM--512-blue)](https://pq-crystals.org/kyber/)

A lightweight, quantum-resistant communication protocol for Internet of Medical Things (IoMT) devices. This project implements KEMTLS (Key Encapsulation Mechanism TLS) using ML-KEM-512 (Kyber), the NIST-standardized post-quantum key encapsulation algorithm.

---

## Why Post-Quantum Cryptography for IoMT?

Current TLS relies on RSA and ECDH, which will be broken by quantum computers. Medical devices have long lifecycles (10-15 years), meaning devices deployed today may still be active when quantum computers become practical. PQ-RGuard addresses this by implementing quantum-resistant cryptography optimized for resource-constrained IoMT devices.

---

## Architecture

```
┌──────────────┐         KEMTLS (8884)        ┌──────────────┐
│  IoMT Client │◄────────────────────────────►│    Broker    │
│  (Raspberry  │    ML-KEM-512 + AES-GCM      │  (Raspberry  │
│   Pi Client) │                              │    Pi 5)     │
└──────────────┘                              └──────┬───────┘
       │                                             │
       │  Encrypted sensor data:                     │
       │  {"hr":85, "temp":36.3}                     ↓
       │                                      ┌──────────────┐
       └─────────────────────────────────────►│  Mosquitto   │
                                              │    (MQTT)    │
                                              └──────────────┘
```

---

## KEMTLS Handshake Protocol

Unlike traditional TLS which uses signatures for authentication, KEMTLS uses key encapsulation:

```
Client                                         Broker
   │                                              │
   │─────────── ClientHello + Client PK ─────────►│
   │                                              │ Verify client
   │◄──────────── ServerHello ────────────────────│
   │◄────────── EncryptedExtensions ──────────────│
   │◄─────────── Certificate (Broker PK) ─────────│
   │                                              │
   │ Verify broker                                │
   │                                              │
   │─────────── KEM Encapsulation ───────────────►│
   │◄──────────── Server KEM CTS ─────────────────│
   │─────────── Client Finished ─────────────────►│
   │◄──────────── Server Finished ────────────────│
   │                                              │
   │◄═══════════ Encrypted Channel ══════════════►│
```

---

## Security Implementation

### Cryptographic Primitives

| Component | Algorithm | Purpose |
| --- | --- | --- |
| Key Encapsulation | ML-KEM-512 (Kyber) | Quantum-resistant key exchange |
| Symmetric Encryption | AES-256-GCM | Data encryption with authentication |
| Key Derivation | PBKDF2-SHA256 | Password-based key derivation |
| Key Storage | AES-256-GCM | Encrypted keys at rest |

### Mutual Authentication

Both parties verify each other before completing the handshake:

1. **Client verification**: Broker checks client's public key against an authorized list
2. **Broker verification**: Client checks broker's public key against a pre-provisioned trusted key

This prevents man-in-the-middle attacks even if an attacker intercepts the handshake.

### Device-Bound Keys

Keys are encrypted using a master key derived from:
- User password
- Device-specific hardware identifiers (CPU serial, SD card CID)

This means encrypted keys cannot be copied to another device.

---

## Performance Results

Measured on Raspberry Pi 5 (ARM Cortex-A76, 2.4GHz):

| Metric | Value |
| --- | --- |
| Handshake Time | 9 ms |
| Pure Crypto Operations | 1.2 ms |
| Memory Usage | 22 KB |
| Energy per Handshake | 0.36 mJ |

---

## Project Structure

```
src/
├── kemtls.c/h              # Core KEMTLS protocol implementation
├── kemtls_metrics.c/h      # Performance measurement utilities
├── mqtt_protocol.c/h       # MQTT packet framing
├── secure_keystore.c/h     # AES-256-GCM encrypted key storage
├── kemtls_broker_secure.c  # Broker with mutual authentication
├── kemtls_client_secure.c  # Client with broker verification
└── pqrguard_provision.c    # Key provisioning tool
```

---

## Key Files Explained

### `kemtls.c` - Core Protocol
Implements the KEMTLS state machine, KEM operations (encapsulation/decapsulation), and key derivation for the encrypted channel.

### `secure_keystore.c` - Encrypted Storage
Provides AES-256-GCM encryption for keys at rest with PBKDF2 key derivation and device binding using hardware identifiers.

### `kemtls_broker_secure.c` - Authenticated Broker
Handles multiple client connections, verifies clients against a trusted list, and proxies decrypted MQTT to Mosquitto.

### `kemtls_client_secure.c` - Authenticated Client
Verifies broker identity before completing handshake, encrypts sensor data, and publishes to MQTT topics.

---

## Technology Stack

| Component | Technology |
| --- | --- |
| Post-Quantum Crypto | liboqs 0.15.0-rc1 (NEON optimized) |
| Symmetric Crypto | OpenSSL 3.5.1 |
| MQTT Broker | Mosquitto 2.x |
| Platform | Raspberry Pi 5, ARM64 |
| Compiler | GCC 14.2, -O3 -march=native |

---

## Team

- Moaz Elsayed
- Rashid Almarri
- Mohammed Almarri
