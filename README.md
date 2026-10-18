# @qmoosa/pqc-hybrid-tls-protocol

[![CI Gate](https://github.com/elon00/qmoosa-pqc-hybrid-tls-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/elon00/qmoosa-pqc-hybrid-tls-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> QMOOSA Post-Quantum Cryptography Suite — Hybrid Classical/Post-Quantum TLS 1.3 Key Exchange Protocol Specification.

## Overview

`@qmoosa/pqc-hybrid-tls-protocol` defines the canonical protocol types, parameter constants, serialization logic, and validation schemas for hybrid key exchange in TLS 1.3 per IETF draft-ietf-tls-hybrid-design and NIST FIPS 203.

## Primary Group: `X25519MLKEM768` (0x11ec)

- **Classical Component:** ECDH over Curve25519 (RFC 7748) — 32-byte public key.
- **Post-Quantum Component:** NIST FIPS 203 ML-KEM-768 (Kyber768) — 1,184-byte encapsulation key, 1,088-byte ciphertext.
- **ClientKeyShare:** 1,216 bytes (`X25519_pk || MLKEM768_ek`).
- **ServerKeyShare:** 1,120 bytes (`X25519_pk || MLKEM768_ct`).
- **Combined Shared Secret:** 64 bytes (`SS_pqc || SS_ecdh`).

## Build & Test

```bash
npm install
npm run build
npm test
npm run lint
```

## Reality Gate Status

- Production Deployment Status: **LOCKED (0 / 1,000 certified)**
- Local Reality-Gate Verification: **ACTIVE**
