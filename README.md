# Post-Quantum Cryptography with liboqs + CGO

[![Go Version](https://img.shields.io/badge/Go-1.18+-blue.svg)](https://golang.org)
[![liboqs](https://img.shields.io/badge/liboqs-latest-green.svg)](https://github.com/open-quantum-safe/liboqs)
[![License](https://img.shields.io/badge/license-BSD--3--blue.svg)](LICENSE)

**High-performance replacement for Cloudflare CIRCL when you only need PQC algorithms**

This library provides Go bindings to [liboqs](https://github.com/open-quantum-safe/liboqs) C implementations, offering significant performance improvements over CIRCL's pure Go PQC implementations.

---

## Author

**Gaurav Pandey**  
Post-Quantum Cryptography Research

---

## Overview.

This library provides quantum-resistant cryptography for Go applications through CGO bindings to the Open Quantum Safe liboqs library.

### Why Use This Instead of CIRCL?

| Feature | CIRCL (Pure Go) | This Library (liboqs+CGO) |
|---------|-----------------|---------------------------|
| **Language** | Pure Go | Optimized C via CGO |
| **Performance** | Slower | Faster |
| **KEMs** | ~3 algorithms | 35 algorithms |
| **Signatures** | ~3 algorithms | 221 algorithms |
| **NIST Standards** | ML-KEM, ML-DSA | ML-KEM, ML-DSA |
| **Additional Algorithms** | Limited | Falcon, SPHINCS+, BIKE, Classic-McEliece |

---

## Features

- Kyber512/768/1024 (ML-KEM-512/768/1024) - Key Encapsulation
- Dilithium2/3/5 (ML-DSA-44/65/87) - Digital Signatures
- Falcon-512/1024 - Compact signatures
- SPHINCS+ (200+ variants) - Stateless hash-based signatures
- 35 KEM algorithms from liboqs
- 221 signature algorithms from liboqs

---

## Installation

### Prerequisites

**macOS (Homebrew):**

