# 🔒 BioLock: Hardware-Anchored Transaction Authorization SDK

[![Java](https://img.shields.io/badge/Java-17%20%7C%2021-ED8B00?style=flat&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F?style=flat&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Redis](https://img.shields.io/badge/Redis-In--Memory%20Locks-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io/)
[![Build Status](https://img.shields.io/badge/Tests-Passing%20(100%25)-brightgreen)](https://github.com/ishcares/Biolock)
[![SLA](https://img.shields.io/badge/Verification%20Latency-%3C%202ms-blue)](https://github.com/ishcares/Biolock)

> **BioLock is a developer-first Java/Spring Boot SDK that enables payment gateways and banks to enforce hardware-anchored passkey transaction signing and zero-trust replay protection with sub-2ms verification latency.**

---

## 🎯 The Problem

Modern payment fraud has shifted away from cracking encryption toward exploiting **edge vulnerabilities**:
1. **Credential Theft & SIM-Swapping:** Attackers intercept SMS OTPs or socially engineer credentials to execute unauthorized transfers.
2. **In-Flight Parameter Tampering:** Man-in-the-middle attacks where transaction amounts or recipients are modified between client submission and backend authorization.
3. **Coercion & "Digital Arrest" Scams:** Victims are forced under duress to authorize transactions while attackers monitor the device screen.

---

## 💡 The Solution: Zero-Trust Transaction Signing

BioLock moves payment authentication from **shared secrets (passwords/OTPs)** to **hardware-anchored public-key cryptography**:

* **Hardware-Bound Passkeys (`secp256r1`):** Signs transactions using the device's native hardware chip (Apple Secure Enclave, Android StrongBox, or FIDO2 tokens) via the WebAuthn standard.
* **Canonical Payload Tamper-Resistance:** Deterministically hashes the `transactionId`, `amount`, `challengeNonce`, and `timestamp`. Any in-flight modification of the amount invalidates the signature mathematically.
* **Sub-2ms High-Throughput Engine:** Pure Java Cryptography Architecture (JCA) implementation with zero mutable state, designed for high-concurrency payment rails.
* **Covert Duress Telemetry:** Enables users under duress to trigger a secondary registered passkey. The client UI displays standard completion, while the backend silently flags high-risk telemetry for fraud quarantine.

---

## 🛠️ System Architecture

```
[ Mobile / WebAuthn Client ]
         │
         ▼ 1. POST /api/transactions
[ BioLock Spring Boot Core ]
         │
         ├─► Generates 256-bit Ephemeral Nonce in Redis (10s TTL)
         └─► Returns Challenge Payload to Client
         │
         ▼ 2. Hardware Signs Hash with Private Key (Secure Enclave)
[ Client signs: txId | amount | challengeNonce | timestamp ]
         │
         ▼ 3. POST /api/transactions/{id}/verify
[ BioLock ECDSA Verification Engine ]
         │
         ├─► Fast-Fail Gatekeeper: Validates & consumes 10s Nonce in Redis (<0.5ms)
         ├─► Validates X.509 Public Key & ECDSA Signature over secp256r1
         │
         ├─► IF AUTHENTIC & STANDARD:
         │   └─► Returns HTTP 200 (APPROVED) ──► Immediate Settlement
         │
         ├─► IF AUTHENTIC & DURESS FLAG:
         │   └─► Returns HTTP 200 (APPROVED to UI) ──► Routes to Fraud Quarantine Queue
         │
         └─► IF TAMPERED OR EXPIRED:
             └─► Fails Closed (HTTP 401 UNAUTHORIZED) ──► Rejection Logged
```

---

## 🚀 3-Step QuickStart (Developer Integration)

BioLock is designed for drop-in integration into any existing Spring Boot microservice:

### 1. Add Component Dependency
Inject the `ECDSAValidator` into your payment processing service:

```java
@Autowired
private ECDSAValidator ecdsaValidator;
```

### 2. Request Challenge Nonce
Generate a cryptographically secure 256-bit challenge tied to the transaction:

```java
Transaction tx = transactionService.createTransaction(2500.00, "merchant@upi");
// Redis sets 10-second TTL lock on challenge nonce
```

### 3. Verify Hardware Signature
Validate the incoming client passkey signature against the canonical transaction payload:

```java
byte[] canonicalPayload = ecdsaValidator.buildCanonicalPayload(
    tx.getId(),
    tx.getAmount(),
    tx.getChallenge(),
    tx.getTimestamp()
);

PublicKey publicKey = ecdsaValidator.decodePublicKey(clientBase64PublicKey);
boolean isAuthentic = ecdsaValidator.verifySignature(canonicalPayload, clientSignature, publicKey);

if (!isAuthentic) {
    throw new SecurityException("Transaction signature mismatch or payload tampered");
}
```

---

## 📊 Performance Benchmarks

Benchmarked on Java 24 (OpenJDK) using high-resolution nanosecond telemetry (`BioLockCryptoTest.java`):

| Test Suite | Iterations | Result | Latency Metric |
| :--- | :---: | :---: | :---: |
| **Authentic Transaction Verification** | 1 | **PASSED ✅** | Validates `secp256r1` signature |
| **In-Flight Amount Tampering (`₹2.5k ➔ ₹25k`)** | 1 | **BLOCKED ✅** | Tampered hash rejected mathematically |
| **100-Run Concurrency Latency Benchmark** | 100 | **PASSED ✅** | **Avg ~1.8 ms** (Budget SLA: < 45ms) |
| **Total Test Suite Execution Time** | Complete | **PASSED ✅** | **0.461s total** |

---

## 🛡️ Security & Threat Model

* **Replay Attack Defense:** Challenge nonces are single-use with an ephemeral 10-second Redis TTL. Replayed requests are discarded in memory before invoking elliptic curve calculations.
* **Stateless Verification:** `ECDSAValidator` holds zero mutable state, enabling frictionless horizontal scaling across Kubernetes clusters behind an API gateway.
* **Fail-Closed Policy:** Any malformed signature bytes, decoding errors, or parameter irregularities fail closed and log a security incident.

---

## 📄 License
MIT License. Open-source developer infrastructure. Maintained by [Ishita Chaurasia](https://github.com/ishcares).

<!-- Verified Zero-Trust Cryptographic Core -->

<!-- Hardware-Anchored Co-Verification Engine -->
