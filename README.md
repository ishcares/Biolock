# 🔒 BioLock: Cryptographic Hardware-Anchored UPI Security Core

BioLock is a B2B zero-trust authentication SDK that enables banks and payment applications to require hardware-bound biometric verification to authorize high-value transactions, completely bypassing the vulnerabilities of SMS OTP and mobile-screen software biometrics.

---

## 🎯 The Problem

Following the RBI's April 2026 mandate enforcing two-factor authentication for digital transactions, SMS OTP is no longer legally sufficient. However, a major security gap remains: **Account Takeover and Recovery**. 
*   Attackers hijack phone numbers via **SIM-swapping** to reset net-banking passwords, recover credentials, and bypass standard authentication gates.
*   Victims typically discover a SIM swap only after their phone loses signal, giving attackers a critical window to compromise linked accounts.
*   Forcing retail users to carry a physical smart card for daily ₹50 UPI transactions introduces high friction and prohibitive distribution costs.

---

## 💡 The Solution: BioLock 2.0 (The Hybrid Moat)

BioLock operates as a **two-tiered Software + Hardware authentication platform** to balance extreme security with frictionless mass-market scaling:

### 1. Tier 1: Software Passkeys (Mass Market - 95%)
*   **Mechanism**: Leverages your JCA/ECDSA backend using the user's smartphone's built-in **Secure Enclave / TPM chip** via the **WebAuthn / FIDO2** standard.
*   **Cost**: Near zero (pure SaaS deployment).
*   **User Experience**: Tapping native biometrics (FaceID/Android Fingerprint) signs the transaction challenge using device-bound private keys.

### 2. Tier 2: Physical Smart Cards (High-Value / Corporate - 5%)
*   **Mechanism**: A premium **biometric NFC smart card** issued for safeguarding high-value, corporate treasury, or merchant transactions.
*   **Cost**: Premium corporate expense.
*   **User Experience**: The private key never leaves the card. The card scans the user's fingerprint offline on the card itself, generating an ECDSA signature transmitted to the phone via NFC.

---

## 🔒 Advanced Duress Protocol: 24-Hour Delayed Escrow

Showing a "Network Timeout" or a failed error screen to an attacker during physical coercion or "Digital Arrest" scams is highly dangerous for the victim. 

BioLock implements a **Delayed Escrow Settlement**:
1.  If the user scans their registered **"Duress Finger"** (or inputs a duress passkey), the application displays a green checkmark showing **"Transaction Successful"** to the attacker.
2.  The Spring Boot backend silently flags the transaction and routes the funds into a **24-hour Security Hold (Escrow Queue)**.
3.  This gives the victim a 24-hour safety window to escape, contact the police, and cancel the transaction before any money is actually transferred to the recipient.

---

## 🛠️ The Software Architecture

```
[Mobile App / WebAuthn Client]
        │
        ▼ POST /api/transactions
[Spring Boot REST Controller]
        │
        ├─► Write to PostgreSQL (Status: PENDING)
        ├─► Write Transaction ID to Redis (10-second TTL)
        │
        ▼ (User validates Passkey or NFC Card within 10 seconds)
[POST /api/transactions/{id}/verify]
        │
        ├─► Read public key + ECDSA signature from request payload
        ├─► Verify signature using Java Cryptography Architecture (JCA)
        │
        ├─► IF VALID & DURESS ACTIVE:
        │       ├─► Update PostgreSQL status to ESCROW_HOLD (24-hour queue)
        │       ├─► Return generic SUCCESS code to the mobile app
        │       └─► Delete Redis key (disarm the timer)
        │
        ├─► IF VALID & STANDARD:
        │       ├─► Update PostgreSQL status to APPROVED (immediate settlement)
        │       └─► Delete Redis key (disarm the timer)
        │
        └─► IF TIMER EXPIRES (Redis TTL = 0):
                └─► Background job updates PostgreSQL status to EXPIRED
```

---

## ⚙️ Tech Stack
*   **Backend**: Java 17, Spring Boot 3, Maven
*   **Database**: PostgreSQL (Transactional ledger)
*   **Cache/Timer**: Redis (10-second challenge TTL locks)
*   **Container**: Docker (Lightweight Alpine base)
*   **Cryptography**: Java Cryptography Architecture (ECDSA/SHA-256 on secp256r1)
