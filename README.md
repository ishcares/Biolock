# 🔒 BioLock: Cryptographic Hardware-Anchored UPI Security Core

BioLock is a B2B zero-trust authentication SDK that enables banks and payment applications to require physical biometric hardware verification (via NFC smart cards) to authorize high-value transactions, completely bypassing the vulnerabilities of SMS OTP and mobile-screen biometrics.

---

## 🎯 The Problem

Following the RBI's April 2026 mandate enforcing two-factor authentication for digital transactions, SMS OTP is no longer legally sufficient. However, a major security gap remains: **Account Takeover and Recovery**. 
*   Attackers hijack phone numbers via **SIM-swapping** to reset net-banking passwords, recover credentials, and bypass standard authentication gates.
*   Victims typically discover a SIM swap only after their phone loses signal, giving attackers a critical window to compromise linked accounts.

---

## 💡 The Solution

BioLock shifts the **Root of Trust** entirely off the phone and onto a physical biometric smart card (cold storage):

1.  **Hardware-Bound Signatures**: The private signing key is locked inside the card's secure enclave. It never leaves the card and is only unlocked via a physical thumbprint scan on the card itself.
2.  **NFC Data Exchange**: The phone's UPI app acts as an NFC reader, sending the transaction challenge to the card and receiving an ECDSA signature back.
3.  **Covert Duress Defense**: If forced to authorize a transaction under physical threat, scanning a registered "Duress Finger" (e.g., pinky) signs the payload but silently embeds a covert flag. The bank's backend silently freezes the transfer and triggers an emergency alarm, while showing a fake "network timeout" to the attacker.

---

## 🛠️ The Software Architecture

```
[Mobile App / Browser]
        │
        ▼ POST /api/transactions
[Spring Boot REST Controller]
        │
        ├─► Write to PostgreSQL (Status: PENDING)
        ├─► Write Transaction ID to Redis (10-second TTL)
        │
        ▼ (User taps card within 10 seconds)
[POST /api/transactions/{id}/verify]
        │
        ├─► Read public key + ECDSA signature from request
        ├─► Verify signature using Java Cryptography Architecture (JCA)
        │
        ├─► IF VALID:
        │       ├─► Update PostgreSQL status to APPROVED
        │       └─► Delete Redis key (disarm the timer)
        │
        └─► IF TIMER EXPIRES (Redis TTL = 0):
                └─► Background job updates PostgreSQL status to EXPIRED
```

---

## ⚙️ Tech Stack
*   **Backend**: Java 17, Spring Boot 3, Maven
*   **Database**: PostgreSQL
*   **Cache/Timer**: Redis (TTL locks)
*   **Container**: Docker (Alpine base, < 100MB)
*   **Cryptography**: Java Cryptography Architecture (ECDSA/SHA-256)
