# 🔐 BioLock: Cryptographic Protocol & Implementation Specification

This document defines the strict cryptographic, mobile-to-card APDU, and backend verification protocol for the BioLock system. All implementations (Android SDK and Spring Boot backend) must comply with these specifications.

---

## 1. The Core Verification Protocol

The transaction signing process must prevent the Android client from altering the transaction details or fabricating the challenge. The backend serves as the single source of truth for the transaction parameters.

```
[Android App]               [Spring Boot Backend]               [Biometric Card]
      │                               │                                 │
      │ 1. Initiate Auth Request      │                                 │
      ├──────────────────────────────►│                                 │
      │                               │ 2. Generate Nonce & Challenge   │
      │                               │    Store transaction in DB      │
      │ 3. Challenge + Payload Hash   │                                 │
      ◄───────────────────────────────┤                                 │
      │                                                                 │
      │ 4. Start NFC Session & Send APDU (Challenge)                    │
      ├────────────────────────────────────────────────────────────────►│
      │                                                                 │ 5. Verify Fingerprint
      │                                                                 │    Sign Hash Offline
      │ 6. Opaque Encrypted Envelope (AEAD)                             │    Generate Signature
      ◄─────────────────────────────────────────────────────────────────┤
      │                               │
      │ 7. Submit Envelope for Settlement
      ├──────────────────────────────►│
      │                               │ 8. Decrypt Envelope
      │                               │    Verify ECDSA Signature
      │                               │    Atomically Consume Challenge
      │                               │    Execute Duress Logic
      │ 9. Standard HTTP Response     │
      ◄───────────────────────────────┤
```

---

## 2. Canonical Transaction Binding

To prevent signature verification failures caused by JSON whitespace, key ordering, or formatting variations, all signed payloads must use a strictly defined, length-prefixed binary structure or canonical CBOR.

### BioLock Message Structure (V1)
```text
BioLockMessageV1 =
    protocolVersion (1 byte)
    domain (UTF-8, length-prefixed)
    issuerId (UTF-8, length-prefixed)
    accountIdHash (32 bytes)
    cardKeyId (UTF-8, length-prefixed)
    transactionId (UTF-8, length-prefixed)
    amountMinorUnits (8 bytes, unsigned integer representing paise/cents)
    currency (3 bytes, ISO 4217 uppercase, e.g., INR)
    beneficiaryHash (32 bytes)
    deviceKeyId (UTF-8, length-prefixed)
    nonce (32 bytes, 256-bit cryptographically secure random value)
    issuedAt (8 bytes, epoch timestamp)
    expiresAt (8 bytes, epoch timestamp)
    policyVersion (4 bytes)
    duressPolicyVersion (4 bytes)
```

### Replay & Substitution Prevention
1.  **Atomic Challenge Table**: The backend must track challenges via a database table enforcing a strict state machine: `CREATED ──► CONSUMED` or `CREATED ──► EXPIRED`.
2.  **Double Hash Prevention**: The backend and card must align on hashing. The card signs `SHA-256(CanonicalEncode(BioLockMessageV1))`. Do not double-hash the digest.
3.  **Strict Verification Bindings**: The backend must compare the signed parameters against the pre-stored transaction record. Never trust transaction variables returned exclusively by the mobile client.

---

## 3. Android APDU State Machine & Polling

To prevent Android `IsoDep` connection timeouts while the user is placing their finger on the sensor, **do not block a single APDU request**. Instead, implement a non-blocking status polling loop.

### APDU Command Flow
1.  **SELECT AID** (Select Card Applet) ──► Returns Success immediately.
2.  **INIT_AUTH(challenge)** ──► Card stores the challenge and begins biometric sensor verification. Returns a fast status word (`0x9100`).
3.  **GET_STATUS** (Polled by Android app every 200–500ms) ──► Returns:
    *   `0x9100`: Fingerprint matching still pending.
    *   `0x9000`: Success (ready to signature fetch).
    *   `0x6985`: Verification failed or user cancelled.
4.  **GET_SIGNATURE** ──► Fetches the generated opaque envelope after `0x9000` status.

### Android Guidelines
*   Always execute NFC transactions on a background worker thread (Coroutines/Dispatchers.IO).
*   Do not blindly retransmit the `SIGN` command after a network/NFC exception. If the card matched the finger and generated the signature, repeating the command could create a duplicate transaction conflict. Recover using `GET_STATUS` or `GET_RESULT` with the same `challengeId`.

---

## 4. Cryptographic Specifications

### Signature Format (ECDSA)
*   **Curve**: `secp256r1` (NIST P-256).
*   **Hash**: `SHA-256`.
*   **Malleability Mitigation**: Enforce low-$s$ signatures ($s \le n/2$, where $n$ is the order of the curve).
*   **Format Normalization**: Java JCA `Signature.verify()` expects **ASN.1 DER-encoded** signatures (`SEQUENCE { r, s }`). If the card secure element outputs raw P1363 format (`r || s`, 64 bytes), the Spring Boot service must parse and translate it to DER format before invoking the verifier.
*   **Psychic Signature Check**: Always verify that signature components `r` and `s` are not zero (`r >= 1` and `s >= 1`).

---

## 5. Covert Duress Envelope

To prevent a compromised Android app (or overlay malware) from detecting the duress state and alerting the attacker, the card must encapsulate the duress state inside an encrypted envelope.

### Envelope Construction
1.  **Generate Plaintext Message**:  
    `M = CanonicalEncode(..., duressState, cardCounter)`
2.  **Generate Signature**:  
    `sig = ECDSA_sign(cardPrivateKey, SHA-256(M))`
3.  **Derive Session Key**: The card and backend derive a temporary symmetric key via Elliptic Curve Diffie-Hellman (ECDH).
4.  **Encrypt Envelope (AEAD)**: The card encrypts the payload using AES-GCM:  
    `C = AES_GCM_Encrypt(sessionKey, nonce, Plaintext(M || sig), AssociatedData = challengeId)`
5.  **Output**: The card returns the opaque ciphertext `C` to the Android client. The app cannot inspect `C` to check if `duressState == true`.

### Silent Backend Actions
*   The backend decrypts `C` and verifies the signature.
*   If `duressState` is active, the backend returns a generic success/processing code to the app to maintain the user's safety.
*   The backend silently freezes the transaction, triggers an alert to designated emergency contacts, and logs the security event in the database for forensic recovery.
