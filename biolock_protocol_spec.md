# 🔐 BioLock: Cryptographic Protocol & Implementation Specification

This document defines the cryptographic parameters, verification mechanics, and backend transaction flow for the BioLock Hybrid authentication system (Tier 1: Device Passkeys, Tier 2: Physical Smart Cards).

---

## 1. The Core Verification Protocol

The transaction signing process must prevent the client application from altering transaction parameters or fabricating the challenge. The backend remains the single source of truth.

### Hybrid Verification Flow (Tier 1 & Tier 2)
```
[Mobile Client]             [Spring Boot Backend]          [Security Anchor]
     │                                │                           │
     │ 1. Initiate Auth Request       │                           │
     ├───────────────────────────────►│                           │
     │                                │ 2. Generate Nonce & Challenge
     │                                │    Store in DB (PENDING)  │
     │ 3. Return Challenge + Payload  │                           │
     ◄────────────────────────────────┤                           │
     │                                                            │
     │ 4. Request Biometric Signature (WebAuthn or NFC APDU)      │
     ├───────────────────────────────────────────────────────────►│
     │                                                            │ 5. Perform Biometric Verification
     │                                                            │    Sign Challenge via ECDSA (P-256)
     │ 6. Cryptographic Signature Payload                         │    Return Signature to Client
     ◄────────────────────────────────────────────────────────────┤
     │                                │
     │ 7. Submit Signature payload for Verification
     ├───────────────────────────────►│
     │                                │ 8. Verify ECDSA signature (JCA)
     │                                │    Atomically consume challenge
     │                                │    Evaluate Duress Flag
     │                                │    IF DURESS: Route to 24hr Escrow
     │                                │    ELSE: Settle immediately
     │ 9. Return Unified HTTP SUCCESS │
     ◄────────────────────────────────┤
```

---

## 2. Canonical Transaction Binding

To prevent signature verification failures caused by JSON variations, keys must be serialized into a strictly defined, length-prefixed binary structure or canonical CBOR representation before hashing.

### BioLock Message Structure (V2)
```text
BioLockMessageV2 =
    protocolVersion (1 byte)
    authType (1 byte: 0x01 = Passkey, 0x02 = Smart Card)
    domain (UTF-8, length-prefixed)
    accountIdHash (32 bytes)
    transactionId (UTF-8, length-prefixed)
    amountMinorUnits (8 bytes, unsigned integer representing paise/cents)
    currency (3 bytes, ISO 4217 uppercase, e.g., INR)
    beneficiaryHash (32 bytes)
    nonce (32 bytes, 256-bit cryptographically secure random value)
    issuedAt (8 bytes, epoch timestamp)
    expiresAt (8 bytes, epoch timestamp)
    duressFlag (1 byte: 0x00 = Standard, 0x01 = Duress Active)
```

---

## 3. Tier-Specific Authentication Mechanics

### Tier 1: Software Passkeys (WebAuthn / FIDO2)
*   **Signature Generation**: The Android client invokes the system Credential Manager API, prompting the OS biometric interface. The phone's internal **TPM / Secure Enclave** signs the challenge payload.
*   **Signature Format**: Standard WebAuthn assertion payload containing the clientDataJSON and authenticatorData, verified on the Spring Boot side using the registered public key.

### Tier 2: Physical Smart Cards (NFC APDU Polling)
*   **Polling Loop**: To prevent connection timeouts while the user places their finger on the card's sensor, the app pings the card using a non-blocking status loop:
    *   `INIT_AUTH(challenge)` ──► Starts card-side sensor scanning. Returns `0x9100` (Pending).
    *   `GET_STATUS` (Polled every 300ms) ──► Returns `0x9100` (Pending), `0x9000` (Success), or `0x6985` (Failed).
    *   `GET_SIGNATURE` ──► Fetches the generated signature payload once `0x9000` is returned.

---

## 4. Cryptographic Specifications

### Signature Format (ECDSA)
*   **Curve**: `secp256r1` (NIST P-256).
*   **Hash**: `SHA-256`.
*   **Malleability Mitigation**: Enforce low-$s$ signatures ($s \le n/2$, where $n$ is the order of the curve) to prevent transaction-malleability attacks.
*   **Format Normalization**: Java JCA `Signature.verify()` expects **ASN.1 DER-encoded** signatures (`SEQUENCE { r, s }`). If the card outputs raw P1363 format (`r || s`, 64 bytes), the Spring Boot service must parse and translate it to DER format before invoking the verifier.
*   **Null Checks**: Always verify that signature components `r` and `s` are greater than zero to prevent signature-bypass vulnerabilities.

---

## 5. Delayed Escrow Duress Protocol

To ensure victim safety during active duress (threat of violence or digital scam coercion), the system must never output error codes or alert the attacker.

### Operations:
1.  **Card/Passkey Signature Generation**: When a registered duress finger is scanned, the signature is generated with the `duressFlag` bit set to `0x01`.
2.  **Generic Success Response**: The backend verifies the signature. If the duress bit is active, the API immediately returns `200 OK` with a success payload to the client app (preventing the attacker from detecting the alarm).
3.  **24-Hour Settlement Escrow**: The transaction is marked as `ESCROW_HOLD` in the PostgreSQL database. The funds are held in an escrow buffer for exactly 24 hours.
4.  **Silent Alarm**: designated emergency contacts are alerted, and a security log is created. The user has 24 hours to cancel the transaction before any assets leave their account.
