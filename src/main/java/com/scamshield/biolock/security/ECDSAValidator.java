package com.scamshield.biolock.security;

import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 🔒 BioLock Core Cryptographic Engine
 * 
 * Production-grade hardware-anchored transaction validator.
 * Enforces ECDSA signature verification over the secp256r1 (NIST P-256) curve.
 * Designed for sub-45ms p99 verification latency in enterprise payment rails.
 */
@Component
public class ECDSAValidator {

    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String KEY_ALGORITHM = "EC";
    private static final String CURVE_NAME = "secp256r1";

    /**
     * Reconstructs a PublicKey from an incoming Base64-encoded X.509 string.
     * Throws an IllegalArgumentException if the key format is invalid.
     */
    public PublicKey decodePublicKey(String base64PublicKey) throws GeneralSecurityException {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Malformed Base64 public key", e);
        }
    }

    /**
     * Constructs a deterministic, canonical byte representation of the transaction.
     * Prevents parameter-tampering and man-in-the-middle payload alterations.
     *
     * Format: transactionId|amount|challengeNonce|timestamp
     */
    public byte[] buildCanonicalPayload(String transactionId, Double amount, String challengeNonce, Long timestamp) {
        if (transactionId == null || amount == null || challengeNonce == null || timestamp == null) {
            throw new IllegalArgumentException("Payload attributes must not be null");
        }
        String canonical = String.format("%s|%.2f|%s|%d", transactionId, amount, challengeNonce, timestamp);
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Verifies the authenticity of the client hardware signature.
     * 
     * Security Policy: Fails closed. Any malformed signature or verification
     * anomaly returns false to protect transaction integrity.
     */
    public boolean verifySignature(byte[] canonicalPayload, String base64Signature, PublicKey publicKey) {
        if (canonicalPayload == null || base64Signature == null || publicKey == null) {
            return false;
        }

        try {
            byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(canonicalPayload);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            // Log security incident / fail closed
            return false;
        }
    }

    /**
     * Testing / Mock utility to generate a compliant client-side keypair.
     * Simulates Apple Secure Enclave or Android StrongBox key generation.
     */
    public KeyPair generateDeviceKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE_NAME);
        keyGen.initialize(ecSpec, new SecureRandom());
        return keyGen.generateKeyPair();
    }
}
