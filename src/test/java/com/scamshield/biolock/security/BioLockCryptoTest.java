package com.scamshield.biolock.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class BioLockCryptoTest {

    private ECDSAValidator validator;
    private KeyPair deviceKeys;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private String base64PublicKey;

    @BeforeEach
    void setUp() throws Exception {
        validator = new ECDSAValidator();
        // Simulate an Apple Secure Enclave or Android StrongBox generating an EC
        // secp256r1 keypair
        deviceKeys = validator.generateDeviceKeyPair();
        publicKey = deviceKeys.getPublic();
        privateKey = deviceKeys.getPrivate();
        base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private String signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(key);
        signer.update(data);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    @Test
    @DisplayName("✅ Test 1: Authentic transaction signature verifies successfully")
    void testAuthenticTransactionVerification() throws Exception {
        String txId = "TX-884920";
        Double amount = 2500.00;
        String challengeNonce = "NONCE_7f9b204c81ae";
        Long timestamp = System.currentTimeMillis();

        // 1. Build canonical payload
        byte[] canonicalPayload = validator.buildCanonicalPayload(txId, amount, challengeNonce, timestamp);

        // 2. Hardware signs payload
        String signature = signData(canonicalPayload, privateKey);

        // 3. Verify on server
        PublicKey decodedKey = validator.decodePublicKey(base64PublicKey);
        boolean isAuthentic = validator.verifySignature(canonicalPayload, signature, decodedKey);

        assertTrue(isAuthentic, "Authentic hardware signature should verify to TRUE");
    }

    @Test
    @DisplayName("🛡️ Test 2: Man-In-The-Middle Amount Tampering is Blocked")
    void testTamperedAmountRejection() throws Exception {
        String txId = "TX-884920";
        Double authorizedAmount = 2500.00;
        String challengeNonce = "NONCE_7f9b204c81ae";
        Long timestamp = System.currentTimeMillis();

        // User authorized ₹2,500.00
        byte[] originalPayload = validator.buildCanonicalPayload(txId, authorizedAmount, challengeNonce, timestamp);
        String signature = signData(originalPayload, privateKey);

        // Attacker intercepts and modifies amount to ₹25,000.00
        Double tamperedAmount = 25000.00;
        byte[] tamperedPayload = validator.buildCanonicalPayload(txId, tamperedAmount, challengeNonce, timestamp);

        PublicKey decodedKey = validator.decodePublicKey(base64PublicKey);
        boolean isTamperedAuthentic = validator.verifySignature(tamperedPayload, signature, decodedKey);

        assertFalse(isTamperedAuthentic, "Tampered amount MUST be rejected mathematically");
    }

    @Test
    @DisplayName("⏱️ Test 3: Sub-45ms Verification Latency Benchmark")
    void testVerificationLatencyBenchmark() throws Exception {
        String txId = "TX-BENCHMARK-01";
        Double amount = 100.00;
        String challengeNonce = "NONCE_BENCH_TEST";
        Long timestamp = System.currentTimeMillis();

        byte[] payload = validator.buildCanonicalPayload(txId, amount, challengeNonce, timestamp);
        String signature = signData(payload, privateKey);
        PublicKey decodedKey = validator.decodePublicKey(base64PublicKey);

        // Measure verification latency over 100 iterations
        long totalNanos = 0;
        int iterations = 100;

        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            boolean valid = validator.verifySignature(payload, signature, decodedKey);
            long end = System.nanoTime();
            assertTrue(valid);
            totalNanos += (end - start);
        }

        double avgMillis = (totalNanos / (double) iterations) / 1_000_000.0;
        System.out.println("==================================================");
        System.out.println("🚀 BioLock Average Verification Latency: " + String.format("%.3f", avgMillis) + " ms");
        System.out.println("==================================================");

        assertTrue(avgMillis < 45.0, "Verification latency must be well under 45ms");
    }
}
