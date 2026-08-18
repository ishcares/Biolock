package com.scamshield.biolock.service;

import com.scamshield.biolock.model.Transaction;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

@Service // Tells Spring Boot to manage this class as a Service bean
public class TransactionService {

    // Thread-safe in-memory database mock
    private final ConcurrentHashMap<String, Transaction> database = new ConcurrentHashMap<>();

    // Cryptographically secure random generator for challenge nonces
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Creates a new pending transaction and generates a secure challenge.
     */
    public Transaction createTransaction(double amount, String recipientUpi) {
        // 1. Strict Validation
        if (amount <= 0) {
            throw new IllegalArgumentException("Transaction amount must be greater than zero.");
        }
        if (recipientUpi == null || recipientUpi.trim().isEmpty()) {
            throw new IllegalArgumentException("Recipient UPI ID cannot be empty.");
        }

        // 2. Initialize Transaction Entity
        Transaction tx = new Transaction();
        tx.setId(UUID.randomUUID().toString()); // Generates a unique transaction token
        tx.setAmount(amount);
        tx.setRecipientUpi(recipientUpi);
        tx.setStatus("PENDING");

        // 3. Generate 256-bit Cryptographic Challenge
        byte[] challengeBytes = new byte[32]; // 32 bytes = 256 bits
        secureRandom.nextBytes(challengeBytes);
        String challengeBase64 = Base64.getEncoder().encodeToString(challengeBytes);
        tx.setChallenge(challengeBase64);

        // 4. Save to Database
        database.put(tx.getId(), tx);

        return tx;
    }

    /**
     * Fetches a transaction by its ID.
     */
    public Transaction getTransaction(String id) {
        return database.get(id);
    }

    /**
     * Verifies the transaction challenge using ECDSA signature verification.
     */
    public boolean verifyTransaction(String id, String signatureBase64, String publicKeyBase64) {
        Transaction tx = database.get(id);
        if (tx == null) {
            throw new IllegalArgumentException("Transaction not found.");
        }
        if (!"PENDING".equals(tx.getStatus())) {
            throw new IllegalStateException("Transaction is not in a pending state.");
        }

        try {
            // 1. Decode Public Key from X.509 Base64
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC"); // Elliptic Curve key factory
            PublicKey pubKey = kf.generatePublic(spec);

            // 2. Initialize ECDSA Signature engine with SHA-256
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pubKey);

            // 3. Feed the original challenge string as the verification payload
            sig.update(tx.getChallenge().getBytes(StandardCharsets.UTF_8));

            // 4. Verify the signature
            byte[] sigBytes = Base64.getDecoder().decode(signatureBase64);
            boolean isValid = sig.verify(sigBytes);

            // 5. Update transaction state
            if (isValid) {
                tx.setStatus("VERIFIED");
                tx.setSignature(signatureBase64);
            } else {
                tx.setStatus("FAILED");
            }

            // Save updated state back to database
            database.put(id, tx);
            return isValid;

        } catch (Exception e) {
            // If any crypto decoding or parsing fails, reject the transaction
            tx.setStatus("FAILED");
            database.put(id, tx);
            return false;
        }
    }

}
