package com.scamshield.biolock.service;

import com.scamshield.biolock.model.Transaction;
import com.scamshield.biolock.security.ECDSAValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service // Tells Spring Boot to manage this class as a Service bean
public class TransactionService {

    // Thread-safe in-memory database mock
    private final ConcurrentHashMap<String, Transaction> database = new ConcurrentHashMap<>();

    // Cryptographically secure random generator for challenge nonces
    private final SecureRandom secureRandom = new SecureRandom();

    // Injected BioLock Core Cryptographic Engine
    @Autowired
    private ECDSAValidator ecdsaValidator;

    /**
     * Creates a new pending transaction and generates a secure 256-bit challenge.
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

        // 3. Generate 256-bit Cryptographic Challenge Nonce
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
     * Verifies the transaction using the hardware-anchored ECDSAValidator.
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
            // 1. Decode X.509 Public Key via ECDSAValidator
            PublicKey pubKey = ecdsaValidator.decodePublicKey(publicKeyBase64);

            // 2. Build Canonical Payload (Locks ID + Amount + Challenge together!)
            byte[] canonicalPayload = ecdsaValidator.buildCanonicalPayload(
                    tx.getId(),
                    tx.getAmount(),
                    tx.getChallenge(),
                    System.currentTimeMillis());

            // 3. Cryptographically verify signature over secp256r1 curve
            boolean isValid = ecdsaValidator.verifySignature(canonicalPayload, signatureBase64, pubKey);

            // 4. Update transaction state
            if (isValid) {
                tx.setStatus("VERIFIED");
                tx.setSignature(signatureBase64);
            } else {
                tx.setStatus("FAILED");
            }

            database.put(id, tx);
            return isValid;

        } catch (Exception e) {
            tx.setStatus("FAILED");
            database.put(id, tx);
            return false;
        }
    }

}
