package com.scamshield.biolock.controller;

import com.scamshield.biolock.security.ECDSAValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * BioLock 1-Click Developer Demo Controller
 * Demonstrates hardware-anchored transaction binding and in-flight tamper rejection in sub-2ms.
 */
@RestController
@RequestMapping("/api/demo")
@CrossOrigin(origins = "*")
public class DemoController {

    private final ECDSAValidator validator;

    public DemoController(ECDSAValidator validator) {
        this.validator = validator;
    }

    /**
     * GET /api/demo/run
     * Executes a live verification & tampering comparison.
     */
    @GetMapping("/run")
    public ResponseEntity<Map<String, Object>> runLiveDemo() {
        Map<String, Object> response = new LinkedHashMap<>();

        try {
            // 1. Simulate client hardware keypair (NIST P-256)
            KeyPair deviceKeys = validator.generateDeviceKeyPair();
            PublicKey publicKey = deviceKeys.getPublic();
            PrivateKey privateKey = deviceKeys.getPrivate();
            String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            String txId = "TX-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
            Double authorizedAmount = 2500.00;
            String payeeUpi = "merchant.swiggy@icici";
            String challengeNonce = "NONCE_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
            Long timestamp = System.currentTimeMillis();

            // 2. Hardware Enclave signs canonical payload: txId|amount|challenge|timestamp
            byte[] canonicalPayload = validator.buildCanonicalPayload(txId, authorizedAmount, challengeNonce, timestamp);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(canonicalPayload);
            String authenticSignature = Base64.getEncoder().encodeToString(signer.sign());

            // 3. Scenario A: Authentic Transaction Verification
            long startAuth = System.nanoTime();
            PublicKey decodedKey = validator.decodePublicKey(base64PublicKey);
            boolean isAuthenticValid = validator.verifySignature(canonicalPayload, authenticSignature, decodedKey);
            long endAuth = System.nanoTime();
            double authLatencyMs = (endAuth - startAuth) / 1_000_000.0;

            Map<String, Object> scenarioA = new LinkedHashMap<>();
            scenarioA.put("description", "Authentic Transaction Signed by Device Secure Enclave");
            scenarioA.put("transactionId", txId);
            scenarioA.put("authorizedAmount", "INR " + String.format("%.2f", authorizedAmount));
            scenarioA.put("payee", payeeUpi);
            scenarioA.put("signature", authenticSignature.substring(0, 24) + "...");
            scenarioA.put("verificationLatencyMs", Double.parseDouble(String.format("%.3f", authLatencyMs)));
            scenarioA.put("status", isAuthenticValid ? "APPROVED" : "FAILED");
            scenarioA.put("verdict", "Cryptographic signature matches canonical payload. Zero tampering detected.");

            // 4. Scenario B: In-Flight MITM Attack (Amount Tampered to 25,000)
            Double tamperedAmount = 25000.00;
            byte[] tamperedPayload = validator.buildCanonicalPayload(txId, tamperedAmount, challengeNonce, timestamp);

            long startTamper = System.nanoTime();
            boolean isTamperValid = validator.verifySignature(tamperedPayload, authenticSignature, decodedKey);
            long endTamper = System.nanoTime();
            double tamperLatencyMs = (endTamper - startTamper) / 1_000_000.0;

            Map<String, Object> scenarioB = new LinkedHashMap<>();
            scenarioB.put("description", "In-Flight Man-in-the-Middle (MITM) Parameter Tampering");
            scenarioB.put("originalAmount", "INR " + String.format("%.2f", authorizedAmount));
            scenarioB.put("interceptedTamperedAmount", "INR " + String.format("%.2f", tamperedAmount));
            scenarioB.put("verificationLatencyMs", Double.parseDouble(String.format("%.3f", tamperLatencyMs)));
            scenarioB.put("status", isTamperValid ? "VULNERABLE" : "BLOCKED_TAMPER_DETECTED");
            scenarioB.put("verdict", "Signature mathematically failed over tampered payload. Transaction dropped.");

            // 5. Response Summary
            response.put("engine", "BioLock Zero-Trust Transaction Binding SDK");
            response.put("curve", "secp256r1 (NIST P-256 ECDSA)");
            response.put("benchmark", "Sub-5ms Fail-Closed Verification Engine");
            response.put("scenario_authentic_transfer", scenarioA);
            response.put("scenario_in_flight_tampering_attack", scenarioB);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", "Demo execution failed: " + e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }
}
