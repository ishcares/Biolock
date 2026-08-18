package com.scamshield.biolock.controller;

import com.scamshield.biolock.model.Transaction;
import com.scamshield.biolock.service.TransactionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController // Exposes this class as a REST API controller
@RequestMapping("/api/transactions") // Sets the base URL path for this controller
public class TransactionController {

    private final TransactionService transactionService;

    // Constructor Injection: Spring Boot automatically injects the
    // TransactionService bean
    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    /**
     * POST /api/transactions
     * Creates a new pending transaction.
     */
    @PostMapping
    public ResponseEntity<?> createTransaction(@RequestBody Transaction request) {
        try {
            Transaction tx = transactionService.createTransaction(request.getAmount(), request.getRecipientUpi());
            return new ResponseEntity<>(tx, HttpStatus.CREATED); // Returns 201 Created with the transaction details
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST); // Returns 400 Bad Request if
                                                                                 // validation fails
        }
    }

    /**
     * GET /api/transactions/{id}
     * Retrieves a transaction by its ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Transaction> getTransaction(@PathVariable String id) {
        Transaction tx = transactionService.getTransaction(id);
        if (tx == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND); // Returns 404 Not Found if transaction doesn't exist
        }
        return new ResponseEntity<>(tx, HttpStatus.OK); // Returns 200 OK with the transaction details
    }

    /**
     * POST /api/transactions/{id}/verify
     * Verifies the biometric signature for a transaction.
     */
    @PostMapping("/{id}/verify")
    public ResponseEntity<?> verifyTransaction(@PathVariable String id, @RequestBody Transaction request) {
        try {
            boolean isValid = transactionService.verifyTransaction(id, request.getSignature(), request.getChallenge()); // Using
                                                                                                                        // signature
                                                                                                                        // &
                                                                                                                        // public
                                                                                                                        // key

            if (isValid) {
                return new ResponseEntity<>("Transaction verified successfully.", HttpStatus.OK);
            } else {
                return new ResponseEntity<>("Signature verification failed.", HttpStatus.UNAUTHORIZED);
            }
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        } catch (IllegalStateException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        }
    }

}
