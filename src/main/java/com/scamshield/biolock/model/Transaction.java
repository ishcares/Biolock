package com.scamshield.biolock.model;

import lombok.Data;

@Data

public class Transaction {

    private String id;
    private double amount;
    private String recipientUpi;
    private String status; // PENDING, APPROVED, REJECTED, ESCROW_HOLD, EXPIRED
    private String challenge; // The 256-bit challenge nonce
    private String signature; // Cryptographic signature payload

}
