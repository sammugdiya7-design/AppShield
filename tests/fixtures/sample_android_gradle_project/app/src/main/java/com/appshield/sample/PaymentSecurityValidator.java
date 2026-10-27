package com.appshield.sample;

/**
 * Controlled test validator class demonstrating symbol obfuscation detection.
 */
public class PaymentSecurityValidator {
    public static final String VALIDATION_SCHEME_IDENTIFIER = "NON_SENSITIVE_VALIDATION_SCHEME_V1";

    /**
     * Identifiable method target for rename verification.
     */
    public boolean validateTransactionToken(String transactionId, double amount) {
        if (transactionId == null || amount <= 0.0) {
            return false;
        }
        return transactionId.startsWith(VALIDATION_SCHEME_IDENTIFIER);
    }
}
