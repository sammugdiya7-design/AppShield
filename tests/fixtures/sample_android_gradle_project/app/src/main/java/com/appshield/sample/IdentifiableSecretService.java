package com.appshield.sample;

/**
 * Controlled test service containing identifiable symbols and strings
 * designed to demonstrate R8 obfuscation and string pool scanning in AppShield verification.
 */
public class IdentifiableSecretService {
    // Identifiable non-sensitive test constants
    public static final String IDENTIFIABLE_CONSTANT_ALPHA = "APP_SHIELD_TEST_STRING_LITERAL_XYZ";
    private static final String INTERNAL_SIGNATURE_MARKER = "DISPOSABLE_TEST_PAYMENT_SECRET_TOKEN";

    /**
     * Identifiable method name intended for R8 renaming.
     */
    public String processUserTokenAndCalculateHash(String tokenPayload) {
        if (tokenPayload == null || tokenPayload.isEmpty()) {
            return IDENTIFIABLE_CONSTANT_ALPHA;
        }
        long checksum = calculateInternalSecurityChecksum(tokenPayload);
        return INTERNAL_SIGNATURE_MARKER + "_" + checksum;
    }

    /**
     * Identifiable internal method intended for inlining/renaming.
     */
    private long calculateInternalSecurityChecksum(String input) {
        long hash = 1125899906842597L; // 64-bit prime
        for (int i = 0; i < input.length(); i++) {
            hash = 31 * hash + input.charAt(i);
        }
        return hash;
    }
}
