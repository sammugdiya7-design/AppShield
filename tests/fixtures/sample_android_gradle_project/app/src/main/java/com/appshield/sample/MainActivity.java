package com.appshield.sample;

import android.app.Activity;
import android.os.Bundle;

/**
 * Main application entry point for the Sample Android Gradle Project.
 * Deliberately retained via ProGuard/R8 keep rules to verify entry-point preservation.
 */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Exercise identifiable services
        IdentifiableSecretService secretService = new IdentifiableSecretService();
        String result = secretService.processUserTokenAndCalculateHash("SAMPLE_USER_TOKEN_INPUT");

        PaymentSecurityValidator validator = new PaymentSecurityValidator();
        boolean isValid = validator.validateTransactionToken("NON_SENSITIVE_VALIDATION_SCHEME_V1_TX123", 50.0);

        if (isValid && result != null) {
            // Execution stub
            System.out.println("AppShield Sample Initialized: " + result.length());
        }
    }
}
