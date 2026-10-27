# ProGuard and R8 Rules for Sample Android Gradle Project

# Explicitly keep MainActivity entry point so it remains named for verification
-keep public class com.appshield.sample.MainActivity extends android.app.Activity {
    public void onCreate(android.os.Bundle);
}

# The following classes are deliberately NOT kept, so that R8 will rename them:
# - com.appshield.sample.IdentifiableSecretService
# - com.appshield.sample.PaymentSecurityValidator
