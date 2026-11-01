# ProGuard and R8 Rules for Sample Android Gradle Project

# Explicitly keep MainActivity entry point so it remains named for verification
-keep public class com.appshield.sample.MainActivity extends android.app.Activity {
    public void onCreate(android.os.Bundle);
}

# Retain target test classes and public methods while explicitly allowing R8 to obfuscate (rename) them.
# The 'allowobfuscation' modifier ensures R8 retains them (preventing dead-code elimination)
# while instructing R8 to obfuscate their names rather than preserving original names.
-keep,allowobfuscation class com.appshield.sample.IdentifiableSecretService {
    public <methods>;
}

-keep,allowobfuscation class com.appshield.sample.PaymentSecurityValidator {
    public <methods>;
}
