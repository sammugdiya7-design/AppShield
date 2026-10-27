# Sample Android Gradle Disposable Test Fixture

This is a minimal, controlled, disposable Android Gradle project designed exclusively
for AppShield automated integration testing and verification.

## Purpose & Scope
- **Integration Target**: Serves as the target project for workspace staging, source immutability verification, sensitive file exclusions, and R8 obfuscation verification.
- **Safety**: Contains **NO** real signing credentials, proprietary secrets, private keys, personal data, or production code.
- **Controlled Elements**: Contains deliberately identifiable classes, methods, and constant strings to empirically verify code obfuscation in later phases.

## Identifiable Test Symbols
- **Classes**:
  - `com.appshield.sample.MainActivity` (Application entry point, explicitly kept in ProGuard/R8)
  - `com.appshield.sample.IdentifiableSecretService` (Target for R8 class renaming)
  - `com.appshield.sample.PaymentSecurityValidator` (Target for R8 method renaming)
- **Methods**:
  - `processUserTokenAndCalculateHash(String)`
  - `calculateInternalSecurityChecksum(String)`
  - `validateTransactionToken(String, double)`
- **Identifiable Test Strings**:
  - `"APP_SHIELD_TEST_STRING_LITERAL_XYZ"`
  - `"DISPOSABLE_TEST_PAYMENT_SECRET_TOKEN"`
  - `"NON_SENSITIVE_VALIDATION_SCHEME_V1"`

## Build Prerequisites & Toolchain Status
- **JDK**: OpenJDK 17 (`JAVA_HOME` configured)
- **Android SDK**: Android API Level 34 (`platforms;android-34`) and Build-Tools 34.0.0 (`zipalign`, `apksigner`)
- **Gradle**: 8.2 (via `gradle-8.2-bin.zip` specified in `gradle-wrapper.properties`)
- **Android Gradle Plugin (AGP)**: 8.2.2
- **Wrapper Files Present**:
  - `gradlew` (POSIX shell script)
  - `gradlew.bat` (Windows command script)
  - `gradle/wrapper/gradle-wrapper.properties` (Distribution URL definition)
  - *Note*: `gradle-wrapper.jar` is deliberately omitted from git tracking. In a live environment, wrapper execution requires either the wrapper JAR or a system-installed Gradle distribution.

## Execution & Security Policy
- Automated tests MUST NEVER execute build scripts from arbitrary or untrusted external projects.
- Live build tests must execute strictly against this repository-controlled fixture inside an isolated ephemeral staging directory.
- **Download Safety**: Standard Gradle Wrapper operations can download the Gradle distribution archive before executing Gradle commands. AppShield strictly forbids silent network downloads. Offline live execution requires the Gradle distribution to be pre-cached in `~/.gradle/wrapper/dists/` or fails with a descriptive missing-dependency error.
