# AppShield

A lightweight, local-only application code-protection CLI for developers targeting Android (with iOS and Windows support planned in future milestones).

AppShield automates application hardening workflows by orchestrating existing, trusted protection engines within isolated staging workspaces while rigorously preserving original source trees, verifying binary protection outcomes, and guaranteeing zero remote telemetry or credential leakage.

---

## Platform Support Matrix

| Platform | Target Projects / Binaries | Implementation Status | Validation Level |
|---|---|---|---|
| **Android (v1)** | Android Gradle Projects (`gradlew` + AGP + R8) | **Implemented & Functional** | **Empirically Validated** (Release build, DEX renaming, Signing, API 37 Runtime Launch) |
| **iOS** | Xcode Projects / Mach-O Binaries | *Future Platform Support (Planned)* | Not implemented; non-Android targets are safely rejected |
| **Windows** | .NET Assemblies / PE Binaries | *Future Platform Support (Planned)* | Not implemented; non-Android targets are safely rejected |

> [!NOTE]
> **Android Only in v1**: AppShield currently implements the Android protection pipeline exclusively. Adapters for iOS and Windows represent future roadmap milestones and are not yet functional. Any configuration specifying an unsupported platform is rejected at configuration validation time.

---

## Core Architectural Invariants

* **100% Local & Offline**: Zero network telemetry, analytics, or remote signing servers. Builds execute locally and offline by default.
* **Source Preservation & Immutability**: Original application source code, sensitive keys (`*.jks`), environment files (`.env`), and configuration files are treated as strictly read-only and verified bit-for-bit identical via pre- and post-run cryptographic SHA-256 manifests.
* **Ephemeral Workspace Staging**: Build transformations and rule injections take place exclusively in isolated temporary directories (`tempfile.gettempdir() / "appshield_staging" / build_<uuid>`) with strict exclusions for credentials and version control files.
* **Objective Verification**: Generates empirical evidence reports (`audit_report.json` and `audit_report.md`) based on objective bytecode inspection, symbol renaming ratios, and decompiler audits, explicitly banning opaque composite "resistance scores".
* **Credential Masking**: Passwords are read strictly via environment variable names; never passed as plaintext CLI arguments, printed in reports, or stored on disk.
* **Simulation Barrier**: Simulated or mocked test runners are strictly blocked from exporting artifacts to production release directories.

---

## Supported Workflows & Target Toolchains

### Android v1 Pipeline
- **Supported Project Type**: Android Gradle Projects (`gradlew` + Android Gradle Plugin, Groovy or Kotlin DSL, single- or multi-module) configured with release minification (`minifyEnabled true` / `isMinifyEnabled = true`) and ProGuard/R8 rules.
- **APK Tasks Only in v1**: Configures and builds release APK tasks (e.g., `assembleRelease`, `assembleProdRelease`). Android App Bundle (`bundle*` / `.aab`) and `debug` tasks are rejected early during validation.
- **Unsupported in v1 MVP**: Standalone precompiled APKs without source Gradle project context are explicitly rejected. Standalone R8 on arbitrary APKs lacks platform dependency jars, compilation classpath, and resource ID tables, leading to runtime failures.

### Tested Toolchain Versions (Android v1)
- **Java Runtime**: OpenJDK 17 LTS (tested: Eclipse Temurin JDK `17.0.21+9`).
- **Gradle**: Gradle 8.2 or newer (tested: Gradle `8.2`).
- **Android Gradle Plugin (AGP)**: AGP 8.2.0 to 8.2.2+ (tested: AGP `8.2.2`).
- **Android SDK Platform**: API Level 34 (tested: `platforms;android-34`).
- **Android SDK Build-Tools**: 34.0.0 or newer (tested: `build-tools;34.0.0`, including `zipalign` and `apksigner`).
- **Google R8**: Tested and verified with R8 compiler version `8.2.47`.

---

## Installation

### Using `uv` (Recommended)
```bash
# Clone the repository
git clone https://github.com/sammugdiya7-design/AppShield.git
cd AppShield

# Install in editable mode
uv pip install -e .

# Or install with development dependencies
uv pip install -e ".[dev]"
```

### Using `pip`
```bash
# Install in editable mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

---

## CLI Usage & Commands

### 1. `appshield info`
Display version, architecture principles, and platform support status:
```bash
appshield info
```

### 2. `appshield doctor`
Inspect local host environment prerequisites (Java, `javac`, `JAVA_HOME`, `ANDROID_HOME`, Gradle, `zipalign`, `apksigner`) and inspect the local Gradle offline dependency cache (AGP & R8, read-only with zero network calls):
```bash
# Inspect host toolchain and local offline Gradle cache status
appshield doctor

# Inspect with a specific Android Gradle project directory to validate wrapper, AGP version, and R8 config
appshield doctor --project-dir tests/fixtures/sample_android_gradle_project
```
> On a fresh environment where AGP/R8 artifacts are not yet cached in `~/.gradle/caches`, `appshield doctor` explains how to pass `--allow-network-dependencies` on the first `appshield protect` run. No local build history cache is stored; build validation executes live during `appshield protect`.

### 3. `appshield protect`
Stage, harden, build, and verify a supported Android Gradle project:
```bash
# Standard offline protection build
appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml --output-dir dist/protected

# Retain R8 mapping privately outside the repository
appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml \
  --output-dir dist/protected \
  --mapping-out "$HOME/.appshield/mappings/my_app/mapping.txt"

# Initial dependency warm-up / online build (requires explicit opt-in)
appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml \
  --output-dir dist/protected \
  --allow-network-dependencies
```

#### Key `protect` Flags:
- `-c, --config <path>`: Path to YAML or JSON configuration file (required).
- `-o, --output-dir <dir>`: Target directory for the protected APK (defaults to `dist/protected`).
- `--mapping-out <path>`: Designated private path to save the R8 `mapping.txt` file outside the repository.
- `--allow-network-dependencies`: Explicitly authorize network access during the build to download and cache missing Gradle dependencies. Subsequent builds run offline.
- `--allow-production-signing`: Explicitly confirm production release signing (blocked by default to prevent accidental signing).
- `--overwrite`: Authorize overwriting existing destination files.

### 4. `appshield verify`
Empirically audit a protected APK artifact using objective static checks:
```bash
# Inspect artifact and verify DEX structure and zip alignment
appshield verify dist/protected/sample_android_gradle_project-release-protected.apk

# Verify with configuration and R8 mapping file for dual-evidence symbol verification
appshield verify dist/protected/sample_android_gradle_project-release-protected.apk \
  -c tests/fixtures/sample_android_gradle_project/appshield.yaml \
  -m "$HOME/.appshield/mappings/my_app/mapping.txt" \
  -o dist/protected/audit_report.json
```

#### Key `verify` Flags:
- `-c, --config <path>`: Optional path to project configuration file.
- `-m, --mapping-file <path>`: Optional path to R8 obfuscation mapping file for symbol renaming verification.
- `-o, --output <path>`: Optional path to export JSON verification report.
- `--overwrite`: Authorize overwriting existing output report file.

---

## Configuration (`appshield.yaml`)

```yaml
version: "1.0"
project_name: "sample_android_gradle_project"
platform: "android"

input:
  project_dir: "."
  verify_source_immutability: true
  exclude_patterns:
    - ".git/**"
    - "build/**"
    - ".gradle/**"
    - "**/*.jks"
    - "local.properties"
    - "**/*.env*"
    - "**/google-services.json"

output:
  dir: "dist/protected"
  overwrite_existing: false

android:
  project_type: "gradle"
  build_variant: "release"
  gradle_task: "assembleRelease"
  r8_rules_file: "app/proguard-rules.pro"
  signing:
    enabled: false
    is_production: false
    keystore_path: null
    key_alias: null
    keystore_password_env: null
    key_password_env: null

verification:
  enabled: true
  fail_on_check_failure: true
  checks:
    - "build_execution"
    - "apk_structure"
    - "symbol_renaming_ratio"
    - "signature_integrity"
    - "package_alignment"
    - "string_pool_inspection"
    - "structural_decompilation_info"
```

#### Configuration Safety & Verification Notes
- **APK Task & Variant Guard**: `gradle_task` must target a release APK task (e.g., `assembleRelease`); `bundle*`/`.aab` and `debug` tasks are rejected during configuration validation.
- **No-Obfuscation Safeguard**: ProGuard/R8 rule files containing active `-dontobfuscate` directives are rejected early during validation and rule staging.
- **Pre-Build Signing Guard**: When `signing.enabled: true`, `keystore_path` (existing file), `key_alias`, password env vars (`keystore_password_env`), and `--allow-production-signing` (when `is_production: true`) are validated before Gradle execution starts.
- **Verification Enforcement**: `verification.enabled`, `fail_on_check_failure`, and canonical `checks` are enforced consistently by `protect` and `verify`; unknown check names are rejected, and disabling verification or omitting mandatory core checks (`build_execution`, `apk_structure`, `symbol_renaming_ratio`, `package_alignment`, plus `signature_integrity` when signing is enabled) prevents `is_verified_protected = True`.

---

## Signing Behavior & Output Artifacts

- **Output Location**: Hardened outputs are written to the designated output folder (`dist/protected/<project>-<variant>-protected.apk`).
- **Unsigned by Default**: When `signing.enabled: false`, AppShield produces a 4-byte ZIP-aligned, unsigned release APK.
- **Honest Status Separation**: Verification reports strictly separate code protection from installation readiness:
  - `is_verified_protected`: Reports `True` when bytecode shrinking, R8 obfuscation, and DEX structure pass all objective checks.
  - `is_installation_ready`: Reports `False` for unsigned APKs because the Android OS Package Manager enforces cryptographic signatures during installation (`INSTALL_PARSE_FAILED_NO_CERTIFICATES`).
- **Keystore Privacy**: Passwords are read strictly via environment variable names (`apksigner --ks-pass env:<VAR>` and `keytool -storepass:env` / `-keypass:env` inside stripped `build_safe_env()` subprocess environments). They never appear in command-line arguments, logs, or parent `os.environ`.

---

## Real-World Empirical Validation Evidence

AppShield Android v1 has undergone full real-world validation against a controlled Android Gradle sample fixture:

1. **Genuine Toolchain Build**:
   - Completed release compilation via Gradle 8.2 and Eclipse Temurin JDK 17 in 186.06 seconds.
   - Google R8 (version 8.2.47) and AGP (version 8.2.2) executed to produce release bytecode.
2. **DEX Bytecode Obfuscation**:
   - Class renaming verified via dual-evidence DEX inspection: 66.7% classes renamed.
   - `com.appshield.sample.IdentifiableSecretService` renamed to class `a:`.
   - `com.appshield.sample.PaymentSecurityValidator` renamed to class `b:`.
   - Application entry point `com.appshield.sample.MainActivity` preserved intact.
3. **Cryptographic Signing & Alignment**:
   - Disposable 2048-bit RSA test key generated outside the repository (`CN=AppShield Disposable Test`).
   - APK Signature Scheme v2 and v3 signatures validated (`apksigner verify --verbose` passed).
   - 4-byte page alignment confirmed (`zipalign -c -v 4` code 0).
4. **On-Device Runtime Execution (Emulator)**:
   - Successfully installed on Android Emulator `emulator-5554` running **Android API 37 (Preview, x86_64 architecture)** via `adb install`.
   - Cold launched `MainActivity` in 988 ms (`am start -W`, assigned PID: 7478).
   - Process verified active and resident; window manager confirmed `MainActivity` as focused display window.
   - Zero fatal exceptions and zero runtime aborts (`ClassNotFoundException: 0`, `NoSuchMethodError: 0`).
   - Logcat captured empirical execution marker `System.out: AppShield Sample Initialized: 56`, proving obfuscated bytecode logic executed correctly at runtime.

### Hardware & Compatibility Limitations
- **Emulator vs. Physical Hardware**: All runtime execution testing to date was performed on an **x86_64 Android Emulator running Android API 37**. Dynamic testing on physical ARM64 / ARMv7 hardware across OEM distributions (e.g. Samsung Knox, Xiaomi MIUI) has not yet been conducted.
- **Reverse Engineering Law**: Reverse engineering of client-side code running on user-controlled hardware can never be made impossible. Obfuscation raises attacker work factors and reverses trivial decompilation, but client-side software cannot be rendered 100% immune to analysis.

---

## Isolation Architecture & Threat Model

1. **Filesystem Copy Isolation**: AppShield copies files into an ephemeral scratch directory under system temporary storage. This is a **filesystem isolation mechanism, NOT an operating system kernel sandbox** (such as seccomp, AppContainer, or Linux namespaces).
2. **Subprocess Privileges**: Build tools (Gradle, Java, R8) execute with the standard operating system privileges of the invoking user.
3. **Network Isolation**: Gradle `--offline` mode is a build-tool switch, not operating-system network isolation. Build scripts can execute arbitrary JVM bytecode; only trusted, verified build scripts should be executed.
4. **Source Immutability**: All original source files are hashed before and after protection. Any file mutation triggers immediate rollback and execution abortion.

---

## Running Tests & Quality Gates

Run the automated test suite (336 unit and integration tests, covering both `tests/fixtures/sample_android_gradle_project/` and mocked generalized Kotlin DSL builds on `tests/fixtures/unrelated_android_gradle_project/`):
```bash
pytest --cov=appshield --cov-report=term-missing
```
> Note: End-to-end live Gradle compilation and emulator runtime execution have been performed on `tests/fixtures/sample_android_gradle_project/`; `tests/fixtures/unrelated_android_gradle_project/` validates multi-module Groovy/Kotlin DSL layout discovery, manifest entry-point preservation, and generalized verification logic under mocked build outputs.

Run code quality and static security analysis:
```bash
# Code linting
ruff check appshield tests

# Formatting check
ruff format --check appshield tests

# Static type checking
mypy appshield tests

# Automated security scanner
bandit -c pyproject.toml -r appshield
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
