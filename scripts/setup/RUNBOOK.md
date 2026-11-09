# AppShield Android Toolchain Setup & Protection Execution Runbook
<!-- Verified Toolchain Runbook: Validated PowerShell Syntax & Clean Environment Variables -->

This runbook provides the verified, step-by-step execution procedure for setting up the local Android build toolchain and executing the genuine AppShield protection workflow against the repository-owned sample fixture (`tests/fixtures/sample_android_gradle_project`).

All commands must be executed in PowerShell from the repository root directory (`appshield`).

---

## Prerequisites & Operational Rules

1. **User Scope & Process-Level Isolation**: All downloads operate strictly at `User` scope (`$env:USERPROFILE` and `$env:LOCALAPPDATA`). Environment variables are configured strictly at the **PowerShell process level** via session launcher (`enter-appshield-env.ps1`), keeping Windows Machine and User registry environment variables completely untouched.
2. **Java PATH Isolation & Oracle Java 8 Preservation**: Windows evaluates Machine PATH before User PATH. Adding OpenJDK 17 to User PATH does not guarantee priority over Oracle Java 8 on Machine PATH. AppShield's session script explicitly prepends OpenJDK 17 to the front of the active process `$env:Path`, ensuring JDK 17 resolution while preserving the host's Oracle Java 8 installation completely intact.
3. **Android SDK Coexistence**: The local workstation already has Android SDK tools and platforms (such as `platforms\android-36`, `platforms\android-36.1`, and `build-tools\36.0.0`). Installing `platforms;android-34` and `build-tools;34.0.0` creates dedicated sibling directories without modifying or deleting existing Android 36 installations.
4. **Environment Variable Consistency**: In PowerShell, environment variables are referenced using `$env:NAME` (e.g. `$env:LOCALAPPDATA`, `$env:USERPROFILE`, `$env:JAVA_HOME`, `$env:Path`).
5. **Source Immutability**: The repository fixture (`tests/fixtures/sample_android_gradle_project/`) is treated as strictly read-only. AppShield copies the project into an isolated temporary staging workspace before applying R8 rules and executing Gradle.
6. **Private Mapping Protection**: R8 `mapping.txt` files are retained privately outside the repository using `--mapping-out`. Destination files and reports will not be overwritten without explicit `--overwrite`.
7. **Air-Gapped Offline Protection**: By default, AppShield enforces `offline = true` (passing `--offline` to Gradle) to ensure reproducible, hermetic builds. Initial dependency caching requires explicit developer authorization (see Network Dependency Authorization below).
8. **Signing Policy**: The sample fixture configuration specifies `signing.enabled: false`. Initial fixture output is 4-byte ZIP-aligned but unsigned. Objective check `CHK-SIG-01` reports `SKIPPED`, which does not block release verification acceptance.

---

## Phase 1: Stage A — Download & Verify Toolchain Binaries (JDK 17 & Gradle 8.2)

Downloads and validates official SHA-256 checksums for Eclipse Temurin OpenJDK 17 LTS (17.0.21+9), Google Android Command-Line Tools (15859902), and Gradle 8.2. Existing valid installations (such as `cmdline-tools\latest` Revision 22.0) are automatically detected and preserved.

### Step 1.1: Preview Planned Downloads (Dry-Run)
Inspect planned downloads, target locations, and checksum verification URLs without downloading any files:
```powershell
& scripts/setup/download-toolchain.ps1 -Preview
```

### Step 1.2: Execute Verified Download and Staged Extraction
Download the archives, verify SHA-256 hashes against official vendor checksums, extract into staging, and transactionally install them into user directories:
```powershell
& scripts/setup/download-toolchain.ps1
```

*Installed Targets:*
- OpenJDK 17: `%USERPROFILE%\.jdk\jdk-17.0.21+9`
- Android Command-Line Tools: `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest` (preserved if already present)
- Gradle 8.2: `%USERPROFILE%\.gradle\gradle-8.2`

---

## Phase 2: Activate Process-Level Isolated Session (Zero System Mutation)

Activates the AppShield build toolchain exclusively for the current PowerShell process session. It sets `$env:JAVA_HOME`, `$env:ANDROID_HOME`, and prepends the 5 toolchain directories to the front of process `$env:Path` so that OpenJDK 17 takes priority over Oracle Java 8 in Machine PATH, while leaving the Windows registry completely untouched.

### Step 2.1: Preview Session Environment Settings (Dry-Run)
Inspect the proposed process-level environment variable settings without modifying the active session:
```powershell
. scripts/setup/enter-appshield-env.ps1 -Preview
```

### Step 2.2: Activate Process-Level Environment
Dot-source the launcher into the current PowerShell session to set `$env:JAVA_HOME` and prepend the toolchain to `$env:Path`:
```powershell
. scripts/setup/enter-appshield-env.ps1
```

*Process-Level Isolation Guarantees:*
- Machine PATH in Windows Registry: Strictly UNTOUCHED.
- User PATH in Windows Registry: Strictly UNTOUCHED.
- Host Oracle Java 8: Preserved intact on Machine PATH.
- Precedence: `$env:JAVA_HOME\bin` is at the very front of the active process `$env:Path`, guaranteeing `java` resolves to OpenJDK 17.

*(Note: Optional persistent User registry configuration via `configure-user-environment.ps1` is retained for developers who explicitly desire persistent variables, but requires separate approval before running.)*

---

## Phase 3: Stages B & C — Android SDK Licenses & Component Installation

Google Android SDK components require manual license review and acceptance. Never automate license acceptance.

### Step 3.1: Stage C — Interactive Android SDK License Review & Acceptance
Interactively review and accept the official Android SDK and build-tools license agreements. The developer must review the terms and interactively enter `y`:
```powershell
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --licenses
```

### Step 3.2: Stage B — Install SDK Platform 34 and Build-Tools 34.0.0
Install the compile SDK platform and build tools required for R8 shrinking, ZIP alignment, and signing:
```powershell
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat" "platforms;android-34" "build-tools;34.0.0"
```

*Installation Safety Note:* This command installs `platforms\android-34` and `build-tools\34.0.0` as independent side-by-side directories in `%LOCALAPPDATA%\Android\Sdk`. It does NOT overwrite or delete existing `platforms\android-36`, `platforms\android-36.1`, or `build-tools\36.0.0`.

---

## Phase 4: Run AppShield Toolchain Doctor

Verify that the active process environment satisfies all required toolchain prerequisites, validating complete wrapper integrity and toolchain versions >= 8.2.

### Step 4.1: Execute Prerequisite Inspection
```powershell
uv run appshield doctor --project-dir tests/fixtures/sample_android_gradle_project
```

*Expected Status:* Exit code `0`, all required prerequisites report `Installed`, and summary confirms `All required prerequisites are met.`

---

## Network Dependency Authorization & Initial Online Build Policy

AppShield enforces offline protection by default (`offline: true` in config, translating to `--offline` in Gradle commands). For an initial clean environment, Gradle needs to cache Android Gradle Plugin (AGP 8.2.2) and R8 dependencies into the user's Gradle cache (`~/.gradle/caches/modules-2/files-2.1/`).

### Exactly What Happens During an Authorized Online Build
When `--allow-network-dependencies` is explicitly passed by the developer:
1. **Full Protection Build (Not Cache-Only)**: AppShield does NOT run a prefetch-only cache task. It executes the full Android protection lifecycle: resolves missing dependencies via Gradle, runs the actual `assembleRelease` Gradle task, executes R8 bytecode shrinking and obfuscation, runs all empirical verification checks, and exports the protected release APK.
2. **Staging Sandbox Scope**: All build activities, rule injection, and dependency resolution occur strictly inside the temporary staging directory (`appshield_staging/<build_id>`). Original repository source files remain 100% immutable (verified cryptographically before export).
3. **OS-Level Isolation Disclaimer**: Gradle's `--offline` flag is a software build-tool setting that disables querying remote Maven repositories. It is **NOT an operating-system-level process network sandbox**. If custom build scripts or Gradle plugins execute low-level socket connections, `--offline` does not restrict OS sockets. AppShield does not claim OS kernel network sandboxing.
4. **Explicit Authorization Required**: The first build that accesses external networks requires explicit developer intent via `--allow-network-dependencies`:
```powershell
uv run appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml --output-dir dist/protected --allow-network-dependencies --mapping-out $privateMappingFile
```

### Verifying Cached Dependencies
After the initial authorized online build, verify local Gradle cache for AGP and R8 artifacts without querying the network:
```powershell
Test-Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\com.android.tools.build\gradle\8.2.2"
Test-Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\com.android.tools\r8"
```
Once cached, all subsequent protection builds run with standard default `--offline` enforcement.

---

## Phase 5: Execute Genuine Android Protection & Empirical Verification

Executes the genuine Android Gradle R8 protection pipeline against the fixture project, validates source immutability, aligns the APK, securely exports the R8 mapping, and runs empirical decompiler verification checks.

### Step 5.1: Create Private Mapping Destination Directory
Create a dedicated private directory outside the repository for retained crash-trace mapping files:
```powershell
$privateMappingDir = Join-Path $env:USERPROFILE ".appshield\mappings\sample_android_gradle_project"
```
```powershell
New-Item -ItemType Directory -Path $privateMappingDir -Force
```
```powershell
$privateMappingFile = Join-Path $privateMappingDir "mapping.txt"
```

### Step 5.2: Execute Android Protection Pipeline
Stage fixture in an isolated workspace, inject R8 rules, build release APK via Gradle in offline mode, zipalign, and verify:
```powershell
uv run appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml --output-dir dist/protected --mapping-out $privateMappingFile
```

*Artifact Produced:* `dist/protected/sample_android_gradle_project-release-protected.apk`

### Step 5.3: Run Standalone Empirical Verification
Perform independent verification of all empirical checks against the compiled APK, passing the configuration via `-c` to verify against the active project contract:
```powershell
uv run appshield verify dist/protected/sample_android_gradle_project-release-protected.apk -c tests/fixtures/sample_android_gradle_project/appshield.yaml -m $privateMappingFile -o dist/protected/standalone_audit.json
```

---

## Artifact Status: Protection, Verification, Signatures & Installation Readiness

AppShield strictly distinguishes four distinct dimensions of an output artifact:

1. **Code-Protection Verification** (`is_verified_protected`):
   - Proves target classes were renamed in both R8 mapping and compiled DEX bytecode (`CHK-SYM-01: PASS`).
   - Proves dead code was eliminated and zero genuine secrets were exposed in string tables (`CHK-STR-01: PASS/INFO`).
   - Proves the build was real (`CHK-BLD-01: PASS`) and original source files were unchanged.
2. **APK Structural Validity & ZIP Alignment** (`CHK-APK-01`, `CHK-ALN-01`):
   - Proves the APK archive structure, Dalvik headers, and 4-byte boundary alignment are valid.
3. **Signature Verification** (`CHK-SIG-01`):
   - Reports cryptographic signature state: `unsigned` (skipped), `test_signed` (disposable debug key), or `production_signed` (authorized key).
4. **Android Installation Readiness** (`is_installation_ready`):
   - **Crucial Rule**: An unsigned APK may pass code-protection verification, but is **NOT installation-ready**. Android OS Package Manager strictly rejects unsigned APKs with `INSTALL_PARSE_FAILED_NO_CERTIFICATES`. An unsigned APK cannot be installed on any physical device or emulator without a signature.

### Signing Status for Default Fixture
The default sample fixture configuration (`appshield.yaml`) specifies:
```yaml
signing:
  enabled: false
```
The output APK is 4-byte ZIP-aligned (`CHK-ALN-01: PASS`) but unsigned:
- `CHK-SIG-01` reports `SKIPPED` (expected when signing is disabled).
- Because `CHK-SIG-01` is skipped and all other checks pass, `is_verified_protected` evaluates to `True`.
- Terminal and Markdown reports explicitly indicate:
  `Android Installation Ready: NOT READY (Unsigned artifact; Android OS requires an APK signature for installation)`
- Benign fixture tokens (e.g. `SAMPLE_FIXTURE_TOKEN_ALPHA`) report `CHK-STR-01: INFO` and do not block verification.

### Optional Disposable Test Signing Configuration
For testing environments where APK signature verification (`CHK-SIG-01: PASS`) and device installation are required, create a disposable debug keystore and use a separate test configuration (`appshield-test-signing.yaml`):
```powershell
keytool -genkeypair -v -keystore test.keystore -alias testkey -keyalg RSA -keysize 2048 -validity 10000 -storepass android -keypass android -dname "CN=TestKey,O=AppShield,C=US"
```
Configure `appshield-test-signing.yaml`:
```yaml
signing:
  enabled: true
  keystore_path: "test.keystore"
  keystore_password: "android"
  key_alias: "testkey"
  key_password: "android"
  v1_signing_enabled: true
  v2_signing_enabled: true
```
*Note on Production Signing*: Disposable test signing is strictly isolated from production signing. Production signing requires explicit `--allow-production-signing`. AppShield **never generates, stores, or exposes production signing credentials**.

---

## Session Termination & Rollback Procedure

When using process-level session isolation (`enter-appshield-env.ps1`), **closing the PowerShell terminal session immediately and completely terminates all environment settings**. No cleanup or rollback script is necessary, because no persistent registry entries were modified.

If the optional persistent configuration (`configure-user-environment.ps1`) was previously applied, use the rollback script to restore exact pre-AppShield registry values:

### Step R.1: Preview Restoration (Dry-Run)
Inspect the values that will be restored from the backup file:
```powershell
& scripts/setup/restore-user-environment.ps1 -Preview
```

### Step R.2: Execute Environment Restoration
Restore `JAVA_HOME`, `ANDROID_HOME`, and `User` PATH to their exact original pre-AppShield values and refresh the active session:
```powershell
& scripts/setup/restore-user-environment.ps1
```
