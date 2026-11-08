# AppShield Android Toolchain Setup & Protection Execution Runbook
<!-- Verified Toolchain Runbook: Validated PowerShell Syntax & Clean Environment Variables -->

This runbook provides the verified, step-by-step execution procedure for setting up the local Android build toolchain and executing the genuine AppShield protection workflow against the repository-owned sample fixture (`tests/fixtures/sample_android_gradle_project`).

All commands must be executed in PowerShell from the repository root directory (`appshield`).

---

## Prerequisites & Operational Rules

1. **User Scope Only**: All downloads and environment modifications operate strictly at `User` scope (`$env:USERPROFILE` and `$env:LOCALAPPDATA`). No administrative or Machine-level changes are required.
2. **Environment Variable Consistency**: In PowerShell, environment variables are referenced using `$env:NAME` (e.g. `$env:LOCALAPPDATA`, `$env:USERPROFILE`, `$env:JAVA_HOME`, `$env:Path`).
3. **Session Behavior**: `configure-user-environment.ps1` sets user registry environment variables and immediately refreshes the active PowerShell process environment (`$env:JAVA_HOME`, `$env:ANDROID_HOME`, `$env:Path`). Restarting your PowerShell session in the same terminal is not required. Any newly opened terminal window will also inherit the variables automatically.
4. **Source Immutability**: The repository fixture (`tests/fixtures/sample_android_gradle_project/`) is treated as strictly read-only. AppShield copies the project into an isolated temporary staging workspace before applying R8 rules and executing Gradle.
5. **Private Mapping Protection**: R8 `mapping.txt` files are retained privately outside the repository using `--mapping-out`. Destination files and reports will not be overwritten without explicit `--overwrite`.
6. **Air-Gapped Offline Protection**: By default, AppShield enforces `offline = true` (passing `--offline` to Gradle) to ensure reproducible, hermetic builds. Initial dependency caching (warm-up) is separated from protection builds (see Dependency Warm-Up below).
7. **Signing Policy**: The sample fixture configuration specifies `signing.enabled: false`. Initial fixture output is 4-byte ZIP-aligned but unsigned. Objective check `CHK-SIG-01` reports `SKIPPED`, which does not block release verification acceptance.

---

## Phase 1: Download & Verify Toolchain Binaries

Downloads and validates official SHA-256 checksums for Eclipse Temurin OpenJDK 17 LTS (17.0.21+9), Google Android Command-Line Tools (15859902), and Gradle 8.2.

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
- Android Command-Line Tools: `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest`
- Gradle 8.2: `%USERPROFILE%\.gradle\gradle-8.2`

---

## Phase 2: Configure User Environment Variables

Backs up the existing environment state to `%USERPROFILE%\.appshield\backup\` (using collision-free naming) and idempotently configures `JAVA_HOME`, `ANDROID_HOME`, and `User` PATH additions while strictly leaving Machine environment untouched.

### Step 2.1: Preview Planned Environment Changes (Dry-Run)
Inspect the proposed environment variable changes without modifying any registry settings:
```powershell
& scripts/setup/configure-user-environment.ps1 -Preview
```

### Step 2.2: Create Backup & Apply User Environment
Creates a timestamped JSON backup of original environment variables, writes `JAVA_HOME`, `ANDROID_HOME`, and the 5 PATH additions to the Windows User registry, and immediately refreshes the current session's `$env:JAVA_HOME`, `$env:ANDROID_HOME`, and `$env:Path`:
```powershell
& scripts/setup/configure-user-environment.ps1
```

*Applied User PATH Additions:*
1. `%USERPROFILE%\.jdk\jdk-17.0.21+9\bin`
2. `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest\bin`
3. `%LOCALAPPDATA%\Android\Sdk\build-tools\34.0.0`
4. `%USERPROFILE%\.gradle\gradle-8.2\bin`
5. `%LOCALAPPDATA%\Android\Sdk\platform-tools`

---

## Phase 3: Android SDK License Acceptance & Component Installation

Uses the official Google Android `sdkmanager` to review licenses and install required SDK build packages.

### Step 3.1: Review and Accept SDK Licenses
Interactively review and accept the official Android SDK and build-tools license agreements:
```powershell
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat" --licenses
```

### Step 3.2: Install SDK Platform 34 and Build-Tools 34.0.0
Install the compile SDK platform and build tools required for R8 shrinking, ZIP alignment, and signing:
```powershell
& "$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin\sdkmanager.bat" "platforms;android-34" "build-tools;34.0.0"
```

---

## Phase 4: Run AppShield Toolchain Doctor

Verify that the local environment satisfies all required toolchain prerequisites, validating complete wrapper integrity and toolchain versions >= 8.2.

### Step 4.1: Execute Prerequisite Inspection
```powershell
uv run appshield doctor --project-dir tests/fixtures/sample_android_gradle_project
```

*Expected Status:* Exit code `0`, all required prerequisites report `Installed`, and summary confirms `All required prerequisites are met.`

---

## Dependency Warm-Up Procedure (One-Time Setup)

AppShield enforces offline protection by default (`offline: true` in config, translating to `--offline` in Gradle commands). For an initial clean environment, Gradle needs to cache Android Gradle Plugin (AGP 8.2.0) and R8 dependencies into the user's Gradle cache (`~/.gradle/caches/modules-2/files-2.1/`).

### Distinguishing Dependency Resolution from OS Sandbox Isolation
- **OS Sandbox Isolation**: Ensures source repository files are never modified in-place and execution is strictly confined to temporary workspaces.
- **Gradle Network Independence**: AppShield defaults to offline builds. To perform an initial dependency fetch, the explicit `--allow-network-dependencies` flag can be passed during an authorized warm-up build on an isolated staging copy:
```powershell
uv run appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.yaml --output-dir dist/protected --allow-network-dependencies --mapping-out $privateMappingFile
```

### Verifying Cached Dependencies
Check local Gradle cache for AGP and R8 artifacts without initiating network queries:
```powershell
Test-Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\com.android.tools.build\gradle\8.2.0"
Test-Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\com.android.tools\r8"
```
Once present, all subsequent builds operate with default `--offline` isolation.

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

## Artifact Signing Status & Optional Test Signing

### Signing Status for Default Fixture
The default sample fixture configuration (`appshield.yaml`) specifies:
```yaml
signing:
  enabled: false
```
The output APK is 4-byte ZIP-aligned (`CHK-ALN-01: PASS`) but unsigned. When verifying:
- `CHK-SIG-01` reports `SKIPPED` (expected when signing is disabled).
- Because `CHK-SIG-01` is skipped and all other checks pass, `is_verified_protected` evaluates to `True`.
- Benign fixture tokens (e.g. `SAMPLE_FIXTURE_TOKEN_ALPHA`) report `CHK-STR-01: INFO` and do not block verification.

### Optional Disposable Test Signing Configuration
For testing environments where APK signature verification (`CHK-SIG-01: PASS`) is required, create a disposable debug keystore and use a separate test configuration (`appshield-test-signing.yaml`):
```powershell
# Generate a disposable local test keystore (NEVER use for production)
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

---

## Rollback / Environment Restoration

If you ever need to restore your environment variables to their exact pre-AppShield state, use the rollback script.

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
