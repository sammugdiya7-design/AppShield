# AppShield Android Toolchain Setup & Protection Execution Runbook

This runbook provides the verified, step-by-step execution procedure for setting up the local Android build toolchain and executing the genuine AppShield protection workflow against the repository-owned sample fixture (`tests/fixtures/sample_android_gradle_project`).

All commands must be executed in PowerShell from the repository root directory (`appshield`).

---

## Prerequisites & Operational Rules

1. **User Scope Only**: All downloads and environment modifications operate strictly at `User` scope (`$env:USERPROFILE` and `$env:LOCALAPPDATA`). No administrative or Machine-level changes are required.
2. **Environment Variable Consistency**: In PowerShell, environment variables are referenced using `$env:NAME` (e.g. `$env:LOCALAPPDATA`, `$env:USERPROFILE`, `$env:JAVA_HOME`, `$env:Path`).
3. **Session Behavior**: `configure-user-environment.ps1` sets user registry environment variables and immediately refreshes the active PowerShell process environment (`$env:JAVA_HOME`, `$env:ANDROID_HOME`, `$env:Path`). Restarting your PowerShell session in the same terminal is not required. Any newly opened terminal window will also inherit the variables automatically.
4. **Source Immutability**: The repository fixture (`tests/fixtures/sample_android_gradle_project/`) is treated as strictly read-only. AppShield copies the project into an isolated temporary staging workspace before applying R8 rules and executing Gradle.
5. **Private Mapping Protection**: R8 `mapping.txt` files are retained privately outside the repository using `--mapping-out`. Destination files and reports will not be overwritten without explicit `--overwrite`.

---

## Phase 1: Download & Verify Toolchain Binaries

Downloads and validates official SHA-256 checksums for Eclipse Temurin OpenJDK 17 LTS (17.0.21+9), Google Android Command-Line Tools (15859902), and Gradle 8.2.

### Step 1.1: Preview Planned Downloads (Dry-Run)
Inspect planned downloads, target locations, and checksum verification URLs without downloading any files:
```powershell
& scripts/setup/download-toolchain.ps1 -Preview
```

### Step 1.2: Execute Verified Download and Staged Extraction
Download the archives, verify SHA-256 hashes against official vendor checksums, extract into staging, and place them into user directories:
```powershell
& scripts/setup/download-toolchain.ps1
```

*Installed Targets:*
- OpenJDK 17: `$env:USERPROFILE\.jdk\jdk-17.0.21+9`
- Android Command-Line Tools: `$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest`
- Gradle 8.2: `$env:USERPROFILE\.gradle\gradle-8.2`

---

## Phase 2: Configure User Environment Variables

Backs up the existing environment state to `$env:USERPROFILE\.appshield\backup\` and idempotently configures `JAVA_HOME`, `ANDROID_HOME`, and `User` PATH additions.

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
1. `$env:USERPROFILE\.jdk\jdk-17.0.21+9\bin`
2. `$env:LOCALAPPDATA\Android\Sdk\cmdline-tools\latest\bin`
3. `$env:LOCALAPPDATA\Android\Sdk\build-tools\34.0.0`
4. `$env:USERPROFILE\.gradle\gradle-8.2\bin`
5. `$env:LOCALAPPDATA\Android\Sdk\platform-tools`

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

Verify that the local environment satisfies all required toolchain prerequisites.

### Step 4.1: Execute Prerequisite Inspection
```powershell
uv run appshield doctor --project-dir tests/fixtures/sample_android_gradle_project
```

*Expected Status:* Exit code `0`, all required prerequisites report `Installed`, and summary confirms `All required prerequisites are met.`

---

## Phase 5: Execute Genuine Android Protection & Empirical Verification

Executes the genuine Android Gradle R8 protection pipeline against the fixture project, validates source immutability, aligns and test-signs the APK, securely exports the R8 mapping, and runs empirical decompiler verification checks.

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
Stage fixture in an isolated workspace, inject R8 rules, build release APK via Gradle, zipalign, sign with disposable test key, and verify:
```powershell
uv run appshield protect -c tests/fixtures/sample_android_gradle_project/appshield.json --mapping-out $privateMappingFile
```

### Step 5.3: Run Standalone Empirical Verification
Perform independent verification of all 7 empirical checks against the compiled APK and exported mapping:
```powershell
uv run appshield verify dist/protected/sample_android_gradle_project-release-protected.apk -m $privateMappingFile -o dist/protected/standalone_audit.json
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
