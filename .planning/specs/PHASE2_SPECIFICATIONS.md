# Phase 2 Specifications: Architecture Contracts, Schemas & MVP Workflows (Revised)

**Project:** AppShield  
**Phase:** 2 (Specifications, Threat Model, Architecture & Acceptance Criteria)  
**Date:** 2026-10-24  
**Status:** Revised Specification Draft for User Review  

---

## 1. Minimal Component Architecture & Contract Design

AppShield maintains a lean 4-module Python architecture without unnecessary abstraction layers:

```
appshield/
├── cli.py             # CLI entrypoint (Typer/Click): protect, verify, doctor, info
├── config.py          # Configuration loader, validator, and schema definition
├── sandbox.py         # Workspace isolation manager (ephemeral staging, read-only input guard)
├── adapters/          # Pluggable platform execution engines
│   ├── base.py        # Abstract Base Class: PlatformAdapter
│   ├── android_gradle.py # Android Gradle Plugin (AGP) + R8 build adapter (MVP)
│   ├── ios.py         # iOS stub (Future integration: Phase 5)
│   └── windows.py     # Windows stub (Future integration: Phase 6)
└── verification/      # Verification & audit engine
    ├── base.py        # Abstract Base Class: VerificationEngine
    ├── checks.py      # Objective empirical checks (symbols, strings, signatures)
    └── reporter.py    # JSON & Markdown report generator
```

### Supported Input Scope (MVP vs Unsupported)
- **Supported MVP Input**: Android application projects using **Gradle and the Android Gradle Plugin (AGP)** with Gradle wrapper (`gradlew`).
- **Unsupported in MVP**: Arbitrary precompiled APK-only input. Standalone APK obfuscation using raw R8 outside a project build tree requires complete external classpath context, Android platform libraries, and resource ID tables that cannot be reliably synthesized in a black-box manner without risk of runtime crashes. Standalone APK input is explicitly marked **unsupported** until a separate, technically validated protection engine (e.g. specialized Smali AST rewriter) is integrated.

---

## 2. CLI Configuration Schema (`appshield.yaml` / `.appshield.json`)

The configuration file is minimal, deterministic, and enforces safety boundaries.

### 2.1. YAML Specification (`appshield.yaml`)

```yaml
version: "1.0"
project_name: "sample_gradle_app"
platform: "android"

input:
  # Path to root of the Android Gradle project (Strictly read-only)
  project_dir: "./samples/android_sample_project"
  # Enforce bit-for-bit source immutability verification (default: true)
  verify_source_immutability: true
  # Patterns excluded when creating the isolated staging copy
  exclude_patterns:
    - ".git/**"
    - "build/**"
    - "**/build/**"
    - ".gradle/**"
    - "**/*.jks"
    - "**/*.keystore"
    - "local.properties"
    - "**/*.env*"
    - "**/google-services.json"

output:
  # Destination directory for hardened artifacts (must be distinct from source)
  dir: "./dist/protected"
  # Require explicit opt-in before overwriting existing files (default: false)
  overwrite_existing: false

android:
  project_type: "gradle"
  build_variant: "release"
  gradle_task: "assembleRelease"
  # Additional R8 rules to inject strictly into the isolated staging copy
  r8_rules_file: "./appshield-r8-rules.pro"
  
  # Signing configuration (No automatic production signing)
  signing:
    enabled: false  # Must be explicitly set to true by user
    is_production: false # Production signing requires explicit configuration
    keystore_path: "./sample_test_keystore.jks"
    key_alias: "test_key"
    # Environment variable names for passwords (NEVER plain passwords)
    keystore_password_env: "APPSHIELD_KS_PASS"
    key_password_env: "APPSHIELD_KEY_PASS"

verification:
  enabled: true
  fail_on_check_failure: false
  checks:
    - symbol_renaming_ratio
    - string_pool_inspection
    - signature_integrity
    - package_alignment
    - structural_decompilation_info
```

### 2.2. JSON Schema Definition

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AppShieldConfig",
  "type": "object",
  "required": ["version", "project_name", "platform", "input", "output"],
  "properties": {
    "version": { "type": "string", "enum": ["1.0"] },
    "project_name": { "type": "string", "pattern": "^[a-zA-Z0-9_-]+$" },
    "platform": { "type": "string", "enum": ["android", "ios", "windows"] },
    "input": {
      "type": "object",
      "required": ["project_dir"],
      "properties": {
        "project_dir": { "type": "string" },
        "verify_source_immutability": { "type": "boolean", "default": true },
        "exclude_patterns": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "output": {
      "type": "object",
      "required": ["dir"],
      "properties": {
        "dir": { "type": "string", "default": "./dist/protected" },
        "overwrite_existing": { "type": "boolean", "default": false }
      }
    },
    "android": {
      "type": "object",
      "properties": {
        "project_type": { "type": "string", "enum": ["gradle"], "default": "gradle" },
        "build_variant": { "type": "string", "default": "release" },
        "gradle_task": { "type": "string", "default": "assembleRelease" },
        "r8_rules_file": { "type": "string" },
        "signing": {
          "type": "object",
          "properties": {
            "enabled": { "type": "boolean", "default": false },
            "is_production": { "type": "boolean", "default": false },
            "keystore_path": { "type": "string" },
            "key_alias": { "type": "string" },
            "keystore_password_env": { "type": "string" },
            "key_password_env": { "type": "string" }
          }
        }
      }
    },
    "verification": {
      "type": "object",
      "properties": {
        "enabled": { "type": "boolean", "default": true },
        "fail_on_check_failure": { "type": "boolean", "default": false },
        "checks": { "type": "array", "items": { "type": "string" } }
      }
    }
  }
}
```

---

## 3. Interface Specifications (`PlatformAdapter` & `VerificationEngine`)

Standard Python Abstract Base Classes (`abc.ABC`) defining platform hooks:

### 3.1. `PlatformAdapter` Interface

```python
"""
Abstract interface contract for platform-specific build and protection pipelines.
Defined in appshield/adapters/base.py
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

@dataclass(frozen=True)
class PrerequisiteCheck:
    tool_name: str
    is_available: bool
    version: Optional[str]
    required: bool
    remediation_hint: str

@dataclass(frozen=True)
class ProtectionResult:
    success: bool
    protected_artifact_path: Optional[Path]
    logs: List[str]
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

class PlatformAdapter(ABC):
    """Base interface for all platform-specific build and protection adapters."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Returns the platform identifier: 'android', 'ios', or 'windows'."""
        pass

    @abstractmethod
    def check_prerequisites(self) -> List[PrerequisiteCheck]:
        """
        Inspects the host environment for required CLI binaries, SDKs, and build tools.
        Used by the `appshield doctor` subcommand and preflight validation.
        """
        pass

    @abstractmethod
    def stage_and_protect(
        self,
        source_project_dir: Path,
        sandbox_dir: Path,
        config: Dict[str, Any]
    ) -> ProtectionResult:
        """
        1. Copies source_project_dir into sandbox_dir excluding sensitive files.
        2. Applies necessary R8 configurations strictly inside sandbox_dir.
        3. Executes the build toolchain (e.g. Gradle assembleRelease) inside sandbox_dir.
        4. Extracts built APK artifact to a staging output location.
        Original source_project_dir is NEVER modified.
        """
        pass

    @abstractmethod
    def sign_if_configured(
        self,
        artifact_path: Path,
        sandbox_dir: Path,
        signing_config: Dict[str, Any]
    ) -> Path:
        """
        Performs local alignment and signing if explicitly enabled and configured.
        Requires non-production confirmation unless explicitly set.
        Returns the path to the signed (or unchanged) artifact.
        """
        pass
```

### 3.2. `VerificationEngine` Interface

```python
"""
Abstract interface contract for post-protection verification.
Defined in appshield/verification/base.py
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional, Any

OutcomeType = Literal["VERIFIED", "HEURISTIC", "INFORMATIONAL", "FAILED", "UNSUPPORTED"]

@dataclass(frozen=True)
class ObjectiveCheckResult:
    check_id: str
    name: str
    category: str
    outcome: OutcomeType
    status: Literal["PASS", "FAIL", "SKIPPED", "INFO"]
    what_it_proves: str
    what_it_does_not_prove: str
    observed_metric: str
    details: Dict[str, Any]
    recommendation: Optional[str] = None

@dataclass(frozen=True)
class VerificationReport:
    timestamp: str
    artifact_name: str
    artifact_sha256: str
    file_size_bytes: int
    checks: List[ObjectiveCheckResult]
    summary: Dict[str, int]
    disclaimer: str

class VerificationEngine(ABC):
    """Base interface for executing objective empirical checks against hardened artifacts."""

    @abstractmethod
    def run_all_checks(
        self,
        artifact_path: Path,
        config: Dict[str, Any]
    ) -> VerificationReport:
        """Executes configured objective checks and generates a structured report."""
        pass
```

---

## 4. Precise Verification Claims & Objective Evidence Matrix

AppShield strictly adheres to honest reporting:
- **No composite security score is computed or presented.**
- Every check explicitly documents what it proves, what it does not prove, and its verification classification.

### 4.1. Objective Evidence Matrix

| Check ID | Check Name | Classification | What It Proves | What It Does NOT Prove |
|:---|:---|:---|:---|:---|
| **CHK-SYM-01** | **Dual-Evidence Symbol Verification** | `VERIFIED` (Direct descriptor renaming) / `HEURISTIC` (Broader resistance inference) | Proves direct evidence that identified class descriptors were altered in `mapping.txt` and that mapped obfuscated descriptors exist in compiled DEX `class_defs` while original names are absent. | Does **NOT** prove that reverse engineering is impossible, that logic cannot be deduced from control-flow, or that reflection-safe entry points are protected. Broader inference of difficulty is `HEURISTIC`. |
| **CHK-STR-01** | **String Constant Pool Scan** | `HEURISTIC` | Proves that scanned literal strings matching known signature patterns (regex for API tokens, URLs, secrets) were not detected in plaintext in the constant pool. | Does **NOT** guarantee that no secrets exist in the binary. Sensitive data can be dynamically reconstructed, split across arrays, or missed by pattern filters. |
| **CHK-SIG-01** | **Cryptographic Signature Check** | `VERIFIED` | Proves whether the APK contains a cryptographically valid, untampered signature under Android APK Signature Schemes (v1, v2, and/or v3). | Does **NOT** prove the application code is secure, trustworthy, or bug-free. Malware and vulnerable apps can be validly signed. |
| **CHK-ALN-01** | **Zip Alignment Verification** | `VERIFIED` | Proves that uncompressed resources and shared libraries inside the APK archive start at 4-byte boundaries suitable for Android OS `mmap`. | Pure packaging format compliance check. Provides zero anti-tamper or security guarantee. |
| **CHK-CMP-01** | **Informational Structural Inspection** | `INFORMATIONAL` | Establishes whether Dalvik Executable byte streams comply with static header and table boundary specifications (DEX versions 035–040; version 041 unsupported). | Does **NOT** prove runtime functional correctness or execution safety. Static structure inspection cannot substitute for running on an actual Android device or emulator. |

### 4.2. Verification Report Schema (`audit_report.json`)

```json
{
  "audit_version": "1.0",
  "project_name": "sample_gradle_app",
  "generated_at": "2026-10-24T18:15:00Z",
  "artifact": {
    "name": "sample_gradle_app-release-protected.apk",
    "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "size_bytes": 1845120
  },
  "summary": {
    "total_checks": 5,
    "verified_passed": 2,
    "heuristic_passed": 2,
    "informational": 1,
    "failed": 0,
    "unsupported": 0
  },
  "objective_checks": [
    {
      "check_id": "CHK-SYM-01",
      "name": "Identifier Renaming Ratio",
      "category": "symbols",
      "outcome": "HEURISTIC",
      "status": "PASS",
      "what_it_proves": "Evidence that class/method/field symbol names were altered from original names to minified tokens.",
      "what_it_does_not_prove": "Does not prove that reverse engineering is impossible or that business logic cannot be analyzed.",
      "observed_metric": "91.4% of eligible non-entry classes renamed (32 of 35 classes)",
      "details": {
        "total_classes": 35,
        "renamed_classes": 32,
        "preserved_classes": [
          "com.appshield.sample.MainActivity",
          "com.appshield.sample.SampleApp"
        ]
      }
    },
    {
      "check_id": "CHK-STR-01",
      "name": "String Pool Constant Scan",
      "category": "strings",
      "outcome": "HEURISTIC",
      "status": "PASS",
      "what_it_proves": "Known regex signature patterns for API tokens were not detected in plaintext.",
      "what_it_does_not_prove": "Cannot guarantee that no secrets exist in the application.",
      "observed_metric": "0 flagged secret patterns detected across 412 string constants",
      "details": {
        "scanned_strings_count": 412,
        "flagged_matches": []
      }
    },
    {
      "check_id": "CHK-SIG-01",
      "name": "APK Signature Verification",
      "category": "signature",
      "outcome": "VERIFIED",
      "status": "PASS",
      "what_it_proves": "Artifact has a valid cryptographic signature under APK Signature Schemes v2 and v3.",
      "what_it_does_not_prove": "Does not prove the application code is secure or free of vulnerabilities.",
      "observed_metric": "Signature scheme v2 and v3 verified valid",
      "details": {
        "schemes": ["v2", "v3"],
        "signer": "CN=Test Key, O=AppShield Fixtures"
      }
    },
    {
      "check_id": "CHK-ALN-01",
      "name": "Zip Alignment Verification",
      "category": "integrity",
      "outcome": "VERIFIED",
      "status": "PASS",
      "what_it_proves": "Data boundaries aligned on 4-byte boundaries for memory mapping.",
      "what_it_does_not_prove": "Provides no security or anti-reverse-engineering guarantee.",
      "observed_metric": "4-byte zip alignment verified",
      "details": { "aligned": true }
    },
    {
      "check_id": "CHK-DEC-01",
      "name": "Structural Decompilation Inspection",
      "category": "integrity",
      "outcome": "INFORMATIONAL",
      "status": "INFO",
      "what_it_proves": "Bytecode structure parsed by disassembler without Dalvik format syntax crashes.",
      "what_it_does_not_prove": "Does not measure obfuscation strength or resistance to decompilation.",
      "observed_metric": "Headless disassembler parsed DEX structures cleanly",
      "details": { "parser_exit_code": 0 }
    }
  ],
  "disclaimer": "All measurements represent empirical evidence from automated static checks. A high renaming ratio or clean string scan increases reverse-engineering work factors, but does NOT prove the binary is impossible to reverse engineer. Reverse engineering of client-side code running on user-controlled devices remains possible."
}
```

---

## 5. Android MVP: Real, Reproducible Android Gradle & R8 Workflow

The Android MVP is built strictly around an **Android project that uses Gradle and the Android Gradle Plugin (AGP)**.

### 5.1. Workflow Architecture
```
[Original Android Project] (STRICTLY READ-ONLY)
         │
         ▼  (Exclude .git, build, *.jks, local.properties, .env)
[Isolated Sandbox: .appshield_staging/<build_uuid>/]
         │
         ├──► Inject AppShield R8 rules into staging proguard-rules.pro
         │
         ├──► Run ./gradlew assembleRelease (Supported AGP Toolchain)
         │       └─ AGP invokes R8 compiler with classpath & android.jar
         │
         ├──► Output APK generated inside sandbox: app/build/outputs/apk/release/
         │
         ├──► Align & Sign (Optional, with masked env vars & non-production guard)
         │
         └──► Check dist/protected/ destination (Fail if exists unless overwrite=true)
                   │
                   ▼
         [Copy to dist/protected/ & Run Verification Engine]
                   │
                   ▼
         [Atomic Sandbox Teardown]
```

### 5.2. Detailed Execution Steps
1. **Source Inspection (Read-Only)**:
   - Validate project structure: presence of `gradlew` (or `gradlew.bat`), `settings.gradle`, and `app/build.gradle`.
   - Calculate hash manifest of original files to verify immutability.
2. **Isolated Sandbox Staging**:
   - Create ephemeral directory `.appshield_staging/<uuid>/`.
   - Copy project tree into sandbox, strictly excluding:
     - Version control: `.git/**`, `.gitignore`
     - Cached build artifacts: `build/**`, `.gradle/**`
     - Credential and signing files: `**/*.jks`, `**/*.keystore`, `local.properties`, `**/*.env*`, `**/google-services.json`
3. **R8 Configuration Injection (Sandbox Only)**:
   - Merge AppShield default R8 hardening rules into the staging copy's `app/proguard-rules.pro`:
     ```pro
     # AppShield Default R8 Protection Rules
     -keepattributes SourceFile,LineNumberTable
     -renamesourcefileattribute SourceFile
     -repackageclasses ''
     -allowaccessmodification
     ```
   - Ensure `app/build.gradle` in staging has `minifyEnabled true` and references the rules file.
4. **Build via Supported Gradle Toolchain**:
   - Run inside the staging sandbox:
     ```bash
     ./gradlew assembleRelease --no-daemon --offline
     ```
   - Gradle and AGP invoke R8 with full access to Android SDK platform jars, dependencies, and resource mappings, producing a fully functional, properly shrunk and obfuscated APK.
5. **Separate Output Directory & Overwrite Guard**:
   - Target output path: `dist/protected/<project_name>-release-protected.apk`.
   - If destination file exists and `output.overwrite_existing` is `false`, execution terminates immediately with an error to prevent accidental data loss.
   - Output APK is copied cleanly to `dist/protected/`.
6. **Verification & Audit Reporting**:
   - `VerificationEngine` runs the objective checks on the generated APK.
   - Outputs `dist/protected/audit_report.json` and `dist/protected/audit_report.md`.
7. **Sandbox Cleanup**:
   - Staging directory is completely wiped from disk.

---

## 6. Safety, Credential Protection & File Preservation

### 6.1. Source Preservation Guarantees
- Original project directory is never written to or modified in place.
- In-memory hash manifest is checked before staging and after execution to guarantee zero source corruption.

### 6.2. Sensitive File Exclusion from Staging
When copying the project to staging, AppShield applies mandatory exclusion filters:
- Version control (`.git/`)
- Existing build caches (`build/`, `.gradle/`)
- Keystores and certificates (`*.jks`, `*.keystore`, `*.p12`, `*.pem`)
- Local configuration and environment variables (`local.properties`, `*.env`, `*.env.*`)
- Service credentials (`google-services.json`, `service-account*.json`)

### 6.3. Credential Protection & Non-Production Guard
- **No Automatic Production Signing**: By default, `signing.enabled` is `false`. Even if enabled, `is_production` must be explicitly acknowledged by the developer. AppShield will refuse to sign production release builds automatically.
- **Zero Logged Credentials**: Passwords are read strictly from environment variable names (`keystore_password_env`, `key_password_env`). Passwords are never passed via CLI flags or written to config/report files.
- **No File Overwrites**: Existing output artifacts are never overwritten without explicit `--overwrite` CLI flag or `overwrite_existing: true` in config.

### 6.4. Failure Recovery & Network Boundaries
- Wrapped in Python context manager (`with SandboxContext() as sb:`).
- On failure (build error, exception, Ctrl+C), temporary directories are purged immediately.
- Partial or incomplete output files are deleted from `dist/protected/`.
- Air-gapped execution: No network requests, telemetry, or remote calls.

---

## 7. Future Integrations Architecture (iOS & Windows)

- **iOS Adapter** (`appshield.adapters.ios` — Phase 5): Deferred. Will support Xcode project / workspace builds with symbol stripping (`strip -x`), `dsymutil`, and local `codesign`.
- **Windows Adapter** (`appshield.adapters.windows` — Phase 6): Deferred. Will support MSBuild / .NET solution builds with Obfuscar post-build integration and PE symbol stripping.

---

## 8. Measurable Acceptance Criteria & Disposable Test Fixtures

### 8.1. Acceptance Criteria for Revised Phase 2 (Design Gate)
- [x] **AC-2.1**: Configuration schema supports Android Gradle project input, sensitive file exclusions, and overwrite guards.
- [x] **AC-2.2**: `PlatformAdapter` and `VerificationEngine` interfaces specified with strict typing and objective check outcomes.
- [x] **AC-2.3**: Verification evidence matrix defined documenting what every check proves, does not prove, and its outcome classification (no composite score).
- [x] **AC-2.4**: Android Gradle & AGP R8 MVP workflow mapped out end-to-end. Arbitrary standalone APK input explicitly declared unsupported.
- [x] **AC-2.5**: Source preservation, sensitive file exclusion, credential protection, and overwrite guards documented.
- [x] **AC-2.6**: Minimal Android Gradle disposable test fixture specified.

### 8.2. Disposable Test Fixture Specification (For Phase 3 & 4)
Replaces precompiled APK fixture with a minimal, reproducible Android Gradle sample project:

- **Location**: `tests/fixtures/sample_android_gradle_project/`
- **Structure**:
  ```
  sample_android_gradle_project/
  ├── gradlew
  ├── gradlew.bat
  ├── gradle/wrapper/gradle-wrapper.properties
  ├── settings.gradle
  ├── build.gradle
  └── app/
      ├── build.gradle (configured with AGP, release buildType, minifyEnabled true)
      ├── proguard-rules.pro
      └── src/main/
          ├── AndroidManifest.xml (declares MainActivity)
          └── java/com/appshield/sample/
              ├── MainActivity.java (entry-point Activity, deliberately kept)
              └── IdentifiableSecretService.java (deliberately identifiable class)
  ```
- **Deliberately Identifiable Elements for Verification**:
  - Class: `IdentifiableSecretService`
  - Method: `processUserTokenAndCalculateHash()`
  - Identifiable constant string: `"APP_SHIELD_TEST_STRING_LITERAL_XYZ"`
- **Test Invariants**:
  - **Source Preservation Test**: Verify that `sample_android_gradle_project/` is byte-identical before and after protection.
  - **Obfuscation Evidence Test**: Verify that in the generated APK, `IdentifiableSecretService` and `processUserTokenAndCalculateHash` are renamed by R8, while `MainActivity` is kept.
  - **Exclusion Test**: Verify that if a mock `test.jks` or `local.properties` is placed in the fixture, it is excluded from the staging sandbox.
