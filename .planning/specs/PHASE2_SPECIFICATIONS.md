# Phase 2 Specifications: Architecture Contracts, Schemas & MVP Workflows

**Project:** AppShield  
**Phase:** 2 (Specifications, Threat Model, Architecture & Acceptance Criteria)  
**Date:** 2026-10-24  
**Status:** Complete Specification Draft for User Review  

---

## 1. Minimal Component Architecture & Contract Design

AppShield avoids unnecessary layers, enterprise dependency injection frameworks, and micro-abstractions. It is organized into 4 lean Python modules:

```
appshield/
├── cli.py             # CLI entrypoint (Typer/Click): protect, verify, doctor, info
├── config.py          # Configuration loader, validator, and schema definition
├── sandbox.py         # Workspace isolation manager (ephemeral staging, read-only input guard)
├── adapters/          # Pluggable platform execution engines
│   ├── base.py        # Abstract Base Class: PlatformAdapter
│   ├── android.py     # Android R8 & packaging adapter (MVP)
│   ├── ios.py         # iOS stub (Future integration: Phase 5)
│   └── windows.py     # Windows stub (Future integration: Phase 6)
└── verification/      # Verification & audit engine
    ├── base.py        # Abstract Base Class: VerificationEngine
    ├── checks.py      # Objective empirical checks (symbols, strings, signatures)
    └── reporter.py    # JSON & Markdown report generator
```

### Execution Flow
1. **Invocation**: User executes `appshield protect --config appshield.yaml` or passes flags.
2. **Config & Environment Validation**: `config.py` loads and validates the configuration. `doctor` preflight checks verify tool availability.
3. **Sandbox Initialization**: `sandbox.py` hashes the original input, mounts/copies it into `.appshield_staging/<build_id>/`, and locks the original source to read-only.
4. **Adapter Execution**: The appropriate `PlatformAdapter` transforms bytecode/binaries strictly within the sandbox.
5. **Signing**: Artifact is aligned and locally signed using credentials provided via masked environment variables.
6. **Verification Audit**: `VerificationEngine` analyzes the protected artifact against objective empirical criteria.
7. **Artifact Delivery**: Validated artifacts are copied to `dist/protected/`, along with `audit_report.json` and `audit_report.md`.
8. **Teardown**: The staging sandbox is wiped immediately.

---

## 2. CLI Configuration Schema (`appshield.yaml` / `.appshield.json`)

The configuration file is designed to be minimal, deterministic, and self-documenting.

### 2.1. YAML Example (`appshield.yaml`)

```yaml
version: "1.0"
project_name: "my_android_app"
platform: "android"

input:
  # Path to original APK, AAB, or compiled DEX/JAR
  path: "./samples/app-release-unsigned.apk"
  # Enforce read-only verification (default: true)
  verify_source_immutability: true

output:
  # Destination directory for hardened artifacts (must be distinct from source)
  dir: "./dist/protected"
  clean_before_run: true

android:
  # Mode: 'r8' (default) or 'proguard'
  engine: "r8"
  min_sdk: 21
  rules:
    - "./proguard-rules.pro"
  # Android package options
  obfuscate_classes: true
  obfuscate_strings: true
  shrink_resources: false
  
  # Signing configuration (Zero plaintext password rule)
  signing:
    enabled: true
    keystore_path: "./sample_keystore.jks"
    key_alias: "app_release_key"
    # Name of the environment variables storing passwords (NEVER plain passwords)
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
```

### 2.2. JSON Schema Definition

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "AppShieldConfig",
  "type": "object",
  "required": ["version", "project_name", "platform", "input", "output"],
  "properties": {
    "version": {
      "type": "string",
      "enum": ["1.0"]
    },
    "project_name": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_-]+$"
    },
    "platform": {
      "type": "string",
      "enum": ["android", "ios", "windows"]
    },
    "input": {
      "type": "object",
      "required": ["path"],
      "properties": {
        "path": { "type": "string" },
        "verify_source_immutability": { "type": "boolean", "default": true }
      }
    },
    "output": {
      "type": "object",
      "required": ["dir"],
      "properties": {
        "dir": { "type": "string", "default": "./dist/protected" },
        "clean_before_run": { "type": "boolean", "default": true }
      }
    },
    "android": {
      "type": "object",
      "properties": {
        "engine": { "type": "string", "enum": ["r8", "proguard"], "default": "r8" },
        "min_sdk": { "type": "integer", "minimum": 14, "default": 21 },
        "rules": { "type": "array", "items": { "type": "string" } },
        "obfuscate_classes": { "type": "boolean", "default": true },
        "obfuscate_strings": { "type": "boolean", "default": true },
        "shrink_resources": { "type": "boolean", "default": false },
        "signing": {
          "type": "object",
          "properties": {
            "enabled": { "type": "boolean", "default": false },
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
        "checks": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    }
  }
}
```

---

## 3. Interface Specifications (`PlatformAdapter` & `VerificationEngine`)

The interfaces are defined as standard Python Abstract Base Classes (`abc.ABC`) with strict type hinting, avoiding heavyweight runtime dependencies.

### 3.1. `PlatformAdapter` Interface

```python
"""
Abstract interface contract for platform-specific protection pipelines.
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
    """Base interface for all platform-specific protection adapters."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Returns the platform identifier: 'android', 'ios', or 'windows'."""
        pass

    @abstractmethod
    def check_prerequisites(self) -> List[PrerequisiteCheck]:
        """
        Inspects the host environment for required CLI binaries and compilers.
        Used by the `appshield doctor` subcommand and preflight validation.
        """
        pass

    @abstractmethod
    def protect(
        self,
        staged_input_path: Path,
        sandbox_dir: Path,
        config: Dict[str, Any]
    ) -> ProtectionResult:
        """
        Executes protection passes strictly within the provided staging sandbox.
        Must NEVER touch the original input path outside the sandbox.
        """
        pass

    @abstractmethod
    def sign(
        self,
        artifact_path: Path,
        sandbox_dir: Path,
        signing_config: Dict[str, Any]
    ) -> Path:
        """
        Performs local alignment and signing using environment-provided credentials.
        Returns the path to the signed artifact.
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
from typing import Dict, List, Literal, Any

@dataclass(frozen=True)
class CheckResult:
    check_id: str
    name: str
    category: str  # e.g., 'symbols', 'strings', 'signature', 'integrity'
    status: Literal["PASS", "FAIL", "SKIPPED", "INFO"]
    observed_metric: str  # e.g., "94.2% classes renamed", "0 plaintext keys found"
    details: Dict[str, Any]
    recommendation: Optional[str] = None

@dataclass(frozen=True)
class VerificationReport:
    timestamp: str
    artifact_name: str
    artifact_sha256: str
    file_size_bytes: int
    checks: List[CheckResult]
    passed_count: int
    failed_count: int
    disclaimer: str

class VerificationEngine(ABC):
    """Base interface for auditing hardened artifacts."""

    @abstractmethod
    def run_all_checks(
        self,
        artifact_path: Path,
        config: Dict[str, Any]
    ) -> VerificationReport:
        """
        Executes configured objective checks against the output binary.
        """
        pass
```

---

## 4. Objective Verification & Reporting Strategy

### 4.1. The "No Subjective Resistance Score" Rule
Per project objectives: **AppShield does NOT compute a composite, arbitrary "Resistance Score" (e.g. 87/100).** 

Scoring models create a false sense of security and mislead developers into believing software security can be reduced to an opaque grade. Instead, AppShield executes **verifiable, objective empirical checks** and reports concrete measurements.

### 4.2. Concrete Objective Checks

| Check ID | Check Name | Target Artifact | Empirical Method | Observable Metric Reported |
|:---|:---|:---|:---|:---|
| **CHK-SYM-01** | **Class & Method Renaming Ratio** | DEX / Smali | Inspect Dex class definitions; count total identifiers vs identifiers shortened to `a`, `b`, etc. | Total classes: `N`, Renamed: `M`, Ratio: `M/N * 100%`, Preserved list (e.g. entry points). |
| **CHK-STR-01** | **High-Entropy & Secret String Scan** | DEX string pool | Extract literal string constants; pattern-match common secrets (`AKIA...`, `api_key=`, URLs); calculate Shannon entropy. | Plaintext matches found: `0`, High-entropy strings encrypted: `YES/NO`. |
| **CHK-SIG-01** | **Cryptographic Signature Verification** | APK / AAB | Run `apksigner verify --verbose` | Verified schemes: `v1, v2, v3`, Signer Common Name, Validity period. |
| **CHK-ALN-01** | **4-Byte Page Alignment Check** | APK | Run `zipalign -c -v 4` | Verification status: `ALIGNED (PASS)` or `UNALIGNED (FAIL)`. |
| **CHK-DEC-01** | **Decompiler Structural Integrity** | APK / DEX | Run headless JADX / Baksmali disassemble pass | Decompilation status: `SUCCEEDED (Valid bytecode)`. Disassembled classes match DEX table. |

### 4.3. Verification Report Schema (`audit_report.json`)

```json
{
  "audit_version": "1.0",
  "project_name": "my_android_app",
  "generated_at": "2026-10-24T18:00:00Z",
  "artifact": {
    "name": "my_android_app-protected.apk",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size_bytes": 14285712
  },
  "summary": {
    "total_checks": 5,
    "passed": 5,
    "failed": 0,
    "skipped": 0
  },
  "objective_checks": [
    {
      "check_id": "CHK-SYM-01",
      "name": "Class Renaming Ratio",
      "category": "symbols",
      "status": "PASS",
      "observed_metric": "92.3% of non-entry classes renamed",
      "details": {
        "total_classes": 52,
        "renamed_classes": 48,
        "preserved_classes": ["com.example.app.MainActivity", "com.example.app.App"]
      }
    },
    {
      "check_id": "CHK-STR-01",
      "name": "String Constant Pool Scan",
      "category": "strings",
      "status": "PASS",
      "observed_metric": "0 exposed secret patterns detected",
      "details": {
        "scanned_string_count": 840,
        "flagged_literals": []
      }
    },
    {
      "check_id": "CHK-SIG-01",
      "name": "APK Signature Verification",
      "category": "signature",
      "status": "PASS",
      "observed_metric": "v2 and v3 signatures verified valid",
      "details": {
        "schemes": ["v2", "v3"],
        "signer": "CN=Android Release Key, O=AppShield Fixtures"
      }
    },
    {
      "check_id": "CHK-ALN-01",
      "name": "Zip Alignment Verification",
      "category": "integrity",
      "status": "PASS",
      "observed_metric": "4-byte zip alignment verified",
      "details": { "aligned": true }
    },
    {
      "check_id": "CHK-DEC-01",
      "name": "Decompiler Bytecode Parsing",
      "category": "integrity",
      "status": "PASS",
      "observed_metric": "Bytecode successfully parsed without Dalvik VM syntax faults",
      "details": { "headless_decompiler_exit_code": 0 }
    }
  ],
  "residual_risks": [
    "Entry-point classes (Activity/Service) preserve readable names to satisfy AndroidManifest requirements.",
    "Dynamic in-memory analysis via Frida/Xposed remains possible on rooted target devices."
  ],
  "disclaimer": "AppShield protection increases reverse-engineering work factors and halts automated static decompilers. It does not provide absolute protection against a determined adversary with runtime device control."
}
```

---

## 5. Android MVP: Real, Reproducible R8-Based Workflow

Rather than inventing a brittle DEX bytecode assembler, the Android MVP orchestrates the standard, official **Google R8** compiler toolchain.

### 5.1. Toolchain Prerequisites
Discovered via `appshield doctor`:
1. `java` (Java 11 or 17+ on PATH).
2. Android SDK `build-tools` (`zipalign`, `apksigner`, `d8`/`r8.jar`).
3. Standalone `r8.jar` fallback (can be bundled or downloaded once locally by user).

### 5.2. Pipeline Execution Steps

```
[Original APK] ──(read-only)──► Sandbox ──► Unpack APK ──► Extract DEX
                                                                │
                                                                ▼
                                                        Generate R8 Rules
                                                                │
                                                                ▼
                                                        Run R8 CLI
                                              (Shrinking & Obfuscation)
                                                                │
                                                                ▼
                                                        Updated DEX
                                                                │
                                                                ▼
                                                        Repack APK
                                                                │
                                                                ▼
                                                        zipalign (4-byte)
                                                                │
                                                                ▼
                                                        apksigner (local KS)
                                                                │
                                                                ▼
                                                        Verify (JADX audit)
                                                                │
                                                                ▼
                                                        [dist/protected/]
```

1. **Extraction**: Unzip the input APK in `.appshield_staging/<build_id>/`. Separate `classes*.dex`, assets, and `AndroidManifest.xml`.
2. **Rule Generation**: Synthesize default AppShield keep-rules:
   ```pro
   -keepattributes SourceFile,LineNumberTable
   -renamesourcefileattribute SourceFile
   -keep public class * extends android.app.Activity
   -keep public class * extends android.app.Application
   -keep public class * extends android.app.Service
   -keep public class * extends android.content.BroadcastReceiver
   -repackageclasses ''
   -allowaccessmodification
   ```
3. **R8 Invocation**:
   ```bash
   java -cp "$ANDROID_HOME/build-tools/<version>/lib/d8.jar" com.android.tools.r8.R8 \
     --release \
     --min-api 21 \
     --output ./staged_output/ \
     --pg-conf ./generated_rules.pro \
     --lib "$ANDROID_HOME/platforms/android-34/android.jar" \
     ./staged_input/classes.dex
   ```
4. **Repack & Align**:
   - Re-insert the obfuscated `classes.dex` into the staging APK archive.
   - Run `zipalign -p -f 4 ./staged_output/unaligned.apk ./staged_output/aligned.apk`.
5. **Signing**:
   - Sign via `apksigner`:
     ```bash
     apksigner sign --ks "$KEYSTORE_PATH" --ks-key-alias "$KEY_ALIAS" \
       --ks-pass "env:APPSHIELD_KS_PASS" --key-pass "env:APPSHIELD_KEY_PASS" \
       ./staged_output/aligned.apk
     ```
   - **Zero Password Exposure**: Uses `env:<VAR_NAME>` argument syntax natively supported by `apksigner`, ensuring passwords never appear in CLI process tables (`ps aux` / Task Manager).

---

## 6. Safety, Isolation, Credential Security & Boundaries

### 6.1. Source File Immutability
- Input files are opened strictly in read-only mode (`open(path, 'rb')`).
- Before and after execution, AppShield verifies that the input file's SHA-256 hash has not changed. If a mismatch is detected, execution immediately aborts with an integrity fault.

### 6.2. Workspace Sandboxing & Failure Recovery
- Staging directory is created at `.appshield_staging/<build_uuid>/` inside OS temporary directories or local cache.
- Wrapped in a Python context manager (`with SandboxContext(...) as sb:`):
  - On standard completion: output artifacts are copied to `dist/protected/`, and the sandbox is purged.
  - On exception or SIGINT (Ctrl+C): all temporary files are purged immediately.
  - If output writing fails mid-way, partial output in `dist/` is cleaned up to prevent broken artifacts.

### 6.3. Credential Safety
- Keystore passwords and private key passphrases are never accepted as raw command-line arguments or saved to configuration files.
- Configuration files reference environment variable names (e.g. `keystore_password_env: "MY_PASS"`).
- Internal logging filters scrub any token matching typical credential formats.

### 6.4. Air-Gapped Network Boundary
- The core CLI explicitly blocks any remote network activity.
- No telemetry, analytics pings, or cloud update checks.
- Python standard library network modules (`urllib.request`, `http.client`, `socket`) are strictly prohibited in the core protection and verification path.

---

## 7. Future Integrations Architecture (iOS & Windows)

iOS and Windows adapters are specified as non-breaking, pluggable extensions:

### 7.1. iOS Adapter (`appshield.adapters.ios`) — Phase 5
- **Host Requirement**: macOS with Xcode Command Line Tools.
- **Workflow**:
  1. Inspect Mach-O binary in unzipped IPA payload (`Payload/<App>.app/<Binary>`).
  2. Execute symbol stripping: `strip -x -S <Binary>`.
  3. Extract and sanitize dSYM bundles: `dsymutil`.
  4. Validate Mach-O load command alignment and code-signing requirements.
  5. Re-sign using Apple Developer identity: `codesign -f -s "<Identity>" --deep Payload/<App>.app`.

### 7.2. Windows Adapter (`appshield.adapters.windows`) — Phase 6
- **Host Requirement**: Windows / cross-platform Mono/CoreCLR.
- **Workflow**:
  1. For .NET assemblies: Orchestrate `obfuscar.console.exe` to rename types/methods and encrypt string resources.
  2. For native C/C++ PE binaries: Orchestrate `llvm-strip` or `dumpbin` to remove export/debug symbol tables.
  3. Run section entropy scan to ensure the output PE does not trigger common heuristic AV flags (e.g., section entropy <= 7.2 to avoid generic heuristic malware classification).

---

## 8. Measurable Acceptance Criteria & Disposable Test Fixtures

### 8.1. Acceptance Criteria for Phase 2 (Design Gate)
- [x] **AC-2.1**: Configuration schema defined in YAML and JSON Schema formats with strict validation rules.
- [x] **AC-2.2**: `PlatformAdapter` and `VerificationEngine` interfaces specified with Python type annotations.
- [x] **AC-2.3**: `audit_report.json` schema defined with objective, empirical checks (no arbitrary resistance score).
- [x] **AC-2.4**: Android R8 MVP workflow documented end-to-end with exact CLI commands and keep-rules.
- [x] **AC-2.5**: Source preservation, isolated output, credential safety, and recovery protocols documented.
- [x] **AC-2.6**: Disposable test fixture specification defined.

### 8.2. Disposable Test Fixture Specification (For Phase 3 & 4)
To satisfy the rule that *risky or destructive operations must only execute on disposable samples*, AppShield will include a minimal test fixture:

- **Location**: `tests/fixtures/sample_android/`
- **Fixture Artifact**: `mini_app.apk` (~15 KB pre-compiled APK).
- **Contents**:
  - `MainActivity.class` (inherits `android.app.Activity`)
  - `UserAuthenticator.class` (contains target test method `validateCredentials()`)
  - Plaintext string constant: `"SAMPLE_API_SECRET_98765"`
  - Hardcoded REST endpoint: `"http://internal.sample.local/v1/auth"`
  - `AndroidManifest.xml` declaring `MainActivity`
- **Purpose**:
  - Phase 3 test harness uses this fixture to verify input immutability (assert SHA-256 remains identical before and after run).
  - Phase 4 integration tests run R8 and verify that `UserAuthenticator` is renamed (e.g. to `a.a`) while `MainActivity` is kept per AndroidManifest keep-rules.
