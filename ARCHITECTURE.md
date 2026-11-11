# AppShield Architecture & Technical Design

This document details the system architecture, security invariants, component boundaries, and threat model considerations of AppShield.

---

## 1. System Overview & Orchestration Model

AppShield uses an **Orchestrator Architecture** rather than an in-house custom bytecode or binary obfuscator.

```
┌────────────────────────────────────────────────────────┐
│                   AppShield CLI                        │
│          (appshield protect / verify / doctor)         │
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │      PlatformAdapter      │
              │  (AndroidPipelineAdapter) │
              └─────────────┬─────────────┘
                            │
      ┌─────────────────────┼─────────────────────┐
      │                     │                     │
┌─────▼──────────┐   ┌──────▼─────────┐    ┌──────▼────────────┐
│ SandboxManager │   │  GradleRunner  │    │ VerificationEngine│
│  (Staging &    │   │  (AGP & R8     │    │  (7 Objective     │
│  Immutability) │   │  Execution)    │    │  Checks)          │
└────────────────┘   └────────────────┘    └───────────────────┘
```

### Rationale:
- **Stability**: Writing a proprietary DEX, Mach-O, or PE compiler backend is highly error-prone and frequently introduces subtle semantic bugs, runtime crashes, and verification errors.
- **Compatibility**: Official toolchains (Google R8 via AGP, Xcode CLI, Obfuscar) are maintained, tested against OS changes, and guaranteed to produce valid bytecode.
- **Orchestration Role**: AppShield automates the lifecycle: safe workspace staging, rule injection, build isolation, credential-masked signing, objective decompiler verification, and honest reporting.

---

## 2. Platform Adapter Architecture

All platform-specific build and protection logic adheres to the abstract interface defined in `appshield/adapters/base.py`:

- **`PlatformAdapter` Contract**:
  - `platform_name()`: Returns platform identifier (`android`, `ios`, `windows`).
  - `check_prerequisites()`: Queries host environment for required SDKs and CLI binaries.
  - `stage_and_protect()`: Executes the complete end-to-end staging, transformation, build, and verification workflow.
  - `sign_if_configured()`: Performs local alignment and signing if explicitly authorized.

- **`AndroidPipelineAdapter` Implementation**:
  - Validates project type: strictly requires an Android Gradle project (single- or multi-module, Groovy `build.gradle` or Kotlin `build.gradle.kts`) with `minifyEnabled true` / `isMinifyEnabled = true`, valid ProGuard/R8 rules without `-dontobfuscate`, and release APK Gradle tasks (rejecting `bundle*`/`.aab` or `debug` tasks).
  - Extracts `AndroidManifest.xml` entry-point components dynamically across arbitrary package names and custom module directories (e.g., `app`, `mobile`, `root`).
  - Explicitly rejects standalone precompiled APK inputs in v1 MVP.
  - Injects AppShield-specific rules into temporary staging copies without altering developer source files.
  - Validates `signing` paths, password environment variables, and production confirmation flags before starting Gradle builds.
  - Enforces release acceptance gates and `VerificationConfig` constraints before exporting any artifacts.

---

## 3. Ephemeral Staging & Source Tree Immutability

AppShield treats developer repositories as strictly read-only inputs.

```
Developer Source Project (Read-Only)
        │
        ├─► [Pre-Run SHA-256 Manifest Calculation]
        │
        ▼ (Copy files with sensitive exclusions)
Ephemeral Staging Sandbox (%TEMP%/appshield_staging/build_<uuid>)
        │
        ├─► [R8 Rules Injected into Staged proguard-rules.pro]
        ├─► [Gradle assembleRelease Executed]
        ├─► [Output APK Extracted to Temporary Location]
        │
        ▼ (Safe Directory Cleanup)
Developer Source Project (Verified Unchanged)
        │
        └─► [Post-Run SHA-256 Manifest Verification: Must match bit-for-bit]
```

### Staging Security Guarantees:
1. **Cryptographic Immutability**: All tracked files in the source tree are hashed before execution. A post-execution hash comparison guarantees zero in-place additions, modifications, or deletions (`SourceImmutabilityError` is raised on any variance).
2. **Sensitive File Exclusions**: Sensitive items (`*.jks`, `*.keystore`, `local.properties`, `*.env*`, `google-services.json`, `.git/**`) are excluded from staging copies to prevent accidental inclusion in compiled artifacts.
3. **Immutability Invariant**: While excluded from staging copies, sensitive credential files are **strictly included in source immutability manifests** to verify they were not tampered with.

---

## 4. Architectural Boundary: Filesystem Staging vs. OS Sandboxing

> [!IMPORTANT]
> AppShield's staging workspace is a **filesystem copy isolation mechanism, NOT an operating-system kernel process sandbox**.

- **Filesystem Isolation**: Ephemeral directories isolate build transformations and prevent polluting the developer's source tree.
- **Process Privilege Reality**: Subprocesses spawned during a build (`gradle.BAT`, `java.exe`, R8, `apksigner`) run with the **standard OS user credentials of the developer**. They are not restricted by Linux seccomp/cgroups, macOS seatbelt, or Windows AppContainers.
- **Untrusted Code Risk**: Gradle build scripts (`build.gradle`, plugins) execute arbitrary Groovy/Kotlin JVM bytecode.
- **Build Policy**: In v1, AppShield must only be executed against trusted developer projects or controlled disposable test fixtures. Untrusted external projects require future VM/container isolation.

---

## 5. Network Dependency Policy & Gradle Offline Mode

1. **Air-Gapped Default**: By default, `appshield protect` enforces `offline = true` (passing `--offline` to Gradle). Builds rely strictly on locally cached dependencies in `~/.gradle/caches/`.
2. **Authorized Dependency Warm-Up**: Passing `--allow-network-dependencies` allows a single authorized build to resolve and cache missing dependencies from Google Maven and Maven Central. Subsequent builds remain offline.
3. **Honest Isolation Disclaimer**: Gradle `--offline` mode is a **build-tool switch, not operating-system network isolation**. It instructs Gradle not to query remote repositories; it does not block raw network sockets if arbitrary JVM code within a build script attempts a socket connection.

---

## 6. APK Signing & Credential Safety Boundaries

AppShield enforces strict credential protection rules:

```
[Developer Environment] ──► $env:APPSHIELD_KS_PASS = "secret"
                                      │
                                      ▼ (Passed by name, NOT value)
[apksigner CLI Execution] ──► apksigner sign --ks-pass env:APPSHIELD_KS_PASS ...
                                      │
                                      ▼ (Read directly from process memory)
[Signed Output APK] ────────► Password never appears in CLI flags, logs, or reports
```

1. **Credential Masking & Process Isolation**: Keystore and key passwords are referenced exclusively via environment variable names (`apksigner --ks-pass env:<VAR>`, `keytool -storepass:env` / `-keypass:env`). Signing subprocesses (`keytool`, `zipalign`, `apksigner`) execute with sanitized `build_safe_env()` environments containing only the specifically required credentials rather than inheriting unrelated secrets or mutating parent `os.environ`.
2. **Pre-Build Validation & Production Gate**: Release signing is disabled by default. Enabling `signing.enabled: true` validates keystore existence, `key_alias`, configured password env vars, and `--allow-production-signing` (when `is_production: true`) before Gradle runs.
3. **Correct Order of Operations**:
   - 1. Build release APK (unsigned).
   - 2. Page-align unsigned APK using `zipalign -p -f 4`.
   - 3. Sign aligned APK using `apksigner sign`.
   - 4. Verify signature using `apksigner verify --verbose`.
   - 5. Confirm alignment on final signed APK using `zipalign -c -v 4` without modifying the signed file.
   - *Invariant*: An APK is never modified after signing.
4. **OS Environment Scope Disclaimer**: Process-local environment variables prevent command-line and process listing exposure (`Get-Process`, Task Manager). However, environment blocks of active processes remain inspectable by same-user or privileged debuggers on the local operating system.

---

## 7. R8 Obfuscation Mapping Protection

The ProGuard/R8 `mapping.txt` file is the translation key that maps obfuscated identifiers back to original class and method names.

1. **Public Output Exclusion**: The mapping file is **never copied to public release directories** (`dist/protected/`) by default and is never committed to Git (`.gitignore` explicitly excludes `**/mapping.txt`).
2. **Designated Private Retention**: When `--mapping-out <path>` is provided, AppShield securely writes the mapping file to a private developer location outside the repository (e.g. `~/.appshield/mappings/`).
3. **Deobfuscation Leak Prevention**: Audit reports (`audit_report.json`) calculate aggregate renaming statistics without including raw symbol maps or dictionary pairs.

---

## 8. Verification Engine & Objective Reporting

Post-protection verification replaces subjective marketing scores with empirical static audits:

| Check ID | Verification Dimension | Evidentiary Level | What It Proves | What It Does NOT Prove |
|:---|:---|:---:|:---|:---|
| **CHK-BLD-01** | Actual Build Completion | `VERIFIED` | Toolchain executed and exited with return code 0. | Does not prove the resulting binary is bug-free or secure. |
| **CHK-APK-01** | APK Structure & DEX Validity | `VERIFIED` | Archive format and Dalvik bytecode header/tables are valid. | Does not prove application runs correctly on a device. |
| **CHK-SYM-01** | Dual-Evidence Symbol Renaming | `VERIFIED` | Cross-verifies R8 `mapping.txt` renamed classes and `AndroidManifest.xml` entry points against DEX bytecode (failing if 0 classes renamed / `-dontobfuscate`). | Does not prove the app is impossible to reverse-engineer. |
| **CHK-SIG-01** | Cryptographic Signature Integrity | `VERIFIED` | APK is validly signed under v2/v3 signature schemes. | Does not prove application code is safe or malicious-free. |
| **CHK-ALN-01** | 4-Byte ZIP Page Alignment | `VERIFIED` | All archive entries align to 4-byte boundaries for mmap. | Does not prove application runtime stability. |
| **CHK-STR-01** | String Constant Pool Scan | `HEURISTIC` | Scans string constants for credentials/tokens with redaction. | Cannot guarantee that no obfuscated or dynamic secrets exist. |
| **CHK-CMP-01** | Informational Structural Inspection | `INFORMATIONAL` | Static Dalvik 035–040 header and table boundary compliance. | Does NOT prove runtime execution without live device testing. |

### Strict Status Separation & Configuration Enforcement:
- **`is_verified_protected`**: Set to `True` only when `verification.enabled` is `True`, all mandatory core checks (`CHK-BLD-01`, `CHK-APK-01`, `CHK-SYM-01`, `CHK-ALN-01`, plus `CHK-SIG-01` when signing is enabled) are executed and pass with 0 failures and 0 inconclusive checks.
- **Anti-Bypass Gate**: Excluding mandatory checks in `verification.checks` or setting `verification.enabled: false` marks skipped checks cleanly as `SKIPPED` and prevents `is_verified_protected = True`.
- **`is_installation_ready`**: Set to `False` for unsigned APKs, honestly reflecting that the Android OS Package Manager rejects unsigned packages upon installation.

---

## 9. Failure and Simulation Barriers

1. **Simulation Barrier**: Simulated or mocked adapters used during unit tests are strictly prohibited from exporting artifacts to production release paths (`dist/protected/`).
2. **Structured Error Handling**: CLI commands (`protect`, `verify`, `doctor`, `info`) catch adapter, Gradle, signing, DEX, mapping, sandbox, overwrite, immutability, and config errors cleanly, returning exit code `1` with actionable hints and redacted secrets rather than raw Python tracebacks.
3. **Atomic Rollback**: If compilation, R8 execution, or signing fails, temporary staging workspaces are automatically purged, preventing partial or corrupted artifacts from reaching release destinations.
4. **Overwrite Safeguards**: Output artifacts, standalone audit reports, and private mapping files are protected by `OverwriteError`. They will not overwrite existing files without explicit authorization (`--overwrite`).
