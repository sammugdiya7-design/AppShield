# MEMORY.md — AppShield Living Project Memory

*Permanent project memory and operational rules. Must be read before starting every task.*

---

## 1. Project Vision, Goals & Non-Goals

### Vision
A simple, local, cross-platform application code-protection CLI for developers targeting Android, iOS, and eventually Windows, designed to raise reverse-engineering work factors without vendor lock-in, recurring SaaS fees, or cloud privacy risks.

### Goals
- **100% Local Execution**: Zero remote network transmission of source code, binaries, or signing credentials.
- **Source Preservation**: Absolute immutability of developer source trees and original binaries.
- **Tool Orchestration**: Wrap existing, compatible, battle-tested tools instead of inventing unstable custom obfuscation compilers.
- **Isolated Staging**: Build and transform exclusively in temporary, sandboxed scratch directories with separate output destinations.
- **Empirical Verification**: Automate post-protection decompiler audits (e.g. headless JADX, symbol scrapers) to measure actual protection.
- **Honest Reporting**: Quantify resilience and explicitly disclaim impossible claims like "100% unbreakable".

### Non-Goals
- Inventing a custom DEX, Mach-O, or PE compiler backend.
- Cloud-based telemetry, analytics, or remote signing servers.
- Marketing "unbreakable DRM" or claiming reverse engineering is impossible.
- In-memory anti-hooking/root evasion without developer app-level SDK integration.

---

## 2. Architecture & Key Technical Decisions

| Area | Decision | Rationale |
|:---|:---|:---|
| **Core Architecture** | CLI Orchestrator with pluggable platform adapters | High stability; avoids semantic bytecode compiler bugs. |
| **Language & Runtime** | Python 3.10+ | Standard cross-platform library (`subprocess`, `tempfile`, `pathlib`), zero binary compile step. |
| **Workspace Staging** | Ephemeral `.appshield_staging/<build_id>` sandbox | Prevents contamination of developer repositories; ensures input immutability. |
| **Verification Loop** | Headless automated decompiler audit (JADX, symbol scan) | Replaces "security theater" with empirical verification. |
| **Licensing Boundary** | MIT/Apache core; GPL tools run strictly as external CLI subprocesses | Prevents viral GPL contamination of the AppShield codebase. |
| **Platform Strategy** | Phased rollout: Android (v1) -> iOS (v2) -> Windows (v2) | Focuses engineering effort on the highest-demand, most accessible mobile platform first. |
| **Objective Verification** | Empirical checks only; no composite "resistance score" | Opaque numerical scores provide a false sense of security; objective counts and percentages provide auditable truth. |
| **Android MVP Engine** | Official Google R8 via AGP 8.2.2 + `zipalign` + `apksigner` | Reliable, modern industry standard; avoids custom bytecode decompiler bugs. |
| **Toolchain Target Standard** | JDK 17 + Gradle 8.2 + AGP 8.2.2 + SDK 34 + Build-Tools 34.0.0 | Selected target version matrix based on AGP compatibility docs; not claimed tested end-to-end until live build succeeds. |
| **Credential Masking** | Passwords referenced exclusively via env var names | Eliminates plaintext credentials from CLI flags, process lists, and disk files. |
| **Disposable Test Fixtures** | Isolated sample Android Gradle project (`sample_android_gradle_project`) for test suites | Satisfies safety rule: destructive/mutating operations run exclusively on disposable fixtures. |
| **Simulation Barrier** | Simulation strictly isolated in test suite; production CLI stops if toolchain missing | Never emit fake or simulated APKs to `dist/protected/`; protection claims require real builds. |
| **Mapping Protection** | R8 `mapping.txt` kept out of public output, logs, and git; secure retention optional | Prevents deobfuscation leakage while allowing crash-trace retention at separate path. |
| **Signing Sequence** | Build -> zipalign unsigned -> apksigner -> apksigner verify -> zipalign -c | Never modify APK after signing. Test-signed only for fixture; production signing opt-in. |
| **DEX Format Scope** | Standard DEX 035–040 supported; DEX 041 explicitly unsupported | MVP targets AGP 8.2 / Android API 34; Container DEX 041 uses an altered container header layout. |
| **Symbol Verification Separation** | Direct descriptor renaming match is `VERIFIED`; broader resilience claim is `HEURISTIC` | Direct mapping & DEX match proves identified symbols were renamed; does not prove application is unbreakable. |
| **Repackaging Support** | Derived dynamically from mapping data (supports default and custom package repackaging) | Avoids hardcoded package assumptions; verifies mapped descriptors in actual compiled APK. |
| **Structural Compatibility Claim** | Strictly labeled "Informational Structural Inspection" | Confirms Dalvik header/table structure; does not prove runtime execution without device testing. |

---

## 3. Current Phase & Progress

- **Current Phase**: Phase 4: Android Protection Pipeline & Verification Engine
- **Current Plan**: Plan 04-04 Complete
- **Status**: Phase 4 completed and empirically verified end-to-end: real Android Gradle release build, R8 obfuscation, test signing, and live runtime execution validated on Android emulator-5554 (API 37) (1 live build validated, 1 test-signed release verified, 1 live runtime execution verified; 301 automated tests passing with 93% coverage; ruff/mypy/bandit 100% clean). P0 and P1 release remediation completed.
- **Overall Progress**: 75% (Phases 1, 2, 3, & 4 complete; 9 of 12 total plans completed)

---

## 4. Completed Features & Pending Tasks

### Completed
- [x] Initialized GSD planning infrastructure (`PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`, `config.json`).
- [x] Completed Phase 1 Research dossier (`.planning/research/PHASE1_RESEARCH.md`).
- [x] Established root-level `MEMORY.md` and permanent project governance rules.
- [x] Completed Phase 2 Specifications dossier (`.planning/specs/PHASE2_SPECIFICATIONS.md`) covering CLI schema, interfaces, report schema, R8 MVP, and test fixtures.
- [x] Completed Plan 03-01: Python CLI Foundation (Approved by user):
  - `pyproject.toml` configuration with editable package support and development dependencies.
  - `README.md` created documenting project invariants, CLI usage, and test commands.
  - `appshield/cli.py`: Implemented CLI entry point and subcommands (`info`, `doctor`, `protect`, `verify`).
  - `appshield/config.py`: Implemented YAML/JSON configuration loader, schema validation, APK rejection, password masking, default exclusions, and `validate_output_destination` overwrite guard.
  - `appshield/doctor.py`: Local environment prerequisite detection (Java, Javac, `JAVA_HOME`, `ANDROID_HOME`, Gradle/gradlew, `zipalign`, `apksigner`).
  - Automated tests: 52 unit tests in `tests/test_cli.py`, `tests/test_config.py`, and `tests/test_doctor.py` passing with 99% test coverage.
  - Linter (`ruff`), type checker (`mypy`), and security scanner (`bandit`) clean with zero issues.
- [x] Completed Plan 03-02: Workspace Sandbox Manager and Workspace Isolation:
  - `appshield/sandbox.py`: Implemented `SandboxManager` (and `SandboxContext` alias), `SourceManifest`, `safe_remove_tree`, `is_path_excluded`, and `check_symlink_safety`.
  - Source tree immutability: Computes SHA-256 manifest before and after staging; detects additions, deletions, and modifications.
  - Sensitive files in immutability manifest: `*.jks`, `local.properties`, `*.env*`, and `google-services.json` are excluded from staging copies but strictly tracked in the source immutability manifest.
  - Workspace staging: Staged in isolated ephemeral build directories under system temp by default; original source tree treated strictly as read-only.
  - Sensitive file exclusions: Excludes `.git/**`, `build/**`, `.gradle/**`, `*.jks`, `*.keystore`, `local.properties`, `*.env*`, `google-services.json`, and `.appshield_staging/**` from staging copies.
  - Failure recovery: Staging failures and errors trigger automatic, safe cleanup of the temporary sandbox without touching external files.
  - Security defenses: Path traversal guards on staging and artifact export; symlink escaping checks; Windows read-only attribute handling.
  - Output safeguards: `export_artifact` enforces destination existence checks and overwrite protection.
  - Automated tests: 31 unit tests in `tests/test_sandbox.py` passing with 95% coverage.
  - Static analysis: `ruff`, `mypy`, and `bandit` passing with 0 warnings.
- [x] Completed Plan 03-03: Disposable Android Gradle Test Fixture and Integration Harness:
  - Created controlled disposable Android Gradle project fixture in `tests/fixtures/sample_android_gradle_project/` with standard structure (`gradlew`, `gradlew.bat`, `gradle-wrapper.properties`, `settings.gradle`, `build.gradle`, `app/build.gradle`, `app/proguard-rules.pro`, `AndroidManifest.xml`, `strings.xml`, `MainActivity.java`, `IdentifiableSecretService.java`, `PaymentSecurityValidator.java`, `appshield.yaml`, `README.md`).
  - Included identifiable test symbols (`IdentifiableSecretService`, `PaymentSecurityValidator`, `processUserTokenAndCalculateHash`, `calculateInternalSecurityChecksum`, `validateTransactionToken`) and non-sensitive strings (`APP_SHIELD_TEST_STRING_LITERAL_XYZ`, `DISPOSABLE_TEST_PAYMENT_SECRET_TOKEN`, `NON_SENSITIVE_VALIDATION_SCHEME_V1`) for future R8 verification.
  - Zero real secrets, private keys, or personal credentials contained in fixture.
  - Implemented `is_android_gradle_project` in `appshield/doctor.py` and exported in `appshield/__init__.py`. Integrated into `run_doctor_checks` when `--project-dir` is provided.
  - Added 10 automated integration tests in `tests/test_integration_fixture.py` (total 93 tests across suite) passing with 95% code coverage.
  - Tests verify structure, supported project detection, source preservation, sensitive file exclusion, path/symlink safety, prerequisite diagnostic messages, and safely distinguish live vs. simulated builds under offline/safe testing boundaries.
- [x] Completed Plan 04-01: Android Gradle Pipeline Adapter, Toolchain Discovery, and R8 Rule Staging:
  - `appshield/adapters/base.py`: Defined abstract `PlatformAdapter` contract, structured dataclasses (`PrerequisiteCheck`, `ProjectInspection`, `ProtectionResult`), and custom exception hierarchy (`AdapterError`, `UnsupportedProjectError`, `ConfigurationInspectionError`, `RuleStagingError`).
  - `appshield/adapters/android.py`: Implemented `AndroidPipelineAdapter`, supported project detection, standalone precompiled APK rejection, multi-module layout inspection, release minification checking (`minifyEnabled true`), rules file validation, safe R8 rule staging into isolated staging sandbox, and defense against accidental test symbol keep-rules.
  - `appshield/adapters/__init__.py`: Exported public adapter API.
  - Extended `appshield/doctor.py` and `appshield/cli.py`: Integrated JDK 17, `JAVA_HOME`, Android SDK, `ANDROID_HOME`, Platform 34, Build-Tools 34.0.0 (`zipalign`, `apksigner`), Wrapper scripts/distribution URL (Gradle 8.2), missing `gradle-wrapper.jar` detection, AGP version extraction, and R8 release configuration verification. Formatted doctor output to distinguish detected versions, selected target versions, and live build validation status (0 live builds validated).
  - Automated tests: Added 28 unit tests in `tests/test_android_adapter.py` and 9 tests in `tests/test_doctor.py` (total 124 tests in test suite) passing with 94% overall code coverage.
  - Zero live builds executed; zero remote downloads or network requests triggered; original source preserved and unchanged.

- [x] Completed Plan 04-02: Safe Gradle Build Execution, APK Output Extraction, and Test Signing:
  - `appshield/gradle.py`: Implemented controlled Gradle build runner (`GradleRunner`), safe subprocess execution without `shell=True`, safe environment policy preserving system variables while stripping credentials, diagnostic capture with automated secret redaction, process tree termination on timeout (`taskkill` on Windows, `killpg` on POSIX), Gradle task name validation, discovery and verification of release APK (`locate_build_apk`) and R8 mapping file (`locate_r8_mapping`), and APK archive validation (`validate_apk_file`).
  - `appshield/signing.py`: Implemented verified 5-step signing pipeline (locate unsigned APK -> zipalign -> apksigner sign with masked env vars -> verify signature -> check alignment on signed APK without modifying it). Added non-production signing guards, disposable test keystore generation (`generate_disposable_test_keystore`), credential redaction, and distinct labeling (`unsigned`, `test_signed`, `production_signed`).
  - Integrated into `AndroidPipelineAdapter.stage_and_protect()`: Prerequisite verification preventing simulated execution on missing host toolchains; staging in ephemeral sandbox; R8 rules injection; Gradle build; release APK discovery; alignment/signing; destination overwrite safeguards; and source immutability verification.
  - Automated tests: Added 45 unit tests in `tests/test_gradle.py`, 33 unit tests in `tests/test_signing.py`, and updated `tests/test_android_adapter.py` (total 205 tests across suite) passing with 93% code coverage.
  - Static analysis: `ruff check` (0 errors), `ruff format` (clean), `mypy` (0 errors in 18 source files), `bandit` (0 issues).
  - Safety & Boundary Confirmation: Host toolchain prerequisites remained unavailable (Java 8 vs 17, missing SDK 34, missing wrapper JAR); runner and adapter verified to fail clearly and safely without executing unapproved builds, downloading binaries, or emitting fake APKs.

- [x] Completed Plan 04-03: Empirical Verification Engine, String Pool Scanner & Mapping Auditor:
  - `appshield/dex.py`: Implemented robust, defensive DEX bytecode inspector for DEX format (versions 035-040). Safely parses DEX headers, endianness, string identifier tables, type identifiers, and class definition tables with strict bounds checking. Implemented `inspect_apk_dex()` for multidex APKs (`classes.dex`, `classes2.dex`, etc.) and `create_synthetic_dex()` for generating binary-compliant synthetic DEX test fixtures without requiring an Android SDK. Treated all DEX structures as untrusted data without executing APK bytecode.
  - `appshield/mapping.py`: Implemented R8 ProGuard `mapping.txt` parser. Extracts class, method, and field obfuscation remappings, computes aggregate renaming ratios, and extracts R8 compiler metadata (`compiler`, `compiler_version`). Keeps raw mappings out of reports to avoid leaking obfuscation internals.
  - `appshield/verify.py`: Implemented `VerificationEngine` with 7 objective, evidence-based verification checks:
    - `CHK-BLD-01`: Build execution status (`VERIFIED` on real build, `INFORMATIONAL` on synthetic/test artifacts, `FAILED` on failure).
    - `CHK-APK-01`: APK structure and DEX validity (`VERIFIED` or `FAILED`).
    - `CHK-SYM-01`: Dual-evidence symbol verification (`HEURISTIC`). Verifies that original developer symbols are absent from DEX class descriptors, mapped obfuscated descriptors exist in DEX bytecode, and entry point classes are preserved. Correctly identifies stripped dead code as missing rather than misclassifying it as obfuscated.
    - `CHK-SIG-01`: Cryptographic signature verification via `apksigner verify` (`VERIFIED`, `FAILED`, or `UNSUPPORTED`).
    - `CHK-ALN-01`: 4-byte ZIP alignment verification via `zipalign -c` (`VERIFIED`, `FAILED`, or `UNSUPPORTED`).
    - `CHK-STR-01`: Heuristic string pool scanner (`HEURISTIC`). Scans DEX string tables for sensitive patterns (API keys, tokens, credentials, fixture tokens) with mandatory redaction (`[REDACTED_SECRET_PATTERN]`, `[REDACTED_FIXTURE_TOKEN]`) in output reports.
    - `CHK-CMP-01`: Bytecode structural compatibility evidence (`INFORMATIONAL`).
  - Strict reporting guarantees: Defined `VerificationReport` with export to JSON (`audit_report.json`), formatted terminal output, and GitHub-flavored Markdown. Explicitly banned composite numerical "resistance scores"; every check reports precise evidence levels, findings, and disclaimers.
  - Environment variable isolation (Requirement 7): Verified signing passwords (`APPSHIELD_KS_PASS`, etc.) never leak into subprocess environments.
  - Automated tests: Added 25 unit tests in `tests/test_dex.py` and 25 unit tests in `tests/test_verify_engine.py` (total 255 tests across suite) passing with 94% code coverage (`dex.py`: 96%, `mapping.py`: 98%, `verify.py`: 91%).
  - Static analysis: `ruff check` (0 errors), `ruff format` (clean), `mypy` (0 errors in 23 source files), `bandit` (0 issues).
- [x] Completed Plan 04-04: End-to-End CLI Integration, Automated Test Matrix, and Security Validation:
  - `appshield/cli.py`: Wired `appshield protect` and `appshield verify` commands directly into `AndroidPipelineAdapter.stage_and_protect()` and `VerificationEngine.run_all_checks()`. Added CLI options `--allow-production-signing`, `--mapping-out`, `-m / --mapping-file`, and `-o / --output`.
  - Full protection lifecycle coordination: Integrates preflight validation, prerequisite checking, ephemeral staging in sandbox, R8 rule injection, Gradle build execution, APK and mapping file extraction, unsigned alignment, APK signing (test vs production authorization), empirical verification of all 7 checks, JSON (`audit_report.json`) and Markdown (`audit_report.md`) audit generation, source tree immutability verification, and release acceptance export.
  - Strict simulation barrier: Rejects simulated/mocked runners in production workflows; even under test execution with `allow_simulated=True`, artifacts from simulated runs are NEVER exported into `dist/protected/`.
  - Release acceptance gate: Enforces that `is_verified_protected` requires a real toolchain build (`CHK-BLD-01` PASS), valid APK archive and parseable DEX (`CHK-APK-01` PASS), verified renaming of target classes in mapping and compiled DEX (`CHK-SYM-01` PASS), zero check failures across all checks, and identical source tree SHA-256 hashes.
  - Mapping security & privacy: `mapping.txt` is retained privately only when `--mapping-out` is provided; never placed in public output directories, never committed, and raw mappings never displayed in public audit reports.
  - Test suite expansion: Added comprehensive end-to-end integration test suite in `tests/test_android_pipeline.py` (11 tests) and expanded CLI tests in `tests/test_cli.py` (total 276 tests across suite) passing with 93% code coverage.
  - Static analysis: `ruff check` (0 errors), `ruff format` (clean), `mypy` (0 errors in 24 source files), `bandit` (0 issues).
  - Honest Toolchain Reporting: Acknowledges that local host lacks complete toolchain (JDK 17, Android SDK 34, wrapper JAR); live builds remain unvalidated (0 live builds validated) pending a workstation with full toolchain installed.
- [x] Completed Toolchain & Verification Defect Resolution (Audit & Hardening):
  - Runbook & Path Alignment: Corrected `scripts/setup/RUNBOOK.md` to reference `tests/fixtures/sample_android_gradle_project/appshield.yaml` (eliminating nonexistent `appshield.json`), explicit `--output-dir dist/protected`, and passing `-c` during standalone verification. Added path-agreement tests verifying configuration existence and output matching.
  - String Pool Scan Classification (`CHK-STR-01`): Modified `appshield/verify.py` to differentiate genuine sensitive credential patterns (which produce `status="FAIL"` and block release acceptance) from known fixture test tokens (`FIXTURE_TEST_STRINGS`, which produce informational findings `status="INFO"` and allow release acceptance `is_verified_protected=True`). All matched patterns remain redacted in audit reports.
  - Gradle Toolchain Discovery & Version Validation: Updated `appshield/doctor.py` and `appshield/gradle.py` to eliminate false positives: Gradle is reported as available only when a complete wrapper (`gradlew` script AND `gradle/wrapper/gradle-wrapper.jar`) or valid system Gradle binary exists, with version >= 8.2 enforced across both.
  - Safe Dependency Warm-Up & Network Build Policy: Documented exact behavior of `--allow-network-dependencies`: it executes a full Android protection build (resolves dependencies, runs `assembleRelease`, executes R8, and exports protected APK) strictly inside ephemeral staging without modifying source files. Clarified that Gradle `--offline` mode is a build-tool switch, NOT operating-system-level network isolation. Required explicit developer authorization for any online build while maintaining strict offline defaults.
  - Artifact Status & Installation Readiness Distinction: Enhanced CLI output and verification reports (`VerificationReport.is_installation_ready` and `installation_readiness_status`) to strictly separate code-protection verification (`is_verified_protected`), structural validity and alignment (`CHK-APK-01`, `CHK-ALN-01`), signature verification (`CHK-SIG-01`), and Android installation readiness. Unsigned APKs may pass code-protection verification, but are strictly reported as not installation-ready because Android OS Package Manager rejects unsigned packages. Disposable test signing remains strictly separated from production signing, and production signing credentials are never generated or exposed.
  - Release Acceptance Gates Audit: Formally verified all 9 gating rules: genuine secrets block export (`CHK-STR-01: FAIL`), fixture markers remain informational, missing/invalid APKs fail, DEX symbol obfuscation is empirically verified in bytecode, 4-byte ZIP alignment passes, signature verification is mandatory when signing is enabled, skipped signing is permitted only when signing is explicitly disabled, simulated builds are blocked from export, and source immutability is cryptographically enforced before export.
  - PowerShell Script Safety: Hardened `download-toolchain.ps1`, `configure-user-environment.ps1`, and `restore-user-environment.ps1` by replacing misleading `SupportsShouldProcess = $true` with `[CmdletBinding()]` and documenting `-Preview` as the dry-run mechanism. Implemented transactional staging replacement with automatic rollback on error in `download-toolchain.ps1`, enforced `-Force` before replacing incomplete directories, guaranteed collision-free backup naming in `configure-user-environment.ps1`, and reconfirmed Machine PATH is strictly read-only.
  - Test Suite Expansion: Added comprehensive regression tests in `tests/test_integration_fixture.py`, `tests/test_doctor.py`, `tests/test_gradle.py`, `tests/test_verify_engine.py`, and `tests/test_cli.py` (total 301 tests across suite) passing with 93% code coverage and 0 lint/type/security issues.
- [x] Completed Toolchain Stage A Provisioning (User-Authorized):
  - Downloaded, verified official SHA-256 (`98518ecf554465057ee5509462631deeee374bc368c12a411d225cd29381f84b`), and transactionally installed Eclipse Temurin OpenJDK 17 LTS (17.0.21+9) at `%USERPROFILE%\.jdk\jdk-17.0.21+9`.
  - Downloaded, verified official SHA-256 (`38f66cd6eef217b4c35855bb11ea4e9fbc53594ccccb5fb82dfd317ef8c2c5a3`), and transactionally installed Gradle 8.2 at `%USERPROFILE%\.gradle\gradle-8.2`.
  - Confirmed Android command-line tools already installed and preserved at `%LOCALAPPDATA%\Android\Sdk\cmdline-tools\latest`.
  - Created process-level launcher `scripts/setup/enter-appshield-env.ps1` providing complete session isolation; guaranteed zero mutation of Machine or User Windows registry environment variables.
  - Verified `java -version` (Temurin 17.0.21+9), `javac -version` (17.0.21), and `gradle --version` (8.2) in isolated session while preserving host Oracle Java 8 on Machine PATH.
  - Preserved Android SDK Platform 34 / Build-Tools 34.0.0 uninstalled and SDK licenses unaccepted, awaiting Stage B/C authorization. Fixture remained 100% untouched (0 bytes diff).
- [x] Completed Toolchain Stage B Provisioning (User-Authorized):
  - Confirmed existing `android-sdk-license` (`24333f8a63b6825ea9c5514f83c2829b004d1fee`) covered both `platforms;android-34` and `build-tools;34.0.0` without requiring any additional licenses.
  - Recorded pre-installation cryptographic SHA-256 manifests across 22,887 files in existing `platforms\android-36`, `platforms\android-36.1`, and `build-tools\36.0.0`.
  - Installed `platforms;android-34` (revision 3) and `build-tools;34.0.0` via `sdkmanager.bat` in isolated process session.
  - Verified `platforms\android-34\android.jar`, `build-tools\34.0.0\zipalign.exe`, and `build-tools\34.0.0\apksigner.bat`.
  - Compared post-installation manifests: confirmed all 22,887 existing files across `android-36`, `android-36.1`, and `build-tools\36.0.0` remain 100% bit-for-bit identical.
  - Executed `appshield doctor`: reported `All required prerequisites are met.` (Java 17, javac 17, JAVA_HOME, ANDROID_HOME, SDK 34, Build-Tools 34.0.0, zipalign, apksigner, AGP 8.2.2).
  - Maintained strict stop conditions: 0 Gradle builds executed, 0 APKs exported, 0 registry mutations, fixture 100% immutable.
- [x] Completed First Genuine Android Protection Build & Empirical Verification (User-Authorized):
  - Executed single authorized release protection run against `tests/fixtures/sample_android_gradle_project` with `--allow-network-dependencies`.
  - Gradle `assembleRelease` completed successfully in 186.06s (exit code 0) using installed Gradle 8.2 and Temurin JDK 17.
  - Successfully resolved and cached AGP 8.2.2 and build dependencies into `%USERPROFILE%\.gradle\caches\modules-2\files-2.1\com.android.tools.build\gradle\8.2.2`.
  - Executed official Google R8 (version 8.2.47) bytecode shrinking and obfuscation.
  - Emitted protected artifact: `dist/protected-first-validation/sample_android_gradle_project-release-protected.apk` (SHA-256: `b4b7ed6f884b8d481de2a5a1ad0fc6af3a355ed8fb580ce1beac3a694bf77e76`, size: 3,147 bytes).
  - Retained R8 obfuscation mapping privately to `%USERPROFILE%\.appshield\mappings\sample_android_gradle_project\mapping.txt` (SHA-256: `ca9f3c0e8300789e87e6613987ad85bc2b51cdb897f0f0831f45955a2101ad95`).
  - Empirical verification results:
    * `CHK-BLD-01`: PASS (Real build completion, exit code 0)
    * `CHK-APK-01`: PASS (Valid Android package archive, 1 DEX file)
    * `CHK-SYM-01`: PASS (Dual-evidence verified: `IdentifiableSecretService -> a`, `PaymentSecurityValidator -> b`, `MainActivity` preserved)
    * `CHK-SIG-01`: SKIPPED (Signing disabled by default; unsigned)
    * `CHK-ALN-01`: PASS (4-byte zip alignment verified)
    * `CHK-STR-01`: INFO (3 benign fixture test markers detected, 0 genuine secrets)
    * `CHK-CMP-01`: INFO (Dalvik 037 structure verified)
  - Release acceptance: `is_verified_protected: True`, `is_installation_ready: False` (unsigned).
  - Source preservation: Cryptographic pre/post manifest verified 100% bit-for-bit identical (`git diff` is 0 bytes).
- [x] Completed Disposable Test Signing & Verification (User-Authorized):
  - Created 2048-bit RSA disposable test keystore at `%USERPROFILE%\.appshield\keystores\disposable_test.jks` with alias `appshield_test` and certificate `CN=AppShield Disposable Test, OU=Testing, O=AppShield, C=US`.
  - Used fresh high-entropy ephemeral test password in process memory passed via `keytool -storepass:env` and `apksigner --ks-pass env:`. Cleared from environment immediately after signing.
  - Signed isolated copy of protected release APK into `dist/test-signed/sample_android_gradle_project-release-test-signed.apk` (size: 12,794 bytes, SHA-256: `c374b2630e6882aac0aec5078e054bd4b909d596cd38cb3649b04566bb3198c0`).
  - Verified original unsigned APK remained 100% bit-for-bit identical (SHA-256 unchanged: `b4b7ed6f884b8d481de2a5a1ad0fc6af3a355ed8fb580ce1beac3a694bf77e76`).
  - Verified signed APK signature (`apksigner verify --verbose`): `Verifies` (v2: `true`, v3: `true`, signer: `CN=AppShield Disposable Test...`).
  - Verified 4-byte ZIP alignment on final signed APK (`zipalign -c -v 4` passed with code 0).
- [x] Completed Android Runtime Installation & Execution Validation (User-Authorized):
  - Pre-installation checks passed: `emulator-5554` (API 37, x86_64 architecture), test-signed APK SHA-256 (`c374b2630e6882aac0aec5078e054bd4b909d596cd38cb3649b04566bb3198c0`), v2/v3 signatures valid, `com.appshield.sample` not previously installed.
  - Installed `dist/test-signed/sample_android_gradle_project-release-test-signed.apk` via `adb -s emulator-5554 install` (Streamed Install: `Success`, exit code 0).
  - Launched `com.appshield.sample.MainActivity` via `adb -s emulator-5554 shell am start -W` (Status: `ok`, LaunchState: `COLD`, TotalTime: 988ms, assigned PID: 7478).
  - Verified runtime lifecycle: Process confirmed alive in `ps -A` (UID `u0_a235`), `dumpsys window` confirmed `mCurrentFocus=Window{... com.appshield.sample/com.appshield.sample.MainActivity}`.
  - Verified zero runtime crashes: Logcat scan confirmed 0 `FATAL EXCEPTION`, 0 `AndroidRuntime`, 0 `ClassNotFoundException`, 0 `NoSuchMethodError`, 0 `VerifyError`.
  - Confirmed empirical functional execution: Logcat captured `I System.out: AppShield Sample Initialized: 56`, proving that obfuscated services (`IdentifiableSecretService` -> `a`, `PaymentSecurityValidator` -> `b`) executed successfully at runtime on Android OS.
  - Preserved emulator state: Application left installed on `emulator-5554` without uninstallation or data wiping per instructions. Both APK artifacts preserved bit-for-bit.
- [x] Completed Android v1 Release Readiness Remediation (Audit Date: 2026-11-10):
  - Created standard MIT `LICENSE` file at repository root with explicit copyright holder placeholder.
  - Implemented GitHub Actions CI workflow `.github/workflows/ci.yml` (multi-Python matrix 3.10/3.11/3.12, ruff lint/format, mypy, bandit, pytest coverage, build).
  - Modernized `README.md` reflecting full Android v1 product reality, prerequisites, CLI usage flags, and empirical verification evidence while removing obsolete Phase 3 notes and correcting paths.
  - Created root `ARCHITECTURE.md` documenting orchestration architecture, staging vs OS sandboxing, signing order, credential safety, and threat boundaries.
  - Synchronized `.planning/PROJECT.md`, `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, `.planning/STATE.md`, and `MEMORY.md`.
  - Modernized `pyproject.toml` license declaration (`license = "MIT"`), resolving packaging deprecation warnings. Verified clean source and wheel builds (`uv build`).

### Pending Tasks (Phase 5+)
- [ ] Phase 5: iOS Protection Engine & Mach-O Sanitization (Plans 05-01 through 05-03)
- [ ] Phase 6: Windows Protection Engine & AV Safety (Plans 06-01 through 06-03)
- [ ] Phase 7: Portfolio Polish, Documentation & GitHub Release (Plans 07-01 through 07-02)

---

## 5. Supported Platforms & Protection Methods

| Platform | Target Binaries / Formats | Primary Protection Methods | Verification Method |
|:---|:---|:---|:---|
| **Android** (v1 MVP) | Android Gradle Projects (`gradlew` + AGP) | R8 shrinking & obfuscation rules applied strictly in isolated staging, built via AGP | Identifier renaming ratio (heuristic), string pool scan (heuristic), signature validity (verified), zip alignment (verified), structural decompilation (informational) |
| **Android (Unsupported in MVP)** | Arbitrary precompiled APKs | *Unsupported* — standalone R8 on arbitrary APKs without full platform/resource classpath causes runtime failures. Treated as unsupported until a validated post-compile engine is added. | N/A |
| **iOS** (v2) | Xcode Projects / Mach-O | Xcode CLI symbol stripping (`strip -x`, `dsymutil`), Swift-Shield symbol renaming, codesign validation | `otool` / `strings` symbol table audit, `codesign --verify --deep` |
| **Windows** (v2) | .NET Solutions, Native PE | Obfuscar (.NET symbol/string obfuscation), native symbol stripping, section entropy check | `dumpbin` / `ildasm` inspection, section entropy scan |

---

## 6. Testing Requirements & Known Limitations

### Testing Requirements
- Unit test suite (`pytest`) with >=85% code coverage for core orchestration.
- Integration tests run against **disposable sample projects / test fixtures only** (`tests/fixtures/sample_android_gradle_project/`) — never against live production developer code.
- Verification tests must assert input files remain bit-for-bit identical (SHA-256 unchanged before and after protection).

### Verification Evidence & Precision Invariants
- **No Composite Score**: Never compute or report an opaque "resistance score" (e.g. 85/100).
- **Precise Evidentiary Claims**:
  - `CHK-SYM-01`: Direct evidence that identified class descriptors were renamed based on matching `mapping.txt` and actual DEX descriptors is `VERIFIED`. The broader inference that obfuscation raises reverse-engineering work factors is `HEURISTIC`. Reports must never imply that verifying several renamed symbols proves the whole app is impossible to reverse-engineer.
  - `CHK-STR-01`: String scanning *detects suspicious patterns* but cannot guarantee that no secrets exist. Classified as `HEURISTIC`. Matched tokens are strictly redacted.
  - `CHK-SIG-01`: Cryptographic signature verification establishes *validity under signature rules*; it does not prove the application code is secure. Classified as `VERIFIED`.
  - `CHK-CMP-01`: Labeled as "Informational Structural Inspection" — confirms static Dalvik/ART header and table bounds; explicitly does *not* prove runtime execution correctness without device/emulator testing. Classified as `INFORMATIONAL`.
  - `CHK-BLD-01`: Real toolchain build verification (`VERIFIED` on real builds, `INFORMATIONAL` on synthetic/test harnesses, `FAILED` on exit errors or inconsistent evidence).
  - `CHK-APK-01`: Validates package ZIP structure and DEX bytecode streams (`VERIFIED` / `FAILED`).
- **Dead-Code Removal vs. Obfuscation**: Never count dead-code elimination as successful obfuscation. If a class is missing from DEX class_defs (stripped by R8), `CHK-SYM-01` reports a discrepancy and fails. Identifiable fixture classes are retained via `-keep,allowobfuscation` to ensure reachability from entry points (`MainActivity`) while allowing R8 to obfuscate.
- **Mapping & Artifact Association**: Verification requires the mapping file to belong to the exact build artifact inspected. Hash tracking (`mapping_sha256`) and build identifier association ensure evidence consistency while keeping raw mappings strictly private.
- **DEX Format Scope**: Dalvik Executable versions 035–040 are supported (AGP 8.2 / Android API 34). DEX version 041 (Android 15+ Container DEX) is explicitly unsupported in this release and rejected with a clear diagnostic.
- Every check explicitly reports what it proves, what it does not prove, and its status: `VERIFIED`, `HEURISTIC`, `INFORMATIONAL`, `FAILED`, or `UNSUPPORTED`.

### Safety, Credentials & Workspace Invariants
- **Sensitive File Exclusion from Staging**: Staging copies strictly exclude `.git/`, `build/`, `.gradle/`, `*.jks`, `*.keystore`, `local.properties`, `*.env*`, and `google-services.json` to prevent leaking credentials into build outputs.
- **Sensitive File Inclusion in Immutability Checks**: Sensitive files are NEVER excluded from source-immutability checks. They are cryptographically hashed and verified before and after execution.
- **Documented Immutability Exclusions**: Only `.git/**` (internal VCS state) and `.appshield_staging/**` / `.appshield_cache/**` (tool-managed temporary directories) are deliberately excluded from immutability checks.
- **No Automatic Production Signing**: Signing is disabled by default; production signing requires explicit confirmation. Unsigned builds are exported as aligned, unsigned APKs with `CHK-SIG-01` reported as `UNSUPPORTED (Signing disabled / unconfigured)`. Initial verification fixture uses a disposable test keystore clearly labeled as test-signed.
- **Correct Signing & Alignment Order**: 1. Build APK -> 2. Run `zipalign` on unsigned APK -> 3. Sign aligned APK with `apksigner` -> 4. Verify signature with `apksigner verify` -> 5. Confirm alignment with `zipalign -c -v 4` without modifying signed APK. Never modify an APK after signing.
- **R8 Mapping File Protection**: `mapping.txt` is never copied to the public output directory (`dist/protected/`) by default, never logged, and never committed to Git. Secure retention at a developer-specified location (`--mapping-out`) is supported for crash-trace deobfuscation. A directory named `secure_vault` in the project root is NOT automatically secure; mapping files must be stored in private, designated developer storage outside the repository and public release bundle with restricted OS file permissions. Verification reads the mapping file in staging strictly to compute aggregate statistics without disclosing raw mappings.
- **Strict Separation Between Simulation & Real Protection**: Production CLI execution requires the actual toolchain. If prerequisites (JDK 17, Android SDK, gradlew, build-tools) are missing, AppShield reports missing items and stops. Simulation/mock harnesses reside strictly within automated tests and never emit fake artifacts to `dist/protected/`.
- **Supported-Project & Narrowed R8 Scope**: Initial R8 integration targets supported Android Gradle projects where release minification is enabled (`minifyEnabled true`) and ProGuard/R8 rules are referenced. Resource shrinking (`shrinkResources`) remains disabled initially. Modifications match the project's actual Groovy DSL without fragile regex rewriting; unsupported or unconfigured projects fail cleanly with clear diagnostics. Automatic configuration of previously unconfigured projects is a future enhancement.
- **Gradle Wrapper & Download Safety**: In `tests/fixtures/sample_android_gradle_project/`, `gradlew`, `gradlew.bat`, and `gradle-wrapper.properties` exist, but `gradle/wrapper/gradle-wrapper.jar` is deliberately not committed. Standard Wrapper JARs can download Gradle distributions before Gradle commands start; `--offline` passed to Gradle does not prevent wrapper downloads. For Plan 04-02: verify the required Gradle distribution is cached locally in `~/.gradle/wrapper/dists/` before attempting offline live builds; forbid silent downloads; require authorization or fail with a missing-dependency error; support distribution SHA-256 verification (`distributionSha256Sum`); and treat Wrapper JAR integrity as part of the trusted toolchain.
- **Android Toolchain Prerequisite & Download Invariants**:
  - Doctor Prerequisites: Android SDK (`ANDROID_HOME`), SDK Platform 34, Build-Tools 34.0.0, `zipalign`, and `apksigner` are strictly marked `required=True` because a verified protected test-signed release cannot be built without them.
  - JDK 17: Eclipse Temurin JDK 17 LTS maintained Windows x64 release (`17.0.21+9`), verified against official Adoptium release repository (`OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip`), installed at user scope (`%USERPROFILE%\.jdk\jdk-17.0.21+9`).
  - Automated Setup Scripts (`scripts/setup/`):
    * `download-toolchain.ps1`: Downloads, verifies SHA-256, and extracts JDK 17.0.21+9, Google Android command-line tools 15859902, and Gradle 8.2 to user-scoped locations; supports `-Preview` and `-Force`. Does NOT automatically accept SDK licenses.
    * `configure-user-environment.ps1`: Backs up environment to protected JSON file before applying changes; idempotently sets user JAVA_HOME, ANDROID_HOME, and User PATH without duplicate entries; supports `-Preview`.
    * `restore-user-environment.ps1`: Completely restores exact pre-AppShield environment variable values from backup file; supports `-Preview`.
  - Android SDK: Official Google command-line tools (`commandlinetools-win-15859902_latest.zip`, SHA-256 `90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a`), installed to `%LOCALAPPDATA%\Android\Sdk`.
  - Gradle Execution: Official Gradle 8.2 binary distribution (SHA-256 `38f66cd6eef217b4c35855bb11ea4e9fbc53594ccccb5fb82dfd317ef8c2c5a3`). User-scoped Gradle 8.2 on PATH (`system` mode) is preferred to avoid mutating the fixture. If Wrapper JAR is used, verify SHA-256 (`a8451eeda314d0568b5340498b36edf147a8f0d692c5ff58082d477abe9146e4`).
  - Dependency Downloads: Strict separation between (1) Gradle distribution archive, (2) Android SDK packages via `sdkmanager`, (3) Maven build plugin resolution (AGP 8.2.2 + R8 8.2.33 from Google Maven/Maven Central), and (4) Offline cached execution. Silent downloads are strictly forbidden; dependencies must be resolved into user cache before offline builds.
- **Accurate Toolchain Status Wording**: Toolchain tables and documentation must distinguish: (1) Selected Target Versions based on AGP compatibility docs (JDK 17, Gradle 8.2, AGP 8.2.2, SDK 34, Build-Tools 34.0.0); (2) Tools detected on the current host; and (3) Versions validated through a successful live build. Never claim end-to-end testing or toolchain validation until a real build succeeds.
- **Dual-Evidence Verification**: `CHK-SYM-01` inspects both `mapping.txt` and actual output `classes.dex` class descriptors to verify that fixture symbols were actually removed from DEX bytecode.
- **No Overwriting Artifacts**: Existing destination files (including protected APKs, standalone audit reports designated via `-o / --output`, and private mapping files designated via `--mapping-out`) are never overwritten without explicit `--overwrite` or `overwrite_existing: true`. Overwrite protection raises `OverwriteError` early during preflight checks, standalone verification, and within the protection pipeline.
- **Zero Logged Credentials**: Passwords referenced exclusively via environment variable names; never passed in CLI flags, printed in reports, or logged.

### Isolation Guarantees vs. OS Sandboxing & Build Execution Risks
- **Isolated Staging Directory**: An ephemeral directory (`tempfile.gettempdir() / "appshield_staging" / build_<uuid>`) where source files are copied.
- **Filesystem Change Protection**: Cryptographic SHA-256 pre/post manifest comparison, sensitive credential exclusions, and overwrite guards on output artifacts.
- **Crucial Distinction from OS Sandbox**: AppShield's staging workspace is a **filesystem copy isolation and verification mechanism, NOT an operating-system kernel process sandbox** (such as Linux namespaces/seccomp, macOS seatbelt, or Windows AppContainer). Subprocesses executed within the staging area (such as Gradle, R8, or Java) run with standard operating system privileges under the user's OS account.
- **Build Execution Risks**: Gradle build scripts (`build.gradle`, `settings.gradle`, plugins) execute arbitrary Groovy/Kotlin JVM bytecode capable of network access and filesystem modification.
- **Plan 03-03 Policy**: All testing in Plan 03-03 and Phase 3 runs exclusively against the controlled, disposable sample project (`tests/fixtures/sample_android_gradle_project/`). Never run automated tests against untrusted or arbitrary external developer projects.
- **Future Untrusted Builds Policy**: Before any future release builds arbitrary or untrusted developer projects, AppShield must define:
  1. An execution threat model acknowledging that build tools execute developer-supplied code;
  2. Explicit user consent and confirmation requirements before triggering build processes;
  3. Appropriate isolation controls (containerization, virtual machines, or `--offline` build flags) or explicit documentation that running a build requires trusting the project's build scripts.

### Known Limitations
- **Android**: Arbitrary precompiled APK input is unsupported for R8; requires supported Android Gradle project. Reflection requires explicit keep-rules.
- **iOS**: Apple App Store Guideline 2.5.2 & W^X memory restrictions strictly forbid binary runtime packers. iOS protection requires a macOS host with Xcode CLI tools.
- **Windows**: Runtime PE packers (e.g. UPX) trigger false-positive malware detections in Windows Defender; protection must focus on symbol stripping and .NET metadata.
- **Fundamental Law**: Client-side software executed on an attacker's hardware cannot be made 100% immune to reverse engineering.

---

## 7. Third-Party Tools, Licenses & Integration Boundaries

| Tool | License | Role | Integration Boundary |
|:---|:---|:---|:---|
| **Gradle / AGP / R8** | Apache 2.0 / BSD-3-Clause | Android build & R8 shrinking/obfuscation | Invocations via project's `gradlew` inside staging sandbox |
| **Android Build-Tools** | Apache 2.0 | Alignment & signing (`zipalign`, `apksigner`) | Subprocess CLI invocations |
| **JADX / Baksmali** | Apache 2.0 / BSD-style | Informational decompilation verification | Headless CLI subprocess |
| **Obfuscar** | MIT | Windows .NET assembly obfuscation (Phase 6) | Subprocess CLI |
| **Apple Xcode CLI** | Proprietary (macOS) | iOS symbol stripping & signing (`strip`, `codesign`) (Phase 5) | Native macOS subprocess commands |

---

## 8. Permanent Review & Operational Rules

### Rule: Read MEMORY.md First
Read this file before starting ANY new task. If an instruction conflicts with approved requirements or roadmap, surface the conflict immediately instead of silently choosing.

### Rule: Permanent 10-Step Full-Review Gate
After completing EVERY task, planning phase, code change, or implementation prompt:
1. Run all applicable automated tests.
2. Run a full code review of all changed files.
3. Run available static analysis, linting, and type checks.
4. Run a security scan using available, appropriate tools.
5. Check for exposed secrets, unsafe file operations, unintended network activity, and original source modifications.
6. Check for unnecessary complexity and duplicated code.
7. Verify that the implementation meets the task's acceptance criteria.
8. Report every failed, skipped, or unavailable check honestly.
9. Update `MEMORY.md` and the project state documents.
10. Summarize what changed, what was tested, the results, and any remaining risks.

*Do not claim a scan passed if it was not executed. Do not hide failures or weaken tests.*

### Rule: Protect Original Code & Credentials
- **Never modify** original application source files during protection operations.
- **Keep output strictly separated** in designated directories (e.g., `dist/protected/`).
- **Never expose or persist** signing keys, keystore passwords, or proprietary code in logs or cache files.
- Test destructive or risky operations **only on disposable sample projects**.
- Require **explicit approval** before destructive actions or major architectural changes.

### Mistakes to Avoid Repeating
- Do not claim arbitrary precompiled APKs can be reliably obfuscated using standalone R8; use supported Android Gradle projects.
- Do not attempt in-memory dynamic anti-tampering/hook evasion without a source-level SDK; black-box injection breaks apps and causes App Store rejections.
- Do not use UPX or runtime PE packers on Windows; they trigger AV false positives.
- Do not compute or report a composite "resistance score"; report objective counts and precise evidence classifications.
- Do not vendor or statically import GPL code into the permissive core.
