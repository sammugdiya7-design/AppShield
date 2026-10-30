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

---

## 3. Current Phase & Progress

- **Current Phase**: Phase 4: Android Protection Pipeline & Verification Engine
- **Current Plan**: Plan 04-03 Complete; Plan 04-04 Pending
- **Status**: Plan 04-03 verified (empirical verification engine, DEX inspector, string pool scanner, R8 mapping auditor, dual-evidence symbol verification, 7 objective checks, 255 tests, 94% coverage); ready for user review
- **Overall Progress**: 67% (Phases 1, 2, & 3 complete; 8 of 12 total plans completed)

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

### Pending Tasks (Phase 4 Decomposed Plans)
- [ ] Plan 04-04: End-to-End CLI Integration, Automated Test Matrix & Security Validation.

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
  - Identifier renaming ratio is *evidence of obfuscation*, not proof that reverse engineering is impossible.
  - String scanning *detects suspicious patterns* but cannot guarantee that no secrets exist.
  - Signature verification establishes *validity under signature rules*; it does not prove the application is secure.
  - Structural decompilation check is *informational* (confirms bytecode validity), not a measure of obfuscation strength.
- Every check explicitly reports what it proves, what it does not prove, and its status: `VERIFIED`, `HEURISTIC`, `INFORMATIONAL`, `FAILED`, or `UNSUPPORTED`.

### Safety, Credentials & Workspace Invariants
- **Sensitive File Exclusion from Staging**: Staging copies strictly exclude `.git/`, `build/`, `.gradle/`, `*.jks`, `*.keystore`, `local.properties`, `*.env*`, and `google-services.json` to prevent leaking credentials into build outputs.
- **Sensitive File Inclusion in Immutability Checks**: Sensitive files are NEVER excluded from source-immutability checks. They are cryptographically hashed and verified before and after execution.
- **Documented Immutability Exclusions**: Only `.git/**` (internal VCS state) and `.appshield_staging/**` / `.appshield_cache/**` (tool-managed temporary directories) are deliberately excluded from immutability checks.
- **No Automatic Production Signing**: Signing is disabled by default; production signing requires explicit confirmation. Unsigned builds are exported as aligned, unsigned APKs with `CHK-SIG-01` reported as `UNSUPPORTED (Signing disabled / unconfigured)`. Initial verification fixture uses a disposable test keystore clearly labeled as test-signed.
- **Correct Signing & Alignment Order**: 1. Build APK -> 2. Run `zipalign` on unsigned APK -> 3. Sign aligned APK with `apksigner` -> 4. Verify signature with `apksigner verify` -> 5. Confirm alignment with `zipalign -c -v 4` without modifying signed APK. Never modify an APK after signing.
- **R8 Mapping File Protection**: `mapping.txt` is never copied to the public output directory (`dist/protected/`) by default, never logged, and never committed to Git. Secure retention at a developer-specified location (`--mapping-out`) is supported for crash-trace deobfuscation. Verification reads the mapping file in staging strictly to compute aggregate statistics without disclosing raw mappings.
- **Strict Separation Between Simulation & Real Protection**: Production CLI execution requires the actual toolchain. If prerequisites (JDK 17, Android SDK, gradlew, build-tools) are missing, AppShield reports missing items and stops. Simulation/mock harnesses reside strictly within automated tests and never emit fake artifacts to `dist/protected/`.
- **Supported-Project & Narrowed R8 Scope**: Initial R8 integration targets supported Android Gradle projects where release minification is enabled (`minifyEnabled true`) and ProGuard/R8 rules are referenced. Resource shrinking (`shrinkResources`) remains disabled initially. Modifications match the project's actual Groovy DSL without fragile regex rewriting; unsupported or unconfigured projects fail cleanly with clear diagnostics. Automatic configuration of previously unconfigured projects is a future enhancement.
- **Gradle Wrapper & Download Safety**: In `tests/fixtures/sample_android_gradle_project/`, `gradlew`, `gradlew.bat`, and `gradle-wrapper.properties` exist, but `gradle/wrapper/gradle-wrapper.jar` is deliberately not committed. Standard Wrapper JARs can download Gradle distributions before Gradle commands start; `--offline` passed to Gradle does not prevent wrapper downloads. For Plan 04-02: verify the required Gradle distribution is cached locally in `~/.gradle/wrapper/dists/` before attempting offline live builds; forbid silent downloads; require authorization or fail with a missing-dependency error; support distribution SHA-256 verification (`distributionSha256Sum`); and treat Wrapper JAR integrity as part of the trusted toolchain.
- **Accurate Toolchain Status Wording**: Toolchain tables and documentation must distinguish: (1) Selected Target Versions based on AGP compatibility docs (JDK 17, Gradle 8.2, AGP 8.2.2, SDK 34, Build-Tools 34.0.0); (2) Tools detected on the current host; and (3) Versions validated through a successful live build. Never claim end-to-end testing or toolchain validation until a real build succeeds.
- **Dual-Evidence Verification**: `CHK-SYM-01` inspects both `mapping.txt` and actual output `classes.dex` class descriptors to verify that fixture symbols were actually removed from DEX bytecode.
- **No Overwriting Artifacts**: Existing destination files are never overwritten without explicit `--overwrite` or `overwrite_existing: true`.
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
