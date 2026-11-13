# MEMORY.md — AppShield Living Project Memory

*Permanent project memory, operational governance, and development instructions for AppShield development sessions. Must be read before starting every task.*

---

## 1. Project Identity

- **Product**: AppShield
- **Category**: Multi-Layer Android Application Protection Platform.
- **Product Vision**: A multi-layer Android application protection platform designed to make reverse engineering, intellectual-property theft, code extraction, tampering, repackaging, runtime manipulation, and unauthorized use substantially more difficult through real, independently verifiable protection mechanisms. It does not promise 100% security.

---

## 2. Long-Term Product Vision & Security Honesty

AppShield evolves beyond a conventional Android obfuscation wrapper into a comprehensive, developer-centric, multi-layer application protection platform.

The platform is designed to make:
- **Reverse engineering significantly more difficult** by removing mnemonic class/field/method names, obscuring control flow, and eliminating obvious symbolic context.
- **Unauthorized code extraction more difficult** through multi-tier compilation, asset encryption, and native code boundaries.
- **Application modification and repackaging detectable** through cryptographic self-validation, manifest verification, and signature binding.
- **Intellectual property theft more difficult** by raising attacker reverse-engineering work factors far beyond standard decompilers (JADX, Ghidra, apktool).
- **Runtime manipulation detectable where technically possible** via anti-debugging, anti-hooking/instrumentation (Frida/Xposed), and environment health signals.
- **Licensing and premium-feature bypasses harder** by binding client entitlements to server-validated integrity proofs when backend connectivity is configured.
- **Unauthorized redistribution less useful** through platform binding and dynamic payload delivery.

### The Security Honesty Principle:
**Never promise 100% security.** On client-controlled hardware where an adversary has physical and administrative access to the runtime environment, absolute client-side protection is mathematically impossible. The engineering objective is the strongest practical protection with measurable, independently verified work-factor escalation.

### Defense Classification Taxonomy:
To maintain technical accuracy, every protection mechanism is classified into one of five categories:
1. **Prevention**: Hard controls that stop an action when platform integrity holds (e.g., cryptographic signing requirements, source immutability).
2. **Detection**: Identifying unauthorized modifications or execution environments (e.g., anti-debug checks, hook detection, signature mismatch).
3. **Deterrence**: Substantially escalating attacker effort, time, and reverse-engineering complexity (e.g., symbol obfuscation, control-flow disruption).
4. **Mitigation**: Minimizing exposure or blast radius if code or data is inspected (e.g., string pool encryption, asset vaulting).
5. **Verification**: Empirical cross-examination proving that protections exist in the compiled binary (e.g., DEX bytecode analysis, ZIP alignment audit).

---

## 3. Core Protection Philosophy

AppShield operates under ten permanent principles:

1. **Defense in Depth**: Security must not rely on any single technique. Protection combines build-time transformations, asset protection, runtime checks, signature verification, and optional backend validation.
2. **Real Protection, Never Fake Code**: Do not add meaningless classes, junk methods, or artificial complexity merely to inflate APK size or create synthetic obfuscation theater. Every protection mechanism must address a defined, documented threat.
3. **Independent Verification of Security Claims**: Every security capability must be subject to automated empirical verification (e.g., verifying that renamed symbols actually exist in DEX bytecode and original symbols are completely absent).
4. **No Invented Security Scores or Guarantees**: Never generate opaque, subjective "resistance scores" (e.g., "94/100 Protection Score") or arbitrary unmeasured performance percentages. Report empirical metrics: exact check passes, failures, counts, and objective findings.
5. **No False Claims of Unbreakable Protection**: Disclaim impossible claims clearly in CLI output and documentation. Obfuscation increases reverse-engineering work factors; it does not render a binary immune to reverse engineering.
6. **Source-Code Immutability**: The developer's original repository, source files, and project assets are strictly read-only and must remain 100% bit-for-bit unchanged before and after protection.
7. **Secure Handling of Credentials and Cryptographic Material**: Keystore passwords, private keys, and API tokens must never appear in command-line arguments, process tables, logs, temporary files, or source control. Subprocess environments must be stripped of unrelated host secrets.
8. **Measured Compatibility and Performance**: Protection mechanisms must be evaluated against app startup latency, memory overhead, APK size growth, and Android runtime stability through baseline measurement, not invented numbers.
9. **Security-Critical Checks Must Not Be Silently Bypassed**: Mandatory core checks (`CHK-BLD-01`, `CHK-APK-01`, `CHK-SYM-01`, `CHK-ALN-01`, and `CHK-SIG-01` when signing is enabled) cannot be skipped or bypassed via lenient flags (`fail_on_check_failure: false`). An unverified APK must never be exported as protected.
10. **Fail-Safe Protection**: Protection failures, compilation errors, or source-integrity violations must immediately abort execution, purge ephemeral staging workspaces, and refuse to emit partial or unverified binaries.

---

## 4. Intended Protection Architecture

AppShield is designed around six coordinated functional systems:

- **System A — Code Protection Engine** *(Deterrence & Mitigation)*: Build-time code hardening, R8/ProGuard orchestration, symbol renaming, keep-rule auditing, and mapping file isolation.
- **System B — Data Protection Engine** *(Mitigation & Deterrence)*: String constant pool encryption, sensitive credential scanning, asset vaulting, and Android Keystore hardware binding.
- **System C — Native Protection Engine** *(Deterrence & Mitigation)*: Selective compilation of critical logic into C/C++ shared libraries (`.so`), native symbol stripping, and hardened dynamic JNI registration.
- **System D — Runtime Defense Engine** *(Detection & Deterrence)*: In-app runtime integrity monitoring, anti-tampering (DEX hash verification), anti-debugging (`ptrace`, `TracerPid`), anti-instrumentation (Frida/Xposed detection), and policy-driven response handling.
- **System E — Anti-Piracy and Trust Engine** *(Detection, Prevention & Attestation)*: Certificate signature pinning, installer verification, and optional backend attestation (supporting Google Play Integrity and custom backend verification schemas for connected apps).
- **System F — Security Verification & Attack Laboratory** *(Verification)*: Empirical DEX bytecode auditing, multi-check verification engine, automated decompiler analysis simulation (JADX), and audit report generation.

### Local-First Execution and Network Policy:
AppShield enforces a precise, local-first operational policy:
1. **Local-First Operation by Default**: AppShield operates locally by default.
2. **Gradle Dependency Resolution**: Gradle dependency resolution uses `--offline` by default.
3. **No Intentional Data Transmission**: AppShield does not intentionally transmit source code, APKs, mappings, credentials, or telemetry to remote services.
4. **Authorized Network Resolution**: Network-enabled dependency resolution requires explicit authorization through `--allow-network-dependencies`.
5. **Optional Network Integrations**: Optional backend, licensing, and Google Play Integrity integrations require explicit configuration and authorization; local runtime defenses operate self-contained for offline applications and are never mandatory for offline operation.
6. **Gradle Offline Boundary Limitation**: Gradle's `--offline` mode prevents network access for dependency resolution, but must not be described as a complete OS-level network sandbox for arbitrary Gradle build scripts or third-party plugins.
7. **Strict Network Isolation**: Strict network isolation requires an external firewall, container, or operating-system network restriction.

---

## 5. Current Implementation Status

### Platform Scope
Android is the active, first implementation platform. iOS and Windows architectures are deferred to post-Android milestones.

### Definition of "Implemented"
> [!NOTE]
> In AppShield's documentation and requirements, **"Implemented"** means the functionality exists in the codebase and is covered by automated unit and integration tests. It does not automatically mean compatibility with every real Android project has been independently demonstrated.

### Toolchain Baseline Status
- **Empirically Verified Toolchain**:
  - OpenJDK: 17 LTS (17.0.x)
  - Gradle: 8.2
  - Android Gradle Plugin (AGP): 8.2.2
  - Android SDK Platform: API Level 34 (Android 14)
  - Android Build-Tools: 34.0.0 (`zipalign`, `apksigner`)
  - Dalvik Executable (DEX): DEX 035 verified on live sample builds; DEX 035, 037, 038, 039 verified via synthetic parser unit tests.
- **Expected / Target Compatibility** *(Pending Multi-Project Live Verification)*:
  - Gradle 8.0 – 8.5
  - AGP 8.0.x – 8.2.x
  - Android API Levels: 24 to 34
- **Untested / Out of Scope for Current Baseline**:
  - Gradle 8.6+ / 9.x
  - AGP 8.3+, 8.4+, 8.5+, 8.6+
  - Android SDK 35+ (Android 15)
  - Production DEX 040 binaries

### Implemented Capabilities
- **Python CLI Core**: Cross-platform CLI entry point (`appshield`) supporting subcommands: `protect`, `verify`, `doctor`, and `info`.
- **Toolchain Orchestration**: Android Gradle Plugin (AGP 8.2.2) and Google R8 (8.2.47) build execution via `GradleRunner` supporting offline builds, timeout termination, process tree kill (`taskkill`/`killpg`), and secret redaction.
- **Isolated Staging & Source Immutability**: Ephemeral `.appshield_staging/<build_id>` workspace staging with sensitive file exclusion (`.git`, `build`, `*.jks`, `local.properties`, `.env`). Pre- and post-build SHA-256 source tree manifests enforce 100% bit-for-bit immutability on both normal and exception paths via `SandboxManager`.
- **DEX Bytecode & Mapping Verification**: Pure-Python defensive DEX inspector (`inspect_apk_dex`) supporting string/class table extraction and synthetic DEX generation. R8 `mapping.txt` parser (`parse_r8_mapping`).
- **Objective Verification Engine**: `VerificationEngine` with 7 empirical checks:
  - `CHK-BLD-01` (Actual Build Completion — `VERIFIED`)
  - `CHK-APK-01` (APK Structure & DEX Validity — `VERIFIED`)
  - `CHK-SYM-01` (Dual-Evidence Symbol Renaming — `VERIFIED` direct match, `HEURISTIC` security inference)
  - `CHK-SIG-01` (Cryptographic Signature Verification — `VERIFIED`)
  - `CHK-ALN-01` (4-Byte ZIP Alignment Verification — `VERIFIED`)
  - `CHK-STR-01` (String Constant Pool Heuristic Scan — `HEURISTIC`)
  - `CHK-CMP-01` (Informational Structural Inspection — `INFORMATIONAL`)
- **Signing & Credential Safety**: Environment-variable-masked keystore passwords (`apksigner --ks-pass env:VAR`, `keytool -storepass:env`), disposable test keystore generation, non-production confirmation guards, and subprocess environment stripping via `build_safe_env()`.
- **Diagnostic Doctor & Offline Cache Inspection**: Prerequisite validation for Java 17, `JAVA_HOME`, `ANDROID_HOME`, SDK Platform 34, Build-Tools 34.0.0, `zipalign`, `apksigner`, and non-networked local Gradle cache inspection (`check_gradle_cache_dependencies`).
- **Structured Error Handling**: Zero raw tracebacks; clean error categorization (`Operational Error`, `Configuration Error`, `Overwrite Error`) with actionable remediation hints.
- **Automated Quality Gates**: Complete unit and integration test matrix running in Python 3.10, 3.11, and 3.12 via GitHub Actions, with pinned Ruff 0.17.4, Mypy type-checking, Bandit security scanning, and package building (`uv build`).

### Current Milestone & Repository State
- **Phase A Local Commit**: `6db1251f40f8a729e3b0c84e6e4fc1d803dea305` ("Remediate Phase A general Android Gradle product blockers").
- **Phase A.1 Status**: Working tree contains uncommitted Phase A.1 corrections across 14 tracked files and 1 untracked test file (`tests/test_phase_a1_verification_integrity.py`).
- **Test Suite Results**: `371 passed, 1 warning` with `93%` statement coverage. Ruff, Mypy, Bandit, and `uv build` pass with zero errors.
- **Fixture Integrity**: Both `tests/fixtures/sample_android_gradle_project/` and `tests/fixtures/unrelated_android_gradle_project/` are 100% clean relative to committed contents.
- **Validation Reality**:
  - Live Gradle compilation and R8 obfuscation have been demonstrated **only** on the controlled Groovy fixture `sample_android_gradle_project/` (1 live build, 1 disposable-signed APK, 1 live launch on Android API 37 emulator).
  - The first offline protection attempt against `unrelated_android_gradle_project/` (Kotlin DSL `:mobile` module) failed cleanly during Gradle project configuration because Kotlin DSL runtime dependencies (`org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.8.20` and `kotlin-reflect:1.8.20`) were missing from the local offline Gradle cache.
  - **No genuine R8 output or DEX verification evidence exists yet for the unrelated Kotlin DSL fixture.**
  - **No stable v1.0 release or PyPI package has been published.**

---

## 6. Engineering Constraints

1. **Python CLI Architecture**: Built as a standard Python 3.10+ package with standard library tooling (`subprocess`, `pathlib`, `zipfile`, `hashlib`), using external tools as isolated subprocesses.
2. **Vanilla Implementation**: No unnecessary third-party runtime frameworks or heavy binary compile steps unless justified and approved.
3. **Toolchain Standards**: Target toolchain is OpenJDK 17 + Gradle 8.2 + AGP 8.2.2 + Android SDK Platform 34 + Build-Tools 34.0.0 (`zipalign`, `apksigner`). Do not claim unvalidated support for newer versions.
4. **Local-First Operation & Dependency Policy**: AppShield operates locally by default. Gradle dependency resolution uses `--offline` by default. AppShield does not intentionally transmit source code, APKs, mappings, credentials, or telemetry to remote services. Network-enabled dependency resolution requires explicit authorization via `--allow-network-dependencies`. Gradle's `--offline` flag must not be described as an OS-level network sandbox; strict network isolation requires an external firewall, container, or operating-system network restriction.
5. **Optional Network Integrations**: Code protection, transformation, and verification operate locally on the developer workstation. Optional backend, licensing, and Google Play Integrity integrations require explicit configuration and authorization and are never mandatory for offline-capable applications.
6. **Source-Tree Immutability**: Original source code is treated strictly as read-only; staging copies are made in ephemeral directories.
7. **Secure Subprocess Execution**: No `shell=True` on untrusted inputs; arguments passed as sanitized token lists; process trees terminated on timeout.
8. **Strict Credential Isolation**: Signing credentials passed via environment variable names or file descriptors; child environments stripped of unrelated host tokens via `build_safe_env()`.
9. **Explicit Authorization**: Network access (`--allow-network-dependencies`), production signing (`--allow-production-signing`), and file overwrites (`--overwrite`) require explicit user flags.
10. **No Silent Git or Registry Actions**: Never modify Machine/User persistent environment variables in the Windows Registry; never push commits or create release tags without explicit user instructions.
11. **Non-Bypassable Verification Gates**: Mandatory security checks cannot be bypassed by configuration toggles or lenient flags.

---

## 7. Development Governance

All future development agents working on AppShield must adhere to these twelve operational rules:

1. **Read MEMORY.md and PRD.md First**: Understand established architecture, threat models, and progress before making changes. Consult `PRD.md` as the authoritative source for functional requirements and `ARCHITECTURE.md` for technical designs.
2. **Inspect Current Git State**: Run `git status` and `git diff` before and after operations; never blindly overwrite or discard working-tree changes.
3. **Separate Implemented from Planned**: Never describe planned capabilities (e.g., native compilation, runtime anti-hooking, profiles) as completed features.
4. **Follow Approved Engineering Phases**: Execute work according to active roadmap phases and specific task scopes.
5. **Work Incrementally**: Implement targeted, cohesive changes rather than broad, speculative rewrites.
6. **Add Tests for Every Mechanism**: Every new protection check, adapter rule, or CLI option must include corresponding unit and integration tests.
7. **Provide Empirical Evidence for Security Claims**: Back every protection claim with real binary evidence (mapping entries, DEX descriptors, alignment bytes).
8. **Never Claim Completion from Mocked Tests Alone**: Differentiate synthetic/mocked test validation from genuine toolchain and runtime execution.
9. **Never Execute Network or Remote Actions Without Authorization**: Do not download tools, push to GitHub, or publish packages without explicit approval.
10. **Preserve User Changes & Fixtures**: Keep test fixtures clean and preserve user modifications across sessions.
11. **Report Limitations and Failures Honestly**: When an offline build fails or dependencies are missing, report the exact root cause without masking errors.
12. **Stop for Review at Major Milestones**: Pause and request user review upon completing phases, before merging branches, or prior to live external operations.

---

## 8. Document Hierarchy & Product Success Definition

### Hierarchy of Project Documentation
- **`MEMORY.md` (This File)**: Persistent project memory, operational governance, and developer instructions.
- **`PRD.md`**: Authoritative product vision, requirements, functionality, and acceptance criteria.
- **`ARCHITECTURE.md`**: Technical architecture and implementation design.
- **`ROADMAP.md`**: Development phases and milestones.
- **`STATE.md`**: Current implementation progress tracking.

### Product Success Definition
AppShield achieves product success when an independent Android developer can:
1. Point AppShield at an arbitrary, real-world Android Gradle application (Groovy or Kotlin DSL, single- or multi-module).
2. Execute the protection pipeline with zero manual source modification.
3. Verify that the output binary demonstrates genuine class renaming, string sanitization, and cryptographic integrity.
4. Successfully install and run the protected application on standard Android hardware or emulators without runtime crashes.
5. Receive an objective, auditable verification report detailing verified defenses, heuristic findings, and transparent limitations.

A stable v1.0 release requires multi-project compatibility, genuine Gradle/R8 execution, runtime stability validation, and demonstrable reverse-engineering resistance against real-world decompilers.
