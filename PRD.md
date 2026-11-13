# Product Requirements Document (PRD) — AppShield

**Product**: AppShield  
**Document Title**: Product Requirements Document (PRD) — Multi-Layer Android Application Protection Platform  
**Version**: 1.0-draft  
**Status**: Living Product Requirements Document  
**Platform Scope**: Android First (iOS and Windows Deferred)  
**Last Updated**: 2026-11-13  
**Repository**: [https://github.com/sammugdiya7-design/AppShield](https://github.com/sammugdiya7-design/AppShield)  
**Related Documents**: [MEMORY.md](file:///C:/Users/Lappy%20House/.gemini/antigravity-ide/scratch/appshield/MEMORY.md), [ARCHITECTURE.md](file:///C:/Users/Lappy%20House/.gemini/antigravity-ide/scratch/appshield/ARCHITECTURE.md), [.planning/ROADMAP.md](file:///C:/Users/Lappy%20House/.gemini/antigravity-ide/scratch/appshield/.planning/ROADMAP.md), [.planning/STATE.md](file:///C:/Users/Lappy%20House/.gemini/antigravity-ide/scratch/appshield/.planning/STATE.md)

---

## 1. Document Control

### 1.1 Purpose
This document establishes the product vision, functional and non-functional requirements, architectural boundaries, threat model, verification criteria, and roadmap for AppShield. It serves as the authoritative product and functional specification guiding implementation, testing, acceptance gates, and release decisions.

### 1.2 Hierarchy of Documentation
AppShield maintains a strict separation of concerns across five core documents:
- **`PRD.md` (This Document)**: The authoritative source of truth for product vision, functional requirements, protection profiles, acceptance criteria, and product roadmap.
- **`MEMORY.md`**: The living operational memory, core security doctrine, development governance rules, current implementation facts, and instructions for development agents.
- **`ARCHITECTURE.md`**: The technical architecture, subsystem contracts, component interfaces, data structures, and security boundary designs.
- **`ROADMAP.md`**: High-level development milestones, phase plans, and sequential execution schedules.
- **`STATE.md`**: Granular tracking of current phase tasks, working-tree status, and immediate next steps.

---

## 2. Executive Summary

Android applications distribute compiled Dalvik Executable (DEX) bytecode within standard ZIP-format APK archives. Standard Dalvik bytecode retains near-complete symbolic, structural, and semantic information. Without specialized protection, tools such as JADX, Bytecode Viewer, APKTool, and Ghidra decompile production APKs back into readable Java and Kotlin source code in seconds.

Existing developer solutions fall into two problematic extremes:
1. **Default Compiler Obfuscation (R8/ProGuard)**: Renames symbols and shrinks bytecode, but leaves control flow, string literals, application assets, entry points, and runtime integrity largely exposed. Configuration is manual, error-prone, and developers rarely have automated means to verify whether protection actually succeeded.
2. **Proprietary Enterprise Application Protection Suites**: Target large enterprises with custom sales-negotiated contracts, annual commitments, and vendor-managed build plugins. This creates a significant barrier for independent developers and smaller engineering teams who require accessible, transparent, local-first application protection without mandatory cloud infrastructure or telemetry.

**AppShield bridges this gap.** It is a multi-layer Android application protection platform designed to make reverse engineering, intellectual-property theft, code extraction, tampering, repackaging, runtime manipulation, and unauthorized use substantially more difficult through real, independently verifiable protection mechanisms. It does not promise 100% security.

Operating as a standalone CLI tool, AppShield operates locally by default, utilizing Gradle's `--offline` mode for dependency resolution without intentionally transmitting source code, APKs, mappings, credentials, or telemetry to remote services. Network-enabled dependency resolution requires explicit user authorization via `--allow-network-dependencies`, and any external runtime integrations require explicit configuration. Crucially, AppShield replaces subjective marketing claims with an automated, empirical verification engine that cross-examines the final output binary against actual compiled bytecode and mapping data.

```
                      +---------------------------------------+
                      |         AppShield CLI Engine          |
                      |   (Local-First, Offline by Default)   |
                      +-------------------+-------------------+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
+-------v-------+                 +-------v-------+                 +-------v-------+
|  Build-Time   |                 | Runtime Guard |                 | Verification  |
|  Protection   |                 |  & Defenses   |                 | & Attack Lab  |
| (R8, Shading, |                 | (Anti-Tamper, |                 | (DEX Audit,   |
| String Vault, |                 | Anti-Debug,   |                 | Mapping Proof,|
| Native Bridge)|                 | Anti-Hooking) |                 | Zip Alignment)|
+---------------+                 +---------------+                 +---------------+
```

---

## 3. Product Vision and Mission

### 3.1 Mission Statement
AppShield is a multi-layer Android application protection platform designed to make reverse engineering, intellectual-property theft, code extraction, tampering, repackaging, runtime manipulation, and unauthorized use substantially more difficult through real, independently verifiable protection mechanisms. Do not promise 100% security.

### 3.2 Vision
AppShield transforms application security from an obscure compiler configuration into an automated, transparent, and auditable pipeline. The platform aims to raise reverse-engineering and cracking work factors to a degree where automated decompilation, trivial patching, unauthorized repackaging, and credential scraping become economically and technically prohibitive.

### 3.3 The Security Honesty Principle
AppShield firmly rejects "security theater" and impossible promises. On client-controlled devices, an attacker with physical control, root access, and dynamic analysis tools (e.g., Frida, IDA Pro, kernel debuggers) can eventually inspect memory or trace execution given sufficient time, skill, and resources. AppShield’s goal is not an unachievable "unbreakable" state, but the **maximal practical escalation of reverse-engineering cost and complexity**, combined with **rapid detection and revocation** of compromised clients where technically viable.

### 3.4 Defense Classification Taxonomy
Every protection capability in AppShield is classified strictly according to its real technical function:
- **Prevention**: Hard controls that stop an action when platform integrity holds (e.g., cryptographic signing requirements, source directory immutability).
- **Detection**: Identifying unauthorized modifications or execution environments (e.g., anti-debug checks, hook detection, signature mismatch).
- **Deterrence**: Substantially escalating attacker effort, time, and reverse-engineering complexity (e.g., symbol obfuscation, control-flow disruption).
- **Mitigation**: Minimizing exposure or blast radius if code or data is inspected (e.g., string pool encryption, asset vaulting).
- **Verification**: Empirical cross-examination proving that protections exist in the compiled binary (e.g., DEX bytecode analysis, ZIP alignment audit).

---

## 4. Problem Statement

Android developers face critical security risks when distributing production applications:

1. **Trivial Reverse Engineering**: Dalvik bytecode accurately mirrors high-level Java/Kotlin abstractions. Competitors and adversaries can extract proprietary algorithms, business workflows, and trade secrets with zero specialized tooling.
2. **Sensitive Credential Exposure**: API keys, cryptographic tokens, encryption initialization vectors, and endpoint URLs hardcoded in code or resources are easily extracted via automated string scraping (`strings`, `apktool`).
3. **Repackaging and Piracy**: Attackers unpack legitimate APKs, remove license checks or in-app purchase validation, insert adware or malicious payloads, resign the archive with an arbitrary key, and redistribute it on third-party app stores.
4. **Dynamic Runtime Manipulation**: Tools like Frida and Xposed hook methods in process memory, spoof return values (e.g., bypassing `isLicenseValid()` or `isDeviceRooted()`), bypass SSL pinning, and extract decryption keys on live devices.
5. **Lack of Protection Verification**: Developers frequently assume that setting `minifyEnabled = true` provides robust protection, unaware that overly broad `-keep` rules or `-dontobfuscate` directives have silently left critical proprietary classes completely unobfuscated.
6. **Workspace Pollution and Accidental Leaks**: Complex security plugins often alter project source trees, inject permanent changes into source control, or leak sensitive signing credentials into logs and environment variables.

---

## 5. Target Users

1. **Independent Android Developers & Indie Studios**: Building commercial or subscription-based applications who require accessible, transparent, local-first application protection without enterprise sales commitments or invasive proprietary build plugins.
2. **Startups & Scale-ups**: Protecting proprietary algorithms, core IP, AI models, or FinTech/HealthTech application logic before broad public distribution.
3. **Enterprise Development Teams**: Demanding local-only, air-gapped protection pipelines that satisfy strict corporate privacy, data residency, and supply-chain security policies.
4. **Security Engineers & Penetration Testers**: Needing an objective, automated tool to audit and verify that build-time hardening standards are genuinely applied across mobile application deliverables.

---

## 6. Product Goals

1. **Measurable Reverse-Engineering Escalation**: Make static decompilation and structural comprehension substantially harder through deep symbol obfuscation, control-flow disruption, and string/data encryption.
2. **Robust Repackaging Detection**: Prevent modified, resigned, or repackaged binaries from executing without detection.
3. **Active Runtime Defense**: Detect live debugging, process hooking (Frida/Xposed), and suspicious/rooted execution environments with configurable response policies.
4. **Guaranteed Source Immutability**: Guarantee 100% bit-for-bit source-code preservation. The developer's project directory is strictly read-only; all staging and builds occur in ephemeral sandboxes.
5. **Zero Credential Exposure**: Eliminate plaintext signing keys, passwords, and tokens from command-line arguments, process tables, logs, temporary files, and shell histories.
6. **Objective, Empirical Verification**: Deliver a verification engine that replaces opaque "security scores" with concrete binary proof: exact descriptor matches, string pool scans, alignment metrics, and signature audits.
7. **Local-First Operation by Default**: Execute locally on the developer workstation by default. Gradle dependency resolution uses `--offline` by default, with no intentional transmission of project source code, APKs, mappings, credentials, or telemetry to remote services. Strict network isolation requires an external firewall, container, or operating-system network restriction.
8. **Broad Android Compatibility**: Support modern Android development standards: Gradle, Kotlin DSL and Groovy DSL, multi-module project architectures, Android SDK Platform 34, and standard Android device/emulator environments.
9. **Low Operational Friction**: Single-command execution (`appshield protect`) integrated cleanly into standard local workflows and CI/CD automation.
10. **Fail-Safe Integrity**: Protection failures, compilation issues, or integrity violations must fail immediately, cleanly abort the pipeline, and refuse to publish unverified artifacts.

---

## 7. Non-Goals

1. **No Claims of 100% Invulnerability**: AppShield will never advertise "unbreakable DRM" or guarantee that an application cannot be cracked on physical client hardware.
2. **No Custom In-House Compiler Core**: AppShield will not invent a proprietary DEX compiler or fork LLVM from scratch; it coordinates battle-tested, standard toolchains (Google R8, AGP, Clang/NDK) and focuses proprietary logic on hardening transformations, verification, and defense hooks.
3. **No Standalone Precompiled APK Input**: Arbitrary precompiled APKs lack full compile classpath, platform dependency jars, and resource ID symbols. AppShield operates strictly on source Android Gradle projects.
4. **No Obfuscation by Synthetic Bloat**: AppShield will not inject thousands of meaningless dummy classes or junk instructions merely to inflate APK size without a clear threat mitigation purpose.
5. **No Blind Root/Device Hostility**: The runtime engine will not arbitrarily crash or brick user applications on rooted devices; it provides risk signals and policy-driven hooks for developer-defined handling.
6. **No Inherent OS-Level Network Sandboxing**: AppShield operates locally and enforces `--offline` dependency resolution by default, but Gradle's `--offline` flag must not be described as a complete OS-level network sandbox for arbitrary Gradle build scripts or third-party plugins. Developers or environments requiring strict network isolation must use an external firewall, container, or operating-system network restriction.
7. **No OS-Level Kernel Modification**: AppShield operates in standard Android user-space and standard workstation developer permissions.
8. **No Multi-Platform Expansion Ahead of Android Maturity**: iOS and Windows engines remain future roadmap milestones; Android protection must achieve complete, validated maturity first.

---

## 8. Threat Model

### 8.1 Protected Assets
- **Application Source & Logic**: Proprietary algorithms, mathematical logic, business rules, API call flows.
- **Data & Credentials**: API keys, backend secrets, cryptographic tokens, database schemas, proprietary assets.
- **Application Identity & Integrity**: Original developer signing certificate, package namespace, DEX bytecode structure, manifest configurations.
- **Licensing & Monetization**: In-app purchase gates, subscription verification logic, premium feature activation routines.

### 8.2 Threat Actor Profiles & Capabilities

| Threat Actor | Motivation | Skill Level | Tools & Techniques Used |
|:---|:---|:---:|:---|
| **Casual Leech / Script Kiddie** | Rebranding, ad replacement, free access | Low | APKTool, MT Manager, one-click patchers, simple resignation |
| **Competitive Analyst / Pirate** | Clone features, extract algorithms, crack premium | Medium | JADX, Ghidra, Frida scripts, objection, Magisk/Zygisk modules |
| **Dedicated Reverse Engineer** | Full bypass, key recovery, commercial piracy | High | IDA Pro, custom Frida hooks, kernel debuggers, memory dumpers, Smali patching |

### 8.3 Attack Surfaces, Mitigations, and Classification

```
+-----------------------------------------------------------------------------------+
|                              ANDROID ATTACK SURFACES                              |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. STATIC REVERSE ENGINEERING                                                    |
|     Threat         : Decompilation of APK into readable Java/Kotlin using JADX.   |
|     Mitigation     : R8 shrinking/renaming + string encryption + native compile.  |
|     Classification : Deterrence & Mitigation (Destroys symbolic comprehension).   |
|     Limitation     : Bytecode instructions remain decompilable; logic can be      |
|                      analyzed by a determined analyst with sufficient time.       |
|                                                                                   |
|  2. REPACKAGING & RESIGNING                                                       |
|     Threat         : Modifying Smali code, adding malware/ads, resigning APK.     |
|     Mitigation     : Self-integrity checks, certificate pinning, Play Integrity. |
|     Classification : Detection & Prevention (Stops execution of modified APK).   |
|     Limitation     : Client-side integrity checks can be patched in Smali unless  |
|                      attested by an external, trusted server.                     |
|                                                                                   |
|  3. RUNTIME INSTRUMENTATION & HOOKING                                             |
|     Threat         : Frida, Xposed, or Substrate hooking methods in memory.       |
|     Mitigation     : In-memory hook detection, native runtime checks, thread scan.|
|     Classification : Detection & Deterrence (Detects dynamic manipulation).       |
|     Limitation     : Advanced kernel-level hooks or hypervisors can conceal       |
|                      instrumentation artifacts.                                   |
|                                                                                   |
|  4. ENVIRONMENT TAMPERING                                                         |
|     Threat         : Rooted devices, emulators, debuggers, custom ROMs.           |
|     Mitigation     : Root/su binary detection, ptrace checks, build property scan.|
|     Classification : Detection (Signals hostile environment to developer policy). |
|     Limitation     : Root-hiding modules (Magisk DenyList, Shamiko) can mask      |
|                      environment indicators.                                      |
|                                                                                   |
|  5. CREDENTIAL & ASSET EXTRACTION                                                 |
|     Threat         : Scraping string pools and asset files for API keys & tokens. |
|     Mitigation     : Dynamic decryption, split-key assembly, Keystore binding.    |
|     Classification : Mitigation (Eliminates plaintext secrets from static DEX).   |
|     Limitation     : Secrets decrypted in client memory can eventually be read    |
|                      from RAM during dynamic runtime analysis.                    |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 9. Detailed Protection Architecture

AppShield is architected into six coordinated systems:

```
+-----------------------------------------------------------------------------------+
|                        APPSHIELD MULTI-LAYER ARCHITECTURE                         |
+-----------------------------------------------------------------------------------+
| [System A] Code Protection Engine   : R8 Obfuscation, Renaming, Keep-Rule Auditing|
| [System B] Data Protection Engine   : String Pool Encryption, Asset Vaulting      |
| [System C] Native Protection Engine : Selective JNI/C++ Compilation, Symbol Hide  |
| [System D] Runtime Defense Engine   : Anti-Debug, Anti-Frida, Integrity Monitoring|
| [System E] Anti-Piracy Engine       : Signature Pinning, Repackaging Detection    |
| [System F] Verification & Lab       : Empirical DEX Audits, Multi-Check Testing   |
+-----------------------------------------------------------------------------------+
```

### System A — Code Protection Engine *(Deterrence & Mitigation — Core Implemented)*
- **R8 Build-Time Orchestration**: Automated generation and safe injection of strict optimization, shrinking, and obfuscation rules into temporary staging build scripts.
- **Symbol & Identifier Obfuscation**: Deep class, field, and method renaming to non-mnemonic descriptors (`a.a`, `a.b`).
- **Keep-Rule Auditing & Safety**: Automated scanning of ProGuard/R8 configuration files to detect and block unsafe directives (such as active `-dontobfuscate` or blanket wildcard keep rules) before compilation begins.
- **Entry-Point Preservation**: Automated parsing of `AndroidManifest.xml` to identify valid Android components (Activities, Services, Receivers, Providers) and keep only necessary public framework entry points while shrinking private classes.
- **Mapping File Privacy**: Automatic isolation of the generated R8 `mapping.txt`. Raw mappings are never committed, never packaged in the APK, and only retained when explicitly directed to a private path via `--mapping-out`.

### System B — Data Protection Engine *(Mitigation & Deterrence — Planned Milestone 2)*
- **String Constant Pool Vaulting**: Heuristic scanning and compile-time transformation of sensitive string literals into encrypted byte arrays decrypted dynamically at runtime.
- **Asset Encryption**: Optional encryption for proprietary models, JSON configurations, database seeds, and graphic assets in `assets/`, unpacked in memory via native streams.
- **Secret Detection Scanners**: Build-time scanning of the compiled DEX string pool against patterns for cloud credentials (AWS, Google, Stripe, private keys), failing or warning before release.
- **Android Keystore Binding**: Automated integration patterns utilizing hardware-backed security modules (TEE / StrongBox) for asymmetric key storage and decryption.

### System C — Native Protection Engine *(Deterrence & Mitigation — Planned Milestone 3)*
- **Selective Native Compilation**: Moving critical algorithms or security validation logic from Dalvik bytecode into native C/C++ libraries (`.so`).
- **Native Symbol Stripping**: Automated execution of toolchain strip utilities (`llvm-strip`) to eliminate native dynamic symbols and debug sections.
- **JNI Boundary Hardening**: Obfuscating native method names and binding functions dynamically via `RegisterNatives` inside `JNI_OnLoad` rather than exposing obvious exported function symbols.
- **ABI Multi-Architecture Support**: Support for `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.

### System D — Runtime Defense Engine *(Detection & Deterrence — Planned Milestone 4)*
- **Anti-Debugging Defenses**: Active detection of attached debuggers via Java API (`Debug.isDebuggerConnected()`) and native checks (`ptrace(PTRACE_TRACEME, ...)`, `/proc/self/status` TracerPid monitoring).
- **Anti-Hooking & Anti-Instrumentation**: Detection of Frida threads, default Frida ports (`27042`), `/proc/self/maps` memory artifacts (`frida-agent.so`), and Xposed framework classes (`de.robv.android.xposed.XposedBridge`).
- **Runtime DEX Self-Integrity**: Background calculation of loaded DEX checksums compared against build-time cryptographic hashes to identify live bytecode modification.
- **Hostile Environment Signals**: Detection of standard root binaries (`/system/bin/su`), Magisk mount points, test keys (`test-keys`), and known emulator hypervisor drivers.
- **Policy Response Handler**: Clean abstraction allowing the developer to choose actions upon detection: exit app, disable sensitive features, alert backend server, or degrade gracefully.

### System E — Anti-Piracy and Trust Engine *(Detection, Prevention & Attestation — Planned Milestone 5)*
- **Signature Identity Pinning**: Self-contained verification of the signing certificate SHA-256 fingerprint at runtime, immediately detecting if the application was resigned with a different key.
- **Installer Package Validation**: Verification that the application was installed from an authorized installer (e.g., `com.android.vending`) rather than side-loaded via unauthorized sources.
- **Server-Side Authorization**: Cryptographic attestation protocols where the client generates a signed token incorporating device health signals and runtime nonce to exchange with the developer's backend.
- **Google Play Integrity API Integration**: Optional, opt-in integration hooks for Google's hardware-backed cloud attestation signals.
- **Offline Application Support**: Local signature pinning and self-integrity checks operate completely self-contained without requiring internet access. Optional backend, licensing, and Google Play Integrity integrations require explicit configuration and authorization; offline applications remain fully supported with local defenses.

### System F — Security Verification & Attack Laboratory *(Verification — Core Implemented)*
- **Automated Decompiler Simulation**: Standalone headless analysis simulating attacker decompilation passes (JADX) to verify that target classes and logic are unreadable.
- **Dual-Evidence Verification (`CHK-SYM-01`)**: Strict cross-verification proving that original class descriptors are absent from the output DEX, mapped obfuscated descriptors exist in DEX class definitions, and dead-code elimination is not misclassified as renaming.
- **Packaging & Alignment Audit (`CHK-ALN-01`)**: Verification that all uncompressed entries in the final APK align to 4-byte boundaries using `zipalign -c`.
- **Signature Audit (`CHK-SIG-01`)**: Independent cryptographic verification of APK Signature Schemes (v1, v2, v3, and v4) using `apksigner verify`.
- **Reproducible Test Benchmarks**: Continuous automated test suites verifying protection efficacy across real and synthetic fixtures without developer intervention.

---

## 10. Protection Profiles

> [!NOTE]
> The Standard, Enhanced, and Maximum profiles defined below represent **intended/planned product profiles** (see FR-021, currently Planned). In the current Phase A / A.1 implementation, AppShield provides core R8 orchestration with configurable CLI options; full preset profiles are scheduled for Milestone 2+.
>
> All overhead figures are **provisional targets (TBD pending empirical baseline measurement)**. AppShield does not publish arbitrary or unmeasured performance claims.

| Dimension | Standard Profile *(Planned)* | Enhanced Profile *(Planned)* | Maximum Profile *(Planned)* |
|:---|:---|:---|:---|
| **Target Audience** | General utility apps, open tools | Commercial SaaS, FinTech, media apps | High-value IP, core algorithms, payment engines |
| **Code Obfuscation** | R8 shrinking & class/method renaming | R8 + Advanced identifier renaming | R8 + Advanced renaming + Control-flow disruption |
| **Data Protection** | Sensitive string detection & warnings | String pool encryption for flagged tokens | String encryption + Asset vaulting |
| **Native Protection** | Standard ABI stripping | JNI boundary symbol hiding | Critical logic compiled to C/C++ native `.so` |
| **Runtime Defenses** | Basic debugger & signature check | Anti-debug + Signature pinning + Root scan | Full runtime defense (Frida, Xposed, TracerPid) |
| **Anti-Piracy** | Package & manifest validation | Signature pinning + Installer check | Signature pinning + Server-side attestation |
| **Verification Level** | Core checks (Build, APK, Symbol, Align) | Core checks + String pool audit + Sig audit | Full 7-check empirical verification audit |
| **Build Overhead Target** | TBD (Provisional: Minimal impact) | TBD (Provisional: Moderate impact) | TBD (Provisional: Calibrated against toolchain) |
| **Startup Overhead Target**| TBD (Provisional: Negligible latency) | TBD (Provisional: Minimal cold start impact)| TBD (Provisional: Calibrated against device) |

---

## 11. Developer Workflow

```
+---------------------------------------------------------------------------------+
|                         APPSHIELD DEVELOPER JOURNEY                             |
+---------------------------------------------------------------------------------+
| 1. INSTALL    : Developer installs AppShield via pip / uv / standalone binary.   |
| 2. DOCTOR     : Runs `appshield doctor` to verify JDK, Android SDK & cache.     |
| 3. INSPECT    : Inspects project structure (`settings.gradle`, modules, AGP).  |
| 4. CONFIGURE  : Generates or edits `appshield.yaml` specifying target & options.|
| 5. VALIDATE   : Runs preflight validation (blocks -dontobfuscate, debug tasks). |
| 6. STAGE      : Creates isolated temporary sandbox; snapshots source hashes.   |
| 7. TRANSFORM  : Injects R8 rules, encrypts strings, prepares native assets.     |
| 8. COMPILE    : Executes offline Gradle release build in sandbox.               |
| 9. SIGN       : Performs 4-byte zipalign and apksigner with masked credentials. |
| 10. INTEGRITY : Verifies original source directory SHA-256 hashes are untouched.|
| 11. VERIFY    : Runs all objective empirical checks against final compiled DEX. |
| 12. REPORT    : Generates JSON (`audit_report.json`) and terminal summary.      |
| 13. EXPORT    : Exports protected APK to `dist/protected/` only if verified.   |
+---------------------------------------------------------------------------------+
```

---

## 12. Functional Requirements

### Legend:
- **Implemented**: The functionality exists in the code and is covered by automated unit and integration tests. It does not automatically mean compatibility with every real Android project has been independently demonstrated.
- **Partially Implemented**: Core framework present; full feature scope in progress.
- **Planned**: Formally specified for development in roadmap milestones.
- **Deferred**: Scheduled for post-Android milestones (iOS/Windows).

### Requirements Matrix

| ID | Title | Description | Status |
|:---|:---|:---|:---:|
| **FR-001** | Android Project Layout Inspection | Validate directory layout, Gradle wrapper, settings file, and module build scripts (Groovy/Kotlin DSL). | **Implemented** |
| **FR-002** | Ephemeral Workspace Staging | Stage builds in an isolated temporary directory with sensitive file exclusions (`.git`, `build`, `*.jks`, `local.properties`). | **Implemented** |
| **FR-003** | Source Immutability Verification | Pre- and post-build SHA-256 manifests ensuring 100% bit-for-bit source preservation across both normal and error paths. | **Implemented** |
| **FR-004** | Release Task & Variant Validation | Reject non-release, debug (`assembleDebug`), instrumentation (`androidTest`), or bundle tasks; require release APK tasks. | **Implemented** |
| **FR-005** | Pre-Build Obfuscation Safety | Reject ProGuard/R8 configurations containing active `-dontobfuscate` directives before running builds. | **Implemented** |
| **FR-006** | Pre-Build Signing Validation | Verify keystore path, alias, and environment password variables before invoking build toolchains. | **Implemented** |
| **FR-007** | Safe Subprocess Execution | Run toolchain commands with tokenized arguments, process tree kill on timeout, and credential redaction in logs. | **Implemented** |
| **FR-008** | Subprocess Credential Isolation | Strip unrelated host API keys and tokens from child processes using `build_safe_env()`. | **Implemented** |
| **FR-009** | Artifact & Mapping Discovery | Discover compiled release APK and R8 `mapping.txt` inside staging sandbox; enforce path containment. | **Implemented** |
| **FR-010** | 4-Byte ZIP Alignment | Align uncompressed APK entries to 4-byte boundaries using `zipalign -p -f 4`. | **Implemented** |
| **FR-011** | APK Signing with Masked Passwords | Sign APKs via `apksigner --ks-pass env:<VAR>` and `keytool -storepass:env` without command-line exposure. | **Implemented** |
| **FR-012** | Disposable Test Keystore Generation | Generate isolated ephemeral RSA 2048-bit test keystores for safe local fixture signing validation. | **Implemented** |
| **FR-013** | Pure-Python DEX Bytecode Inspector | Defensive parser for Dalvik DEX 035–040 files; extracts classes, strings, types without executing bytecode. | **Implemented** |
| **FR-014** | R8 Obfuscation Mapping Parser | Parse R8 `mapping.txt` into class and member structures and extract compiler metadata without leaking raw mappings. | **Implemented** |
| **FR-015** | Dual-Evidence Symbol Verification | Cross-verify that original classes are absent from DEX and mapped classes exist in bytecode; fail on stale mappings. | **Implemented** |
| **FR-016** | Heuristic String Pool Scanning | Scan DEX string pools for sensitive tokens (AWS, Google, private keys) and redact matches in audit reports. | **Implemented** |
| **FR-017** | Diagnostic Doctor & Cache Check | Check local JDK 17, Android SDK, and inspect local Gradle cache for offline AGP/R8 dependencies without network calls. | **Implemented** |
| **FR-018** | Non-Bypassable Verification Gate | Mandatory core checks cannot be bypassed via `fail_on_check_failure: false`; unverified APKs are never exported. | **Implemented** |
| **FR-019** | Structured Error Handling | CLI catches adapter, Gradle, signing, DEX, mapping, and IO errors cleanly, exiting with code 1 without tracebacks. | **Implemented** |
| **FR-020** | Overwrite Safeguards | Prevent silent destruction of existing artifacts, reports, or retained mappings without explicit `--overwrite`. | **Implemented** |
| **FR-021** | Configurable Protection Profiles | Support `--profile standard\|enhanced\|maximum` selecting predefined hardening configurations. | **Planned** |
| **FR-022** | Compile-Time String Encryption | Automatically transform sensitive string literals into encrypted byte arrays with runtime decryption routines. | **Planned** |
| **FR-023** | Encrypted Asset Vaulting | Encrypt selected asset files in `assets/` and provide a streaming in-memory native decryption layer. | **Planned** |
| **FR-024** | Selective Native C++ Compilation | Automatically package security-critical validation logic into compiled native shared libraries (`.so`). | **Planned** |
| **FR-025** | Anti-Debugging Runtime Monitor | Inject runtime checks detecting JDWP debuggers, `ptrace` attachment, and `TracerPid` changes. | **Planned** |
| **FR-026** | Anti-Hooking / Anti-Frida Defenses | Detect in-memory Frida agent libraries, named pipes, and default communication sockets. | **Planned** |
| **FR-027** | Runtime Signature Pinning | Verify that the running application was signed by the authorized developer certificate; exit or signal if resigned. | **Planned** |
| **FR-028** | Server-Side Attestation Gateway | Provide backend verification schemas validating client integrity nonces and hardware attestations. | **Planned** |
| **FR-029** | Automated Attack Laboratory CLI | Run simulated decompiler and unpacker suites against output APKs, outputting an empirical adversary resistance report. | **Planned** |
| **FR-030** | iOS Toolchain Adapter | Orchestrate macOS Xcode symbol stripping (`strip`, `dsymutil`) and Mach-O binary hardening. | **Deferred** |
| **FR-031** | Windows Toolchain Adapter | Orchestrate Windows .NET assembly obfuscation (Obfuscar) and native PE symbol stripping. | **Deferred** |

> [!IMPORTANT]
> **Implementation Reality Note**: While FR-001 through FR-020 are implemented and validated within the automated test suite, live compilation has been verified exclusively against `sample_android_gradle_project/`. The second fixture (`unrelated_android_gradle_project/`) encountered missing Kotlin DSL cache dependencies during offline configuration; genuine multi-project build verification remains an open task.

---

## 13. Non-Functional Requirements

### 13.1 Security & Safety
- **Local-First & Data Privacy**: AppShield operates locally by default and does not intentionally transmit source code, APKs, mappings, credentials, or telemetry to remote services.
- **Network Sandboxing Boundaries**: Gradle's `--offline` mode prevents network access for dependency resolution, but is not an OS-level network sandbox. Strict network isolation requires an external firewall, container, or operating-system network restriction.
- **Least Privilege**: The CLI must operate entirely within standard developer user permissions. No administrator or root elevation required.
- **Fail-Safe Defaults**: Any failure during compilation, rule injection, or verification must result in an immediate non-zero exit code and zero exported artifacts.

### 13.2 Reliability & Immutability
- **Source Preservation**: Pre- and post-build SHA-256 manifests must confirm zero bytes modified, added, or deleted in the source project directory.
- **Deterministic Verification**: Running `appshield verify` on the same APK and mapping file must produce identical JSON audit reports.

### 13.3 Performance Overhead Targets *(Provisional / TBD)*
- **Build Overhead**: TBD pending empirical baseline measurement. The design goal is minimal overhead over standard Gradle R8 builds; formal thresholds will be calibrated across standard test fixtures.
- **Application Startup Latency**: TBD pending empirical baseline measurement. The design goal is negligible impact on cold app launch latency on standard Android hardware (API 31+).
- **APK Size & Memory Impact**: TBD pending empirical baseline measurement. R8 shrinking typically reduces code size, while string encryption and native libraries introduce modest size additions.

### 13.4 Usability & Portability
- **Cross-Platform Host Support**: CLI orchestration must execute reliably on Windows (PowerShell/CMD), macOS (Zsh/Bash), and Linux (Bash).
- **Clear Diagnostics**: The `doctor` command must provide actionable remediation hints when host prerequisites are missing.

---

## 14. Security Architecture and Trust Boundaries

```
+---------------------------------------------------------------------------------+
|                          APPSHIELD TRUST BOUNDARIES                             |
+---------------------------------------------------------------------------------+
|                                                                                 |
| [BOUNDARY 1: HOST WORKSPACE] (Fully Trusted)                                    |
|   Developer Source Repository -> Read-Only Input                                |
|   Environment Secrets (Key passwords) -> Isolated in memory                     |
|                                                                                 |
|                              | (Strict File-Copy Isolation)                     |
|                              v                                                  |
|                                                                                 |
| [BOUNDARY 2: EPHEMERAL SANDBOX] (Controlled Execution)                          |
|   Staged Workspace -> Temporary build directory under system temp               |
|   Gradle Subprocess -> Offline dependency resolution by default (--offline);    |
|                        strict isolation requires container/OS firewall          |
|                                                                                 |
|                              | (Cryptographic Verification Gate)                |
|                              v                                                  |
|                                                                                 |
| [BOUNDARY 3: OUTPUT ARTIFACTS] (Export Destination)                             |
|   dist/protected/ -> Hardened, verified APK and audit reports                   |
|   Private Path    -> R8 mapping.txt (Never published)                           |
|                                                                                 |
|                              | (Untrusted Client Distribution)                  |
|                              v                                                  |
|                                                                                 |
| [BOUNDARY 4: CLIENT RUNTIME ENVIRONMENT] (Zero Trust / Hostile)                 |
|   Client Device   -> May be rooted, running emulators, or hooked with Frida     |
|   Offline Apps    -> Rely entirely on self-contained local detection/defense    |
|   Connected Apps  -> Can augment local defense with optional backend attestation|
|                                                                                 |
+---------------------------------------------------------------------------------+
```

### Critical Trust Realities:
- **Client-Side Code Cannot Keep Absolute Secrets**: Symmetrically encrypted strings or keys embedded in client binaries can eventually be captured when decrypted into memory. Highly sensitive decisions (e.g., authorization, financial transactions) must be verified on a trusted backend for connected apps.
- **Runtime Defenses Are Deterrents and Detections, Not Proofs**: In-memory hook detectors and root checks make dynamic analysis significantly more difficult, but can be bypassed by advanced kernel-level tools. The primary barrier is raising the economic cost for the attacker.
- **Offline Integrity Limits**: For applications running strictly offline, integrity checks (signature pinning, DEX hash self-checks) operate without server validation. A dedicated reverse engineer with Smali patching skills can theoretically locate and patch out local checks if they defeat obfuscation; AppShield's multi-layer defense makes locating and patching these checks substantially more difficult.

---

## 15. Verification and Acceptance Criteria

Every implemented protection mechanism must satisfy a four-part acceptance test before release:

1. **Implementation Test**: Unit and functional tests proving the mechanism executes properly without syntax or runtime crashes.
2. **Positive Verification Test**: Empirical test proving the defense is active in the output binary (e.g., checking DEX bytecode class definitions).
3. **Negative / Bypass Test**: Test verifying that if the defense is disabled, missing, or compromised, the verification check fails and reports an error.
4. **Failure Barrier Test**: Test proving that when a mandatory check fails, `is_verified_protected` is `False`, the command exits with code `1`, and no protected APK is exported.

---

## 16. Toolchain Baseline & Compatibility Requirements

### 16.1 Toolchain Status Matrix

| Component | Empirically Verified Baseline | Expected / Target Compatibility *(Pending Verification)* | Untested / Out of Scope |
|:---|:---|:---|:---|
| **Java Runtime** | OpenJDK 17 LTS (17.0.x) | JDK 17 (any compliant distribution) | JDK 21+, JDK 11, JDK 8 |
| **Gradle** | Gradle 8.2 | Gradle 8.0 – 8.5 | Gradle 8.6+, Gradle 9.x |
| **AGP** | 8.2.2 | 8.0.x – 8.2.x | 8.3+, 8.4+, 8.5+, 8.6+ |
| **Android SDK** | API Level 34 (Android 14) | API Level 24 through 34 | API Level 35+ (Android 15) |
| **Build-Tools** | 34.0.0 (`zipalign`, `apksigner`) | 34.0.0 | Older or preview build-tools |
| **DEX Format** | DEX 035 (Live fixture build); 035, 037, 038, 039 (Synthetic unit tests) | DEX 035 – 039 | DEX 040 in live production APKs |

### 16.2 Runtime Android Compatibility
- **Target Minimum SDK**: Android API Level 24 (Android 7.0 Nougat) and above.
- **Target Architectures**: ARM64-v8a, ARMv7, x86_64, and x86.

---

## 17. Privacy, Network Policy, and Credential Security

AppShield enforces a precise local-first operational and network policy:

1. **Local-First Operation by Default**: AppShield operates locally by default.
2. **Gradle Dependency Resolution**: Gradle dependency resolution uses `--offline` by default.
3. **No Intentional Data Transmission**: AppShield does not intentionally transmit source code, APKs, mappings, credentials, or telemetry to remote services.
4. **Authorized Network Resolution**: Network-enabled dependency resolution requires explicit authorization through `--allow-network-dependencies`.
5. **Optional Network Integrations**: Optional backend, licensing, and Google Play Integrity integrations require explicit configuration and authorization; offline applications remain fully supported with local defenses.
6. **Gradle Offline Boundary Limitation**: Gradle's `--offline` mode prevents network access for dependency resolution, but must not be described as a complete OS-level network sandbox for arbitrary Gradle build scripts or third-party plugins.
7. **Strict Network Isolation**: Strict network isolation requires an external firewall, container, or operating-system network restriction.

### Credential and Artifact Security:
- **Credential Redaction**: Passwords, certificate paths, and sensitive patterns are automatically scrubbed from logs and terminal output.
- **Subprocess Isolation**: Subprocess calls (`keytool`, `zipalign`, `apksigner`) execute within a clean environment built by `build_safe_env()`, stripping host credentials (`AWS_*`, `GITHUB_*`, `SSH_*`).
- **Mapping File Protection**: R8 mapping files contain the complete symbol deobfuscation dictionary. They are never exported into public directories or included in build archives.

---

## 18. Product Roadmap

```
+---------------------------------------------------------------------------------+
|                               APPSHIELD ROADMAP                                 |
+---------------------------------------------------------------------------------+
|                                                                                 |
| MILESTONE 1: FOUNDATION & GENERALIZATION (Phases 1-4, Phase A, Phase A.1)       |
|   [Complete] Python CLI, Sandbox, R8 Orchestration, Dual-Evidence Verification  |
|   [Active]   Multi-project validation across Groovy and Kotlin DSL projects     |
|                                                                                 |
| MILESTONE 2: ADVANCED CODE & STRING PROTECTION                                  |
|   [Planned]  Compile-time string encryption vault; control-flow obfuscation     |
|                                                                                 |
| MILESTONE 3: NATIVE HARDENING & ASSET SHIELD                                    |
|   [Planned]  Selective JNI/C++ logic compilation; encrypted asset storage       |
|                                                                                 |
| MILESTONE 4: RUNTIME DEFENSE & INTEGRITY MONITORING                             |
|   [Planned]  Anti-debug, anti-Frida/hooking, in-memory DEX integrity checks     |
|                                                                                 |
| MILESTONE 5: ANTI-PIRACY & SERVER-SIDE TRUST                                    |
|   [Planned]  Signature pinning, repackaging detection, backend auth schemas    |
|                                                                                 |
| MILESTONE 6: SECURITY VERIFICATION & ATTACK LABORATORY                          |
|   [Planned]  Automated decompiler benchmarks (JADX audit), bypass test suite    |
|                                                                                 |
| MILESTONE 7: STABLE ANDROID RELEASE (v1.0)                                      |
|   [Planned]  Public PyPI distribution, binary packages, developer documentation |
|                                                                                 |
+---------------------------------------------------------------------------------+
```

---

## 19. Release Readiness Gates (v1.0 Release Criteria)

Before AppShield can be tagged as a stable v1.0 release or distributed on PyPI, all of the following criteria must be satisfied:

1. **Multi-Project Compatibility**: Successfully protect and verify at least three distinct, unrelated Android Gradle projects (including pure Java, mixed Kotlin, Groovy DSL, and Kotlin DSL).
2. **Genuine Build Evidence**: Every project must build successfully through live Gradle/R8 execution with zero mock substitutions.
3. **Empirical DEX Verification**: Verified absence of original classes and verified presence of renamed classes confirmed in actual compiled bytecode.
4. **Real Runtime Validation**: The protected APK must install and execute cleanly on both an Android emulator (API 31+) and at least one physical Android hardware device without runtime exceptions.
5. **Adversarial Audit**: The output binary must be subjected to automated JADX decompilation, proving that core protected logic cannot be recovered via default decompilation.
6. **Clean Toolchain & CI**: Zero failing tests, >=90% test coverage, zero Ruff linter errors, zero Mypy type errors, zero Bandit security vulnerabilities, and verified wheel packaging.
7. **Documentation Accuracy**: All documentation (`README.md`, `ARCHITECTURE.md`, `MEMORY.md`, `PRD.md`) accurately reflects implemented functionality with zero inflated claims.

---

## 20. Risks and Technical Limitations

1. **Client-Side Secret Exposure**: Any secret bundled in an Android application can theoretically be extracted by an adversary monitoring memory at the exact moment of decryption.
2. **Runtime Overhead vs. Security Trade-off**: Aggressive string encryption and runtime integrity loops consume CPU cycles and memory; protections must be calibrated through baseline measurement to avoid noticeable user lag.
3. **Compatibility with Third-Party SDKs**: Heavy obfuscation and shrinking can break reflection-dependent libraries (e.g., Gson, Retrofit, Firebase). AppShield must respect explicit keep rules for third-party libraries while aggressively obfuscating application code.
4. **Anti-Debugging Fragility**: Operating-system updates or custom OEM kernels (MIUI, ColorOS) can alter `/proc/self/status` or `ptrace` behavior, risking false-positive crash loops if runtime checks are not carefully defensive.
5. **Network Dependency for Initial Builds**: Building Gradle projects requires all plugin dependencies (AGP, Kotlin DSL, R8) to exist in the local Gradle cache. An initial online build or cache warm-up is mandatory before offline protection can succeed.

---

## 21. Open Engineering Decisions

1. **Native Defense Architecture**: Should runtime defense checks (anti-Frida, anti-debug) be injected as pure Dalvik bytecode or compiled as a compact, stripped native C library (`libappshield.so`)?
   - *Consideration*: Native C libraries provide stronger resistance against Java-level method hooking, but introduce multi-ABI binary size overhead (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
2. **String Vault Decryption Strategy**: Should decrypted strings be cached in memory or decrypted on-demand per access?
   - *Consideration*: In-memory caching minimizes CPU overhead for frequently accessed strings, but leaves plaintext secrets resident in heap dumps.
3. **Integration Mechanism for Runtime Defense**: Should AppShield inject runtime defenses via automated bytecode manipulation during build staging, or provide an official, lightweight Android SDK (`com.appshield:runtime`) that developers include in their dependencies?
   - *Consideration*: Bytecode injection requires zero code changes from the developer, but risks bytecode verifier issues; an explicit SDK dependency is clean and reliable, but requires source-level developer adoption.
