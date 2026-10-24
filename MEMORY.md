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
| **Android MVP Engine** | Official Google R8 CLI + `zipalign` + `apksigner` | Reliable, modern industry standard; avoids custom bytecode decompiler bugs. |
| **Credential Masking** | Passwords referenced exclusively via env var names | Eliminates plaintext credentials from CLI flags, process lists, and disk files. |
| **Disposable Test Fixtures** | Isolated sample APK (`mini_app.apk`) for test suites | Satisfies safety rule: destructive/mutating operations run exclusively on disposable fixtures. |

---

## 3. Current Phase & Progress

- **Current Phase**: Phase 2: Specifications, Threat Model, Architecture & Acceptance Criteria
- **Current Plan**: 02-01 (Architecture contracts, schemas, and MVP specifications)
- **Status**: Phase 2 Planning Complete (Awaiting User Approval before Phase 3 Implementation)
- **Overall Progress**: 28% (Phases 1 & 2 planned and verified; Phases 3–7 pending implementation)

---

## 4. Completed Features & Pending Tasks

### Completed
- [x] Initialized GSD planning infrastructure (`PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`, `config.json`).
- [x] Completed Phase 1 Research dossier (`.planning/research/PHASE1_RESEARCH.md`).
- [x] Established root-level `MEMORY.md` and permanent project governance rules.
- [x] Completed Phase 2 Specifications dossier (`.planning/specs/PHASE2_SPECIFICATIONS.md`) covering CLI schema, interfaces, report schema, R8 MVP, and test fixtures.

### Pending Immediate Tasks
- [ ] Obtain user approval for Phase 2 specifications.
- [ ] Prepare Phase 3 implementation plan (`03-01`: CLI scaffolding & config loader, `03-02`: sandbox manager & test harness).
- [ ] Build disposable test fixture (`tests/fixtures/sample_android/mini_app.apk`).

---

## 5. Supported Platforms & Protection Methods

| Platform | Target Binaries / Formats | Primary Protection Methods | Verification Method |
|:---|:---|:---|:---|
| **Android** (v1) | APK, AAB | R8/ProGuard shrinking, Smali string encryption, resource obfuscation, zipalign, apksigner | Headless JADX decompiler audit, string table scan, signature check |
| **iOS** (v2) | IPA, Mach-O, dSYM | Xcode CLI symbol stripping (`strip -x`, `dsymutil`), Swift-Shield symbol renaming, codesign validation | `otool` / `strings` symbol table audit, `codesign --verify --deep` |
| **Windows** (v2) | .NET Assemblies, Native PE | Obfuscar (.NET symbol/string obfuscation), native symbol stripping, AV heuristic safety scan | `dumpbin` / `ildasm` inspection, section entropy scan |

---

## 6. Testing Requirements & Known Limitations

### Testing Requirements
- Unit test suite (`pytest`) with >=85% code coverage for core orchestration.
- Integration tests run against **disposable sample projects / test fixtures only** — never against live production developer code.
- Verification tests must assert input files remain bit-for-bit identical (SHA-256 unchanged before and after protection).

### Known Limitations
- **Android**: Google Play App Signing requires bytecode protection before `.aab` bundling. Reflection requires explicit keep-rules.
- **iOS**: Apple App Store Guideline 2.5.2 & W^X memory restrictions strictly forbid binary runtime packers. iOS protection requires a macOS host with Xcode CLI tools.
- **Windows**: Runtime PE packers (e.g. UPX) trigger false-positive malware detections in Windows Defender; protection must focus on symbol stripping and .NET metadata.
- **Fundamental Law**: Client-side software executed on an attacker's hardware cannot be made 100% immune to reverse engineering.

---

## 7. Third-Party Tools, Licenses & Integration Boundaries

| Tool | License | Role | Integration Boundary |
|:---|:---|:---|:---|
| **R8 / ProGuard** | BSD-3-Clause / Apache 2.0 | Android bytecode shrinking & renaming | CLI subprocess invocation / build-tools |
| **Apktool** | Apache 2.0 | APK resource extraction & rebuilding | Subprocess CLI (`apktool.jar`) |
| **JADX** | Apache 2.0 | Android automated verification decompiler | Headless CLI subprocess (`jadx`) |
| **Obfuscapk** | GPLv3 | Reference/optional smali transforms | Loose CLI subprocess only (never imported or linked) |
| **Obfuscar** | MIT | Windows .NET assembly obfuscation | Subprocess CLI |
| **Apple Xcode CLI** | Proprietary (macOS) | iOS symbol stripping & signing (`strip`, `codesign`) | Native macOS subprocess commands |

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
- Do not attempt in-memory dynamic anti-tampering/hook evasion without a source-level SDK; black-box injection breaks apps and causes App Store rejections.
- Do not use UPX or runtime PE packers on Windows; they trigger AV false positives.
- Do not vendor or statically import GPL code into the permissive core.
