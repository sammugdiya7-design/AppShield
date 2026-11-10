# Requirements: AppShield

**Defined:** 2026-10-24  
**Core Value:** The developer's original source code and signing credentials remain completely untouched and local, while production application binaries undergo verifiable, reproducible multi-layer code protection with honest, auditable security reporting.

## v1 Requirements

Requirements committed for v1 release (Phases 1–4).

### Core CLI & Configuration

- [x] **CLI-01**: User can execute the unified `appshield` CLI across platforms (Windows, macOS, Linux) with subcommands: `protect`, `verify`, `doctor`, and `info`.
- [x] **CLI-02**: User can configure target paths, rules, and engines via `appshield.yaml` / `appshield.json` or CLI flags.
- [x] **CLI-03**: CLI enforces 100% offline local execution with zero network telemetry and no outbound network calls.

### Isolation & Workspace Safety

- [x] **ISO-01**: Source tree immutability — original source files and build configurations are treated as strictly read-only and never modified in place.
- [x] **ISO-02**: Staged build execution — all intermediate transformation, R8 rule injection, and build steps take place in isolated temporary staging workspaces with sensitive file exclusions (`.git`, `build`, `*.jks`, `local.properties`, `.env`).
- [x] **ISO-03**: Clean artifact output & overwrite guard — hardened outputs are written to a designated, distinct output folder (e.g., `dist/protected/`); existing artifacts are never overwritten without explicit user confirmation.

### Android Protection Engine

- [x] **AND-01**: `doctor` subcommand checks for local Android SDK prerequisites (`java`, `apksigner`, `zipalign`, Android build-tools) and reports missing dependencies cleanly.
- [x] **AND-02**: Engine orchestrates protection via supported Android Gradle Plugin (AGP) and R8 build toolchain on Android Gradle projects; arbitrary precompiled APK input is unsupported in MVP.
- [x] **AND-03**: Engine supports safe local APK signing and alignment; credentials read strictly via environment variable names; no automatic production signing.

### Verification & Honest Reporting

- [x] **VER-01**: Post-build automated verification executes objective empirical checks (identifier renaming ratio, string pool inspection, signature integrity, zip alignment).
- [x] **VER-02**: Precise evidentiary classification: identifier renaming is evidence of obfuscation (not impossible reverse engineering), string scans detect patterns without absolute guarantees, signature checks prove signature validity (not app safety), and decompilation checks are informational.
- [x] **VER-03**: Report generator outputs objective metrics and explicit evidentiary definitions without any composite security scores.

### Permanent Review & Governance

- [x] **GOV-01**: Automated test execution harness (`pytest`) integrated and enforced across every task, plan, and code change.
- [x] **GOV-02**: Execution of the mandatory 10-step full review process (tests, code review, static analysis/linting/typing, security scans, secret/file safety checks, complexity checks, acceptance checks, honest status reporting, MEMORY.md sync, change summary).
- [x] **GOV-03**: Zero-credential leakage assurance — strict masking and prevention of private signing keys, keystore passwords, or sensitive application code appearing in logs, temp files, or version control.
- [x] **GOV-04**: Disposable sample test policy — all destructive or mutating operations run strictly on disposable fixtures (`tests/fixtures/sample_android_gradle_project/`); developer source files remain untouched.

## v2 Requirements

Deferred to subsequent phases (Phases 5–7).

### iOS Protection Engine (Phase 5)

- **IOS-01**: macOS-native Xcode toolchain integration for Swift/Obj-C symbol stripping (`strip`, `dsymutil`) and Mach-O binary metadata sanitization.
- **IOS-02**: Automated Apple Developer `codesign` validation and provisioning profile preservation.

### Windows Protection Engine (Phase 6)

- **WIN-01**: Windows .NET assembly protection orchestration using proven engines (e.g. Obfuscar) and native PE symbol stripping.
- **WIN-02**: AV heuristic safety check verifying the protected Windows executable does not trigger common generic heuristic flags.

### Portfolio & Distribution (Phase 7)

- **DOC-01**: Production-grade open-source GitHub repository setup with CI/CD pipeline, security policy, threat model documentation, and reproducible demo fixtures.
- **DOC-02**: PyPI package distribution and standalone single-file binary builds (via PyInstaller/uv).

## Out of Scope

Explicitly excluded to protect project safety, focus, and integrity.

| Feature | Reason |
|---------|--------|
| Arbitrary Precompiled APK Obfuscation via Standalone R8 | R8 requires full compile-time classpath, platform jars, and resource ID tables available in Gradle projects; arbitrary APKs without build context are unsupported in MVP. |
| Custom Bytecode / Mach-O / PE Obfuscation Compiler | High maintenance burden, fragile semantics, and high probability of introducing runtime bugs; wrapping mature tools is significantly more reliable. |
| Remote / Cloud Telemetry or SaaS Processing | Breaches Core Requirement #6; source code and credentials must never leave the developer's workstation. |
| Unbreakable Protection Claims / Composite Security Scores | Technically impossible; client-side binaries running on user-controlled hardware can always be analyzed given enough time, skill, and tooling. |
| In-Memory Runtime Hook Evasion without Source SDK | Injecting fragile runtime memory hooks (e.g. anti-Frida/Xposed) into black-box APKs/Mach-O binaries causes crashes and store rejections; best handled by dedicated in-app SDKs if chosen by the developer. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | Phase 3 | Complete |
| CLI-02 | Phase 3 | Complete |
| CLI-03 | Phase 3 | Complete |
| ISO-01 | Phase 3 | Complete |
| ISO-02 | Phase 3 | Complete |
| ISO-03 | Phase 3 | Complete |
| AND-01 | Phase 4 | Complete |
| AND-02 | Phase 4 | Complete |
| AND-03 | Phase 4 | Complete |
| VER-01 | Phase 4 | Complete |
| VER-02 | Phase 4 | Complete |
| VER-03 | Phase 4 | Complete |
| GOV-01 | Phase 3 | Complete |
| GOV-02 | Phase 1–7 | Active (Continuous) |
| GOV-03 | Phase 3 | Complete |
| GOV-04 | Phase 3 | Complete |
| IOS-01 | Phase 5 | Deferred (v2) |
| IOS-02 | Phase 5 | Deferred (v2) |
| WIN-01 | Phase 6 | Deferred (v2) |
| WIN-02 | Phase 6 | Deferred (v2) |
| DOC-01 | Phase 7 | Deferred (v2) |
| DOC-02 | Phase 7 | Deferred (v2) |

**Coverage:**
- v1 requirements: 16 total
- Completed in v1: 16 (100%)
- Mapped to phases: 16
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-24*
*Last updated: 2026-11-10 with Phase 4 Android v1 completion*
