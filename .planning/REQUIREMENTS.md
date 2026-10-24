# Requirements: AppShield

**Defined:** 2026-10-24  
**Core Value:** The developer's original source code and signing credentials remain completely untouched and local, while production application binaries undergo verifiable, reproducible multi-layer code protection with honest, auditable security reporting.

## v1 Requirements

Requirements committed for v1 release (Phases 1–4).

### Core CLI & Configuration

- [ ] **CLI-01**: User can execute the unified `appshield` CLI across platforms (Windows, macOS, Linux) with subcommands: `protect`, `verify`, `doctor`, and `info`.
- [ ] **CLI-02**: User can configure target paths, rules, and engines via `appshield.yaml` / `appshield.json` or CLI flags.
- [ ] **CLI-03**: CLI enforces 100% offline local execution with zero network telemetry and no outbound network calls.

### Isolation & Workspace Safety

- [ ] **ISO-01**: Source tree immutability — original source files and input binaries are treated as strictly read-only and never modified in place.
- [ ] **ISO-02**: Staged build execution — all intermediate transformation and decompilation steps take place in isolated temporary staging workspaces.
- [ ] **ISO-03**: Clean artifact output — hardened outputs are written to a designated, distinct output folder (e.g., `dist/protected/`) alongside a verification audit report.

### Android Protection Engine

- [ ] **AND-01**: `doctor` subcommand checks for local Android SDK prerequisites (`java`, `apksigner`, `zipalign`, Android build-tools) and reports missing dependencies cleanly.
- [ ] **AND-02**: Engine orchestrates compatible existing protection tools (R8/ProGuard configuration generation, APK resource and Dex bytecode protection) without inventing a custom bytecode compiler.
- [ ] **AND-03**: Engine supports safe local APK signing and alignment using local keystores without persisting or leaking credentials in logs or staging files.

### Verification & Honest Reporting

- [ ] **VER-01**: Post-build automated verification executes static analysis (symbol obfuscation check, string table encryption check, resource integrity).
- [ ] **VER-02**: Verification engine runs an automated decompilation audit (e.g. headless JADX / Dex disassembler check) and scores reverse-engineering resistance.
- [ ] **VER-03**: Report generator outputs an honest security summary that clearly explains residual risks and explicitly disclaims that reverse engineering is impossible.

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
| Custom Bytecode / Mach-O / PE Obfuscation Compiler | High maintenance burden, fragile semantics, and high probability of introducing runtime bugs; wrapping mature tools is significantly more reliable. |
| Remote / Cloud Telemetry or SaaS Processing | Breaches Core Requirement #6; source code and credentials must never leave the developer's workstation. |
| Unbreakable Protection Claims / DRM Guarantee | Technically impossible; client-side binaries running on user-controlled hardware can always be analyzed given enough time, skill, and tooling. |
| In-Memory Runtime Hook Evasion without Source SDK | Injecting fragile runtime memory hooks (e.g. anti-Frida/Xposed) into black-box APKs/Mach-O binaries causes crashes and store rejections; best handled by dedicated in-app SDKs if chosen by the developer. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLI-01 | Phase 3 | Pending |
| CLI-02 | Phase 3 | Pending |
| CLI-03 | Phase 3 | Pending |
| ISO-01 | Phase 3 | Pending |
| ISO-02 | Phase 3 | Pending |
| ISO-03 | Phase 3 | Pending |
| AND-01 | Phase 4 | Pending |
| AND-02 | Phase 4 | Pending |
| AND-03 | Phase 4 | Pending |
| VER-01 | Phase 4 | Pending |
| VER-02 | Phase 4 | Pending |
| VER-03 | Phase 4 | Pending |
| IOS-01 | Phase 5 | Deferred (v2) |
| IOS-02 | Phase 5 | Deferred (v2) |
| WIN-01 | Phase 6 | Deferred (v2) |
| WIN-02 | Phase 6 | Deferred (v2) |
| DOC-01 | Phase 7 | Deferred (v2) |
| DOC-02 | Phase 7 | Deferred (v2) |

**Coverage:**
- v1 requirements: 12 total
- Mapped to v1 phases: 12
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-24*
