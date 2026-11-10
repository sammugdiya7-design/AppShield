# AppShield

## What This Is

AppShield is a lightweight, local-only, cross-platform application code-protection CLI for developers targeting Android, iOS, and eventually Windows. It automates hardening workflows by orchestrating existing, trusted protection engines within isolated staging workspaces while rigorously preserving original source trees, verifying binary protection outcomes, and guaranteeing zero remote telemetry or credential leakage.

## Core Value

The developer's original source code and signing credentials remain completely untouched and local, while production application binaries undergo verifiable, reproducible multi-layer code protection with honest, auditable security reporting.

## Requirements

### Validated

- **CLI-01**: Python-based cross-platform CLI supporting modular commands (`protect`, `verify`, `info`, `doctor`) — Validated in Phase 3.
- **ISO-01**: Source tree immutability guarantee — original source files and build configurations are opened read-only and never modified in place — Validated in Phase 3.
- **ISO-02**: Staged build execution in isolated temporary workspaces with sensitive file exclusions and dedicated output artifact directories — Validated in Phase 3.
- **SEC-01**: Zero remote network transmission — no source code, telemetry, or signing keys/keystores ever leave the host machine — Validated in Phase 3.
- **ENG-01**: Integration of verified Android protection workflows (leveraging Android Gradle Plugin and R8 toolchain on supported Android Gradle projects) — Validated in Phase 4.
- **VER-01**: Automated post-protection verification (symbol renaming ratio, string table inspection, signature integrity, and zip alignment) — Validated in Phase 4.
- **VER-02**: Honest reporting engine — outputs objective evidence metrics without subjective composite scores and without claiming reverse engineering is impossible — Validated in Phase 4.
- **ENG-02**: Pluggable architecture ready for iOS (Phase 5) and Windows (Phase 6) pipelines — Validated in Phase 4 (`PlatformAdapter` interface).

### Active

- [ ] **DEV-01**: Dynamic physical-device testing across diverse Android OEM hardware (ARM64/ARMv7, Samsung Knox, Xiaomi MIUI, ColorOS).
- [ ] **IOS-01**: iOS Protection Engine & Mach-O Sanitization (Phase 5).
- [ ] **WIN-01**: Windows Protection Engine & AV Safety (Phase 6).

### Out of Scope

- **Arbitrary Precompiled APK-Only Obfuscation via Standalone R8**: Running R8 directly on arbitrary precompiled APKs without full platform dependencies, compile classpath, and resource ID tables is technically brittle and unsupported in MVP. Android protection requires an Android Gradle project.
- **Custom Obfuscation Engine**: AppShield will NOT write a proprietary Dex, Mach-O, or PE compiler/obfuscation core from scratch; it orchestrates battle-tested, compatible existing tools.
- **Remote / Cloud Protection Service**: No cloud backend, web dashboard, or SaaS telemetry server.
- **Unbreakable DRM / Anti-Tamper Claims**: Defeating all reverse engineering indefinitely is technically impossible on client devices where the adversary possesses local physical execution control. AppShield raises attack cost/complexity, but will never claim absolute immunity.
- **Dynamic In-Memory Anti-Hooking / Root Evasion without App SDK Integration**: Client-side runtime hook detection (e.g., Frida/Xposed hooks) requires deep in-process SDK integration, which cannot be reliably injected into arbitrary black-box binaries without source-level runtime hooks or risking platform policy rejections.

## Context

Developers and indie studios often face a steep barrier between free, bare-bones compiler flags (like default ProGuard/R8 rules) and prohibitive enterprise protection suites (Guardsquare DexGuard/iXGuard, Promon SHIELD, Digital.ai Arxan) that cost thousands of dollars per year and often mandate cloud integrations. 

AppShield fills the gap by providing an open, developer-centric, transparent CLI tool that runs locally, automates multi-stage protection, prevents workspace pollution, and verifies that the output binary actually resisted standard decompilation tools (like JADX, strings, objdump) before shipping.

## Constraints

- **Tech Stack**: Python 3.10+ CLI with minimal external dependencies, leveraging native OS subprocesses for tooling engines.
- **Local Isolation**: Absolute requirement for offline operation; network sockets disabled during protection operations.
- **Workspace Safety & Input Immutability**: Original source directories and binaries treated strictly as read-only inputs. Protected outputs kept separate.
- **Credential Protection**: Never expose, log, or persist private signing keys, keystore passwords, or proprietary code.
- **Testing Safety**: Destructive or potentially risky operations tested ONLY on disposable sample projects.
- **License Compliance**: Any bundled or invoked third-party engines (GPL/Apache/MIT) must maintain clean subprocess execution boundaries to ensure license compatibility.
- **Permanent Review Gate**: Every task, planning phase, or code change must undergo the mandatory 10-step full review process documented in `MEMORY.md`.
- **Platform Limitations**: 
  - Android requires valid keystores for repackaged APK/AAB alignment and v2/v3/v4 signing.
  - iOS requires macOS host and Apple Developer code signing certificates (`codesign`) to run on physical hardware; Mach-O tampering risks invalidating App Store validation if not compliant with FairPlay and Xcode toolchains.
  - Windows requires PE Authenticode considerations; heavy binary packing triggers heuristic antivirus (AV) false positives.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Orchestrator Architecture over Custom Obfuscator | Building a compiler backend is prone to semantic breakage and maintenance overhead; existing tools (R8, ProGuard, Obfuscar, Swift tools) are mature and robust. | ✓ Good |
| Android Gradle Project as Primary MVP Input | Running R8 via AGP on complete Gradle projects ensures full classpath, resource bindings, and platform compatibility. Standalone APK input is explicitly unsupported. | ✓ Good |
| Ephemeral Build Sandbox with Exclusion Filters | Copying inputs into an isolated `.appshield_staging/` sandbox while filtering `.git`, `build`, and keystores prevents project corruption and credential leaks. | ✓ Good |
| Objective Evidence Matrix over Composite Score | Avoids misleading "security scores"; reports concrete metrics, what each check proves, what it does not prove, and evidence status (`verified`/`heuristic`/`informational`). | ✓ Good |
| Honest Security Doctrine | Explicitly stating the limits of obfuscation builds professional credibility and aligns with OWASP MASVS recommendations. | ✓ Good |
| Root MEMORY.md & Mandatory 10-Step Review Gate | Ensures institutional memory, continuous regression detection, zero credential leakage, and strict adherence to project invariants across all sessions. | ✓ Good |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition**:
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone**:
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-11-10 after Phase 4 Android v1 completion and runtime validation*
