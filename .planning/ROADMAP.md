# Roadmap: AppShield

## Overview

AppShield is developed across 7 modular phases, transitioning from deep domain and competitive intelligence to a robust cross-platform CLI architecture, followed by platform-specific engine implementations (Android, iOS, Windows), rigorous automated verification, and open-source portfolio release.

## Phases

- [ ] **Phase 1: Domain Research, Engines, Licenses & Platform Limitations** - In-depth research of existing tools, competitive landscape, licensing boundaries, and OS constraints.
- [ ] **Phase 2: Specifications, Threat Model, System Architecture & Acceptance Criteria** - Formalize data contracts, threat boundaries, pipeline plugins, and verification matrices.
- [ ] **Phase 3: Core Python CLI Foundation, Workspace Isolation & Test Harness** - Scaffold CLI commands (`protect`, `verify`, `doctor`), ephemeral sandboxing, and unit test suite.
- [ ] **Phase 4: Android Protection Pipeline & Verification Engine** - Integrate Android toolchains (R8/ProGuard/APK hardening), signing workflows, and JADX-based automated verification.
- [ ] **Phase 5: iOS Protection Engine & Mach-O Sanitization** - Add macOS/Xcode toolchain support, symbol stripping, and codesign validation.
- [ ] **Phase 6: Windows Protection Engine & AV Safety** - Add Windows .NET/PE protection orchestration and AV heuristic risk reporting.
- [ ] **Phase 7: Portfolio Polish, Documentation & GitHub Release** - Finalize documentation, reproducible test fixture showcase, CI/CD workflows, and release packaging.

---

## Phase Details

### Phase 1: Domain Research, Engines, Licenses & Platform Limitations
**Goal**: Identify existing, battle-tested protection engines for Android/iOS/Windows, map out licensing obligations, audit competitor feature sets, establish platform limitations, and institutionalize permanent project governance rules.  
**Depends on**: Nothing (Initial Phase)  
**Requirements**: Research foundation for all requirements, GOV-02  
**Success Criteria**:
  1. Complete competitive matrix comparing open-source and commercial protection tools (Guardsquare, Promon, Obfuscapk, Obfuscar, Swift-Shield, R8/ProGuard).
  2. Identified compatible, permissively orchestratable engines per platform and established subprocess boundary license compatibility.
  3. Formulated honest security doctrine defining the boundaries between raising reverse-engineering work factors vs. impossible "unbreakable" claims.
  4. Platform limitations documented for Android (signing v2/v3, AAB vs APK), iOS (App Store guidelines, Mach-O integrity, codesign), and Windows (Authenticode, AV heuristics).
  5. Established root-level `MEMORY.md` recording vision, non-goals, architecture, limitations, and operational invariants.
  6. Phase 1 closure verified via the mandatory 10-step full review process.  
**Plans**: 1 plan (01-01: Research synthesis, architecture proposal, and governance foundation)

Plans:
- [ ] 01-01: Domain research synthesis, license audit, competitor comparison, technical feasibility documentation, and root MEMORY.md initialization.

---

### Phase 2: Specifications, Threat Model, Architecture & Acceptance Criteria
**Goal**: Produce the system architecture blueprint, modular plugin API design, threat model, and rigorous acceptance test criteria.  
**Depends on**: Phase 1  
**Requirements**: Architecture definition for CLI-01, ISO-01, ISO-02, ISO-03, SEC-01  
**Success Criteria**:
  1. Documented component architecture: CLI Dispatcher, Sandbox Manager, Platform Pipeline Adapters, Verification Engine, and Audit Reporter.
  2. Threat Model document explicitly identifying in-scope adversary capabilities and out-of-scope physical runtime attacks.
  3. Formal schema for `appshield.yaml` configuration and JSON verification reports.
  4. Measurable acceptance test criteria defined for every subsequent phase.  
**Plans**: 1 plan (02-01: Specifications, Threat Model, and Architecture Contract)

Plans:
- [ ] 02-01: Architecture contract, threat model, and configuration schema design.

---

### Phase 3: Core Python CLI Foundation, Workspace Isolation & Test Harness
**Goal**: Build the extensible Python CLI framework, isolated workspace staging manager, and automated testing foundation.  
**Depends on**: Phase 2  
**Requirements**: CLI-01, CLI-02, CLI-03, ISO-01, ISO-02, ISO-03  
**Success Criteria**:
  1. Running `appshield --help`, `appshield doctor`, and `appshield info` succeeds across Windows, macOS, and Linux.
  2. Workspace isolation verified: staging directories are created in temp/cache paths, source files are strictly read-only, and original files remain bit-for-bit identical after execution.
  3. Clean separation of artifacts: protected outputs and verification logs write exclusively to the designated destination directory.
  4. Complete unit test harness passing with >85% code coverage for core orchestration.  
**Plans**: 2 plans (03-01: CLI shell & config parser, 03-02: Isolated workspace & sandbox manager)

Plans:
- [ ] 03-01: CLI scaffolding, subcommand registration, and config loader.
- [ ] 03-02: Workspace sandbox manager, input immutability guard, and test suite.

---

### Phase 4: Android Protection Pipeline & Verification Engine
**Goal**: Deliver a functional, real-world Android hardening pipeline with automated decompilation and symbol verification.  
**Depends on**: Phase 3  
**Requirements**: AND-01, AND-02, AND-03, VER-01, VER-02, VER-03  
**Success Criteria**:
  1. `appshield doctor` verifies presence of Android SDK tools (`java`, `apksigner`, `zipalign`) with actionable remediation tips if missing.
  2. `appshield protect --platform android` successfully processes an input APK/AAB through multi-layer obfuscation (class/method renaming, string encryption, resource shrinking) in isolated staging.
  3. Hardened APK is aligned and signed using a local keystore without leaking keystore passwords in logs.
  4. `appshield verify` executes an automated decompilation audit (headless analysis) and generates a quantitative resistance score and honest residual risk report.  
**Plans**: 2 plans (04-01: Android protection orchestrator & signing, 04-02: Automated verification & security audit reporter)

Plans:
- [ ] 04-01: Android pipeline adapter, toolchain discovery, and signing workflow.
- [ ] 04-02: Headless decompilation verification, string table audit, and honest report generator.

---

### Phase 5: iOS Protection Engine & Mach-O Sanitization
**Goal**: Implement macOS/Xcode toolchain integration for iOS applications (Swift/Objective-C symbol stripping and binary hardening).  
**Depends on**: Phase 4  
**Requirements**: IOS-01, IOS-02  
**Success Criteria**:
  1. Platform adapter detects macOS host and Xcode command-line tools (`strip`, `dsymutil`, `otool`, `codesign`).
  2. Swift/Obj-C binary undergoes symbol stripping and metadata sanitization without corrupting dynamic linking or Mach-O load commands.
  3. Re-codesigning completes successfully and validates with `codesign --verify --deep`.  
**Plans**: 1 plan (05-01: iOS pipeline adapter and Mach-O verification)

Plans:
- [ ] 05-01: iOS toolchain integration, symbol stripping, and codesign validator.

---

### Phase 6: Windows Support (.NET & Native PE)
**Goal**: Implement Windows executable protection orchestration and AV heuristic risk evaluation.  
**Depends on**: Phase 4  
**Requirements**: WIN-01, WIN-02  
**Success Criteria**:
  1. Support for Windows .NET assemblies using established tools (such as Obfuscar) to rename symbols and encrypt string constants.
  2. Native PE header and symbol sanitization for compiled C/C++ binaries.
  3. AV safety check flagging high-risk heuristic patterns (e.g., suspicious PE section entropy or known packer signatures).  
**Plans**: 1 plan (06-01: Windows .NET/PE protection adapter and AV heuristic check)

Plans:
- [ ] 06-01: Windows pipeline adapter, .NET/PE protection orchestration, and AV risk analyzer.

---

### Phase 7: Portfolio Polish, Documentation & GitHub Release
**Goal**: Package AppShield into a world-class, production-ready open-source portfolio project with documentation, demo fixtures, and CI automation.  
**Depends on**: Phases 1–6  
**Requirements**: DOC-01, DOC-02  
**Success Criteria**:
  1. Professional README with architecture diagrams, quickstart guide, security disclosure policy, and sample audit reports.
  2. Automated test matrix running on GitHub Actions across Ubuntu, macOS, and Windows runners.
  3. Standalone packaging via PyInstaller / uv wheel release.  
**Plans**: 1 plan (07-01: Portfolio release, documentation, demo fixtures, and CI/CD)

Plans:
- [ ] 07-01: Portfolio release engineering, demo test apps, and documentation suite.

---

## Progress

**Execution Order:**
Phases execute in order: 1 → 2 → 3 → 4 → 5 → 6 → 7

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Domain Research & Feasibility | 0/1 | In progress | - |
| 2. Specs & Threat Model | 0/1 | Not started | - |
| 3. CLI Foundation & Sandboxing | 0/2 | Not started | - |
| 4. Android Pipeline & Verification | 0/2 | Not started | - |
| 5. iOS Protection Engine | 0/1 | Not started | - |
| 6. Windows Support | 0/1 | Not started | - |
| 7. Portfolio Release | 0/1 | Not started | - |
