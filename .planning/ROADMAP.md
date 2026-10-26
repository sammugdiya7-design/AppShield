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
- [x] 01-01: Domain research synthesis, license audit, competitor comparison, technical feasibility documentation, and root MEMORY.md initialization.

---

### Phase 2: Specifications, Threat Model, Architecture & Acceptance Criteria
**Goal**: Produce the system architecture blueprint, minimal plugin API design, configuration schema, objective verification report schema, and Android R8 MVP workflow without writing implementation code.  
**Depends on**: Phase 1  
**Requirements**: CLI-01, CLI-02, ISO-01, ISO-02, ISO-03, SEC-01, GOV-02, GOV-03, GOV-04  
**Success Criteria**:
  1. Minimal component architecture: CLI Dispatcher, Sandbox Manager, PlatformAdapter, and VerificationEngine specified without unnecessary abstractions.
  2. Strict configuration schema specified for `appshield.yaml` and `.appshield.json`.
  3. Objective empirical verification report schema (`audit_report.json`) defined, explicitly banning opaque composite "resistance scores".
  4. Real, reproducible Android R8 MVP protection workflow mapped out (unbundling, keep-rules, R8 invocation, zipalign, and credential-safe apksigner).
  5. Source preservation, isolated output directory, credential safety, and atomic failure recovery protocols documented.
  6. Disposable sample test fixture specification defined (`mini_app.apk`).  
**Plans**: 1 plan (02-01: Specifications, Schemas, and Architecture Contracts)

Plans:
- [x] 02-01: Architecture contracts, configuration schema, verification report schema, and Android R8 MVP specifications.

---

### Phase 3: Core Python CLI Foundation, Workspace Isolation & Test Harness
**Goal**: Build the extensible Python CLI framework, isolated workspace staging manager, disposable Android Gradle test fixture, and automated testing foundation.  
**Depends on**: Phase 2  
**Requirements**: CLI-01, CLI-02, CLI-03, ISO-01, ISO-02, ISO-03, GOV-01, GOV-02, GOV-04  
**Success Criteria**:
  1. Running `appshield --help`, `appshield doctor`, and `appshield info` succeeds across Windows, macOS, and Linux.
  2. Workspace isolation verified: staging directories created in temp paths with sensitive file exclusions (`.git`, `build`, `*.jks`, `local.properties`), source files strictly read-only and verified bit-for-bit identical before and after run.
  3. Clean separation of artifacts: protected outputs written strictly to distinct output folder; existing outputs never overwritten without explicit flag.
  4. Disposable Android Gradle project fixture (`tests/fixtures/sample_android_gradle_project/`) constructed for safe, repeatable testing.
  5. Complete unit test harness passing with >85% code coverage for core orchestration.  
**Plans**: 2 plans (03-01: CLI shell & config parser, 03-02: Isolated workspace sandbox manager & test fixture harness)

Plans:
- [x] 03-01: CLI scaffolding, subcommand registration, and config loader.
- [ ] 03-02: Workspace sandbox manager, input immutability guard, test fixture, and test suite.

---

### Phase 4: Android Protection Pipeline & Verification Engine
**Goal**: Deliver a functional, reproducible Android hardening pipeline for Android Gradle projects with automated objective verification.  
**Depends on**: Phase 3  
**Requirements**: AND-01, AND-02, AND-03, VER-01, VER-02, VER-03  
**Success Criteria**:
  1. `appshield doctor` verifies presence of Android build prerequisites (`java`, `gradlew`, Android SDK tools).
  2. `appshield protect --platform android` successfully processes an Android Gradle project via isolated staging, injecting R8 rules, invoking AGP build, and saving the protected APK to `dist/protected/`. Standalone precompiled APKs treated as unsupported.
  3. Output overwrite guard prevents accidental destruction of existing destination artifacts.
  4. Signing workflow supports environment-variable-masked keystores without leaking credentials in logs or process tables; production signing requires explicit confirmation.
  5. `appshield verify` executes objective empirical checks (renaming ratio, string scan, signature validity, zip alignment) and outputs `audit_report.json` with precise evidentiary classifications (no composite score).  
**Plans**: 2 plans (04-01: Android Gradle pipeline adapter & signing, 04-02: Objective verification & honest report generator)

Plans:
- [ ] 04-01: Android Gradle pipeline adapter, toolchain discovery, and signing workflow.
- [ ] 04-02: Objective verification engine, string pool scanner, and honest report generator.

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
| 1. Domain Research & Feasibility | 1/1 | Complete | 2026-10-24 |
| 2. Specs & Threat Model | 1/1 | Complete (Planning) | 2026-10-24 |
| 3. CLI Foundation & Sandboxing | 1/2 | In progress | - |
| 4. Android Pipeline & Verification | 0/2 | Not started | - |
| 5. iOS Protection Engine | 0/1 | Not started | - |
| 6. Windows Support | 0/1 | Not started | - |
| 7. Portfolio Release | 0/1 | Not started | - |
