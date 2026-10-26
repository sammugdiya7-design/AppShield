# AppShield

A simple, local, cross-platform application code-protection CLI for developers targeting Android, iOS, and Windows.

Designed to raise reverse-engineering work factors without vendor lock-in, recurring SaaS fees, or cloud privacy risks.

## Core Architectural Invariants

* **100% Local & Offline**: Zero network telemetry, analytics, or remote signing servers.
* **Source Preservation & Immutability**: Original application source code, sensitive keys (`*.jks`), environment files (`.env`), and configuration files are treated as strictly read-only and verified bit-for-bit identical via pre- and post-run SHA-256 manifests.
* **Ephemeral Workspace Staging**: Build transformations take place exclusively in isolated temporary directories with strict exclusions for credentials and version control files.
* **Objective Verification**: Generates empirical evidence reports based on objective decompilation and symbol scans, explicitly banning opaque composite "resistance scores".
* **Credential Masking**: Passwords are read strictly via environment variable names; never passed as plaintext CLI arguments or stored on disk.

## Isolation Architecture & Threat Model Boundaries

AppShield enforces strict boundaries between filesystem staging, input verification, and execution security:

1. **Isolated Staging Directory**: An ephemeral directory created under the host's system temporary storage (`tempfile.gettempdir() / "appshield_staging" / build_<uuid>`). Project files are copied here to prevent in-place modification of developer repositories.
2. **Protection Against Unintended Filesystem Changes**:
   - **Source Immutability**: A cryptographic SHA-256 manifest of the source directory is computed before staging and verified after execution. Any modification, addition, or deletion of original project files triggers an immediate `SourceImmutabilityError`.
   - **Sensitive Exclusions**: Sensitive files (`*.jks`, `*.keystore`, `local.properties`, `*.env*`, `google-services.json`) are excluded from the staging copy to prevent credential leakage into build outputs, but remain strictly protected under source-immutability checks.
   - **Artifact Overwrite Guards**: Protected outputs are written exclusively to designated output directories (`dist/protected/`) and will never overwrite existing files without explicit authorization (`--overwrite`).
3. **Crucial Distinction: Staging Directory vs. OS Process Sandbox**:
   - **AppShield is NOT an OS-level kernel process sandbox** (such as Linux namespaces/seccomp, macOS seatbelt, or Windows AppContainers).
   - An ephemeral temporary folder provides **filesystem copy isolation**, not process privilege restriction.
   - Subprocesses spawned during a build (e.g., `gradlew`, R8, Java runtime) execute with the **standard operating system privileges of the invoking user** and have standard network/filesystem access permitted by the OS.
4. **Build Execution Risks & Untrusted Code**:
   - Build scripts (`build.gradle`, `settings.gradle`, build plugins) execute arbitrary Groovy/Kotlin JVM bytecode.
   - **Testing Policy**: Automated tests and integration harnesses execute exclusively on controlled, disposable sample projects. Never run automated tests against untrusted or arbitrary external developer projects.
   - **Future Release Requirements**: Before AppShield can safely build untrusted developer projects, we must define explicit user consent prompts, execution threat models, and containerized/sandboxed build execution environments.

## Installation

Install in editable development mode:

```bash
pip install -e .
```

With development dependencies:

```bash
pip install -e ".[dev]"
```

## CLI Usage

### 1. `appshield info`
Display version, architecture principles, and platform support status:

```bash
appshield info
```

### 2. `appshield doctor`
Inspect local host environment and tool prerequisites (Java, javac, `JAVA_HOME`, `ANDROID_HOME`, Gradle/gradlew, `zipalign`, `apksigner`):

```bash
appshield doctor
# Or inspect with a specific Android project directory to detect gradlew
appshield doctor --project-dir ./samples/android_sample_project
```

### 3. `appshield protect`
Validate configuration files (`appshield.yaml` or `appshield.json`), check prerequisites, and enforce output overwrite protection:

```bash
appshield protect -c appshield.yaml
```

*(Note: In Plan 03-01, preflight validation and guards are active; the actual Android R8 build pipeline will be executed in Phase 4).*

### 4. `appshield verify`
Inspect application artifacts and report empirical check capability status:

```bash
appshield verify ./dist/protected/sample_app-release-protected.apk
```

## Running Tests

Run the test suite with coverage:

```bash
pytest --cov=appshield --cov-report=term-missing
```

Linting and type checking:

```bash
ruff check appshield tests
ruff format --check appshield tests
mypy appshield tests
bandit -r appshield
```
