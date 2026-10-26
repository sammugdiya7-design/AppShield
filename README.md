# AppShield

A simple, local, cross-platform application code-protection CLI for developers targeting Android, iOS, and Windows.

Designed to raise reverse-engineering work factors without vendor lock-in, recurring SaaS fees, or cloud privacy risks.

## Core Architectural Invariants

* **100% Local & Offline**: Zero network telemetry, analytics, or remote signing servers.
* **Source Preservation**: Original application source code and binaries are treated as strictly read-only and never modified in place.
* **Ephemeral Workspace Staging**: Build transformations take place exclusively in isolated temporary directories with strict exclusions for credentials and version control files.
* **Objective Verification**: Generates empirical evidence reports based on objective decompilation and symbol scans, explicitly banning opaque composite "resistance scores".
* **Credential Masking**: Passwords are read strictly via environment variable names; never passed as plaintext CLI arguments or stored on disk.

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
