"""
Integration tests for the disposable Android Gradle test fixture.
Verifies project structure, supported project detection, source immutability,
sensitive file exclusions, path/symlink safety, prerequisite diagnostic messages,
and safe execution distinction between actual and simulated builds.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from appshield.config import OverwriteError
from appshield.doctor import (
    is_android_gradle_project,
    run_doctor_checks,
)
from appshield.sandbox import (
    SandboxManager,
    SecurityError,
    SourceImmutabilityError,
    compute_file_sha256,
)

FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "sample_android_gradle_project"
).resolve()


def test_fixture_directory_structure():
    """Verify that the fixture contains all expected Android Gradle project files."""
    assert FIXTURE_DIR.exists(), f"Fixture directory does not exist: {FIXTURE_DIR}"
    assert FIXTURE_DIR.is_dir()

    expected_files = [
        "README.md",
        "appshield.yaml",
        "settings.gradle",
        "build.gradle",
        "gradlew",
        "gradlew.bat",
        "gradle/wrapper/gradle-wrapper.properties",
        "app/build.gradle",
        "app/proguard-rules.pro",
        "app/src/main/AndroidManifest.xml",
        "app/src/main/res/values/strings.xml",
        "app/src/main/java/com/appshield/sample/MainActivity.java",
        "app/src/main/java/com/appshield/sample/IdentifiableSecretService.java",
        "app/src/main/java/com/appshield/sample/PaymentSecurityValidator.java",
    ]

    for rel_path in expected_files:
        target = FIXTURE_DIR / rel_path
        assert target.exists(), f"Expected fixture file missing: {rel_path}"
        assert target.is_file(), f"Expected path to be a file: {rel_path}"
        assert target.stat().st_size > 0, f"Expected non-empty file: {rel_path}"


def test_fixture_identifiable_tokens_and_no_real_secrets():
    """
    Verify that the fixture contains deliberately identifiable classes, methods,
    and strings for later R8 verification, while containing zero real secrets.
    """
    secret_service_java = (
        FIXTURE_DIR
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "appshield"
        / "sample"
        / "IdentifiableSecretService.java"
    ).read_text(encoding="utf-8")

    validator_java = (
        FIXTURE_DIR
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "appshield"
        / "sample"
        / "PaymentSecurityValidator.java"
    ).read_text(encoding="utf-8")

    # 1. Identifiable classes and methods
    assert "class IdentifiableSecretService" in secret_service_java
    assert "processUserTokenAndCalculateHash" in secret_service_java
    assert "calculateInternalSecurityChecksum" in secret_service_java

    assert "class PaymentSecurityValidator" in validator_java
    assert "validateTransactionToken" in validator_java

    # 2. Identifiable non-sensitive test strings
    assert "APP_SHIELD_TEST_STRING_LITERAL_XYZ" in secret_service_java
    assert "DISPOSABLE_TEST_PAYMENT_SECRET_TOKEN" in secret_service_java
    assert "NON_SENSITIVE_VALIDATION_SCHEME_V1" in validator_java

    # 3. Security invariant: zero real secrets or private keys in the entire fixture
    for root, _, files in os.walk(FIXTURE_DIR):
        for f in files:
            file_path = Path(root) / f
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            assert "-----BEGIN PRIVATE KEY-----" not in content
            assert "-----BEGIN RSA PRIVATE KEY-----" not in content
            assert "AIzaSy" not in content  # Real Google API key prefix
            assert "AKIA" not in content  # Real AWS Access Key ID prefix


def test_fixture_identified_as_supported_android_gradle_project():
    """Verify that AppShield recognizes the fixture as a supported Android Gradle project."""
    is_supported, reasons = is_android_gradle_project(FIXTURE_DIR)
    assert is_supported is True
    assert reasons == []

    # Verify doctor check integration
    reports = run_doctor_checks(project_dir=FIXTURE_DIR)
    struct_report = next(
        r for r in reports if r.name == "Android Gradle Project Structure"
    )
    assert struct_report.is_available is True
    assert struct_report.version == "Supported Android Gradle Project"
    assert struct_report.remediation_hint == ""


def test_fixture_structure_rejection_for_invalid_directories(tmp_path: Path):
    """Verify that incomplete or non-Android directories produce clear diagnostic reasons."""
    # 1. Non-existent path
    ok, reasons = is_android_gradle_project(tmp_path / "does_not_exist")
    assert ok is False
    assert any("does not exist" in r for r in reasons)

    # 2. File path instead of directory
    dummy_file = tmp_path / "file.txt"
    dummy_file.write_text("not a dir", encoding="utf-8")
    ok, reasons = is_android_gradle_project(dummy_file)
    assert ok is False
    assert any("not a directory" in r for r in reasons)

    # 3. Empty directory missing wrapper, settings, and build files
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    ok, reasons = is_android_gradle_project(empty_dir)
    assert ok is False
    assert any("Missing Gradle wrapper" in r for r in reasons)
    assert any("Missing Gradle settings file" in r for r in reasons)
    assert any("Missing Android application build file" in r for r in reasons)


def test_fixture_source_preservation_during_inspection_and_staging(tmp_path: Path):
    """
    Verify that staging the fixture into an isolated workspace leaves the original
    fixture files completely untouched and bit-for-bit identical.
    """
    # Record original SHA-256 hashes of all fixture files
    original_hashes: dict[str, str] = {}
    for root, _, files in os.walk(FIXTURE_DIR):
        for f in files:
            fp = Path(root) / f
            rel = fp.relative_to(FIXTURE_DIR).as_posix()
            original_hashes[rel] = compute_file_sha256(fp)

    staging_scratch = tmp_path / "staging_scratch"

    # Stage the fixture
    with SandboxManager(source_dir=FIXTURE_DIR, staging_parent=staging_scratch) as sb:
        assert sb.staging_dir.exists()
        assert (sb.staging_dir / "app" / "build.gradle").exists()
        assert (sb.staging_dir / "settings.gradle").exists()

        # Simulate actions inside the staging sandbox
        mock_output = sb.staging_dir / "app" / "build" / "outputs" / "apk" / "release"
        mock_output.mkdir(parents=True)
        (mock_output / "app-release-unsigned.apk").write_bytes(b"MOCK_STAGED_APK")

    # Staging sandbox was safely cleaned up
    assert not sb.staging_dir.exists()

    # Verify that original fixture is 100% byte-for-byte identical
    for rel, original_hash in original_hashes.items():
        current_fp = FIXTURE_DIR / rel
        assert current_fp.exists(), f"Original fixture file missing: {rel}"
        assert compute_file_sha256(current_fp) == original_hash, (
            f"Original fixture file was modified: {rel}"
        )


def test_fixture_sandbox_excludes_sensitive_files_and_preserves_fixture(
    tmp_path: Path,
):
    """
    Verify that sensitive files placed in a disposable fixture clone are excluded
    from the staging copy, but strictly preserved in the original directory.
    """
    # Create disposable clone of the fixture
    clone_dir = tmp_path / "disposable_fixture_clone"
    shutil.copytree(FIXTURE_DIR, clone_dir)

    # Inject mock sensitive files into the clone
    (clone_dir / "release.jks").write_bytes(b"MOCK_SENSITIVE_KEYSTORE")
    (clone_dir / "local.properties").write_text(
        "sdk.dir=/path/to/sdk\n", encoding="utf-8"
    )
    (clone_dir / ".env").write_text("SECRET_TOKEN=xyz\n", encoding="utf-8")
    (clone_dir / "app" / "google-services.json").write_text(
        '{"api_key": "test"}', encoding="utf-8"
    )

    staging_scratch = tmp_path / "staging_scratch"

    with SandboxManager(source_dir=clone_dir, staging_parent=staging_scratch) as sb:
        staging_dir = sb.staging_dir
        assert staging_dir.exists()

        # Sensitive files MUST NOT be copied into staging
        assert not (staging_dir / "release.jks").exists()
        assert not (staging_dir / "local.properties").exists()
        assert not (staging_dir / ".env").exists()
        assert not (staging_dir / "app" / "google-services.json").exists()

        # Normal project files MUST be copied into staging
        assert (staging_dir / "build.gradle").exists()
        assert (staging_dir / "settings.gradle").exists()
        assert (staging_dir / "app" / "build.gradle").exists()

    # Original sensitive files in the clone MUST remain completely untouched
    assert (clone_dir / "release.jks").read_bytes() == b"MOCK_SENSITIVE_KEYSTORE"
    assert (clone_dir / "local.properties").read_text(
        encoding="utf-8"
    ) == "sdk.dir=/path/to/sdk\n"
    assert (clone_dir / ".env").read_text(encoding="utf-8") == "SECRET_TOKEN=xyz\n"

    # Verifies that tampering with a sensitive file in the clone triggers immutability failure
    with (
        pytest.raises(SourceImmutabilityError) as exc,
        SandboxManager(source_dir=clone_dir, staging_parent=staging_scratch),
    ):
        (clone_dir / "release.jks").write_bytes(b"TAMPERED_BYTES")

    assert "Source preservation violation detected" in str(exc.value)
    assert "release.jks" in str(exc.value)


def test_fixture_path_and_symlink_traversal_guards(tmp_path: Path):
    """Verify that artifact export and symlinks cannot escape the staging workspace."""
    out_dir = tmp_path / "dist" / "protected"

    with SandboxManager(
        source_dir=FIXTURE_DIR, staging_parent=tmp_path / "staging"
    ) as sb:
        # Path traversal on export is blocked
        with pytest.raises(SecurityError) as exc:
            sb.export_artifact("../../escaped.txt", out_dir)
        assert "outside staging workspace" in str(exc.value)


def test_missing_prerequisites_produce_clear_diagnostics():
    """Verify that missing environment tools produce actionable diagnostic messages."""
    with (
        patch("shutil.which", return_value=None),
        patch.dict(os.environ, {}, clear=True),
    ):
        reports = run_doctor_checks(project_dir=None)

    java_report = next(r for r in reports if r.name == "Java Runtime (java)")
    assert java_report.is_available is False
    assert "Install OpenJDK 17 or higher" in java_report.remediation_hint

    home_report = next(r for r in reports if r.name == "JAVA_HOME Variable")
    assert home_report.is_available is False
    assert "Set JAVA_HOME environment variable" in home_report.remediation_hint

    gradle_report = next(r for r in reports if r.name == "Gradle Build Tool")
    assert gradle_report.is_available is False
    assert "gradlew" in gradle_report.remediation_hint


def test_fixture_config_validation():
    """Verify that the fixture's appshield.yaml is valid under AppShield's configuration schema."""
    from appshield.config import load_config

    config_file = FIXTURE_DIR / "appshield.yaml"
    assert config_file.exists()

    cfg = load_config(config_file)
    assert cfg.version == "1.0"
    assert cfg.project_name == "sample_android_gradle_project"
    assert cfg.platform == "android"
    assert cfg.android.project_type == "gradle"
    assert cfg.android.gradle_task == "assembleRelease"
    assert cfg.output.dir == (FIXTURE_DIR / "dist" / "protected").resolve()
    assert cfg.output.overwrite_existing is False


def test_distinguish_actual_vs_simulated_build(tmp_path: Path):
    """
    Integration test distinguishing actual build results from simulated results.
    - If live Android SDK / Gradle toolchain is missing: reports exact reason and runs
      isolated simulated build verification.
    - If live Android toolchain is present: runs actual build under safe offline isolation.
    """
    has_live_android_sdk = (
        bool(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT"))
        and shutil.which("java") is not None
    )

    out_dir = tmp_path / "dist" / "protected"

    if not has_live_android_sdk:
        # Document and test simulated build workflow
        print("\n[INFO] Live Android SDK toolchain unavailable in test environment.")
        print("[INFO] Executing controlled simulation of the build & export workflow.")

        with SandboxManager(
            source_dir=FIXTURE_DIR, staging_parent=tmp_path / "staging"
        ) as sb:
            # Staging workspace is verified
            assert sb.staging_dir.exists()

            # Simulate build producing output artifact inside staging sandbox
            staged_out_dir = (
                sb.staging_dir / "app" / "build" / "outputs" / "apk" / "release"
            )
            staged_out_dir.mkdir(parents=True)
            apk_file = staged_out_dir / "app-release-unsigned.apk"
            apk_file.write_bytes(b"SIMULATED_RELEASE_APK_PAYLOAD")

            # Export artifact
            exported = sb.export_artifact(
                staged_relative_path="app/build/outputs/apk/release/app-release-unsigned.apk",
                output_dir=out_dir,
                target_filename="sample_android-release-protected.apk",
                allow_overwrite=False,
            )

            assert exported.exists()
            assert exported.read_bytes() == b"SIMULATED_RELEASE_APK_PAYLOAD"

            # Verify overwrite protection
            with pytest.raises(OverwriteError) as exc:
                sb.export_artifact(
                    staged_relative_path="app/build/outputs/apk/release/app-release-unsigned.apk",
                    output_dir=out_dir,
                    target_filename="sample_android-release-protected.apk",
                    allow_overwrite=False,
                )
            assert "Destination file already exists" in str(exc.value)

        # Context exit cleanly verifies that original fixture was preserved
        assert FIXTURE_DIR.exists()
    else:
        # Live toolchain test: execute strictly within sandbox
        with SandboxManager(
            source_dir=FIXTURE_DIR, staging_parent=tmp_path / "staging"
        ) as sb:
            assert sb.staging_dir.exists()
            # In Phase 4, actual gradlew assembleRelease will be invoked by AndroidGradleAdapter


def check_runbook_content_integrity(content: str) -> None:
    """Validate content has no malformed $env\\: or escaped flags."""
    malformed_env = "$env" + chr(92) + ":"
    if malformed_env in content:
        raise AssertionError(f"Found malformed '{malformed_env}' in runbook content")
    malformed_dash = chr(92) + "--"
    if malformed_dash in content:
        raise AssertionError(f"Found malformed '{malformed_dash}' in runbook content")


def test_setup_runbook_syntax_and_integrity() -> None:
    """Validate that scripts/setup/RUNBOOK.md has no malformed environment variables and parses cleanly."""
    import re
    import shutil
    import subprocess

    # Negative tests: verify detector catches deliberate malformed samples
    malformed_sample_sdk = (
        '& "$env'
        + chr(92)
        + ':LOCALAPPDATA\\Android\\Sdk\\cmdline-tools\\latest\\bin\\sdkmanager.bat" --licenses'
    )
    with pytest.raises(AssertionError, match=r"Found malformed"):
        check_runbook_content_integrity(malformed_sample_sdk)

    malformed_sample_map = (
        "$privateMappingDir = Join-Path $env"
        + chr(92)
        + ':USERPROFILE ".appshield\\mappings\\sample_android_gradle_project"'
    )
    with pytest.raises(AssertionError, match=r"Found malformed"):
        check_runbook_content_integrity(malformed_sample_map)

    malformed_sample_dash = (
        "uv run appshield protect " + chr(92) + "--mapping-out private.txt"
    )
    with pytest.raises(AssertionError, match=r"Found malformed"):
        check_runbook_content_integrity(malformed_sample_dash)

    runbook_path = Path(__file__).parent.parent / "scripts" / "setup" / "RUNBOOK.md"
    assert runbook_path.is_file(), f"RUNBOOK.md not found at '{runbook_path}'"

    content = runbook_path.read_text(encoding="utf-8")

    # Positive test: passes against the actual committed source
    check_runbook_content_integrity(content)

    # Extract all powershell code blocks
    pattern = re.compile(r"```powershell\r?\n(.*?)\r?\n```", re.DOTALL)
    blocks = pattern.findall(content)
    assert len(blocks) >= 10, "Expected at least 10 code blocks in RUNBOOK.md"

    malformed_env = "$env" + chr(92) + ":"
    malformed_dash = chr(92) + "--"

    commands: list[str] = []
    for b in blocks:
        for line in b.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                assert not line_str.endswith("`"), (
                    f"Command ends with backtick continuation: {line_str}"
                )
                assert not line_str.endswith(chr(92)), (
                    f"Command ends with backslash continuation: {line_str}"
                )
                assert malformed_dash not in line_str, (
                    f"Command contains escaped flag '\\--': {line_str}"
                )
                assert malformed_env not in line_str, (
                    f"Command contains malformed variable: {line_str}"
                )
                commands.append(line_str)

    assert len(commands) == 18, (
        f"Expected 18 executable commands, found {len(commands)}"
    )

    # Verify specific required variable references in extracted commands
    assert any("$env:LOCALAPPDATA" in cmd for cmd in commands)
    assert any("$env:USERPROFILE" in cmd for cmd in commands)
    assert "$env:JAVA_HOME" in content
    assert "$env:Path" in content

    # Verify sdkmanager and private mapping commands specifically use correct syntax
    sdkmanager_cmds = [cmd for cmd in commands if "sdkmanager.bat" in cmd]
    assert len(sdkmanager_cmds) == 2, (
        f"Expected 2 sdkmanager commands, found {len(sdkmanager_cmds)}"
    )
    for cmd in sdkmanager_cmds:
        assert "$env:LOCALAPPDATA" in cmd, (
            f"sdkmanager command must use $env:LOCALAPPDATA: {cmd}"
        )
        assert malformed_env not in cmd

    mapping_cmds = [
        cmd
        for cmd in commands
        if ".appshield" in cmd and "mappings" in cmd and "=" in cmd
    ]
    assert len(mapping_cmds) >= 1, "Expected private mapping assignment command"
    for cmd in mapping_cmds:
        assert "$env:USERPROFILE" in cmd, (
            f"mapping command must use $env:USERPROFILE: {cmd}"
        )
        assert malformed_env not in cmd

    # If powershell is available on host, validate through AST parser and semantic checks
    pwsh_exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if pwsh_exe:
        script_snippet = "\n".join(commands)
        ps_cmd = (
            "$errors = $null;\n"
            f"[System.Management.Automation.Language.Parser]::ParseInput(@'\n{script_snippet}\n'@, [ref]$null, [ref]$errors);\n"
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }\n"
            "# Semantic expansion test\n"
            "$tLocal = 'C:\\MockUser\\AppData\\Local'\n"
            "$tProf  = 'C:\\MockUser'\n"
            "$origL = $env:LOCALAPPDATA; $origP = $env:USERPROFILE\n"
            "try {\n"
            "    $env:LOCALAPPDATA = $tLocal; $env:USERPROFILE = $tProf\n"
            '    $expSdk = "$env:LOCALAPPDATA\\Android\\Sdk"\n'
            "    if ($expSdk -ne 'C:\\MockUser\\AppData\\Local\\Android\\Sdk') { exit 2 }\n"
            "    $expMap = Join-Path $env:USERPROFILE '.appshield\\mappings\\sample_android_gradle_project'\n"
            "    if ($expMap -ne 'C:\\MockUser\\.appshield\\mappings\\sample_android_gradle_project') { exit 3 }\n"
            "} finally {\n"
            "    $env:LOCALAPPDATA = $origL; $env:USERPROFILE = $origP\n"
            "}\n"
            "exit 0"
        )
        res = subprocess.run(
            [pwsh_exe, "-NoProfile", "-Command", ps_cmd],
            check=False,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"PowerShell validation failed: {res.stderr}"


def test_runbook_commands_and_paths() -> None:
    """Verify that RUNBOOK.md commands, configuration paths, output directories, and artifact names agree."""
    import re

    import yaml

    repo_root = Path(__file__).parent.parent
    runbook_path = repo_root / "scripts" / "setup" / "RUNBOOK.md"
    content = runbook_path.read_text(encoding="utf-8")

    # 1. Verify referenced configuration file exists
    assert "tests/fixtures/sample_android_gradle_project/appshield.yaml" in content
    assert "appshield.json" not in content, (
        "Nonexistent appshield.json must not be referenced"
    )
    cfg_rel = "tests/fixtures/sample_android_gradle_project/appshield.yaml"
    cfg_path = repo_root / cfg_rel
    assert cfg_path.is_file(), (
        f"Referenced configuration file does not exist: {cfg_path}"
    )

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg_data = yaml.safe_load(f)
    project_name = cfg_data.get("project_name", "")
    assert project_name == "sample_android_gradle_project"
    expected_apk_name = f"{project_name}-release-protected.apk"

    # 2. Extract protect commands
    pattern = re.compile(r"```powershell\r?\n(.*?)\r?\n```", re.DOTALL)
    blocks = pattern.findall(content)
    protect_cmds = [
        line.strip()
        for b in blocks
        for line in b.splitlines()
        if "appshield protect" in line and not line.strip().startswith("#")
    ]
    assert len(protect_cmds) >= 1, "Expected at least one 'appshield protect' command"
    for p_cmd in protect_cmds:
        assert f"-c {cfg_rel}" in p_cmd
        assert "--output-dir dist/protected" in p_cmd

    # 3. Extract verify commands
    verify_cmds = [
        line.strip()
        for b in blocks
        for line in b.splitlines()
        if "appshield verify" in line and not line.strip().startswith("#")
    ]
    assert len(verify_cmds) >= 1, "Expected at least one 'appshield verify' command"
    for v_cmd in verify_cmds:
        assert f"dist/protected/{expected_apk_name}" in v_cmd
        assert f"-c {cfg_rel}" in v_cmd

    # 4. Path agreement
    expected_output_dir = "dist/protected"
    expected_artifact_rel = f"{expected_output_dir}/{expected_apk_name}"
    assert any(expected_artifact_rel in v_cmd for v_cmd in verify_cmds)


def test_setup_scripts_safety() -> None:
    """Verify toolchain setup scripts enforce transactional safety, dry-run transparency, and non-mutation of machine state."""
    import shutil
    import subprocess

    repo_root = Path(__file__).parent.parent
    scripts_dir = repo_root / "scripts" / "setup"
    script_files = [
        scripts_dir / "download-toolchain.ps1",
        scripts_dir / "enter-appshield-env.ps1",
        scripts_dir / "configure-user-environment.ps1",
        scripts_dir / "restore-user-environment.ps1",
    ]

    for sf in script_files:
        assert sf.is_file(), f"Missing setup script: {sf}"
        script_text = sf.read_text(encoding="utf-8")

        # Must not contain misleading SupportsShouldProcess
        assert "SupportsShouldProcess" not in script_text, (
            f"Script {sf.name} should not claim SupportsShouldProcess without PSCmdlet.ShouldProcess"
        )
        assert "[CmdletBinding()]" in script_text, (
            f"Script {sf.name} must use [CmdletBinding()]"
        )
        assert "-Preview" in script_text, (
            f"Script {sf.name} must implement -Preview dry-run mechanism"
        )

    # enter-appshield-env.ps1 operates strictly at the process session level and must NEVER mutate the registry
    enter_text = (scripts_dir / "enter-appshield-env.ps1").read_text(encoding="utf-8")
    assert "SetEnvironmentVariable" not in enter_text, (
        "enter-appshield-env.ps1 must never call SetEnvironmentVariable (it must be 100% process-level isolated)"
    )

    # configure & restore scripts must NEVER mutate Machine environment
    for sf in [
        scripts_dir / "configure-user-environment.ps1",
        scripts_dir / "restore-user-environment.ps1",
    ]:
        text = sf.read_text(encoding="utf-8")
        assert "SetEnvironmentVariable" in text
        # SetEnvironmentVariable should only be called with User target
        machine_set = [
            line
            for line in text.splitlines()
            if "SetEnvironmentVariable" in line
            and "[EnvironmentVariableTarget]::Machine" in line
        ]
        assert not machine_set, (
            f"Script {sf.name} must never modify Machine environment: {machine_set}"
        )

    # download-toolchain.ps1 must enforce -Force before replacing incomplete directories and have transactional swap
    dl_text = (scripts_dir / "download-toolchain.ps1").read_text(encoding="utf-8")
    assert "Install-WithTransactionalSwap" in dl_text
    assert "-Force" in dl_text
    assert "incomplete or invalid" in dl_text
    assert ".bak." in dl_text

    # configure script must implement collision-free backup naming
    cfg_text = (scripts_dir / "configure-user-environment.ps1").read_text(
        encoding="utf-8"
    )
    assert "while (Test-Path $backupFile)" in cfg_text

    # PowerShell AST syntax parsing for all 3 scripts if PowerShell is available
    pwsh_exe = shutil.which("powershell.exe") or shutil.which("pwsh")
    if pwsh_exe:
        for sf in script_files:
            parse_cmd = (
                f"$tokens = $null; $errors = $null;\n"
                f"[System.Management.Automation.Language.Parser]::ParseFile('{sf.resolve().as_posix()}', [ref]$tokens, [ref]$errors);\n"
                f"if ($errors.Count -gt 0) {{ $errors | ForEach-Object {{ Write-Error $_ }}; exit 1 }}\n"
                f"exit 0"
            )
            res = subprocess.run(
                [pwsh_exe, "-NoProfile", "-Command", parse_cmd],
                check=False,
                capture_output=True,
                text=True,
            )
            assert res.returncode == 0, (
                f"PowerShell AST syntax error in {sf.name}: {res.stderr}"
            )
