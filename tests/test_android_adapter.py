"""
Unit tests for AndroidPipelineAdapter (Plan 04-01).
Tests project detection, release build inspection, R8 rule staging,
source preservation, error handling, and toolchain checks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from appshield.adapters.android import (
    FORBIDDEN_TEST_KEEP_PATTERNS,
    AndroidPipelineAdapter,
    extract_block,
    extract_release_block,
)
from appshield.adapters.base import (
    PrerequisiteCheck,
    ProjectInspection,
    RuleStagingError,
)
from appshield.config import AppShieldConfig, InputConfig, OutputConfig
from appshield.sandbox import SandboxManager, compute_file_sha256

FIXTURE_DIR = Path("tests/fixtures/sample_android_gradle_project").resolve()


def create_minimal_android_project(
    base_dir: Path,
    minify_enabled: bool = True,
    shrink_resources: bool = False,
    include_rules_file: bool = True,
    rules_file_exists: bool = True,
    app_module_name: str = "app",
    custom_release_content: str | None = None,
    is_kotlin_dsl: bool = False,
) -> Path:
    """Helper to scaffold minimal Android Gradle test projects in temporary directories."""
    proj = base_dir / "test_android_project"
    proj.mkdir(parents=True, exist_ok=True)

    # 1. Gradle wrapper scripts
    (proj / "gradlew").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (proj / "gradlew.bat").write_text("@echo off\nexit /b 0\n", encoding="utf-8")

    # 2. Settings file
    (proj / "settings.gradle").write_text(
        f"rootProject.name = 'test_proj'\ninclude ':{app_module_name}'\n",
        encoding="utf-8",
    )

    # 3. Root build.gradle
    (proj / "build.gradle").write_text(
        "plugins {\n    id 'com.android.application' version '8.2.2' apply false\n}\n",
        encoding="utf-8",
    )

    # 4. App module
    mod_dir = proj / app_module_name
    mod_dir.mkdir(parents=True, exist_ok=True)

    build_ext = "gradle.kts" if is_kotlin_dsl else "gradle"
    build_file = mod_dir / f"build.{build_ext}"

    if custom_release_content is not None:
        release_body = custom_release_content
    elif is_kotlin_dsl:
        rules_ref = (
            'proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")'
            if include_rules_file
            else ""
        )
        release_body = f"""
        release {{
            isMinifyEnabled = {str(minify_enabled).lower()}
            isShrinkResources = {str(shrink_resources).lower()}
            {rules_ref}
        }}
        """
    else:
        rules_ref = (
            "proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'"
            if include_rules_file
            else ""
        )
        release_body = f"""
        release {{
            minifyEnabled {str(minify_enabled).lower()}
            shrinkResources {str(shrink_resources).lower()}
            {rules_ref}
        }}
        """

    build_content = f"""
plugins {{
    id 'com.android.application'
}}

android {{
    namespace 'com.example.test'
    compileSdk 34

    defaultConfig {{
        applicationId "com.example.test"
        minSdk 24
        targetSdk 34
    }}

    buildTypes {{
        {release_body}
    }}
}}
"""
    build_file.write_text(build_content, encoding="utf-8")

    if include_rules_file and rules_file_exists:
        (mod_dir / "proguard-rules.pro").write_text(
            "# Base rules\n-keep class com.example.test.MainActivity { *; }\n",
            encoding="utf-8",
        )

    return proj


def test_adapter_platform_name():
    """Verify adapter platform identifier is 'android'."""
    adapter = AndroidPipelineAdapter()
    assert adapter.platform_name == "android"


def test_validate_sample_fixture():
    """Verify validation on the controlled sample Android Gradle fixture."""
    adapter = AndroidPipelineAdapter()
    inspection: ProjectInspection = adapter.validate_project(FIXTURE_DIR)

    assert inspection.is_supported is True
    assert inspection.platform == "android"
    assert inspection.project_type == "gradle"
    assert inspection.module_name == "app"
    assert inspection.build_file == FIXTURE_DIR / "app" / "build.gradle"
    assert inspection.rules_file == FIXTURE_DIR / "app" / "proguard-rules.pro"
    assert inspection.minify_enabled is True
    assert inspection.shrink_resources is False
    assert inspection.agp_version == "8.2.2"
    assert inspection.compile_sdk == 34
    assert inspection.target_sdk == 34
    assert inspection.errors == []


def test_reject_precompiled_apk_file(tmp_path: Path):
    """Verify arbitrary precompiled APK input is strictly rejected."""
    adapter = AndroidPipelineAdapter()

    fake_apk = tmp_path / "target_app.apk"
    fake_apk.write_bytes(b"PK\x03\x04FAKE_APK")

    inspection = adapter.validate_project(fake_apk)
    assert inspection.is_supported is False
    assert inspection.project_type == "unsupported_binary"
    assert any(
        "Arbitrary precompiled APK input is unsupported" in err
        for err in inspection.errors
    )


def test_reject_nonexistent_directory(tmp_path: Path):
    """Verify non-existent directory fails project validation."""
    adapter = AndroidPipelineAdapter()
    missing_dir = tmp_path / "does_not_exist"

    inspection = adapter.validate_project(missing_dir)
    assert inspection.is_supported is False
    assert any("does not exist" in err for err in inspection.errors)


def test_reject_file_path_as_project(tmp_path: Path):
    """Verify a text file passed as project directory is rejected."""
    adapter = AndroidPipelineAdapter()
    fake_file = tmp_path / "project.txt"
    fake_file.write_text("not a directory", encoding="utf-8")

    inspection = adapter.validate_project(fake_file)
    assert inspection.is_supported is False
    assert any("not a directory" in err for err in inspection.errors)


def test_reject_missing_gradlew(tmp_path: Path):
    """Verify missing gradlew wrapper script is detected and reported."""
    proj = create_minimal_android_project(tmp_path)
    (proj / "gradlew").unlink()
    (proj / "gradlew.bat").unlink()

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any("Missing Gradle wrapper script" in err for err in inspection.errors)


def test_reject_missing_settings_gradle(tmp_path: Path):
    """Verify missing settings.gradle is detected and reported."""
    proj = create_minimal_android_project(tmp_path)
    (proj / "settings.gradle").unlink()

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any("Missing Gradle settings file" in err for err in inspection.errors)


def test_reject_missing_application_module(tmp_path: Path):
    """Verify missing application module is detected and reported."""
    proj = create_minimal_android_project(tmp_path)
    # Remove app build file
    (proj / "app" / "build.gradle").unlink()

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any(
        "Missing Android application build file" in err for err in inspection.errors
    )


def test_reject_ambiguous_multiple_modules(tmp_path: Path):
    """Verify that multiple application modules without standard 'app' are reported as ambiguous."""
    proj = tmp_path / "ambiguous_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    (proj / "settings.gradle").write_text(
        "include ':mod_a', ':mod_b'\n", encoding="utf-8"
    )

    mod_a = proj / "mod_a"
    mod_a.mkdir()
    (mod_a / "build.gradle").write_text(
        "plugins { id 'com.android.application' }\n", encoding="utf-8"
    )

    mod_b = proj / "mod_b"
    mod_b.mkdir()
    (mod_b / "build.gradle").write_text(
        "plugins { id 'com.android.application' }\n", encoding="utf-8"
    )

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any("Ambiguous Android project layout" in err for err in inspection.errors)


def test_single_module_root_project(tmp_path: Path):
    """Verify single-module root project is supported."""
    proj = tmp_path / "root_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    (proj / "settings.gradle").write_text(
        "rootProject.name = 'root_proj'\n", encoding="utf-8"
    )
    (proj / "build.gradle").write_text(
        """
plugins { id 'com.android.application' }
android {
    compileSdk 34
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles 'proguard-rules.pro'
        }
    }
}
""",
        encoding="utf-8",
    )
    (proj / "proguard-rules.pro").write_text("# rules\n", encoding="utf-8")

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is True
    assert inspection.module_name == "root"


def test_reject_release_without_minify_enabled(tmp_path: Path):
    """Verify release buildType without minifyEnabled is rejected."""
    proj = create_minimal_android_project(tmp_path, minify_enabled=False)

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert inspection.minify_enabled is False
    assert any(
        "does not enable R8 code minification" in err for err in inspection.errors
    )


def test_reject_release_without_proguard_rules(tmp_path: Path):
    """Verify release buildType without ProGuard rules file reference is rejected."""
    proj = create_minimal_android_project(tmp_path, include_rules_file=False)

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any(
        "does not configure a ProGuard/R8 rules file" in err
        for err in inspection.errors
    )


def test_reject_release_with_nonexistent_rules_file(tmp_path: Path):
    """Verify configured rules file that does not exist on disk is rejected."""
    proj = create_minimal_android_project(
        tmp_path, include_rules_file=True, rules_file_exists=False
    )

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any("does not exist" in err for err in inspection.errors)


def test_reject_missing_release_block(tmp_path: Path):
    """Verify application build file missing 'release' buildType is rejected."""
    custom_content = """
    debug {
        minifyEnabled false
    }
    """
    proj = create_minimal_android_project(
        tmp_path, custom_release_content=custom_content
    )

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is False
    assert any("No 'release' buildType block found" in err for err in inspection.errors)


def test_kotlin_dsl_inspection(tmp_path: Path):
    """Verify inspection handles Kotlin DSL (build.gradle.kts) project syntax."""
    proj = create_minimal_android_project(
        tmp_path, is_kotlin_dsl=True, shrink_resources=True
    )

    adapter = AndroidPipelineAdapter()
    inspection = adapter.validate_project(proj)
    assert inspection.is_supported is True
    assert inspection.minify_enabled is True
    assert inspection.shrink_resources is True
    assert inspection.rules_file is not None
    assert inspection.rules_file.name == "proguard-rules.pro"


def test_kotlin_dsl_get_by_name_and_named(tmp_path: Path):
    """Verify extraction handles getByName('release') and named('release')."""
    text_get = """
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }
    """
    block = extract_release_block(text_get)
    assert block is not None
    assert "isMinifyEnabled = true" in block

    text_named = """
    buildTypes {
        named("release") {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }
    """
    block2 = extract_release_block(text_named)
    assert block2 is not None
    assert "isMinifyEnabled = true" in block2


def test_extract_block_nested():
    """Verify extract_block correctly balances nested curly braces."""
    nested = """
    outer {
        level1 {
            level2 {
                value = 1
            }
        }
        remaining = true
    }
    """
    content = extract_block(nested, "outer")
    assert content is not None
    assert "remaining = true" in content
    assert "level2" in content

    # Non-existent block
    assert extract_block(nested, "non_existent") is None


def test_stage_rules_appends_to_staged_copy(tmp_path: Path):
    """Verify stage_rules appends AppShield rules to staged copy without touching original."""
    proj = create_minimal_android_project(tmp_path)
    original_rules_file = proj / "app" / "proguard-rules.pro"
    original_hash = compute_file_sha256(original_rules_file)

    # Create staging copy
    staging_dir = tmp_path / "staging_copy"
    staging_dir.mkdir()
    # Copy project into staging
    import shutil

    shutil.copytree(proj, staging_dir / "proj")
    staged_proj = staging_dir / "proj"

    adapter = AndroidPipelineAdapter()
    staged_rules_file = adapter.stage_rules(staged_proj)

    assert staged_rules_file.is_file()
    staged_content = staged_rules_file.read_text(encoding="utf-8")

    # AppShield rules were appended
    assert "-repackageclasses ''" in staged_content
    assert "-allowaccessmodification" in staged_content
    assert "-renamesourcefileattribute SourceFile" in staged_content
    assert "-keep class com.example.test.MainActivity" in staged_content

    # Original project rules file is completely untouched
    assert compute_file_sha256(original_rules_file) == original_hash


def test_stage_rules_with_custom_rules(tmp_path: Path):
    """Verify stage_rules appends custom inline rules and custom rules file."""
    proj = create_minimal_android_project(tmp_path)
    staging_dir = tmp_path / "staged_proj"
    import shutil

    shutil.copytree(proj, staging_dir)

    custom_file = tmp_path / "custom-keep.pro"
    custom_file.write_text(
        "-keep class com.example.custom.SafeClass { *; }\n", encoding="utf-8"
    )

    custom_inline = "-keepattributes Signature\n"

    adapter = AndroidPipelineAdapter()
    staged_rules = adapter.stage_rules(
        staging_dir,
        custom_rules=custom_inline,
        custom_rules_file=custom_file,
    )

    content = staged_rules.read_text(encoding="utf-8")
    assert "-keep class com.example.custom.SafeClass" in content
    assert "-keepattributes Signature" in content
    assert "-repackageclasses ''" in content


@pytest.mark.parametrize("forbidden_symbol", FORBIDDEN_TEST_KEEP_PATTERNS)
def test_stage_rules_rejects_forbidden_test_symbols(
    tmp_path: Path, forbidden_symbol: str
):
    """Verify that custom rules keeping test symbols intended for obfuscation verification are rejected."""
    proj = create_minimal_android_project(tmp_path)
    staging_dir = tmp_path / "staged_proj"
    import shutil

    shutil.copytree(proj, staging_dir)

    adapter = AndroidPipelineAdapter()

    # Inline rule violation
    forbidden_rule = f"-keep class com.appshield.sample.{forbidden_symbol} {{ *; }}"
    with pytest.raises(RuleStagingError, match="forbidden keep directive"):
        adapter.stage_rules(staging_dir, custom_rules=forbidden_rule)

    # File rule violation
    bad_file = tmp_path / "bad.pro"
    bad_file.write_text(forbidden_rule, encoding="utf-8")
    with pytest.raises(RuleStagingError, match="forbidden keep directive"):
        adapter.stage_rules(staging_dir, custom_rules_file=bad_file)


def test_stage_rules_error_handling(tmp_path: Path):
    """Verify error handling on invalid staging directory or missing rules file."""
    adapter = AndroidPipelineAdapter()

    # Non-existent staging dir
    with pytest.raises(RuleStagingError, match="does not exist"):
        adapter.stage_rules(tmp_path / "non_existent")

    # Staging dir missing rules file
    proj = create_minimal_android_project(tmp_path, include_rules_file=False)
    with pytest.raises(RuleStagingError, match="staging project validation failed"):
        adapter.stage_rules(proj)


def test_source_preservation_with_sandbox_manager(tmp_path: Path):
    """
    Verify complete integration between AndroidPipelineAdapter and SandboxManager:
    Staging rules inside sandbox leaves the controlled sample fixture 100% bit-for-bit unchanged.
    """
    config = AppShieldConfig(
        version="1.0",
        project_name="sample_android_gradle_project",
        platform="android",
        input=InputConfig(project_dir=FIXTURE_DIR, verify_source_immutability=True),
        output=OutputConfig(dir=tmp_path / "dist"),
    )

    staging_parent = tmp_path / "staging_scratch"

    with SandboxManager(
        source_dir=config.input.project_dir, staging_parent=staging_parent
    ) as sandbox:
        assert sandbox.staging_dir.exists()

        adapter = AndroidPipelineAdapter()
        # Validate project in staging
        inspection = adapter.validate_project(sandbox.staging_dir)
        assert inspection.is_supported is True

        # Stage rules into staging copy
        staged_rules = adapter.stage_rules(sandbox.staging_dir)
        assert staged_rules.is_file()

        # Check that rules were applied in staging
        staged_text = staged_rules.read_text(encoding="utf-8")
        assert "-repackageclasses ''" in staged_text

        # Verify source immutability
        sandbox.verify_source_integrity()

    # Sandbox cleaned up
    assert not sandbox.staging_dir.exists()


import zipfile
from unittest.mock import MagicMock, patch

from appshield.config import OverwriteError
from appshield.gradle import GradleBuildResult
from appshield.signing import SigningResult


def create_dummy_apk(
    path: Path, include_manifest: bool = True, include_dex: bool = True
) -> Path:
    """Helper to create a minimal synthetic valid zip archive representing an APK."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        if include_manifest:
            zf.writestr("AndroidManifest.xml", b"<dummy-manifest/>")
        if include_dex:
            zf.writestr("classes.dex", b"<dummy-dex-bytecode/>")
        zf.writestr("resources.arsc", b"<dummy-resources/>")
    return path


def test_stage_and_protect_stops_on_missing_prerequisites(tmp_path: Path):
    """Verify stage_and_protect safely halts when required toolchain prerequisites are missing."""
    dist_dir = tmp_path / "dist"
    config = AppShieldConfig(
        version="1.0",
        project_name="sample_android_gradle_project",
        platform="android",
        input=InputConfig(project_dir=FIXTURE_DIR),
        output=OutputConfig(dir=dist_dir),
    )
    adapter = AndroidPipelineAdapter()

    # The current host environment lacks JDK 17 / Android SDK
    result = adapter.stage_and_protect(config)
    assert result.success is False
    assert result.protected_artifact_path is None
    assert (
        "missing required toolchain prerequisites"
        in (result.error_message or "").lower()
    )
    # Confirm no fake or simulated artifact was created
    assert not dist_dir.exists() or len(list(dist_dir.iterdir())) == 0


def test_stage_and_protect_mocked_end_to_end_success(tmp_path: Path):
    """Verify stage_and_protect completes full staging, build, discovery, export and source verification."""
    dist_dir = tmp_path / "dist"
    config = AppShieldConfig(
        version="1.0",
        project_name="sample_android_gradle_project",
        platform="android",
        input=InputConfig(project_dir=FIXTURE_DIR, verify_source_immutability=True),
        output=OutputConfig(dir=dist_dir),
    )
    adapter = AndroidPipelineAdapter()

    mock_runner = MagicMock()

    def fake_run(tasks: str, **kwargs: object) -> GradleBuildResult:
        # Simulate Gradle build producing release APK inside staging sandbox
        apk_path = (
            mock_runner.project_dir
            / "app"
            / "build"
            / "outputs"
            / "apk"
            / "release"
            / "app-release-unsigned.apk"
        )
        create_dummy_apk(apk_path)
        return GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="BUILD SUCCESSFUL",
            stderr="",
            duration_seconds=1.5,
            command=["gradlew", tasks],
        )

    mock_runner.run_task.side_effect = fake_run

    with patch("appshield.adapters.android.align_and_sign_apk") as mock_align_sign:

        def fake_signing(
            unsigned_apk: Path, output_dir: Path, **kwargs: object
        ) -> SigningResult:
            final_apk = output_dir / "app-release-unsigned-aligned.apk"
            create_dummy_apk(final_apk)
            return SigningResult(
                success=True,
                signature_type="unsigned",
                aligned_apk_path=final_apk,
                final_apk_path=final_apk,
                is_aligned=True,
            )

        mock_align_sign.side_effect = fake_signing

        result = adapter.stage_and_protect(config, runner=mock_runner)
        assert result.success is True
        assert result.protected_artifact_path is not None
        assert result.protected_artifact_path.is_file()
        assert (
            result.protected_artifact_path.name
            == "sample_android_gradle_project-release-protected.apk"
        )
        assert result.metadata["signature_type"] == "unsigned"
        assert result.metadata["is_aligned"] == "True"


def test_stage_and_protect_overwrite_guard(tmp_path: Path):
    """Verify stage_and_protect enforces destination overwrite protection."""
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    target_apk = dist_dir / "sample_android_gradle_project-release-protected.apk"
    target_apk.write_bytes(b"existing_content")

    config = AppShieldConfig(
        version="1.0",
        project_name="sample_android_gradle_project",
        platform="android",
        input=InputConfig(project_dir=FIXTURE_DIR),
        output=OutputConfig(dir=dist_dir, overwrite_existing=False),
    )
    adapter = AndroidPipelineAdapter()
    mock_runner = MagicMock()

    with pytest.raises(OverwriteError):
        adapter.stage_and_protect(config, runner=mock_runner)


def test_check_prerequisites_returns_prerequisite_checks():
    """Verify check_prerequisites returns list of PrerequisiteCheck dataclasses."""
    adapter = AndroidPipelineAdapter()
    checks = adapter.check_prerequisites(FIXTURE_DIR)
    assert len(checks) > 0
    assert all(isinstance(c, PrerequisiteCheck) for c in checks)

    check_names = {c.tool_name for c in checks}
    assert "Java Runtime (java)" in check_names
    assert "Android Gradle Project Structure" in check_names
    assert "Gradle Distribution Configuration" in check_names
    assert "Android Release R8 Configuration" in check_names
