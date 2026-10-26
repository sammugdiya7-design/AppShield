"""
Unit tests for AppShield SandboxManager and Workspace Isolation.
Verifies source immutability, sensitive file exclusion, staging lifecycle,
atomic cleanup, overwrite protection, path traversal defenses, and symlink safety.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from appshield.config import (
    AppShieldConfig,
    InputConfig,
    OutputConfig,
    OverwriteError,
)
from appshield.sandbox import (
    SandboxContext,
    SandboxError,
    SandboxManager,
    SecurityError,
    SourceImmutabilityError,
    StagingError,
    compute_file_sha256,
    compute_source_manifest,
    is_path_excluded,
    safe_remove_tree,
)


@pytest.fixture
def sample_source_project(tmp_path: Path) -> Path:
    """Create a realistic disposable source project with regular and sensitive files."""
    src = tmp_path / "my_project"
    src.mkdir()

    # Normal application files
    (src / "build.gradle").write_text("// top-level build", encoding="utf-8")
    (src / "settings.gradle").write_text("// settings", encoding="utf-8")
    (src / "gradlew").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    app_dir = src / "app"
    app_dir.mkdir()
    (app_dir / "build.gradle").write_text("// app build", encoding="utf-8")

    src_java = app_dir / "src" / "main" / "java" / "com" / "example"
    src_java.mkdir(parents=True)
    (src_java / "MainActivity.java").write_text(
        "package com.example;\npublic class MainActivity {}", encoding="utf-8"
    )

    # Sensitive files and directories that MUST be excluded
    git_dir = src / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text(
        "[core]\nrepositoryformatversion = 0\n", encoding="utf-8"
    )
    (git_dir / "HEAD").write_text("ref: refs/heads/master\n", encoding="utf-8")

    gradle_cache = src / ".gradle" / "caches"
    gradle_cache.mkdir(parents=True)
    (gradle_cache / "cache.bin").write_bytes(b"\x00\x01\x02")

    build_dir = app_dir / "build" / "intermediates"
    build_dir.mkdir(parents=True)
    (build_dir / "classes.dex").write_bytes(b"dex\n035\x00")

    (src / "local.properties").write_text("sdk.dir=/path/to/sdk\n", encoding="utf-8")
    (src / "release.jks").write_bytes(b"FAKE_KEYSTORE_BYTES")
    (app_dir / "debug.keystore").write_bytes(b"FAKE_DEBUG_KEYSTORE_BYTES")
    (src / ".env").write_text("API_SECRET=supersecret\n", encoding="utf-8")
    (src / ".env.local").write_text("LOCAL_SECRET=12345\n", encoding="utf-8")
    (app_dir / "google-services.json").write_text(
        '{"project_id": "test"}', encoding="utf-8"
    )

    return src


def test_is_path_excluded():
    """Test pattern exclusion matcher on various paths and patterns."""
    patterns = [
        ".git/**",
        ".git",
        "build/**",
        "**/build/**",
        ".gradle/**",
        "**/*.jks",
        "**/*.keystore",
        "local.properties",
        "**/*.env*",
        "**/google-services.json",
    ]

    assert is_path_excluded(Path(".git/config"), patterns) is True
    assert is_path_excluded(Path(".git"), patterns) is True
    assert is_path_excluded(Path(".gradle/caches/file"), patterns) is True
    assert is_path_excluded(Path("build/output.apk"), patterns) is True
    assert is_path_excluded(Path("app/build/out.dex"), patterns) is True
    assert is_path_excluded(Path("secret.jks"), patterns) is True
    assert is_path_excluded(Path("app/keys/prod.jks"), patterns) is True
    assert is_path_excluded(Path("debug.keystore"), patterns) is True
    assert is_path_excluded(Path("local.properties"), patterns) is True
    assert is_path_excluded(Path("sub/local.properties"), patterns) is True
    assert is_path_excluded(Path(".env"), patterns) is True
    assert is_path_excluded(Path(".env.local"), patterns) is True
    assert is_path_excluded(Path("config/.env.prod"), patterns) is True
    assert is_path_excluded(Path("google-services.json"), patterns) is True
    assert is_path_excluded(Path("app/google-services.json"), patterns) is True

    # Legitimate non-excluded files
    assert is_path_excluded(Path("build.gradle"), patterns) is False
    assert is_path_excluded(Path("settings.gradle"), patterns) is False
    assert (
        is_path_excluded(Path("app/src/main/java/MainActivity.java"), patterns) is False
    )
    assert is_path_excluded(Path("gradlew"), patterns) is False


def test_compute_file_sha256(tmp_path: Path):
    """Test SHA-256 calculation for a file."""
    f = tmp_path / "hello.txt"
    f.write_text("hello world", encoding="utf-8")
    expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert compute_file_sha256(f) == expected_hash


def test_source_manifest_comparison(tmp_path: Path):
    """Test SourceManifest comparison logic for identical, modified, added, and deleted files."""
    f1 = tmp_path / "file1.txt"
    f1.write_text("content1", encoding="utf-8")

    manifest1 = compute_source_manifest(tmp_path)
    is_same, diffs = manifest1.compare(manifest1)
    assert is_same is True
    assert diffs == []

    # Modification
    f1.write_text("modified content", encoding="utf-8")
    manifest_mod = compute_source_manifest(tmp_path)
    is_same, diffs = manifest1.compare(manifest_mod)
    assert is_same is False
    assert any("Modified file: 'file1.txt'" in d for d in diffs)

    # Addition
    f2 = tmp_path / "file2.txt"
    f2.write_text("content2", encoding="utf-8")
    manifest_add = compute_source_manifest(tmp_path)
    is_same, diffs = manifest1.compare(manifest_add)
    assert is_same is False
    assert any("New file created" in d for d in diffs)

    # Deletion
    f1.unlink()
    f2.unlink()
    manifest_del = compute_source_manifest(tmp_path)
    is_same, diffs = manifest1.compare(manifest_del)
    assert is_same is False
    assert any("Deleted file: 'file1.txt'" in d for d in diffs)


def test_sandbox_staging_excludes_sensitive_files(
    sample_source_project: Path, tmp_path: Path
):
    """Verify that staging copies normal files and strictly excludes sensitive files."""
    staging_base = tmp_path / "staging_scratch"

    with SandboxManager(
        source_dir=sample_source_project,
        staging_parent=staging_base,
        cleanup_on_exit=False,
    ) as sb:
        staging_dir = sb.staging_dir
        assert staging_dir.exists()
        assert staging_dir.is_dir()

        # Legitimate source files MUST be present in staging
        assert (staging_dir / "build.gradle").exists()
        assert (staging_dir / "settings.gradle").exists()
        assert (staging_dir / "gradlew").exists()
        assert (staging_dir / "app" / "build.gradle").exists()
        assert (
            staging_dir
            / "app"
            / "src"
            / "main"
            / "java"
            / "com"
            / "example"
            / "MainActivity.java"
        ).exists()

        # Sensitive files MUST NOT be present in staging
        assert not (staging_dir / ".git").exists()
        assert not (staging_dir / ".gradle").exists()
        assert not (staging_dir / "app" / "build").exists()
        assert not (staging_dir / "release.jks").exists()
        assert not (staging_dir / "app" / "debug.keystore").exists()
        assert not (staging_dir / "local.properties").exists()
        assert not (staging_dir / ".env").exists()
        assert not (staging_dir / ".env.local").exists()
        assert not (staging_dir / "app" / "google-services.json").exists()

    # Manual cleanup because cleanup_on_exit=False
    sb.cleanup()
    assert not staging_dir.exists()


def test_sandbox_source_immutability_passes_when_unmodified(
    sample_source_project: Path,
):
    """When source directory is completely untouched, immutability check passes without error."""
    with SandboxManager(source_dir=sample_source_project) as sb:
        # Operations inside staging sandbox
        scratch_file = sb.staging_dir / "staged_artifact.txt"
        scratch_file.write_text("generated inside sandbox", encoding="utf-8")
        assert scratch_file.exists()

    # Exiting context manager verifies source preservation cleanly
    assert sample_source_project.exists()


def test_sandbox_source_immutability_detects_file_modification(
    sample_source_project: Path,
):
    """When a source file is modified in place, SourceImmutabilityError is raised."""
    with (
        pytest.raises(SourceImmutabilityError) as exc,
        SandboxManager(source_dir=sample_source_project),
    ):
        # Deliberately violate source immutability
        src_file = sample_source_project / "build.gradle"
        src_file.write_text("// corrupted source in place!", encoding="utf-8")

    assert "Source preservation violation detected" in str(exc.value)
    assert "build.gradle" in str(exc.value)


def test_sandbox_source_immutability_detects_new_file_in_source(
    sample_source_project: Path,
):
    """When a new file is added to source directory, SourceImmutabilityError is raised."""
    with (
        pytest.raises(SourceImmutabilityError) as exc,
        SandboxManager(source_dir=sample_source_project),
    ):
        # Deliberately pollute original source tree
        polluted = sample_source_project / "unintended_artifact.bin"
        polluted.write_bytes(b"leak")

    assert "Source preservation violation detected" in str(exc.value)
    assert "unintended_artifact.bin" in str(exc.value)


def test_sandbox_source_immutability_detects_deleted_file(
    sample_source_project: Path,
):
    """When a source file is deleted, SourceImmutabilityError is raised."""
    with (
        pytest.raises(SourceImmutabilityError) as exc,
        SandboxManager(source_dir=sample_source_project),
    ):
        # Deliberately delete file from source tree
        src_file = sample_source_project / "settings.gradle"
        src_file.unlink()

    assert "Source preservation violation detected" in str(exc.value)
    assert "settings.gradle" in str(exc.value)


def test_sandbox_atomic_cleanup_on_staging_failure(tmp_path: Path):
    """If staging fails midway, the staging directory is completely wiped."""
    src = tmp_path / "valid_src"
    src.mkdir()
    (src / "file.txt").write_text("ok", encoding="utf-8")

    staging_parent = tmp_path / "staging_scratch"
    sb = SandboxManager(source_dir=src, staging_parent=staging_parent)

    with (
        patch("shutil.copy2", side_effect=OSError("Disk full or I/O failure")),
        pytest.raises(StagingError) as exc,
    ):
        sb.stage()

    assert "Staging failed" in str(exc.value)
    # Staging directory must be cleaned up
    assert not sb.staging_dir.exists()


def test_sandbox_staging_nonexistent_source(tmp_path: Path):
    """Staging a nonexistent source directory raises StagingError."""
    sb = SandboxManager(source_dir=tmp_path / "does_not_exist")
    with pytest.raises(StagingError) as exc:
        sb.stage()
    assert "Source directory does not exist" in str(exc.value)


def test_sandbox_staging_source_is_file(tmp_path: Path):
    """Staging when source path is a file raises StagingError."""
    f = tmp_path / "not_a_dir.txt"
    f.write_text("file", encoding="utf-8")
    sb = SandboxManager(source_dir=f)
    with pytest.raises(StagingError) as exc:
        sb.stage()
    assert "Source path is not a directory" in str(exc.value)


def test_sandbox_staging_directory_identical_to_source(
    sample_source_project: Path,
):
    """Staging directory cannot be identical to source directory."""
    sb = SandboxManager(source_dir=sample_source_project)
    # Force staging_dir to equal source_dir
    sb.staging_dir = sample_source_project
    with pytest.raises(SecurityError) as exc:
        sb.stage()
    assert "Staging directory cannot be identical to the source directory" in str(
        exc.value
    )


def test_safe_remove_tree_guards(tmp_path: Path):
    """Test safety guards in safe_remove_tree preventing deletion of parent or external paths."""
    parent = tmp_path / "parent_dir"
    parent.mkdir()
    child = parent / "child_staging"
    child.mkdir()
    (child / "dummy.txt").write_text("data", encoding="utf-8")

    # Safe delete of child should succeed
    safe_remove_tree(child, parent)
    assert not child.exists()

    # Refuse to delete parent when target == parent
    with pytest.raises(SecurityError) as exc:
        safe_remove_tree(parent, parent)
    assert "Target directory is identical to parent" in str(exc.value)

    # Refuse to delete outside parent
    external = tmp_path / "external_dir"
    external.mkdir()
    with pytest.raises(SecurityError) as exc:
        safe_remove_tree(external, parent)
    assert "is outside allowed parent" in str(exc.value)


def test_safe_remove_tree_windows_readonly(tmp_path: Path):
    """Test safe_remove_tree successfully cleans up read-only files on Windows."""
    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child"
    child.mkdir()

    ro_file = child / "readonly.txt"
    ro_file.write_text("readonly content", encoding="utf-8")
    # Set read-only bit
    os.chmod(ro_file, stat.S_IREAD)

    safe_remove_tree(child, parent)
    assert not child.exists()


def test_sandbox_export_artifact_success(sample_source_project: Path, tmp_path: Path):
    """Test exporting an artifact from staging to a clean output directory."""
    out_dir = tmp_path / "dist" / "protected"

    with SandboxManager(source_dir=sample_source_project) as sb:
        # Create simulated protected APK in staging
        staged_apk = sb.staging_dir / "app-release-protected.apk"
        staged_apk.write_bytes(b"PROTECTED_APK_BYTES")

        exported_path = sb.export_artifact(
            staged_relative_path="app-release-protected.apk",
            output_dir=out_dir,
            allow_overwrite=False,
        )

        assert exported_path.exists()
        assert exported_path.read_bytes() == b"PROTECTED_APK_BYTES"
        assert exported_path == (out_dir / "app-release-protected.apk").resolve()


def test_sandbox_export_artifact_overwrite_prevention(
    sample_source_project: Path, tmp_path: Path
):
    """Test that export_artifact respects overwrite guards when artifact already exists."""
    out_dir = tmp_path / "dist" / "protected"
    out_dir.mkdir(parents=True)
    existing_apk = out_dir / "app-release-protected.apk"
    existing_apk.write_bytes(b"ORIGINAL_EXISTING_APK")

    with SandboxManager(source_dir=sample_source_project) as sb:
        staged_apk = sb.staging_dir / "app-release-protected.apk"
        staged_apk.write_bytes(b"NEW_APK_CONTENT")

        # Overwrite = False must raise OverwriteError and preserve existing file
        with pytest.raises(OverwriteError) as exc:
            sb.export_artifact(
                staged_relative_path="app-release-protected.apk",
                output_dir=out_dir,
                allow_overwrite=False,
            )
        assert "Destination file already exists" in str(exc.value)
        assert existing_apk.read_bytes() == b"ORIGINAL_EXISTING_APK"

        # Overwrite = True must succeed
        exported = sb.export_artifact(
            staged_relative_path="app-release-protected.apk",
            output_dir=out_dir,
            allow_overwrite=True,
        )
        assert exported.read_bytes() == b"NEW_APK_CONTENT"


def test_sandbox_export_artifact_missing_staged_file(
    sample_source_project: Path, tmp_path: Path
):
    """Test error handling when staged artifact was not generated."""
    out_dir = tmp_path / "dist"

    with SandboxManager(source_dir=sample_source_project) as sb:
        with pytest.raises(SandboxError) as exc:
            sb.export_artifact("nonexistent.apk", out_dir)
        assert "Staged artifact not found" in str(exc.value)


def test_sandbox_export_artifact_traversal_blocked(
    sample_source_project: Path, tmp_path: Path
):
    """Test that path traversal attempts during export are blocked."""
    out_dir = tmp_path / "dist"

    with SandboxManager(source_dir=sample_source_project) as sb:
        with pytest.raises(SecurityError) as exc:
            sb.export_artifact("../../escaped.txt", out_dir)
        assert "outside staging workspace" in str(exc.value)


def test_symlink_outside_source_tree_blocked(
    sample_source_project: Path, tmp_path: Path
):
    """
    Test that symlinks pointing outside the source tree raise SecurityError.
    Handles Windows privilege constraints cleanly without global Path patching.
    """
    external_secret = tmp_path / "external_secret.txt"
    external_secret.write_text("SECRET", encoding="utf-8")

    link_path = sample_source_project / "evil_link.txt"

    can_create_symlink = False
    try:
        link_path.symlink_to(external_secret)
        can_create_symlink = True
    except OSError:
        pass

    if can_create_symlink:
        try:
            with (
                pytest.raises(SecurityError) as exc,
                SandboxManager(source_dir=sample_source_project),
            ):
                pass
            assert "points outside source tree" in str(exc.value)
        finally:
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()
    else:
        # On Windows without elevated symlink privileges, verify check_symlink_safety
        from appshield.sandbox import check_symlink_safety

        class MockSymlinkPath:
            def is_symlink(self) -> bool:
                return True

            def resolve(self) -> Path:
                return external_secret.resolve()

            def __str__(self) -> str:
                return "evil_link.txt"

        with pytest.raises(SecurityError) as exc:
            check_symlink_safety(MockSymlinkPath(), sample_source_project)  # type: ignore[arg-type]
        assert "points outside source tree" in str(exc.value)


def test_check_symlink_safety_safe_internal_link(sample_source_project: Path):
    """Test check_symlink_safety permits internal symlinks."""
    internal_target = sample_source_project / "build.gradle"
    from appshield.sandbox import check_symlink_safety

    class MockInternalSymlink:
        def is_symlink(self) -> bool:
            return True

        def resolve(self) -> Path:
            return internal_target.resolve()

        def __str__(self) -> str:
            return "internal_link.txt"

    # Internal symlink should not raise any error
    check_symlink_safety(MockInternalSymlink(), sample_source_project)  # type: ignore[arg-type]


def test_check_symlink_safety_resolution_error(sample_source_project: Path):
    """Test check_symlink_safety wraps OSError as SecurityError."""
    from appshield.sandbox import check_symlink_safety

    class MockBrokenSymlink:
        def is_symlink(self) -> bool:
            return True

        def resolve(self) -> Path:
            raise OSError("Corrupted symlink target")

        def __str__(self) -> str:
            return "broken_link.txt"

    with pytest.raises(SecurityError) as exc:
        check_symlink_safety(MockBrokenSymlink(), sample_source_project)  # type: ignore[arg-type]
    assert "Failed to resolve symlink" in str(exc.value)


def test_sandbox_context_alias():
    """Verify SandboxContext alias exists and is identical to SandboxManager."""
    assert SandboxContext is SandboxManager


def test_sandbox_from_config(sample_source_project: Path, tmp_path: Path):
    """Test SandboxManager.from_config factory method."""
    cfg = AppShieldConfig(
        version="1.0",
        project_name="test_proj",
        platform="android",
        input=InputConfig(
            project_dir=sample_source_project,
            verify_source_immutability=True,
            exclude_patterns=[".git/**", "build/**"],
        ),
        output=OutputConfig(dir=tmp_path / "dist"),
    )

    sb = SandboxManager.from_config(cfg)
    assert sb.source_dir == sample_source_project.resolve()
    assert sb.exclude_patterns == [".git/**", "build/**"]
    assert sb.verify_source_immutability is True
