"""
Unit tests for AppShield Gradle Runner and Artifact Extraction (Plan 04-02).
Tests subprocess safety, process tree termination, safe environment policies,
secret redaction, task validation, APK discovery, and error recovery.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from appshield.gradle import (
    ArtifactExtractionError,
    GradleError,
    GradleExecutionError,
    GradleRunner,
    GradleTaskValidationError,
    GradleTimeoutError,
    GradleToolchainIncompatibleError,
    GradleToolchainMissingError,
    build_safe_env,
    check_gradle_cache_dependencies,
    kill_process_tree,
    locate_build_apk,
    locate_r8_mapping,
    redact_secrets,
    resolve_gradle_executable,
    validate_apk_file,
    validate_gradle_task,
)


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


class TestSecretRedaction:
    def test_redact_secrets_explicit(self) -> None:
        text = "Building with keystore password super_secret_123 and token abc_def_xyz"
        redacted = redact_secrets(text, secrets=["super_secret_123", "abc_def_xyz"])
        assert "super_secret_123" not in redacted
        assert "abc_def_xyz" not in redacted
        assert "***REDACTED***" in redacted

    def test_redact_secrets_patterns(self) -> None:
        log_sample = (
            "./gradlew -Pandroid.injected.signing.store.password=topsecret "
            "--ks-pass pass:my_ks_password "
            "--key-pass pass:my_key_password "
            "-storepass store_pass_123 "
            "-keypass key_pass_456"
        )
        redacted = redact_secrets(log_sample)
        assert "topsecret" not in redacted
        assert "my_ks_password" not in redacted
        assert "my_key_password" not in redacted
        assert "store_pass_123" not in redacted
        assert "key_pass_456" not in redacted
        assert "***REDACTED***" in redacted

    def test_redact_empty(self) -> None:
        assert redact_secrets("") == ""
        assert redact_secrets("normal log message") == "normal log message"


class TestSafeEnvironment:
    def test_build_safe_env_preserves_required(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("JAVA_HOME", "/opt/jdk-17")
        monkeypatch.setenv("ANDROID_HOME", "/opt/android-sdk")
        safe = build_safe_env()
        assert safe["PATH"] == "/usr/bin:/bin"
        assert safe["JAVA_HOME"] == "/opt/jdk-17"
        assert safe["ANDROID_HOME"] == "/opt/android-sdk"

    def test_build_safe_env_strips_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super_secret")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_123456")
        monkeypatch.setenv("MY_APP_PASSWORD", "pass123")
        monkeypatch.setenv("PRIVATE_SIGNING_KEY", "privkey")
        safe = build_safe_env()
        assert "AWS_SECRET_ACCESS_KEY" not in safe
        assert "GITHUB_TOKEN" not in safe
        assert "MY_APP_PASSWORD" not in safe
        assert "PRIVATE_SIGNING_KEY" not in safe

    def test_build_safe_env_extra_env(self) -> None:
        extra = {"CUSTOM_VAR": "custom_val"}
        safe = build_safe_env(extra_env=extra)
        assert safe["CUSTOM_VAR"] == "custom_val"


class TestTaskValidation:
    @pytest.mark.parametrize(
        "task",
        [
            "assembleRelease",
            ":app:assembleRelease",
            "bundleRelease",
            "clean",
            "testReleaseUnitTest",
            ":core:module:assembleRelease",
        ],
    )
    def test_valid_tasks(self, task: str) -> None:
        validate_gradle_task(task)

    @pytest.mark.parametrize(
        "invalid_task",
        [
            "",
            "--stacktrace",
            "-Pmyprop=val",
            "assembleRelease; rm -rf /",
            "task & echo hello",
            "task | grep foo",
            "task$(whoami)",
            "task`id`",
        ],
    )
    def test_invalid_tasks_rejected(self, invalid_task: str) -> None:
        with pytest.raises(GradleTaskValidationError):
            validate_gradle_task(invalid_task)


class TestGradleExecutableResolution:
    def test_custom_gradle_path_exists(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom_gradle"
        custom.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        cmd, mode = resolve_gradle_executable(tmp_path, custom_gradle_path=custom)
        assert cmd == [str(custom.resolve())]
        assert mode == "custom"

    def test_custom_gradle_path_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "non_existent_gradle"
        with pytest.raises(GradleToolchainMissingError):
            resolve_gradle_executable(tmp_path, custom_gradle_path=missing)

    def test_wrapper_with_jar_present(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        cmd, mode = resolve_gradle_executable(tmp_path)
        assert cmd == [str(script.resolve())]
        assert mode == "wrapper"

    def test_wrapper_without_jar_raises_error_if_no_system_gradle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        # Wrapper jar is missing!
        monkeypatch.setattr("shutil.which", lambda x: None)

        with pytest.raises(GradleToolchainMissingError) as exc_info:
            resolve_gradle_executable(tmp_path)
        assert "Wrapper JAR" in str(exc_info.value)
        assert "Silent download is forbidden" in str(exc_info.value)

    def test_wrapper_without_jar_falls_back_to_system_gradle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        # Wrapper jar is missing, but system gradle exists
        monkeypatch.setattr(
            "shutil.which", lambda x: "/usr/bin/gradle" if x == "gradle" else None
        )

        cmd, mode = resolve_gradle_executable(tmp_path)
        assert cmd == ["/usr/bin/gradle"]
        assert mode == "system"

    def test_no_gradle_at_all_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda x: None)
        with pytest.raises(GradleToolchainMissingError) as exc_info:
            resolve_gradle_executable(tmp_path)
        assert "No Gradle build tool found" in str(exc_info.value)

    def test_wrapper_with_incompatible_declared_version_raises(
        self, tmp_path: Path
    ) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        (tmp_path / script_name).write_text("dummy", encoding="utf-8")
        wrap_dir = tmp_path / "gradle" / "wrapper"
        wrap_dir.mkdir(parents=True)
        (wrap_dir / "gradle-wrapper.jar").write_bytes(b"dummy")
        (wrap_dir / "gradle-wrapper.properties").write_text(
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-7.6-bin.zip\n",
            encoding="utf-8",
        )
        with pytest.raises(GradleToolchainIncompatibleError) as exc_info:
            resolve_gradle_executable(tmp_path)
        assert "Gradle 7.6" in str(exc_info.value)
        assert "requires Gradle 8.2 or higher" in str(exc_info.value)

    def test_system_gradle_incompatible_version_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "shutil.which", lambda x: "/usr/bin/gradle" if x == "gradle" else None
        )
        monkeypatch.setattr(
            "subprocess.check_output",
            lambda cmd, **kwargs: "Gradle 7.5\nBuild time: 2022",
        )
        with pytest.raises(GradleToolchainIncompatibleError) as exc_info:
            resolve_gradle_executable(tmp_path)
        assert "7.5" in str(exc_info.value)
        assert "8.2" in str(exc_info.value)

    def test_check_gradle_cache_dependencies_missing_and_present(
        self, tmp_path: Path
    ) -> None:
        # 1. Missing cache
        res = check_gradle_cache_dependencies(tmp_path)
        assert res["cache_dir_exists"] is False
        assert res["agp_cached"] is False
        assert res["r8_cached"] is False

        # 2. Present cache
        agp_cache = (
            tmp_path
            / "caches"
            / "modules-2"
            / "files-2.1"
            / "com.android.tools.build"
            / "gradle"
            / "8.2.2"
        )
        agp_cache.mkdir(parents=True)
        (agp_cache / "gradle-8.2.2.jar").write_bytes(b"dummy")

        r8_cache = (
            tmp_path
            / "caches"
            / "modules-2"
            / "files-2.1"
            / "com.android.tools"
            / "r8"
            / "8.2.33"
        )
        r8_cache.mkdir(parents=True)
        (r8_cache / "r8-8.2.33.jar").write_bytes(b"dummy")

        res_populated = check_gradle_cache_dependencies(tmp_path)
        assert res_populated["cache_dir_exists"] is True
        assert res_populated["agp_cached"] is True
        assert res_populated["r8_cached"] is True


class TestGradleRunnerExecution:
    def test_invalid_project_dir_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        with pytest.raises(GradleError):
            GradleRunner(project_dir=missing)

    def test_mocked_success(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        runner = GradleRunner(
            project_dir=tmp_path,
            timeout_seconds=30.0,
            offline=True,
            no_daemon=True,
        )

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("BUILD SUCCESSFUL in 1s", "")
        mock_proc.returncode = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            result = runner.run_task("assembleRelease")
            assert result.success is True
            assert result.exit_code == 0
            assert "BUILD SUCCESSFUL" in result.stdout
            assert result.is_simulated is False

            # Verify command arguments
            cmd_called = mock_popen.call_args[0][0]
            assert "assembleRelease" in cmd_called
            assert "--no-daemon" in cmd_called
            assert "--offline" in cmd_called

    def test_mocked_failure_raises_execution_error(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        runner = GradleRunner(project_dir=tmp_path)

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (
            "",
            "Compilation error in MainActivity.java",
        )
        mock_proc.returncode = 1

        with patch("subprocess.Popen", return_value=mock_proc):
            with pytest.raises(GradleExecutionError) as exc_info:
                runner.run_task("assembleRelease")
            assert exc_info.value.exit_code == 1
            assert "Compilation error" in exc_info.value.stderr

    def test_mocked_timeout_kills_tree_and_raises(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        runner = GradleRunner(project_dir=tmp_path, timeout_seconds=10.0)

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd=["gradlew"], timeout=10.0),
            ("timeout output", "timeout error"),
        ]

        with (
            patch("subprocess.Popen", return_value=mock_proc),
            patch("appshield.gradle.kill_process_tree") as mock_kill,
        ):
            with pytest.raises(GradleTimeoutError) as exc_info:
                runner.run_task("assembleRelease")
            mock_kill.assert_called_once_with(99999)
            assert exc_info.value.timeout_seconds == 10.0


class TestApkExtraction:
    def test_validate_apk_file_missing(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.apk"
        with pytest.raises(ArtifactExtractionError):
            validate_apk_file(missing)

    def test_validate_apk_file_empty(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.apk"
        empty.write_bytes(b"")
        with pytest.raises(ArtifactExtractionError):
            validate_apk_file(empty)

    def test_validate_apk_file_invalid_zip(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.apk"
        bad.write_bytes(b"not a real zip file")
        with pytest.raises(ArtifactExtractionError):
            validate_apk_file(bad)

    def test_validate_apk_file_missing_markers(self, tmp_path: Path) -> None:
        no_markers = tmp_path / "no_markers.apk"
        with zipfile.ZipFile(no_markers, "w") as zf:
            zf.writestr("random.txt", b"hello")
        with pytest.raises(ArtifactExtractionError) as exc_info:
            validate_apk_file(no_markers)
        assert "expected Android markers" in str(exc_info.value)

    def test_validate_apk_file_valid(self, tmp_path: Path) -> None:
        apk = tmp_path / "valid.apk"
        create_dummy_apk(apk)
        validate_apk_file(apk)

    def test_locate_build_apk_missing_output_dir(self, tmp_path: Path) -> None:
        with pytest.raises(ArtifactExtractionError) as exc_info:
            locate_build_apk(tmp_path, module_name="app", build_variant="release")
        assert "Build output directory" in str(exc_info.value)

    def test_locate_build_apk_no_apks_in_dir(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "app" / "build" / "outputs" / "apk" / "release"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "output-metadata.json").write_text("{}", encoding="utf-8")
        with pytest.raises(ArtifactExtractionError) as exc_info:
            locate_build_apk(tmp_path, module_name="app", build_variant="release")
        assert "No APK artifacts found" in str(exc_info.value)

    def test_locate_build_apk_success_single(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "app" / "build" / "outputs" / "apk" / "release"
        apk = create_dummy_apk(out_dir / "app-release-unsigned.apk")
        located = locate_build_apk(tmp_path, module_name="app", build_variant="release")
        assert located == apk.resolve()

    def test_locate_build_apk_ambiguous_fails(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "app" / "build" / "outputs" / "apk" / "release"
        create_dummy_apk(out_dir / "app-flavor1-release.apk")
        create_dummy_apk(out_dir / "app-flavor2-release.apk")
        with pytest.raises(ArtifactExtractionError) as exc_info:
            locate_build_apk(tmp_path, module_name="app", build_variant="release")
        assert "Ambiguous APK output" in str(exc_info.value)

    def test_locate_r8_mapping(self, tmp_path: Path) -> None:
        mapping = (
            tmp_path
            / "app"
            / "build"
            / "outputs"
            / "mapping"
            / "release"
            / "mapping.txt"
        )
        mapping.parent.mkdir(parents=True, exist_ok=True)
        mapping.write_text("com.example.Foo -> a.a:\n", encoding="utf-8")

        found = locate_r8_mapping(tmp_path, module_name="app", build_variant="release")
        assert found == mapping.resolve()

    def test_locate_r8_mapping_root_fallback(self, tmp_path: Path) -> None:
        mapping = tmp_path / "build" / "outputs" / "mapping" / "release" / "mapping.txt"
        mapping.parent.mkdir(parents=True, exist_ok=True)
        mapping.write_text("com.example.Bar -> b.b:\n", encoding="utf-8")

        found = locate_r8_mapping(tmp_path, module_name="app", build_variant="release")
        assert found == mapping.resolve()

    def test_locate_r8_mapping_missing_returns_none(self, tmp_path: Path) -> None:
        found = locate_r8_mapping(tmp_path, module_name="app", build_variant="release")
        assert found is None


class TestGradleRunnerEdgeCases:
    def test_runner_with_extra_args_and_env(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        runner = GradleRunner(project_dir=tmp_path)
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("BUILD SUCCESSFUL", "")
        mock_proc.returncode = 0

        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
            res = runner.run_task(
                tasks="assembleRelease",
                extra_args=["--stacktrace", "-x", "test"],
                extra_env={"MY_BUILD_ENV": "1"},
            )
            assert res.success is True
            cmd_called = mock_popen.call_args[0][0]
            assert "--stacktrace" in cmd_called
            assert "-x" in cmd_called
            assert "test" in cmd_called
            env_called = mock_popen.call_args[1]["env"]
            assert env_called["MY_BUILD_ENV"] == "1"

    def test_runner_oserror_handling(self, tmp_path: Path) -> None:
        script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
        script = tmp_path / script_name
        script.write_text("dummy", encoding="utf-8")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(b"dummy_jar")

        runner = GradleRunner(project_dir=tmp_path)
        with (
            patch("subprocess.Popen", side_effect=OSError("Process creation failed")),
            pytest.raises(GradleExecutionError, match="Operating system error"),
        ):
            runner.run_task("assembleRelease")

    def test_kill_process_tree_zero_or_negative(self) -> None:
        kill_process_tree(0)
        kill_process_tree(-1)

    def test_kill_process_tree_posix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "linux")
        with (
            patch("os.killpg", create=True) as mock_killpg,
            patch("os.getpgid", create=True, return_value=1234),
        ):
            kill_process_tree(1234)
            mock_killpg.assert_called_once_with(1234, 9)
