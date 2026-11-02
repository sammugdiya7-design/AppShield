"""
Unit tests for AppShield Doctor: Environment and prerequisite tool detection.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from appshield.doctor import (
    check_command_version,
    parse_java_version,
    run_doctor_checks,
)


def test_check_command_version_success():
    """check_command_version returns first non-empty line of stdout/stderr."""
    mock_proc = MagicMock()
    mock_proc.stdout = (
        "openjdk version 17.0.2 2022-01-18\nOpenJDK Runtime Environment\n"
    )
    mock_proc.stderr = ""
    with patch("subprocess.run", return_value=mock_proc):
        ver = check_command_version(["java", "-version"])
    assert ver == "openjdk version 17.0.2 2022-01-18"


def test_check_command_version_empty_output():
    """check_command_version returns 'Installed' if command produces no output."""
    mock_proc = MagicMock()
    mock_proc.stdout = ""
    mock_proc.stderr = ""
    with patch("subprocess.run", return_value=mock_proc):
        ver = check_command_version(["some_tool"])
    assert ver == "Installed"


def test_check_command_version_error():
    """check_command_version returns None on SubprocessError or OSError."""
    with patch("subprocess.run", side_effect=subprocess.SubprocessError("timeout")):
        ver = check_command_version(["failing_tool"])
    assert ver is None

    with patch("subprocess.run", side_effect=OSError("not found")):
        ver = check_command_version(["failing_tool"])
    assert ver is None


def test_parse_java_version():
    """Test parsing major and detailed Java versions from various runtime outputs."""
    # Java 8 legacy
    major, ver_str = parse_java_version('java version "1.8.0_401"')
    assert major == 8
    assert ver_str == "1.8.0_401"

    # OpenJDK 17
    major, ver_str = parse_java_version('openjdk version "17.0.9" 2023-10-17')
    assert major == 17
    assert ver_str == "17.0.9"

    # Modern Java 21
    major, ver_str = parse_java_version('java version "21.0.1" 2023-10-17 LTS')
    assert major == 21
    assert ver_str == "21.0.1"

    # Unknown
    major, ver_str = parse_java_version("some custom jvm")
    assert major is None
    assert ver_str == "some custom jvm"


def test_run_doctor_checks_all_tools_present(tmp_path: Path):
    """Test doctor checks when all tools and env variables are present."""
    fake_java = str(tmp_path / "java")
    fake_javac = str(tmp_path / "javac")
    fake_gradle = str(tmp_path / "gradle")
    fake_zipalign = str(tmp_path / "zipalign")
    fake_apksigner = str(tmp_path / "apksigner")

    fake_java_home = tmp_path / "jdk17"
    fake_bin = fake_java_home / "bin"
    fake_bin.mkdir(parents=True)
    fake_java_exe = fake_bin / ("java.exe" if os.name == "nt" else "java")
    fake_java_exe.write_text("#!/bin/sh", encoding="utf-8")

    fake_android_home = tmp_path / "android_sdk"
    fake_platform_34 = fake_android_home / "platforms" / "android-34"
    fake_platform_34.mkdir(parents=True)
    fake_bt_34 = fake_android_home / "build-tools" / "34.0.0"
    fake_bt_34.mkdir(parents=True)

    def mock_which(cmd: str) -> str | None:
        mapping = {
            "java": fake_java,
            "javac": fake_javac,
            "gradle": fake_gradle,
            "zipalign": fake_zipalign,
            "apksigner": fake_apksigner,
        }
        return mapping.get(cmd)

    env_vars = {
        "JAVA_HOME": str(fake_java_home),
        "ANDROID_HOME": str(fake_android_home),
    }

    with (
        patch("shutil.which", side_effect=mock_which),
        patch.dict("os.environ", env_vars, clear=False),
        patch(
            "appshield.doctor.check_command_version",
            return_value='openjdk version "17.0.2"',
        ),
    ):
        reports = run_doctor_checks()

    assert len(reports) == 9
    report_map = {r.name: r for r in reports}

    assert report_map["Java Runtime (java)"].is_available is True
    assert "Java 17" in (report_map["Java Runtime (java)"].version or "")
    assert report_map["Java Compiler (javac)"].is_available is True
    assert report_map["JAVA_HOME Variable"].is_available is True
    assert report_map["Android SDK (ANDROID_HOME)"].is_available is True
    assert report_map["Android SDK Platform 34"].is_available is True
    assert report_map["Android SDK Build-Tools 34.0.0"].is_available is True
    assert report_map["Gradle Build Tool"].is_available is True
    assert report_map["zipalign"].is_available is True
    assert report_map["apksigner"].is_available is True


def test_run_doctor_checks_all_tools_missing():
    """Test doctor checks when tools and env variables are completely missing."""
    with (
        patch("shutil.which", return_value=None),
        patch.dict("os.environ", {}, clear=True),
    ):
        reports = run_doctor_checks()

    assert len(reports) == 9
    report_map = {r.name: r for r in reports}

    assert report_map["Java Runtime (java)"].is_available is False
    assert report_map["Java Runtime (java)"].required is True
    assert "Install OpenJDK" in report_map["Java Runtime (java)"].remediation_hint

    assert report_map["JAVA_HOME Variable"].is_available is False
    assert report_map["JAVA_HOME Variable"].required is True

    assert report_map["Gradle Build Tool"].is_available is False
    assert report_map["Gradle Build Tool"].required is True

    assert report_map["Android SDK (ANDROID_HOME)"].is_available is False
    assert report_map["Android SDK (ANDROID_HOME)"].required is True

    assert report_map["Android SDK Platform 34"].is_available is False
    assert report_map["Android SDK Platform 34"].required is True

    assert report_map["Android SDK Build-Tools 34.0.0"].is_available is False
    assert report_map["Android SDK Build-Tools 34.0.0"].required is True

    assert report_map["zipalign"].is_available is False
    assert report_map["zipalign"].required is True

    assert report_map["apksigner"].is_available is False
    assert report_map["apksigner"].required is True


def test_run_doctor_checks_java_8_incompatible(tmp_path: Path):
    """Test that Java 8 is detected and flagged as incompatible with AGP 8.2."""
    fake_java = str(tmp_path / "java")
    with (
        patch("shutil.which", return_value=fake_java),
        patch(
            "appshield.doctor.check_command_version",
            return_value='java version "1.8.0_401"',
        ),
    ):
        reports = run_doctor_checks()

    report_map = {r.name: r for r in reports}
    java_rep = report_map["Java Runtime (java)"]
    assert java_rep.is_available is False
    assert "Incompatible" in (java_rep.version or "")
    assert "Detected Java 8" in java_rep.remediation_hint


def test_run_doctor_checks_project_gradlew_detection(tmp_path: Path):
    """Test that doctor checks detect gradlew in the provided project directory."""
    project_dir = tmp_path / "sample_app"
    project_dir.mkdir()
    gradlew_file = project_dir / "gradlew"
    gradlew_file.write_text("#!/bin/sh\n", encoding="utf-8")

    with patch("shutil.which", return_value=None):
        reports = run_doctor_checks(project_dir=project_dir)

    report_map = {r.name: r for r in reports}
    gradle_report = report_map["Gradle Build Tool"]
    assert gradle_report.is_available is True
    assert gradle_report.version is not None
    assert "project wrapper detected" in gradle_report.version
    assert gradle_report.path == str(gradlew_file)


def test_run_doctor_checks_fixture_inspection():
    """Test doctor checks against the controlled sample Android Gradle fixture."""
    fixture_dir = Path("tests/fixtures/sample_android_gradle_project")
    assert fixture_dir.is_dir()

    reports = run_doctor_checks(project_dir=fixture_dir)
    report_map = {r.name: r for r in reports}

    # Verify project-level checks exist
    assert "Android Gradle Project Structure" in report_map
    assert report_map["Android Gradle Project Structure"].is_available is True

    assert "Gradle Distribution Configuration" in report_map
    assert report_map["Gradle Distribution Configuration"].is_available is True
    assert "gradle-8.2-bin.zip" in (
        report_map["Gradle Distribution Configuration"].version or ""
    )

    # Wrapper JAR is omitted from git tracking in fixture
    assert "Gradle Wrapper JAR (gradle-wrapper.jar)" in report_map
    assert report_map["Gradle Wrapper JAR (gradle-wrapper.jar)"].is_available is False
    assert (
        "Missing from gradle/wrapper/"
        in report_map["Gradle Wrapper JAR (gradle-wrapper.jar)"].version
    )

    # AGP version 8.2.2 detected from fixture
    assert "Android Gradle Plugin (AGP)" in report_map
    assert report_map["Android Gradle Plugin (AGP)"].is_available is True
    assert "AGP 8.2.2" in (report_map["Android Gradle Plugin (AGP)"].version or "")

    # Release minification configuration verified in fixture
    assert "Android Release R8 Configuration" in report_map
    assert report_map["Android Release R8 Configuration"].is_available is True
    assert "minifyEnabled=true" in (
        report_map["Android Release R8 Configuration"].version or ""
    )
