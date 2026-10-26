"""
Unit tests for AppShield CLI subcommands: info, doctor, protect, and verify.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from appshield.cli import main
from appshield.doctor import ToolReport


def test_cli_no_args(capsys):
    """Running CLI with no arguments should display help and exit 0."""
    code = main([])
    assert code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "appshield" in captured.out.lower()


def test_cli_info(capsys):
    """'appshield info' should display version, air-gapped architecture, and platform scope."""
    code = main(["info"])
    assert code == 0
    captured = capsys.readouterr()
    assert "AppShield CLI" in captured.out
    assert "100% Local, Offline Orchestrator (Air-Gapped)" in captured.out
    assert "Android Gradle Projects (AGP + R8)" in captured.out
    assert "Arbitrary precompiled APK input is unsupported" in captured.out
    assert "Objective empirical evidence only (No composite scores)" in captured.out


def test_cli_doctor_all_ok(capsys):
    """'appshield doctor' exits 0 when all required tools are available."""
    mock_reports = [
        ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
        ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
        ToolReport("Gradle Build Tool", True, "gradlew", True, ""),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(["doctor"])
    assert code == 0
    captured = capsys.readouterr()
    assert "[OK]" in captured.out
    assert "Java Runtime (java)" in captured.out
    assert "All required prerequisites are met" in captured.out


def test_cli_doctor_missing_required(capsys):
    """'appshield doctor' exits 1 when a required dependency is missing."""
    mock_reports = [
        ToolReport("Java Runtime (java)", False, None, True, "Install OpenJDK 17+"),
        ToolReport("Gradle Build Tool", False, None, True, "Ensure gradlew exists"),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(["doctor"])
    assert code == 1
    captured = capsys.readouterr()
    assert "[MISSING]" in captured.out
    assert "Java Runtime (java)" in captured.out
    assert "Remediation : Install OpenJDK 17+" in captured.out
    assert "Missing required dependencies" in captured.out


def test_cli_protect_missing_config_arg(capsys):
    """'appshield protect' without -c/--config exits non-zero (argparse error)."""
    with pytest.raises(SystemExit) as exc:
        main(["protect"])
    assert exc.value.code != 0


def test_cli_protect_nonexistent_config_file(tmp_path: Path, capsys):
    """'appshield protect' with nonexistent config file exits 1 with clean error."""
    nonexistent = tmp_path / "missing.yaml"
    code = main(["protect", "-c", str(nonexistent)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Configuration file not found" in captured.err


def test_cli_protect_invalid_config_file(tmp_path: Path, capsys):
    """'appshield protect' with invalid config schema exits 1."""
    bad_cfg = tmp_path / "bad.json"
    bad_cfg.write_text('{"version": "9.9"}', encoding="utf-8")
    code = main(["protect", "-c", str(bad_cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Configuration Validation Error" in captured.err


def test_cli_protect_nonexistent_project_dir(tmp_path: Path, capsys):
    """'appshield protect' exits 1 if input.project_dir does not exist."""
    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {{ "project_dir": "./missing_project_dir" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    code = main(["protect", "-c", str(cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Input project directory does not exist" in captured.err


def test_cli_protect_project_path_is_file(tmp_path: Path, capsys):
    """'appshield protect' exits 1 if project_dir is a file rather than a directory."""
    dummy_file = tmp_path / "sample.apk"
    dummy_file.write_text("fake apk", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {{ "project_dir": "{dummy_file.as_posix()}" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    code = main(["protect", "-c", str(cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Input project path is not a directory" in captured.err


def test_cli_protect_overwrite_blocked(tmp_path: Path, capsys):
    """'appshield protect' stops and exits 1 if target output already exists without --overwrite."""
    proj = tmp_path / "android_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")

    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    target_apk = out_dir / "test_app-release-protected.apk"
    target_apk.write_text("existing artifact bytes", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {{ "project_dir": "{proj.as_posix()}" }},
        "output": {{ "dir": "{out_dir.as_posix()}", "overwrite_existing": false }}
    }}""",
        encoding="utf-8",
    )

    code = main(["protect", "-c", str(cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Overwrite Protection Error" in captured.err
    assert "Destination file already exists" in captured.err


def test_cli_protect_overwrite_allowed(tmp_path: Path, capsys):
    """'appshield protect' proceeds past overwrite check if --overwrite is provided."""
    proj = tmp_path / "android_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")

    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    target_apk = out_dir / "test_app-release-protected.apk"
    target_apk.write_text("existing artifact bytes", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {{ "project_dir": "{proj.as_posix()}" }},
        "output": {{ "dir": "{out_dir.as_posix()}", "overwrite_existing": false }}
    }}""",
        encoding="utf-8",
    )

    mock_reports = [
        ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
        ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
        ToolReport("Gradle Build Tool", True, "gradlew", True, ""),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(["protect", "-c", str(cfg), "--overwrite"])

    assert code == 0
    captured = capsys.readouterr()
    assert "PREFLIGHT VALIDATION: SUCCESSFUL" in captured.out
    assert (
        "NOTICE: The protection engine is NOT implemented in Plan 03-01" in captured.out
    )


def test_cli_protect_unimplemented_notice(tmp_path: Path, capsys):
    """
    Test that 'protect' explicitly communicates that the protection engine
    is NOT implemented in Plan 03-01 and does NOT claim to protect anything.
    """
    proj = tmp_path / "my_android_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "demo_app",
        "platform": "android",
        "input": {{ "project_dir": "{proj.as_posix()}" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    mock_reports = [
        ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
        ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
        ToolReport("Gradle Build Tool", True, "gradlew", True, ""),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(["protect", "-c", str(cfg)])

    assert code == 0
    captured = capsys.readouterr()
    assert "PREFLIGHT VALIDATION: SUCCESSFUL." in captured.out
    assert (
        "NOTICE: The protection engine is NOT implemented in Plan 03-01."
        in captured.out
    )
    assert (
        "The Android Gradle + R8 protection workflow will be implemented and validated in Phase 4."
        in captured.out
    )


def test_cli_protect_missing_prerequisites(tmp_path: Path, capsys):
    """'appshield protect' fails preflight if required doctor prerequisites are missing."""
    proj = tmp_path / "my_android_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "demo_app",
        "platform": "android",
        "input": {{ "project_dir": "{proj.as_posix()}" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    mock_reports = [
        ToolReport("Java Runtime (java)", False, None, True, "Install OpenJDK 17"),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(["protect", "-c", str(cfg)])

    assert code == 1
    captured = capsys.readouterr()
    assert "PREFLIGHT VALIDATION: FAILED" in captured.err


def test_cli_verify_nonexistent_artifact(tmp_path: Path, capsys):
    """'appshield verify' exits 1 if the target artifact file does not exist."""
    missing = tmp_path / "nonexistent.apk"
    code = main(["verify", str(missing)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Target artifact not found" in captured.err


def test_cli_verify_artifact_is_directory(tmp_path: Path, capsys):
    """'appshield verify' exits 1 if the target artifact path is a directory."""
    directory = tmp_path / "some_dir"
    directory.mkdir()
    code = main(["verify", str(directory)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Target path is not a file" in captured.err


def test_cli_verify_unimplemented_notice(tmp_path: Path, capsys):
    """
    Test that 'verify' validates that the artifact file exists,
    explicitly lists objective checks as UNAVAILABLE in Plan 03-01,
    and states that no composite security scores will be generated.
    """
    dummy_apk = tmp_path / "app-release.apk"
    dummy_apk.write_text("dummy binary content", encoding="utf-8")

    code = main(["verify", str(dummy_apk)])
    assert code == 0
    captured = capsys.readouterr()
    assert "Artifact validated: File exists and is readable." in captured.out
    assert (
        "[CHK-SYM-01] Identifier Renaming Ratio      : UNAVAILABLE (Planned for Phase 4)"
        in captured.out
    )
    assert (
        "[CHK-STR-01] String Pool Constant Scan      : UNAVAILABLE (Planned for Phase 4)"
        in captured.out
    )
    assert (
        "[CHK-SIG-01] APK Signature Verification     : UNAVAILABLE (Planned for Phase 4)"
        in captured.out
    )
    assert (
        "[CHK-ALN-01] Zip Alignment Verification     : UNAVAILABLE (Planned for Phase 4)"
        in captured.out
    )
    assert (
        "[CHK-DEC-01] Structural Decompilation Check : UNAVAILABLE (Planned for Phase 4)"
        in captured.out
    )
    assert (
        "NOTICE: Objective verification checks are NOT implemented in Plan 03-01."
        in captured.out
    )
    assert "No composite security scores will be generated." in captured.out


def test_cli_protect_cli_overrides(tmp_path: Path, capsys):
    """'appshield protect' applies CLI overrides for project-dir, output-dir, and platform."""
    base_proj = tmp_path / "base_proj"
    base_proj.mkdir()
    override_proj = tmp_path / "override_proj"
    override_proj.mkdir()
    (override_proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")
    override_out = tmp_path / "custom_dist"

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "override_app",
        "platform": "android",
        "input": {{ "project_dir": "{base_proj.as_posix()}" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    mock_reports = [
        ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
        ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
        ToolReport("Gradle Build Tool", True, "gradlew", True, ""),
    ]
    with patch("appshield.cli.run_doctor_checks", return_value=mock_reports):
        code = main(
            [
                "protect",
                "-c",
                str(cfg),
                "--project-dir",
                str(override_proj),
                "--output-dir",
                str(override_out),
                "--platform",
                "android",
            ]
        )

    assert code == 0
    captured = capsys.readouterr()
    assert str(override_proj.resolve()) in captured.out
    assert str(override_out.resolve()) in captured.out


def test_cli_protect_generic_config_error(tmp_path: Path, capsys):
    """'appshield protect' cleanly reports generic ConfigError."""
    cfg = tmp_path / "dummy.json"
    cfg.write_text("{}", encoding="utf-8")
    from appshield.config import ConfigError

    with patch(
        "appshield.cli.load_config", side_effect=ConfigError("Generic parse issue")
    ):
        code = main(["protect", "-c", str(cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Configuration Error: Generic parse issue" in captured.err
