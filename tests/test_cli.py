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
    from appshield.adapters.base import ProtectionResult

    with (
        patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
        patch(
            "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
            return_value=ProtectionResult(
                success=True,
                protected_artifact_path=target_apk,
                logs=["Staging complete", "Build complete"],
            ),
        ),
    ):
        code = main(["protect", "-c", str(cfg), "--overwrite"])

    assert code == 0
    captured = capsys.readouterr()
    assert "PREFLIGHT VALIDATION: SUCCESSFUL" in captured.out
    assert "Protection SUCCEEDED" in captured.out


def test_cli_protect_unsupported_platform(tmp_path: Path, capsys):
    """'appshield protect' rejects platforms other than android in v1 MVP."""
    proj = tmp_path / "ios_proj"
    proj.mkdir()

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "ios_app",
        "platform": "ios",
        "input": {{ "project_dir": "{proj.as_posix()}" }},
        "output": {{ "dir": "{tmp_path.as_posix()}/dist" }}
    }}""",
        encoding="utf-8",
    )

    code = main(["protect", "-c", str(cfg)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Platform 'ios' is not supported yet" in captured.err


def test_cli_protect_flags_forwarded(tmp_path: Path, capsys):
    """Verify --allow-production-signing and --mapping-out are passed to stage_and_protect."""
    proj = tmp_path / "android_proj"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh", encoding="utf-8")

    cfg = tmp_path / "appshield.json"
    cfg.write_text(
        f"""{{
        "version": "1.0",
        "project_name": "test_app",
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
    mapping_out = tmp_path / "retained_mapping.txt"
    from appshield.adapters.base import ProtectionResult

    with (
        patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
        patch(
            "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
            return_value=ProtectionResult(
                success=True,
                protected_artifact_path=tmp_path
                / "dist"
                / "test_app-release-protected.apk",
                logs=["Protected build executed"],
            ),
        ) as mock_stage,
    ):
        code = main(
            [
                "protect",
                "-c",
                str(cfg),
                "--allow-production-signing",
                "--mapping-out",
                str(mapping_out),
            ]
        )

    assert code == 0
    assert mock_stage.call_count == 1
    call_kwargs = mock_stage.call_args.kwargs
    assert call_kwargs["allow_production_signing"] is True
    assert call_kwargs["mapping_out"] == mapping_out


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


def test_cli_verify_success_with_valid_apk(tmp_path: Path, capsys):
    """'appshield verify' runs objective checks against an APK and prints terminal report."""
    import zipfile

    from appshield.dex import create_synthetic_dex

    apk_file = tmp_path / "valid.apk"
    dex_bytes = create_synthetic_dex(classes=["a.a", "a.b", "MainActivity"])
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy/>")
        zf.writestr("classes.dex", dex_bytes)

    code = main(["verify", str(apk_file)])
    assert code == 0
    captured = capsys.readouterr()
    assert "AppShield Empirical Verification Report" in captured.out
    assert "CHK-APK-01" in captured.out
    assert "Objective Verification Checks" in captured.out


def test_cli_verify_with_mapping_and_json_output(tmp_path: Path, capsys):
    """'appshield verify' uses provided -m mapping and exports -o JSON report."""
    import json
    import zipfile

    from appshield.dex import create_synthetic_dex

    apk_file = tmp_path / "app.apk"
    dex_bytes = create_synthetic_dex(classes=["a.a", "a.b", "MainActivity"])
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy/>")
        zf.writestr("classes.dex", dex_bytes)

    mapping_file = tmp_path / "mapping.txt"
    mapping_file.write_text(
        """com.example.sample.IdentifiableSecretService -> a.a:
com.example.sample.PaymentSecurityValidator -> a.b:
com.example.sample.MainActivity -> MainActivity:
""",
        encoding="utf-8",
    )
    json_out = tmp_path / "report.json"

    code = main(
        [
            "verify",
            str(apk_file),
            "-m",
            str(mapping_file),
            "-o",
            str(json_out),
        ]
    )
    assert code == 0
    assert json_out.is_file()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["audit_version"] == "1.0"
    assert len(data["objective_checks"]) == 7
    captured = capsys.readouterr()
    assert f"Audit report exported to: '{json_out.resolve()}'" in captured.out


def test_cli_verify_missing_mapping_file(tmp_path: Path, capsys):
    """'appshield verify' exits 1 if specified mapping file does not exist."""
    import zipfile

    apk_file = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy/>")

    missing_map = tmp_path / "nonexistent_mapping.txt"
    code = main(["verify", str(apk_file), "-m", str(missing_map)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Mapping file not found" in captured.err


def test_cli_verify_refuses_output_overwrite(tmp_path: Path, capsys):
    """'appshield verify' exits 1 if destination output report already exists without --overwrite."""
    import zipfile

    from appshield.dex import create_synthetic_dex

    apk_file = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy/>")
        zf.writestr("classes.dex", create_synthetic_dex(["com.example.MainActivity"]))

    existing_out = tmp_path / "standalone_audit.json"
    existing_out.write_text("prior report content", encoding="utf-8")

    code = main(["verify", str(apk_file), "-o", str(existing_out)])
    assert code == 1
    captured = capsys.readouterr()
    assert "Overwrite Protection Error" in captured.err
    assert "Destination audit report already exists" in captured.err
    assert existing_out.read_text(encoding="utf-8") == "prior report content"


def test_cli_verify_allows_output_overwrite_with_flag(tmp_path: Path, capsys):
    """'appshield verify' overwrites destination output report when --overwrite is passed."""
    import zipfile

    from appshield.dex import create_synthetic_dex

    apk_file = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_file, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy/>")
        zf.writestr("classes.dex", create_synthetic_dex(["com.example.MainActivity"]))

    existing_out = tmp_path / "standalone_audit.json"
    existing_out.write_text("prior report content", encoding="utf-8")

    code = main(["verify", str(apk_file), "-o", str(existing_out), "--overwrite"])
    assert code == 0
    captured = capsys.readouterr()
    assert f"Audit report exported to: '{existing_out.resolve()}'" in captured.out
    assert existing_out.read_text(encoding="utf-8") != "prior report content"


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
    from appshield.adapters.base import ProtectionResult

    with (
        patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
        patch(
            "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
            return_value=ProtectionResult(
                success=True,
                protected_artifact_path=override_out
                / "override_app-release-protected.apk",
                logs=["Protected override"],
            ),
        ),
    ):
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


def test_cli_protect_allow_network_dependencies_flag(tmp_path: Path):
    """'appshield protect --allow-network-dependencies' sets config.android.offline to False."""
    from appshield.adapters.base import ProtectionResult
    from appshield.doctor import ToolReport

    proj = tmp_path / "app"
    proj.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    cfg = tmp_path / "appshield.yaml"
    cfg.write_text(
        f"""
version: "1.0"
project_name: "test_net_override"
platform: "android"
input:
  project_dir: "{proj.as_posix()}"
output:
  dir: "{out.as_posix()}"
android:
  offline: true
""",
        encoding="utf-8",
    )

    mock_reports = [
        ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
        ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
        ToolReport("Gradle Build Tool", True, "8.2", True, ""),
    ]

    captured_config = []

    def mock_stage_and_protect(
        self, config, mapping_out=None, allow_production_signing=False
    ):
        captured_config.append(config)
        return ProtectionResult(
            success=True,
            protected_artifact_path=out / "test_net_override-release-protected.apk",
            logs=["Protected"],
        )

    with (
        patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
        patch(
            "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
            side_effect=mock_stage_and_protect,
            autospec=True,
        ),
    ):
        code = main(["protect", "-c", str(cfg), "--allow-network-dependencies"])

    assert code == 0
    assert len(captured_config) == 1
    assert captured_config[0].android.offline is False
