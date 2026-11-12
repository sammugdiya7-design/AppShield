"""
Phase A Regression Test Suite:
Validates generalization beyond fixtures, structured error handling, accurate doctor
offline cache diagnostics, VerificationConfig enforcement, pre-build safety gates,
and signing subprocess credential isolation.
"""

from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from appshield.adapters.android import (
    AndroidPipelineAdapter,
    contains_dontobfuscate_directive,
    extract_manifest_entry_points,
)
from appshield.cli import main
from appshield.config import (
    CANONICAL_VERIFICATION_CHECKS,
    AndroidConfig,
    AppShieldConfig,
    ConfigValidationError,
    InputConfig,
    OutputConfig,
    SigningConfig,
    VerificationConfig,
    load_config,
)
from appshield.dex import create_synthetic_dex, inspect_apk_dex
from appshield.doctor import ToolReport, run_doctor_checks
from appshield.gradle import (
    ArtifactExtractionError,
    GradleBuildResult,
    GradleExecutionError,
    GradleTimeoutError,
)
from appshield.mapping import parse_r8_mapping
from appshield.sandbox import SourceImmutabilityError, compute_file_sha256
from appshield.signing import (
    SigningResult,
    generate_disposable_test_keystore,
    sign_apk,
    verify_apk_signature,
    verify_zipalign,
    zipalign_apk,
)
from appshield.verify import VerificationEngine

UNRELATED_FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "unrelated_android_gradle_project"
).resolve()

UNRELATED_MAPPING_CONTENT = """# compiler: R8
# compiler_version: 8.2.2
org.acme.ledger.InvoiceCalculator -> a.a:
    org.acme.ledger.TaxRuleEngine taxRuleEngine -> a
    void <init>(org.acme.ledger.TaxRuleEngine) -> <init>
    1:5:long computeTotalCents(long,java.lang.String) -> a
org.acme.ledger.TaxRuleEngine -> a.b:
    void <init>() -> <init>
    1:8:int resolveBasisPoints(java.lang.String) -> a
org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:
    1:6:void onCreate(android.os.Bundle) -> onCreate
"""


def _build_apk(
    path: Path,
    classes: list[str],
    strings: list[str] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    dex_bytes = create_synthetic_dex(
        classes=classes,
        strings=strings or ["AcmeLedger", "EU"],
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='org.acme.ledger'/>")
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("resources.arsc", b"<resources/>")
    return path


def _snapshot_tree_hashes(root_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for root, _, files in os.walk(root_dir):
        for fname in files:
            fpath = Path(root) / fname
            hashes[fpath.relative_to(root_dir).as_posix()] = compute_file_sha256(fpath)
    return hashes


class TestUnrelatedAndroidProjectGeneralization:
    """Task 1: AppShield protects arbitrary Android projects unrelated to internal fixture."""

    def test_unrelated_fixture_manifest_and_module_discovery(self) -> None:
        adapter = AndroidPipelineAdapter()
        inspection = adapter.validate_project(UNRELATED_FIXTURE_DIR)

        assert inspection.is_supported is True
        assert inspection.module_name == "mobile"
        assert inspection.minify_enabled is True
        assert inspection.shrink_resources is True
        assert inspection.agp_version == "8.2.2"
        assert (
            inspection.rules_file
            == UNRELATED_FIXTURE_DIR / "mobile" / "proguard-rules.pro"
        )

        entry_points = extract_manifest_entry_points(
            UNRELATED_FIXTURE_DIR,
            module_name=inspection.module_name,
            build_file=inspection.build_file,
        )
        assert entry_points == ["org.acme.ledger.LedgerHomeActivity"]

    def test_unrelated_project_full_protection_via_cli(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        proj_copy = tmp_path / "acme_ledger_project"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        before_hashes = _snapshot_tree_hashes(proj_copy)

        dist_dir = tmp_path / "dist"
        cfg_file = tmp_path / "appshield.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "acme_ledger",
                    "platform": "android",
                    "input": {
                        "project_dir": str(proj_copy),
                        "verify_source_immutability": True,
                    },
                    "output": {"dir": str(dist_dir), "overwrite_existing": False},
                    "android": {
                        "project_type": "gradle",
                        "build_variant": "release",
                        "gradle_task": "assembleRelease",
                        "signing": {"enabled": False},
                    },
                    "verification": {
                        "enabled": True,
                        "fail_on_check_failure": True,
                        "checks": list(CANONICAL_VERIFICATION_CHECKS),
                    },
                }
            ),
            encoding="utf-8",
        )

        dex_classes = ["a.a", "a.b", "org.acme.ledger.LedgerHomeActivity"]
        mock_reports = [
            ToolReport("Java Runtime (java)", True, "17.0.9", True, ""),
            ToolReport("JAVA_HOME Variable", True, "/jdk-17", True, ""),
            ToolReport("Gradle Build Tool", True, "Gradle 8.2", True, ""),
        ]

        staged_paths_seen: list[Path] = []

        def fake_gradle_run(
            self: Any, task: str, **kwargs: object
        ) -> GradleBuildResult:
            staged_paths_seen.append(self.project_dir)
            apk_path = (
                self.project_dir
                / "mobile"
                / "build"
                / "outputs"
                / "apk"
                / "release"
                / "mobile-release-unsigned.apk"
            )
            _build_apk(apk_path, classes=dex_classes)
            mapping_path = (
                self.project_dir
                / "mobile"
                / "build"
                / "outputs"
                / "mapping"
                / "release"
                / "mapping.txt"
            )
            mapping_path.parent.mkdir(parents=True, exist_ok=True)
            mapping_path.write_text(UNRELATED_MAPPING_CONTENT, encoding="utf-8")
            return GradleBuildResult(
                success=True,
                exit_code=0,
                stdout="BUILD SUCCESSFUL",
                stderr="",
                duration_seconds=1.1,
                command=["gradlew", task],
                apk_path=apk_path,
                mapping_file=mapping_path,
                is_simulated=False,
            )

        def fake_align_sign(
            unsigned_apk: Path, output_dir: Path, **kwargs: object
        ) -> SigningResult:
            final_apk = output_dir / "mobile-release-unsigned-aligned.apk"
            _build_apk(final_apk, classes=dex_classes)
            return SigningResult(
                success=True,
                signature_type="unsigned",
                aligned_apk_path=final_apk,
                final_apk_path=final_apk,
                is_aligned=True,
            )

        with (
            patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
            patch(
                "appshield.adapters.android.AndroidPipelineAdapter.check_prerequisites",
                return_value=[],
            ),
            patch("appshield.adapters.android.GradleRunner.run_task", fake_gradle_run),
            patch(
                "appshield.adapters.android.align_and_sign_apk",
                side_effect=fake_align_sign,
            ),
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            exit_code = main(["protect", "-c", str(cfg_file)])

        assert exit_code == 0
        out = capsys.readouterr().out
        assert "Protection SUCCEEDED" in out
        assert "Code-Protection Verified   : YES" in out

        protected_apk = dist_dir / "acme_ledger-release-protected.apk"
        assert protected_apk.is_file()
        audit_data = json.loads(
            (dist_dir / "audit_report.json").read_text(encoding="utf-8")
        )
        assert audit_data["is_verified_protected"] is True
        sym_check = next(
            c for c in audit_data["objective_checks"] if c["check_id"] == "CHK-SYM-01"
        )
        assert sym_check["status"] == "PASS"
        assert sym_check["details"]["verification_mode"] == "generalized_mapping"
        assert sym_check["details"]["generalized_classes_verified"] == 2
        assert sym_check["details"]["entry_points_checked"] == 1

        # Staging dir cleaned up and source untouched
        assert len(staged_paths_seen) == 1
        assert not staged_paths_seen[0].exists()
        assert _snapshot_tree_hashes(proj_copy) == before_hashes

    def test_generalized_sym_check_rejects_dontobfuscate_zero_renaming(
        self, tmp_path: Path
    ) -> None:
        unrenamed_mapping = """# compiler: R8
org.acme.ledger.InvoiceCalculator -> org.acme.ledger.InvoiceCalculator:
org.acme.ledger.TaxRuleEngine -> org.acme.ledger.TaxRuleEngine:
org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:
"""
        apk = _build_apk(
            tmp_path / "unobf.apk",
            classes=[
                "org.acme.ledger.InvoiceCalculator",
                "org.acme.ledger.TaxRuleEngine",
                "org.acme.ledger.LedgerHomeActivity",
            ],
        )
        engine = VerificationEngine()
        res = engine.check_sym_01(
            dex_summary=inspect_apk_dex(apk),
            mapping=parse_r8_mapping(unrenamed_mapping),
            expected_fixture_classes=None,
            expected_entry_points=["org.acme.ledger.LedgerHomeActivity"],
        )
        assert res.status == "FAIL"
        assert res.outcome == "FAILED"
        assert "discrepancy" in res.observed_metric

    def test_generalized_sym_check_rejects_stripped_or_mismatched_dex(
        self, tmp_path: Path
    ) -> None:
        # DEX lacks obfuscated a.a / a.b even though mapping claims renaming happened
        apk = _build_apk(
            tmp_path / "stripped.apk",
            classes=["org.acme.ledger.LedgerHomeActivity"],
        )
        engine = VerificationEngine()
        res = engine.check_sym_01(
            dex_summary=inspect_apk_dex(apk),
            mapping=parse_r8_mapping(UNRELATED_MAPPING_CONTENT),
            expected_fixture_classes=None,
            expected_entry_points=["org.acme.ledger.LedgerHomeActivity"],
        )
        assert res.status == "FAIL"
        assert res.outcome == "FAILED"

    def test_generalized_sym_check_rejects_missing_manifest_entry_point(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(tmp_path / "no_entry.apk", classes=["a.a", "a.b"])
        engine = VerificationEngine()
        res = engine.check_sym_01(
            dex_summary=inspect_apk_dex(apk),
            mapping=parse_r8_mapping(UNRELATED_MAPPING_CONTENT),
            expected_fixture_classes=None,
            expected_entry_points=["org.acme.ledger.LedgerHomeActivity"],
        )
        assert res.status == "FAIL"
        assert res.details["entry_points_checked"] == 1


class TestPrebuildSafetyValidation:
    """Task 5: Early rejection of unsafe/unsupported configurations."""

    def test_detect_dontobfuscate_in_project_rules(self, tmp_path: Path) -> None:
        proj = tmp_path / "dontobf_proj"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj)
        rules_file = proj / "mobile" / "proguard-rules.pro"
        rules_file.write_text(
            "# comment mentioning -dontobfuscate\n-dontobfuscate\n",
            encoding="utf-8",
        )

        assert contains_dontobfuscate_directive(
            "-keep class foo\n  -dontobfuscate  # why\n"
        )
        assert not contains_dontobfuscate_directive(
            "# -dontobfuscate\n-keep class foo\n"
        )

        adapter = AndroidPipelineAdapter()
        inspection = adapter.validate_project(proj)
        assert inspection.is_supported is False
        assert any("-dontobfuscate" in err for err in inspection.errors)

        cfg = AppShieldConfig(
            version="1.0",
            project_name="dontobf_app",
            platform="android",
            input=InputConfig(project_dir=proj),
            output=OutputConfig(dir=tmp_path / "dist"),
        )
        res = adapter.stage_and_protect(cfg, runner=MagicMock())
        assert res.success is False
        assert "-dontobfuscate" in (res.error_message or "")

    def test_detect_dontobfuscate_in_custom_r8_rules_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad_rules = tmp_path / "custom-bad.pro"
        bad_rules.write_text("-dontobfuscate\n", encoding="utf-8")

        cfg_file = tmp_path / "appshield.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "custom_dontobf",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "android": {"r8_rules_file": str(bad_rules)},
                }
            ),
            encoding="utf-8",
        )

        with patch(
            "appshield.cli.run_doctor_checks",
            return_value=[ToolReport("Java", True, "17", True, "")],
        ):
            code = main(["protect", "-c", str(cfg_file)])
        assert code == 1
        err = capsys.readouterr().err
        assert "-dontobfuscate" in err

    @pytest.mark.parametrize(
        "bad_task",
        ["bundleRelease", ":mobile:bundleRelease", "clean", "assembleDebug", "-evil"],
    )
    def test_cli_rejects_invalid_or_bundle_gradle_tasks(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], bad_task: str
    ) -> None:
        cfg_file = tmp_path / "appshield.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "bad_task_app",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "android": {"gradle_task": bad_task},
                }
            ),
            encoding="utf-8",
        )
        code = main(["protect", "-c", str(cfg_file)])
        assert code == 1
        err = capsys.readouterr().err
        assert "Configuration Validation Error" in err

    def test_stage_and_protect_rejects_bundle_task_programmatically(
        self, tmp_path: Path
    ) -> None:
        cfg = AppShieldConfig(
            version="1.0",
            project_name="aab_app",
            platform="android",
            input=InputConfig(project_dir=UNRELATED_FIXTURE_DIR),
            output=OutputConfig(dir=tmp_path / "dist"),
            android=AndroidConfig(gradle_task="bundleRelease"),
        )
        mock_runner = MagicMock()
        res = AndroidPipelineAdapter().stage_and_protect(cfg, runner=mock_runner)
        assert res.success is False
        assert "App Bundles (.aab" in (res.error_message or "")
        mock_runner.run_task.assert_not_called()

    def test_prebuild_signing_missing_env_halts_before_gradle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ks = tmp_path / "release.jks"
        ks.write_bytes(b"keystore")
        monkeypatch.delenv("MISSING_KS_PASS", raising=False)

        cfg = AppShieldConfig(
            version="1.0",
            project_name="missing_env_app",
            platform="android",
            input=InputConfig(project_dir=UNRELATED_FIXTURE_DIR),
            output=OutputConfig(dir=tmp_path / "dist"),
            android=AndroidConfig(
                signing=SigningConfig(
                    enabled=True,
                    is_production=False,
                    keystore_path=ks,
                    key_alias="test_alias",
                    keystore_password_env="MISSING_KS_PASS",
                )
            ),
        )
        mock_runner = MagicMock()
        res = AndroidPipelineAdapter().stage_and_protect(cfg, runner=mock_runner)
        assert res.success is False
        assert "MISSING_KS_PASS" in (res.error_message or "")
        mock_runner.run_task.assert_not_called()

    def test_prebuild_production_signing_blocked_before_gradle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ks = tmp_path / "prod.jks"
        ks.write_bytes(b"prod-keystore")
        monkeypatch.setenv("PROD_KS_PASS", "super-secret")

        cfg = AppShieldConfig(
            version="1.0",
            project_name="prod_gate_app",
            platform="android",
            input=InputConfig(project_dir=UNRELATED_FIXTURE_DIR),
            output=OutputConfig(dir=tmp_path / "dist"),
            android=AndroidConfig(
                signing=SigningConfig(
                    enabled=True,
                    is_production=True,
                    keystore_path=ks,
                    key_alias="prod",
                    keystore_password_env="PROD_KS_PASS",
                )
            ),
        )
        mock_runner = MagicMock()
        res = AndroidPipelineAdapter().stage_and_protect(
            cfg, runner=mock_runner, allow_production_signing=False
        )
        assert res.success is False
        assert "--allow-production-signing" in (res.error_message or "")
        mock_runner.run_task.assert_not_called()

    def test_missing_mapping_output_produces_actionable_failure(
        self, tmp_path: Path
    ) -> None:
        cfg = AppShieldConfig(
            version="1.0",
            project_name="no_map_app",
            platform="android",
            input=InputConfig(project_dir=UNRELATED_FIXTURE_DIR),
            output=OutputConfig(dir=tmp_path / "dist"),
        )
        mock_runner = MagicMock()
        mock_runner.is_simulated = False

        def fake_no_map(task: str, **kwargs: object) -> GradleBuildResult:
            apk = (
                mock_runner.project_dir
                / "mobile"
                / "build"
                / "outputs"
                / "apk"
                / "release"
                / "mobile-release-unsigned.apk"
            )
            _build_apk(apk, classes=["a.a", "org.acme.ledger.LedgerHomeActivity"])
            return GradleBuildResult(
                success=True,
                exit_code=0,
                stdout="OK",
                stderr="",
                duration_seconds=1.0,
                command=["gradlew", task],
                apk_path=apk,
                mapping_file=None,
            )

        mock_runner.run_task.side_effect = fake_no_map
        res = AndroidPipelineAdapter().stage_and_protect(cfg, runner=mock_runner)
        assert res.success is False
        assert "mapping.txt" in (res.error_message or "")
        assert res.metadata.get("error_type") == "MissingMappingFile"


class TestStructuredCliErrorHandling:
    """Task 2: Runtime failures render clean errors without tracebacks & preserve source/cleanup."""

    def _write_cfg(self, tmp_path: Path, proj_dir: Path, dist_dir: Path) -> Path:
        cfg = tmp_path / "appshield.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "err_test",
                    "platform": "android",
                    "input": {"project_dir": str(proj_dir)},
                    "output": {"dir": str(dist_dir)},
                }
            ),
            encoding="utf-8",
        )
        return cfg

    def test_cli_protect_handles_gradle_timeout_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        proj_copy = tmp_path / "proj"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        before_hashes = _snapshot_tree_hashes(proj_copy)
        dist_dir = tmp_path / "dist"
        cfg_file = self._write_cfg(tmp_path, proj_copy, dist_dir)

        staged_dirs: list[Path] = []

        def fake_timeout(self: Any, task: str, **kwargs: object) -> GradleBuildResult:
            staged_dirs.append(self.project_dir)
            raise GradleTimeoutError(
                "Timed out after 300s",
                timeout_seconds=300.0,
                command=["gradlew", task],
            )

        with (
            patch(
                "appshield.cli.run_doctor_checks",
                return_value=[ToolReport("Java", True, "17", True, "")],
            ),
            patch(
                "appshield.adapters.android.AndroidPipelineAdapter.check_prerequisites",
                return_value=[],
            ),
            patch("appshield.adapters.android.GradleRunner.run_task", fake_timeout),
        ):
            code = main(["protect", "-c", str(cfg_file)])

        assert code == 1
        err = capsys.readouterr().err
        assert "Protection FAILED:" in err
        assert "Timed out after 300s" in err
        assert "Traceback" not in err
        assert len(staged_dirs) == 1
        assert not staged_dirs[0].exists()
        assert _snapshot_tree_hashes(proj_copy) == before_hashes

    def test_cli_protect_handles_gradle_exception_and_offline_hint(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")
        monkeypatch.setenv("TEST_SIGN_SECRET", "top_secret_val_999")

        cfg_file = tmp_path / "appshield.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "offline_fail",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "android": {
                        "offline": True,
                        "signing": {
                            "enabled": True,
                            "is_production": False,
                            "keystore_path": str(ks),
                            "key_alias": "k",
                            "keystore_password_env": "TEST_SIGN_SECRET",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )

        def fake_exec_error(
            self: Any, task: str, **kwargs: object
        ) -> GradleBuildResult:
            raise GradleExecutionError(
                "Gradle build failed with exit code 1 (token top_secret_val_999)",
                exit_code=1,
                command=["gradlew", task, "--offline"],
                stderr="Plugin [id: 'com.android.application'] was not found in any of the following sources: --offline",
            )

        with (
            patch(
                "appshield.cli.run_doctor_checks",
                return_value=[ToolReport("Java", True, "17", True, "")],
            ),
            patch(
                "appshield.adapters.android.AndroidPipelineAdapter.check_prerequisites",
                return_value=[],
            ),
            patch("appshield.adapters.android.GradleRunner.run_task", fake_exec_error),
        ):
            code = main(["protect", "-c", str(cfg_file)])

        assert code == 1
        err = capsys.readouterr().err
        assert "--allow-network-dependencies" in err
        assert "top_secret_val_999" not in err
        assert "Traceback" not in err

    def test_cli_protect_handles_missing_apk_output_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg_file = self._write_cfg(tmp_path, UNRELATED_FIXTURE_DIR, tmp_path / "dist")

        def fake_missing_apk(*args: object, **kwargs: object) -> Path:
            raise ArtifactExtractionError("No APK found in release output")

        with (
            patch(
                "appshield.cli.run_doctor_checks",
                return_value=[ToolReport("Java", True, "17", True, "")],
            ),
            patch(
                "appshield.adapters.android.AndroidPipelineAdapter.check_prerequisites",
                return_value=[],
            ),
            patch(
                "appshield.adapters.android.GradleRunner.run_task",
                return_value=GradleBuildResult(
                    success=True,
                    exit_code=0,
                    stdout="OK",
                    stderr="",
                    duration_seconds=1.0,
                    command=["gradlew", "assembleRelease"],
                ),
            ),
            patch(
                "appshield.adapters.android.locate_build_apk",
                side_effect=fake_missing_apk,
            ),
        ):
            code = main(["protect", "-c", str(cfg_file)])

        assert code == 1
        err = capsys.readouterr().err
        assert "No APK found in release output" in err
        assert "Traceback" not in err

    def test_cli_protect_handles_source_immutability_error_cleanly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg_file = self._write_cfg(tmp_path, UNRELATED_FIXTURE_DIR, tmp_path / "dist")

        with (
            patch(
                "appshield.cli.run_doctor_checks",
                return_value=[ToolReport("Java", True, "17", True, "")],
            ),
            patch(
                "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
                side_effect=SourceImmutabilityError("Source file checksum mismatch"),
            ),
        ):
            code = main(["protect", "-c", str(cfg_file)])

        assert code == 1
        err = capsys.readouterr().err
        assert "SourceImmutabilityError" in err
        assert "Traceback" not in err


class TestVerificationConfigEnforcement:
    """Task 4: VerificationConfig enabled, checks, unknown checks, and anti-bypass."""

    def test_defaults_match_readme_and_unknown_check_raises(
        self, tmp_path: Path
    ) -> None:
        cfg_file = tmp_path / "defaults.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "defaults_app",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                }
            ),
            encoding="utf-8",
        )
        loaded = load_config(cfg_file)
        assert loaded.verification.enabled is True
        assert loaded.verification.fail_on_check_failure is True
        assert loaded.verification.checks == list(CANONICAL_VERIFICATION_CHECKS)

        bad_cfg = tmp_path / "bad_checks.yaml"
        bad_cfg.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "bad_checks_app",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "verification": {
                        "checks": ["symbol_renaming_ratio", "made_up_check"]
                    },
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(ConfigValidationError, match="Unknown verification check"):
            load_config(bad_cfg)

    def test_disabled_verification_marks_all_skipped_and_never_verified(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        mapping = tmp_path / "mapping.txt"
        mapping.write_text("org.acme.Foo -> a.a:\n", encoding="utf-8")

        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=1.0,
            command=["gradlew"],
            apk_path=apk,
            mapping_file=mapping,
        )
        engine = VerificationEngine(project_name="disabled_test")
        report = engine.run_all_checks(
            apk_path=apk,
            mapping_file=mapping,
            build_result=build_res,
            is_real_build=True,
            verification_config=VerificationConfig(enabled=False),
        )
        assert report.is_verified_protected is False
        assert report.summary["skipped"] == 7
        assert all(c.status == "SKIPPED" for c in report.objective_checks)

    def test_mandatory_check_exclusion_prevents_verified_protected(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        mapping = tmp_path / "mapping.txt"
        mapping.write_text("org.acme.Foo -> a.a:\n", encoding="utf-8")
        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=1.0,
            command=["gradlew"],
            apk_path=apk,
            mapping_file=mapping,
        )
        engine = VerificationEngine()
        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            # Skipping mandatory CHK-SYM-01 cannot claim Verified Protected
            report_no_sym = engine.run_all_checks(
                apk_path=apk,
                mapping_file=mapping,
                build_result=build_res,
                is_real_build=True,
                verification_config=VerificationConfig(
                    enabled=True,
                    checks=[
                        "build_execution",
                        "apk_structure",
                        "package_alignment",
                    ],
                ),
            )
            assert report_no_sym.is_verified_protected is False
            sym = next(
                c for c in report_no_sym.objective_checks if c.check_id == "CHK-SYM-01"
            )
            assert sym.status == "SKIPPED"

            # Skipping only optional checks allows Verified Protected when mandatory checks pass
            report_optional_skipped = engine.run_all_checks(
                apk_path=apk,
                mapping_file=mapping,
                build_result=build_res,
                is_real_build=True,
                verification_config=VerificationConfig(
                    enabled=True,
                    checks=[
                        "build_execution",
                        "apk_structure",
                        "symbol_renaming_ratio",
                        "package_alignment",
                    ],
                ),
            )
            assert report_optional_skipped.is_verified_protected is True
            str_chk = next(
                c
                for c in report_optional_skipped.objective_checks
                if c.check_id == "CHK-STR-01"
            )
            assert str_chk.status == "SKIPPED"

    def test_cli_verify_honors_config_checks_and_fail_on_check_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(tmp_path / "unaligned.apk", classes=["a.a"])
        cfg_strict = tmp_path / "strict.yaml"
        cfg_strict.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "strict_app",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "verification": {
                        "enabled": True,
                        "fail_on_check_failure": True,
                        "checks": ["apk_structure", "package_alignment"],
                    },
                }
            ),
            encoding="utf-8",
        )
        cfg_lenient = tmp_path / "lenient.yaml"
        cfg_lenient.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "lenient_app",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "verification": {
                        "enabled": True,
                        "fail_on_check_failure": False,
                        "checks": ["apk_structure", "package_alignment"],
                    },
                }
            ),
            encoding="utf-8",
        )

        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=False),
        ):
            code_strict = main(["verify", str(apk), "-c", str(cfg_strict)])
            code_lenient = main(["verify", str(apk), "-c", str(cfg_lenient)])

        assert code_strict == 1
        assert code_lenient == 1
        out = capsys.readouterr().out
        assert "[SKIPPED] CHK-SYM-01" in out
        assert "REJECTED" in out


class TestDoctorAccuracyAndOfflineCache:
    """Task 3: Honest doctor reporting + non-networked Gradle cache detection."""

    def test_doctor_removes_fake_live_build_zero_and_shows_uncached_guidance(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_reports = [
            ToolReport("Java Runtime (java)", True, "17.0.9", True, ""),
            ToolReport("Gradle Build Tool", True, "Gradle 8.2", True, ""),
        ]
        uncached = [
            ToolReport(
                "Gradle Offline Cache (AGP)",
                False,
                None,
                False,
                "Run with '--allow-network-dependencies'",
                target_version="com.android.tools.build:gradle",
            ),
            ToolReport(
                "Gradle Offline Cache (R8)",
                False,
                None,
                False,
                "Run with '--allow-network-dependencies'",
                target_version="com.android.tools:r8",
            ),
        ]
        with (
            patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
            patch(
                "appshield.cli.get_offline_dependency_cache_reports",
                return_value=uncached,
            ),
        ):
            code = main(["doctor"])

        assert code == 0
        out = capsys.readouterr().out
        assert "Live Builds Validated" not in out
        assert "has not yet been validated" not in out
        assert "[NOT CACHED] Gradle Offline Cache (AGP)" in out
        assert "--allow-network-dependencies" in out

    def test_doctor_detects_cached_agp_and_r8_without_network(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        gradle_home = tmp_path / "gradle_home"
        (
            gradle_home
            / "caches"
            / "modules-2"
            / "files-2.1"
            / "com.android.tools.build"
            / "gradle"
            / "8.2.2"
        ).mkdir(parents=True)
        (
            gradle_home
            / "caches"
            / "modules-2"
            / "files-2.1"
            / "com.android.tools"
            / "r8"
            / "8.2.47"
        ).mkdir(parents=True)
        monkeypatch.setenv("GRADLE_USER_HOME", str(gradle_home))

        with patch(
            "appshield.cli.run_doctor_checks",
            return_value=[ToolReport("Java Runtime (java)", True, "17", True, "")],
        ):
            code = main(["doctor"])

        assert code == 0
        out = capsys.readouterr().out
        assert "[OK]         Gradle Offline Cache (AGP)" in out
        assert "[OK]         Gradle Offline Cache (R8)" in out

    def test_doctor_flags_dontobfuscate_on_project_dir(self, tmp_path: Path) -> None:
        proj = tmp_path / "bad_r8"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj)
        (proj / "mobile" / "proguard-rules.pro").write_text(
            "-dontobfuscate\n", encoding="utf-8"
        )
        reports = run_doctor_checks(project_dir=proj)
        r8_rep = next(
            r for r in reports if r.name == "Android Release R8 Configuration"
        )
        assert r8_rep.is_available is False
        assert "-dontobfuscate" in r8_rep.remediation_hint


class TestSigningSubprocessIsolation:
    """Task 6: Sanitized subprocess env & keytool env-var password passing."""

    def test_generate_disposable_keystore_uses_env_and_sanitized_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "unrelated_host_aws_secret")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_unrelatedtokenvalue")

        ks = tmp_path / "disp.jks"
        fake_keytool = tmp_path / "keytool"
        fake_keytool.write_text("tool", encoding="utf-8")

        captured_cmd: list[str] = []
        captured_env: dict[str, str] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
            nonlocal captured_cmd, captured_env
            captured_cmd = list(cmd)
            captured_env = dict(kwargs["env"])
            ks.write_bytes(b"generated_ks")
            proc = MagicMock()
            proc.returncode = 0
            return proc

        with patch("subprocess.run", side_effect=fake_run):
            generate_disposable_test_keystore(
                ks,
                password="SecretDisposablePass_42",
                keytool_path=fake_keytool,
            )

        assert "-storepass:env" in captured_cmd
        assert "-keypass:env" in captured_cmd
        assert "-storepass" not in captured_cmd
        assert "-keypass" not in captured_cmd
        assert "SecretDisposablePass_42" not in " ".join(captured_cmd)
        assert "AWS_SECRET_ACCESS_KEY" not in captured_env
        assert "GITHUB_TOKEN" not in captured_env
        assert "SecretDisposablePass_42" in captured_env.values()
        # Parent os.environ must not be polluted with temporary pass vars
        assert not any(k.startswith("APPSHIELD_KEYTOOL_PASS_") for k in os.environ)

    def test_signing_and_alignment_subprocesses_strip_unrelated_secrets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UNRELATED_API_TOKEN", "should_not_leak")
        monkeypatch.setenv("SIGNING_KS_PASS", "allowed_ks_secret")
        monkeypatch.setenv("SIGNING_KEY_PASS", "allowed_key_secret")

        apk_in = _build_apk(tmp_path / "in.apk", classes=["a.a"])
        apk_aligned = tmp_path / "aligned.apk"
        apk_signed = tmp_path / "signed.apk"
        ks = tmp_path / "ks.jks"
        ks.write_bytes(b"ks")
        fake_tool = tmp_path / "tool"
        fake_tool.write_text("tool", encoding="utf-8")

        seen_envs: list[dict[str, str]] = []

        def fake_sub(cmd: list[str], **kwargs: Any) -> MagicMock:
            seen_envs.append(dict(kwargs["env"]))
            if str(apk_aligned) in cmd:
                _build_apk(apk_aligned, classes=["a.a"])
            if str(apk_signed) in cmd:
                _build_apk(apk_signed, classes=["a.a"])
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = "Verifies\n"
            proc.stderr = ""
            return proc

        with patch("subprocess.run", side_effect=fake_sub):
            zipalign_apk(apk_in, apk_aligned, zipalign_path=fake_tool)
            verify_zipalign(apk_aligned, zipalign_path=fake_tool)
            sign_apk(
                apk_aligned,
                apk_signed,
                keystore_path=ks,
                key_alias="a",
                keystore_password_env="SIGNING_KS_PASS",
                key_password_env="SIGNING_KEY_PASS",
                apksigner_path=fake_tool,
            )
            verify_apk_signature(apk_signed, apksigner_path=fake_tool)

        assert len(seen_envs) == 4
        # zipalign / verify_zipalign / verify_apk_signature strip ALL signing & host secrets
        for idx in (0, 1, 3):
            assert "UNRELATED_API_TOKEN" not in seen_envs[idx]
            assert "SIGNING_KS_PASS" not in seen_envs[idx]
            assert "SIGNING_KEY_PASS" not in seen_envs[idx]
        # sign_apk preserves only the explicitly configured signing password vars
        assert "UNRELATED_API_TOKEN" not in seen_envs[2]
        assert seen_envs[2].get("SIGNING_KS_PASS") == "allowed_ks_secret"
        assert seen_envs[2].get("SIGNING_KEY_PASS") == "allowed_key_secret"
