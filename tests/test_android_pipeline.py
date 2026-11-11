"""
End-to-End Integration Test Matrix for AppShield Android Protection Pipeline (Plan 04-04).
Validates the complete protection lifecycle against the repo-owned fixture:
  - Toolchain discovery and safe prerequisite verification.
  - Staging isolation and R8 protection rule injection.
  - Gradle build execution and error/timeout handling.
  - Output artifact discovery, validation, alignment, and signing.
  - Empirical verification engine execution across all 7 checks.
  - Release acceptance gate and simulation barrier enforcement.
  - Source tree immutability verification.
  - Credential isolation and audit report export.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from appshield.adapters.android import AndroidPipelineAdapter
from appshield.adapters.base import PrerequisiteCheck, ProtectionResult
from appshield.cli import main
from appshield.config import (
    AppShieldConfig,
    InputConfig,
    OutputConfig,
    OverwriteError,
    SigningConfig,
)
from appshield.dex import create_synthetic_dex
from appshield.doctor import ToolReport
from appshield.gradle import (
    GradleBuildResult,
)
from appshield.sandbox import SourceImmutabilityError
from appshield.signing import SigningResult

FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "sample_android_gradle_project"
).resolve()

SAMPLE_MAPPING_CONTENT = """
# compiler: R8
# compiler_version: 8.2.2
com.appshield.sample.IdentifiableSecretService -> a.a:
    java.lang.String secretToken -> a
    void <init>() -> <init>
    1:3:java.lang.String processUserTokenAndCalculateHash(java.lang.String) -> a
com.appshield.sample.PaymentSecurityValidator -> a.b:
    1:2:boolean validateTransactionToken(java.lang.String) -> a
com.appshield.sample.MainActivity -> com.appshield.sample.MainActivity:
    1:5:void onCreate(android.os.Bundle) -> onCreate
"""


def create_valid_test_apk(
    path: Path,
    classes: list[str] | None = None,
    strings: list[str] | None = None,
) -> Path:
    """Helper to create a valid synthetic Android APK archive with proper DEX bytecode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    dex_classes = classes or ["a.a", "a.b", "com.appshield.sample.MainActivity"]
    dex_strings = strings or ["hello", "world"]
    dex_bytes = create_synthetic_dex(classes=dex_classes, strings=dex_strings)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy-manifest/>")
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("resources.arsc", b"<dummy-resources/>")
    return path


def setup_mock_gradle_success(
    mock_runner: MagicMock,
    classes: list[str] | None = None,
    mapping_text: str = SAMPLE_MAPPING_CONTENT,
) -> None:
    """Configure mock Gradle runner to produce valid build outputs."""
    mock_runner.is_simulated = False

    def fake_run(tasks: str, **kwargs: object) -> GradleBuildResult:
        staging = mock_runner.project_dir
        apk_path = (
            staging
            / "app"
            / "build"
            / "outputs"
            / "apk"
            / "release"
            / "app-release-unsigned.apk"
        )
        create_valid_test_apk(apk_path, classes=classes)

        mapping_file = (
            staging
            / "app"
            / "build"
            / "outputs"
            / "mapping"
            / "release"
            / "mapping.txt"
        )
        mapping_file.parent.mkdir(parents=True, exist_ok=True)
        mapping_file.write_text(mapping_text, encoding="utf-8")

        return GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="BUILD SUCCESSFUL in 2s",
            stderr="",
            duration_seconds=2.0,
            command=["gradlew", tasks],
            apk_path=apk_path,
            mapping_file=mapping_file,
            is_simulated=False,
            metadata={"build_id": "test-build-1"},
        )

    mock_runner.run_task.side_effect = fake_run


class TestProtectionPipelineLifecycle:
    """Tests the full end-to-end protection pipeline lifecycle and verification."""

    def test_full_lifecycle_success_and_artifact_export(self, tmp_path: Path):
        """
        Verify complete protection workflow:
          1. Project validation against fixture.
          2. Isolated staging copy.
          3. R8 protection rule injection.
          4. Gradle execution in sandbox.
          5. Release APK and mapping discovery.
          6. Alignment and test signing.
          7. Empirical verification checks.
          8. Audit report generation (JSON and MD).
          9. Source immutability check.
          10. Release acceptance and export to dist.
        """
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR, verify_source_immutability=True),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is True
        assert result.is_verified_protected is True
        assert result.protected_artifact_path is not None
        assert result.protected_artifact_path.is_file()
        assert (
            result.protected_artifact_path.name
            == "sample_android_gradle_project-release-protected.apk"
        )

        # Verify audit reports exist and are valid
        audit_json = dist_dir / "audit_report.json"
        audit_md = dist_dir / "audit_report.md"
        assert audit_json.is_file()
        assert audit_md.is_file()

        data = json.loads(audit_json.read_text(encoding="utf-8"))
        assert data["audit_version"] == "1.0"
        assert data["is_verified_protected"] is True
        assert data["summary"]["failed"] == 0
        assert data["summary"]["passed"] >= 3

        # Verify no raw mapping in public output directory
        assert not (dist_dir / "mapping.txt").exists()

    def test_mapping_out_retention(self, tmp_path: Path):
        """Verify --mapping-out securely copies mapping.txt to user-specified path."""
        dist_dir = tmp_path / "dist"
        retained_mapping = tmp_path / "secure_vault" / "retained_mapping.txt"

        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                mapping_out=retained_mapping,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is True
        assert retained_mapping.is_file()
        assert (
            "com.appshield.sample.IdentifiableSecretService -> a.a:"
            in retained_mapping.read_text(encoding="utf-8")
        )
        # Ensure public output does NOT have mapping
        assert not (dist_dir / "mapping.txt").exists()


class TestSimulationBarrier:
    """Validates strict boundary between simulation/mocking and production builds."""

    def test_simulated_runner_rejected_in_production(self, tmp_path: Path):
        """Simulated runner without explicit allow_simulated flag must be rejected."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        mock_runner.is_simulated = True

        adapter = AndroidPipelineAdapter()
        result = adapter.stage_and_protect(
            config=config, runner=mock_runner, allow_simulated=False
        )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None
        assert "Simulated execution is forbidden" in (result.error_message or "")
        # Output directory must not have protected artifacts
        assert not (
            dist_dir / "sample_android_gradle_project-release-protected.apk"
        ).exists()

    def test_simulated_build_result_suppresses_artifact_export(self, tmp_path: Path):
        """Even with allow_simulated=True, simulated artifacts must NEVER be exported."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        mock_runner.is_simulated = True

        def fake_run(tasks: str, **kwargs: object) -> GradleBuildResult:
            staging = mock_runner.project_dir
            apk_path = (
                staging
                / "app"
                / "build"
                / "outputs"
                / "apk"
                / "release"
                / "app-release-unsigned.apk"
            )
            create_valid_test_apk(apk_path)
            mapping_file = (
                staging
                / "app"
                / "build"
                / "outputs"
                / "mapping"
                / "release"
                / "mapping.txt"
            )
            mapping_file.parent.mkdir(parents=True, exist_ok=True)
            mapping_file.write_text(SAMPLE_MAPPING_CONTENT, encoding="utf-8")
            return GradleBuildResult(
                success=True,
                exit_code=0,
                stdout="SIMULATED BUILD",
                stderr="",
                duration_seconds=0.1,
                command=["gradlew", tasks],
                apk_path=apk_path,
                mapping_file=mapping_file,
                is_simulated=True,
            )

        mock_runner.run_task.side_effect = fake_run

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config, runner=mock_runner, allow_simulated=True
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None
        assert "Simulated build artifacts are strictly prohibited" in (
            result.error_message or ""
        )
        assert not (
            dist_dir / "sample_android_gradle_project-release-protected.apk"
        ).exists()


class TestReleaseAcceptanceGate:
    """Tests that verification failures block protected artifact export."""

    def test_unobfuscated_symbols_blocks_export(self, tmp_path: Path):
        """If target fixture classes were NOT renamed, CHK-SYM-01 fails and export is blocked."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        # Mapping keeps original names unrenamed
        unrenamed_mapping = """
com.appshield.sample.IdentifiableSecretService -> com.appshield.sample.IdentifiableSecretService:
com.appshield.sample.PaymentSecurityValidator -> com.appshield.sample.PaymentSecurityValidator:
com.appshield.sample.MainActivity -> com.appshield.sample.MainActivity:
"""
        setup_mock_gradle_success(
            mock_runner,
            classes=[
                "com.appshield.sample.IdentifiableSecretService",
                "com.appshield.sample.PaymentSecurityValidator",
                "com.appshield.sample.MainActivity",
            ],
            mapping_text=unrenamed_mapping,
        )

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(
                    final_apk,
                    classes=[
                        "com.appshield.sample.IdentifiableSecretService",
                        "com.appshield.sample.PaymentSecurityValidator",
                        "com.appshield.sample.MainActivity",
                    ],
                )
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None
        assert not (
            dist_dir / "sample_android_gradle_project-release-protected.apk"
        ).exists()

    def test_missing_dex_classes_blocks_export(self, tmp_path: Path):
        """If mapped classes are completely missing from compiled DEX, verification fails."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        # APK only has MainActivity, missing a.a and a.b
        setup_mock_gradle_success(
            mock_runner,
            classes=["com.appshield.sample.MainActivity"],
        )

        adapter = AndroidPipelineAdapter()

        with patch("appshield.adapters.android.align_and_sign_apk") as mock_sign:

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(
                    final_apk, classes=["com.appshield.sample.MainActivity"]
                )
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None

    def test_unsupported_zipalign_blocks_verified_protected(self, tmp_path: Path):
        """If zipalign is missing, CHK-ALN-01 is SKIPPED and release export is blocked."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=None),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=False,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None
        assert not (
            dist_dir / "sample_android_gradle_project-release-protected.apk"
        ).exists()

    def test_unsupported_signature_verification_blocks_verified_protected(
        self, tmp_path: Path
    ):
        """If signing is enabled but apksigner is missing, CHK-SIG-01 is SKIPPED and export is blocked."""
        dist_dir = tmp_path / "dist"
        from appshield.config import AndroidConfig

        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
            android=AndroidConfig(signing=SigningConfig(enabled=True)),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
            patch("appshield.verify.find_apksigner", return_value=None),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-signed.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="test_signed",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None
        assert not (
            dist_dir / "sample_android_gradle_project-release-protected.apk"
        ).exists()

    def test_inconclusive_check_blocks_verified_protected(self, tmp_path: Path):
        """If any check produces INCONCLUSIVE status, is_verified_protected must be False."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        from appshield.verify import (
            ObjectiveCheckResult,
            VerificationEngine,
            VerificationReport,
        )

        real_run_all = VerificationEngine.run_all_checks

        def fake_run_all(*args: Any, **kwargs: Any) -> VerificationReport:
            dummy_engine = VerificationEngine()
            report = real_run_all(dummy_engine, *args, **kwargs)  # type: ignore[arg-type]
            inconclusive_check = ObjectiveCheckResult(
                check_id="CHK-HEUR-01",
                name="Heuristic Check",
                category="heuristics",
                outcome="HEURISTIC",
                status="INCONCLUSIVE",
                what_it_proves="Nothing",
                what_it_does_not_prove="Everything",
                observed_metric="Inconclusive",
            )
            return VerificationReport(
                audit_version=report.audit_version,
                project_name=report.project_name,
                generated_at=report.generated_at,
                artifact=report.artifact,
                summary={
                    **report.summary,
                    "inconclusive": report.summary.get("inconclusive", 0) + 1,
                },
                objective_checks=report.objective_checks + [inconclusive_check],
                is_verified_protected=False,
                disclaimer=report.disclaimer,
            )

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
            patch(
                "appshield.adapters.android.VerificationEngine.run_all_checks",
                side_effect=fake_run_all,
            ),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            result = adapter.stage_and_protect(
                config=config,
                runner=mock_runner,
                expected_fixture_classes=[
                    "com.appshield.sample.IdentifiableSecretService",
                    "com.appshield.sample.PaymentSecurityValidator",
                ],
                expected_entry_points=["com.appshield.sample.MainActivity"],
            )

        assert result.success is False
        assert result.is_verified_protected is False
        assert result.protected_artifact_path is None


class TestErrorAndSecurityEdgeCases:
    """Tests failure recovery, overwrite safeguards, and security borders."""

    def test_gradle_build_failure(self, tmp_path: Path):
        """Non-zero Gradle return code stops the pipeline and logs error."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        mock_runner.is_simulated = False
        mock_runner.run_task.return_value = GradleBuildResult(
            success=False,
            exit_code=1,
            stdout="",
            stderr="Compilation error in MainActivity.java:42",
            duration_seconds=1.2,
            command=["gradlew", "assembleRelease"],
            is_simulated=False,
        )

        adapter = AndroidPipelineAdapter()
        result = adapter.stage_and_protect(config=config, runner=mock_runner)

        assert result.success is False
        assert result.protected_artifact_path is None
        assert "failed (exit code 1)" in (result.error_message or "")
        assert not dist_dir.exists() or len(list(dist_dir.iterdir())) == 0

    def test_destination_overwrite_protection(self, tmp_path: Path):
        """Enforces overwrite guard when target APK already exists without --overwrite."""
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        existing = dist_dir / "sample_android_gradle_project-release-protected.apk"
        existing.write_text("existing APK bytes", encoding="utf-8")

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
            adapter.stage_and_protect(config=config, runner=mock_runner)

    def test_source_tree_immutability_violation_detection(self, tmp_path: Path):
        """If source tree is tampered with during build, SourceImmutabilityError is raised."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR, verify_source_immutability=True),
            output=OutputConfig(dir=dist_dir),
        )

        mock_runner = MagicMock()
        setup_mock_gradle_success(mock_runner)

        adapter = AndroidPipelineAdapter()

        with (
            patch("appshield.adapters.android.align_and_sign_apk") as mock_sign,
            patch(
                "appshield.sandbox.SandboxManager.verify_source_integrity",
                side_effect=SourceImmutabilityError("Source tree modified"),
            ),
        ):

            def fake_signing(
                unsigned_apk: Path, output_dir: Path, **kwargs: object
            ) -> SigningResult:
                final_apk = output_dir / "app-release-unsigned-aligned.apk"
                create_valid_test_apk(final_apk)
                return SigningResult(
                    success=True,
                    signature_type="unsigned",
                    aligned_apk_path=final_apk,
                    final_apk_path=final_apk,
                    is_aligned=True,
                )

            mock_sign.side_effect = fake_signing

            with pytest.raises(SourceImmutabilityError):
                adapter.stage_and_protect(config=config, runner=mock_runner)

    def test_missing_toolchain_prerequisites_halt(self, tmp_path: Path):
        """If host lacks required prerequisites, pipeline stops cleanly."""
        dist_dir = tmp_path / "dist"
        config = AppShieldConfig(
            version="1.0",
            project_name="sample_android_gradle_project",
            platform="android",
            input=InputConfig(project_dir=FIXTURE_DIR),
            output=OutputConfig(dir=dist_dir),
        )

        adapter = AndroidPipelineAdapter()
        missing_prereqs = [
            PrerequisiteCheck(
                tool_name="Gradle Build Tool",
                is_available=False,
                detected_version=None,
                target_version="8.2",
                required=True,
                remediation_hint="Install Gradle 8.2 or configure wrapper.",
                validated_live=False,
            )
        ]
        with patch.object(adapter, "check_prerequisites", return_value=missing_prereqs):
            result = adapter.stage_and_protect(config=config, runner=None)

        assert result.success is False
        assert "missing required toolchain prerequisites" in (
            result.error_message or ""
        )


class TestCliEndToEndFlow:
    """Validates CLI protect and verify commands in sequence."""

    def test_cli_protect_and_verify_e2e(self, tmp_path: Path, capsys):
        """Run `appshield protect` followed by `appshield verify` via CLI."""
        dist_dir = tmp_path / "dist"
        cfg_file = tmp_path / "appshield.json"
        cfg_file.write_text(
            f"""{{
            "version": "1.0",
            "project_name": "sample_android_gradle_project",
            "platform": "android",
            "input": {{ "project_dir": "{FIXTURE_DIR.as_posix()}" }},
            "output": {{ "dir": "{dist_dir.as_posix()}" }}
        }}""",
            encoding="utf-8",
        )

        mock_reports = [
            ToolReport("Java Runtime (java)", True, "17.0.2", True, ""),
            ToolReport("JAVA_HOME Variable", True, "/usr/lib/jvm/default", True, ""),
            ToolReport("Gradle Build Tool", True, "gradlew", True, ""),
        ]

        target_apk = dist_dir / "sample_android_gradle_project-release-protected.apk"
        mapping_file = tmp_path / "retained_mapping.txt"

        def fake_stage(*args: object, **kwargs: object) -> ProtectionResult:
            mapping_file.write_text(SAMPLE_MAPPING_CONTENT, encoding="utf-8")
            create_valid_test_apk(target_apk)
            return ProtectionResult(
                success=True,
                protected_artifact_path=target_apk,
                logs=["Build completed", "Verification passed"],
                is_verified_protected=True,
            )

        with (
            patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
            patch(
                "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
                side_effect=fake_stage,
            ),
        ):
            code_protect = main(
                [
                    "protect",
                    "-c",
                    str(cfg_file),
                    "--mapping-out",
                    str(mapping_file),
                ]
            )

        assert code_protect == 0
        captured_protect = capsys.readouterr()
        assert "Protection SUCCEEDED" in captured_protect.out

        # Now verify the generated artifact with appshield verify
        audit_out = tmp_path / "verify_audit.json"
        with (
            patch(
                "appshield.verify.find_zipalign", return_value=Path("/mock/zipalign")
            ),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            code_verify = main(
                [
                    "verify",
                    str(target_apk),
                    "-m",
                    str(mapping_file),
                    "-o",
                    str(audit_out),
                ]
            )

        assert code_verify == 0
        captured_verify = capsys.readouterr()
        assert "AppShield Empirical Verification Report" in captured_verify.out
        assert "CHK-SYM-01" in captured_verify.out
        assert audit_out.is_file()

    def test_cli_protect_refuses_mapping_out_overwrite(self, tmp_path: Path, capsys):
        """CLI protect refuses to silently overwrite an existing mapping file."""
        dist_dir = tmp_path / "dist"
        cfg_file = tmp_path / "appshield.json"
        existing_mapping = tmp_path / "existing_mapping.txt"
        existing_mapping.write_text("existing content", encoding="utf-8")

        cfg_file.write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "project_name": "sample_android_gradle_project",
                    "platform": "android",
                    "input": {"project_dir": str(FIXTURE_DIR)},
                    "output": {"dir": str(dist_dir), "overwrite_existing": False},
                }
            ),
            encoding="utf-8",
        )

        code = main(
            [
                "protect",
                "-c",
                str(cfg_file),
                "--mapping-out",
                str(existing_mapping),
            ]
        )
        assert code == 1
        captured = capsys.readouterr()
        assert "Overwrite Protection Error" in captured.err
        assert "Destination mapping file already exists" in captured.err
        assert existing_mapping.read_text(encoding="utf-8") == "existing content"

    def test_cli_protect_allows_mapping_out_overwrite_with_flag(
        self, tmp_path: Path, capsys
    ):
        """CLI protect allows overwriting existing mapping file when --overwrite is passed."""
        dist_dir = tmp_path / "dist"
        cfg_file = tmp_path / "appshield.json"
        existing_mapping = tmp_path / "existing_mapping.txt"
        existing_mapping.write_text("existing content", encoding="utf-8")

        cfg_file.write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "project_name": "sample_android_gradle_project",
                    "platform": "android",
                    "input": {"project_dir": str(FIXTURE_DIR)},
                    "output": {"dir": str(dist_dir), "overwrite_existing": False},
                }
            ),
            encoding="utf-8",
        )

        mock_reports = [
            ToolReport("Java Runtime (java)", True, "17.0.21", True, ""),
            ToolReport("Android SDK Platform 34", True, "34", True, ""),
            ToolReport("Android SDK Build-Tools 34.0.0", True, "34.0.0", True, ""),
            ToolReport("Gradle Build Tool", True, "8.2", True, ""),
        ]

        def fake_stage(
            config: Any,
            mapping_out: Path | None = None,
            **kwargs: Any,
        ) -> ProtectionResult:
            if mapping_out:
                mapping_out.write_text(SAMPLE_MAPPING_CONTENT, encoding="utf-8")
            target_apk = (
                config.output.dir
                / f"{config.project_name}-{config.android.build_variant}-protected.apk"
            )
            create_valid_test_apk(target_apk)
            return ProtectionResult(
                success=True,
                protected_artifact_path=target_apk,
                logs=["Stage and protect succeeded"],
                verification_report=None,
            )

        with (
            patch("appshield.cli.run_doctor_checks", return_value=mock_reports),
            patch(
                "appshield.cli.AndroidPipelineAdapter.stage_and_protect",
                side_effect=fake_stage,
            ),
        ):
            code = main(
                [
                    "protect",
                    "-c",
                    str(cfg_file),
                    "--mapping-out",
                    str(existing_mapping),
                    "--overwrite",
                ]
            )

        assert code == 0
        assert existing_mapping.read_text(encoding="utf-8") == SAMPLE_MAPPING_CONTENT
