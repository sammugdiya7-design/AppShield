"""
Phase A.1 Verification Integrity & Final Corrections Regression Suite:
Validates generalized mapping verification, mandatory verification evidence & exit codes,
source integrity ordering and failure-path preservation, fail_on_check_failure policy
semantics across protect/verify, and Android release task / doctor checks.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import warnings
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from appshield.adapters.android import AndroidPipelineAdapter
from appshield.adapters.base import PrerequisiteCheck
from appshield.cli import main
from appshield.config import (
    AppShieldConfig,
    ConfigValidationError,
    InputConfig,
    OutputConfig,
    load_config,
    validate_android_release_task,
)
from appshield.dex import create_synthetic_dex, inspect_apk_dex
from appshield.doctor import ToolReport, run_doctor_checks
from appshield.gradle import GradleBuildResult, GradleExecutionError, GradleTimeoutError
from appshield.mapping import MappingParseError, parse_r8_mapping
from appshield.sandbox import (
    SandboxManager,
    SourceImmutabilityError,
    compute_file_sha256,
)
from appshield.signing import SigningError, SigningResult
from appshield.verify import ObjectiveCheckResult, VerificationEngine

UNRELATED_FIXTURE_DIR = (
    Path(__file__).parent / "fixtures" / "unrelated_android_gradle_project"
).resolve()


def _build_apk(
    path: Path,
    classes: list[str],
    strings: list[str] | None = None,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    dex_bytes = create_synthetic_dex(
        classes=classes,
        strings=strings or ["AcmeLedger", "OK"],
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


def _passing_aln_check() -> ObjectiveCheckResult:
    return ObjectiveCheckResult(
        check_id="CHK-ALN-01",
        name="Zip Alignment Verification",
        category="alignment",
        outcome="VERIFIED",
        status="PASS",
        what_it_proves="Proves alignment",
        what_it_does_not_prove="",
        observed_metric="4-byte aligned",
        details={},
    )


class TestPhaseA1MappingVerification:
    """Task 1: Generalized CHK-SYM-01 mapping verification and provenance binding."""

    def test_single_coincidental_match_among_unrelated_mappings_fails(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a", "z.z"])
        lines = ["org.acme.OnlyThisMatched -> a.a:"]
        for idx in range(25):
            lines.append(f"com.unrelated.Module{idx} -> b.{chr(97 + (idx % 26))}{idx}:")
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        mapping = parse_r8_mapping(mapping_file)
        dex_summary = inspect_apk_dex(apk)
        res = VerificationEngine().check_sym_01(dex_summary, mapping)

        assert res.status == "FAIL"
        assert res.outcome == "FAILED"
        assert res.details["generalized_classes_verified"] == 1
        assert res.details["generalized_classes_missing"] == 25

    def test_stale_mapping_content_and_mtime_before_build_start_fail(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(
            tmp_path / "app.apk",
            classes=["a.a", "a.b", "org.acme.ledger.LedgerHomeActivity"],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.acme.ledger.InvoiceCalculator -> a.a:\n"
            "org.acme.ledger.TaxRuleEngine -> a.b:\n"
            "org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:\n",
            encoding="utf-8",
        )
        build_started_at = time.time() + 100.0
        old_ts = build_started_at - 500.0
        os.utime(mapping_file, (old_ts, old_ts))

        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="BUILD SUCCESSFUL",
            stderr="",
            duration_seconds=2.0,
            command=["gradlew", "assembleRelease"],
            is_simulated=False,
            apk_path=apk,
            mapping_file=mapping_file,
            metadata={
                "build_started_at": str(build_started_at),
                "mapping_sha256": compute_file_sha256(mapping_file),
            },
        )
        engine = VerificationEngine()
        with patch.object(engine, "check_aln_01", return_value=_passing_aln_check()):
            report = engine.run_all_checks(
                apk_path=apk,
                mapping_file=mapping_file,
                build_result=build_res,
                is_real_build=True,
            )

        sym = next(c for c in report.objective_checks if c.check_id == "CHK-SYM-01")
        bld = next(c for c in report.objective_checks if c.check_id == "CHK-BLD-01")
        assert sym.status == "FAIL"
        assert bld.status == "FAIL"
        assert report.is_verified_protected is False

    def test_apk_and_mapping_from_different_builds_fail(self, tmp_path: Path) -> None:
        # Different-build content mismatch (unmapped obfuscated DEX class + missing renamed entry)
        apk = _build_apk(
            tmp_path / "app.apk",
            classes=["x.a", "x.b", "com.other.DifferentMainActivity"],
        )
        other_mapping = tmp_path / "other_mapping.txt"
        other_mapping.write_text(
            "org.acme.ledger.InvoiceCalculator -> a.a:\n"
            "org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:\n",
            encoding="utf-8",
        )
        mapping = parse_r8_mapping(other_mapping)
        dex_summary = inspect_apk_dex(apk)
        res = VerificationEngine().check_sym_01(
            dex_summary,
            mapping,
            expected_entry_points=["com.other.DifferentMainActivity"],
        )
        assert res.status == "FAIL"
        assert res.details["has_discrepancies"] is True
        assert res.details["unmapped_dex_classes_count"] >= 2

        # SHA-256 build provenance mismatch in run_all_checks
        matching_map = tmp_path / "current_map.txt"
        matching_map.write_text(
            "org.acme.Other -> x.a:\norg.acme.OtherTwo -> x.b:\n"
            "com.other.DifferentMainActivity -> com.other.DifferentMainActivity:\n",
            encoding="utf-8",
        )
        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="BUILD SUCCESSFUL",
            stderr="",
            duration_seconds=2.0,
            command=["gradlew", "assembleRelease"],
            is_simulated=False,
            apk_path=apk,
            mapping_file=matching_map,
            metadata={"mapping_sha256": "0" * 64},
        )
        engine = VerificationEngine()
        with patch.object(engine, "check_aln_01", return_value=_passing_aln_check()):
            report = engine.run_all_checks(
                apk_path=apk,
                mapping_file=matching_map,
                build_result=build_res,
                is_real_build=True,
            )
        sym = next(c for c in report.objective_checks if c.check_id == "CHK-SYM-01")
        assert sym.status == "FAIL"
        assert "SHA-256" in sym.observed_metric

    def test_dead_code_removed_by_r8_allowed_when_majority_genuinely_renamed(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(
            tmp_path / "shrunk.apk",
            classes=["a.a", "a.b", "org.acme.LedgerHomeActivity"],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.acme.InvoiceCalc -> a.a:\n"
            "org.acme.TaxEngine -> a.b:\n"
            "org.acme.UnusedHelper -> a.c:\n"
            "org.acme.LedgerHomeActivity -> org.acme.LedgerHomeActivity:\n",
            encoding="utf-8",
        )
        mapping = parse_r8_mapping(mapping_file)
        dex_summary = inspect_apk_dex(apk)
        res = VerificationEngine().check_sym_01(
            dex_summary,
            mapping,
            expected_entry_points=["org.acme.LedgerHomeActivity"],
        )

        assert res.status == "PASS"
        assert res.details["generalized_classes_verified"] == 2
        assert res.details["generalized_classes_missing"] == 1

    def test_all_renamed_classes_removed_by_r8_fails(self, tmp_path: Path) -> None:
        apk = _build_apk(
            tmp_path / "empty_renamed.apk",
            classes=["org.acme.LedgerHomeActivity"],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.acme.InvoiceCalc -> a.a:\n"
            "org.acme.TaxEngine -> a.b:\n"
            "org.acme.LedgerHomeActivity -> org.acme.LedgerHomeActivity:\n",
            encoding="utf-8",
        )
        mapping = parse_r8_mapping(mapping_file)
        dex_summary = inspect_apk_dex(apk)
        res = VerificationEngine().check_sym_01(dex_summary, mapping)

        assert res.status == "FAIL"
        assert res.details["generalized_classes_verified"] == 0

    def test_kept_classes_alongside_renamed_classes_pass_without_ratio_trap(
        self, tmp_path: Path
    ) -> None:
        # 5 explicitly kept classes + 2 renamed classes (<30% renamed by naive count,
        # but both renamed classes genuinely verified and no leaks).
        apk = _build_apk(
            tmp_path / "kept.apk",
            classes=[
                "a.a",
                "a.b",
                "org.acme.MainActivity",
                "org.acme.KeepOne",
                "org.acme.KeepTwo",
                "org.acme.KeepThree",
                "org.acme.KeepFour",
            ],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.acme.SecretOne -> a.a:\n"
            "org.acme.SecretTwo -> a.b:\n"
            "org.acme.MainActivity -> org.acme.MainActivity:\n"
            "org.acme.KeepOne -> org.acme.KeepOne:\n"
            "org.acme.KeepTwo -> org.acme.KeepTwo:\n"
            "org.acme.KeepThree -> org.acme.KeepThree:\n"
            "org.acme.KeepFour -> org.acme.KeepFour:\n",
            encoding="utf-8",
        )
        res = VerificationEngine().check_sym_01(
            inspect_apk_dex(apk),
            parse_r8_mapping(mapping_file),
            expected_entry_points=["org.acme.MainActivity"],
        )
        assert res.status == "PASS"
        assert res.details["generalized_classes_verified"] == 2
        assert res.details["kept_classes_verified"] == 5

    def test_small_single_class_app_passes(self, tmp_path: Path) -> None:
        apk = _build_apk(tmp_path / "tiny.apk", classes=["a.a"])
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("com.tiny.SecretWorker -> a.a:\n", encoding="utf-8")
        res = VerificationEngine().check_sym_01(
            inspect_apk_dex(apk),
            parse_r8_mapping(mapping_file),
        )
        assert res.status == "PASS"
        assert res.details["generalized_classes_verified"] == 1

    def test_missing_unreadable_and_malformed_mapping_files_fail(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        engine = VerificationEngine()

        # Missing mapping path
        missing = tmp_path / "missing.txt"
        with patch.object(engine, "check_aln_01", return_value=_passing_aln_check()):
            rep_missing = engine.run_all_checks(apk_path=apk, mapping_file=missing)
        sym_missing = next(
            c for c in rep_missing.objective_checks if c.check_id == "CHK-SYM-01"
        )
        assert sym_missing.status == "FAIL"
        assert rep_missing.is_verified_protected is False

        # Unreadable mapping file (PermissionError / OSError)
        unreadable = tmp_path / "unreadable.txt"
        unreadable.write_text("com.a.B -> a.a:\n", encoding="utf-8")
        with (
            patch(
                "appshield.verify.parse_r8_mapping",
                side_effect=PermissionError("denied"),
            ),
            patch.object(engine, "check_aln_01", return_value=_passing_aln_check()),
        ):
            rep_unreadable = engine.run_all_checks(
                apk_path=apk, mapping_file=unreadable
            )
        sym_unreadable = next(
            c for c in rep_unreadable.objective_checks if c.check_id == "CHK-SYM-01"
        )
        assert sym_unreadable.status == "FAIL"
        assert "denied" in sym_unreadable.details["mapping_error"]

        # Malformed mapping data: binary NUL bytes & syntax errors
        bad_bin = tmp_path / "binary.txt"
        bad_bin.write_bytes(b"\x00\xff\xfe\x00not a mapping")
        with pytest.raises(MappingParseError):
            parse_r8_mapping(bad_bin)

        bad_syntax = tmp_path / "bad_syntax.txt"
        bad_syntax.write_text("THIS IS GARBAGE NOT A MAPPING LINE\n", encoding="utf-8")
        with pytest.raises(MappingParseError):
            parse_r8_mapping(bad_syntax)

        with patch.object(engine, "check_aln_01", return_value=_passing_aln_check()):
            rep_bad = engine.run_all_checks(apk_path=apk, mapping_file=bad_syntax)
        sym_bad = next(
            c for c in rep_bad.objective_checks if c.check_id == "CHK-SYM-01"
        )
        assert sym_bad.status == "FAIL"

    def test_inconsistent_mapping_with_leaked_original_descriptor_fails(
        self, tmp_path: Path
    ) -> None:
        apk = _build_apk(
            tmp_path / "leaked.apk",
            classes=["org.acme.SecretCalc", "a.a"],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text(
            "org.acme.SecretCalc -> a.a:\norg.acme.TaxEngine -> a.b:\n",
            encoding="utf-8",
        )
        res = VerificationEngine().check_sym_01(
            inspect_apk_dex(apk),
            parse_r8_mapping(mapping_file),
        )
        assert res.status == "FAIL"
        assert res.details["has_discrepancies"] is True
        assert res.details["discrepancies_count"] >= 1


class TestPhaseA1VerifyExitAndEvidence:
    """Task 2: Unreadable/missing mandatory evidence fails verify with clean distinction."""

    def test_verify_unreadable_mapping_reports_operational_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        bad_map = tmp_path / "map_dir"
        bad_map.mkdir()

        code = main(["verify", str(apk), "-m", str(bad_map)])
        assert code == 1
        err = capsys.readouterr().err
        assert "Operational Error" in err
        assert "not a file" in err

    def test_verify_malformed_mapping_fails_chk_sym_and_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        malformed = tmp_path / "malformed.txt"
        malformed.write_text("not a mapping at all\n", encoding="utf-8")

        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            code = main(["verify", str(apk), "-m", str(malformed)])
        assert code == 1
        out = capsys.readouterr().out
        assert "[FAIL] CHK-SYM-01" in out
        assert "Verification Status: REJECTED" in out

    def test_verify_disabled_verification_in_config_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("org.acme.Secret -> a.a:\n", encoding="utf-8")
        cfg = tmp_path / "disabled.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "disabled_test",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "verification": {
                        "enabled": False,
                        "fail_on_check_failure": False,
                    },
                }
            ),
            encoding="utf-8",
        )

        code = main(["verify", str(apk), "-m", str(mapping_file), "-c", str(cfg)])
        assert code == 1
        out = capsys.readouterr().out
        assert "REJECTED" in out

    def test_verify_allows_legitimate_skipped_optional_and_unsigned_checks(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(tmp_path / "app.apk", classes=["a.a"])
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("org.acme.Secret -> a.a:\n", encoding="utf-8")
        cfg = tmp_path / "core_only.yaml"
        cfg.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "core_only",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "verification": {
                        "enabled": True,
                        "fail_on_check_failure": True,
                        "checks": [
                            "build_execution",
                            "apk_structure",
                            "symbol_renaming_ratio",
                            "package_alignment",
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            code = main(["verify", str(apk), "-m", str(mapping_file), "-c", str(cfg)])
        assert code == 0
        out = capsys.readouterr().out
        assert "[SKIPPED] CHK-SIG-01" in out
        assert "[SKIPPED] CHK-STR-01" in out
        assert "[SKIPPED] CHK-CMP-01" in out
        assert "Verification Status: STATIC CHECKS PASSED" in out
        assert "Protected Release Verified : NO" in out


class TestPhaseA1SourceIntegrityAndPipelineOrder:
    """Task 3: Verify source integrity before report/APK export and preserve on failures."""

    def test_source_tampering_blocks_report_mapping_and_apk_export(
        self, tmp_path: Path
    ) -> None:
        proj_copy = tmp_path / "proj"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        staged_apk = _build_apk(
            tmp_path / "built.apk",
            classes=["a.a", "org.acme.ledger.LedgerHomeActivity"],
        )
        staged_map = tmp_path / "built_mapping.txt"
        staged_map.write_text(
            "org.acme.ledger.InvoiceCalculator -> a.a:\n"
            "org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:\n",
            encoding="utf-8",
        )

        dist_dir = tmp_path / "dist"
        mapping_out = tmp_path / "retained_mapping.txt"
        cfg = AppShieldConfig(
            version="1.0",
            project_name="tamper_test",
            platform="android",
            input=InputConfig(project_dir=proj_copy, verify_source_immutability=True),
            output=OutputConfig(dir=dist_dir),
        )
        adapter = AndroidPipelineAdapter()
        prereqs = [
            PrerequisiteCheck("Gradle Build Tool", True, "8.2", "8.2", True, ""),
            PrerequisiteCheck("Android SDK Platform 34", True, "34", "34", True, ""),
        ]

        mock_runner = MagicMock()
        mock_runner.is_simulated = False

        def fake_run(task: str, **kwargs: Any) -> GradleBuildResult:
            build_dir = mock_runner.project_dir
            out_apk = (
                build_dir
                / "mobile"
                / "build"
                / "outputs"
                / "apk"
                / "release"
                / "mobile-release.apk"
            )
            out_apk.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_apk, out_apk)
            out_map = (
                build_dir
                / "mobile"
                / "build"
                / "outputs"
                / "mapping"
                / "release"
                / "mapping.txt"
            )
            out_map.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_map, out_map)
            # Simulate out-of-band source modification during pipeline
            (proj_copy / "settings.gradle.kts").write_text(
                "// tampered!", encoding="utf-8"
            )
            return GradleBuildResult(
                success=True,
                exit_code=0,
                stdout="BUILD SUCCESSFUL",
                stderr="",
                duration_seconds=1.0,
                command=["gradlew", task],
                is_simulated=False,
                apk_path=out_apk,
                mapping_file=out_map,
                metadata={"build_id": "tamper-1"},
            )

        mock_runner.run_task.side_effect = fake_run

        def fake_sign(
            unsigned_apk: Path, output_dir: Path, **kwargs: object
        ) -> SigningResult:
            output_dir.mkdir(parents=True, exist_ok=True)
            final_apk = output_dir / "mobile-release-aligned.apk"
            shutil.copy2(unsigned_apk, final_apk)
            return SigningResult(
                success=True,
                signature_type="unsigned",
                aligned_apk_path=final_apk,
                final_apk_path=final_apk,
                is_aligned=True,
            )

        with (
            warnings.catch_warnings(record=True),
            patch.object(adapter, "check_prerequisites", return_value=prereqs),
            patch(
                "appshield.adapters.android.align_and_sign_apk",
                side_effect=fake_sign,
            ),
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            warnings.simplefilter("always")
            with pytest.raises(SourceImmutabilityError):
                adapter.stage_and_protect(
                    cfg, runner=mock_runner, mapping_out=mapping_out
                )

        # Crucially, NOTHING was published before source integrity check ran
        assert not (dist_dir / "audit_report.json").exists()
        assert not (dist_dir / "audit_report.md").exists()
        assert not mapping_out.exists()
        assert not list(dist_dir.glob("*.apk"))

    def test_sandbox_exit_preserves_original_exception_alongside_integrity_violation(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "Main.kt").write_text("class Main", encoding="utf-8")

        sandbox = SandboxManager(
            source_dir=src,
            staging_parent=tmp_path / "staging",
            verify_source_immutability=True,
            cleanup_on_exit=True,
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with (
                pytest.raises(RuntimeError, match="primary build error") as exc_info,
                sandbox,
            ):
                (src / "Main.kt").write_text("class Tampered", encoding="utf-8")
                raise RuntimeError("primary build error")

        assert sandbox.integrity_violation is not None
        assert not sandbox.staging_dir.exists()
        notes = getattr(exc_info.value, "__notes__", [])
        assert any("Source integrity violation" in n for n in notes)
        assert any("Source integrity violation" in str(w.message) for w in caught)

    def test_failed_gradle_path_runs_source_integrity_and_surfaces_violation(
        self, tmp_path: Path
    ) -> None:
        proj_copy = tmp_path / "proj"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        cfg = AppShieldConfig(
            version="1.0",
            project_name="fail_integrity",
            platform="android",
            input=InputConfig(project_dir=proj_copy, verify_source_immutability=True),
            output=OutputConfig(dir=tmp_path / "dist"),
        )
        adapter = AndroidPipelineAdapter()
        prereqs = [
            PrerequisiteCheck("Gradle Build Tool", True, "8.2", "8.2", True, ""),
            PrerequisiteCheck("Android SDK Platform 34", True, "34", "34", True, ""),
        ]
        mock_runner = MagicMock()
        mock_runner.is_simulated = False

        def failing_build(task: str, **kwargs: Any) -> GradleBuildResult:
            (proj_copy / "settings.gradle.kts").write_text(
                "// mutated!", encoding="utf-8"
            )
            raise GradleTimeoutError(
                "timed out", timeout_seconds=10.0, command=["gradlew", task]
            )

        mock_runner.run_task.side_effect = failing_build

        with (
            warnings.catch_warnings(record=True),
            patch.object(adapter, "check_prerequisites", return_value=prereqs),
        ):
            warnings.simplefilter("always")
            res = adapter.stage_and_protect(cfg, runner=mock_runner)

        assert res.success is False
        assert res.metadata["source_integrity_verified"] == "False"
        assert "Source integrity violation detected" in (res.error_message or "")
        assert any("Source integrity violation detected" in log for log in res.logs)

    @pytest.mark.parametrize(
        "exc",
        [
            GradleExecutionError(
                "gradle crashed", exit_code=1, command=["gradlew", "assembleRelease"]
            ),
            SigningError("apksigner crashed"),
        ],
    )
    def test_non_tampered_failed_paths_leave_source_hashes_identical(
        self, tmp_path: Path, exc: Exception
    ) -> None:
        proj_copy = tmp_path / "proj"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        before_hashes = _snapshot_tree_hashes(proj_copy)

        cfg = AppShieldConfig(
            version="1.0",
            project_name="clean_fail",
            platform="android",
            input=InputConfig(project_dir=proj_copy, verify_source_immutability=True),
            output=OutputConfig(dir=tmp_path / "dist"),
        )
        adapter = AndroidPipelineAdapter()
        prereqs = [
            PrerequisiteCheck("Gradle Build Tool", True, "8.2", "8.2", True, ""),
            PrerequisiteCheck("Android SDK Platform 34", True, "34", "34", True, ""),
        ]
        mock_runner = MagicMock()
        mock_runner.is_simulated = False
        mock_runner.run_task.side_effect = exc

        with patch.object(adapter, "check_prerequisites", return_value=prereqs):
            res = adapter.stage_and_protect(cfg, runner=mock_runner)

        assert res.success is False
        assert res.metadata["source_integrity_verified"] == "True"
        assert _snapshot_tree_hashes(proj_copy) == before_hashes


class TestPhaseA1FailOnCheckFailureSemantics:
    """Task 4: Mandatory checks never bypassed; fail_on_check_failure only governs non-mandatory failures."""

    def _run_protect_with_secret_failure(
        self,
        tmp_path: Path,
        *,
        fail_on_check_failure: bool,
        zipalign_ok: bool = True,
    ) -> tuple[int, Path]:
        proj_copy = tmp_path / f"proj_{fail_on_check_failure}_{zipalign_ok}"
        shutil.copytree(UNRELATED_FIXTURE_DIR, proj_copy)
        dist_dir = tmp_path / f"dist_{fail_on_check_failure}_{zipalign_ok}"

        staged_apk = _build_apk(
            tmp_path / f"apk_{fail_on_check_failure}_{zipalign_ok}.apk",
            classes=["a.a", "a.b", "org.acme.ledger.LedgerHomeActivity"],
            strings=["AKIAIOSFODNN7EXAMPLE"],
        )
        staged_map = tmp_path / f"map_{fail_on_check_failure}_{zipalign_ok}.txt"
        staged_map.write_text(
            "org.acme.ledger.InvoiceCalculator -> a.a:\n"
            "org.acme.ledger.TaxRuleEngine -> a.b:\n"
            "org.acme.ledger.LedgerHomeActivity -> org.acme.ledger.LedgerHomeActivity:\n",
            encoding="utf-8",
        )
        cfg_file = tmp_path / f"cfg_{fail_on_check_failure}_{zipalign_ok}.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "policy_app",
                    "platform": "android",
                    "input": {"project_dir": str(proj_copy)},
                    "output": {"dir": str(dist_dir)},
                    "verification": {
                        "enabled": True,
                        "fail_on_check_failure": fail_on_check_failure,
                    },
                }
            ),
            encoding="utf-8",
        )
        prereqs = [
            PrerequisiteCheck("Gradle Build Tool", True, "8.2", "8.2", True, ""),
            PrerequisiteCheck("Android SDK Platform 34", True, "34", "34", True, ""),
        ]

        mock_runner_instance = MagicMock()
        mock_runner_instance.is_simulated = False

        def fake_build(task: str, **kwargs: Any) -> GradleBuildResult:
            build_dir = mock_runner_instance.project_dir
            out_apk = (
                build_dir
                / "mobile"
                / "build"
                / "outputs"
                / "apk"
                / "release"
                / "mobile-release.apk"
            )
            out_apk.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_apk, out_apk)
            out_map = (
                build_dir
                / "mobile"
                / "build"
                / "outputs"
                / "mapping"
                / "release"
                / "mapping.txt"
            )
            out_map.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(staged_map, out_map)
            return GradleBuildResult(
                success=True,
                exit_code=0,
                stdout="BUILD SUCCESSFUL",
                stderr="",
                duration_seconds=1.0,
                command=["gradlew", task],
                is_simulated=False,
                apk_path=out_apk,
                mapping_file=out_map,
                metadata={"mapping_sha256": compute_file_sha256(out_map)},
            )

        mock_runner_instance.run_task.side_effect = fake_build

        def make_runner(project_dir: Path, **kwargs: Any) -> MagicMock:
            mock_runner_instance.project_dir = project_dir
            return mock_runner_instance

        def fake_sign(
            unsigned_apk: Path, output_dir: Path, **kwargs: object
        ) -> SigningResult:
            output_dir.mkdir(parents=True, exist_ok=True)
            final_apk = output_dir / "mobile-release-aligned.apk"
            shutil.copy2(unsigned_apk, final_apk)
            return SigningResult(
                success=True,
                signature_type="unsigned",
                aligned_apk_path=final_apk,
                final_apk_path=final_apk,
                is_aligned=zipalign_ok,
            )

        doctor_reports = [
            ToolReport("Java Runtime (java)", True, "17.0.9", True, ""),
            ToolReport("JAVA_HOME Variable", True, "/jdk-17", True, ""),
            ToolReport("Gradle Build Tool", True, "Gradle 8.2", True, ""),
        ]

        with (
            patch("appshield.cli.run_doctor_checks", return_value=doctor_reports),
            patch.object(
                AndroidPipelineAdapter, "check_prerequisites", return_value=prereqs
            ),
            patch("appshield.adapters.android.GradleRunner", side_effect=make_runner),
            patch(
                "appshield.adapters.android.align_and_sign_apk",
                side_effect=fake_sign,
            ),
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=zipalign_ok),
        ):
            code = main(["protect", "-c", str(cfg_file)])
        return code, dist_dir

    def test_protect_non_mandatory_str_failure_strict_vs_lenient(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code_strict, dist_strict = self._run_protect_with_secret_failure(
            tmp_path, fail_on_check_failure=True
        )
        out_strict = capsys.readouterr().out
        assert code_strict == 1
        assert "Verification Status: REJECTED" in out_strict
        assert not list(dist_strict.glob("*.apk"))

        code_lenient, dist_lenient = self._run_protect_with_secret_failure(
            tmp_path, fail_on_check_failure=False
        )
        out_lenient = capsys.readouterr().out
        assert code_lenient == 0
        assert "Verification Status: UNVERIFIED" in out_lenient
        assert "WITHOUT exporting protected APK" in out_lenient
        # Unverified APK must STILL never be exported!
        assert not list(dist_lenient.glob("*.apk"))
        report_data = json.loads(
            (dist_lenient / "audit_report.json").read_text(encoding="utf-8")
        )
        assert report_data["is_verified_protected"] is False
        assert report_data["verification_status"].startswith("UNVERIFIED")

    def test_protect_mandatory_failure_ignores_lenient_fail_on_check_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code_mand, dist_mand = self._run_protect_with_secret_failure(
            tmp_path, fail_on_check_failure=False, zipalign_ok=False
        )
        out_mand = capsys.readouterr().out
        assert code_mand == 1
        assert "Verification Status: REJECTED" in out_mand
        assert not list(dist_mand.glob("*.apk"))

    def test_verify_non_mandatory_str_failure_strict_vs_lenient(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        apk = _build_apk(
            tmp_path / "secret.apk",
            classes=["a.a"],
            strings=["AKIAIOSFODNN7EXAMPLE"],
        )
        mapping_file = tmp_path / "mapping.txt"
        mapping_file.write_text("org.acme.Secret -> a.a:\n", encoding="utf-8")

        for flag, expected_code, expected_phrase in [
            (True, 1, "failing per 'fail_on_check_failure: true'"),
            (False, 0, "Verification Status: UNVERIFIED"),
        ]:
            cfg = tmp_path / f"v_{flag}.yaml"
            cfg.write_text(
                yaml.safe_dump(
                    {
                        "version": "1.0",
                        "project_name": "v_policy",
                        "platform": "android",
                        "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                        "output": {"dir": str(tmp_path / "dist")},
                        "verification": {
                            "enabled": True,
                            "fail_on_check_failure": flag,
                        },
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch(
                    "appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")
                ),
                patch("appshield.verify.verify_zipalign", return_value=True),
            ):
                code = main(
                    ["verify", str(apk), "-m", str(mapping_file), "-c", str(cfg)]
                )
            out = capsys.readouterr().out
            assert code == expected_code
            assert expected_phrase in out
            assert "Protected Release Verified : NO" in out


class TestPhaseA1ReleaseTaskAndDoctor:
    """Task 5: Reject Android instrumentation/test tasks and fix doctor AGP module detection."""

    @pytest.mark.parametrize(
        "bad_task",
        [
            "assembleAndroidTest",
            "assembleReleaseAndroidTest",
            ":mobile:assembleDebugAndroidTest",
            "assembleReleaseUnitTest",
            "assembleDebug",
            ":app:assemble",
            "testAssemble",
            ":app:",
            "connectedAndroidTest",
        ],
    )
    def test_rejects_non_release_and_instrumentation_tasks(self, bad_task: str) -> None:
        with pytest.raises(ConfigValidationError):
            validate_android_release_task(bad_task)

    @pytest.mark.parametrize(
        "good_task",
        [
            "assembleRelease",
            ":mobile:assembleRelease",
            ":app:assembleProdRelease",
        ],
    )
    def test_accepts_valid_release_tasks(self, good_task: str) -> None:
        validate_android_release_task(good_task)

    def test_load_config_rejects_assemble_android_test(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "bad_task.yaml"
        cfg_file.write_text(
            yaml.safe_dump(
                {
                    "version": "1.0",
                    "project_name": "bad_task",
                    "platform": "android",
                    "input": {"project_dir": str(UNRELATED_FIXTURE_DIR)},
                    "output": {"dir": str(tmp_path / "dist")},
                    "android": {
                        "gradle_task": "assembleAndroidTest",
                        "build_variant": "release",
                    },
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(ConfigValidationError, match="test tasks"):
            load_config(cfg_file)

    def test_doctor_detects_agp_in_custom_module_kts(self) -> None:
        reports = run_doctor_checks(project_dir=UNRELATED_FIXTURE_DIR)
        agp = next(r for r in reports if r.name == "Android Gradle Plugin (AGP)")
        assert agp.is_available is True
        assert agp.version is not None
        assert "8.2.2" in agp.version
        assert agp.path is not None
        assert agp.path.endswith("build.gradle.kts")
