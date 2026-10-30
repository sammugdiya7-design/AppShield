"""
Unit tests for AppShield Empirical Verification Engine (Plan 04-03).
Tests all 7 verification checks (build, APK structure, dual-evidence symbols, signatures,
alignment, string pool scan, and structural compatibility), R8 mapping parser,
report generation (JSON/Markdown/Terminal), and signing credential isolation.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from appshield.config import SigningConfig
from appshield.dex import create_synthetic_dex, inspect_apk_dex
from appshield.gradle import GradleBuildResult, build_safe_env
from appshield.mapping import parse_r8_mapping
from appshield.signing import ApkSignatureVerificationResult
from appshield.verify import (
    FIXTURE_TEST_STRINGS,
    STANDARD_DISCLAIMER,
    VerificationEngine,
    export_report_json,
    format_report_markdown,
    format_report_terminal,
)


def create_test_apk(
    path: Path,
    classes: list[str],
    strings: list[str] | None = None,
) -> Path:
    """Helper to create a synthetic APK with valid binary DEX bytecode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    dex_bytes = create_synthetic_dex(classes=classes, strings=strings)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<dummy-manifest/>")
        zf.writestr("classes.dex", dex_bytes)
    return path


SAMPLE_R8_MAPPING = """
# compiler: R8
# compiler_version: 8.2.2
# min_api: 24
com.example.sample.IdentifiableSecretService -> a.a:
    java.lang.String secretToken -> a
    void <init>() -> <init>
    1:3:java.lang.String processUserTokenAndCalculateHash(java.lang.String) -> a
com.example.sample.PaymentSecurityValidator -> a.b:
    1:2:boolean validateTransactionToken(java.lang.String) -> a
com.example.sample.MainActivity -> com.example.sample.MainActivity:
    1:5:void onCreate(android.os.Bundle) -> onCreate
"""


class TestR8MappingParser:
    def test_parse_r8_mapping_success(self) -> None:
        summary = parse_r8_mapping(SAMPLE_R8_MAPPING)
        assert summary.total_classes == 3
        assert summary.renamed_classes_count == 2
        assert summary.kept_classes_count == 1
        assert abs(summary.class_renaming_ratio - (2 / 3)) < 0.001
        assert summary.compiler_metadata["compiler"] == "R8"
        assert summary.compiler_metadata["compiler_version"] == "8.2.2"

        # Check class mapping details
        secret_service = summary.classes["com.example.sample.IdentifiableSecretService"]
        assert secret_service.obfuscated_name == "a.a"
        assert secret_service.is_renamed is True
        assert len(secret_service.methods) == 2
        assert (
            secret_service.renamed_methods_count == 1
        )  # <init> is not considered renamed
        assert len(secret_service.fields) == 1
        assert secret_service.fields[0].is_renamed is True

        # Check preserved entry point
        main_activity = summary.classes["com.example.sample.MainActivity"]
        assert main_activity.obfuscated_name == "com.example.sample.MainActivity"
        assert main_activity.is_renamed is False

        # Check reverse lookup dictionary
        assert (
            summary.obfuscated_to_original["a.a"]
            == "com.example.sample.IdentifiableSecretService"
        )
        assert (
            summary.obfuscated_to_original["a.b"]
            == "com.example.sample.PaymentSecurityValidator"
        )

    def test_parse_r8_mapping_from_file(self, tmp_path: Path) -> None:
        map_file = tmp_path / "mapping.txt"
        map_file.write_text(SAMPLE_R8_MAPPING, encoding="utf-8")
        summary = parse_r8_mapping(map_file)
        assert summary.total_classes == 3

    def test_parse_r8_mapping_missing_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing_map.txt"
        with pytest.raises(FileNotFoundError):
            parse_r8_mapping(missing)


class TestDualEvidenceSymbolVerification:
    def test_dual_evidence_success(self, tmp_path: Path) -> None:
        # In DEX: obfuscated classes 'a.a', 'a.b' and preserved 'MainActivity'
        apk = create_test_apk(
            tmp_path / "test.apk",
            classes=["a.a", "a.b", "com.example.sample.MainActivity"],
        )
        dex_summary = inspect_apk_dex(apk)
        mapping_summary = parse_r8_mapping(SAMPLE_R8_MAPPING)

        engine = VerificationEngine()
        result = engine.check_sym_01(
            dex_summary=dex_summary,
            mapping=mapping_summary,
            expected_fixture_classes=[
                "IdentifiableSecretService",
                "PaymentSecurityValidator",
            ],
            expected_entry_points=["MainActivity"],
        )

        assert result.status == "PASS"
        assert result.outcome == "HEURISTIC"
        assert "Dual-evidence verified" in result.observed_metric
        assert result.details["fixture_classes_verified"] == 2
        assert result.details["discrepancies_count"] == 0

    def test_dual_evidence_fails_when_original_symbol_still_in_dex(
        self, tmp_path: Path
    ) -> None:
        # DEX contains original un-obfuscated name: should FAIL
        apk = create_test_apk(
            tmp_path / "test.apk",
            classes=[
                "com.example.sample.IdentifiableSecretService",  # UNRENAMED in DEX!
                "a.b",
                "com.example.sample.MainActivity",
            ],
        )
        dex_summary = inspect_apk_dex(apk)
        mapping_summary = parse_r8_mapping(SAMPLE_R8_MAPPING)

        engine = VerificationEngine()
        result = engine.check_sym_01(
            dex_summary=dex_summary,
            mapping=mapping_summary,
            expected_fixture_classes=["IdentifiableSecretService"],
            expected_entry_points=["MainActivity"],
        )

        assert result.status == "FAIL"
        assert result.outcome == "FAILED"
        assert "discrepancy" in result.observed_metric

    def test_dual_evidence_fails_when_class_stripped_out_entirely(
        self, tmp_path: Path
    ) -> None:
        # DEX contains only MainActivity; IdentifiableSecretService was stripped by dead code elimination!
        apk = create_test_apk(
            tmp_path / "test.apk",
            classes=["com.example.sample.MainActivity"],
        )
        dex_summary = inspect_apk_dex(apk)
        mapping_summary = parse_r8_mapping(SAMPLE_R8_MAPPING)

        engine = VerificationEngine()
        result = engine.check_sym_01(
            dex_summary=dex_summary,
            mapping=mapping_summary,
            expected_fixture_classes=["IdentifiableSecretService"],
            expected_entry_points=["MainActivity"],
        )

        # Must NOT mistake stripped classes for obfuscation!
        assert result.status == "FAIL"
        assert result.details["fixture_classes_missing"] == 1

    def test_dual_evidence_fails_when_entry_point_missing(self, tmp_path: Path) -> None:
        # DEX contains obfuscated classes, but MainActivity is missing!
        apk = create_test_apk(
            tmp_path / "test.apk",
            classes=["a.a", "a.b"],
        )
        dex_summary = inspect_apk_dex(apk)
        mapping_summary = parse_r8_mapping(SAMPLE_R8_MAPPING)

        engine = VerificationEngine()
        result = engine.check_sym_01(
            dex_summary=dex_summary,
            mapping=mapping_summary,
            expected_fixture_classes=["IdentifiableSecretService"],
            expected_entry_points=["MainActivity"],
        )

        assert result.status == "FAIL"

    def test_dual_evidence_skipped_when_no_mapping(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "test.apk", classes=["a.a"])
        dex_summary = inspect_apk_dex(apk)

        engine = VerificationEngine()
        result = engine.check_sym_01(dex_summary=dex_summary, mapping=None)
        assert result.status == "SKIPPED"
        assert result.outcome == "UNSUPPORTED"


class TestBuildCheck:
    def test_bld_01_real_build_success(self) -> None:
        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="BUILD SUCCESSFUL",
            stderr="",
            duration_seconds=5.2,
            command=["gradlew", "assembleRelease"],
            is_simulated=False,
        )
        engine = VerificationEngine()
        check = engine.check_bld_01(build_res, is_real_build=True)
        assert check.status == "PASS"
        assert check.outcome == "VERIFIED"

    def test_bld_01_simulated_build_is_informational(self) -> None:
        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="SIMULATED",
            stderr="",
            duration_seconds=0.1,
            command=["mocked"],
            is_simulated=True,
        )
        engine = VerificationEngine()
        check = engine.check_bld_01(build_res, is_real_build=False)
        assert check.status == "INFO"
        assert check.outcome == "INFORMATIONAL"

    def test_bld_01_build_failure(self) -> None:
        build_res = GradleBuildResult(
            success=False,
            exit_code=1,
            stdout="",
            stderr="Compile error",
            duration_seconds=1.0,
            command=["gradlew"],
            is_simulated=False,
        )
        engine = VerificationEngine()
        check = engine.check_bld_01(build_res, is_real_build=True)
        assert check.status == "FAIL"
        assert check.outcome == "FAILED"


class TestApkStructureAndDexValidity:
    def test_apk_01_valid_apk(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["com.example.Foo"])
        dex_summary = inspect_apk_dex(apk)

        engine = VerificationEngine()
        check = engine.check_apk_01(apk, dex_summary)
        assert check.status == "PASS"
        assert check.outcome == "VERIFIED"

    def test_apk_01_missing_apk(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.apk"
        engine = VerificationEngine()
        check = engine.check_apk_01(missing, None)
        assert check.status == "FAIL"
        assert check.outcome == "FAILED"


class TestSignatureCheck:
    def test_sig_01_signing_disabled_skipped(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        engine = VerificationEngine()
        check = engine.check_sig_01(apk, signing_config=None)
        assert check.status == "SKIPPED"
        assert check.outcome == "UNSUPPORTED"

    def test_sig_01_tool_missing_skipped(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        cfg = SigningConfig(
            enabled=True,
            keystore_path=Path("k.jks"),
            key_alias="a",
            keystore_password_env="P",
        )
        engine = VerificationEngine()
        with patch("appshield.verify.find_apksigner", return_value=None):
            check = engine.check_sig_01(apk, signing_config=cfg)
            assert check.status == "SKIPPED"
            assert check.outcome == "UNSUPPORTED"

    def test_sig_01_valid_test_signature(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        cfg = SigningConfig(
            enabled=True,
            is_production=False,
            keystore_path=Path("k.jks"),
            key_alias="a",
            keystore_password_env="P",
        )

        mock_sig_res = ApkSignatureVerificationResult(
            is_valid=True,
            v2_scheme_signed=True,
            v3_scheme_signed=True,
            signer_certificate_dn="CN=TestKey",
        )

        engine = VerificationEngine()
        with (
            patch(
                "appshield.verify.find_apksigner", return_value=Path("/bin/apksigner")
            ),
            patch("appshield.verify.verify_apk_signature", return_value=mock_sig_res),
        ):
            check = engine.check_sig_01(apk, signing_config=cfg)
            assert check.status == "PASS"
            assert check.outcome == "VERIFIED"
            assert "test-signed" in check.observed_metric

    def test_sig_01_invalid_signature_fails(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        cfg = SigningConfig(
            enabled=True,
            is_production=False,
            keystore_path=Path("k.jks"),
            key_alias="a",
            keystore_password_env="P",
        )

        mock_sig_res = ApkSignatureVerificationResult(
            is_valid=False,
            errors=["Digest mismatch in classes.dex"],
        )

        engine = VerificationEngine()
        with (
            patch(
                "appshield.verify.find_apksigner", return_value=Path("/bin/apksigner")
            ),
            patch("appshield.verify.verify_apk_signature", return_value=mock_sig_res),
        ):
            check = engine.check_sig_01(apk, signing_config=cfg)
            assert check.status == "FAIL"
            assert check.outcome == "FAILED"


class TestAlignmentCheck:
    def test_aln_01_missing_tool_skipped(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        engine = VerificationEngine()
        with patch("appshield.verify.find_zipalign", return_value=None):
            check = engine.check_aln_01(apk)
            assert check.status == "SKIPPED"
            assert check.outcome == "UNSUPPORTED"

    def test_aln_01_verified_pass(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        engine = VerificationEngine()
        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            check = engine.check_aln_01(apk)
            assert check.status == "PASS"
            assert check.outcome == "VERIFIED"

    def test_aln_01_unaligned_fails(self, tmp_path: Path) -> None:
        apk = create_test_apk(tmp_path / "app.apk", classes=["a.a"])
        engine = VerificationEngine()
        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=False),
        ):
            check = engine.check_aln_01(apk)
            assert check.status == "FAIL"
            assert check.outcome == "FAILED"


class TestStringPoolScan:
    def test_str_01_clean_pool_passes(self, tmp_path: Path) -> None:
        apk = create_test_apk(
            tmp_path / "app.apk",
            classes=["a.a"],
            strings=["benign_string_1", "regular_ui_label"],
        )
        dex_summary = inspect_apk_dex(apk)
        engine = VerificationEngine()
        check = engine.check_str_01(dex_summary)
        assert check.status == "PASS"
        assert check.outcome == "HEURISTIC"
        assert "0 flagged secret patterns" in check.observed_metric

    def test_str_01_sensitive_pattern_detected_and_redacted(
        self, tmp_path: Path
    ) -> None:
        # Include a secret: AWS access key
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        apk = create_test_apk(
            tmp_path / "app.apk",
            classes=["a.a"],
            strings=["some_label", raw_secret],
        )
        dex_summary = inspect_apk_dex(apk)
        engine = VerificationEngine()
        check = engine.check_str_01(dex_summary)

        assert check.status == "FAIL"
        assert check.outcome == "HEURISTIC"
        assert "1 flagged pattern match(es)" in check.observed_metric

        # CRITICAL ASSERTION: The plaintext secret MUST NOT appear in the report details!
        details_str = json.dumps(check.details)
        assert raw_secret not in details_str
        assert "[REDACTED_SECRET_PATTERN]" in details_str

    def test_str_01_fixture_token_detected_and_redacted(self, tmp_path: Path) -> None:
        fixture_token = FIXTURE_TEST_STRINGS[0]
        apk = create_test_apk(
            tmp_path / "app.apk",
            classes=["a.a"],
            strings=["label", fixture_token],
        )
        dex_summary = inspect_apk_dex(apk)
        engine = VerificationEngine()
        check = engine.check_str_01(dex_summary)

        assert check.status == "FAIL"
        details_str = json.dumps(check.details)
        assert "[REDACTED_FIXTURE_TOKEN]" in details_str


class TestReportGeneration:
    def test_full_report_deterministic_structure(self, tmp_path: Path) -> None:
        apk = create_test_apk(
            tmp_path / "app.apk",
            classes=["a.a", "a.b", "com.example.sample.MainActivity"],
            strings=["clean_ui_text"],
        )
        map_file = tmp_path / "mapping.txt"
        map_file.write_text(SAMPLE_R8_MAPPING, encoding="utf-8")

        build_res = GradleBuildResult(
            success=True,
            exit_code=0,
            stdout="OK",
            stderr="",
            duration_seconds=2.0,
            command=["gradlew", "assembleRelease"],
            is_simulated=False,
        )

        engine = VerificationEngine(project_name="my_test_app")
        with (
            patch("appshield.verify.find_zipalign", return_value=Path("/bin/zipalign")),
            patch("appshield.verify.verify_zipalign", return_value=True),
        ):
            report = engine.run_all_checks(
                apk_path=apk,
                mapping_file=map_file,
                signing_config=None,  # unsigned
                build_result=build_res,
                is_real_build=True,
                expected_fixture_classes=[
                    "IdentifiableSecretService",
                    "PaymentSecurityValidator",
                ],
                expected_entry_points=["MainActivity"],
            )

        assert report.project_name == "my_test_app"
        assert report.summary["total_checks"] == 7
        assert report.summary["failed"] == 0
        assert report.is_verified_protected is True

        # Export JSON
        out_json = tmp_path / "audit_report.json"
        export_report_json(report, out_json)
        assert out_json.is_file()

        parsed_json = json.loads(out_json.read_text(encoding="utf-8"))
        assert parsed_json["project_name"] == "my_test_app"
        assert len(parsed_json["objective_checks"]) == 7

        # Terminal format
        term_text = format_report_terminal(report)
        assert "AppShield Empirical Verification Report" in term_text
        assert STANDARD_DISCLAIMER in term_text

        # Markdown format
        md_text = format_report_markdown(report)
        assert "# AppShield Verification Report: my_test_app" in md_text
        assert "| `CHK-SYM-01` |" in md_text


class TestSigningCredentialIsolationBoundary:
    """
    Validates Requirement 7:
    Signing password environment variables must NOT leak into the GradleRunner environment.
    """

    def test_gradle_runner_environment_strips_signing_passwords(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APPSHIELD_KS_PASS", "super_secret_keystore_password")
        monkeypatch.setenv("APPSHIELD_KEY_PASS", "super_secret_key_password")
        monkeypatch.setenv("MY_SIGNING_PASSWORD", "secret123")
        monkeypatch.setenv("JAVA_HOME", "/opt/jdk-17")

        safe_env = build_safe_env()

        # Build environment MUST NOT inherit signing credentials
        assert "APPSHIELD_KS_PASS" not in safe_env
        assert "APPSHIELD_KEY_PASS" not in safe_env
        assert "MY_SIGNING_PASSWORD" not in safe_env
        assert safe_env.get("JAVA_HOME") == "/opt/jdk-17"
