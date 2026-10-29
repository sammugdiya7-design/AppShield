"""
Unit tests for AppShield APK Alignment and Signing Workflow (Plan 04-02).
Tests zipalign execution, disposable keystore generation, apksigner invocation,
signature verification, credential masking, non-production guards, and output protection.
"""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from appshield.config import SigningConfig
from appshield.gradle import ArtifactExtractionError
from appshield.signing import (
    ApkSignatureVerificationError,
    ApkSignatureVerificationResult,
    ProductionSigningError,
    SigningCredentialError,
    SigningError,
    SigningToolchainMissingError,
    ZipAlignError,
    align_and_sign_apk,
    find_apksigner,
    find_keytool,
    find_zipalign,
    generate_disposable_test_keystore,
    sign_apk,
    verify_apk_signature,
    verify_zipalign,
    zipalign_apk,
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


class TestToolDiscovery:
    def test_find_zipalign_custom_path(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom_zipalign"
        custom.write_text("dummy", encoding="utf-8")
        assert find_zipalign(custom) == custom.resolve()

    def test_find_apksigner_custom_path(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom_apksigner"
        custom.write_text("dummy", encoding="utf-8")
        assert find_apksigner(custom) == custom.resolve()

    def test_find_keytool_custom_path(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom_keytool"
        custom.write_text("dummy", encoding="utf-8")
        assert find_keytool(custom) == custom.resolve()

    def test_find_tools_via_android_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sdk_dir = tmp_path / "mock_sdk"
        bt_dir = sdk_dir / "build-tools" / "34.0.0"
        bt_dir.mkdir(parents=True, exist_ok=True)
        zipalign_bin = bt_dir / "zipalign"
        zipalign_bin.write_text("dummy", encoding="utf-8")
        apksigner_bin = bt_dir / "apksigner"
        apksigner_bin.write_text("dummy", encoding="utf-8")

        monkeypatch.setenv("ANDROID_HOME", str(sdk_dir))
        assert find_zipalign() == zipalign_bin.resolve()
        assert find_apksigner() == apksigner_bin.resolve()


class TestDisposableKeystoreGeneration:
    def test_keystore_exists_no_overwrite_raises(self, tmp_path: Path) -> None:
        ks = tmp_path / "existing.jks"
        ks.write_bytes(b"dummy")
        with pytest.raises(FileExistsError):
            generate_disposable_test_keystore(ks, overwrite=False)

    def test_keytool_missing_raises_toolchain_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ks = tmp_path / "test.jks"
        monkeypatch.setattr("appshield.signing.find_keytool", lambda x=None: None)
        with pytest.raises(SigningToolchainMissingError):
            generate_disposable_test_keystore(ks)

    def test_generate_keystore_mocked_success(self, tmp_path: Path) -> None:
        ks = tmp_path / "test.jks"
        mock_keytool = tmp_path / "keytool"
        mock_keytool.write_text("dummy", encoding="utf-8")

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            # Create the file on invocation
            ks.write_bytes(b"mock_keystore_bytes")
            proc = MagicMock()
            proc.returncode = 0
            return proc

        with patch("subprocess.run", side_effect=fake_run):
            res = generate_disposable_test_keystore(
                keystore_path=ks,
                alias="test_alias",
                password="test_password_123",
                keytool_path=mock_keytool,
            )
            assert res == ks.resolve()
            assert ks.is_file()

    def test_generate_keystore_failure_redacts_password(self, tmp_path: Path) -> None:
        ks = tmp_path / "test.jks"
        mock_keytool = tmp_path / "keytool"
        mock_keytool.write_text("dummy", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "keytool error with storepass test_password_123 invalid"

        with patch("subprocess.run", return_value=mock_proc):
            with pytest.raises(SigningError) as exc_info:
                generate_disposable_test_keystore(
                    keystore_path=ks,
                    password="test_password_123",
                    keytool_path=mock_keytool,
                )
            assert "test_password_123" not in str(exc_info.value)
            assert "***REDACTED***" in str(exc_info.value)


class TestZipAlign:
    def test_zipalign_missing_input_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.apk"
        out = tmp_path / "out.apk"
        with pytest.raises(ArtifactExtractionError):
            zipalign_apk(missing, out)

    def test_zipalign_output_exists_no_overwrite_raises(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        out.write_bytes(b"dummy")
        with pytest.raises(FileExistsError):
            zipalign_apk(apk, out, overwrite=False)

    def test_zipalign_tool_missing_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        monkeypatch.setattr("appshield.signing.find_zipalign", lambda x=None: None)
        with pytest.raises(SigningToolchainMissingError):
            zipalign_apk(apk, out)

    def test_zipalign_mocked_success(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        mock_tool = tmp_path / "zipalign"
        mock_tool.write_text("dummy", encoding="utf-8")

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            create_dummy_apk(out)
            proc = MagicMock()
            proc.returncode = 0
            return proc

        with patch("subprocess.run", side_effect=fake_run):
            res = zipalign_apk(apk, out, zipalign_path=mock_tool)
            assert res == out.resolve()
            assert out.is_file()

    def test_zipalign_mocked_failure(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        mock_tool = tmp_path / "zipalign"
        mock_tool.write_text("dummy", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "zipalign error"

        with (
            patch("subprocess.run", return_value=mock_proc),
            pytest.raises(ZipAlignError),
        ):
            zipalign_apk(apk, out, zipalign_path=mock_tool)

    def test_verify_zipalign_true_and_false(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "test.apk")
        mock_tool = tmp_path / "zipalign"
        mock_tool.write_text("dummy", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        with patch("subprocess.run", return_value=mock_proc):
            assert verify_zipalign(apk, zipalign_path=mock_tool) is True

        mock_proc.returncode = 1
        with patch("subprocess.run", return_value=mock_proc):
            assert verify_zipalign(apk, zipalign_path=mock_tool) is False


class TestApkSigning:
    def test_production_guard_blocks_without_confirmation(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "prod.jks"
        ks.write_bytes(b"dummy")

        with pytest.raises(ProductionSigningError) as exc_info:
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="prod_key",
                keystore_password_env="PROD_KS_PASS",
                is_production=True,
                allow_production_signing=False,
            )
        assert "Automatic production signing is blocked" in str(exc_info.value)

    def test_missing_keystore_file_raises(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        missing_ks = tmp_path / "missing.jks"

        with pytest.raises(SigningCredentialError) as exc_info:
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=missing_ks,
                key_alias="test_key",
                keystore_password_env="TEST_KS_PASS",
            )
        assert "keystore file does not exist" in str(exc_info.value)

    def test_missing_env_var_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.delenv("UNSET_KS_PASS", raising=False)
        with pytest.raises(SigningCredentialError) as exc_info:
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="test_key",
                keystore_password_env="UNSET_KS_PASS",
            )
        assert (
            "Keystore password environment variable 'UNSET_KS_PASS' is not set"
            in str(exc_info.value)
        )

    def test_sign_apk_masked_arguments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.setenv("MY_KS_PASS_ENV", "super_secret_password_999")
        mock_apksigner = tmp_path / "apksigner"
        mock_apksigner.write_text("dummy", encoding="utf-8")

        executed_cmd: list[str] = []

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            nonlocal executed_cmd
            executed_cmd = cmd
            create_dummy_apk(out)
            proc = MagicMock()
            proc.returncode = 0
            return proc

        with patch("subprocess.run", side_effect=fake_run):
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="test_alias",
                keystore_password_env="MY_KS_PASS_ENV",
                apksigner_path=mock_apksigner,
            )

        # CRITICAL ASSERTION: The plaintext password MUST NOT appear in command arguments!
        cmd_str = " ".join(executed_cmd)
        assert "super_secret_password_999" not in cmd_str
        # MUST use apksigner's native env flag
        assert "--ks-pass env:MY_KS_PASS_ENV" in cmd_str
        assert "--key-pass env:MY_KS_PASS_ENV" in cmd_str

    def test_verify_apk_signature_valid_parsing(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "signed.apk")
        mock_apksigner = tmp_path / "apksigner"
        mock_apksigner.write_text("dummy", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = (
            "Verifies\n"
            "Verified using v1 scheme (JAR signing): true\n"
            "Verified using v2 scheme (APK Signature Scheme v2): true\n"
            "Verified using v3 scheme (APK Signature Scheme v3): true\n"
            "Verified using v4 scheme (APK Signature Scheme v4): false\n"
            "Number of signers: 1\n"
            "Signer #1 certificate DN: CN=AppShield Test, O=AppShield, C=US\n"
        )
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            res = verify_apk_signature(apk, apksigner_path=mock_apksigner)
            assert res.is_valid is True
            assert res.v1_scheme_signed is True
            assert res.v2_scheme_signed is True
            assert res.v3_scheme_signed is True
            assert res.v4_scheme_signed is False
            assert res.signer_certificate_dn == "CN=AppShield Test, O=AppShield, C=US"
            assert len(res.errors) == 0


class TestAlignAndSignWorkflow:
    def test_unsigned_workflow(self, tmp_path: Path) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"

        mock_zipalign = tmp_path / "zipalign"
        mock_zipalign.write_text("dummy", encoding="utf-8")

        with (
            patch("appshield.signing.zipalign_apk") as mock_align,
            patch("appshield.signing.verify_zipalign", return_value=True),
        ):
            # Simulate zipalign creating the output file
            def fake_align(input_apk: Path, output_apk: Path, **kwargs: object) -> Path:
                return create_dummy_apk(output_apk)

            mock_align.side_effect = fake_align

            res = align_and_sign_apk(
                unsigned_apk=raw_apk,
                output_dir=out_dir,
                signing_config=None,  # Signing disabled
                zipalign_path=mock_zipalign,
            )

            assert res.success is True
            assert res.signature_type == "unsigned"
            assert res.is_aligned is True
            assert res.signature_verification is None
            assert res.final_apk_path.name == "app-release-unsigned-aligned.apk"

    def test_signed_workflow_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.setenv("TEST_KS_PASS", "test_pass")

        signing_config = SigningConfig(
            enabled=True,
            is_production=False,
            keystore_path=ks,
            key_alias="test_key",
            keystore_password_env="TEST_KS_PASS",
        )

        with (
            patch("appshield.signing.zipalign_apk") as mock_align,
            patch("appshield.signing.sign_apk") as mock_sign,
            patch("appshield.signing.verify_apk_signature") as mock_verify_sig,
            patch("appshield.signing.verify_zipalign", return_value=True),
        ):

            def fake_align(input_apk: Path, output_apk: Path, **kwargs: object) -> Path:
                return create_dummy_apk(output_apk)

            def fake_sign(
                aligned_apk: Path, output_apk: Path, **kwargs: object
            ) -> Path:
                return create_dummy_apk(output_apk)

            mock_align.side_effect = fake_align
            mock_sign.side_effect = fake_sign
            mock_verify_sig.return_value = ApkSignatureVerificationResult(
                is_valid=True,
                v2_scheme_signed=True,
                signer_certificate_dn="CN=Test",
            )

            res = align_and_sign_apk(
                unsigned_apk=raw_apk,
                output_dir=out_dir,
                signing_config=signing_config,
            )

            assert res.success is True
            assert res.signature_type == "test_signed"
            assert res.is_aligned is True
            assert res.signature_verification is not None
            assert res.signature_verification.is_valid is True
            assert res.final_apk_path.name == "app-release-test-signed.apk"

    def test_signed_workflow_sig_verification_failure_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.setenv("TEST_KS_PASS", "test_pass")

        signing_config = SigningConfig(
            enabled=True,
            is_production=False,
            keystore_path=ks,
            key_alias="test_key",
            keystore_password_env="TEST_KS_PASS",
        )

        with (
            patch("appshield.signing.zipalign_apk") as mock_align,
            patch("appshield.signing.sign_apk") as mock_sign,
            patch("appshield.signing.verify_apk_signature") as mock_verify_sig,
        ):

            def fake_align(input_apk: Path, output_apk: Path, **kwargs: object) -> Path:
                return create_dummy_apk(output_apk)

            def fake_sign(
                aligned_apk: Path, output_apk: Path, **kwargs: object
            ) -> Path:
                return create_dummy_apk(output_apk)

            mock_align.side_effect = fake_align
            mock_sign.side_effect = fake_sign
            mock_verify_sig.return_value = ApkSignatureVerificationResult(
                is_valid=False,
                errors=["Signature verification failed"],
            )

            with pytest.raises(ApkSignatureVerificationError):
                align_and_sign_apk(
                    unsigned_apk=raw_apk,
                    output_dir=out_dir,
                    signing_config=signing_config,
                )

    def test_signed_workflow_alignment_verification_failure_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.setenv("TEST_KS_PASS", "test_pass")

        signing_config = SigningConfig(
            enabled=True,
            is_production=False,
            keystore_path=ks,
            key_alias="test_key",
            keystore_password_env="TEST_KS_PASS",
        )

        with (
            patch("appshield.signing.zipalign_apk") as mock_align,
            patch("appshield.signing.sign_apk") as mock_sign,
            patch("appshield.signing.verify_apk_signature") as mock_verify_sig,
            patch("appshield.signing.verify_zipalign", return_value=False),
        ):

            def fake_align(input_apk: Path, output_apk: Path, **kwargs: object) -> Path:
                return create_dummy_apk(output_apk)

            def fake_sign(
                aligned_apk: Path, output_apk: Path, **kwargs: object
            ) -> Path:
                return create_dummy_apk(output_apk)

            mock_align.side_effect = fake_align
            mock_sign.side_effect = fake_sign
            mock_verify_sig.return_value = ApkSignatureVerificationResult(
                is_valid=True,
                v2_scheme_signed=True,
            )

            with pytest.raises(ZipAlignError, match="Alignment verification failed"):
                align_and_sign_apk(
                    unsigned_apk=raw_apk,
                    output_dir=out_dir,
                    signing_config=signing_config,
                )

    def test_align_and_sign_unsigned_alignment_fail(self, tmp_path: Path) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"

        with (
            patch("appshield.signing.zipalign_apk"),
            patch("appshield.signing.verify_zipalign", return_value=False),
            pytest.raises(
                ZipAlignError, match="Alignment verification failed on unsigned"
            ),
        ):
            align_and_sign_apk(
                unsigned_apk=raw_apk,
                output_dir=out_dir,
                signing_config=None,
            )

    def test_align_and_sign_missing_config_fields(self, tmp_path: Path) -> None:
        raw_apk = create_dummy_apk(tmp_path / "app-release-unsigned.apk")
        out_dir = tmp_path / "dist"
        with patch("appshield.signing.zipalign_apk"):
            # Missing keystore_path
            cfg1 = SigningConfig(
                enabled=True,
                keystore_path=None,
                key_alias="a",
                keystore_password_env="P",
            )
            with pytest.raises(SigningCredentialError, match="keystore_path"):
                align_and_sign_apk(raw_apk, out_dir, signing_config=cfg1)

            # Missing key_alias
            cfg2 = SigningConfig(
                enabled=True,
                keystore_path=Path("k.jks"),
                key_alias=None,
                keystore_password_env="P",
            )
            with pytest.raises(SigningCredentialError, match="key_alias"):
                align_and_sign_apk(raw_apk, out_dir, signing_config=cfg2)

            # Missing keystore_password_env
            cfg3 = SigningConfig(
                enabled=True,
                keystore_path=Path("k.jks"),
                key_alias="a",
                keystore_password_env=None,
            )
            with pytest.raises(SigningCredentialError, match="keystore_password_env"):
                align_and_sign_apk(raw_apk, out_dir, signing_config=cfg3)


class TestSigningEdgeCases:
    def test_find_tools_path_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANDROID_HOME", raising=False)
        monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)
        monkeypatch.setattr("shutil.which", lambda x: f"/bin/{x}")
        assert find_zipalign() == Path("/bin/zipalign").resolve()
        assert find_apksigner() == Path("/bin/apksigner").resolve()
        assert find_keytool() == Path("/bin/keytool").resolve()

    def test_find_keytool_via_java_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        java_home = tmp_path / "jdk"
        bin_dir = java_home / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        tool_name = "keytool.exe" if os.name == "nt" else "keytool"
        kt = bin_dir / tool_name
        kt.write_text("dummy", encoding="utf-8")
        monkeypatch.setenv("JAVA_HOME", str(java_home))
        assert find_keytool() == kt.resolve()

    def test_generate_keystore_timeout_and_oserror(self, tmp_path: Path) -> None:
        ks = tmp_path / "test.jks"
        mock_keytool = tmp_path / "keytool"
        mock_keytool.write_text("dummy", encoding="utf-8")

        with (
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["keytool"], timeout=30),
            ),
            pytest.raises(SigningError, match="timed out"),
        ):
            generate_disposable_test_keystore(ks, keytool_path=mock_keytool)

        with (
            patch("subprocess.run", side_effect=OSError("OS spawn failure")),
            pytest.raises(SigningError, match="Failed to execute keytool"),
        ):
            generate_disposable_test_keystore(ks, keytool_path=mock_keytool)

    def test_zipalign_timeout_and_oserror(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        mock_tool = tmp_path / "zipalign"
        mock_tool.write_text("dummy", encoding="utf-8")

        with (
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["zipalign"], timeout=60),
            ),
            pytest.raises(ZipAlignError, match="timed out"),
        ):
            zipalign_apk(apk, out, zipalign_path=mock_tool)

        with (
            patch("subprocess.run", side_effect=OSError("OS error")),
            pytest.raises(ZipAlignError, match="Failed to execute zipalign"),
        ):
            zipalign_apk(apk, out, zipalign_path=mock_tool)

    def test_sign_apk_different_key_pass_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")

        monkeypatch.setenv("KS_PASS", "ks_secret")
        monkeypatch.setenv("KEY_PASS", "key_secret")
        mock_tool = tmp_path / "apksigner"
        mock_tool.write_text("dummy", encoding="utf-8")

        def fake_run(cmd: list[str], **kwargs: object) -> MagicMock:
            create_dummy_apk(out)
            proc = MagicMock()
            proc.returncode = 0
            return proc

        with patch("subprocess.run", side_effect=fake_run) as mock_run:
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="test_alias",
                keystore_password_env="KS_PASS",
                key_password_env="KEY_PASS",
                apksigner_path=mock_tool,
            )
            cmd_called = " ".join(mock_run.call_args[0][0])
            assert "--ks-pass env:KS_PASS" in cmd_called
            assert "--key-pass env:KEY_PASS" in cmd_called

    def test_sign_apk_timeout_and_oserror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")
        monkeypatch.setenv("KS_PASS", "secret")
        mock_tool = tmp_path / "apksigner"
        mock_tool.write_text("dummy", encoding="utf-8")

        with (
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["apksigner"], timeout=90),
            ),
            pytest.raises(SigningError, match="timed out"),
        ):
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="alias",
                keystore_password_env="KS_PASS",
                apksigner_path=mock_tool,
            )

        with (
            patch("subprocess.run", side_effect=OSError("OS error")),
            pytest.raises(SigningError, match="Failed to execute apksigner"),
        ):
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="alias",
                keystore_password_env="KS_PASS",
                apksigner_path=mock_tool,
            )

    def test_sign_apk_returncode_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        apk = create_dummy_apk(tmp_path / "in.apk")
        out = tmp_path / "out.apk"
        ks = tmp_path / "test.jks"
        ks.write_bytes(b"dummy")
        monkeypatch.setenv("KS_PASS", "secret")
        mock_tool = tmp_path / "apksigner"
        mock_tool.write_text("dummy", encoding="utf-8")

        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stderr = "apksigner: Keystore password incorrect"

        with (
            patch("subprocess.run", return_value=mock_proc),
            pytest.raises(SigningError, match="apksigner failed with exit code 2"),
        ):
            sign_apk(
                aligned_apk=apk,
                output_apk=out,
                keystore_path=ks,
                key_alias="alias",
                keystore_password_env="KS_PASS",
                apksigner_path=mock_tool,
            )

    def test_verify_signature_exception_handling(self, tmp_path: Path) -> None:
        apk = create_dummy_apk(tmp_path / "signed.apk")
        mock_tool = tmp_path / "apksigner"
        mock_tool.write_text("dummy", encoding="utf-8")

        with patch(
            "subprocess.run", side_effect=subprocess.SubprocessError("Unexpected crash")
        ):
            res = verify_apk_signature(apk, apksigner_path=mock_tool)
            assert res.is_valid is False
            assert any("Failed to execute" in err for err in res.errors)
