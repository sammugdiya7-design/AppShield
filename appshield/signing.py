"""
AppShield APK Alignment and Signing Workflow.
Implements the verified order of operations:
  1. Build APK (unsigned)
  2. ZipAlign unsigned APK (4-byte page-aligned)
  3. Sign aligned APK using apksigner with masked environment variables
  4. Verify resulting APK signature
  5. Confirm alignment on final signed APK without modifying it

Enforces non-production safety guards, credential redaction, and distinct
classification of unsigned, test-signed, and production-signed artifacts.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from appshield.config import SigningConfig
from appshield.gradle import redact_secrets, validate_apk_file

SignatureType = Literal["unsigned", "test_signed", "production_signed"]


class SigningError(Exception):
    """Base exception for all APK signing and alignment errors."""


class SigningToolchainMissingError(SigningError):
    """Raised when required signing or alignment tools (zipalign, apksigner, keytool) are missing."""


class SigningCredentialError(SigningError):
    """Raised when required credential environment variables are missing or invalid."""


class ProductionSigningError(SigningError):
    """Raised when production signing is attempted without explicit developer authorization."""


class ZipAlignError(SigningError):
    """Raised when APK zip alignment or alignment verification fails."""


class ApkSignatureVerificationError(SigningError):
    """Raised when APK signature verification fails."""


@dataclass(frozen=True)
class ApkSignatureVerificationResult:
    """Detailed result of apksigner verify inspection."""

    is_valid: bool
    v1_scheme_signed: bool = False
    v2_scheme_signed: bool = False
    v3_scheme_signed: bool = False
    v4_scheme_signed: bool = False
    signer_certificate_dn: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_output: str = ""


@dataclass(frozen=True)
class SigningResult:
    """Result of the complete alignment and signing workflow."""

    success: bool
    signature_type: SignatureType
    aligned_apk_path: Path
    final_apk_path: Path
    is_aligned: bool
    signature_verification: ApkSignatureVerificationResult | None = None
    keystore_used: Path | None = None
    metadata: dict[str, str] = field(default_factory=dict)


def find_tool_in_build_tools(tool_name: str) -> Path | None:
    """
    Search for a tool in the Android SDK build-tools directories.
    Checks $ANDROID_HOME and $ANDROID_SDK_ROOT.
    """
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not android_home:
        return None

    sdk_path = Path(android_home)
    build_tools_dir = sdk_path / "build-tools"
    if not build_tools_dir.is_dir():
        return None

    # Search in reverse order (newest version first)
    versions = sorted(
        [d for d in build_tools_dir.iterdir() if d.is_dir()],
        key=lambda d: d.name,
        reverse=True,
    )

    executable_names = [tool_name]
    if sys.platform == "win32":
        executable_names.extend([f"{tool_name}.bat", f"{tool_name}.exe"])

    for ver_dir in versions:
        for name in executable_names:
            candidate = ver_dir / name
            if candidate.is_file():
                return candidate

    return None


def find_zipalign(custom_path: Path | None = None) -> Path | None:
    """Locate the zipalign executable via custom path, build-tools, or PATH."""
    if custom_path is not None and custom_path.is_file():
        return custom_path.resolve()

    in_build_tools = find_tool_in_build_tools("zipalign")
    if in_build_tools is not None:
        return in_build_tools

    which_result = shutil.which("zipalign")
    if which_result:
        return Path(which_result).resolve()

    return None


def find_apksigner(custom_path: Path | None = None) -> Path | None:
    """Locate the apksigner executable via custom path, build-tools, or PATH."""
    if custom_path is not None and custom_path.is_file():
        return custom_path.resolve()

    in_build_tools = find_tool_in_build_tools("apksigner")
    if in_build_tools is not None:
        return in_build_tools

    which_result = shutil.which("apksigner")
    if which_result:
        return Path(which_result).resolve()

    return None


def find_keytool(custom_path: Path | None = None) -> Path | None:
    """Locate the keytool executable via custom path, JAVA_HOME, or PATH."""
    if custom_path is not None and custom_path.is_file():
        return custom_path.resolve()

    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        tool_name = "keytool.exe" if sys.platform == "win32" else "keytool"
        candidate = Path(java_home) / "bin" / tool_name
        if candidate.is_file():
            return candidate.resolve()

    which_result = shutil.which("keytool")
    if which_result:
        return Path(which_result).resolve()

    return None


def generate_disposable_test_keystore(
    keystore_path: Path,
    alias: str = "appshield_test",
    password: str = "appshield_test_pass",  # nosec: B107
    validity_days: int = 365,
    keytool_path: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """
    Generate a disposable RSA 2048-bit test keystore using keytool.
    Intended strictly for automated test suites and fixture validation.
    Must never be used for production applications.
    """
    resolved_path = keystore_path.resolve()
    if resolved_path.exists() and not overwrite:
        raise FileExistsError(
            f"Keystore file already exists: '{resolved_path}'. Use overwrite=True to replace."
        )

    resolved_keytool = find_keytool(keytool_path)
    if resolved_keytool is None:
        raise SigningToolchainMissingError(
            "Java 'keytool' executable was not found. "
            "Please ensure OpenJDK/JDK is installed and JAVA_HOME is configured."
        )

    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(resolved_keytool),
        "-genkeypair",
        "-v",
        "-keystore",
        str(resolved_path),
        "-alias",
        alias,
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        str(validity_days),
        "-storepass",
        password,
        "-keypass",
        password,
        "-dname",
        "CN=AppShield Disposable Test, OU=Testing, O=AppShield, C=US",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as e:
        raise SigningError(
            "keytool timed out while generating disposable test keystore."
        ) from e
    except OSError as e:
        raise SigningError(f"Failed to execute keytool: {e}") from e

    if proc.returncode != 0:
        err_msg = redact_secrets(proc.stderr, [password])
        raise SigningError(
            f"keytool failed with exit code {proc.returncode}: {err_msg}"
        )

    if not resolved_path.is_file() or resolved_path.stat().st_size == 0:
        raise SigningError(
            f"Keystore generation failed: file was not created at '{resolved_path}'"
        )

    return resolved_path


def zipalign_apk(
    input_apk: Path,
    output_apk: Path,
    zipalign_path: Path | None = None,
    alignment: int = 4,
    overwrite: bool = False,
) -> Path:
    """
    Align uncompressed APK archive data boundaries to 4-byte page boundaries using zipalign.

    Args:
        input_apk: Path to input (unsigned or unaligned) APK.
        output_apk: Destination path for aligned APK.
        zipalign_path: Optional explicit path to zipalign binary.
        alignment: Alignment boundary in bytes (default: 4).
        overwrite: Allow overwriting destination if it already exists.

    Returns:
        Path to aligned APK.
    """
    input_resolved = input_apk.resolve()
    validate_apk_file(input_resolved)

    output_resolved = output_apk.resolve()
    if output_resolved.exists() and not overwrite:
        raise FileExistsError(
            f"Output aligned APK already exists: '{output_resolved}'. Overwrite not authorized."
        )

    tool = find_zipalign(zipalign_path)
    if tool is None:
        raise SigningToolchainMissingError(
            "Android SDK 'zipalign' tool was not found on PATH or in ANDROID_HOME/build-tools."
        )

    output_resolved.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(tool),
        "-p",  # page-align shared object files
        "-f",  # overwrite existing outputFile
        str(alignment),
        str(input_resolved),
        str(output_resolved),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired as e:
        raise ZipAlignError("zipalign timed out during alignment.") from e
    except OSError as e:
        raise ZipAlignError(f"Failed to execute zipalign: {e}") from e

    if proc.returncode != 0:
        raise ZipAlignError(
            f"zipalign failed with exit code {proc.returncode}: {proc.stderr.strip()}"
        )

    validate_apk_file(output_resolved)
    return output_resolved


def verify_zipalign(
    apk_path: Path,
    zipalign_path: Path | None = None,
    alignment: int = 4,
) -> bool:
    """
    Verify that an APK's data boundaries are aligned on 4-byte boundaries.
    Runs `zipalign -c -v <alignment> <apk_path>`.
    Does NOT modify the APK.
    """
    resolved = apk_path.resolve()
    if not resolved.is_file():
        return False

    tool = find_zipalign(zipalign_path)
    if tool is None:
        raise SigningToolchainMissingError(
            "Android SDK 'zipalign' tool was not found to verify alignment."
        )

    cmd = [
        str(tool),
        "-c",  # check alignment
        "-v",  # verbose
        str(alignment),
        str(resolved),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def sign_apk(
    aligned_apk: Path,
    output_apk: Path,
    keystore_path: Path,
    key_alias: str,
    keystore_password_env: str,
    key_password_env: str | None = None,
    apksigner_path: Path | None = None,
    is_production: bool = False,
    allow_production_signing: bool = False,
    overwrite: bool = False,
) -> Path:
    """
    Sign an aligned APK using apksigner with credentials passed strictly via environment variables.

    Security Invariants:
      - Passwords are NEVER passed in command-line arguments.
      - Passwords are read by apksigner directly using `--ks-pass env:<VAR>` and `--key-pass env:<VAR>`.
      - Production release signing is blocked unless explicit confirmation is provided.
    """
    if is_production and not allow_production_signing:
        raise ProductionSigningError(
            "Automatic production signing is blocked by safety policy. "
            "Production signing requires explicit developer confirmation."
        )

    aligned_resolved = aligned_apk.resolve()
    validate_apk_file(aligned_resolved)

    output_resolved = output_apk.resolve()
    if output_resolved.exists() and not overwrite:
        raise FileExistsError(
            f"Target signed APK already exists: '{output_resolved}'. Overwrite not authorized."
        )

    ks_resolved = keystore_path.resolve()
    if not ks_resolved.is_file():
        raise SigningCredentialError(
            f"Signing keystore file does not exist: '{ks_resolved}'"
        )

    # Verify that the required password environment variables are set
    if keystore_password_env not in os.environ:
        raise SigningCredentialError(
            f"Keystore password environment variable '{keystore_password_env}' is not set."
        )

    effective_key_pass_env = key_password_env or keystore_password_env
    if effective_key_pass_env not in os.environ:
        raise SigningCredentialError(
            f"Key password environment variable '{effective_key_pass_env}' is not set."
        )

    tool = find_apksigner(apksigner_path)
    if tool is None:
        raise SigningToolchainMissingError(
            "Android SDK 'apksigner' tool was not found on PATH or in ANDROID_HOME/build-tools."
        )

    output_resolved.parent.mkdir(parents=True, exist_ok=True)

    # Note: apksigner sign natively supports `--ks-pass env:<VAR>`!
    # This guarantees the password NEVER appears in process command arguments or logs.
    cmd = [
        str(tool),
        "sign",
        "--ks",
        str(ks_resolved),
        "--ks-key-alias",
        key_alias,
        "--ks-pass",
        f"env:{keystore_password_env}",
        "--key-pass",
        f"env:{effective_key_pass_env}",
        "--out",
        str(output_resolved),
        str(aligned_resolved),
    ]

    # Redact actual secret strings in any potential error formatting
    secrets_to_redact = [
        os.environ.get(keystore_password_env, ""),
        os.environ.get(effective_key_pass_env, ""),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
    except subprocess.TimeoutExpired as e:
        raise SigningError("apksigner timed out during signing.") from e
    except OSError as e:
        raise SigningError(f"Failed to execute apksigner: {e}") from e

    if proc.returncode != 0:
        err_msg = redact_secrets(proc.stderr, secrets_to_redact)
        raise SigningError(
            f"apksigner failed with exit code {proc.returncode}: {err_msg.strip()}"
        )

    validate_apk_file(output_resolved)
    return output_resolved


def verify_apk_signature(
    apk_path: Path,
    apksigner_path: Path | None = None,
) -> ApkSignatureVerificationResult:
    """
    Verify the signature of an APK using `apksigner verify --verbose`.
    Parses v1, v2, v3, and v4 signing scheme statuses and signer certificates.
    """
    resolved = apk_path.resolve()
    validate_apk_file(resolved)

    tool = find_apksigner(apksigner_path)
    if tool is None:
        raise SigningToolchainMissingError(
            "Android SDK 'apksigner' tool was not found to verify signature."
        )

    cmd = [
        str(tool),
        "verify",
        "--verbose",
        str(resolved),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError) as e:
        return ApkSignatureVerificationResult(
            is_valid=False,
            errors=[f"Failed to execute apksigner verify: {e}"],
        )

    output = proc.stdout + "\n" + proc.stderr
    is_valid = proc.returncode == 0

    v1 = bool(
        re.search(
            r"Verified using v1 scheme \(JAR signing\):\s*true",
            output,
            re.IGNORECASE,
        )
    )
    v2 = bool(
        re.search(
            r"Verified using v2 scheme \(APK Signature Scheme v2\):\s*true",
            output,
            re.IGNORECASE,
        )
    )
    v3 = bool(
        re.search(
            r"Verified using v3 scheme \(APK Signature Scheme v3\):\s*true",
            output,
            re.IGNORECASE,
        )
    )
    v4 = bool(
        re.search(
            r"Verified using v4 scheme \(APK Signature Scheme v4\):\s*true",
            output,
            re.IGNORECASE,
        )
    )

    dn_match = re.search(
        r"Signer #[0-9]+ certificate DN:\s*(.+)", output, re.IGNORECASE
    )
    cert_dn = dn_match.group(1).strip() if dn_match else None

    errors: list[str] = []
    warnings: list[str] = []

    for line in output.splitlines():
        line_trimmed = line.strip()
        if line_trimmed.startswith("ERROR:"):
            errors.append(line_trimmed[6:].strip())
        elif line_trimmed.startswith("WARNING:"):
            warnings.append(line_trimmed[8:].strip())

    return ApkSignatureVerificationResult(
        is_valid=is_valid,
        v1_scheme_signed=v1,
        v2_scheme_signed=v2,
        v3_scheme_signed=v3,
        v4_scheme_signed=v4,
        signer_certificate_dn=cert_dn,
        warnings=warnings,
        errors=errors,
        raw_output=output,
    )


def align_and_sign_apk(
    unsigned_apk: Path,
    output_dir: Path,
    signing_config: SigningConfig | None = None,
    zipalign_path: Path | None = None,
    apksigner_path: Path | None = None,
    allow_production_signing: bool = False,
    overwrite: bool = False,
) -> SigningResult:
    """
    Orchestrate the complete, verified APK alignment and signing pipeline.

    Workflow:
      1. Verify unsigned APK exists and is readable.
      2. If signing is disabled:
         - Align unsigned APK using zipalign -> produces aligned unsigned APK.
         - Verify 4-byte alignment.
         - Return SigningResult with signature_type='unsigned'.
      3. If signing is enabled:
         - Check non-production safety guard.
         - Align unsigned APK into intermediate file.
         - Sign aligned APK using apksigner with environment variables.
         - Verify signature validity using apksigner verify.
         - Check alignment on final signed APK (never modifies signed APK).
         - Label artifact as 'test_signed' or 'production_signed'.
    """
    unsigned_resolved = unsigned_apk.resolve()
    validate_apk_file(unsigned_resolved)

    output_dir_resolved = output_dir.resolve()
    output_dir_resolved.mkdir(parents=True, exist_ok=True)

    base_name = unsigned_resolved.stem
    # Strip '-unsigned' suffix if present for clean target naming
    clean_stem = base_name.removesuffix("-unsigned")

    # 1. Signing Disabled: produce aligned unsigned APK
    if signing_config is None or not signing_config.enabled:
        aligned_unsigned_target = (
            output_dir_resolved / f"{clean_stem}-unsigned-aligned.apk"
        )
        zipalign_apk(
            input_apk=unsigned_resolved,
            output_apk=aligned_unsigned_target,
            zipalign_path=zipalign_path,
            alignment=4,
            overwrite=overwrite,
        )

        is_aligned = verify_zipalign(
            aligned_unsigned_target, zipalign_path=zipalign_path, alignment=4
        )
        if not is_aligned:
            raise ZipAlignError(
                f"Alignment verification failed on unsigned artifact: '{aligned_unsigned_target.name}'"
            )

        return SigningResult(
            success=True,
            signature_type="unsigned",
            aligned_apk_path=aligned_unsigned_target,
            final_apk_path=aligned_unsigned_target,
            is_aligned=is_aligned,
            signature_verification=None,
            keystore_used=None,
            metadata={"status": "unsigned_aligned"},
        )

    # 2. Signing Enabled
    if not signing_config.keystore_path:
        raise SigningCredentialError(
            "Signing is enabled in configuration, but 'keystore_path' is missing."
        )
    if not signing_config.key_alias:
        raise SigningCredentialError(
            "Signing is enabled in configuration, but 'key_alias' is missing."
        )
    if not signing_config.keystore_password_env:
        raise SigningCredentialError(
            "Signing is enabled in configuration, but 'keystore_password_env' is missing."
        )

    # Intermediate aligned file before signing
    temp_aligned = output_dir_resolved / f"{clean_stem}-temp-aligned.apk"
    zipalign_apk(
        input_apk=unsigned_resolved,
        output_apk=temp_aligned,
        zipalign_path=zipalign_path,
        alignment=4,
        overwrite=True,
    )

    # Final signed APK
    sig_label = "production" if signing_config.is_production else "test"
    final_signed_apk = output_dir_resolved / f"{clean_stem}-{sig_label}-signed.apk"

    try:
        sign_apk(
            aligned_apk=temp_aligned,
            output_apk=final_signed_apk,
            keystore_path=signing_config.keystore_path,
            key_alias=signing_config.key_alias,
            keystore_password_env=signing_config.keystore_password_env,
            key_password_env=signing_config.key_password_env,
            apksigner_path=apksigner_path,
            is_production=signing_config.is_production,
            allow_production_signing=allow_production_signing,
            overwrite=overwrite,
        )
    finally:
        # Clean up temporary aligned artifact
        if temp_aligned.exists():
            try:
                temp_aligned.unlink()
            except OSError:
                pass

    # Step 4: Verify signature
    sig_verification = verify_apk_signature(
        final_signed_apk, apksigner_path=apksigner_path
    )
    if not sig_verification.is_valid:
        raise ApkSignatureVerificationError(
            f"Signature verification failed on '{final_signed_apk.name}': "
            f"{'; '.join(sig_verification.errors)}"
        )

    # Step 5: Check alignment without modifying the signed APK
    is_aligned = verify_zipalign(
        final_signed_apk, zipalign_path=zipalign_path, alignment=4
    )
    if not is_aligned:
        raise ZipAlignError(
            f"Alignment verification failed on signed APK '{final_signed_apk.name}'. "
            f"APK will not be modified after signing."
        )

    signature_type: SignatureType = (
        "production_signed" if signing_config.is_production else "test_signed"
    )

    return SigningResult(
        success=True,
        signature_type=signature_type,
        aligned_apk_path=final_signed_apk,
        final_apk_path=final_signed_apk,
        is_aligned=is_aligned,
        signature_verification=sig_verification,
        keystore_used=signing_config.keystore_path,
        metadata={
            "status": signature_type,
            "certificate_dn": sig_verification.signer_certificate_dn or "Unknown",
        },
    )
