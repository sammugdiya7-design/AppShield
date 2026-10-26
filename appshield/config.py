"""
AppShield Configuration Loader and Validator.
Handles YAML/JSON configuration files, validation against the Phase 2 schema,
safe output path checks, and overwrite protection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml

    HAVE_YAML = True
except ImportError:  # pragma: no cover
    HAVE_YAML = False


# Default sensitive and build cache patterns excluded when copying to staging
DEFAULT_EXCLUDE_PATTERNS = [
    ".git/**",
    ".git",
    "build/**",
    "**/build/**",
    ".gradle/**",
    "**/*.jks",
    "**/*.keystore",
    "local.properties",
    "**/*.env*",
    "**/google-services.json",
    ".appshield_staging/**",
    ".appshield_staging",
]

PROJECT_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_-]+$")
ENV_VAR_REGEX = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class AppShieldError(Exception):
    """Base exception for all AppShield errors."""


class ConfigError(AppShieldError):
    """Raised when configuration cannot be loaded or parsed."""


class ConfigNotFoundError(ConfigError):
    """Raised when the specified configuration file does not exist."""


class ConfigValidationError(ConfigError):
    """Raised when configuration values fail schema or safety validation."""


class OverwriteError(AppShieldError):
    """Raised when an output artifact would overwrite an existing file without authorization."""


@dataclass
class InputConfig:
    project_dir: Path
    verify_source_immutability: bool = True
    exclude_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS)
    )


@dataclass
class OutputConfig:
    dir: Path = field(default_factory=lambda: Path("./dist/protected"))
    overwrite_existing: bool = False


@dataclass
class SigningConfig:
    enabled: bool = False
    is_production: bool = False
    keystore_path: Path | None = None
    key_alias: str | None = None
    keystore_password_env: str | None = None
    key_password_env: str | None = None


@dataclass
class AndroidConfig:
    project_type: str = "gradle"
    build_variant: str = "release"
    gradle_task: str = "assembleRelease"
    r8_rules_file: Path | None = None
    signing: SigningConfig = field(default_factory=SigningConfig)


@dataclass
class VerificationConfig:
    enabled: bool = True
    fail_on_check_failure: bool = False
    checks: list[str] = field(
        default_factory=lambda: [
            "symbol_renaming_ratio",
            "string_pool_inspection",
            "signature_integrity",
            "package_alignment",
            "structural_decompilation_info",
        ]
    )


@dataclass
class AppShieldConfig:
    version: str
    project_name: str
    platform: str
    input: InputConfig
    output: OutputConfig
    android: AndroidConfig = field(default_factory=AndroidConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    config_source: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a safe, serializable dictionary without exposing secrets."""
        return {
            "version": self.version,
            "project_name": self.project_name,
            "platform": self.platform,
            "input": {
                "project_dir": str(self.input.project_dir),
                "verify_source_immutability": self.input.verify_source_immutability,
                "exclude_patterns": self.input.exclude_patterns,
            },
            "output": {
                "dir": str(self.output.dir),
                "overwrite_existing": self.output.overwrite_existing,
            },
            "android": {
                "project_type": self.android.project_type,
                "build_variant": self.android.build_variant,
                "gradle_task": self.android.gradle_task,
                "r8_rules_file": str(self.android.r8_rules_file)
                if self.android.r8_rules_file
                else None,
                "signing": {
                    "enabled": self.android.signing.enabled,
                    "is_production": self.android.signing.is_production,
                    "keystore_path": str(self.android.signing.keystore_path)
                    if self.android.signing.keystore_path
                    else None,
                    "key_alias": self.android.signing.key_alias,
                    "keystore_password_env": self.android.signing.keystore_password_env,
                    "key_password_env": self.android.signing.key_password_env,
                },
            },
            "verification": {
                "enabled": self.verification.enabled,
                "fail_on_check_failure": self.verification.fail_on_check_failure,
                "checks": self.verification.checks,
            },
        }


def load_config_file(config_path: Path | str) -> dict[str, Any]:
    """
    Read raw data from a YAML or JSON file.
    Does not modify the original file.
    """
    path = Path(config_path).resolve()
    if not path.is_file():
        raise ConfigNotFoundError(f"Configuration file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except Exception as e:
        raise ConfigError(f"Failed to read configuration file '{path}': {e}") from e

    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        if not HAVE_YAML:  # pragma: no cover
            raise ConfigError(
                "PyYAML is required to parse YAML configuration files. Please install pyyaml."
            )
        try:
            data = yaml.safe_load(content)
        except Exception as e:
            raise ConfigError(f"Malformed YAML in '{path}': {e}") from e
    elif suffix == ".json":
        try:
            data = json.loads(content)
        except Exception as e:
            raise ConfigError(f"Malformed JSON in '{path}': {e}") from e
    else:
        # Attempt JSON first, then YAML if supported
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            if HAVE_YAML:
                try:
                    data = yaml.safe_load(content)
                except Exception as e:
                    raise ConfigError(
                        f"Unsupported or malformed configuration in '{path}': {e}"
                    ) from e
            else:  # pragma: no cover
                raise ConfigError(
                    f"Unsupported configuration file extension '{suffix}'. Use .json or .yaml."
                )

    if not isinstance(data, dict):
        raise ConfigValidationError(
            f"Configuration file '{path}' must define a top-level dictionary/object."
        )

    return data


def validate_and_parse_config(
    raw_data: dict[str, Any],
    base_dir: Path | None = None,
    source_path: Path | None = None,
) -> AppShieldConfig:
    """
    Validate raw dictionary data against the AppShield Phase 2 specification
    and produce a typed AppShieldConfig.
    """
    if base_dir is None:
        base_dir = source_path.parent if source_path else Path.cwd()

    # 1. Top-level required fields
    version = raw_data.get("version")
    if version != "1.0":
        raise ConfigValidationError(
            f"Invalid or unsupported configuration version: '{version}'. Expected '1.0'."
        )

    project_name = raw_data.get("project_name")
    if (
        not project_name
        or not isinstance(project_name, str)
        or not PROJECT_NAME_REGEX.match(project_name)
    ):
        raise ConfigValidationError(
            f"Invalid 'project_name': '{project_name}'. Must be alphanumeric with underscores or dashes."
        )

    platform = raw_data.get("platform")
    if platform not in ("android", "ios", "windows"):
        raise ConfigValidationError(
            f"Unsupported platform: '{platform}'. Supported platforms in specification: 'android', 'ios', 'windows'."
        )

    # 2. Input configuration
    raw_input = raw_data.get("input")
    if not isinstance(raw_input, dict):
        raise ConfigValidationError(
            "Missing required 'input' section in configuration."
        )

    # In Phase 2: project_dir is the primary input
    raw_project_dir = raw_input.get("project_dir") or raw_input.get("path")
    if not raw_project_dir or not isinstance(raw_project_dir, str):
        raise ConfigValidationError(
            "Missing or invalid 'input.project_dir' in configuration."
        )

    project_dir_path = (
        (base_dir / raw_project_dir).resolve()
        if not Path(raw_project_dir).is_absolute()
        else Path(raw_project_dir).resolve()
    )
    verify_immutability = bool(raw_input.get("verify_source_immutability", True))

    raw_excludes = raw_input.get("exclude_patterns")
    if raw_excludes is not None:
        if not isinstance(raw_excludes, list) or not all(
            isinstance(x, str) for x in raw_excludes
        ):
            raise ConfigValidationError(
                "'input.exclude_patterns' must be a list of string glob patterns."
            )
        exclude_patterns = list(raw_excludes)
    else:
        exclude_patterns = list(DEFAULT_EXCLUDE_PATTERNS)

    input_config = InputConfig(
        project_dir=project_dir_path,
        verify_source_immutability=verify_immutability,
        exclude_patterns=exclude_patterns,
    )

    # 3. Output configuration
    raw_output = raw_data.get("output", {})
    if not isinstance(raw_output, dict):
        raise ConfigValidationError("'output' section must be a dictionary.")

    raw_output_dir = raw_output.get("dir", "./dist/protected")
    if not isinstance(raw_output_dir, str) or not raw_output_dir.strip():
        raise ConfigValidationError("Invalid 'output.dir' in configuration.")

    output_dir_path = (
        (base_dir / raw_output_dir).resolve()
        if not Path(raw_output_dir).is_absolute()
        else Path(raw_output_dir).resolve()
    )
    overwrite_existing = bool(raw_output.get("overwrite_existing", False))

    output_config = OutputConfig(
        dir=output_dir_path,
        overwrite_existing=overwrite_existing,
    )

    # 4. Android configuration (for platform == 'android')
    android_config = AndroidConfig()
    if platform == "android":
        raw_android = raw_data.get("android", {})
        if not isinstance(raw_android, dict):
            raise ConfigValidationError(
                "'android' section must be a dictionary when platform is 'android'."
            )

        project_type = raw_android.get("project_type", "gradle")
        if project_type != "gradle":
            raise ConfigValidationError(
                f"Unsupported Android project_type: '{project_type}'. "
                "Only 'gradle' projects are supported in this MVP. "
                "Arbitrary precompiled APK-only input is unsupported."
            )

        build_variant = raw_android.get("build_variant", "release")
        gradle_task = raw_android.get("gradle_task", "assembleRelease")

        raw_r8_rules = raw_android.get("r8_rules_file")
        r8_rules_path = None
        if raw_r8_rules:
            if not isinstance(raw_r8_rules, str):
                raise ConfigValidationError(
                    "'android.r8_rules_file' must be a string path."
                )
            r8_rules_path = (
                (base_dir / raw_r8_rules).resolve()
                if not Path(raw_r8_rules).is_absolute()
                else Path(raw_r8_rules).resolve()
            )

        # Signing sub-configuration
        raw_signing = raw_android.get("signing", {})
        if not isinstance(raw_signing, dict):
            raise ConfigValidationError("'android.signing' must be a dictionary.")

        signing_enabled = bool(raw_signing.get("enabled", False))
        is_production = bool(raw_signing.get("is_production", False))
        keystore_path = None
        if raw_signing.get("keystore_path"):
            ks = raw_signing["keystore_path"]
            keystore_path = (
                (base_dir / ks).resolve()
                if not Path(ks).is_absolute()
                else Path(ks).resolve()
            )

        key_alias = raw_signing.get("key_alias")
        ks_pass_env = raw_signing.get("keystore_password_env")
        key_pass_env = raw_signing.get("key_password_env")

        # Validate that env var names do not look like plain passwords
        for env_field, env_val in [
            ("keystore_password_env", ks_pass_env),
            ("key_password_env", key_pass_env),
        ]:
            if env_val is not None and (
                not isinstance(env_val, str) or not ENV_VAR_REGEX.match(env_val.strip())
            ):
                raise ConfigValidationError(
                    f"Field 'android.signing.{env_field}' must specify the NAME of an environment variable "
                    f"(e.g., 'APPSHIELD_KEY_PASS'), not a plaintext password. Provided: '{env_val}'"
                )

        signing_config = SigningConfig(
            enabled=signing_enabled,
            is_production=is_production,
            keystore_path=keystore_path,
            key_alias=key_alias,
            keystore_password_env=ks_pass_env,
            key_password_env=key_pass_env,
        )

        android_config = AndroidConfig(
            project_type=project_type,
            build_variant=build_variant,
            gradle_task=gradle_task,
            r8_rules_file=r8_rules_path,
            signing=signing_config,
        )

    # 5. Verification configuration
    raw_ver = raw_data.get("verification", {})
    if not isinstance(raw_ver, dict):
        raise ConfigValidationError("'verification' section must be a dictionary.")

    ver_enabled = bool(raw_ver.get("enabled", True))
    fail_on_failure = bool(raw_ver.get("fail_on_check_failure", False))
    raw_checks = raw_ver.get("checks")
    if raw_checks is not None:
        if not isinstance(raw_checks, list) or not all(
            isinstance(c, str) for c in raw_checks
        ):
            raise ConfigValidationError(
                "'verification.checks' must be a list of check name strings."
            )
        checks = list(raw_checks)
    else:
        checks = [
            "symbol_renaming_ratio",
            "string_pool_inspection",
            "signature_integrity",
            "package_alignment",
            "structural_decompilation_info",
        ]

    verification_config = VerificationConfig(
        enabled=ver_enabled,
        fail_on_check_failure=fail_on_failure,
        checks=checks,
    )

    return AppShieldConfig(
        version=version,
        project_name=project_name,
        platform=platform,
        input=input_config,
        output=output_config,
        android=android_config,
        verification=verification_config,
        config_source=source_path,
    )


def load_config(config_path: Path | str) -> AppShieldConfig:
    """Convenience helper to load and parse a configuration file in one call."""
    path = Path(config_path).resolve()
    raw = load_config_file(path)
    return validate_and_parse_config(raw, base_dir=path.parent, source_path=path)


def validate_output_destination(
    output_dir: Path, artifact_name: str, allow_overwrite: bool = False
) -> Path:
    """
    Validate that the destination directory is safe and that the target artifact
    does not already exist unless overwrite is explicitly authorized.
    """
    target_path = (output_dir / artifact_name).resolve()

    if target_path.exists() and not allow_overwrite:
        raise OverwriteError(
            f"Destination file already exists: '{target_path}'. "
            "AppShield will not overwrite existing artifacts without authorization. "
            "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
        )

    return target_path
