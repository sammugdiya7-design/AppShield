"""
Unit tests for AppShield configuration loading, schema validation, and overwrite protection.
"""

import json
from pathlib import Path

import pytest
import yaml

from appshield.config import (
    DEFAULT_EXCLUDE_PATTERNS,
    AppShieldConfig,
    ConfigError,
    ConfigNotFoundError,
    ConfigValidationError,
    InputConfig,
    OutputConfig,
    OverwriteError,
    load_config,
    validate_and_parse_config,
    validate_output_destination,
)


@pytest.fixture
def sample_gradle_dir(tmp_path: Path) -> Path:
    """Create a temporary valid Android Gradle project structure."""
    proj = tmp_path / "sample_android_app"
    proj.mkdir()
    (proj / "gradlew").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (proj / "build.gradle").write_text("// build", encoding="utf-8")
    (proj / "settings.gradle").write_text("// settings", encoding="utf-8")
    return proj


def test_load_valid_yaml_config(tmp_path: Path, sample_gradle_dir: Path):
    """Test loading and validating a complete, valid YAML configuration."""
    config_file = tmp_path / "appshield.yaml"
    data = {
        "version": "1.0",
        "project_name": "sample_app",
        "platform": "android",
        "input": {
            "project_dir": str(sample_gradle_dir),
            "verify_source_immutability": True,
            "exclude_patterns": [".git/**", "build/**"],
        },
        "output": {
            "dir": str(tmp_path / "dist" / "protected"),
            "overwrite_existing": False,
        },
        "android": {
            "project_type": "gradle",
            "build_variant": "release",
            "gradle_task": "assembleRelease",
            "r8_rules_file": "custom-rules.pro",
            "signing": {
                "enabled": True,
                "is_production": False,
                "keystore_path": "test.jks",
                "key_alias": "test_alias",
                "keystore_password_env": "TEST_KS_PASS",
                "key_password_env": "TEST_KEY_PASS",
            },
        },
        "verification": {
            "enabled": True,
            "fail_on_check_failure": False,
            "checks": ["symbol_renaming_ratio", "signature_integrity"],
        },
    }
    config_file.write_text(yaml.safe_dump(data), encoding="utf-8")

    cfg = load_config(config_file)
    assert isinstance(cfg, AppShieldConfig)
    assert cfg.version == "1.0"
    assert cfg.project_name == "sample_app"
    assert cfg.platform == "android"
    assert cfg.input.project_dir == sample_gradle_dir.resolve()
    assert cfg.input.verify_source_immutability is True
    assert cfg.input.exclude_patterns == [".git/**", "build/**"]
    assert cfg.output.overwrite_existing is False
    assert cfg.android.project_type == "gradle"
    assert cfg.android.signing.enabled is True
    assert cfg.android.signing.is_production is False
    assert cfg.android.signing.keystore_password_env == "TEST_KS_PASS"
    assert cfg.verification.checks == ["symbol_renaming_ratio", "signature_integrity"]


def test_load_valid_json_config(tmp_path: Path, sample_gradle_dir: Path):
    """Test loading and validating a valid JSON configuration."""
    config_file = tmp_path / "appshield.json"
    data = {
        "version": "1.0",
        "project_name": "json_app",
        "platform": "android",
        "input": {
            "project_dir": str(sample_gradle_dir),
        },
        "output": {
            "dir": "./dist/out",
        },
    }
    config_file.write_text(json.dumps(data), encoding="utf-8")

    cfg = load_config(config_file)
    assert cfg.project_name == "json_app"
    assert cfg.platform == "android"
    assert cfg.input.verify_source_immutability is True
    assert cfg.input.exclude_patterns == DEFAULT_EXCLUDE_PATTERNS
    assert cfg.output.overwrite_existing is False
    assert cfg.android.project_type == "gradle"


def test_config_not_found():
    """Test error handling when the configuration file does not exist."""
    with pytest.raises(ConfigNotFoundError) as exc:
        load_config(Path("nonexistent_appshield.yaml"))
    assert "Configuration file not found" in str(exc.value)


def test_malformed_yaml(tmp_path: Path):
    """Test error handling when YAML content is malformed."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("version: 1.0\n  bad_indentation: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(bad_yaml)
    assert "Malformed YAML" in str(exc.value)


def test_malformed_json(tmp_path: Path):
    """Test error handling when JSON content is malformed."""
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{ unquoted_key: 123, }", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(bad_json)
    assert "Malformed JSON" in str(exc.value)


def test_invalid_version():
    """Test rejection of unsupported schema version."""
    data = {
        "version": "2.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": "."},
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Invalid or unsupported configuration version" in str(exc.value)


def test_invalid_project_name():
    """Test rejection of invalid project names."""
    data = {
        "version": "1.0",
        "project_name": "invalid name with spaces!",
        "platform": "android",
        "input": {"project_dir": "."},
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Invalid 'project_name'" in str(exc.value)


def test_invalid_platform():
    """Test rejection of unsupported platform identifier."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "solaris",
        "input": {"project_dir": "."},
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Unsupported platform: 'solaris'" in str(exc.value)


def test_unsupported_apk_project_type():
    """
    Test that arbitrary precompiled APK project_type is explicitly rejected
    per the Phase 2 specification.
    """
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": "."},
        "output": {"dir": "dist"},
        "android": {
            "project_type": "apk",
        },
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Unsupported Android project_type: 'apk'" in str(exc.value)
    assert "Arbitrary precompiled APK-only input is unsupported" in str(exc.value)


def test_plain_password_in_env_field_rejected():
    """
    Test that sensitive fields require valid environment variable names
    and reject raw password values.
    """
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": "."},
        "output": {"dir": "dist"},
        "android": {
            "project_type": "gradle",
            "signing": {
                "enabled": True,
                "keystore_password_env": "MyP@ssw0rd123!",  # Invalid env var name
            },
        },
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "must specify the NAME of an environment variable" in str(exc.value)


def test_validate_output_destination_overwrite_prevention(tmp_path: Path):
    """Test that overwrite guard prevents overwriting existing artifacts without authorization."""
    out_dir = tmp_path / "protected"
    out_dir.mkdir()
    target_file = out_dir / "my_app-release-protected.apk"
    target_file.write_text("existing artifact bytes", encoding="utf-8")

    # When overwrite is False (default), OverwriteError must be raised
    with pytest.raises(OverwriteError) as exc:
        validate_output_destination(
            out_dir, "my_app-release-protected.apk", allow_overwrite=False
        )
    assert "Destination file already exists" in str(exc.value)
    assert "AppShield will not overwrite existing artifacts" in str(exc.value)


def test_validate_output_destination_overwrite_allowed(tmp_path: Path):
    """Test that overwrite guard permits target path when explicitly authorized."""
    out_dir = tmp_path / "protected"
    out_dir.mkdir()
    target_file = out_dir / "my_app-release-protected.apk"
    target_file.write_text("existing artifact bytes", encoding="utf-8")

    # When allow_overwrite is True, return target path safely
    path = validate_output_destination(
        out_dir, "my_app-release-protected.apk", allow_overwrite=True
    )
    assert path == target_file.resolve()


def test_config_to_dict_safe(sample_gradle_dir: Path):
    """Test that to_dict() returns a clean, safe representation."""
    cfg = AppShieldConfig(
        version="1.0",
        project_name="safe_app",
        platform="android",
        input=InputConfig(project_dir=sample_gradle_dir),
        output=OutputConfig(),
    )
    d = cfg.to_dict()
    assert d["project_name"] == "safe_app"
    assert d["platform"] == "android"
    assert d["input"]["verify_source_immutability"] is True
    assert d["output"]["overwrite_existing"] is False
    assert d["android"]["signing"]["keystore_password_env"] is None
    assert d["android"]["signing"]["key_password_env"] is None
    # Ensure no raw password fields exist in the serialized dictionary
    raw_json = json.dumps(d)
    assert '"password"' not in raw_json
    assert '"keystore_password"' not in raw_json
    assert '"key_password"' not in raw_json
