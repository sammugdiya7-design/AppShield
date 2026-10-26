"""
Unit tests for AppShield configuration loading, schema validation, and overwrite protection.
"""

import json
from pathlib import Path
from unittest.mock import patch

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


def test_load_config_file_read_error(tmp_path: Path):
    """Test that file read errors raise ConfigError."""
    cfg = tmp_path / "unreadable.json"
    cfg.write_text("{}", encoding="utf-8")
    with (
        patch("pathlib.Path.read_text", side_effect=OSError("Read permission denied")),
        pytest.raises(ConfigError) as exc,
    ):
        load_config(cfg)
    assert "Failed to read configuration file" in str(exc.value)


def test_load_config_file_no_extension(tmp_path: Path, sample_gradle_dir: Path):
    """Test loading configuration from a file without standard extension."""
    cfg = tmp_path / "appshield_custom"
    data = {
        "version": "1.0",
        "project_name": "custom_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
    }
    cfg.write_text(json.dumps(data), encoding="utf-8")
    loaded = load_config(cfg)
    assert loaded.project_name == "custom_app"


def test_load_config_file_no_extension_yaml(tmp_path: Path, sample_gradle_dir: Path):
    """Test loading YAML configuration from a file without standard extension."""
    cfg = tmp_path / "appshield_custom_yaml"
    data = {
        "version": "1.0",
        "project_name": "custom_yaml_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
    }
    cfg.write_text(yaml.safe_dump(data), encoding="utf-8")
    loaded = load_config(cfg)
    assert loaded.project_name == "custom_yaml_app"


def test_load_config_file_no_extension_malformed(tmp_path: Path):
    """Test loading malformed YAML from a file without standard extension."""
    cfg = tmp_path / "appshield_custom_bad"
    cfg.write_text("{ unclosed: [", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(cfg)
    assert "Unsupported or malformed configuration" in str(exc.value)


def test_config_not_a_dict(tmp_path: Path):
    """Test that a non-dict root object raises ConfigValidationError."""
    cfg = tmp_path / "list_root.json"
    cfg.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ConfigValidationError) as exc:
        load_config(cfg)
    assert "must define a top-level dictionary/object" in str(exc.value)


def test_input_not_a_dict():
    """Test that a non-dict 'input' section raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": "not a dict",
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Missing required 'input' section" in str(exc.value)


def test_input_missing_project_dir():
    """Test that missing 'project_dir' in input section raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {},
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Missing or invalid 'input.project_dir'" in str(exc.value)


def test_input_invalid_exclude_patterns(sample_gradle_dir: Path):
    """Test that non-string items in exclude_patterns raise ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {
            "project_dir": str(sample_gradle_dir),
            "exclude_patterns": [123, True],
        },
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'input.exclude_patterns' must be a list of string glob patterns" in str(
        exc.value
    )


def test_output_not_a_dict(sample_gradle_dir: Path):
    """Test that non-dict 'output' section raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": "dist",
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'output' section must be a dictionary" in str(exc.value)


def test_output_dir_invalid(sample_gradle_dir: Path):
    """Test that whitespace/empty 'output.dir' raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "   "},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "Invalid 'output.dir'" in str(exc.value)


def test_android_not_a_dict(sample_gradle_dir: Path):
    """Test that non-dict 'android' section raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
        "android": "invalid",
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'android' section must be a dictionary" in str(exc.value)


def test_android_r8_rules_not_string(sample_gradle_dir: Path):
    """Test that non-string 'android.r8_rules_file' raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
        "android": {"r8_rules_file": 12345},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'android.r8_rules_file' must be a string path" in str(exc.value)


def test_android_signing_not_a_dict(sample_gradle_dir: Path):
    """Test that non-dict 'android.signing' raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
        "android": {"signing": "enabled"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'android.signing' must be a dictionary" in str(exc.value)


def test_verification_not_a_dict(sample_gradle_dir: Path):
    """Test that non-dict 'verification' section raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
        "verification": "all",
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'verification' section must be a dictionary" in str(exc.value)


def test_verification_checks_not_list_of_strings(sample_gradle_dir: Path):
    """Test that non-string items in 'verification.checks' raise ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {"project_dir": str(sample_gradle_dir)},
        "output": {"dir": "dist"},
        "verification": {"checks": [1, 2]},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'verification.checks' must be a list of check name strings" in str(
        exc.value
    )


def test_input_immutability_exclude_patterns_valid(sample_gradle_dir: Path):
    """Test valid custom immutability_exclude_patterns in input."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {
            "project_dir": str(sample_gradle_dir),
            "immutability_exclude_patterns": [".git/**", "custom_scratch/**"],
        },
        "output": {"dir": "dist"},
    }
    cfg = validate_and_parse_config(data)
    assert cfg.input.immutability_exclude_patterns == [".git/**", "custom_scratch/**"]
    exported = cfg.to_dict()
    assert exported["input"]["immutability_exclude_patterns"] == [".git/**", "custom_scratch/**"]


def test_input_immutability_exclude_patterns_invalid(sample_gradle_dir: Path):
    """Test that invalid immutability_exclude_patterns raises ConfigValidationError."""
    data = {
        "version": "1.0",
        "project_name": "test_app",
        "platform": "android",
        "input": {
            "project_dir": str(sample_gradle_dir),
            "immutability_exclude_patterns": "not_a_list",
        },
        "output": {"dir": "dist"},
    }
    with pytest.raises(ConfigValidationError) as exc:
        validate_and_parse_config(data)
    assert "'input.immutability_exclude_patterns' must be a list of string glob patterns" in str(
        exc.value
    )
