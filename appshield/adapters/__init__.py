"""
AppShield Platform Adapters Package.
Provides pluggable build, staging, and protection pipeline adapters for supported platforms.
"""

from __future__ import annotations

from appshield.adapters.android import (
    APPSHIELD_STANDARD_R8_RULES,
    FORBIDDEN_TEST_KEEP_PATTERNS,
    AndroidPipelineAdapter,
    extract_block,
    extract_release_block,
)
from appshield.adapters.base import (
    AdapterError,
    ConfigurationInspectionError,
    PlatformAdapter,
    PrerequisiteCheck,
    ProjectInspection,
    ProtectionResult,
    RuleStagingError,
    UnsupportedProjectError,
)

__all__ = [
    "APPSHIELD_STANDARD_R8_RULES",
    "FORBIDDEN_TEST_KEEP_PATTERNS",
    "AdapterError",
    "AndroidPipelineAdapter",
    "ConfigurationInspectionError",
    "PlatformAdapter",
    "PrerequisiteCheck",
    "ProjectInspection",
    "ProtectionResult",
    "RuleStagingError",
    "UnsupportedProjectError",
    "extract_block",
    "extract_release_block",
]
