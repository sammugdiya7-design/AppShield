"""
AppShield Platform Adapter Base Interfaces.
Defines the abstract interface contracts for platform-specific build, staging, and protection pipelines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from appshield.config import AppShieldConfig, AppShieldError


class AdapterError(AppShieldError):
    """Base exception for platform adapter errors."""


class UnsupportedProjectError(AdapterError):
    """Raised when an unsupported project structure or non-project input is provided."""


class ConfigurationInspectionError(AdapterError):
    """Raised when project configuration (e.g. minification, rules file) is missing or invalid."""


class RuleStagingError(AdapterError):
    """Raised when ProGuard/R8 protection rule staging fails."""


@dataclass(frozen=True)
class PrerequisiteCheck:
    """Toolchain or prerequisite inspection result."""

    tool_name: str
    is_available: bool
    detected_version: str | None
    target_version: str | None
    required: bool
    remediation_hint: str
    validated_live: bool = False
    path: str | None = None


@dataclass(frozen=True)
class ProjectInspection:
    """Detailed result of inspecting a project's build configuration."""

    is_supported: bool
    platform: str
    project_type: str
    module_name: str | None
    build_file: Path | None
    rules_file: Path | None
    minify_enabled: bool
    shrink_resources: bool
    agp_version: str | None
    compile_sdk: int | None
    target_sdk: int | None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProtectionResult:
    """Result of a protection pipeline execution (for future plans)."""

    success: bool
    protected_artifact_path: Path | None
    logs: list[str] = field(default_factory=list)
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class PlatformAdapter(ABC):
    """Base interface for all platform-specific build and protection adapters."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Return the platform identifier: 'android', 'ios', or 'windows'."""

    @abstractmethod
    def validate_project(self, project_path: Path) -> ProjectInspection:
        """
        Detect supported project structure and inspect release build configuration.
        Rejects arbitrary precompiled binaries and unsupported layouts.
        """

    @abstractmethod
    def check_prerequisites(
        self, project_path: Path | None = None
    ) -> list[PrerequisiteCheck]:
        """
        Inspect host environment and project for required CLI binaries, SDKs, and build tools.
        """

    @abstractmethod
    def stage_rules(
        self,
        staging_dir: Path,
        custom_rules: str | None = None,
        custom_rules_file: Path | None = None,
    ) -> Path:
        """
        Inject protection rules into the isolated staging copy without modifying original files.
        """

    @abstractmethod
    def stage_and_protect(
        self,
        config: AppShieldConfig,
    ) -> ProtectionResult:
        """
        Full protection pipeline (to be implemented in Plan 04-02).
        Must raise NotImplementedError in Plan 04-01.
        """
