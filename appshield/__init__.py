"""
AppShield: A simple, local, cross-platform application code-protection CLI.
"""

from appshield.adapters import (
    AdapterError,
    AndroidPipelineAdapter,
    ConfigurationInspectionError,
    PlatformAdapter,
    PrerequisiteCheck,
    ProjectInspection,
    ProtectionResult,
    RuleStagingError,
    UnsupportedProjectError,
)
from appshield.doctor import (
    ToolReport,
    is_android_gradle_project,
    run_doctor_checks,
)
from appshield.sandbox import (
    SandboxContext,
    SandboxError,
    SandboxManager,
    SecurityError,
    SourceImmutabilityError,
    SourceManifest,
    StagingError,
)

__version__ = "0.1.0"
__author__ = "AppShield Developer"
__license__ = "MIT"

__all__ = [
    "AdapterError",
    "AndroidPipelineAdapter",
    "ConfigurationInspectionError",
    "PlatformAdapter",
    "PrerequisiteCheck",
    "ProjectInspection",
    "ProtectionResult",
    "RuleStagingError",
    "SandboxContext",
    "SandboxError",
    "SandboxManager",
    "SecurityError",
    "SourceImmutabilityError",
    "SourceManifest",
    "StagingError",
    "ToolReport",
    "UnsupportedProjectError",
    "__version__",
    "is_android_gradle_project",
    "run_doctor_checks",
]
