"""
AppShield: A simple, local, cross-platform application code-protection CLI.
"""

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
    "SandboxContext",
    "SandboxError",
    "SandboxManager",
    "SecurityError",
    "SourceImmutabilityError",
    "SourceManifest",
    "StagingError",
    "ToolReport",
    "__version__",
    "is_android_gradle_project",
    "run_doctor_checks",
]
