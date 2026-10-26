"""
AppShield: A simple, local, cross-platform application code-protection CLI.
"""

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
    "__version__",
]
