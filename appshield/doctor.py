"""
AppShield Doctor: Environment and prerequisite tool detection.
Inspects local tools (Java, Gradle, Android build-tools) without modifying the system.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolReport:
    name: str
    is_available: bool
    version: str | None
    required: bool
    remediation_hint: str
    path: str | None = None


def check_command_version(cmd: list[str]) -> str | None:
    """Safely run a command to query its version, returning first non-empty line."""
    try:
        proc = subprocess.run(  # nosec B603
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        combined = (proc.stdout + "\n" + proc.stderr).strip()
        lines = [line.strip() for line in combined.splitlines() if line.strip()]
        return lines[0] if lines else "Installed"
    except (subprocess.SubprocessError, OSError, UnicodeDecodeError):
        return None


def run_doctor_checks(project_dir: Path | None = None) -> list[ToolReport]:
    """Inspect host system and environment for Android Gradle build requirements."""
    reports: list[ToolReport] = []

    # 1. Java runtime
    java_path = shutil.which("java")
    if java_path:
        ver = check_command_version(["java", "-version"])
        reports.append(
            ToolReport(
                name="Java Runtime (java)",
                is_available=True,
                version=ver,
                required=True,
                remediation_hint="",
                path=java_path,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Java Runtime (java)",
                is_available=False,
                version=None,
                required=True,
                remediation_hint="Install OpenJDK 17 or higher and ensure 'java' is on PATH. (e.g. from adoptium.net or package manager)",
            )
        )

    # 2. Java compiler (javac)
    javac_path = shutil.which("javac")
    if javac_path:
        ver = check_command_version(["javac", "-version"])
        reports.append(
            ToolReport(
                name="Java Compiler (javac)",
                is_available=True,
                version=ver,
                required=False,
                remediation_hint="",
                path=javac_path,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Java Compiler (javac)",
                is_available=False,
                version=None,
                required=False,
                remediation_hint="Ensure full JDK (not just JRE) is installed and 'JAVA_HOME/bin' is on PATH.",
            )
        )

    # 3. JAVA_HOME environment variable
    java_home = os.environ.get("JAVA_HOME")
    if java_home and Path(java_home).is_dir():
        reports.append(
            ToolReport(
                name="JAVA_HOME Variable",
                is_available=True,
                version=java_home,
                required=True,
                remediation_hint="",
                path=java_home,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="JAVA_HOME Variable",
                is_available=False,
                version=None,
                required=True,
                remediation_hint="Set JAVA_HOME environment variable pointing to your JDK 17+ installation directory.",
            )
        )

    # 4. Android SDK (ANDROID_HOME or ANDROID_SDK_ROOT)
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home and Path(android_home).is_dir():
        reports.append(
            ToolReport(
                name="Android SDK (ANDROID_HOME)",
                is_available=True,
                version=android_home,
                required=False,
                remediation_hint="",
                path=android_home,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Android SDK (ANDROID_HOME)",
                is_available=False,
                version=None,
                required=False,
                remediation_hint="Set ANDROID_HOME environment variable pointing to your Android SDK installation.",
            )
        )

    # 5. Gradle / Gradle Wrapper
    gradle_system = shutil.which("gradle")
    gradlew_path: Path | None = None
    if project_dir and (project_dir / "gradlew").is_file():
        gradlew_path = project_dir / "gradlew"

    if gradlew_path is not None:
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=True,
                version="gradlew (project wrapper detected)",
                required=True,
                remediation_hint="",
                path=str(gradlew_path),
            )
        )
    elif gradle_system:
        ver = check_command_version(["gradle", "--version"])
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=True,
                version=ver or "System Gradle",
                required=True,
                remediation_hint="",
                path=gradle_system,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=False,
                version=None,
                required=True,
                remediation_hint="Ensure project contains 'gradlew' wrapper or install Gradle system-wide.",
            )
        )

    # 6. Android Build Tools: zipalign & apksigner
    zipalign_path = shutil.which("zipalign")
    reports.append(
        ToolReport(
            name="zipalign",
            is_available=bool(zipalign_path),
            version=check_command_version(["zipalign", "-h"])
            if zipalign_path
            else None,
            required=False,
            remediation_hint="Required for aligning APK packages. Found in $ANDROID_HOME/build-tools/<version>/zipalign",
            path=zipalign_path,
        )
    )

    apksigner_path = shutil.which("apksigner")
    reports.append(
        ToolReport(
            name="apksigner",
            is_available=bool(apksigner_path),
            version=check_command_version(["apksigner", "--version"])
            if apksigner_path
            else None,
            required=False,
            remediation_hint="Required for signing and signature verification. Found in $ANDROID_HOME/build-tools/<version>/apksigner",
            path=apksigner_path,
        )
    )

    return reports
