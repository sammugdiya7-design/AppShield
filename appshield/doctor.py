"""
AppShield Doctor: Environment and prerequisite tool detection.
Inspects local tools (Java, Gradle, Android SDK, build-tools, wrapper) without modifying the system.
Clearly distinguishes missing dependencies, detected versions, selected target versions,
and live build validation status.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ToolReport:
    """Toolchain or prerequisite inspection result."""

    name: str
    is_available: bool
    version: str | None
    required: bool
    remediation_hint: str
    path: str | None = None
    target_version: str | None = None
    validated_live: bool = False


def check_command_version(cmd: list[str]) -> str | None:
    """Safely run a command to query its version, returning the first non-empty line."""
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


def parse_java_version(version_output: str) -> tuple[int | None, str]:
    """
    Parse the Java major version and full version string from 'java -version' output.
    Examples:
      - 'java version "1.8.0_401"' -> (8, "1.8.0_401")
      - 'openjdk version "17.0.9" 2023-10-17' -> (17, "17.0.9")
      - 'java version "21.0.1"' -> (21, "21.0.1")
    """
    # Check for legacy 1.x versioning (e.g. 1.8 -> Java 8)
    m_legacy = re.search(r'version\s+"1\.(\d+)[^"]*"', version_output)
    if m_legacy:
        major = int(m_legacy.group(1))
        m_full = re.search(r'version\s+"([^"]+)"', version_output)
        full_ver = m_full.group(1) if m_full else f"1.{major}"
        return major, full_ver

    # Modern versioning (e.g. "17.0.9", "21")
    m_modern = re.search(r'version\s+"(\d+)(?:\.([^"]+))?"', version_output)
    if m_modern:
        major = int(m_modern.group(1))
        m_full = re.search(r'version\s+"([^"]+)"', version_output)
        full_ver = m_full.group(1) if m_full else str(major)
        return major, full_ver

    return None, version_output.strip()


def run_doctor_checks(project_dir: Path | None = None) -> list[ToolReport]:
    """
    Inspect host system, Android SDK, and project environment for build prerequisites.
    Clearly reports detected versions against selected target versions.
    """
    reports: list[ToolReport] = []

    # 1. Java runtime (java)
    java_path = shutil.which("java")
    if java_path:
        raw_ver = check_command_version(["java", "-version"]) or ""
        major, ver_str = parse_java_version(raw_ver)
        if major is not None and major < 17:
            reports.append(
                ToolReport(
                    name="Java Runtime (java)",
                    is_available=False,
                    version=f"Detected Java {major} ({ver_str}) - Incompatible",
                    target_version="OpenJDK 17 (17.0.x)",
                    required=True,
                    remediation_hint=f"Detected Java {major}. Android Gradle Plugin 8.2 requires OpenJDK 17 or higher. "
                    "Install OpenJDK 17 and configure PATH.",
                    path=java_path,
                    validated_live=False,
                )
            )
        else:
            reports.append(
                ToolReport(
                    name="Java Runtime (java)",
                    is_available=True,
                    version=f"Java {major} ({ver_str})"
                    if major
                    else (ver_str or "Installed"),
                    target_version="OpenJDK 17 (17.0.x)",
                    required=True,
                    remediation_hint="",
                    path=java_path,
                    validated_live=False,
                )
            )
    else:
        reports.append(
            ToolReport(
                name="Java Runtime (java)",
                is_available=False,
                version=None,
                target_version="OpenJDK 17 (17.0.x)",
                required=True,
                remediation_hint="Install OpenJDK 17 or higher and ensure 'java' is on PATH. (e.g. from adoptium.net)",
                validated_live=False,
            )
        )

    # 2. Java compiler (javac)
    javac_path = shutil.which("javac")
    if javac_path:
        raw_ver = check_command_version(["javac", "-version"]) or ""
        reports.append(
            ToolReport(
                name="Java Compiler (javac)",
                is_available=True,
                version=raw_ver or "Installed",
                target_version="JDK 17 javac",
                required=False,
                remediation_hint="",
                path=javac_path,
                validated_live=False,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Java Compiler (javac)",
                is_available=False,
                version=None,
                target_version="JDK 17 javac",
                required=False,
                remediation_hint="Ensure full OpenJDK 17 (not just JRE) is installed and 'JAVA_HOME/bin' is on PATH.",
                validated_live=False,
            )
        )

    # 3. JAVA_HOME environment variable
    java_home = os.environ.get("JAVA_HOME")
    if java_home and Path(java_home).is_dir():
        java_exe = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if java_exe.is_file():
            reports.append(
                ToolReport(
                    name="JAVA_HOME Variable",
                    is_available=True,
                    version=java_home,
                    target_version="Points to OpenJDK 17 directory",
                    required=True,
                    remediation_hint="",
                    path=java_home,
                    validated_live=False,
                )
            )
        else:
            reports.append(
                ToolReport(
                    name="JAVA_HOME Variable",
                    is_available=False,
                    version=f"{java_home} (missing bin/java)",
                    target_version="Points to OpenJDK 17 directory",
                    required=True,
                    remediation_hint=f"JAVA_HOME is set to '{java_home}' but does not contain a valid 'bin/java' executable.",
                    path=java_home,
                    validated_live=False,
                )
            )
    else:
        reports.append(
            ToolReport(
                name="JAVA_HOME Variable",
                is_available=False,
                version=None,
                target_version="Points to OpenJDK 17 directory",
                required=True,
                remediation_hint="Set JAVA_HOME environment variable pointing to your OpenJDK 17 installation directory.",
                validated_live=False,
            )
        )

    # 4. Android SDK (ANDROID_HOME or ANDROID_SDK_ROOT)
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    android_sdk_dir: Path | None = None
    if android_home and Path(android_home).is_dir():
        android_sdk_dir = Path(android_home)
        reports.append(
            ToolReport(
                name="Android SDK (ANDROID_HOME)",
                is_available=True,
                version=android_home,
                target_version="Android SDK Directory",
                required=False,
                remediation_hint="",
                path=android_home,
                validated_live=False,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Android SDK (ANDROID_HOME)",
                is_available=False,
                version=None,
                target_version="Android SDK Directory",
                required=False,
                remediation_hint="Set ANDROID_HOME environment variable pointing to your Android SDK installation directory.",
                validated_live=False,
            )
        )

    # 5. Android SDK Platform 34
    platform_34_installed = False
    platform_34_path: Path | None = None
    if android_sdk_dir is not None:
        p34 = android_sdk_dir / "platforms" / "android-34"
        if p34.is_dir():
            platform_34_installed = True
            platform_34_path = p34

    reports.append(
        ToolReport(
            name="Android SDK Platform 34",
            is_available=platform_34_installed,
            version="Installed (android-34)" if platform_34_installed else None,
            target_version="platforms;android-34 (API Level 34)",
            required=False,
            remediation_hint="Install Android SDK Platform 34 via SDK Manager: sdkmanager 'platforms;android-34'"
            if not platform_34_installed
            else "",
            path=str(platform_34_path) if platform_34_path else None,
            validated_live=False,
        )
    )

    # 6. Android SDK Build-Tools 34.0.0
    bt_34_installed = False
    bt_34_path: Path | None = None
    if android_sdk_dir is not None:
        bt = android_sdk_dir / "build-tools" / "34.0.0"
        if bt.is_dir():
            bt_34_installed = True
            bt_34_path = bt

    reports.append(
        ToolReport(
            name="Android SDK Build-Tools 34.0.0",
            is_available=bt_34_installed,
            version="Installed (34.0.0)" if bt_34_installed else None,
            target_version="build-tools;34.0.0",
            required=False,
            remediation_hint="Install Android SDK Build-Tools 34.0.0 via SDK Manager: sdkmanager 'build-tools;34.0.0'"
            if not bt_34_installed
            else "",
            path=str(bt_34_path) if bt_34_path else None,
            validated_live=False,
        )
    )

    # 7. Gradle Build Tool / Gradle Wrapper
    gradle_system = shutil.which("gradle")
    gradlew_path: Path | None = None
    if project_dir and (project_dir / "gradlew").is_file():
        gradlew_path = project_dir / "gradlew"
    elif project_dir and (project_dir / "gradlew.bat").is_file():
        gradlew_path = project_dir / "gradlew.bat"

    if gradlew_path is not None:
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=True,
                version="gradlew (project wrapper detected)",
                target_version="Gradle 8.2+",
                required=True,
                remediation_hint="",
                path=str(gradlew_path),
                validated_live=False,
            )
        )
    elif gradle_system:
        ver = check_command_version(["gradle", "--version"])
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=True,
                version=ver or "System Gradle",
                target_version="Gradle 8.2+",
                required=True,
                remediation_hint="",
                path=gradle_system,
                validated_live=False,
            )
        )
    else:
        reports.append(
            ToolReport(
                name="Gradle Build Tool",
                is_available=False,
                version=None,
                target_version="Gradle 8.2+",
                required=True,
                remediation_hint="Ensure project contains 'gradlew' wrapper or install Gradle system-wide.",
                validated_live=False,
            )
        )

    # 8. zipalign
    zipalign_path: str | None = None
    if bt_34_path:
        cand_zip = bt_34_path / ("zipalign.exe" if os.name == "nt" else "zipalign")
        if cand_zip.is_file():
            zipalign_path = str(cand_zip)
    if zipalign_path is None:
        zipalign_path = shutil.which("zipalign")

    reports.append(
        ToolReport(
            name="zipalign",
            is_available=bool(zipalign_path),
            version=check_command_version(["zipalign", "-h"])
            if zipalign_path
            else None,
            target_version="Build-Tools 34.0.0 zipalign",
            required=False,
            remediation_hint="Required for aligning APK packages. Found in $ANDROID_HOME/build-tools/34.0.0/zipalign",
            path=zipalign_path,
            validated_live=False,
        )
    )

    # 9. apksigner
    apksigner_path: str | None = None
    if bt_34_path:
        cand_apk = bt_34_path / ("apksigner.bat" if os.name == "nt" else "apksigner")
        if cand_apk.is_file():
            apksigner_path = str(cand_apk)
    if apksigner_path is None:
        apksigner_path = shutil.which("apksigner")

    reports.append(
        ToolReport(
            name="apksigner",
            is_available=bool(apksigner_path),
            version=check_command_version(["apksigner", "--version"])
            if apksigner_path
            else None,
            target_version="Build-Tools 34.0.0 apksigner",
            required=False,
            remediation_hint="Required for signing and signature verification. Found in $ANDROID_HOME/build-tools/34.0.0/apksigner",
            path=apksigner_path,
            validated_live=False,
        )
    )

    # 10. Project-specific diagnostics (when project_dir is provided)
    if project_dir is not None:
        proj = project_dir.resolve()

        # 10a. Android Gradle Project Structure (maintains compatibility with Phase 3 tests)
        is_supported, reasons = is_android_gradle_project(proj)
        reports.append(
            ToolReport(
                name="Android Gradle Project Structure",
                is_available=is_supported,
                version="Supported Android Gradle Project" if is_supported else None,
                target_version="Standard Android Gradle layout",
                required=True,
                remediation_hint="; ".join(reasons) if not is_supported else "",
                path=str(proj),
                validated_live=False,
            )
        )

        # 10b. Gradle Wrapper Properties & Distribution URL
        wrapper_props_file = proj / "gradle" / "wrapper" / "gradle-wrapper.properties"
        dist_url: str | None = None
        has_sha256 = False
        if wrapper_props_file.is_file():
            content = wrapper_props_file.read_text(encoding="utf-8", errors="replace")
            m_url = re.search(r"distributionUrl\s*=\s*(.+)", content)
            if m_url:
                dist_url = m_url.group(1).strip()
            if "distributionSha256Sum" in content:
                has_sha256 = True

        reports.append(
            ToolReport(
                name="Gradle Distribution Configuration",
                is_available=dist_url is not None,
                version=f"Configured: {dist_url}"
                + (" (checksum pinned)" if has_sha256 else " (no checksum pin)")
                if dist_url
                else None,
                target_version="Gradle 8.2 (gradle-8.2-bin.zip)",
                required=True,
                remediation_hint="Missing or malformed 'gradle/wrapper/gradle-wrapper.properties' with distributionUrl."
                if dist_url is None
                else "",
                path=str(wrapper_props_file) if wrapper_props_file.is_file() else None,
                validated_live=False,
            )
        )

        # 10c. Gradle Wrapper JAR (gradle-wrapper.jar)
        wrapper_jar_file = proj / "gradle" / "wrapper" / "gradle-wrapper.jar"
        wrapper_jar_exists = wrapper_jar_file.is_file()
        reports.append(
            ToolReport(
                name="Gradle Wrapper JAR (gradle-wrapper.jar)",
                is_available=wrapper_jar_exists,
                version="Present in gradle/wrapper/"
                if wrapper_jar_exists
                else "Missing from gradle/wrapper/",
                target_version="gradle-wrapper.jar (Gradle 8.2 bootstrap)",
                required=False,
                remediation_hint="The Gradle Wrapper JAR is omitted from git tracking. "
                "Live execution will require adding a trusted wrapper JAR or having Gradle installed system-wide. "
                "Do not download silently.",
                path=str(wrapper_jar_file) if wrapper_jar_exists else None,
                validated_live=False,
            )
        )

        # 10d. Declared Android Gradle Plugin (AGP) Version
        agp_detected: str | None = None
        for b_cand in [
            proj / "build.gradle",
            proj / "build.gradle.kts",
            proj / "app" / "build.gradle",
            proj / "app" / "build.gradle.kts",
        ]:
            if b_cand.is_file():
                txt = b_cand.read_text(encoding="utf-8", errors="replace")
                m_agp = re.search(
                    r"['\"]com\.android\.application['\"]\s+version\s+['\"]([^'\"]+)['\"]",
                    txt,
                )
                if m_agp:
                    agp_detected = m_agp.group(1)
                    break
                m_agp_alt = re.search(
                    r"id\s*\(?['\"]com\.android\.application['\"]\)?\s+version\s+['\"]([^'\"]+)['\"]",
                    txt,
                )
                if m_agp_alt:
                    agp_detected = m_agp_alt.group(1)
                    break
                m_cp = re.search(r"com\.android\.tools\.build:gradle:([0-9.]+)", txt)
                if m_cp:
                    agp_detected = m_cp.group(1)
                    break

        reports.append(
            ToolReport(
                name="Android Gradle Plugin (AGP)",
                is_available=agp_detected is not None,
                version=f"AGP {agp_detected} (declared in build scripts)"
                if agp_detected
                else None,
                target_version="AGP 8.2.2",
                required=True,
                remediation_hint="Could not detect 'com.android.application' version in project build scripts."
                if agp_detected is None
                else "",
                path=str(proj / "build.gradle")
                if (proj / "build.gradle").is_file()
                else None,
                validated_live=False,
            )
        )

        # 10e. Android Release Minification & R8 Rules Configuration
        from appshield.adapters.android import AndroidPipelineAdapter

        adapter = AndroidPipelineAdapter()
        inspection = adapter.validate_project(proj)
        reports.append(
            ToolReport(
                name="Android Release R8 Configuration",
                is_available=inspection.is_supported,
                version=f"minifyEnabled=true; rules='{inspection.rules_file.name}'"
                if inspection.is_supported and inspection.rules_file
                else None,
                target_version="minifyEnabled=true with ProGuard/R8 rules",
                required=True,
                remediation_hint="; ".join(inspection.errors)
                if not inspection.is_supported
                else "",
                path=str(inspection.build_file) if inspection.build_file else None,
                validated_live=False,
            )
        )

    return reports


def is_android_gradle_project(project_dir: Path) -> tuple[bool, list[str]]:
    """
    Inspect a directory to determine if it is a supported Android Gradle project.
    Checks for:
      - Directory existence
      - Gradle wrapper script ('gradlew' or 'gradlew.bat')
      - Settings file ('settings.gradle' or 'settings.gradle.kts')
      - Application build file ('app/build.gradle' or 'build.gradle')
    Returns (is_supported, missing_reasons).
    """
    resolved = project_dir.resolve()
    reasons: list[str] = []

    if not resolved.exists():
        return False, [f"Project directory does not exist: '{resolved}'"]
    if not resolved.is_dir():
        return False, [f"Project path is not a directory: '{resolved}'"]

    has_gradlew = (resolved / "gradlew").is_file() or (
        resolved / "gradlew.bat"
    ).is_file()
    if not has_gradlew:
        reasons.append(
            "Missing Gradle wrapper script ('gradlew' or 'gradlew.bat') in project root"
        )

    has_settings = (resolved / "settings.gradle").is_file() or (
        resolved / "settings.gradle.kts"
    ).is_file()
    if not has_settings:
        reasons.append(
            "Missing Gradle settings file ('settings.gradle' or 'settings.gradle.kts')"
        )

    has_app_build = (
        (resolved / "app" / "build.gradle").is_file()
        or (resolved / "app" / "build.gradle.kts").is_file()
        or (resolved / "build.gradle").is_file()
        or (resolved / "build.gradle.kts").is_file()
    )
    if not has_app_build:
        reasons.append(
            "Missing Android application build file ('app/build.gradle' or 'build.gradle')"
        )

    return len(reasons) == 0, reasons
