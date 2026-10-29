"""
AppShield Gradle Build Runner and Artifact Extractor.
Provides safe, controlled execution of Gradle tasks inside isolated staging workspaces,
process tree management, diagnostic capturing with secret redaction, safe environment
filtering, and release APK discovery/validation.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

# Safe environment variables preserved across platforms
PRESERVED_ENV_VARS_COMMON = {
    "PATH",
    "JAVA_HOME",
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "GRADLE_USER_HOME",
    "GRADLE_OPTS",
    "JAVA_OPTS",
    "JAVA_TOOL_OPTIONS",
}

PRESERVED_ENV_VARS_WINDOWS = {
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "ALLUSERSPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "SYSTEMDRIVE",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "COMMONPROGRAMFILES",
}

PRESERVED_ENV_VARS_POSIX = {
    "HOME",
    "USER",
    "SHELL",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TERM",
}

# Regex to detect potentially sensitive variable names
SENSITIVE_VAR_PATTERN = re.compile(
    r"(KEY|PASS|TOKEN|SECRET|AUTH|CREDENTIAL|PRIVATE|SIGN|CERT)",
    re.IGNORECASE,
)

# Regex to validate task names (prevents argument/flag injection)
VALID_TASK_REGEX = re.compile(r"^[a-zA-Z0-9_:\-]+$")


class GradleError(Exception):
    """Base exception for all Gradle runner errors."""


class GradleToolchainMissingError(GradleError):
    """Raised when required Gradle or Java toolchain components are missing."""


class GradleTaskValidationError(GradleError):
    """Raised when a requested Gradle task name is invalid or suspicious."""


class GradleExecutionError(GradleError):
    """Raised when a Gradle build task exits with a non-zero exit code."""

    def __init__(
        self,
        message: str,
        exit_code: int,
        command: Sequence[str],
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.command = list(command)
        self.stdout = stdout
        self.stderr = stderr


class GradleTimeoutError(GradleError):
    """Raised when a Gradle build task exceeds the configured timeout."""

    def __init__(
        self,
        message: str,
        timeout_seconds: float,
        command: Sequence[str],
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.timeout_seconds = timeout_seconds
        self.command = list(command)
        self.stdout = stdout
        self.stderr = stderr


class ArtifactExtractionError(GradleError):
    """Raised when the expected output APK is missing, ambiguous, or invalid."""


@dataclass(frozen=True)
class GradleBuildResult:
    """Structured result of a Gradle build invocation."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    command: list[str]
    apk_path: Path | None = None
    mapping_file: Path | None = None
    is_simulated: bool = False
    metadata: dict[str, str] = field(default_factory=dict)


def redact_secrets(text: str, secrets: Sequence[str] | None = None) -> str:
    """
    Redact known sensitive strings and standard credential patterns from text.
    Ensures passwords, tokens, and keystore arguments do not appear in logs.
    """
    if not text:
        return ""

    redacted = text

    # Redact explicit secrets
    if secrets:
        for secret in secrets:
            if secret and len(secret) >= 3:
                redacted = redacted.replace(secret, "***REDACTED***")

    # Redact common credential patterns in CLI arguments and logs
    patterns = [
        (
            re.compile(
                r"(-P[a-zA-Z0-9_.]*(?:password|secret|key|token)=)[^\s]+",
                re.IGNORECASE,
            ),
            r"\1***REDACTED***",
        ),
        (
            re.compile(r"(--ks-pass\s+pass:)[^\s]+", re.IGNORECASE),
            r"\1***REDACTED***",
        ),
        (
            re.compile(r"(--key-pass\s+pass:)[^\s]+", re.IGNORECASE),
            r"\1***REDACTED***",
        ),
        (
            re.compile(r"(-storepass\s+)[^\s]+", re.IGNORECASE),
            r"\1***REDACTED***",
        ),
        (
            re.compile(r"(-keypass\s+)[^\s]+", re.IGNORECASE),
            r"\1***REDACTED***",
        ),
    ]

    for pattern, replacement in patterns:
        redacted = pattern.sub(replacement, redacted)

    return redacted


def build_safe_env(
    extra_env: dict[str, str] | None = None,
    allowed_sensitive_vars: Sequence[str] | None = None,
) -> dict[str, str]:
    """
    Construct a sanitized environment dictionary for Gradle subprocess execution.
    Preserves essential OS and build tool variables while stripping credentials,
    signing passwords, and secret tokens.
    """
    allowed_keys = set(PRESERVED_ENV_VARS_COMMON)
    if sys.platform == "win32":
        allowed_keys.update(PRESERVED_ENV_VARS_WINDOWS)
    else:
        allowed_keys.update(PRESERVED_ENV_VARS_POSIX)

    allowed_sensitive = set(allowed_sensitive_vars or [])

    safe_env: dict[str, str] = {}

    for key, value in os.environ.items():
        key_upper = key.upper()
        # Keep if explicitly in preserved set
        if key_upper in allowed_keys or key in allowed_keys:
            # Check for accidental sensitive variable named in preserved set
            if SENSITIVE_VAR_PATTERN.search(key) and key not in allowed_sensitive:
                continue
            safe_env[key] = value
        elif key in allowed_sensitive:
            safe_env[key] = value
        elif not SENSITIVE_VAR_PATTERN.search(key):
            # Also keep non-sensitive standard variables that might be needed
            # (e.g. CI, TERM, etc.)
            if key_upper.startswith(("GRADLE_", "JAVA_", "ANDROID_")):
                safe_env[key] = value

    if extra_env:
        for k, v in extra_env.items():
            safe_env[k] = v

    return safe_env


def validate_gradle_task(task: str) -> None:
    """
    Validate that a Gradle task token is safe and properly formed.
    Rejects task strings that start with '-' or contain shell metacharacters.
    """
    if not task or not isinstance(task, str):
        raise GradleTaskValidationError("Gradle task name cannot be empty.")

    task_trimmed = task.strip()
    if task_trimmed.startswith("-"):
        raise GradleTaskValidationError(
            f"Invalid Gradle task '{task}': Task names cannot start with '-' (flags must be passed separately)."
        )

    if not VALID_TASK_REGEX.match(task_trimmed):
        raise GradleTaskValidationError(
            f"Invalid Gradle task '{task}': Task names can only contain alphanumeric characters, ':', '_', and '-'."
        )


def kill_process_tree(pid: int) -> None:
    """
    Terminate an entire process tree by process ID.
    On Windows, uses `taskkill /F /T /PID`.
    On POSIX, attempts `os.killpg` or `SIGKILL`.
    """
    if pid <= 0:
        return

    if sys.platform == "win32":
        taskkill_path = shutil.which("taskkill") or "taskkill"
        try:
            subprocess.run(
                [taskkill_path, "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError):
            pass
    else:
        try:
            if hasattr(os, "getpgid") and hasattr(os, "killpg"):
                pgid = os.getpgid(pid)
                os.killpg(pgid, 9)  # SIGKILL
            else:
                os.kill(pid, 9)
        except (subprocess.SubprocessError, OSError):
            try:
                os.kill(pid, 9)
            except OSError:
                pass


def resolve_gradle_executable(
    project_dir: Path,
    custom_gradle_path: Path | None = None,
) -> tuple[list[str], str]:
    """
    Determine the trusted Gradle command and execution mode for a project.

    Returns:
        (command_prefix, mode_label)
        where mode_label is 'wrapper', 'system', or 'custom'.

    Raises:
        GradleToolchainMissingError: If no valid, trusted Gradle executable is available.
    """
    resolved_dir = project_dir.resolve()

    # 1. Custom Gradle executable explicitly specified
    if custom_gradle_path is not None:
        custom_resolved = custom_gradle_path.resolve()
        if not custom_resolved.exists():
            raise GradleToolchainMissingError(
                f"Configured custom Gradle executable does not exist: '{custom_resolved}'"
            )
        return [str(custom_resolved)], "custom"

    # 2. Project Gradle Wrapper
    wrapper_script_name = "gradlew.bat" if sys.platform == "win32" else "gradlew"
    wrapper_script = resolved_dir / wrapper_script_name
    wrapper_jar = resolved_dir / "gradle" / "wrapper" / "gradle-wrapper.jar"

    if wrapper_script.is_file():
        # Check wrapper JAR presence
        if wrapper_jar.is_file():
            if sys.platform != "win32":
                # Ensure execution permission on POSIX
                if not os.access(wrapper_script, os.X_OK):
                    try:
                        wrapper_script.chmod(wrapper_script.stat().st_mode | 0o111)
                    except OSError:
                        pass
            return [str(wrapper_script)], "wrapper"
        else:
            # Wrapper script exists, but wrapper JAR is missing.
            # Do NOT silently download it. Check for system Gradle fallback.
            system_gradle = shutil.which("gradle")
            if system_gradle:
                return [system_gradle], "system"
            raise GradleToolchainMissingError(
                f"Gradle Wrapper script '{wrapper_script_name}' exists, but the Wrapper JAR "
                f"'{wrapper_jar.relative_to(resolved_dir)}' is missing, and no system 'gradle' "
                f"executable was found on PATH. Silent download is forbidden by project safety rules. "
                f"Please provide a trusted gradle-wrapper.jar or install Gradle system-wide."
            )

    # 3. System Gradle on PATH
    system_gradle = shutil.which("gradle")
    if system_gradle:
        return [system_gradle], "system"

    raise GradleToolchainMissingError(
        f"No Gradle build tool found for project at '{resolved_dir}'. "
        f"Neither a complete Gradle Wrapper ('{wrapper_script_name}' + 'gradle-wrapper.jar') "
        f"nor a system 'gradle' binary was found on PATH."
    )


def validate_apk_file(apk_path: Path) -> None:
    """
    Validate that an APK file exists, is non-empty, and has valid ZIP/DEX structure.
    Raises ArtifactExtractionError if the file is invalid.
    """
    resolved = apk_path.resolve()
    if not resolved.exists():
        raise ArtifactExtractionError(f"APK file does not exist: '{resolved}'")
    if not resolved.is_file():
        raise ArtifactExtractionError(f"APK path is not a regular file: '{resolved}'")
    if resolved.stat().st_size == 0:
        raise ArtifactExtractionError(f"APK file is empty (0 bytes): '{resolved}'")

    if not zipfile.is_zipfile(resolved):
        raise ArtifactExtractionError(
            f"APK file '{resolved.name}' is not a valid ZIP/APK archive."
        )

    # Inspect zip contents for standard Android APK markers
    try:
        with zipfile.ZipFile(resolved, "r") as zf:
            namelist = zf.namelist()
            has_manifest = "AndroidManifest.xml" in namelist
            has_dex = any(n.endswith(".dex") for n in namelist)
            if not has_manifest and not has_dex:
                raise ArtifactExtractionError(
                    f"APK archive '{resolved.name}' does not contain expected Android markers "
                    f"('AndroidManifest.xml' or 'classes.dex'). Contents: {namelist[:5]}"
                )
    except zipfile.BadZipFile as e:
        raise ArtifactExtractionError(
            f"Corrupted APK archive '{resolved.name}': {e}"
        ) from e


def locate_build_apk(
    staging_dir: Path,
    module_name: str = "app",
    build_variant: str = "release",
) -> Path:
    """
    Discover and validate the release APK produced by Gradle in the staging directory.
    Searches standard AGP output paths:
      - `<staging_dir>/<module_name>/build/outputs/apk/<build_variant>/`
      - `<staging_dir>/build/outputs/apk/<build_variant>/`

    Rejects missing, ambiguous, or invalid APK artifacts.
    """
    resolved_dir = staging_dir.resolve()
    candidate_dirs = [
        resolved_dir / module_name / "build" / "outputs" / "apk" / build_variant,
        resolved_dir / "build" / "outputs" / "apk" / build_variant,
    ]

    target_dir: Path | None = None
    for c in candidate_dirs:
        if c.is_dir():
            target_dir = c
            break

    if target_dir is None:
        raise ArtifactExtractionError(
            f"Build output directory for variant '{build_variant}' does not exist. "
            f"Searched: {[str(c.relative_to(resolved_dir) if c.is_relative_to(resolved_dir) else c) for c in candidate_dirs]}"
        )

    apk_files = [
        f for f in target_dir.iterdir() if f.is_file() and f.suffix.lower() == ".apk"
    ]

    if not apk_files:
        raise ArtifactExtractionError(
            f"No APK artifacts found in build output directory '{target_dir}'."
        )

    # If exactly one APK, use it
    if len(apk_files) == 1:
        chosen_apk = apk_files[0]
    else:
        # If multiple APKs exist, look for expected pattern: <module>-<variant>*.apk
        # Prefer unsigned over unaligned if unsigned exists
        variant_lower = build_variant.lower()
        module_lower = module_name.lower()
        matching = [
            f
            for f in apk_files
            if module_lower in f.name.lower() and variant_lower in f.name.lower()
        ]
        # Filter out intermediate/unaligned APKs if a final or unsigned exists
        filtered = [f for f in matching if "unaligned" not in f.name.lower()]
        if len(filtered) == 1:
            chosen_apk = filtered[0]
        elif len(matching) == 1:
            chosen_apk = matching[0]
        else:
            names = [f.name for f in apk_files]
            raise ArtifactExtractionError(
                f"Ambiguous APK output in '{target_dir}': multiple candidate APKs found ({names}). "
                f"Cannot determine target artifact without explicit configuration."
            )

    validate_apk_file(chosen_apk)
    return chosen_apk


def locate_r8_mapping(
    staging_dir: Path,
    module_name: str = "app",
    build_variant: str = "release",
) -> Path | None:
    """
    Locate the R8/ProGuard obfuscation mapping file if generated by AGP.
    Standard path: `<staging_dir>/<module_name>/build/outputs/mapping/<build_variant>/mapping.txt`.
    Returns None if no mapping file was produced.
    """
    resolved_dir = staging_dir.resolve()
    candidate_paths = [
        resolved_dir
        / module_name
        / "build"
        / "outputs"
        / "mapping"
        / build_variant
        / "mapping.txt",
        resolved_dir / "build" / "outputs" / "mapping" / build_variant / "mapping.txt",
    ]

    for p in candidate_paths:
        if p.is_file() and p.stat().st_size > 0:
            return p

    return None


class GradleRunner:
    """
    Controlled Gradle build execution runner for isolated staging workspaces.
    Enforces safe subprocess execution, process tree termination on timeout,
    secret redaction, safe environment policies, and offline build flags.
    """

    def __init__(
        self,
        project_dir: Path,
        gradle_path: Path | None = None,
        timeout_seconds: float = 300.0,
        offline: bool = True,
        no_daemon: bool = True,
        secrets_to_redact: Sequence[str] | None = None,
    ) -> None:
        self.project_dir = project_dir.resolve()
        if not self.project_dir.exists() or not self.project_dir.is_dir():
            raise GradleError(
                f"Project directory does not exist or is not a directory: '{self.project_dir}'"
            )

        self.custom_gradle_path = gradle_path
        self.timeout_seconds = max(5.0, timeout_seconds)
        self.offline = offline
        self.no_daemon = no_daemon
        self.secrets_to_redact = list(secrets_to_redact or [])

    def run_task(
        self,
        tasks: str | Sequence[str],
        extra_args: Sequence[str] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> GradleBuildResult:
        """
        Execute one or more Gradle tasks inside the project directory.

        Args:
            tasks: Gradle task or sequence of tasks (e.g. 'assembleRelease' or [':app:assembleRelease']).
            extra_args: Additional command line flags (e.g. ['--stacktrace']).
            extra_env: Additional environment variables to merge safely.

        Returns:
            GradleBuildResult describing outcome and diagnostic output.

        Raises:
            GradleToolchainMissingError: If Gradle executable or required toolchain is missing.
            GradleTaskValidationError: If task string is invalid or dangerous.
            GradleTimeoutError: If execution exceeds timeout.
            GradleExecutionError: If Gradle exits with non-zero code.
        """
        # 1. Normalize and validate tasks
        task_list: list[str] = [tasks] if isinstance(tasks, str) else list(tasks)
        if not task_list:
            raise GradleTaskValidationError(
                "At least one Gradle task must be specified."
            )

        for t in task_list:
            validate_gradle_task(t)

        # 2. Resolve executable
        exec_cmd, mode = resolve_gradle_executable(
            self.project_dir, self.custom_gradle_path
        )

        # 3. Assemble command arguments
        cmd: list[str] = list(exec_cmd)
        cmd.extend(task_list)

        if self.no_daemon:
            cmd.append("--no-daemon")
        if self.offline:
            cmd.append("--offline")

        if extra_args:
            cmd.extend(extra_args)

        # 4. Construct safe environment
        safe_env = build_safe_env(extra_env=extra_env)

        # 5. Execute subprocess without shell=True
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        import time

        t0 = time.monotonic()

        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=str(self.project_dir),
                env=safe_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creationflags,
            )

            stdout_raw, stderr_raw = proc.communicate(timeout=self.timeout_seconds)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            if proc is not None:
                kill_process_tree(proc.pid)
                try:
                    out, err = proc.communicate(timeout=5.0)
                except (subprocess.SubprocessError, OSError):
                    out, err = "", ""
                stdout_redacted = redact_secrets(out or "", self.secrets_to_redact)
                stderr_redacted = redact_secrets(err or "", self.secrets_to_redact)
            else:
                stdout_redacted, stderr_redacted = "", ""

            raise GradleTimeoutError(
                f"Gradle build timed out after {self.timeout_seconds:.1f} seconds. "
                f"Command: {cmd}. Process tree terminated.",
                timeout_seconds=self.timeout_seconds,
                command=cmd,
                stdout=stdout_redacted,
                stderr=stderr_redacted,
            ) from e
        except FileNotFoundError as e:
            raise GradleToolchainMissingError(
                f"Failed to execute Gradle: executable not found: '{cmd[0]}'"
            ) from e
        except OSError as e:
            raise GradleExecutionError(
                f"Operating system error while executing Gradle command: {e}",
                exit_code=-1,
                command=cmd,
            ) from e

        t1 = time.monotonic()
        duration = t1 - t0

        stdout_clean = redact_secrets(stdout_raw, self.secrets_to_redact)
        stderr_clean = redact_secrets(stderr_raw, self.secrets_to_redact)

        if exit_code != 0:
            raise GradleExecutionError(
                f"Gradle build failed with exit code {exit_code}. "
                f"Command: {' '.join(cmd)}\n{stderr_clean[:1000]}",
                exit_code=exit_code,
                command=cmd,
                stdout=stdout_clean,
                stderr=stderr_clean,
            )

        return GradleBuildResult(
            success=True,
            exit_code=0,
            stdout=stdout_clean,
            stderr=stderr_clean,
            duration_seconds=duration,
            command=cmd,
            is_simulated=False,
            metadata={"execution_mode": mode},
        )
