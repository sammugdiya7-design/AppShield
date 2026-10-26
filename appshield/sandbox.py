"""
AppShield Sandbox Manager and Workspace Isolation.

ARCHITECTURAL DISTINCTION:
  1. Isolated Staging Directory: An ephemeral filesystem scratch folder (under system temp
     by default) into which project source files are copied, excluding sensitive credentials,
     keys, and build caches.
  2. Filesystem Change Protection & Source Immutability: Guarantees that the original developer
     source project remains bit-for-bit identical via pre- and post-run SHA-256 manifests,
     sensitive file exclusion from staging, safe directory cleanup, and overwrite protection.
  3. NOT an OS Process Sandbox: This staging workspace is a filesystem isolation mechanism,
     NOT an operating-system kernel process sandbox (such as Linux seccomp/cgroups/namespaces,
     macOS seatbelt, or Windows AppContainer). Subprocesses executed within the staging area
     (such as Gradle or R8) run under the user's OS credentials and can make network calls
     or execute arbitrary code if their build scripts contain such instructions.

BUILD EXECUTION RISKS:
  Gradle build scripts (build.gradle, settings.gradle, plugins) execute arbitrary JVM bytecode.
  For automated tests, only controlled, disposable sample fixtures must be used. Untrusted
  developer projects require future execution threat models, consent requirements, and process
  isolation controls before execution.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self  # pragma: no cover

from appshield.config import (
    DEFAULT_IMMUTABILITY_EXCLUDE_PATTERNS,
    DEFAULT_STAGING_EXCLUDE_PATTERNS,
    AppShieldConfig,
    AppShieldError,
    validate_output_destination,
)


class SandboxError(AppShieldError):
    """Base exception for workspace sandbox and isolation errors."""


class SourceImmutabilityError(SandboxError):
    """Raised when source files are modified or corrupted during execution."""


class StagingError(SandboxError):
    """Raised when staging workspace creation or file copying fails."""


class SecurityError(SandboxError):
    """Raised when an unsafe operation (path traversal, escaping symlink) is detected."""


def is_path_excluded(rel_path: Path, patterns: list[str]) -> bool:
    """
    Determine whether a relative path matches any exclusion pattern.
    Handles exact names, glob wildcards, and directory subtrees.
    """
    rel_posix = rel_path.as_posix()
    for pat in patterns:
        clean_pat = pat.strip()
        if not clean_pat:
            continue

        # Check direct match with Path.match
        try:
            if rel_path.match(clean_pat):
                return True
        except (ValueError, re.error):
            pass

        # Check filename match for **/ prefixes
        if clean_pat.startswith("**/"):
            sub_pat = clean_pat[3:]
            if fnmatch.fnmatch(rel_path.name, sub_pat):
                return True
            try:
                if rel_path.match(sub_pat):
                    return True
            except (ValueError, re.error):
                pass

        # Match against name or full posix path
        if fnmatch.fnmatch(rel_path.name, clean_pat):
            return True
        if fnmatch.fnmatch(rel_posix, clean_pat):
            return True

        # Directory subtree match (e.g. 'build/**', '.git/**', '.gradle/**')
        if clean_pat.endswith("/**"):
            dir_prefix = clean_pat[:-3]
            if dir_prefix.startswith("**/"):
                dir_name = dir_prefix[3:]
                if dir_name in rel_path.parts:
                    return True
            elif dir_prefix in rel_path.parts or rel_posix.startswith(dir_prefix + "/"):
                return True

        # Part match for simple directory names (e.g. '.git', 'build')
        if clean_pat in rel_path.parts:
            return True

    return False


def compute_file_sha256(file_path: Path) -> str:
    """Calculate the SHA-256 hex digest of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True)
class SourceManifest:
    """Snapshot of file paths and their SHA-256 hashes within a source directory."""

    root_dir: Path
    file_hashes: dict[str, str]

    def compare(self, current: SourceManifest) -> tuple[bool, list[str]]:
        """
        Compare this manifest against a current manifest.
        Returns (is_identical, list_of_discrepancy_messages).
        """
        differences: list[str] = []

        # Check modified or missing files
        for rel_path, original_hash in self.file_hashes.items():
            if rel_path not in current.file_hashes:
                differences.append(f"Deleted file: '{rel_path}'")
            elif current.file_hashes[rel_path] != original_hash:
                differences.append(
                    f"Modified file: '{rel_path}' (original SHA256: {original_hash[:8]}..., "
                    f"current SHA256: {current.file_hashes[rel_path][:8]}...)"
                )

        # Check newly created files
        for rel_path in current.file_hashes:
            if rel_path not in self.file_hashes:
                differences.append(f"New file created in source tree: '{rel_path}'")

        return len(differences) == 0, differences


def compute_source_manifest(
    source_dir: Path,
    exclude_patterns: list[str] | None = None,
) -> SourceManifest:
    """
    Scan the source directory and compute SHA-256 hashes for all non-excluded files.

    CRITICAL SECURITY INVARIANTS:
      1. Sensitive files (*.jks, *.keystore, local.properties, *.env*, google-services.json)
         are NOT excluded from immutability verification. They MUST be hashed and verified.
      2. Deliberately excluded paths are documented in DEFAULT_IMMUTABILITY_EXCLUDE_PATTERNS
         (only VCS internals like .git and tool-managed staging/caches).
      3. Symlinks are verified to ensure they resolve strictly within source_dir. Escaping
         symlinks raise SecurityError to prevent data leakage or external traversal.
      4. Never logs file contents, secrets, or signing material.
    """
    resolved_root = source_dir.resolve()
    patterns = (
        list(exclude_patterns)
        if exclude_patterns is not None
        else list(DEFAULT_IMMUTABILITY_EXCLUDE_PATTERNS)
    )
    file_hashes: dict[str, str] = {}

    for root, dirs, files in os.walk(resolved_root, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(resolved_root)

        # Check symlink safety for directories before traversing
        for d in dirs:
            dir_path = root_path / d
            if dir_path.is_symlink():
                check_symlink_safety(dir_path, resolved_root)

        dirs[:] = [d for d in dirs if not is_path_excluded(rel_root / d, patterns)]

        for file_name in files:
            file_path = root_path / file_name
            rel_file = file_path.relative_to(resolved_root)
            if is_path_excluded(rel_file, patterns):
                continue

            # Symlink safety check: symlinks must not escape source_dir
            if file_path.is_symlink():
                check_symlink_safety(file_path, resolved_root)

            try:
                if file_path.is_symlink() and not file_path.is_file():
                    target_str = os.readlink(file_path)
                    file_hashes[rel_file.as_posix()] = hashlib.sha256(
                        f"symlink:{target_str}".encode()
                    ).hexdigest()
                else:
                    file_hashes[rel_file.as_posix()] = compute_file_sha256(file_path)
            except (OSError, PermissionError) as e:
                raise SandboxError(
                    f"Failed to hash source file '{file_path}': {e}"
                ) from e

    return SourceManifest(root_dir=resolved_root, file_hashes=file_hashes)


def check_symlink_safety(src_file: Path, source_dir: Path) -> None:
    """
    Verify that a symlink does not escape the source directory.
    Raises SecurityError if the symlink targets an external location.
    """
    if src_file.is_symlink():
        try:
            resolved_target = src_file.resolve()
            if not resolved_target.is_relative_to(source_dir.resolve()):
                raise SecurityError(
                    f"Security check failed: Symlink '{src_file}' points outside source tree "
                    f"('{resolved_target}'). Rejecting to prevent data leakage."
                )
        except Exception as e:
            if isinstance(e, SecurityError):
                raise
            raise SecurityError(f"Failed to resolve symlink '{src_file}': {e}") from e


def _remove_readonly(func: Any, path: str, exc_info: Any) -> None:
    """Error handler for shutil.rmtree on Windows to clear read-only file attributes."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except (OSError, PermissionError):
        pass


def safe_remove_tree(target_dir: Path, allowed_parent: Path) -> None:
    """
    Safely delete a directory tree, strictly verifying that target_dir is a
    subdirectory of allowed_parent to prevent unintended file deletions.
    """
    resolved_target = target_dir.resolve()
    resolved_parent = allowed_parent.resolve()

    if resolved_target == resolved_parent:
        raise SecurityError(
            f"Safety guard: Target directory is identical to parent '{resolved_parent}'. Refusing to delete."
        )

    if not resolved_target.is_relative_to(resolved_parent):
        raise SecurityError(
            f"Safety guard: Target directory '{resolved_target}' is outside allowed parent '{resolved_parent}'."
        )

    # Prevent deleting root or current working directory
    cwd = Path.cwd().resolve()
    if resolved_target == cwd:
        raise SecurityError(
            f"Safety guard: Target directory is the current working directory '{cwd}'. Refusing to delete."
        )

    if not resolved_target.exists():
        return

    # Delete directory contents safely
    if sys.version_info >= (3, 12):
        shutil.rmtree(resolved_target, onexc=_remove_readonly)
    else:
        shutil.rmtree(resolved_target, onerror=_remove_readonly)  # pragma: no cover


class SandboxManager:
    """
    Manages isolated ephemeral staging workspaces.

    Guarantees:
      1. Original project is strictly read-only and verified bit-for-bit identical.
      2. Intermediate operations occur exclusively within an isolated staging scratch folder.
      3. Sensitive files (*.jks, local.properties, *.env*) are excluded from the staging copy,
         yet strictly verified in the source immutability manifest.
      4. Staging failures and errors trigger safe cleanup of the temporary staging directory.
      5. Source preservation is verified via SHA-256 manifest comparisons.
      6. Output artifacts are safely exported with overwrite safeguards.
      7. Cleanup strictly deletes files within its own staging directory.
      8. Avoids executing project scripts or arbitrary configuration commands.

    Distinction:
      This is an isolated filesystem staging scratchpad, NOT an operating-system process sandbox.
      Subprocesses (like Gradle) run with user privileges. Build scripts can execute code.
    """

    def __init__(
        self,
        source_dir: Path | str,
        staging_parent: Path | str | None = None,
        staging_exclude_patterns: list[str] | None = None,
        immutability_exclude_patterns: list[str] | None = None,
        exclude_patterns: list[str] | None = None,  # Backward compatibility alias
        verify_source_immutability: bool = True,
        cleanup_on_exit: bool = True,
    ):
        self.source_dir = Path(source_dir).resolve()

        # Staging exclusions: files that must NOT be copied into staging
        if staging_exclude_patterns is not None:
            self.staging_exclude_patterns = list(staging_exclude_patterns)
        elif exclude_patterns is not None:
            self.staging_exclude_patterns = list(exclude_patterns)
        else:
            self.staging_exclude_patterns = list(DEFAULT_STAGING_EXCLUDE_PATTERNS)

        self.exclude_patterns = self.staging_exclude_patterns

        # Immutability exclusions: paths deliberately excluded from source-preservation hashing
        self.immutability_exclude_patterns = (
            list(immutability_exclude_patterns)
            if immutability_exclude_patterns is not None
            else list(DEFAULT_IMMUTABILITY_EXCLUDE_PATTERNS)
        )

        self.verify_source_immutability = verify_source_immutability
        self.cleanup_on_exit = cleanup_on_exit

        # Default staging parent to system temp directory to prevent polluting source tree
        if staging_parent:
            self.staging_parent = Path(staging_parent).resolve()
        else:
            self.staging_parent = (
                Path(tempfile.gettempdir()) / "appshield_staging"
            ).resolve()

        # Generate unique build staging path
        self.build_id = f"build_{uuid.uuid4().hex}"
        self.staging_dir = self.staging_parent / self.build_id

        self.initial_manifest: SourceManifest | None = None
        self.is_staged: bool = False
        self._cleaned_up: bool = False

    @classmethod
    def from_config(
        cls,
        config: AppShieldConfig,
        staging_parent: Path | str | None = None,
        cleanup_on_exit: bool = True,
    ) -> SandboxManager:
        """Create a SandboxManager instance from an AppShieldConfig object."""
        return cls(
            source_dir=config.input.project_dir,
            staging_parent=staging_parent,
            staging_exclude_patterns=config.input.exclude_patterns,
            immutability_exclude_patterns=config.input.immutability_exclude_patterns,
            verify_source_immutability=config.input.verify_source_immutability,
            cleanup_on_exit=cleanup_on_exit,
        )

    def stage(self) -> Path:
        """
        Stage the source project into the isolated sandbox.
        Applies sensitive file exclusions and verifies path traversal safety.
        """
        if not self.source_dir.exists():
            raise StagingError(f"Source directory does not exist: '{self.source_dir}'")
        if not self.source_dir.is_dir():
            raise StagingError(f"Source path is not a directory: '{self.source_dir}'")

        # 1. Take initial SHA-256 snapshot for source preservation verification
        # Sensitive files (*.jks, local.properties, .env) ARE included here!
        if self.verify_source_immutability:
            self.initial_manifest = compute_source_manifest(
                self.source_dir, self.immutability_exclude_patterns
            )

        # 2. Guard against invalid staging directory locations
        if self.staging_dir == self.source_dir:
            raise SecurityError(
                "Staging directory cannot be identical to the source directory."
            )

        try:
            self.staging_parent.mkdir(parents=True, exist_ok=True)
            self.staging_dir.mkdir(parents=True, exist_ok=False)
        except Exception as e:
            raise StagingError(
                f"Failed to create staging directory '{self.staging_dir}': {e}"
            ) from e

        # 3. Copy source files into staging excluding sensitive paths
        try:
            for root, dirs, files in os.walk(self.source_dir):
                root_path = Path(root)
                rel_root = root_path.relative_to(self.source_dir)

                # Filter out excluded directories and staging parent in-place
                dirs[:] = [
                    d
                    for d in dirs
                    if (root_path / d).resolve() != self.staging_parent
                    and not is_path_excluded(rel_root / d, self.exclude_patterns)
                ]

                # Create corresponding directory in staging
                dest_dir = self.staging_dir / rel_root
                dest_dir.mkdir(parents=True, exist_ok=True)

                for file_name in files:
                    src_file = root_path / file_name
                    rel_file = src_file.relative_to(self.source_dir)

                    # Exclude sensitive files
                    if is_path_excluded(rel_file, self.exclude_patterns):
                        continue

                    dest_file = self.staging_dir / rel_file

                    # Path traversal guard: ensure destination stays within staging_dir
                    resolved_dest = dest_file.resolve()
                    if not resolved_dest.is_relative_to(self.staging_dir.resolve()):
                        raise SecurityError(
                            f"Path traversal detected during staging: '{rel_file}' attempts to escape staging directory."
                        )

                    # Symlink safety check: symlinks must not point outside source_dir
                    check_symlink_safety(src_file, self.source_dir)

                    # Safe copy: copy file content preserving permissions without modifying source
                    shutil.copy2(src_file, dest_file)

        except Exception as e:
            # Atomic failure recovery: cleanup staging directory immediately
            self.cleanup()
            if isinstance(e, (SecurityError, StagingError)):
                raise
            raise StagingError(f"Staging failed: {e}") from e

        self.is_staged = True
        return self.staging_dir

    def verify_source_integrity(self) -> None:
        """
        Recompute SHA-256 hashes of the original source files and verify
        that no file was modified, added, or deleted during execution.
        """
        if not self.verify_source_immutability or self.initial_manifest is None:
            return

        current_manifest = compute_source_manifest(
            self.source_dir, self.immutability_exclude_patterns
        )
        is_identical, discrepancies = self.initial_manifest.compare(current_manifest)

        if not is_identical:
            err_details = "\n  - ".join(discrepancies)
            raise SourceImmutabilityError(
                f"Source preservation violation detected! The original source directory was modified:\n  - {err_details}"
            )

    def export_artifact(
        self,
        staged_relative_path: Path | str,
        output_dir: Path | str,
        target_filename: str | None = None,
        allow_overwrite: bool = False,
    ) -> Path:
        """
        Export a built or protected artifact from the sandbox to the final output directory.
        Enforces destination existence checks and overwrite protection.
        """
        staged_path = (self.staging_dir / staged_relative_path).resolve()

        # Security check: staged_path must not escape staging workspace
        if not staged_path.is_relative_to(self.staging_dir.resolve()):
            raise SecurityError(
                f"Attempted to export artifact outside staging workspace: '{staged_path}'"
            )

        if not staged_path.exists():
            raise SandboxError(
                f"Staged artifact not found: '{staged_path}'. Build may have failed to produce output."
            )

        dest_dir = Path(output_dir).resolve()
        dest_filename = target_filename or staged_path.name

        # Enforce overwrite guard
        target_dest = validate_output_destination(
            dest_dir, dest_filename, allow_overwrite=allow_overwrite
        )

        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_path, target_dest)
        return target_dest

    def cleanup(self) -> None:
        """Safely delete the isolated staging directory."""
        if self._cleaned_up:
            return

        if self.staging_dir.exists():
            safe_remove_tree(self.staging_dir, self.staging_parent)

        # Attempt to remove staging_parent if empty
        if self.staging_parent.exists():
            try:
                if not any(self.staging_parent.iterdir()):
                    self.staging_parent.rmdir()
            except (OSError, PermissionError):
                pass

        self.is_staged = False
        self._cleaned_up = True

    def __enter__(self) -> Self:
        self.stage()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        try:
            # Verify source immutability if no exception occurred, or still check
            if exc_type is None:
                self.verify_source_integrity()
        finally:
            if self.cleanup_on_exit:
                self.cleanup()


# Alias for spec consistency
SandboxContext = SandboxManager
