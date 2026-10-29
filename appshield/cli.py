"""
AppShield Command Line Interface (CLI).
Implements the 4 foundational commands: info, doctor, protect, and verify.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import appshield
from appshield.config import (
    ConfigError,
    ConfigNotFoundError,
    ConfigValidationError,
    OverwriteError,
    load_config,
    validate_output_destination,
)
from appshield.doctor import run_doctor_checks


def build_parser() -> argparse.ArgumentParser:
    """Construct the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="appshield",
        description="AppShield: Local, cross-platform application code-protection CLI.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"AppShield {appshield.__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. info
    subparsers.add_parser(
        "info",
        help="Display AppShield version, architecture, and supported capabilities.",
    )

    # 2. doctor
    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check local environment and tool prerequisites.",
    )
    doctor_parser.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Path to Android project to inspect for gradlew wrapper.",
    )

    # 3. protect
    protect_parser = subparsers.add_parser(
        "protect",
        help="Validate configuration and stage a protection pipeline.",
    )
    protect_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        required=True,
        help="Path to appshield.yaml or appshield.json configuration file.",
    )
    protect_parser.add_argument(
        "--project-dir",
        type=Path,
        default=None,
        help="Override input project directory path.",
    )
    protect_parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Override destination output directory.",
    )
    protect_parser.add_argument(
        "--platform",
        choices=["android", "ios", "windows"],
        default=None,
        help="Override target platform.",
    )
    protect_parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Authorize overwriting existing destination files.",
    )

    # 4. verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Inspect hardened artifact and run objective verification checks.",
    )
    verify_parser.add_argument(
        "artifact",
        type=Path,
        help="Path to the application binary / APK artifact to verify.",
    )
    verify_parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Optional path to configuration file.",
    )

    return parser


def cmd_info() -> int:
    """Handle `appshield info` command."""
    print("=================================================================")
    print(f"AppShield CLI - Version {appshield.__version__}")
    print("Simple, Local, Cross-Platform Application Code-Protection")
    print("=================================================================")
    print("Architecture:")
    print("  - Execution Model     : 100% Local, Offline Orchestrator (Air-Gapped)")
    print("  - Remote Telemetry    : Disabled by design (Zero remote network calls)")
    print("  - Input Handling      : Read-only input guarantee (Source immutability)")
    print(
        "  - Build Isolation     : Ephemeral sandboxing with sensitive file exclusions"
    )
    print(
        "  - Verification Policy : Objective empirical evidence only (No composite scores)"
    )
    print()
    print("Platform Support:")
    print("  - Android (v1 MVP)    : Supported - Android Gradle Projects (AGP + R8)")
    print(
        "                          Note: Arbitrary precompiled APK input is unsupported."
    )
    print("  - iOS (v2)            : Planned (Phase 5) - Xcode CLI & symbol stripping")
    print(
        "  - Windows (v2)        : Planned (Phase 6) - .NET Obfuscar & PE symbol stripping"
    )
    print()
    print("Configuration Formats:")
    print("  - YAML (.yaml, .yml)  : Supported")
    print("  - JSON (.json)        : Supported")
    print("=================================================================")
    return 0


def cmd_doctor(project_dir: Path | None = None) -> int:
    """Handle `appshield doctor` command."""
    print("AppShield Doctor: Checking local toolchain prerequisites...")
    print("-----------------------------------------------------------------")
    reports = run_doctor_checks(project_dir)

    all_required_ok = True
    for item in reports:
        tag = (
            "[OK]"
            if item.is_available
            else ("[MISSING]" if item.required else "[OPTIONAL]")
        )
        req_str = " (Required)" if item.required else " (Optional)"
        print(f"{tag:<10} {item.name}{req_str}")
        if item.is_available:
            ver_text = f"         Version/Path: {item.version or item.path}"
            print(ver_text)
            if item.target_version:
                print(f"         Target Vers : {item.target_version}")
        else:
            if item.target_version:
                print(f"         Target Vers : {item.target_version}")
            if item.required:
                all_required_ok = False
            print(f"         Remediation : {item.remediation_hint}")

    print("-----------------------------------------------------------------")
    print("Toolchain Validation Status:")
    print("  [INFO] Live Builds Validated : 0")
    print(
        "  Note : Selected target versions are based on AGP compatibility documentation."
    )
    print(
        "         Toolchain compatibility has not yet been validated through a successful live build."
    )
    print("-----------------------------------------------------------------")
    if all_required_ok:
        print("Status: All required prerequisites are met.")
        return 0
    else:
        print(
            "Status: Missing required dependencies. Please see remediation hints above."
        )
        return 1


def cmd_protect(
    config_path: Path,
    project_dir: Path | None = None,
    output_dir: Path | None = None,
    platform: Path | None = None,
    overwrite: bool = False,
) -> int:
    """Handle `appshield protect` command."""
    print("AppShield Protect: Validating configuration and prerequisites...")

    try:
        config = load_config(config_path)
    except ConfigNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ConfigValidationError as e:
        print(f"Configuration Validation Error: {e}", file=sys.stderr)
        return 1
    except ConfigError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        return 1

    # Apply CLI overrides if specified
    if project_dir:
        config.input.project_dir = project_dir.resolve()
    if output_dir:
        config.output.dir = output_dir.resolve()
    if platform:
        config.platform = str(platform)
    if overwrite:
        config.output.overwrite_existing = True

    print(f"  - Project Name : {config.project_name}")
    print(f"  - Platform     : {config.platform}")
    print(f"  - Input Dir    : {config.input.project_dir}")
    print(f"  - Output Dir   : {config.output.dir}")

    # Validate that input project directory exists
    if not config.input.project_dir.exists():
        print(
            f"Error: Input project directory does not exist: '{config.input.project_dir}'",
            file=sys.stderr,
        )
        return 1

    if not config.input.project_dir.is_dir():
        print(
            f"Error: Input project path is not a directory: '{config.input.project_dir}'. "
            "AppShield requires a supported Android Gradle project root.",
            file=sys.stderr,
        )
        return 1

    # Validate output destination and check overwrite guard
    expected_artifact_name = (
        f"{config.project_name}-{config.android.build_variant}-protected.apk"
    )
    try:
        target_output = validate_output_destination(
            config.output.dir,
            expected_artifact_name,
            allow_overwrite=config.output.overwrite_existing,
        )
        print(f"  - Target File  : {target_output}")
    except OverwriteError as e:
        print(f"Overwrite Protection Error: {e}", file=sys.stderr)
        return 1

    # Check prerequisites
    doctor_res = cmd_doctor(config.input.project_dir)
    print("-----------------------------------------------------------------")
    if doctor_res != 0:
        print(
            "PREFLIGHT VALIDATION: FAILED (Missing environment prerequisites).",
            file=sys.stderr,
        )
        return doctor_res

    # IMPORTANT: Explicitly report that protection execution is NOT implemented in Plan 03-01
    print("PREFLIGHT VALIDATION: SUCCESSFUL.")
    print("NOTICE: The protection engine is NOT implemented in Plan 03-01.")
    print("Configuration, path validation, and overwrite protection checks completed.")
    print(
        "The Android Gradle + R8 protection workflow will be implemented and validated in Phase 4."
    )
    print("-----------------------------------------------------------------")
    return 0


def cmd_verify(artifact_path: Path, config_path: Path | None = None) -> int:
    """Handle `appshield verify` command."""
    print("AppShield Verify: Inspecting artifact and reporting check capabilities...")
    print(f"Target Artifact: {artifact_path}")

    resolved_artifact = artifact_path.resolve()
    if not resolved_artifact.exists():
        print(
            f"Error: Target artifact not found: '{resolved_artifact}'", file=sys.stderr
        )
        return 1

    if not resolved_artifact.is_file():
        print(
            f"Error: Target path is not a file: '{resolved_artifact}'", file=sys.stderr
        )
        return 1

    print("Artifact validated: File exists and is readable.")
    print("-----------------------------------------------------------------")
    print("Objective Verification Capabilities Status (Plan 03-01):")
    print(
        "  [CHK-SYM-01] Identifier Renaming Ratio      : UNAVAILABLE (Planned for Phase 4)"
    )
    print(
        "               Evidence Type: Heuristic (evidence of renaming per keep-rules)"
    )
    print(
        "  [CHK-STR-01] String Pool Constant Scan      : UNAVAILABLE (Planned for Phase 4)"
    )
    print(
        "               Evidence Type: Heuristic (pattern detection; no absolute guarantee)"
    )
    print(
        "  [CHK-SIG-01] APK Signature Verification     : UNAVAILABLE (Planned for Phase 4)"
    )
    print("               Evidence Type: Verified (validity under signature rules)")
    print(
        "  [CHK-ALN-01] Zip Alignment Verification     : UNAVAILABLE (Planned for Phase 4)"
    )
    print("               Evidence Type: Verified (4-byte alignment check)")
    print(
        "  [CHK-DEC-01] Structural Decompilation Check : UNAVAILABLE (Planned for Phase 4)"
    )
    print("               Evidence Type: Informational (Dalvik format syntax check)")
    print("-----------------------------------------------------------------")
    print("NOTICE: Objective verification checks are NOT implemented in Plan 03-01.")
    print(
        "Input artifact was validated. Verification engine execution begins in Phase 4."
    )
    print("No composite security scores will be generated.")
    return 0


def main(args: list[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        return 0

    if parsed_args.command == "info":
        return cmd_info()
    elif parsed_args.command == "doctor":
        return cmd_doctor(parsed_args.project_dir)
    elif parsed_args.command == "protect":
        return cmd_protect(
            config_path=parsed_args.config,
            project_dir=parsed_args.project_dir,
            output_dir=parsed_args.output_dir,
            platform=parsed_args.platform,
            overwrite=parsed_args.overwrite,
        )
    elif parsed_args.command == "verify":
        return cmd_verify(
            artifact_path=parsed_args.artifact,
            config_path=parsed_args.config,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
