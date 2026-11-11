"""
AppShield Command Line Interface (CLI).
Implements the 4 foundational commands: info, doctor, protect, and verify.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import appshield
from appshield.adapters.android import AndroidPipelineAdapter
from appshield.config import (
    AppShieldError,
    ConfigError,
    ConfigNotFoundError,
    ConfigValidationError,
    OverwriteError,
    VerificationConfig,
    load_config,
    validate_output_destination,
)
from appshield.dex import DexError
from appshield.doctor import (
    get_offline_dependency_cache_reports,
    run_doctor_checks,
)
from appshield.gradle import GradleError
from appshield.mapping import MappingParseError
from appshield.signing import SigningError
from appshield.verify import (
    VerificationEngine,
    export_report_json,
    format_report_terminal,
)


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
    protect_parser.add_argument(
        "--allow-production-signing",
        action="store_true",
        default=False,
        help="Explicitly authorize using a production signing keystore.",
    )
    protect_parser.add_argument(
        "--allow-network-dependencies",
        action="store_true",
        default=False,
        help="Explicitly authorize network dependency resolution during this build (overrides default offline mode). Use for initial dependency warm-up in staging.",
    )
    protect_parser.add_argument(
        "--mapping-out",
        type=Path,
        default=None,
        help="Path to securely retain the generated R8 mapping.txt file.",
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
    verify_parser.add_argument(
        "-m",
        "--mapping-file",
        type=Path,
        default=None,
        help="Path to R8 mapping.txt file associated with the artifact.",
    )
    verify_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Path to export audit report JSON.",
    )
    verify_parser.add_argument(
        "--overwrite",
        action="store_true",
        default=False,
        help="Authorize overwriting existing destination files.",
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

    cache_reports = get_offline_dependency_cache_reports()
    print("-----------------------------------------------------------------")
    print("Offline Gradle Dependency Cache Status (read-only local inspection):")
    missing_cache = False
    for cache_item in cache_reports:
        cache_tag = "[OK]" if cache_item.is_available else "[NOT CACHED]"
        print(f"{cache_tag:<12} {cache_item.name}")
        if cache_item.is_available:
            print(f"             Status: {cache_item.version}")
        else:
            missing_cache = True
            if cache_item.target_version:
                print(f"             Target: {cache_item.target_version}")
            print(f"             Hint  : {cache_item.remediation_hint}")
    if missing_cache:
        print(
            "  Note : Host toolchain prerequisites are evaluated separately from the local Gradle dependency cache."
        )
        print(
            "         On a fresh environment without cached AGP/R8 artifacts, pass '--allow-network-dependencies'"
        )
        print("         on your first 'appshield protect' run.")
    print(
        "  Info : No local build history cache is stored; build validation runs live during 'appshield protect'."
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
    allow_production_signing: bool = False,
    allow_network_dependencies: bool = False,
    mapping_out: Path | None = None,
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
    if allow_network_dependencies:
        config.android.offline = False
        print(
            "  [NOTICE] Network dependency access explicitly authorized by developer (--allow-network-dependencies).\n"
            "           Gradle will resolve dependencies during this full protection build in the staging sandbox."
        )

    print(f"  - Project Name : {config.project_name}")
    print(f"  - Platform     : {config.platform}")
    print(f"  - Input Dir    : {config.input.project_dir}")
    print(f"  - Output Dir   : {config.output.dir}")

    # Validate target platform
    if config.platform != "android":
        print(
            f"Error: Platform '{config.platform}' is not supported yet (only 'android' is supported in v1).",
            file=sys.stderr,
        )
        return 1

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
        if mapping_out is not None:
            mapping_out_resolved = mapping_out.resolve()
            if mapping_out_resolved.exists() and not config.output.overwrite_existing:
                raise OverwriteError(
                    f"Destination mapping file already exists: '{mapping_out_resolved}'. "
                    "AppShield will not overwrite existing mapping files without authorization. "
                    "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
                )
            print(f"  - Mapping Out  : {mapping_out_resolved}")
        for report_name in ("audit_report.json", "audit_report.md"):
            rep_path = (config.output.dir / report_name).resolve()
            if rep_path.exists() and not config.output.overwrite_existing:
                raise OverwriteError(
                    f"Destination report file already exists: '{rep_path}'. "
                    "AppShield will not overwrite existing report files without authorization. "
                    "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
                )
    except OverwriteError as e:
        print(f"Overwrite Protection Error: {e}", file=sys.stderr)
        return 1

    # Check prerequisites via doctor checks
    doctor_res = cmd_doctor(config.input.project_dir)
    print("-----------------------------------------------------------------")
    if doctor_res != 0:
        print(
            "PREFLIGHT VALIDATION: FAILED (Missing environment prerequisites).",
            file=sys.stderr,
        )
        return doctor_res

    print("PREFLIGHT VALIDATION: SUCCESSFUL.")
    print("Starting Android Gradle + R8 protection workflow...")
    print("-----------------------------------------------------------------")

    adapter = AndroidPipelineAdapter()
    try:
        result = adapter.stage_and_protect(
            config=config,
            mapping_out=mapping_out,
            allow_production_signing=allow_production_signing,
        )
    except OverwriteError as e:
        print(f"Overwrite Protection Error: {e}", file=sys.stderr)
        return 1
    except (
        AppShieldError,
        GradleError,
        SigningError,
        DexError,
        MappingParseError,
    ) as e:
        print(f"Protection Error ({type(e).__name__}): {e}", file=sys.stderr)
        return 1

    for log_msg in result.logs:
        print(f"  [PIPELINE] {log_msg}")

    if result.verification_report is not None:
        print()
        print(format_report_terminal(result.verification_report))

    print("-----------------------------------------------------------------")
    if not result.success:
        err_msg = result.error_message or "Protection pipeline failed"
        print(f"Protection FAILED: {err_msg}", file=sys.stderr)
        return 1

    print(f"Protection SUCCEEDED: '{result.protected_artifact_path}'")
    if result.verification_report is not None:
        print(
            f"  - Code-Protection Verified   : {'YES' if result.verification_report.is_verified_protected else 'NO'}"
        )
        print(
            f"  - Android Installation Ready : {result.verification_report.installation_readiness_status}"
        )
    if result.audit_report_path:
        print(f"Audit Report: '{result.audit_report_path}'")
    return 0


def cmd_verify(
    artifact_path: Path,
    config_path: Path | None = None,
    mapping_file: Path | None = None,
    output_path: Path | None = None,
    overwrite: bool = False,
) -> int:
    """Handle `appshield verify` command."""
    print("AppShield Verify: Inspecting artifact and running objective checks...")
    print(f"Target Artifact: {artifact_path}")

    resolved_artifact = artifact_path.resolve()
    if not resolved_artifact.exists():
        print(
            f"Error: Target artifact not found: '{resolved_artifact}'",
            file=sys.stderr,
        )
        return 1

    if not resolved_artifact.is_file():
        print(
            f"Error: Target path is not a file: '{resolved_artifact}'",
            file=sys.stderr,
        )
        return 1

    resolved_mapping: Path | None = None
    if mapping_file is not None:
        resolved_mapping = mapping_file.resolve()
        if not resolved_mapping.exists():
            print(
                f"Error: Mapping file not found: '{resolved_mapping}'",
                file=sys.stderr,
            )
            return 1
        if not resolved_mapping.is_file():
            print(
                f"Error: Mapping path is not a file: '{resolved_mapping}'",
                file=sys.stderr,
            )
            return 1

    project_name = "AppShieldProject"
    signing_config = None
    verification_config: VerificationConfig | None = None
    if config_path is not None:
        try:
            cfg = load_config(config_path)
            project_name = cfg.project_name
            verification_config = cfg.verification
            if cfg.platform == "android" and cfg.android:
                signing_config = cfg.android.signing
        except ConfigError as e:
            print(f"Configuration Error: {e}", file=sys.stderr)
            return 1

    engine = VerificationEngine(project_name=project_name)
    try:
        report = engine.run_all_checks(
            apk_path=resolved_artifact,
            mapping_file=resolved_mapping,
            signing_config=signing_config,
            build_result=None,
            is_real_build=True,
            verification_config=verification_config,
        )
    except (
        AppShieldError,
        GradleError,
        SigningError,
        DexError,
        MappingParseError,
    ) as e:
        print(f"Verification Error ({type(e).__name__}): {e}", file=sys.stderr)
        return 1

    print()
    print(format_report_terminal(report))

    if output_path is not None:
        try:
            exported = export_report_json(
                report, output_path, allow_overwrite=overwrite
            )
            print(f"\nAudit report exported to: '{exported}'")
        except OverwriteError as e:
            print(f"Overwrite Protection Error: {e}", file=sys.stderr)
            return 1

    failed_count = report.summary.get("failed", 0)
    ver_enabled = (
        verification_config.enabled if verification_config is not None else True
    )
    fail_on_failure = (
        verification_config.fail_on_check_failure
        if verification_config is not None
        else True
    )

    if not report.is_verified_protected:
        if not ver_enabled:
            print(
                "\nNotice: Verification is disabled in configuration ('verification.enabled: false'); "
                "artifact is NOT designated as a verified protected release."
            )
        elif failed_count == 0:
            print(
                "\nNotice: Artifact inspection succeeded (0 check failures), but artifact is NOT "
                "designated as a verified protected release (requires all mandatory checks passing in an attached toolchain build session)."
            )
        else:
            print(f"\nVerification FAILED: {failed_count} objective check(s) failed.")
    else:
        print("\nVerified Protected Release: YES")

    print(f"Android Installation Ready: {report.installation_readiness_status}")

    if failed_count > 0 and fail_on_failure:
        return 1
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
            allow_production_signing=parsed_args.allow_production_signing,
            allow_network_dependencies=parsed_args.allow_network_dependencies,
            mapping_out=parsed_args.mapping_out,
        )
    elif parsed_args.command == "verify":
        return cmd_verify(
            artifact_path=parsed_args.artifact,
            config_path=parsed_args.config,
            mapping_file=parsed_args.mapping_file,
            output_path=parsed_args.output,
            overwrite=parsed_args.overwrite,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
