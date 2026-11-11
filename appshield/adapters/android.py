"""
AppShield Android Platform Adapter.
Implements project validation, release build configuration inspection,
toolchain prerequisite discovery, and safe R8 rule staging for Android Gradle projects.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
from pathlib import Path

from appshield.adapters.base import (
    AdapterError,
    PlatformAdapter,
    PrerequisiteCheck,
    ProjectInspection,
    ProtectionResult,
    RuleStagingError,
)
from appshield.config import (
    AppShieldConfig,
    ConfigValidationError,
    OverwriteError,
    SigningConfig,
    validate_android_release_task,
    validate_output_destination,
)
from appshield.dex import DexError
from appshield.doctor import run_doctor_checks
from appshield.gradle import (
    GradleError,
    GradleExecutionError,
    GradleRunner,
    GradleTimeoutError,
    locate_build_apk,
    locate_r8_mapping,
    redact_secrets,
    validate_apk_file,
)
from appshield.mapping import MappingParseError
from appshield.sandbox import (
    SandboxError,
    SandboxManager,
    SourceImmutabilityError,
)
from appshield.signing import SigningError, align_and_sign_apk
from appshield.verify import (
    VerificationEngine,
    export_report_json,
    format_report_markdown,
)

# Standard AppShield R8 hardening rules to inject into staging workspace
APPSHIELD_STANDARD_R8_RULES = """
# =================================================================
# AppShield Staged R8 Protection Rules
# Injected into staging workspace only; original rules preserved.
# =================================================================
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
-repackageclasses ''
-allowaccessmodification
"""

# Test symbols from controlled fixture that MUST NOT be kept by custom rules
FORBIDDEN_TEST_KEEP_PATTERNS = [
    "IdentifiableSecretService",
    "PaymentSecurityValidator",
    "processUserTokenAndCalculateHash",
    "calculateInternalSecurityChecksum",
    "validateTransactionToken",
]


def contains_unobfuscated_keep_directive(text: str, pattern: str) -> bool:
    """
    Check whether rules text contains a -keep directive for pattern that preserves original names.
    Directives specifying 'allowobfuscation' are permitted because they retain symbols for reachability
    while explicitly instructing R8 to obfuscate/rename them.
    """
    for line in text.splitlines():
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        if (
            re.search(r"-keep\b", line_clean, re.IGNORECASE)
            and pattern in line_clean
            and "allowobfuscation" not in line_clean.lower()
        ):
            return True
    return False


def contains_dontobfuscate_directive(text: str) -> bool:
    """
    Detect whether ProGuard/R8 rules contain an active '-dontobfuscate' directive.
    Ignores comments beginning with '#'.
    """
    for raw_line in text.splitlines():
        line_no_comment = raw_line.split("#", 1)[0].strip()
        if not line_no_comment:
            continue
        if re.search(r"(?:^|\s)-dontobfuscate(?:\s|$)", line_no_comment, re.IGNORECASE):
            return True
    return False


def contains_dontshrink_directive(text: str) -> bool:
    """Detect whether ProGuard/R8 rules contain an active '-dontshrink' directive."""
    for raw_line in text.splitlines():
        line_no_comment = raw_line.split("#", 1)[0].strip()
        if not line_no_comment:
            continue
        if re.search(r"(?:^|\s)-dontshrink(?:\s|$)", line_no_comment, re.IGNORECASE):
            return True
    return False


def extract_manifest_entry_points(
    project_dir: Path,
    module_name: str | None = None,
    build_file: Path | None = None,
) -> list[str]:
    """
    Extract Android application entry-point class names belonging to the project
    package/namespace from its source AndroidManifest.xml (e.g., activities, services).
    Returns fully-qualified class names when namespace/package can be resolved.
    Uses comment-stripped regex parsing to stay deterministic and dependency-free.
    """
    resolved = project_dir.resolve()
    candidates: list[Path] = []
    if module_name and module_name != "root":
        candidates.append(
            resolved / module_name / "src" / "main" / "AndroidManifest.xml"
        )
    candidates.append(resolved / "app" / "src" / "main" / "AndroidManifest.xml")
    candidates.append(resolved / "src" / "main" / "AndroidManifest.xml")

    manifest_path: Path | None = None
    for cand in candidates:
        if cand.is_file():
            manifest_path = cand
            break

    if manifest_path is None:
        return []

    raw_xml = manifest_path.read_text(encoding="utf-8", errors="replace")
    clean_xml = re.sub(r"<!--.*?-->", "", raw_xml, flags=re.DOTALL)

    base_package: str | None = None
    pkg_match = re.search(r"\bpackage\s*=\s*['\"]([^'\"]+)['\"]", clean_xml)
    if pkg_match:
        base_package = pkg_match.group(1).strip()

    app_id: str | None = None
    if build_file is not None and build_file.is_file():
        build_txt = build_file.read_text(encoding="utf-8", errors="replace")
        if base_package is None:
            ns_match = re.search(r"\bnamespace\s*=?\s*['\"]([^'\"]+)['\"]", build_txt)
            if ns_match:
                base_package = ns_match.group(1).strip()
        app_id_match = re.search(
            r"\bapplicationId\s*=?\s*['\"]([^'\"]+)['\"]", build_txt
        )
        if app_id_match:
            app_id = app_id_match.group(1).strip()
        if base_package is None:
            base_package = app_id

    tag_pattern = re.compile(
        r"<(application|activity|service|receiver|provider)\b([^>]*)>",
        re.IGNORECASE | re.DOTALL,
    )
    name_attr_pattern = re.compile(r"\bandroid:name\s*=\s*['\"]([^'\"]+)['\"]")

    entry_points: list[str] = []
    for _tag, attrs in tag_pattern.findall(clean_xml):
        m_name = name_attr_pattern.search(attrs)
        if not m_name:
            continue
        comp_name = m_name.group(1).strip()
        if "${applicationId}" in comp_name and (app_id or base_package):
            comp_name = comp_name.replace(
                "${applicationId}", app_id or base_package or ""
            )
        if not comp_name or "${" in comp_name:
            continue

        resolved_cls: str | None = None
        if comp_name.startswith("."):
            if base_package:
                resolved_cls = f"{base_package}{comp_name}"
        elif "." not in comp_name:
            if base_package:
                resolved_cls = f"{base_package}.{comp_name}"
        else:
            # Include fully qualified components belonging to this app's package/namespace
            # or if no base_package was detected, include non-AndroidX/platform classes
            if base_package:
                if comp_name == base_package or comp_name.startswith(
                    f"{base_package}."
                ):
                    resolved_cls = comp_name
            elif not comp_name.startswith(("android.", "androidx.")):
                resolved_cls = comp_name

        if resolved_cls and resolved_cls not in entry_points:
            entry_points.append(resolved_cls)

    return entry_points


def validate_prebuild_signing_config(
    signing_config: SigningConfig, allow_production_signing: bool
) -> list[str]:
    """Validate signing configuration and environment variables prior to build execution."""
    if not signing_config.enabled:
        return []

    errors: list[str] = []
    if signing_config.is_production and not allow_production_signing:
        errors.append(
            "Automatic production signing is blocked. Pass '--allow-production-signing' "
            "to explicitly authorize signing with a production keystore."
        )

    if signing_config.keystore_path is None:
        errors.append(
            "Signing is enabled ('android.signing.enabled: true') but 'keystore_path' is missing."
        )
    elif not signing_config.keystore_path.is_file():
        errors.append(
            f"Signing keystore file does not exist: '{signing_config.keystore_path}'."
        )

    if not signing_config.key_alias:
        errors.append(
            "Signing is enabled ('android.signing.enabled: true') but 'key_alias' is missing."
        )

    if not signing_config.keystore_password_env:
        errors.append(
            "Signing is enabled ('android.signing.enabled: true') but 'keystore_password_env' is missing."
        )
    elif not os.environ.get(signing_config.keystore_password_env):
        errors.append(
            f"Signing keystore password environment variable '{signing_config.keystore_password_env}' is not set or empty."
        )

    if signing_config.key_password_env and not os.environ.get(
        signing_config.key_password_env
    ):
        errors.append(
            f"Signing key password environment variable '{signing_config.key_password_env}' is not set or empty."
        )

    return errors


def extract_block(text: str, block_name: str) -> str | None:
    """
    Extract the content of a named curly-brace block: `block_name { ... }`.
    Handles arbitrary nested curly braces.
    """
    pattern = re.compile(rf"\b{re.escape(block_name)}\s*\{{", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return None
    start_idx = match.end() - 1  # index of '{'
    depth = 0
    end_idx = start_idx
    for i in range(start_idx, len(text)):
        char = text[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end_idx = i
                break
    if depth == 0:
        return text[start_idx + 1 : end_idx]
    return None


def extract_release_block(text: str) -> str | None:
    """
    Extract the release buildType block from Gradle build script content.
    Supports standard Groovy and Kotlin DSL block variants:
      - release { ... }
      - getByName("release") { ... }
      - named("release") { ... }
    """
    # 1. Search inside buildTypes { ... } if present
    build_types_content = extract_block(text, "buildTypes")
    target_text = build_types_content if build_types_content is not None else text

    # Direct 'release { ... }'
    direct = extract_block(target_text, "release")
    if direct is not None:
        return direct

    # Kotlin DSL 'getByName("release") { ... }'
    pattern_get = re.compile(
        r'getByName\s*\(\s*["\']release["\']\s*\)\s*\{', re.MULTILINE
    )
    match = pattern_get.search(target_text)
    if match:
        start_idx = match.end() - 1
        depth = 0
        for i in range(start_idx, len(target_text)):
            if target_text[i] == "{":
                depth += 1
            elif target_text[i] == "}":
                depth -= 1
                if depth == 0:
                    return target_text[start_idx + 1 : i]

    # Kotlin DSL 'named("release") { ... }'
    pattern_named = re.compile(
        r'named\s*\(\s*["\']release["\']\s*\)\s*\{', re.MULTILINE
    )
    match = pattern_named.search(target_text)
    if match:
        start_idx = match.end() - 1
        depth = 0
        for i in range(start_idx, len(target_text)):
            if target_text[i] == "{":
                depth += 1
            elif target_text[i] == "}":
                depth -= 1
                if depth == 0:
                    return target_text[start_idx + 1 : i]

    return None


def is_application_build_script(content: str) -> bool:
    """
    Check if a Gradle build script applies the 'com.android.application' plugin.
    Distinguishes active plugin application from 'apply false' declarations in root build files.
    """
    # Check for Groovy 'apply plugin: "com.android.application"'
    if re.search(r"apply\s+plugin:\s*['\"]com\.android\.application['\"]", content):
        return True

    # Check plugins { ... } block
    plugins_content = extract_block(content, "plugins")
    if plugins_content:
        for line in plugins_content.splitlines():
            line_clean = line.strip()
            if (
                "com.android.application" in line_clean
                and "apply false" not in line_clean
                and "apply(false)" not in line_clean
            ):
                return True
    return False


class AndroidPipelineAdapter(PlatformAdapter):
    """
    Adapter orchestrating Android Gradle projects and R8 code-protection.
    Enforces project validation, release minification verification,
    and safe rule staging within isolated sandboxes.
    """

    @property
    def platform_name(self) -> str:
        return "android"

    def validate_project(self, project_path: Path) -> ProjectInspection:
        """
        Validate that the target path is a supported Android Gradle project.
        Rejects arbitrary precompiled APKs and unsupported layouts.
        Inspects the release build configuration for R8 minification and rules.
        """
        resolved = project_path.resolve()
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Reject precompiled APK files or arbitrary binaries
        if resolved.suffix.lower() == ".apk":
            return ProjectInspection(
                is_supported=False,
                platform="android",
                project_type="unsupported_binary",
                module_name=None,
                build_file=None,
                rules_file=None,
                minify_enabled=False,
                shrink_resources=False,
                agp_version=None,
                compile_sdk=None,
                target_sdk=None,
                errors=[
                    (
                        "Arbitrary precompiled APK input is unsupported for R8 processing. "
                        "AppShield requires a supported Android Gradle project root."
                    )
                ],
                warnings=[],
            )

        # 2. Check directory existence and type
        if not resolved.exists():
            return ProjectInspection(
                is_supported=False,
                platform="android",
                project_type="unknown",
                module_name=None,
                build_file=None,
                rules_file=None,
                minify_enabled=False,
                shrink_resources=False,
                agp_version=None,
                compile_sdk=None,
                target_sdk=None,
                errors=[f"Project directory does not exist: '{resolved}'"],
                warnings=[],
            )

        if not resolved.is_dir():
            return ProjectInspection(
                is_supported=False,
                platform="android",
                project_type="unknown",
                module_name=None,
                build_file=None,
                rules_file=None,
                minify_enabled=False,
                shrink_resources=False,
                agp_version=None,
                compile_sdk=None,
                target_sdk=None,
                errors=[f"Project path is not a directory: '{resolved}'"],
                warnings=[],
            )

        # 3. Check for Gradle wrapper scripts
        has_gradlew = (resolved / "gradlew").is_file() or (
            resolved / "gradlew.bat"
        ).is_file()
        if not has_gradlew:
            errors.append(
                "Missing Gradle wrapper script ('gradlew' or 'gradlew.bat') in project root"
            )

        # 4. Check for Gradle settings file
        has_settings = (resolved / "settings.gradle").is_file() or (
            resolved / "settings.gradle.kts"
        ).is_file()
        if not has_settings:
            errors.append(
                "Missing Gradle settings file ('settings.gradle' or 'settings.gradle.kts')"
            )

        # 5. Locate application module and build script
        app_module: str | None = None
        build_file: Path | None = None
        module_dir: Path | None = None

        app_dir = resolved / "app"
        if app_dir.is_dir():
            if (app_dir / "build.gradle").is_file():
                app_module = "app"
                build_file = app_dir / "build.gradle"
                module_dir = app_dir
            elif (app_dir / "build.gradle.kts").is_file():
                app_module = "app"
                build_file = app_dir / "build.gradle.kts"
                module_dir = app_dir

        if build_file is None:
            # Check if root build file is a single-module Android project
            for root_cand in ["build.gradle", "build.gradle.kts"]:
                cand = resolved / root_cand
                if cand.is_file():
                    content = cand.read_text(encoding="utf-8", errors="replace")
                    if is_application_build_script(content):
                        app_module = "root"
                        build_file = cand
                        module_dir = resolved
                        break

        # Check for ambiguous multiple application modules if standard 'app' was not found
        if build_file is None:
            cand_modules: list[str] = []
            for child in resolved.iterdir():
                if child.is_dir() and not child.name.startswith("."):
                    for b_name in ["build.gradle", "build.gradle.kts"]:
                        b_cand = child / b_name
                        if b_cand.is_file():
                            b_text = b_cand.read_text(
                                encoding="utf-8", errors="replace"
                            )
                            if is_application_build_script(b_text):
                                cand_modules.append(child.name)
            if len(cand_modules) > 1:
                errors.append(
                    f"Ambiguous Android project layout: multiple application modules found ({', '.join(sorted(cand_modules))}). "
                    "Expected standard 'app' module."
                )
            elif len(cand_modules) == 1:
                mod_name = cand_modules[0]
                app_module = mod_name
                module_dir = resolved / mod_name
                build_file = (
                    module_dir / "build.gradle"
                    if (module_dir / "build.gradle").is_file()
                    else module_dir / "build.gradle.kts"
                )
            else:
                errors.append(
                    "Missing Android application build file ('app/build.gradle' or 'build.gradle' applying 'com.android.application')"
                )

        # 6. Parse and inspect application build file if found
        minify_enabled = False
        shrink_resources = False
        compile_sdk: int | None = None
        target_sdk: int | None = None
        rules_file: Path | None = None
        agp_version: str | None = None

        if build_file is not None and build_file.is_file():
            build_content = build_file.read_text(encoding="utf-8", errors="replace")

            # Extract compileSdk
            m_comp = re.search(r"\bcompileSdk(?:Version)?\s*=?\s*(\d+)", build_content)
            if m_comp:
                compile_sdk = int(m_comp.group(1))

            # Extract targetSdk
            m_target = re.search(r"\btargetSdk(?:Version)?\s*=?\s*(\d+)", build_content)
            if m_target:
                target_sdk = int(m_target.group(1))

            # Inspect release buildType block
            release_block = extract_release_block(build_content)
            if release_block is None:
                errors.append(
                    f"No 'release' buildType block found in '{build_file.relative_to(resolved)}'."
                )
            else:
                # Check minifyEnabled
                if re.search(
                    r"\b(?:minifyEnabled\s+true|isMinifyEnabled\s*=\s*true)\b",
                    release_block,
                ):
                    minify_enabled = True
                else:
                    errors.append(
                        f"Release buildType in '{build_file.relative_to(resolved)}' does not enable R8 code minification ('minifyEnabled true'). "
                        "AppShield requires code minification to be enabled for release builds."
                    )

                # Check shrinkResources
                if re.search(
                    r"\b(?:shrinkResources\s+true|isShrinkResources\s*=\s*true)\b",
                    release_block,
                ):
                    shrink_resources = True

                # Check configured ProGuard/R8 rules files
                # Match quoted file names ending in .pro
                pro_matches = re.findall(r"['\"]([^'\"]+\.pro)['\"]", release_block)
                if not pro_matches:
                    errors.append(
                        f"Release buildType in '{build_file.relative_to(resolved)}' does not configure a ProGuard/R8 rules file (e.g., 'proguard-rules.pro')."
                    )
                else:
                    target_dir = module_dir if module_dir is not None else resolved
                    for pro_name in pro_matches:
                        pro_cand = target_dir / pro_name
                        if pro_cand.is_file():
                            rules_file = pro_cand
                            break
                    if rules_file is None:
                        expected_cand = target_dir / pro_matches[0]
                        errors.append(
                            f"Configured ProGuard/R8 rules file does not exist: '{expected_cand.resolve()}'"
                        )
                    else:
                        rules_text = rules_file.read_text(
                            encoding="utf-8", errors="replace"
                        )
                        if contains_dontobfuscate_directive(rules_text):
                            errors.append(
                                f"Unsafe ProGuard/R8 rule '-dontobfuscate' detected in '{rules_file.relative_to(resolved)}'. "
                                "R8 symbol obfuscation is disabled; remove '-dontobfuscate' before running AppShield."
                            )
                        if contains_dontshrink_directive(rules_text):
                            warnings.append(
                                f"ProGuard/R8 rules file '{rules_file.relative_to(resolved)}' contains '-dontshrink'; "
                                "code shrinking may be reduced."
                            )

        # 7. Extract AGP version from root build.gradle or module build.gradle
        for cand_root in [
            resolved / "build.gradle",
            resolved / "build.gradle.kts",
            build_file,
        ]:
            if cand_root and cand_root.is_file():
                txt = cand_root.read_text(encoding="utf-8", errors="replace")
                m_agp = re.search(
                    r"['\"]com\.android\.application['\"]\s+version\s+['\"]([^'\"]+)['\"]",
                    txt,
                )
                if m_agp:
                    agp_version = m_agp.group(1)
                    break
                m_agp_alt = re.search(
                    r"id\s*\(?['\"]com\.android\.application['\"]\)?\s+version\s+['\"]([^'\"]+)['\"]",
                    txt,
                )
                if m_agp_alt:
                    agp_version = m_agp_alt.group(1)
                    break
                m_cp = re.search(r"com\.android\.tools\.build:gradle:([0-9.]+)", txt)
                if m_cp:
                    agp_version = m_cp.group(1)
                    break

        is_supported = len(errors) == 0

        return ProjectInspection(
            is_supported=is_supported,
            platform="android",
            project_type="gradle",
            module_name=app_module,
            build_file=build_file,
            rules_file=rules_file,
            minify_enabled=minify_enabled,
            shrink_resources=shrink_resources,
            agp_version=agp_version,
            compile_sdk=compile_sdk,
            target_sdk=target_sdk,
            errors=errors,
            warnings=warnings,
        )

    def check_prerequisites(
        self, project_path: Path | None = None
    ) -> list[PrerequisiteCheck]:
        """
        Inspect host environment and project prerequisites using doctor inspection.
        """
        reports = run_doctor_checks(project_path)
        checks: list[PrerequisiteCheck] = []
        for r in reports:
            checks.append(
                PrerequisiteCheck(
                    tool_name=r.name,
                    is_available=r.is_available,
                    detected_version=r.version,
                    target_version=r.target_version,
                    required=r.required,
                    remediation_hint=r.remediation_hint,
                    validated_live=r.validated_live,
                    path=r.path,
                )
            )
        return checks

    def stage_rules(
        self,
        staging_dir: Path,
        custom_rules: str | None = None,
        custom_rules_file: Path | None = None,
    ) -> Path:
        """
        Inject AppShield protection rules into the isolated staging copy's ProGuard/R8 rules file.
        Operates exclusively on files within staging_dir.
        Original project files are never touched.
        Fails clearly if the target rules file is missing or ambiguous.
        """
        staging_resolved = staging_dir.resolve()
        if not staging_resolved.exists() or not staging_resolved.is_dir():
            raise RuleStagingError(
                f"Staging directory does not exist or is not a directory: '{staging_resolved}'"
            )

        inspection = self.validate_project(staging_resolved)
        if not inspection.is_supported:
            raise RuleStagingError(
                f"Cannot stage rules: staging project validation failed: {'; '.join(inspection.errors)}"
            )

        target_rules_file = inspection.rules_file
        if target_rules_file is None or not target_rules_file.is_file():
            raise RuleStagingError(
                f"Cannot stage rules: no valid ProGuard/R8 rules file found in staging directory '{staging_resolved}'"
            )

        # Check custom rules for forbidden test keep patterns
        rules_to_append = [APPSHIELD_STANDARD_R8_RULES]

        if custom_rules_file is not None:
            custom_resolved = custom_rules_file.resolve()
            if not custom_resolved.is_file():
                raise RuleStagingError(
                    f"Configured custom R8 rules file does not exist: '{custom_resolved}'"
                )
            file_rules = custom_resolved.read_text(encoding="utf-8", errors="replace")
            if contains_dontobfuscate_directive(file_rules):
                raise RuleStagingError(
                    f"Custom rules file '{custom_resolved.name}' contains unsafe '-dontobfuscate' directive; "
                    "remove '-dontobfuscate' so R8 obfuscates symbols."
                )
            for pattern in FORBIDDEN_TEST_KEEP_PATTERNS:
                if contains_unobfuscated_keep_directive(file_rules, pattern):
                    raise RuleStagingError(
                        f"Custom rules file contains forbidden keep directive for test symbol '{pattern}' intended for obfuscation verification."
                    )
            rules_to_append.append(
                f"\n# --- User Custom Rules from {custom_rules_file.name} ---\n{file_rules}\n"
            )

        if custom_rules is not None:
            if contains_dontobfuscate_directive(custom_rules):
                raise RuleStagingError(
                    "Custom rules string contains unsafe '-dontobfuscate' directive; "
                    "remove '-dontobfuscate' so R8 obfuscates symbols."
                )
            for pattern in FORBIDDEN_TEST_KEEP_PATTERNS:
                if contains_unobfuscated_keep_directive(custom_rules, pattern):
                    raise RuleStagingError(
                        f"Custom rules string contains forbidden keep directive for test symbol '{pattern}' intended for obfuscation verification."
                    )
            rules_to_append.append(
                f"\n# --- User Inline Custom Rules ---\n{custom_rules}\n"
            )

        # Append rules safely to the staged rules file only
        existing_content = target_rules_file.read_text(
            encoding="utf-8", errors="replace"
        )
        new_content = existing_content + "\n" + "\n".join(rules_to_append) + "\n"
        target_rules_file.write_text(new_content, encoding="utf-8")

        return target_rules_file

    def stage_and_protect(
        self,
        config: AppShieldConfig,
        allow_production_signing: bool = False,
        runner: GradleRunner | None = None,
        allow_simulated: bool = False,
        mapping_out: Path | None = None,
        expected_fixture_classes: list[str] | None = None,
        expected_entry_points: list[str] | None = None,
    ) -> ProtectionResult:
        """
        Execute the full 16-step Android protection pipeline:
          1. Validate project layout and release build configuration.
          2. Check host toolchain prerequisites; halt safely if required tools are missing.
          3. Validate output destination overwrite guards.
          4. Create isolated staging workspace copy.
          5. Inject AppShield R8 protection rules into staging rules file.
          6. Execute release build task via GradleRunner in sandbox.
          7. Locate and validate the generated release APK.
          8. Locate and securely retain associated R8 mapping file.
          9. Align unsigned APK inside sandbox.
          10. Sign APK using explicitly configured test or production mode.
          11. Verify signature and alignment.
          12. Execute all 7 empirical verification checks.
          13. Generate and export audit_report.json and readable markdown summary.
          14. Verify original source tree immutability.
          15. Export protected artifact only when release acceptance conditions are met.
          16. Clean up staging files safely.
        """
        # 1. Validate project structure and release build configuration
        inspection = self.validate_project(config.input.project_dir)
        if not inspection.is_supported:
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=["Project validation failed."],
                error_message=f"Cannot protect project: {'; '.join(inspection.errors)}",
                metadata={"validation_errors": inspection.errors},
            )

        # 1b. Pre-build safety validation (task, variant, custom rules, signing config)
        try:
            validate_android_release_task(
                config.android.gradle_task, config.android.build_variant
            )
        except ConfigValidationError as e:
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=["Pre-build task configuration validation failed."],
                error_message=f"Pre-build configuration error: {e}",
                metadata={"error_type": "InvalidTaskConfiguration"},
            )

        if config.android.r8_rules_file is not None:
            custom_rules_path = config.android.r8_rules_file.resolve()
            if not custom_rules_path.is_file():
                return ProtectionResult(
                    success=False,
                    protected_artifact_path=None,
                    logs=["Pre-build R8 rules validation failed."],
                    error_message=(
                        f"Configured custom R8 rules file does not exist: '{custom_rules_path}'."
                    ),
                    metadata={"error_type": "MissingCustomRulesFile"},
                )
            custom_rules_text = custom_rules_path.read_text(
                encoding="utf-8", errors="replace"
            )
            if contains_dontobfuscate_directive(custom_rules_text):
                return ProtectionResult(
                    success=False,
                    protected_artifact_path=None,
                    logs=["Pre-build R8 rules validation failed."],
                    error_message=(
                        f"Unsafe ProGuard/R8 rule '-dontobfuscate' detected in custom rules file "
                        f"'{custom_rules_path}'. Remove '-dontobfuscate' before running AppShield."
                    ),
                    metadata={"error_type": "UnsafeProguardRules"},
                )

        signing_preflight_errors = validate_prebuild_signing_config(
            config.android.signing,
            allow_production_signing=allow_production_signing,
        )
        if signing_preflight_errors:
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=["Pre-build signing configuration validation failed."],
                error_message=(
                    "Signing configuration error:\n  - "
                    + "\n  - ".join(signing_preflight_errors)
                ),
                metadata={"error_type": "SigningConfigurationError"},
            )

        # 2. Check prerequisites if running with default runner
        if runner is None:
            checks = self.check_prerequisites(config.input.project_dir)
            missing = [c for c in checks if c.required and not c.is_available]
            if missing:
                error_lines = [
                    f"  - {c.tool_name}: {c.remediation_hint}" for c in missing
                ]
                return ProtectionResult(
                    success=False,
                    protected_artifact_path=None,
                    logs=[
                        f"Prerequisite check failed: {len(missing)} required toolchain dependencies missing."
                    ],
                    error_message=(
                        "Cannot proceed with Android protection: missing required toolchain prerequisites:\n"
                        + "\n".join(error_lines)
                    ),
                    metadata={"missing_dependencies": [c.tool_name for c in missing]},
                )

        # 3. Validate output destination overwrite safeguards
        module_name = (
            inspection.module_name
            or getattr(config.android, "module_name", None)
            or "app"
        )
        target_filename = (
            f"{config.project_name}-{config.android.build_variant}-protected.apk"
        )
        validate_output_destination(
            output_dir=config.output.dir,
            artifact_name=target_filename,
            allow_overwrite=config.output.overwrite_existing,
        )
        if mapping_out is not None:
            mapping_out_path = mapping_out.resolve()
            if mapping_out_path.exists() and not config.output.overwrite_existing:
                raise OverwriteError(
                    f"Destination mapping file already exists: '{mapping_out_path}'. "
                    "AppShield will not overwrite existing mapping files without authorization. "
                    "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
                )
        for report_name in ("audit_report.json", "audit_report.md"):
            rep_path = (config.output.dir / report_name).resolve()
            if rep_path.exists() and not config.output.overwrite_existing:
                raise OverwriteError(
                    f"Destination report file already exists: '{rep_path}'. "
                    "AppShield will not overwrite existing report files without authorization. "
                    "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
                )

        # 4. Strict simulation barrier
        if (
            runner is not None
            and getattr(runner, "is_simulated", False) is True
            and not allow_simulated
        ):
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=["Simulated runner rejected."],
                error_message=(
                    "Simulated execution is forbidden in production protection workflows. "
                    "A real toolchain execution is required."
                ),
                metadata={"is_simulated": "True"},
            )

        logs: list[str] = [
            "Starting Android Gradle protection pipeline in isolated staging sandbox."
        ]

        secrets_to_redact: list[str] = []
        for env_name in (
            config.android.signing.keystore_password_env,
            config.android.signing.key_password_env,
        ):
            if env_name:
                val = os.environ.get(env_name, "")
                if val:
                    secrets_to_redact.append(val)

        # 5. Isolated Staging Sandbox with structured operational error handling
        sandbox = SandboxManager(
            source_dir=config.input.project_dir,
            exclude_patterns=config.input.exclude_patterns,
            immutability_exclude_patterns=config.input.immutability_exclude_patterns,
        )

        try:
            with sandbox:
                staging_dir = sandbox.staging_dir
                logs.append(f"Project staged in ephemeral sandbox: '{staging_dir}'")

                # 6. Inject R8 protection rules into staging workspace
                staged_rules_file = self.stage_rules(
                    staging_dir=staging_dir,
                    custom_rules_file=config.android.r8_rules_file,
                )
                logs.append(
                    f"Injected AppShield R8 protection rules into '{staged_rules_file.name}'"
                )

                # 7. Execute Gradle build inside staging sandbox
                if runner is not None:
                    active_runner = runner
                    if hasattr(active_runner, "project_dir"):
                        active_runner.project_dir = staging_dir
                else:
                    active_runner = GradleRunner(
                        project_dir=staging_dir,
                        timeout_seconds=300.0,
                        offline=config.android.offline,
                        no_daemon=True,
                        secrets_to_redact=secrets_to_redact,
                    )

                if not config.android.offline:
                    logs.append(
                        "Network dependency resolution EXPLICITLY AUTHORIZED for this build. Operating in staging sandbox."
                    )
                else:
                    logs.append(
                        "Offline mode enforced (--offline). Using local Gradle and Android dependency cache."
                    )

                build_res = active_runner.run_task(config.android.gradle_task)
                if not build_res.success:
                    err_diag = redact_secrets(
                        build_res.stderr or build_res.stdout or "Unknown build error",
                        secrets_to_redact,
                    )
                    hint = ""
                    if config.android.offline and any(
                        tok in err_diag.lower()
                        for tok in (
                            "not found in any of the following sources",
                            "no cached version",
                            "--offline",
                            "could not resolve",
                        )
                    ):
                        hint = (
                            "\nRemediation: Missing offline Gradle dependencies detected. "
                            "Re-run with '--allow-network-dependencies' once to populate the local Gradle cache."
                        )
                    logs.append(
                        f"Gradle task '{config.android.gradle_task}' failed with exit code {build_res.exit_code}."
                    )
                    return ProtectionResult(
                        success=False,
                        protected_artifact_path=None,
                        logs=logs,
                        error_message=(
                            f"Gradle build task '{config.android.gradle_task}' failed "
                            f"(exit code {build_res.exit_code}): {err_diag}{hint}"
                        ),
                        metadata={
                            "error_type": "GradleExecutionError",
                            "exit_code": str(build_res.exit_code),
                            "is_simulated": str(build_res.is_simulated),
                        },
                    )

                logs.append(
                    f"Gradle task '{config.android.gradle_task}' succeeded in {build_res.duration_seconds:.2f}s."
                )

                # 8. Locate built APK artifact and validate
                raw_apk = locate_build_apk(
                    staging_dir=staging_dir,
                    module_name=module_name,
                    build_variant=config.android.build_variant,
                )
                validate_apk_file(raw_apk)
                logs.append(f"Located and validated release APK: '{raw_apk.name}'")

                # 9. Locate R8 mapping file and securely retain if requested
                mapping_file = locate_r8_mapping(
                    staging_dir=staging_dir,
                    module_name=module_name,
                    build_variant=config.android.build_variant,
                )
                if mapping_file is None:
                    logs.append(
                        f"R8 mapping file was not generated for module '{module_name}' variant '{config.android.build_variant}'."
                    )
                    return ProtectionResult(
                        success=False,
                        protected_artifact_path=None,
                        logs=logs,
                        error_message=(
                            f"Expected R8 obfuscation mapping file (mapping.txt) was not generated for module "
                            f"'{module_name}' variant '{config.android.build_variant}'. Ensure R8 minification is active "
                            "(minifyEnabled true) and '-dontobfuscate' is not disabling mapping output."
                        ),
                        metadata={"error_type": "MissingMappingFile"},
                    )

                logs.append(f"Located R8 mapping file: '{mapping_file.name}'")
                if mapping_out is not None:
                    mapping_out_path = mapping_out.resolve()
                    if (
                        mapping_out_path.exists()
                        and not config.output.overwrite_existing
                    ):
                        raise OverwriteError(
                            f"Destination mapping file already exists: '{mapping_out_path}'. "
                            "AppShield will not overwrite existing mapping files without authorization. "
                            "Use '--overwrite' or set 'output.overwrite_existing: true' to permit overwriting."
                        )
                    mapping_out_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(mapping_file, mapping_out_path)
                    logs.append(
                        f"Securely retained R8 mapping file to '{mapping_out_path}'"
                    )

                # 10. Align and sign within staging sandbox
                signing_res = align_and_sign_apk(
                    unsigned_apk=raw_apk,
                    output_dir=staging_dir / "appshield_signing_temp",
                    signing_config=config.android.signing,
                    allow_production_signing=allow_production_signing,
                    overwrite=True,
                )
                logs.append(
                    f"Alignment and signing completed: signature_type='{signing_res.signature_type}'"
                )

                # Associate build result with the final aligned/signed APK for verification evidence
                build_res = dataclasses.replace(
                    build_res,
                    apk_path=signing_res.final_apk_path,
                    mapping_file=mapping_file or build_res.mapping_file,
                )

                # 11. Execute configured empirical verification checks
                engine = VerificationEngine(project_name=config.project_name)
                if expected_entry_points is not None:
                    entries = expected_entry_points
                else:
                    entries = extract_manifest_entry_points(
                        project_dir=staging_dir,
                        module_name=module_name,
                        build_file=inspection.build_file,
                    )

                verification_report = engine.run_all_checks(
                    apk_path=signing_res.final_apk_path,
                    mapping_file=mapping_file,
                    signing_config=config.android.signing,
                    build_result=build_res,
                    is_real_build=not build_res.is_simulated,
                    expected_fixture_classes=expected_fixture_classes,
                    expected_entry_points=entries,
                    verification_config=config.verification,
                )

                # 12. Generate and export audit reports
                audit_report_dest = config.output.dir / "audit_report.json"
                audit_report_dest.parent.mkdir(parents=True, exist_ok=True)
                export_report_json(
                    verification_report,
                    audit_report_dest,
                    allow_overwrite=config.output.overwrite_existing,
                )
                logs.append(
                    f"Generated verification audit report: '{audit_report_dest}'"
                )

                audit_md_dest = config.output.dir / "audit_report.md"
                audit_md_dest.write_text(
                    format_report_markdown(verification_report), encoding="utf-8"
                )

                # 13. Verify original source tree immutability
                if config.input.verify_source_immutability:
                    sandbox.verify_source_integrity()
                    logs.append(
                        "Verified original source tree immutability (SHA-256 matches pre-build state)."
                    )

                # 14. Release Acceptance & Simulation Barrier:
                # Simulation/mocked execution is NEVER exported as a protected release
                if build_res.is_simulated:
                    logs.append(
                        "Simulation mode: Artifact export to production directory suppressed."
                    )
                    return ProtectionResult(
                        success=False,
                        protected_artifact_path=None,
                        logs=logs,
                        error_message=(
                            "Simulated build artifacts are strictly prohibited from being exported as protected releases."
                        ),
                        metadata={
                            "signature_type": signing_res.signature_type,
                            "is_aligned": str(signing_res.is_aligned),
                            "is_verified_protected": "False",
                            "is_simulated": "True",
                        },
                        verification_report=verification_report,
                        audit_report_path=audit_report_dest,
                        is_verified_protected=False,
                    )

                # Protected release acceptance criteria
                is_acceptable = verification_report.is_verified_protected
                exported_path = None
                if is_acceptable:
                    rel_signed_apk = signing_res.final_apk_path.relative_to(staging_dir)
                    exported_path = sandbox.export_artifact(
                        staged_relative_path=rel_signed_apk,
                        output_dir=config.output.dir,
                        target_filename=target_filename,
                        allow_overwrite=config.output.overwrite_existing,
                    )
                    logs.append(
                        f"Exported verified protected artifact to '{exported_path}'"
                    )
                else:
                    logs.append(
                        "Release acceptance failed: artifact did not meet all verified-protected criteria."
                    )
                    if config.verification.fail_on_check_failure:
                        return ProtectionResult(
                            success=False,
                            protected_artifact_path=None,
                            logs=logs,
                            error_message=(
                                "Protection verification failed: artifact did not meet all verified-protected criteria."
                            ),
                            metadata={
                                "signature_type": signing_res.signature_type,
                                "is_aligned": str(signing_res.is_aligned),
                                "is_verified_protected": "False",
                                "is_simulated": "False",
                            },
                            verification_report=verification_report,
                            audit_report_path=audit_report_dest,
                            is_verified_protected=False,
                        )

                return ProtectionResult(
                    success=is_acceptable,
                    protected_artifact_path=exported_path,
                    logs=logs,
                    error_message=(
                        None
                        if is_acceptable
                        else "Artifact was not verified as protected."
                    ),
                    metadata={
                        "signature_type": signing_res.signature_type,
                        "is_aligned": str(signing_res.is_aligned),
                        "r8_mapping_found": str(mapping_file is not None),
                        "r8_mapping_path": str(mapping_file) if mapping_file else "",
                        "is_verified_protected": str(
                            verification_report.is_verified_protected
                        ),
                        "is_simulated": "False",
                    },
                    verification_report=verification_report,
                    audit_report_path=audit_report_dest,
                    is_verified_protected=verification_report.is_verified_protected,
                )
        except (OverwriteError, SourceImmutabilityError):
            raise
        except GradleTimeoutError as e:
            err_msg = redact_secrets(str(e), secrets_to_redact)
            logs.append(f"Gradle build timed out after {e.timeout_seconds:.1f}s.")
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=logs,
                error_message=err_msg,
                metadata={
                    "error_type": "GradleTimeoutError",
                    "timeout_seconds": str(e.timeout_seconds),
                },
            )
        except GradleExecutionError as e:
            err_msg = redact_secrets(str(e), secrets_to_redact)
            if config.android.offline and any(
                tok in (err_msg + "\n" + e.stderr).lower()
                for tok in (
                    "not found in any of the following sources",
                    "no cached version",
                    "--offline",
                    "could not resolve",
                )
            ):
                err_msg += (
                    "\nRemediation: Missing offline Gradle dependencies detected. "
                    "Re-run with '--allow-network-dependencies' once to populate the local Gradle cache."
                )
            logs.append(f"Gradle build failed with exit code {e.exit_code}.")
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=logs,
                error_message=err_msg,
                metadata={
                    "error_type": "GradleExecutionError",
                    "exit_code": str(e.exit_code),
                },
            )
        except (
            GradleError,
            SigningError,
            AdapterError,
            DexError,
            MappingParseError,
            SandboxError,
            ConfigValidationError,
            OSError,
        ) as e:
            err_msg = redact_secrets(str(e), secrets_to_redact)
            logs.append(f"Pipeline error ({type(e).__name__}): {err_msg}")
            return ProtectionResult(
                success=False,
                protected_artifact_path=None,
                logs=logs,
                error_message=err_msg,
                metadata={"error_type": type(e).__name__},
            )
