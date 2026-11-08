"""
AppShield Empirical Verification Engine.
Executes objective empirical checks (symbols, strings, structure, signatures, alignment)
against Android APK binaries and R8 mapping files.
Generates deterministic, auditable audit reports without composite resistance scores.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from appshield.config import OverwriteError, SigningConfig
from appshield.dex import ApkDexSummary, DexError, class_to_descriptor, inspect_apk_dex
from appshield.gradle import GradleBuildResult
from appshield.mapping import MappingParseError, R8MappingSummary, parse_r8_mapping
from appshield.signing import (
    find_apksigner,
    find_zipalign,
    verify_apk_signature,
    verify_zipalign,
)

OutcomeType = Literal["VERIFIED", "HEURISTIC", "INFORMATIONAL", "FAILED", "UNSUPPORTED"]
StatusType = Literal["PASS", "FAIL", "SKIPPED", "INFO", "INCONCLUSIVE"]

STANDARD_DISCLAIMER = (
    "All measurements represent empirical evidence from automated static checks. "
    "A high renaming ratio or clean string scan increases reverse-engineering work factors, "
    "but does NOT prove the binary is impossible to reverse engineer. "
    "Reverse engineering of client-side code running on user-controlled devices remains possible."
)

DEFAULT_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    (
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "PEM Private Key Header",
    ),
    (re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"), "GitHub Personal Access Token"),
    (
        re.compile(
            r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
        ),
        "JSON Web Token (JWT)",
    ),
]

FIXTURE_TEST_STRINGS = [
    "APP_SHIELD_TEST_STRING_LITERAL_XYZ",
    "DISPOSABLE_TEST_PAYMENT_SECRET_TOKEN",
    "NON_SENSITIVE_VALIDATION_SCHEME_V1",
]


@dataclass(frozen=True)
class ObjectiveCheckResult:
    """Detailed result of a single empirical verification check."""

    check_id: str
    name: str
    category: str
    outcome: OutcomeType
    status: StatusType
    what_it_proves: str
    what_it_does_not_prove: str
    observed_metric: str
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None


@dataclass(frozen=True)
class VerificationReport:
    """Structured, reproducible verification audit report."""

    audit_version: str
    project_name: str
    generated_at: str
    artifact: dict[str, Any]
    summary: dict[str, int]
    objective_checks: list[ObjectiveCheckResult]
    is_verified_protected: bool
    disclaimer: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "project_name": self.project_name,
            "generated_at": self.generated_at,
            "artifact": self.artifact,
            "summary": self.summary,
            "is_verified_protected": self.is_verified_protected,
            "objective_checks": [asdict(c) for c in self.objective_checks],
            "disclaimer": self.disclaimer,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class VerificationEngine:
    """
    Executes the suite of 7 objective empirical verification checks
    against an Android APK artifact, mapping file, and build context.
    """

    def __init__(
        self,
        project_name: str = "appshield_project",
        sensitive_patterns: list[tuple[re.Pattern[str], str]] | None = None,
        fixture_tokens: list[str] | None = None,
    ) -> None:
        self.project_name = project_name
        self.sensitive_patterns = (
            sensitive_patterns
            if sensitive_patterns is not None
            else list(DEFAULT_SENSITIVE_PATTERNS)
        )
        self.fixture_tokens = (
            fixture_tokens if fixture_tokens is not None else list(FIXTURE_TEST_STRINGS)
        )

    def check_bld_01(
        self,
        build_result: GradleBuildResult | None,
        is_real_build: bool,
        evidence_errors: list[str] | None = None,
    ) -> ObjectiveCheckResult:
        """
        CHK-BLD-01: Actual build completion.
        Verifies that an actual build toolchain executed and completed successfully,
        and that build evidence (APK and mapping artifacts) is consistent.
        """
        proves = "Proves that the build toolchain executed and exited successfully with return code 0."
        does_not_prove = (
            "Does not prove the resulting artifact is secure, obfuscated, or bug-free."
        )

        if evidence_errors:
            return ObjectiveCheckResult(
                check_id="CHK-BLD-01",
                name="Actual Build Completion",
                category="build",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"Inconsistent build evidence: {'; '.join(evidence_errors)}",
                details={"evidence_errors": evidence_errors},
                recommendation="Ensure the mapping file and APK belong to the exact same build session.",
            )

        if build_result is None:
            return ObjectiveCheckResult(
                check_id="CHK-BLD-01",
                name="Actual Build Completion",
                category="build",
                outcome="INFORMATIONAL",
                status="INFO",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="External or pre-existing build artifact inspected (no direct build session attached)",
                details={"has_build_result": False, "is_real_build": is_real_build},
            )

        if not is_real_build or build_result.is_simulated:
            return ObjectiveCheckResult(
                check_id="CHK-BLD-01",
                name="Actual Build Completion",
                category="build",
                outcome="INFORMATIONAL",
                status="INFO",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="Build was simulated or executed under test harness (not a real production toolchain run)",
                details={
                    "is_simulated": True,
                    "exit_code": build_result.exit_code,
                    "duration_seconds": build_result.duration_seconds,
                },
                recommendation="A real Android toolchain execution (JDK 17 + AGP + SDK) is required for protected release verification.",
            )

        if build_result.success and build_result.exit_code == 0:
            return ObjectiveCheckResult(
                check_id="CHK-BLD-01",
                name="Actual Build Completion",
                category="build",
                outcome="VERIFIED",
                status="PASS",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"Real build succeeded in {build_result.duration_seconds:.2f}s (exit code 0)",
                details={
                    "exit_code": 0,
                    "duration_seconds": build_result.duration_seconds,
                    "command": build_result.command[:3],
                },
            )

        return ObjectiveCheckResult(
            check_id="CHK-BLD-01",
            name="Actual Build Completion",
            category="build",
            outcome="FAILED",
            status="FAIL",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=f"Build failed with exit code {build_result.exit_code}",
            details={"exit_code": build_result.exit_code},
            recommendation="Inspect Gradle build logs and fix compilation or packaging errors.",
        )

    def check_apk_01(
        self, apk_path: Path, dex_summary: ApkDexSummary | None
    ) -> ObjectiveCheckResult:
        """
        CHK-APK-01: APK structure and DEX validity.
        Verifies archive packaging and valid Dalvik Executable byte streams.
        """
        proves = "Proves that the APK is a structurally valid Android package archive containing parseable DEX bytecode."
        does_not_prove = "Does not prove the application bytecode is obfuscated, resilient, or bug-free."

        if not apk_path.is_file():
            return ObjectiveCheckResult(
                check_id="CHK-APK-01",
                name="APK Structure and DEX Validity",
                category="structure",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="Target APK file does not exist on disk",
                details={"path": str(apk_path)},
            )

        if dex_summary is None or dex_summary.errors:
            err_msg = (
                "; ".join(dex_summary.errors)
                if dex_summary
                else "Failed to read DEX tables"
            )
            return ObjectiveCheckResult(
                check_id="CHK-APK-01",
                name="APK Structure and DEX Validity",
                category="structure",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"APK structure or DEX verification failed: {err_msg}",
                details={"errors": dex_summary.errors if dex_summary else []},
                recommendation="Ensure the APK is an uncorrupted Android package produced by a valid build toolchain.",
            )

        if dex_summary.dex_files_count == 0:
            return ObjectiveCheckResult(
                check_id="CHK-APK-01",
                name="APK Structure and DEX Validity",
                category="structure",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="No classes.dex files found in APK archive",
                details={},
                recommendation="The APK does not contain DEX executable bytecode.",
            )

        metric = (
            f"Valid APK archive with {dex_summary.dex_files_count} DEX file(s) "
            f"({dex_summary.total_classes_count} classes, {dex_summary.total_strings_count} strings)"
        )
        return ObjectiveCheckResult(
            check_id="CHK-APK-01",
            name="APK Structure and DEX Validity",
            category="structure",
            outcome="VERIFIED",
            status="PASS",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=metric,
            details={
                "dex_files_count": dex_summary.dex_files_count,
                "dex_names": dex_summary.dex_names,
                "total_classes": dex_summary.total_classes_count,
                "total_strings": dex_summary.total_strings_count,
            },
        )

    def check_sym_01(
        self,
        dex_summary: ApkDexSummary | None,
        mapping: R8MappingSummary | None,
        expected_fixture_classes: list[str] | None = None,
        expected_entry_points: list[str] | None = None,
    ) -> ObjectiveCheckResult:
        """
        CHK-SYM-01: Dual-evidence symbol verification.
        Verifies both mapping.txt and compiled DEX class definitions.
        Ensures expected classes were renamed and their mapped descriptors exist in DEX bytecode.
        """
        proves = (
            "Direct evidence that identified class descriptors were renamed: confirms that target class symbols "
            "were renamed in R8 mapping.txt and their mapped obfuscated descriptors exist in compiled DEX class_defs "
            "while original descriptors are absent, and entry points remain retained."
        )
        does_not_prove = (
            "Does NOT prove that reverse engineering is impossible or that the entire application cannot be analyzed. "
            "The broader inference that obfuscation increases reverse-engineering work factors is HEURISTIC. "
            "Verifying that specific class descriptors were renamed provides direct evidence of symbol renaming "
            "for those classes only, not proof of complete application protection or control-flow resistance."
        )

        if mapping is None:
            return ObjectiveCheckResult(
                check_id="CHK-SYM-01",
                name="Dual-Evidence Symbol Verification",
                category="symbols",
                outcome="UNSUPPORTED",
                status="SKIPPED",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="R8 mapping file not provided or unavailable for dual-evidence verification",
                details={"mapping_available": False},
                recommendation="Provide the R8 mapping.txt generated during release compilation.",
            )

        if dex_summary is None or dex_summary.dex_files_count == 0:
            return ObjectiveCheckResult(
                check_id="CHK-SYM-01",
                name="Dual-Evidence Symbol Verification",
                category="symbols",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="Cannot perform symbol verification: DEX bytecode unavailable",
                details={},
            )

        dex_descriptors = set(dex_summary.unique_class_descriptors)

        # 1. Evaluate aggregate class renaming ratio
        ratio_pct = mapping.class_renaming_ratio * 100.0
        discrepancies: list[str] = []

        # 2. Dual-evidence verification for fixture classes
        fixture_classes = expected_fixture_classes or []
        verified_obfuscated_count = 0
        missing_retained_count = 0

        for full_or_simple_name in fixture_classes:
            # Find class mapping by exact name or substring suffix
            target_mapping = None
            for orig_name, cls_map in mapping.classes.items():
                if orig_name == full_or_simple_name or orig_name.endswith(
                    f".{full_or_simple_name}"
                ):
                    target_mapping = cls_map
                    break

            if target_mapping is None:
                discrepancies.append(
                    f"Expected class '{full_or_simple_name}' was not found in R8 mapping.txt."
                )
                continue

            orig_desc = class_to_descriptor(target_mapping.original_name)
            obf_desc = class_to_descriptor(target_mapping.obfuscated_name)

            # Check 1: Was it renamed in mapping?
            if not target_mapping.is_renamed:
                discrepancies.append(
                    f"Class '{target_mapping.original_name}' was kept unrenamed in mapping.txt."
                )
                continue

            # Check 2: Original descriptor MUST NOT exist in DEX
            if orig_desc in dex_descriptors:
                discrepancies.append(
                    f"Original un-obfuscated descriptor '{orig_desc}' still present in DEX class_defs!"
                )
                continue

            # Check 3: Mapped obfuscated descriptor MUST exist in DEX
            if obf_desc in dex_descriptors:
                verified_obfuscated_count += 1
            else:
                # Do NOT mistake stripped/unreachable classes for obfuscation
                missing_retained_count += 1
                discrepancies.append(
                    f"Class '{target_mapping.original_name}' is not retained in compiled DEX "
                    f"(neither original nor mapped descriptor '{obf_desc}' found in DEX class_defs)."
                )

        # 3. Check entry points (e.g. MainActivity)
        entry_points = expected_entry_points or []
        for ep in entry_points:
            ep_desc = class_to_descriptor(ep)
            # Find entry point in mapping
            ep_mapping = None
            for orig_name, cls_map in mapping.classes.items():
                if orig_name == ep or orig_name.endswith(f".{ep}"):
                    ep_mapping = cls_map
                    break

            target_desc = (
                class_to_descriptor(ep_mapping.obfuscated_name)
                if ep_mapping
                else ep_desc
            )
            if target_desc not in dex_descriptors:
                discrepancies.append(
                    f"Required application entry point '{ep}' is missing from DEX bytecode!"
                )

        status: StatusType = "PASS"
        outcome: OutcomeType = "VERIFIED"

        if discrepancies:
            status = "FAIL"
            outcome = "FAILED"
            observed = (
                f"{len(discrepancies)} symbol verification discrepancy(ies) detected; "
                f"renaming ratio: {ratio_pct:.1f}%"
            )
        else:
            observed = (
                f"Direct descriptor renaming verified: {ratio_pct:.1f}% classes renamed "
                f"({mapping.renamed_classes_count}/{mapping.total_classes} in mapping); "
                f"{verified_obfuscated_count} fixture symbol(s) confirmed renamed and present in DEX "
                "(heuristic inference: symbol renaming raises reverse-engineering work factor)"
            )

        return ObjectiveCheckResult(
            check_id="CHK-SYM-01",
            name="Dual-Evidence Symbol Verification",
            category="symbols",
            outcome=outcome,
            status=status,
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=observed,
            details={
                "evidence_classification": "VERIFIED (direct descriptor and mapping match)",
                "security_inference": "HEURISTIC (renaming symbols increases reverse-engineering work factor but does not prevent decompilation or logic analysis)",
                "total_mapping_classes": mapping.total_classes,
                "renamed_mapping_classes": mapping.renamed_classes_count,
                "renaming_ratio": round(mapping.class_renaming_ratio, 4),
                "total_mapping_methods": mapping.total_methods,
                "renamed_mapping_methods": mapping.renamed_methods_count,
                "fixture_classes_checked": len(fixture_classes),
                "fixture_classes_verified": verified_obfuscated_count,
                "fixture_classes_missing": missing_retained_count,
                "discrepancies_count": len(discrepancies),
                "has_discrepancies": bool(discrepancies),
            },
            recommendation=(
                "Check ProGuard/R8 keep rules to ensure identifiable classes are not preserved, "
                "and ensure test classes are referenced so they are not eliminated as dead code."
                if discrepancies
                else None
            ),
        )

    def check_sig_01(
        self, apk_path: Path, signing_config: SigningConfig | None
    ) -> ObjectiveCheckResult:
        """
        CHK-SIG-01: Cryptographic signature verification.
        Verifies signature schemes v1, v2, v3, and v4 using apksigner.
        """
        proves = (
            "Proves that the APK contains a cryptographically valid, untampered signature under "
            "Android APK Signature Schemes (v1, v2, v3, and/or v4)."
        )
        does_not_prove = (
            "Does not prove the application code is secure, trustworthy, or bug-free."
        )

        if signing_config is None or not signing_config.enabled:
            return ObjectiveCheckResult(
                check_id="CHK-SIG-01",
                name="Cryptographic Signature Verification",
                category="signature",
                outcome="UNSUPPORTED",
                status="SKIPPED",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="Signing disabled in configuration (artifact is unsigned)",
                details={"signing_enabled": False},
                recommendation="Enable signing in appshield.yaml to verify cryptographic signature integrity.",
            )

        apksigner_bin = find_apksigner()
        if apksigner_bin is None:
            return ObjectiveCheckResult(
                check_id="CHK-SIG-01",
                name="Cryptographic Signature Verification",
                category="signature",
                outcome="UNSUPPORTED",
                status="SKIPPED",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="apksigner tool not found on PATH or in ANDROID_HOME/build-tools",
                details={"apksigner_found": False},
                recommendation="Install Android SDK Build-Tools to verify APK signatures.",
            )

        sig_res = verify_apk_signature(apk_path, apksigner_path=apksigner_bin)

        if not sig_res.is_valid:
            err_summary = "; ".join(sig_res.errors) or "Invalid signature"
            return ObjectiveCheckResult(
                check_id="CHK-SIG-01",
                name="Cryptographic Signature Verification",
                category="signature",
                outcome="FAILED",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"Signature verification failed: {err_summary}",
                details={"errors": sig_res.errors},
                recommendation="Ensure the APK was properly signed with apksigner without subsequent modifications.",
            )

        schemes: list[str] = []
        if sig_res.v1_scheme_signed:
            schemes.append("v1")
        if sig_res.v2_scheme_signed:
            schemes.append("v2")
        if sig_res.v3_scheme_signed:
            schemes.append("v3")
        if sig_res.v4_scheme_signed:
            schemes.append("v4")

        signer_dn = sig_res.signer_certificate_dn or "Unknown"
        sig_label = "production" if signing_config.is_production else "test"
        observed = f"Cryptographically verified valid ({sig_label}-signed, schemes: {', '.join(schemes)})"

        return ObjectiveCheckResult(
            check_id="CHK-SIG-01",
            name="Cryptographic Signature Verification",
            category="signature",
            outcome="VERIFIED",
            status="PASS",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=observed,
            details={
                "schemes": schemes,
                "signer_dn": signer_dn,
                "is_production": signing_config.is_production,
            },
        )

    def check_aln_01(self, apk_path: Path) -> ObjectiveCheckResult:
        """
        CHK-ALN-01: Zip alignment verification.
        Verifies 4-byte page alignment using zipalign without modifying the artifact.
        """
        proves = "Proves that uncompressed archive entries start at 4-byte boundaries suitable for Android OS mmap."
        does_not_prove = "Pure packaging format compliance check. Provides zero anti-tamper or security guarantee."

        tool = find_zipalign()
        if tool is None:
            return ObjectiveCheckResult(
                check_id="CHK-ALN-01",
                name="Zip Alignment Verification",
                category="integrity",
                outcome="UNSUPPORTED",
                status="SKIPPED",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="zipalign tool not found on PATH or in ANDROID_HOME/build-tools",
                details={"zipalign_found": False},
                recommendation="Install Android SDK Build-Tools to verify APK zip alignment.",
            )

        is_aligned = verify_zipalign(apk_path, zipalign_path=tool, alignment=4)

        if is_aligned:
            return ObjectiveCheckResult(
                check_id="CHK-ALN-01",
                name="Zip Alignment Verification",
                category="integrity",
                outcome="VERIFIED",
                status="PASS",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="4-byte zip alignment verified successfully",
                details={"alignment_bytes": 4, "aligned": True},
            )

        return ObjectiveCheckResult(
            check_id="CHK-ALN-01",
            name="Zip Alignment Verification",
            category="integrity",
            outcome="FAILED",
            status="FAIL",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric="APK zip alignment verification failed (not aligned on 4-byte boundaries)",
            details={"aligned": False},
            recommendation="Run 'zipalign -p -f 4 <in.apk> <out.apk>' before signing.",
        )

    def check_str_01(self, dex_summary: ApkDexSummary | None) -> ObjectiveCheckResult:
        """
        CHK-STR-01: DEX string-pool heuristic scanning.
        Scans all string constants across all DEX files for sensitive patterns and fixture tokens.
        Matched values are redacted in reports to prevent secret exposure.
        """
        proves = (
            "Proves that scanned literal string patterns for sensitive tokens and secrets "
            "were not detected in plaintext in the DEX string constant pool."
        )
        does_not_prove = (
            "Cannot guarantee that no secrets exist in the binary. Sensitive data can be dynamically reconstructed, "
            "split across arrays, or missed by pattern filters."
        )

        if dex_summary is None or dex_summary.dex_files_count == 0:
            return ObjectiveCheckResult(
                check_id="CHK-STR-01",
                name="String Constant Pool Scan",
                category="strings",
                outcome="UNSUPPORTED",
                status="SKIPPED",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="DEX string pool unavailable for scanning",
                details={},
            )

        total_strings = len(dex_summary.unique_strings)
        flagged_sensitive_categories: list[dict[str, Any]] = []
        informational_fixture_categories: list[dict[str, Any]] = []

        # Scan against regular expression sensitive patterns
        for pattern, label in self.sensitive_patterns:
            matches_count = 0
            for s in dex_summary.unique_strings:
                if pattern.search(s):
                    matches_count += 1
            if matches_count > 0:
                flagged_sensitive_categories.append(
                    {
                        "category": label,
                        "match_count": matches_count,
                        "redacted_preview": "[REDACTED_SECRET_PATTERN]",
                    }
                )

        # Scan against known, explicitly documented fixture test tokens
        fixture_matches_count = 0
        for token in self.fixture_tokens:
            for s in dex_summary.unique_strings:
                if token in s:
                    fixture_matches_count += 1
                    break

        if fixture_matches_count > 0:
            informational_fixture_categories.append(
                {
                    "category": "Fixture Test Tokens",
                    "match_count": fixture_matches_count,
                    "redacted_preview": "[REDACTED_FIXTURE_TOKEN]",
                }
            )

        all_categories = flagged_sensitive_categories + informational_fixture_categories

        if not all_categories:
            return ObjectiveCheckResult(
                check_id="CHK-STR-01",
                name="String Constant Pool Scan",
                category="strings",
                outcome="HEURISTIC",
                status="PASS",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"0 flagged secret patterns detected across {total_strings} string constants",
                details={
                    "total_strings_scanned": total_strings,
                    "flagged_categories_count": 0,
                    "flagged_categories": [],
                    "sensitive_findings": [],
                    "informational_findings": [],
                },
            )

        if flagged_sensitive_categories:
            total_flagged = sum(c["match_count"] for c in flagged_sensitive_categories)
            return ObjectiveCheckResult(
                check_id="CHK-STR-01",
                name="String Constant Pool Scan",
                category="strings",
                outcome="HEURISTIC",
                status="FAIL",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric=f"{total_flagged} flagged pattern match(es) (sensitive credentials) detected across {total_strings} strings",
                details={
                    "total_strings_scanned": total_strings,
                    "flagged_categories_count": len(all_categories),
                    "flagged_categories": all_categories,
                    "sensitive_findings": flagged_sensitive_categories,
                    "informational_findings": informational_fixture_categories,
                },
                recommendation="Review hardcoded strings; avoid embedding API tokens or credentials in source code.",
            )

        # Only benign fixture markers detected: classify as informational finding
        total_fixture = sum(c["match_count"] for c in informational_fixture_categories)
        return ObjectiveCheckResult(
            check_id="CHK-STR-01",
            name="String Constant Pool Scan",
            category="strings",
            outcome="HEURISTIC",
            status="INFO",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=f"{total_fixture} documented fixture test marker(s) detected across {total_strings} strings (informational)",
            details={
                "total_strings_scanned": total_strings,
                "flagged_categories_count": len(informational_fixture_categories),
                "flagged_categories": informational_fixture_categories,
                "sensitive_findings": [],
                "informational_findings": informational_fixture_categories,
            },
            recommendation="Documented fixture test markers retained for verification testing. Not a sensitive credential finding.",
        )

    def check_cmp_01(self, dex_summary: ApkDexSummary | None) -> ObjectiveCheckResult:
        """
        CHK-CMP-01: Informational structural inspection.
        Confirms that bytecode structures comply with Dalvik/ART executable specifications.
        """
        proves = (
            "Provides informational confirmation that DEX bytecode structures comply with static Dalvik/ART header "
            "and table boundary specifications without binary corruption."
        )
        does_not_prove = (
            "Does NOT prove that the application runs, launches, or executes correctly at runtime. "
            "Structural static inspection cannot guarantee runtime functional correctness; runtime verification "
            "requires execution testing on an actual Android device or emulator."
        )

        if dex_summary is None or dex_summary.dex_files_count == 0:
            return ObjectiveCheckResult(
                check_id="CHK-CMP-01",
                name="Informational Structural Inspection",
                category="compatibility",
                outcome="INFORMATIONAL",
                status="INFO",
                what_it_proves=proves,
                what_it_does_not_prove=does_not_prove,
                observed_metric="DEX structures unavailable for structural inspection",
                details={
                    "static_inspection_only": True,
                    "runtime_execution_tested": False,
                },
            )

        dex_versions = [info.header.version for info in dex_summary.dex_files]
        endian_flags = [info.header.is_little_endian for info in dex_summary.dex_files]
        all_little_endian = all(endian_flags)

        observed = (
            f"Informational static inspection: All {dex_summary.dex_files_count} DEX file(s) conform to Dalvik specifications "
            f"(DEX version: {', '.join(set(dex_versions))}, standard little-endian; runtime execution not tested)"
        )

        return ObjectiveCheckResult(
            check_id="CHK-CMP-01",
            name="Informational Structural Inspection",
            category="compatibility",
            outcome="INFORMATIONAL",
            status="INFO",
            what_it_proves=proves,
            what_it_does_not_prove=does_not_prove,
            observed_metric=observed,
            details={
                "static_inspection_only": True,
                "runtime_execution_tested": False,
                "dex_files_count": dex_summary.dex_files_count,
                "dex_versions": list(set(dex_versions)),
                "all_little_endian": all_little_endian,
                "total_classes": dex_summary.total_classes_count,
            },
        )

    def run_all_checks(
        self,
        apk_path: Path,
        mapping_file: Path | None = None,
        signing_config: SigningConfig | None = None,
        build_result: GradleBuildResult | None = None,
        is_real_build: bool = False,
        expected_fixture_classes: list[str] | None = None,
        expected_entry_points: list[str] | None = None,
        build_id: str | None = None,
    ) -> VerificationReport:
        """
        Execute all 7 empirical verification checks and generate a structured audit report.
        Ensures the mapping file and build artifacts belong to the exact build session.
        """
        resolved_apk = apk_path.resolve()

        # Compute file SHA-256 and size
        if resolved_apk.is_file():
            hasher = hashlib.sha256()
            with open(resolved_apk, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            apk_sha256 = hasher.hexdigest()
            apk_size = resolved_apk.stat().st_size
        else:
            apk_sha256 = ""
            apk_size = 0

        # Compute mapping SHA-256 (keeps raw mapping content private)
        mapping_sha256: str | None = None
        if mapping_file is not None and mapping_file.is_file():
            hasher_m = hashlib.sha256()
            with open(mapping_file, "rb") as mf:
                while chunk := mf.read(65536):
                    hasher_m.update(chunk)
            mapping_sha256 = hasher_m.hexdigest()

        # Validate build evidence consistency between build_result and artifacts
        evidence_errors: list[str] = []
        if build_result is not None:
            if (
                build_result.apk_path is not None
                and resolved_apk != build_result.apk_path.resolve()
            ):
                evidence_errors.append(
                    f"APK path '{resolved_apk}' does not match build result artifact '{build_result.apk_path.resolve()}'"
                )
            if build_result.mapping_file is not None:
                if mapping_file is None:
                    evidence_errors.append(
                        f"Build result produced mapping '{build_result.mapping_file.resolve()}', but none was provided for verification"
                    )
                elif mapping_file.resolve() != build_result.mapping_file.resolve():
                    evidence_errors.append(
                        f"Provided mapping file '{mapping_file.resolve()}' does not match build result mapping '{build_result.mapping_file.resolve()}'"
                    )

        # Inspect DEX structures
        dex_summary: ApkDexSummary | None = None
        try:
            dex_summary = inspect_apk_dex(resolved_apk)
        except (DexError, OSError) as e:
            dex_summary = ApkDexSummary(
                dex_files_count=0,
                dex_names=[],
                total_classes_count=0,
                total_strings_count=0,
                unique_class_descriptors=[],
                unique_strings=[],
                dex_files=[],
                errors=[str(e)],
            )

        # Parse R8 mapping if provided
        mapping_summary: R8MappingSummary | None = None
        if mapping_file is not None and mapping_file.is_file():
            try:
                mapping_summary = parse_r8_mapping(mapping_file)
            except (MappingParseError, OSError):
                mapping_summary = None

        # Execute checks
        checks: list[ObjectiveCheckResult] = [
            self.check_bld_01(
                build_result, is_real_build, evidence_errors=evidence_errors
            ),
            self.check_apk_01(resolved_apk, dex_summary),
            self.check_sym_01(
                dex_summary,
                mapping_summary,
                expected_fixture_classes,
                expected_entry_points,
            ),
            self.check_sig_01(resolved_apk, signing_config),
            self.check_aln_01(resolved_apk),
            self.check_str_01(dex_summary),
            self.check_cmp_01(dex_summary),
        ]

        summary_counts: dict[str, int] = {
            "total_checks": len(checks),
            "passed": sum(1 for c in checks if c.status == "PASS"),
            "failed": sum(1 for c in checks if c.status == "FAIL"),
            "skipped": sum(1 for c in checks if c.status == "SKIPPED"),
            "info": sum(1 for c in checks if c.status == "INFO"),
            "inconclusive": sum(1 for c in checks if c.status == "INCONCLUSIVE"),
        }

        # Determine if verified protected:
        # Requires:
        # 1. Real toolchain build (is_real_build is True)
        # 2. No check failures across all checks (summary_counts['failed'] == 0)
        # 3. No inconclusive checks (summary_counts['inconclusive'] == 0)
        # 4. CHK-BLD-01 PASS (build succeeded with matching evidence)
        # 5. CHK-APK-01 PASS (valid APK archive and parseable DEX)
        # 6. CHK-SYM-01 PASS (dual-evidence symbol obfuscation verified)
        # 7. CHK-ALN-01 PASS (zip alignment verified; unsupported/skipped alignment is not sufficient)
        # 8. CHK-SIG-01 PASS if signing is configured/enabled (signature verified)
        bld_pass = any(
            c.check_id == "CHK-BLD-01" and c.status == "PASS" for c in checks
        )
        apk_pass = any(
            c.check_id == "CHK-APK-01" and c.status == "PASS" for c in checks
        )
        sym_pass = any(
            c.check_id == "CHK-SYM-01" and c.status == "PASS" for c in checks
        )
        aln_pass = any(
            c.check_id == "CHK-ALN-01" and c.status == "PASS" for c in checks
        )

        sig_required = signing_config is not None and signing_config.enabled
        sig_pass = (
            any(c.check_id == "CHK-SIG-01" and c.status == "PASS" for c in checks)
            if sig_required
            else True
        )

        no_failures = summary_counts["failed"] == 0
        no_inconclusive = summary_counts["inconclusive"] == 0

        is_verified_protected = bool(
            is_real_build
            and no_failures
            and no_inconclusive
            and bld_pass
            and apk_pass
            and sym_pass
            and aln_pass
            and sig_pass
        )

        # Signature type label
        if signing_config is None or not signing_config.enabled:
            sig_type = "unsigned"
        elif signing_config.is_production:
            sig_type = "production_signed"
        else:
            sig_type = "test_signed"

        now_iso = datetime.now(timezone.utc).isoformat()

        effective_build_id = build_id
        if effective_build_id is None and build_result is not None:
            effective_build_id = build_result.metadata.get("build_id")

        artifact_dict: dict[str, Any] = {
            "name": resolved_apk.name if resolved_apk.is_file() else str(apk_path),
            "path": str(resolved_apk),
            "sha256": apk_sha256,
            "size_bytes": apk_size,
            "is_real_build": is_real_build,
            "signature_type": sig_type,
            "mapping_sha256": mapping_sha256,
        }
        if effective_build_id:
            artifact_dict["build_id"] = effective_build_id

        return VerificationReport(
            audit_version="1.0",
            project_name=self.project_name,
            generated_at=now_iso,
            artifact=artifact_dict,
            summary=summary_counts,
            objective_checks=checks,
            is_verified_protected=is_verified_protected,
            disclaimer=STANDARD_DISCLAIMER,
        )


def export_report_json(
    report: VerificationReport, output_path: Path, allow_overwrite: bool = False
) -> Path:
    """Write verification report to disk in JSON format."""
    resolved = output_path.resolve()
    if resolved.exists() and not allow_overwrite:
        raise OverwriteError(
            f"Destination audit report already exists: '{resolved}'. "
            "AppShield will not overwrite existing reports without authorization. "
            "Specify '--overwrite' to allow replacing it."
        )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(report.to_json(indent=2), encoding="utf-8")
    return resolved


def format_report_terminal(report: VerificationReport) -> str:
    """Format verification report for human-readable terminal output."""
    lines: list[str] = [
        "=" * 68,
        f"AppShield Empirical Verification Report — {report.project_name}",
        "=" * 68,
        f"Artifact   : {report.artifact.get('name', 'Unknown')}",
        f"SHA-256    : {report.artifact.get('sha256', 'N/A')}",
        f"Size       : {report.artifact.get('size_bytes', 0):,} bytes",
        f"Sign Type  : {report.artifact.get('signature_type', 'unsigned')}",
        f"Real Build : {'Yes' if report.artifact.get('is_real_build') else 'No (Simulated / Test Fixture)'}",
        "-" * 68,
        "Objective Verification Checks (No composite scores):",
    ]

    for c in report.objective_checks:
        badge = f"[{c.status}]"
        lines.append(f"  {badge:<6} {c.check_id} - {c.name} ({c.outcome})")
        lines.append(f"         Metric: {c.observed_metric}")
        if c.recommendation:
            lines.append(f"         Hint  : {c.recommendation}")

    lines.extend(
        [
            "-" * 68,
            (
                f"Summary: {report.summary.get('passed', 0)} Passed, "
                f"{report.summary.get('failed', 0)} Failed, "
                f"{report.summary.get('skipped', 0)} Skipped, "
                f"{report.summary.get('info', 0)} Informational"
            ),
            f"Protected Release Verified: {'YES' if report.is_verified_protected else 'NO'}",
            "=" * 68,
            f"Disclaimer: {report.disclaimer}",
            "=" * 68,
        ]
    )

    return "\n".join(lines)


def format_report_markdown(report: VerificationReport) -> str:
    """Format verification report as GitHub-flavored Markdown."""
    lines: list[str] = [
        f"# AppShield Verification Report: {report.project_name}",
        "",
        f"- **Generated At**: `{report.generated_at}`",
        f"- **Artifact**: `{report.artifact.get('name')}`",
        f"- **SHA-256**: `{report.artifact.get('sha256')}`",
        f"- **File Size**: `{report.artifact.get('size_bytes', 0):,} bytes`",
        f"- **Signature**: `{report.artifact.get('signature_type')}`",
        f"- **Real Build**: `{'Yes' if report.artifact.get('is_real_build') else 'No (Simulated / Fixture)'}`",
        f"- **Verified Protected**: `{'Yes' if report.is_verified_protected else 'No'}`",
        "",
        "## Summary",
        "",
        "| Total Checks | Passed | Failed | Skipped | Info | Inconclusive |",
        "|:---:|:---:|:---:|:---:|:---:|:---:|",
        f"| {report.summary.get('total_checks')} | {report.summary.get('passed')} | {report.summary.get('failed')} | {report.summary.get('skipped')} | {report.summary.get('info')} | {report.summary.get('inconclusive')} |",
        "",
        "## Objective Checks",
        "",
        "| Check ID | Name | Category | Classification | Status | Observed Metric |",
        "|:---|:---|:---|:---|:---:|:---|",
    ]

    for c in report.objective_checks:
        lines.append(
            f"| `{c.check_id}` | {c.name} | {c.category} | `{c.outcome}` | **{c.status}** | {c.observed_metric} |"
        )

    lines.extend(
        [
            "",
            "## Disclaimer",
            "",
            "> [!NOTE]",
            f"> {report.disclaimer}",
        ]
    )

    return "\n".join(lines)
