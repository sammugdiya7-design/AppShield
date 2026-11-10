"""
AppShield Disposable Test-Signing Utility.
Generates an ephemeral, process-local test certificate and signs a copy
of the protected release APK strictly in dist/test-signed/.

Security and Invariant Guarantees:
  - Generates a fresh high-entropy private test password in process memory.
  - Never logs, prints, or commits passwords or private keys.
  - Passes credentials using native `env:` mechanisms (keytool -storepass:env, apksigner --ks-pass env:).
  - Keeps credentials process-local and clears environment variables immediately after signing.
  - Keystore stored outside repository (%USERPROFILE%\\.appshield\\keystores\\).
  - Never overwrites existing keystores or output APKs.
  - Preserves original unsigned APK bit-for-bit.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess  # nosec: B404
import sys
from pathlib import Path

EXPECTED_ORIGINAL_SHA256 = (
    "b4b7ed6f884b8d481de2a5a1ad0fc6af3a355ed8fb580ce1beac3a694bf77e76"
)


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def find_tool(name: str, candidate_paths: list[Path]) -> Path:
    """Find a tool binary from candidates or PATH."""
    for p in candidate_paths:
        if p.is_file():
            return p.resolve()
    which_res = shutil.which(name)
    if which_res:
        return Path(which_res).resolve()
    raise FileNotFoundError(f"Required tool '{name}' could not be located.")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    source_apk = (
        repo_root
        / "dist"
        / "protected-first-validation"
        / "sample_android_gradle_project-release-protected.apk"
    )
    output_dir = repo_root / "dist" / "test-signed"
    output_apk = output_dir / "sample_android_gradle_project-release-test-signed.apk"

    user_profile = Path(os.environ.get("USERPROFILE") or os.path.expanduser("~"))
    keystore_dir = user_profile / ".appshield" / "keystores"
    keystore_path = keystore_dir / "disposable_test.jks"

    sdk_dir = Path(
        os.environ.get(
            "ANDROID_HOME",
            user_profile / "AppData" / "Local" / "Android" / "Sdk",
        )
    )
    jdk_dir = Path(os.environ.get("JAVA_HOME", user_profile / ".jdk" / "jdk-17.0.21+9"))

    print("=== AppShield Disposable Test-Signing Workflow ===")
    print(f"Repository Root    : {repo_root}")
    print(f"Source APK         : {source_apk}")
    print(f"Target Output APK  : {output_apk}")
    print(f"Target Keystore    : {keystore_path}")
    print("--------------------------------------------------")

    # 1. Verify Source APK exists and matches first-build SHA-256
    if not source_apk.is_file():
        print(f"ERROR: Source APK not found at '{source_apk}'", file=sys.stderr)
        return 1

    source_sha_before = compute_sha256(source_apk)
    print(f"[CHECK] Source APK pre-signing SHA-256: {source_sha_before}")
    if source_sha_before != EXPECTED_ORIGINAL_SHA256:
        print(
            f"ERROR: Source APK hash mismatch! Expected {EXPECTED_ORIGINAL_SHA256}, got {source_sha_before}",
            file=sys.stderr,
        )
        return 1
    print(
        "[PASS] Source APK verified bit-for-bit identical to first genuine build report."
    )

    # 2. Check Overwrite Guards
    if output_apk.exists():
        print(
            f"ERROR: Target output APK already exists: '{output_apk}'. Overwrite not authorized.",
            file=sys.stderr,
        )
        return 1

    if keystore_path.exists():
        print(
            f"ERROR: Target keystore already exists: '{keystore_path}'. Overwrite not authorized.",
            file=sys.stderr,
        )
        return 1

    # 3. Locate Tools
    keytool = find_tool(
        "keytool", [jdk_dir / "bin" / "keytool.exe", jdk_dir / "bin" / "keytool"]
    )
    apksigner = find_tool(
        "apksigner",
        [
            sdk_dir / "build-tools" / "34.0.0" / "apksigner.bat",
            sdk_dir / "build-tools" / "34.0.0" / "apksigner",
        ],
    )
    zipalign = find_tool(
        "zipalign",
        [
            sdk_dir / "build-tools" / "34.0.0" / "zipalign.exe",
            sdk_dir / "build-tools" / "34.0.0" / "zipalign",
        ],
    )

    print(f"[OK] Keytool   : {keytool}")
    print(f"[OK] Apksigner : {apksigner}")
    print(f"[OK] Zipalign  : {zipalign}")
    print("--------------------------------------------------")

    # 4. Generate Fresh Private Test Password & Set Process-Local Env Var
    # Generate 256-bit cryptographically secure random secret
    ephemeral_secret = secrets.token_urlsafe(32)
    env_var_name = "APPSHIELD_DISPOSABLE_TEST_PASS"
    os.environ[env_var_name] = ephemeral_secret

    print(
        "[SECURITY] Generated fresh 256-bit cryptographically secure test password in process memory."
    )
    print(
        f"[SECURITY] Set process-local environment variable '{env_var_name}' (value masked)."
    )
    print(
        "[SECURITY] Value will NEVER appear on command line arguments or in log output."
    )
    print(
        "[NOTE] Environment variables are process-local, but accessible to same-user/elevated OS inspectors."
    )

    keystore_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 5. Create Disposable Test Keystore using native -storepass:env
        print("\n--- Step 1: Creating Disposable Test Keystore ---")
        alias = "appshield_test"
        dname = "CN=AppShield Disposable Test, OU=Testing, O=AppShield, C=US"
        keytool_cmd = [
            str(keytool),
            "-genkeypair",
            "-v",
            "-keystore",
            str(keystore_path),
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "365",
            "-storepass:env",
            env_var_name,
            "-keypass:env",
            env_var_name,
            "-dname",
            dname,
        ]

        proc_kt = subprocess.run(  # nosec: B603
            keytool_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if proc_kt.returncode != 0:
            print(
                f"ERROR: keytool failed with code {proc_kt.returncode}:\n{proc_kt.stderr}",
                file=sys.stderr,
            )
            return 1

        print(f"[PASS] Disposable keystore created at: {keystore_path}")
        print(f"       Alias: {alias}")
        print(f"       Certificate Subject: {dname}")
        print("       Key Algorithm: RSA 2048-bit, Validity: 365 days")

        # 6. Sign APK Copy using apksigner with native --ks-pass env:
        print("\n--- Step 2: Signing APK Copy via apksigner ---")
        apksigner_cmd = [
            str(apksigner),
            "sign",
            "--ks",
            str(keystore_path),
            "--ks-key-alias",
            alias,
            "--ks-pass",
            f"env:{env_var_name}",
            "--key-pass",
            f"env:{env_var_name}",
            "--out",
            str(output_apk),
            str(source_apk),
        ]

        proc_sign = subprocess.run(  # nosec: B603
            apksigner_cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if proc_sign.returncode != 0:
            print(
                f"ERROR: apksigner failed with code {proc_sign.returncode}:\n{proc_sign.stderr}",
                file=sys.stderr,
            )
            return 1

        print(f"[PASS] Signed APK generated at: {output_apk}")
        print(f"       Size: {output_apk.stat().st_size} bytes")

    finally:
        # Immediately clear credential from environment
        if env_var_name in os.environ:
            del os.environ[env_var_name]
        del ephemeral_secret
        print(
            "\n[SECURITY] Ephemeral password variable cleared from process environment."
        )

    # 7. Signature Verification via apksigner verify --verbose
    print("\n--- Step 3: Verifying Signature Schemes (apksigner verify) ---")
    proc_ver = subprocess.run(  # nosec: B603
        [str(apksigner), "verify", "--verbose", str(output_apk)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    print(f"apksigner verify exit code: {proc_ver.returncode}")
    print(proc_ver.stdout.strip())
    if proc_ver.returncode != 0:
        print(
            f"ERROR: Signature verification failed:\n{proc_ver.stderr}", file=sys.stderr
        )
        return 1

    # 8. Alignment Verification via zipalign -c -v 4
    print("\n--- Step 4: Verifying 4-Byte ZIP Alignment (zipalign -c) ---")
    proc_aln = subprocess.run(  # nosec: B603
        [str(zipalign), "-c", "-v", "4", str(output_apk)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    print(f"zipalign exit code: {proc_aln.returncode}")
    if proc_aln.returncode != 0:
        print(
            f"ERROR: ZIP alignment verification failed:\n{proc_aln.stderr}",
            file=sys.stderr,
        )
        return 1
    print("[PASS] Final signed APK satisfies 4-byte page alignment.")

    # 9. Cryptographic Hash & Immutability Verification
    print("\n--- Step 5: Cryptographic Hash Verification ---")
    signed_sha = compute_sha256(output_apk)
    source_sha_after = compute_sha256(source_apk)

    print(f"Signed APK SHA-256   : {signed_sha}")
    print(
        f"Original APK SHA-256 : {source_sha_after} (Expected: {EXPECTED_ORIGINAL_SHA256})"
    )

    if source_sha_after != EXPECTED_ORIGINAL_SHA256:
        print(
            "CRITICAL ERROR: Original APK was altered during signing!", file=sys.stderr
        )
        return 1
    print("[PASS] Original APK remains 100% bit-for-bit identical and unmodified.")

    print("\n==================================================")
    print("TEST SIGNING & VERIFICATION COMPLETED SUCCESSFULLY")
    print("==================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
