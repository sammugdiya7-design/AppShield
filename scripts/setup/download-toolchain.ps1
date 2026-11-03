<#
.SYNOPSIS
    Downloads, cryptographically verifies, and extracts user-scoped toolchain binaries
    (Eclipse Temurin OpenJDK 17 LTS, Google Android Command-Line Tools, and Gradle 8.2)
    required for building AppShield Android protection fixtures.

.DESCRIPTION
    This script is a controlled, user-scoped installation helper for Windows x64 workstations.
    It performs the following:
      1. Downloads Eclipse Temurin JDK 17 (17.0.21+9) and validates its official SHA-256 checksum.
      2. Downloads Google Android Command-Line Tools (15859902) and validates its published SHA-256.
      3. Downloads Gradle 8.2 binary distribution and validates its published SHA-256.
      4. Staged extraction: extracts into an isolated temporary folder before moving to target.
      5. Safe overwrite protection: skips extraction if a valid existing installation is detected,
         unless -Force is explicitly supplied.
      6. Post-install verification: checks that critical executables exist and are accessible.

    IMPORTANT: This script does NOT automatically accept Android SDK licenses or install SDK
    platform components. Android SDK licenses must be reviewed and accepted interactively
    by the developer via 'sdkmanager --licenses'.

.PARAMETER Preview
    If specified, displays what actions would be performed without downloading or extracting files.

.PARAMETER Force
    If specified, allows re-downloading and overwriting existing valid toolchain installations.

.PARAMETER ToolsDir
    Root directory for user-scoped tools. Defaults to standard user profile paths.

.EXAMPLE
    .\download-toolchain.ps1 -Preview
    Displays planned downloads, target paths, and checksums without downloading.

.EXAMPLE
    .\download-toolchain.ps1
    Downloads, verifies, and extracts all three toolchain components to user-scoped directories.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Preview,
    [switch]$Force,
    [string]$JdkTargetDir = (Join-Path $env:USERPROFILE ".jdk\jdk-17.0.21+9"),
    [string]$AndroidSdkDir = (Join-Path $env:LOCALAPPDATA "Android\Sdk"),
    [string]$GradleTargetDir = (Join-Path $env:USERPROFILE ".gradle\gradle-8.2")
)

$ErrorActionPreference = "Stop"

# --- Toolchain Metadata & Published Checksums ---

$Toolchain = @{
    Jdk = @{
        Name            = "Eclipse Temurin OpenJDK 17 LTS (17.0.21+9)"
        ArchiveFilename = "OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip"
        DownloadUrl     = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip"
        ChecksumUrl     = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip.sha256.txt"
        TargetDir       = $JdkTargetDir
        ExpectedExec    = @("bin\java.exe", "bin\javac.exe")
    }
    AndroidSdk = @{
        Name            = "Google Android Command-Line Tools (15859902)"
        ArchiveFilename = "commandlinetools-win-15859902_latest.zip"
        DownloadUrl     = "https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip"
        ExpectedSha256  = "90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a"
        TargetDir       = $AndroidSdkDir
        ExpectedExec    = @("cmdline-tools\latest\bin\sdkmanager.bat")
    }
    Gradle = @{
        Name            = "Gradle 8.2 Binary Distribution"
        ArchiveFilename = "gradle-8.2-bin.zip"
        DownloadUrl     = "https://services.gradle.org/distributions/gradle-8.2-bin.zip"
        ChecksumUrl     = "https://services.gradle.org/distributions/gradle-8.2-bin.zip.sha256"
        ExpectedSha256  = "38f66cd6eef217b4c35855bb11ea4e9fbc53594ccccb5fb82dfd317ef8c2c5a3"
        TargetDir       = $GradleTargetDir
        ExpectedExec    = @("bin\gradle.bat")
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n[STEP] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnNotice {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-ValidInstallation {
    param(
        [string]$BaseDir,
        [string[]]$RelativeExecutables
    )
    if (-not (Test-Path -Path $BaseDir -PathType Container)) {
        return $false
    }
    foreach ($rel in $RelativeExecutables) {
        $fullPath = Join-Path $BaseDir $rel
        if (-not (Test-Path -Path $fullPath -PathType Leaf)) {
            return $false
        }
    }
    return $true
}

function Verify-FileChecksum {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )
    Write-Host "  Calculating SHA-256 for: $FilePath"
    $actualHash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $normalizedExpected = $ExpectedHash.Trim().ToLowerInvariant()

    if ($actualHash -eq $normalizedExpected) {
        Write-Success "SHA-256 verified successfully: $actualHash"
        return $true
    }
    else {
        Write-Host "  FAILED: Checksum mismatch!" -ForegroundColor Red
        Write-Host "  Expected: $normalizedExpected" -ForegroundColor Red
        Write-Host "  Actual  : $actualHash" -ForegroundColor Red
        return $false
    }
}

# --- Preview Mode ---

if ($Preview) {
    Write-Host "=== AppShield Toolchain Download & Setup (PREVIEW MODE) ===" -ForegroundColor Magenta
    Write-Host "No files will be downloaded or extracted."
    Write-Host ""
    foreach ($key in @("Jdk", "AndroidSdk", "Gradle")) {
        $info = $Toolchain[$key]
        Write-Host "Tool: $($info.Name)" -ForegroundColor Yellow
        Write-Host "  Archive    : $($info.ArchiveFilename)"
        Write-Host "  URL        : $($info.DownloadUrl)"
        if ($info.ExpectedSha256) {
            Write-Host "  Pinned SHA : $($info.ExpectedSha256)"
        }
        elseif ($info.ChecksumUrl) {
            Write-Host "  ChecksumURL: $($info.ChecksumUrl)"
        }
        Write-Host "  Target Dir : $($info.TargetDir)"
        $isValid = Test-ValidInstallation -BaseDir $info.TargetDir -RelativeExecutables $info.ExpectedExec
        Write-Host "  Installed? : $(if ($isValid) { 'Yes (Valid)' } else { 'No / Incomplete' })"
        Write-Host ""
    }
    Write-Host "To execute actual setup, run without -Preview."
    return
}

Write-Host "=== AppShield Android Toolchain Setup ===" -ForegroundColor Cyan
$stagingRoot = Join-Path $env:TEMP ("appshield_toolchain_staging_" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null

try {
    # -------------------------------------------------------------
    # 1. Eclipse Temurin OpenJDK 17 LTS (17.0.21+9)
    # -------------------------------------------------------------
    $jdkInfo = $Toolchain.Jdk
    Write-Step "Checking $($jdkInfo.Name)"
    $jdkInstalled = Test-ValidInstallation -BaseDir $jdkInfo.TargetDir -RelativeExecutables $jdkInfo.ExpectedExec

    if ($jdkInstalled -and -not $Force) {
        Write-Success "Valid JDK installation already detected at '$($jdkInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    else {
        $jdkZip = Join-Path $stagingRoot $jdkInfo.ArchiveFilename
        Write-Host "  Downloading JDK from: $($jdkInfo.DownloadUrl)"
        Invoke-WebRequest -Uri $jdkInfo.DownloadUrl -OutFile $jdkZip -UseBasicParsing

        Write-Host "  Retrieving official Adoptium SHA-256 checksum..."
        $jdkShaContent = (Invoke-RestMethod -Uri $jdkInfo.ChecksumUrl -UseBasicParsing).Trim()
        $expectedJdkSha = ($jdkShaContent -split "\s+")[0].Trim().ToLowerInvariant()

        if (-not (Verify-FileChecksum -FilePath $jdkZip -ExpectedHash $expectedJdkSha)) {
            Remove-Item $jdkZip -Force -ErrorAction SilentlyContinue
            throw "JDK 17 download integrity check failed. Aborting."
        }

        Write-Host "  Extracting JDK archive into temporary staging..."
        $jdkExtractTemp = Join-Path $stagingRoot "jdk_unpacked"
        Expand-Archive -Path $jdkZip -DestinationPath $jdkExtractTemp -Force

        # Locate root directory inside archive (e.g. jdk-17.0.21+9)
        $jdkRoot = (Get-ChildItem -Path $jdkExtractTemp -Directory)[0].FullName
        $targetParent = Split-Path -Path $jdkInfo.TargetDir -Parent
        if (-not (Test-Path $targetParent)) {
            New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        }

        if (Test-Path $jdkInfo.TargetDir) {
            Remove-Item -Recurse -Force $jdkInfo.TargetDir
        }
        Move-Item -Path $jdkRoot -Destination $jdkInfo.TargetDir -Force
        Remove-Item -Recurse -Force $jdkExtractTemp, $jdkZip

        if (-not (Test-ValidInstallation -BaseDir $jdkInfo.TargetDir -RelativeExecutables $jdkInfo.ExpectedExec)) {
            throw "JDK verification failed after installation at '$($jdkInfo.TargetDir)'."
        }
        Write-Success "JDK 17 installed and verified at '$($jdkInfo.TargetDir)'."
    }

    # -------------------------------------------------------------
    # 2. Google Android Command-Line Tools (15859902)
    # -------------------------------------------------------------
    $sdkInfo = $Toolchain.AndroidSdk
    Write-Step "Checking $($sdkInfo.Name)"
    $sdkInstalled = Test-ValidInstallation -BaseDir $sdkInfo.TargetDir -RelativeExecutables $sdkInfo.ExpectedExec

    if ($sdkInstalled -and -not $Force) {
        Write-Success "Valid Android SDK command-line tools already detected at '$($sdkInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    else {
        $sdkZip = Join-Path $stagingRoot $sdkInfo.ArchiveFilename
        Write-Host "  Downloading Android command-line tools from: $($sdkInfo.DownloadUrl)"
        Invoke-WebRequest -Uri $sdkInfo.DownloadUrl -OutFile $sdkZip -UseBasicParsing

        if (-not (Verify-FileChecksum -FilePath $sdkZip -ExpectedHash $sdkInfo.ExpectedSha256)) {
            Remove-Item $sdkZip -Force -ErrorAction SilentlyContinue
            throw "Android SDK tools download integrity check failed. Aborting."
        }

        Write-Host "  Extracting Android command-line tools into temporary staging..."
        $sdkExtractTemp = Join-Path $stagingRoot "cmdline_unpacked"
        Expand-Archive -Path $sdkZip -DestinationPath $sdkExtractTemp -Force

        # Google command-line tools require being in <ANDROID_HOME>/cmdline-tools/latest
        $cmdlineLatest = Join-Path $sdkInfo.TargetDir "cmdline-tools\latest"
        $cmdlineParent = Split-Path -Path $cmdlineLatest -Parent
        if (-not (Test-Path $cmdlineParent)) {
            New-Item -ItemType Directory -Path $cmdlineParent -Force | Out-Null
        }

        if (Test-Path $cmdlineLatest) {
            Remove-Item -Recurse -Force $cmdlineLatest
        }

        $sourceCmdline = Join-Path $sdkExtractTemp "cmdline-tools"
        Move-Item -Path $sourceCmdline -Destination $cmdlineLatest -Force
        Remove-Item -Recurse -Force $sdkExtractTemp, $sdkZip

        if (-not (Test-ValidInstallation -BaseDir $sdkInfo.TargetDir -RelativeExecutables $sdkInfo.ExpectedExec)) {
            throw "Android SDK command-line tools verification failed after installation."
        }
        Write-Success "Android Command-Line Tools installed and verified at '$cmdlineLatest'."
    }

    # -------------------------------------------------------------
    # 3. Gradle 8.2 Binary Distribution
    # -------------------------------------------------------------
    $gradleInfo = $Toolchain.Gradle
    Write-Step "Checking $($gradleInfo.Name)"
    $gradleInstalled = Test-ValidInstallation -BaseDir $gradleInfo.TargetDir -RelativeExecutables $gradleInfo.ExpectedExec

    if ($gradleInstalled -and -not $Force) {
        Write-Success "Valid Gradle 8.2 installation already detected at '$($gradleInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    else {
        $gradleZip = Join-Path $stagingRoot $gradleInfo.ArchiveFilename
        Write-Host "  Downloading Gradle 8.2 from: $($gradleInfo.DownloadUrl)"
        Invoke-WebRequest -Uri $gradleInfo.DownloadUrl -OutFile $gradleZip -UseBasicParsing

        if (-not (Verify-FileChecksum -FilePath $gradleZip -ExpectedHash $gradleInfo.ExpectedSha256)) {
            Remove-Item $gradleZip -Force -ErrorAction SilentlyContinue
            throw "Gradle 8.2 download integrity check failed. Aborting."
        }

        Write-Host "  Extracting Gradle 8.2 into temporary staging..."
        $gradleExtractTemp = Join-Path $stagingRoot "gradle_unpacked"
        Expand-Archive -Path $gradleZip -DestinationPath $gradleExtractTemp -Force

        $extractedGradle = (Get-ChildItem -Path $gradleExtractTemp -Directory)[0].FullName
        $gradleParent = Split-Path -Path $gradleInfo.TargetDir -Parent
        if (-not (Test-Path $gradleParent)) {
            New-Item -ItemType Directory -Path $gradleParent -Force | Out-Null
        }

        if (Test-Path $gradleInfo.TargetDir) {
            Remove-Item -Recurse -Force $gradleInfo.TargetDir
        }
        Move-Item -Path $extractedGradle -Destination $gradleInfo.TargetDir -Force
        Remove-Item -Recurse -Force $gradleExtractTemp, $gradleZip

        if (-not (Test-ValidInstallation -BaseDir $gradleInfo.TargetDir -RelativeExecutables $gradleInfo.ExpectedExec)) {
            throw "Gradle 8.2 verification failed after installation."
        }
        Write-Success "Gradle 8.2 installed and verified at '$($gradleInfo.TargetDir)'."
    }

    Write-Step "Toolchain Download & Staging Complete (Phase 1 Complete)"
    Write-Host ""
    Write-Host "NEXT REQUIRED STEP: Phase 2 - User Environment Configuration" -ForegroundColor Cyan
    Write-Host "  Run configure-user-environment.ps1 to configure JAVA_HOME, ANDROID_HOME, and User PATH."
    Write-Host "  (This ensures OpenJDK 17 is on PATH before executing sdkmanager in Phase 3):"
    Write-Host "    & scripts/setup/configure-user-environment.ps1" -ForegroundColor Yellow
    Write-Host ""
    Write-WarnNotice "Phase 3 (Post-Configuration): Android SDK Licenses & Component Provisioning"
    Write-Host "  After Phase 2 has configured JAVA_HOME, review and accept licenses interactively:"
    Write-Host "    & `"$($sdkInfo.TargetDir)\cmdline-tools\latest\bin\sdkmanager.bat`" --licenses" -ForegroundColor Cyan
    Write-Host "  Then install required compile SDK platform 34 and build-tools 34.0.0:"
    Write-Host "    & `"$($sdkInfo.TargetDir)\cmdline-tools\latest\bin\sdkmanager.bat`" `"platforms;android-34`" `"build-tools;34.0.0`"" -ForegroundColor Cyan
    Write-Host ""
}
finally {
    if (Test-Path $stagingRoot) {
        Remove-Item -Recurse -Force $stagingRoot -ErrorAction SilentlyContinue
    }
}

