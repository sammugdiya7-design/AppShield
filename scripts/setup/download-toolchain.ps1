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
      4. Staged extraction and transactional replacement: extracts into an isolated temporary folder,
         verifies payload integrity, swaps directories transactionally with rollback on error,
         and cleans up temporary staging.
      5. Safe overwrite protection: skips extraction if a valid existing installation is detected,
         and refuses to overwrite existing incomplete installations unless -Force is explicitly supplied.
      6. Post-install verification: checks that critical executables exist and are accessible.

    IMPORTANT: This script does NOT automatically accept Android SDK licenses or install SDK
    platform components. Android SDK licenses must be reviewed and accepted interactively
    by the developer via 'sdkmanager --licenses'.

.PARAMETER Preview
    Safe dry-run mechanism. If specified, displays planned downloads, target paths, checksums,
    and installation status without downloading, writing, or extracting any files.

.PARAMETER Force
    If specified, allows re-downloading and transactionally replacing existing toolchain installations.

.PARAMETER JdkTargetDir
    Root directory for user-scoped JDK. Defaults to $env:USERPROFILE\.jdk\jdk-17.0.21+9.

.PARAMETER AndroidSdkDir
    Root directory for user-scoped Android SDK. Defaults to $env:LOCALAPPDATA\Android\Sdk.

.PARAMETER GradleTargetDir
    Root directory for user-scoped Gradle. Defaults to $env:USERPROFILE\.gradle\gradle-8.2.

.EXAMPLE
    .\download-toolchain.ps1 -Preview
    Displays planned downloads, target paths, and checksums without downloading.

.EXAMPLE
    .\download-toolchain.ps1
    Downloads, verifies, and extracts all three toolchain components to user-scoped directories.
#>

[CmdletBinding()]
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
        ExpectedSha256  = "98518ecf554465057ee5509462631deeee374bc368c12a411d225cd29381f84b"
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

function Install-WithTransactionalSwap {
    param(
        [string]$SourceDir,
        [string]$TargetDir,
        [string[]]$RelativeExecutables
    )
    $targetParent = Split-Path -Path $TargetDir -Parent
    if (-not (Test-Path $targetParent)) {
        New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
    }

    $backupDir = $null
    if (Test-Path $TargetDir) {
        $guid = [System.Guid]::NewGuid().ToString("N")
        $backupDir = "$TargetDir.bak.$guid"
        Move-Item -Path $TargetDir -Destination $backupDir -Force
    }

    $installSucceeded = $false
    try {
        Move-Item -Path $SourceDir -Destination $TargetDir -Force
        if (-not (Test-ValidInstallation -BaseDir $TargetDir -RelativeExecutables $RelativeExecutables)) {
            throw "Post-installation verification failed for '$TargetDir'."
        }
        $installSucceeded = $true
        if ($backupDir -and (Test-Path $backupDir)) {
            Remove-Item -Recurse -Force $backupDir -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Rollback on failure
        if (-not $installSucceeded) {
            if (Test-Path $TargetDir) {
                Remove-Item -Recurse -Force $TargetDir -ErrorAction SilentlyContinue
            }
            if ($backupDir -and (Test-Path $backupDir)) {
                Move-Item -Path $backupDir -Destination $TargetDir -Force
            }
        }
        throw
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
    $jdkTargetExists = Test-Path -Path $jdkInfo.TargetDir -PathType Container
    $jdkInstalled = Test-ValidInstallation -BaseDir $jdkInfo.TargetDir -RelativeExecutables $jdkInfo.ExpectedExec

    if ($jdkInstalled -and -not $Force) {
        Write-Success "Valid JDK installation already detected at '$($jdkInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    elseif ($jdkTargetExists -and -not $jdkInstalled -and -not $Force) {
        throw "Target directory '$($jdkInfo.TargetDir)' exists but is incomplete or invalid. Aborting to protect existing files. Re-run with -Force to replace this directory."
    }
    else {
        if ($Force -and $jdkInstalled) {
            Write-WarnNotice "Existing valid JDK installation will be replaced because -Force was specified."
        }
        elseif ($Force -and $jdkTargetExists) {
            Write-WarnNotice "Existing incomplete JDK directory will be replaced because -Force was specified."
        }

        $jdkZip = Join-Path $stagingRoot $jdkInfo.ArchiveFilename
        Write-Host "  Downloading JDK from: $($jdkInfo.DownloadUrl)"
        Invoke-WebRequest -Uri $jdkInfo.DownloadUrl -OutFile $jdkZip -UseBasicParsing

        if ($jdkInfo.ExpectedSha256) {
            $expectedJdkSha = $jdkInfo.ExpectedSha256.Trim().ToLowerInvariant()
            Write-Host "  Using verified pinned Adoptium SHA-256 checksum: $expectedJdkSha"
        }
        else {
            Write-Host "  Retrieving official Adoptium SHA-256 checksum..."
            $jdkShaContent = (Invoke-RestMethod -Uri $jdkInfo.ChecksumUrl -UseBasicParsing).Trim()
            $expectedJdkSha = ($jdkShaContent -split "\s+")[0].Trim().ToLowerInvariant()
        }

        if (-not (Verify-FileChecksum -FilePath $jdkZip -ExpectedHash $expectedJdkSha)) {
            Remove-Item $jdkZip -Force -ErrorAction SilentlyContinue
            throw "JDK 17 download integrity check failed. Aborting."
        }

        Write-Host "  Extracting JDK archive into temporary staging..."
        $jdkExtractTemp = Join-Path $stagingRoot "jdk_unpacked"
        Expand-Archive -Path $jdkZip -DestinationPath $jdkExtractTemp -Force

        # Locate root directory inside archive (e.g. jdk-17.0.21+9)
        $jdkRoot = (Get-ChildItem -Path $jdkExtractTemp -Directory)[0].FullName

        Write-Host "  Installing JDK with transactional swap..."
        Install-WithTransactionalSwap -SourceDir $jdkRoot -TargetDir $jdkInfo.TargetDir -RelativeExecutables $jdkInfo.ExpectedExec
        Remove-Item -Recurse -Force $jdkExtractTemp, $jdkZip -ErrorAction SilentlyContinue

        Write-Success "JDK 17 installed and verified at '$($jdkInfo.TargetDir)'."
    }

    # -------------------------------------------------------------
    # 2. Google Android Command-Line Tools (15859902)
    # -------------------------------------------------------------
    $sdkInfo = $Toolchain.AndroidSdk
    Write-Step "Checking $($sdkInfo.Name)"
    $cmdlineLatest = Join-Path $sdkInfo.TargetDir "cmdline-tools\latest"
    $cmdlineTargetExists = Test-Path -Path $cmdlineLatest -PathType Container
    $sdkInstalled = Test-ValidInstallation -BaseDir $sdkInfo.TargetDir -RelativeExecutables $sdkInfo.ExpectedExec

    if ($sdkInstalled -and -not $Force) {
        Write-Success "Valid Android SDK command-line tools already detected at '$($sdkInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    elseif ($cmdlineTargetExists -and -not $sdkInstalled -and -not $Force) {
        throw "Target directory '$cmdlineLatest' exists but is incomplete or invalid. Aborting to protect existing files. Re-run with -Force to replace this directory."
    }
    else {
        if ($Force -and $sdkInstalled) {
            Write-WarnNotice "Existing valid Android SDK tools will be replaced because -Force was specified."
        }
        elseif ($Force -and $cmdlineTargetExists) {
            Write-WarnNotice "Existing incomplete Android SDK tools directory will be replaced because -Force was specified."
        }

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

        $sourceCmdline = Join-Path $sdkExtractTemp "cmdline-tools"
        Write-Host "  Installing Android Command-Line Tools with transactional swap..."
        Install-WithTransactionalSwap -SourceDir $sourceCmdline -TargetDir $cmdlineLatest -RelativeExecutables @("bin\sdkmanager.bat")
        Remove-Item -Recurse -Force $sdkExtractTemp, $sdkZip -ErrorAction SilentlyContinue

        Write-Success "Android Command-Line Tools installed and verified at '$cmdlineLatest'."
    }

    # -------------------------------------------------------------
    # 3. Gradle 8.2 Binary Distribution
    # -------------------------------------------------------------
    $gradleInfo = $Toolchain.Gradle
    Write-Step "Checking $($gradleInfo.Name)"
    $gradleTargetExists = Test-Path -Path $gradleInfo.TargetDir -PathType Container
    $gradleInstalled = Test-ValidInstallation -BaseDir $gradleInfo.TargetDir -RelativeExecutables $gradleInfo.ExpectedExec

    if ($gradleInstalled -and -not $Force) {
        Write-Success "Valid Gradle 8.2 installation already detected at '$($gradleInfo.TargetDir)'. Skipping (use -Force to reinstall)."
    }
    elseif ($gradleTargetExists -and -not $gradleInstalled -and -not $Force) {
        throw "Target directory '$($gradleInfo.TargetDir)' exists but is incomplete or invalid. Aborting to protect existing files. Re-run with -Force to replace this directory."
    }
    else {
        if ($Force -and $gradleInstalled) {
            Write-WarnNotice "Existing valid Gradle installation will be replaced because -Force was specified."
        }
        elseif ($Force -and $gradleTargetExists) {
            Write-WarnNotice "Existing incomplete Gradle directory will be replaced because -Force was specified."
        }

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
        Write-Host "  Installing Gradle with transactional swap..."
        Install-WithTransactionalSwap -SourceDir $extractedGradle -TargetDir $gradleInfo.TargetDir -RelativeExecutables $gradleInfo.ExpectedExec
        Remove-Item -Recurse -Force $gradleExtractTemp, $gradleZip -ErrorAction SilentlyContinue

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
