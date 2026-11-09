<#
.SYNOPSIS
    Configures process-level environment variables (JAVA_HOME, ANDROID_HOME, and PATH)
    for the active PowerShell session to run AppShield with complete toolchain isolation.

.DESCRIPTION
    This script activates an isolated environment for the current PowerShell process ONLY:
      1. Sets process-level $env:JAVA_HOME to the user-scoped OpenJDK 17 directory.
      2. Sets process-level $env:ANDROID_HOME to the user-scoped Android SDK directory.
      3. Prepends the AppShield toolchain directories (JDK bin, SDK cmdline-tools bin,
         SDK build-tools, Gradle bin, platform-tools) to the front of process $env:Path.
      4. Guarantees that OpenJDK 17 takes priority over any older Java versions (such as
         Oracle Java 8) located in the Machine PATH.
      5. Strictly NEVER modifies persistent Machine or User environment variables in the Windows registry.
      6. Preserves the host's existing Oracle Java 8 installation and Android 36 SDK components intact.
      7. When this PowerShell session is closed, all environment changes vanish with zero cleanup required.

.PARAMETER Preview
    Safe dry-run mechanism. If specified, displays proposed process environment settings without altering the active session.

.PARAMETER JdkPath
    Path to user-scoped JDK. Defaults to $env:USERPROFILE\.jdk\jdk-17.0.21+9.

.PARAMETER SdkPath
    Path to user-scoped Android SDK. Defaults to $env:LOCALAPPDATA\Android\Sdk.

.PARAMETER GradlePath
    Path to user-scoped Gradle. Defaults to $env:USERPROFILE\.gradle\gradle-8.2.

.EXAMPLE
    . scripts/setup/enter-appshield-env.ps1 -Preview
    Shows what process environment variables would be set for the session without applying them.

.EXAMPLE
    . scripts/setup/enter-appshield-env.ps1
    Dot-source into the current PowerShell session to activate the isolated AppShield toolchain environment.
#>

[CmdletBinding()]
param(
    [switch]$Preview,
    [string]$JdkPath = (Join-Path $env:USERPROFILE ".jdk\jdk-17.0.21+9"),
    [string]$SdkPath = (Join-Path $env:LOCALAPPDATA "Android\Sdk"),
    [string]$GradlePath = (Join-Path $env:USERPROFILE ".gradle\gradle-8.2")
)

$ErrorActionPreference = "Stop"

# --- 1. Toolchain Target Directories ---
$toolchainDirs = @(
    (Join-Path $JdkPath "bin"),
    (Join-Path $SdkPath "cmdline-tools\latest\bin"),
    (Join-Path $SdkPath "build-tools\34.0.0"),
    (Join-Path $GradlePath "bin"),
    (Join-Path $SdkPath "platform-tools")
)

# --- 2. Preview Mode ---
if ($Preview) {
    Write-Host "=== AppShield Process-Level Session Environment (PREVIEW MODE) ===" -ForegroundColor Magenta
    Write-Host "No persistent or session environment changes will be applied."
    Write-Host ""
    Write-Host "Isolation Guarantees:" -ForegroundColor Yellow
    Write-Host "  - Persistent Machine PATH in Windows Registry: Strictly UNTOUCHED"
    Write-Host "  - Persistent User PATH in Windows Registry   : Strictly UNTOUCHED"
    Write-Host "  - Existing Oracle Java 8 in Machine PATH    : Strictly PRESERVED"
    Write-Host "  - Existing Android SDK 36/36.1 components   : Strictly PRESERVED"
    Write-Host ""
    Write-Host "Proposed Process-Level Settings for Current Session:" -ForegroundColor Yellow
    Write-Host "  `$env:JAVA_HOME    = '$JdkPath'"
    Write-Host "  `$env:ANDROID_HOME = '$SdkPath'"
    Write-Host "  `$env:Path Prepend Order (front of process PATH):"
    foreach ($dir in $toolchainDirs) {
        $exists = Test-Path $dir
        Write-Host "    + $dir $(if ($exists) { '[Found]' } else { '[Pending Install]' })" -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "To activate in current session, dot-source the script:"
    Write-Host "  . scripts/setup/enter-appshield-env.ps1" -ForegroundColor Green
    return
}

# --- 3. Apply Process-Level Variables ---
Write-Host "=== Activating AppShield Isolated Session Environment ===" -ForegroundColor Cyan

# Set process environment variables
$env:JAVA_HOME = $JdkPath
$env:ANDROID_HOME = $SdkPath

# Build deduplicated prepend list
$currentPathEntries = $env:Path -split ";"
$existingSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($e in $currentPathEntries) {
    $t = $e.Trim()
    if ($t) { $existingSet.Add($t) | Out-Null }
}

$prependList = [System.Collections.Generic.List[string]]::new()
foreach ($dir in $toolchainDirs) {
    if (-not $existingSet.Contains($dir)) {
        $prependList.Add($dir)
    }
}

if ($prependList.Count -gt 0) {
    $env:Path = ($prependList -join ";") + ";" + $env:Path
}

Write-Host "[OK] Process environment configured successfully for active session." -ForegroundColor Green
Write-Host "  `$env:JAVA_HOME    : $env:JAVA_HOME"
Write-Host "  `$env:ANDROID_HOME : $env:ANDROID_HOME"
Write-Host "  Prepended Paths    : $($prependList.Count) directories added to front of process `$env:Path"
Write-Host ""
Write-Host "Verification & Isolation Status:" -ForegroundColor Yellow
Write-Host "  Machine Environment Registry : Completely UNTOUCHED"
Write-Host "  User Environment Registry    : Completely UNTOUCHED"
Write-Host "  Host Oracle Java 8           : Preserved intact on Machine PATH"

# Check active java binary resolution
$resolvedJava = Get-Command java -ErrorAction SilentlyContinue
if ($resolvedJava) {
    Write-Host "  Active 'java' Command        : $($resolvedJava.Source)" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Session is ready for AppShield execution. When this terminal window closes,"
Write-Host "all process settings disappear automatically with zero system modification." -ForegroundColor DarkGray

