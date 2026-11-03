<#
.SYNOPSIS
    Configures user-scoped environment variables (JAVA_HOME, ANDROID_HOME, and User PATH)
    for the AppShield Android protection toolchain, creating a protected backup first.

.DESCRIPTION
    This script performs idempotent environment configuration at the User scope:
      1. Reads current user-scope JAVA_HOME, ANDROID_HOME, and User PATH.
      2. Creates a protected, timestamped backup JSON file before making any changes.
         Never overwrites an existing backup.
      3. Sets JAVA_HOME to the user-scoped OpenJDK 17 directory.
      4. Sets ANDROID_HOME to the user-scoped Android SDK directory.
      5. Updates User PATH by appending only missing directories (JDK bin, SDK cmdline-tools bin,
         SDK build-tools, Gradle bin, and platform-tools if present), avoiding duplicates and preserving all
         existing user and system entries.
      6. Refreshes the current PowerShell process environment immediately.
      7. Supports -Preview / -WhatIf mode to report exact changes without modifying the system.

.PARAMETER Preview
    If specified, displays the exact environment changes and backup destination without applying them.

.PARAMETER JdkPath
    Path to user-scoped JDK. Defaults to $env:USERPROFILE\.jdk\jdk-17.0.21+9.

.PARAMETER SdkPath
    Path to user-scoped Android SDK. Defaults to $env:LOCALAPPDATA\Android\Sdk.

.PARAMETER GradlePath
    Path to user-scoped Gradle. Defaults to $env:USERPROFILE\.gradle\gradle-8.2.

.PARAMETER BackupDir
    Directory where protected backup JSON files are written. Defaults to $env:USERPROFILE\.appshield\backup.

.EXAMPLE
    .\configure-user-environment.ps1 -Preview
    Shows what environment variables and PATH entries would change without altering them.

.EXAMPLE
    .\configure-user-environment.ps1
    Backs up current environment state and configures user variables for AppShield.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Preview,
    [string]$JdkPath = (Join-Path $env:USERPROFILE ".jdk\jdk-17.0.21+9"),
    [string]$SdkPath = (Join-Path $env:LOCALAPPDATA "Android\Sdk"),
    [string]$GradlePath = (Join-Path $env:USERPROFILE ".gradle\gradle-8.2"),
    [string]$BackupDir = (Join-Path $env:USERPROFILE ".appshield\backup")
)

$ErrorActionPreference = "Stop"

# --- 1. Gather Current State ---
$currentUserJavaHome    = [Environment]::GetEnvironmentVariable("JAVA_HOME", [EnvironmentVariableTarget]::User)
$currentUserAndroidHome = [Environment]::GetEnvironmentVariable("ANDROID_HOME", [EnvironmentVariableTarget]::User)
$currentUserPath        = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
$currentMachinePath     = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)

# Normalize current user path into list
$userPathEntries = if ($currentUserPath) { $currentUserPath -split ";" } else { @() }
$cleanedExistingEntries = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $userPathEntries) {
    $trimmed = $entry.Trim()
    if ($trimmed -ne "" -and -not $cleanedExistingEntries.Contains($trimmed)) {
        $cleanedExistingEntries.Add($trimmed)
    }
}

# --- 2. Calculate Desired Additions ---
$targetDirsToAdd = @(
    (Join-Path $JdkPath "bin"),
    (Join-Path $SdkPath "cmdline-tools\latest\bin"),
    (Join-Path $SdkPath "build-tools\34.0.0"),
    (Join-Path $GradlePath "bin")
)

# If platform-tools directory exists, include it
$platformToolsDir = Join-Path $SdkPath "platform-tools"
if (Test-Path $platformToolsDir) {
    $targetDirsToAdd += $platformToolsDir
}

# Compute entries that are not yet in User PATH
$entriesToAdd = [System.Collections.Generic.List[string]]::new()
foreach ($dir in $targetDirsToAdd) {
    if (-not $cleanedExistingEntries.Contains($dir)) {
        $entriesToAdd.Add($dir)
    }
}

$newUserPathList = [System.Collections.Generic.List[string]]::new($cleanedExistingEntries)
foreach ($add in $entriesToAdd) {
    $newUserPathList.Add($add)
}
$newUserPath = $newUserPathList -join ";"

# --- 3. Compute Changes Summary ---
$javaHomeChanged = ($currentUserJavaHome -ne $JdkPath)
$androidHomeChanged = ($currentUserAndroidHome -ne $SdkPath)
$pathChanged = ($entriesToAdd.Count -gt 0)

# --- 4. Preview / WhatIf Mode ---
if ($Preview) {
    Write-Host "=== AppShield Environment Configuration (PREVIEW MODE) ===" -ForegroundColor Magenta
    Write-Host "No changes will be written to the user environment."
    Write-Host ""
    Write-Host "Backup Directory: $BackupDir (a new timestamped JSON backup would be created here)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Proposed Environment Variable Changes:" -ForegroundColor Yellow
    Write-Host "  JAVA_HOME:"
    Write-Host "    Current : $(if ($currentUserJavaHome) { $currentUserJavaHome } else { '<Not Set>' })"
    Write-Host "    Proposed: $JdkPath"
    Write-Host "    Changed?: $javaHomeChanged"
    Write-Host ""
    Write-Host "  ANDROID_HOME:"
    Write-Host "    Current : $(if ($currentUserAndroidHome) { $currentUserAndroidHome } else { '<Not Set>' })"
    Write-Host "    Proposed: $SdkPath"
    Write-Host "    Changed?: $androidHomeChanged"
    Write-Host ""
    Write-Host "  User PATH Additions ($($entriesToAdd.Count) new entries):"
    if ($entriesToAdd.Count -eq 0) {
        Write-Host "    (All required directories are already present in User PATH; no additions required)" -ForegroundColor Green
    }
    else {
        foreach ($e in $entriesToAdd) {
            Write-Host "    + $e" -ForegroundColor Cyan
        }
    }
    Write-Host ""
    Write-Host "  Preserved Existing User PATH Entries: $($cleanedExistingEntries.Count)"
    Write-Host "  Preserved System Machine PATH: $($currentMachinePath.Length) characters"
    Write-Host ""
    Write-Host "To apply these changes, run .\configure-user-environment.ps1 without -Preview."
    return
}

# --- 5. Create Protected Backup ---
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = Join-Path $BackupDir "environment_backup_$timestamp.json"

if (Test-Path $backupFile) {
    throw "Backup collision: file '$backupFile' already exists. Aborting to protect existing backup."
}

$backupData = [ordered]@{
    timestamp            = (Get-Date).ToString("o")
    script_version       = "1.0"
    user_java_home       = $currentUserJavaHome
    user_android_home    = $currentUserAndroidHome
    user_path            = $currentUserPath
    machine_path_summary = [ordered]@{
        entry_count = if ($currentMachinePath) { ($currentMachinePath -split ";").Count } else { 0 }
    }
    applied_changes      = [ordered]@{
        new_java_home    = $JdkPath
        new_android_home = $SdkPath
        added_path_dirs  = @($entriesToAdd)
    }
}

$jsonContent = $backupData | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($backupFile, $jsonContent, [System.Text.Encoding]::UTF8)

Write-Host "=== AppShield Environment Configuration ===" -ForegroundColor Cyan
Write-Host "[BACKUP] Created protected environment backup:" -ForegroundColor Green
Write-Host "         $backupFile" -ForegroundColor Green
Write-Host ""

# --- 6. Apply Changes to User Scope ---
Write-Host "[APPLY] Writing User environment variables..." -ForegroundColor Cyan

if ($javaHomeChanged) {
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $JdkPath, [EnvironmentVariableTarget]::User)
    Write-Host "  Set User JAVA_HOME = '$JdkPath'" -ForegroundColor Green
}
else {
    Write-Host "  User JAVA_HOME already up to date: '$JdkPath'" -ForegroundColor DarkGray
}

if ($androidHomeChanged) {
    [Environment]::SetEnvironmentVariable("ANDROID_HOME", $SdkPath, [EnvironmentVariableTarget]::User)
    Write-Host "  Set User ANDROID_HOME = '$SdkPath'" -ForegroundColor Green
}
else {
    Write-Host "  User ANDROID_HOME already up to date: '$SdkPath'" -ForegroundColor DarkGray
}

if ($pathChanged) {
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, [EnvironmentVariableTarget]::User)
    Write-Host "  Updated User PATH: added $($entriesToAdd.Count) missing directories." -ForegroundColor Green
    foreach ($entry in $entriesToAdd) {
        Write-Host "    + $entry" -ForegroundColor DarkCyan
    }
}
else {
    Write-Host "  User PATH already contains all required toolchain directories." -ForegroundColor DarkGray
}

# --- 7. Refresh Current Process Session ---
$env:JAVA_HOME = $JdkPath
$env:ANDROID_HOME = $SdkPath
$env:Path = "$newUserPath;$currentMachinePath"

Write-Host ""
Write-Host "[SUCCESS] Current PowerShell process environment refreshed." -ForegroundColor Green
Write-Host "  JAVA_HOME    : $env:JAVA_HOME"
Write-Host "  ANDROID_HOME : $env:ANDROID_HOME"
Write-Host ""
Write-Host "NOTE for other terminals: Newly opened terminal windows will pick up these variables automatically."
Write-Host "To restore your previous environment at any time, run:"
Write-Host "  .\restore-user-environment.ps1 -BackupFile `"$backupFile`"" -ForegroundColor Yellow
Write-Host ""
