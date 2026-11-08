<#
.SYNOPSIS
    Restores the exact original user environment variables (JAVA_HOME, ANDROID_HOME, and User PATH)
    from a protected backup JSON file created by configure-user-environment.ps1.

.DESCRIPTION
    This script performs a complete rollback of AppShield environment modifications:
      1. Locates the specified backup file or finds the most recent backup in the backup directory.
      2. Validates that the backup file exists, is well-formed JSON, and contains the required keys.
      3. Restores user-scope JAVA_HOME to its exact original value (or clears it if originally unset).
      4. Restores user-scope ANDROID_HOME to its exact original value (or clears it if originally unset).
      5. Restores user-scope PATH to its exact original value.
      6. Refreshes the current PowerShell process environment immediately.
      7. Supports -Preview mode to show what would be restored without modifying the system.
      8. Strictly preserves Machine PATH and all system-wide environment configurations without mutation.

.PARAMETER BackupFile
    Path to the backup JSON file. If omitted, the script automatically searches for the most recent
    backup file in $env:USERPROFILE\.appshield\backup\.

.PARAMETER Preview
    Safe dry-run mechanism. If specified, displays the exact values that would be restored without applying any changes.

.EXAMPLE
    .\restore-user-environment.ps1 -Preview
    Shows what would be restored from the most recent backup without applying changes.

.EXAMPLE
    .\restore-user-environment.ps1
    Restores original environment variables from the most recent backup file.

.EXAMPLE
    .\restore-user-environment.ps1 -BackupFile "$env:USERPROFILE\.appshield\backup\environment_backup_20261103_120000.json"
    Restores original environment variables from a specific backup file.
#>

[CmdletBinding()]
param(
    [string]$BackupFile,
    [switch]$Preview
)

$ErrorActionPreference = "Stop"

$DefaultBackupDir = Join-Path $env:USERPROFILE ".appshield\backup"

# --- 1. Locate Backup File ---
if (-not $BackupFile) {
    if (-not (Test-Path $DefaultBackupDir)) {
        throw "No backup directory found at '$DefaultBackupDir'. Cannot perform automatic restoration."
    }

    $candidateBackups = Get-ChildItem -Path $DefaultBackupDir -Filter "environment_backup_*.json" | Sort-Object -Property LastWriteTime -Descending
    if (-not $candidateBackups -or $candidateBackups.Count -eq 0) {
        throw "No environment backup files found in '$DefaultBackupDir'. Please specify -BackupFile explicitly."
    }

    $BackupFile = $candidateBackups[0].FullName
    Write-Host "[INFO] Automatically selected most recent backup: '$BackupFile'" -ForegroundColor Cyan
}

if (-not (Test-Path $BackupFile -PathType Leaf)) {
    throw "Specified backup file does not exist: '$BackupFile'"
}

# --- 2. Read and Validate Backup Data ---
Write-Host "Reading backup file: '$BackupFile'..." -ForegroundColor Cyan
try {
    $rawJson = [System.IO.File]::ReadAllText($BackupFile, [System.Text.Encoding]::UTF8)
    $backupData = $rawJson | ConvertFrom-Json
}
catch {
    throw "Failed to parse backup JSON file '$BackupFile': $_"
}

# Validate required structure
$requiredKeys = @("timestamp", "user_java_home", "user_android_home", "user_path")
foreach ($key in $requiredKeys) {
    if (-not (Get-Member -InputObject $backupData -Name $key)) {
        throw "Corrupt or incomplete backup file: missing required key '$key' in '$BackupFile'."
    }
}

$origJavaHome    = $backupData.user_java_home
$origAndroidHome = $backupData.user_android_home
$origUserPath    = $backupData.user_path
$backupTimestamp = $backupData.timestamp

# Gather current state for comparison
$currentJavaHome    = [Environment]::GetEnvironmentVariable("JAVA_HOME", [EnvironmentVariableTarget]::User)
$currentAndroidHome = [Environment]::GetEnvironmentVariable("ANDROID_HOME", [EnvironmentVariableTarget]::User)
$currentUserPath    = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
$currentMachinePath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)

# --- 3. Preview Mode ---
if ($Preview) {
    Write-Host "`n=== AppShield Environment Restoration (PREVIEW MODE) ===" -ForegroundColor Magenta
    Write-Host "Backup Timestamp: $backupTimestamp"
    Write-Host "Backup Source   : $BackupFile"
    Write-Host ""
    Write-Host "Proposed Restoration Actions:" -ForegroundColor Yellow
    Write-Host "  JAVA_HOME:"
    Write-Host "    Current  : $(if ($currentJavaHome) { $currentJavaHome } else { '<Not Set>' })"
    Write-Host "    Restore To: $(if ($origJavaHome) { $origJavaHome } else { '<Unset / Null>' })"
    Write-Host ""
    Write-Host "  ANDROID_HOME:"
    Write-Host "    Current  : $(if ($currentAndroidHome) { $currentAndroidHome } else { '<Not Set>' })"
    Write-Host "    Restore To: $(if ($origAndroidHome) { $origAndroidHome } else { '<Unset / Null>' })"
    Write-Host ""
    Write-Host "  User PATH:"
    Write-Host "    Current Entry Count: $(if ($currentUserPath) { ($currentUserPath -split ';').Count } else { 0 })"
    Write-Host "    Restore Entry Count: $(if ($origUserPath) { ($origUserPath -split ';').Count } else { 0 })"
    Write-Host ""
    Write-Host "  System Machine PATH: strictly preserved ($($currentMachinePath.Length) characters)."
    Write-Host ""
    Write-Host "To execute this restoration, run .\restore-user-environment.ps1 without -Preview."
    return
}

# --- 4. Apply Restoration ---
Write-Host "`n=== AppShield Environment Restoration ===" -ForegroundColor Cyan
Write-Host "Restoring environment from backup taken at: $backupTimestamp" -ForegroundColor Cyan

# Restore JAVA_HOME
if ($origJavaHome) {
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $origJavaHome, [EnvironmentVariableTarget]::User)
    $env:JAVA_HOME = $origJavaHome
    Write-Host "  [OK] Restored User JAVA_HOME = '$origJavaHome'" -ForegroundColor Green
}
else {
    # Remove from Windows User registry and current process
    [Environment]::SetEnvironmentVariable("JAVA_HOME", $null, [EnvironmentVariableTarget]::User)
    Remove-Item Env:JAVA_HOME -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cleared User JAVA_HOME from registry (was originally unset)" -ForegroundColor Green
}

# Restore ANDROID_HOME
if ($origAndroidHome) {
    [Environment]::SetEnvironmentVariable("ANDROID_HOME", $origAndroidHome, [EnvironmentVariableTarget]::User)
    $env:ANDROID_HOME = $origAndroidHome
    Write-Host "  [OK] Restored User ANDROID_HOME = '$origAndroidHome'" -ForegroundColor Green
}
else {
    # Remove from Windows User registry and current process
    [Environment]::SetEnvironmentVariable("ANDROID_HOME", $null, [EnvironmentVariableTarget]::User)
    Remove-Item Env:ANDROID_HOME -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cleared User ANDROID_HOME from registry (was originally unset)" -ForegroundColor Green
}

# Restore User PATH
if ($origUserPath) {
    [Environment]::SetEnvironmentVariable("Path", $origUserPath, [EnvironmentVariableTarget]::User)
    Write-Host "  [OK] Restored User PATH to exact original value ($((($origUserPath -split ';').Count)) entries)." -ForegroundColor Green
}
else {
    [Environment]::SetEnvironmentVariable("Path", $null, [EnvironmentVariableTarget]::User)
    Write-Host "  [OK] Cleared User PATH from registry (was originally unset)." -ForegroundColor Green
}

# Refresh process PATH
$env:Path = if ($origUserPath) { "$origUserPath;$currentMachinePath" } else { $currentMachinePath }

Write-Host ""
Write-Host "[SUCCESS] User environment successfully restored to original pre-AppShield state." -ForegroundColor Green
Write-Host "Current process session has been refreshed." -ForegroundColor Green
Write-Host "Backup file retained for reference: '$BackupFile'" -ForegroundColor DarkGray
Write-Host ""
