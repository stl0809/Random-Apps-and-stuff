
<# 
.SYNOPSIS
Scan local user profiles (C:\Users\*) on this machine for AppData\Local\Apps\Remote Desktop\msrdcw.exe.
Outputs results to console only. Optional removal of the "Remote Desktop" folder if msrdcw.exe is found.

.PARAMETER UsersRoot
Root folder that contains local user profiles (default: C:\Users)

.PARAMETER IncludeHiddenProfiles
Include hidden/system-like profile folders (default: excluded)

.PARAMETER ShowErrors
Print an error summary at the end

.PARAMETER VerboseFileInfo
Print per-file details (version, size, timestamps) when found

.PARAMETER RemoveFound
If specified, remove the "Remote Desktop" folder for profiles where msrdcw.exe is found.
Respects -WhatIf and -Confirm.

.NOTES
- Run in an elevated PowerShell prompt (Administrator) for best coverage and removal capability.
- Removal target: <Profile>\AppData\Local\Apps\Remote Desktop
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$UsersRoot = "C:\Users",
    [switch]$IncludeHiddenProfiles,
    [switch]$ShowErrors,
    [switch]$VerboseFileInfo,
    [switch]$RemoveFound
)

# Profiles to skip by default (system/stock profiles)
$defaultSkips = @('Default', 'Default User', 'Public', 'All Users', 'WDAGUtilityAccount', 'Administrator')

Write-Host "Scanning local profiles under: $UsersRoot" -ForegroundColor Cyan

# Discover candidate profile directories
$profileDirs = Get-ChildItem -Path $UsersRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
    if ($IncludeHiddenProfiles) { 
        $true 
    } else {
        $_.Name -notin $defaultSkips -and -not ($_.Attributes -band [IO.FileAttributes]::Hidden) -and -not ($_.Attributes -band [IO.FileAttributes]::System)
    }
}

if (-not $profileDirs -or $profileDirs.Count -eq 0) {
    Write-Host "No user profile directories found under $UsersRoot." -ForegroundColor Yellow
    return
}

$results = New-Object System.Collections.Generic.List[object]
$errors  = New-Object System.Collections.Generic.List[string]
$removed = New-Object System.Collections.Generic.List[string]

foreach ($dir in $profileDirs) {
    $userName     = $dir.Name
    $profilePath  = $dir.FullName
    $rdFolderPath = Join-Path -Path $profilePath -ChildPath "AppData\Local\Apps\Remote Desktop"
    $targetPath   = Join-Path -Path $rdFolderPath -ChildPath "msrdcw.exe"

    $exists    = $false
    $version   = $null
    $size      = $null
    $lastWrite = $null
    $errorMsg  = $null

    try {
        if (Test-Path -LiteralPath $targetPath -PathType Leaf) {
            $exists = $true
            $file = Get-Item -LiteralPath $targetPath -ErrorAction Stop
            $version   = $file.VersionInfo.FileVersion
            $size      = $file.Length
            $lastWrite = $file.LastWriteTime

            if ($VerboseFileInfo) {
                Write-Host ("Found for {0}: {1}" -f $userName, $targetPath) -ForegroundColor Green
                Write-Host ("  Version: {0} | Size: {1} bytes | Modified: {2}" -f $version, $size, $lastWrite) -ForegroundColor DarkGray
            }

            if ($RemoveFound) {
                # Remove the containing Remote Desktop folder
                if (Test-Path -LiteralPath $rdFolderPath -PathType Container) {
                    try {
                        if ($PSCmdlet.ShouldProcess($rdFolderPath, "Remove Remote Desktop folder recursively")) {
                            Remove-Item -LiteralPath $rdFolderPath -Recurse -Force -ErrorAction Stop
                            Write-Host ("Removed folder for {0}: {1}" -f $userName, $rdFolderPath) -ForegroundColor Yellow
                            $removed.Add(("{0} -> {1}" -f $userName, $rdFolderPath))
                        }
                    } catch {
                        $err = $_.Exception.Message
                        Write-Warning ("Failed to remove for {0}: {1}" -f $userName, $err)
                        $errors.Add(("[{0}] removal: {1}" -f $userName, $err))
                    }
                }
            }
        } else {
            Write-Host ("Not found for {0}" -f $userName) -ForegroundColor DarkYellow
        }
    } catch {
        $errorMsg = $_.Exception.Message
        $errors.Add(("[{0}] {1}" -f $userName, $errorMsg))
    }

    $results.Add([pscustomobject]@{
        UserName      = $userName
        ProfilePath   = $profilePath
        Exists        = $exists
        FullPath      = $targetPath
        FileVersion   = $version
        SizeBytes     = $size
        LastWriteTime = $lastWrite
        Error         = $errorMsg
        RemovedFolder = if ($exists -and ($removed | Where-Object { $_ -like "$userName*"})) { $true } else { $false }
    })
}

# Table of results
Write-Host "`n=== Results ===" -ForegroundColor Cyan
$results | Sort-Object UserName | Format-Table UserName, Exists, FileVersion, SizeBytes, LastWriteTime, FullPath, RemovedFolder -AutoSize

# Summary
$foundCount   = ($results | Where-Object { $_.Exists }).Count
$totalCount   = $results.Count
$removedCount = ($results | Where-Object { $_.RemovedFolder }).Count
Write-Host ("`nSummary: Found msrdcw.exe in {0} of {1} profiles" -f $foundCount, $totalCount) -ForegroundColor Cyan
if ($RemoveFound) {
    Write-Host ("Folders removed: {0}" -f $removedCount) -ForegroundColor Yellow
}

# Errors (optional)
if ($ShowErrors) {
    if ($errors.Count -gt 0) {
        Write-Host "`nErrors encountered:" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkRed }
    } else {
        Write-Host "`nNo errors encountered." -ForegroundColor Green
    }
}
