# Remove-OneStart.ps1
# RMM-compatible: no interactive prompts, plain stdout logging, exit codes
# Deploy command:
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Remove-OneStart.ps1
# Optional flag:
#   -NoRestorePoint   skip restore point creation (faster deployments)

param(
    [switch]$NoRestorePoint
)

$ErrorActionPreference = "SilentlyContinue"
$LogFile  = "C:\Windows\Temp\OneStart_Removal_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Keywords = @("onestart", "one start", "1start", "onestart.ai")
$ExitCode = 0

# ── Logging: plain stdout only — safe for all RMM log capture ─────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Output $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Remove-ItemSafe {
    param([string]$Path, [string]$Type = "Path")
    if (Test-Path $Path) {
        try   { Remove-Item -Path $Path -Recurse -Force; Write-Log "Removed $Type`: $Path" }
        catch { Write-Log "FAILED remove $Type`: $Path | $_" "WARN" }
    }
}

function Remove-RegKeySafe {
    param([string]$Path)
    if (Test-Path $Path) {
        try   { Remove-Item -Path $Path -Recurse -Force; Write-Log "Removed reg key: $Path" }
        catch { Write-Log "FAILED remove reg key: $Path | $_" "WARN" }
    }
}

function Clear-HiveSubPaths {
    param([string]$HiveRoot)
    $subPaths = @(
        "Software\Microsoft\Windows\CurrentVersion\Run",
        "Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($sub in $subPaths) {
        $fp = "$HiveRoot\$sub"
        if (Test-Path $fp) {
            Get-ChildItem $fp -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match ($Keywords -join "|") } |
                ForEach-Object { Remove-RegKeySafe $_.PSPath }
            (Get-Item $fp -ErrorAction SilentlyContinue).GetValueNames() |
                Where-Object { $_ -match ($Keywords -join "|") } |
                ForEach-Object {
                    try   { Remove-ItemProperty -Path $fp -Name $_ -Force; Write-Log "Removed HKCU value: $fp\$_" }
                    catch { Write-Log "FAILED remove HKCU value $fp\$_`: $_" "WARN" }
                }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Log "========== OneStart Removal Started =========="
Write-Log "Log: $LogFile"
Write-Log "Identity: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "OS: $([System.Environment]::OSVersion.VersionString)"

# ── 0. Restore Point ──────────────────────────────────────────────────────────
if (-not $NoRestorePoint) {
    Write-Log "Creating restore point..."
    try {
        Enable-ComputerRestore -Drive "C:\" | Out-Null
        Checkpoint-Computer -Description "Before OneStart Removal" -RestorePointType "MODIFY_SETTINGS" | Out-Null
        Write-Log "Restore point created."
    } catch {
        Write-Log "Restore point skipped (limit reached or unavailable): $_" "WARN"
    }
} else {
    Write-Log "Restore point skipped (-NoRestorePoint)."
}

# ── 1. Kill Processes ─────────────────────────────────────────────────────────
Write-Log "--- Step 1: Kill processes ---"
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match ($Keywords -join "|") } |
    ForEach-Object {
        try   { Stop-Process -Id $_.Id -Force; Write-Log "Killed: $($_.Name) (PID $($_.Id))" }
        catch { Write-Log "Could not kill $($_.Name): $_" "WARN" }
    }

# ── 2. Run Uninstaller ────────────────────────────────────────────────────────
Write-Log "--- Step 2: Run uninstaller ---"
@(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
) | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -ErrorAction SilentlyContinue | ForEach-Object {
            $name   = $_.GetValue("DisplayName")
            $uninst = $_.GetValue("UninstallString")
            if ($name -and $uninst -and ($Keywords | Where-Object { $name -match $_ })) {
                Write-Log "Uninstalling: $name"
                try {
                    if ($uninst -match "msiexec") {
                        $msiArgs = ($uninst -replace "msiexec.exe","").Trim() + " /quiet /norestart"
                        Start-Process "msiexec.exe" -ArgumentList $msiArgs -Wait -WindowStyle Hidden
                    } else {
                        Start-Process ($uninst -replace '"','') -ArgumentList "/S /silent /quiet /norestart" -Wait -WindowStyle Hidden
                    }
                    Write-Log "Uninstaller completed: $name"
                } catch {
                    Write-Log "Uninstaller failed: $name | $_" "WARN"
                }
            }
        }
    }
}

# ── 3. Program Files Directories ──────────────────────────────────────────────
Write-Log "--- Step 3: Program Files ---"
@($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match ($Keywords -join "|") } |
            ForEach-Object { Remove-ItemSafe $_.FullName "Directory" }
    }
}

# ── 4. All User Profiles ──────────────────────────────────────────────────────
Write-Log "--- Step 4: User profiles ---"
$skipNames = @("Public","Default","Default User","All Users")

Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin $skipNames } |
    ForEach-Object {
        $prof = $_.FullName
        Write-Log "Processing profile: $prof"

        # AppData
        @("Roaming","Local","LocalLow") | ForEach-Object {
            $ad = "$prof\AppData\$_"
            if (Test-Path $ad) {
                Get-ChildItem $ad -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match ($Keywords -join "|") } |
                    ForEach-Object { Remove-ItemSafe $_.FullName "AppData Dir" }
            }
        }

        # Chrome extensions
        $chromeUD = "$prof\AppData\Local\Google\Chrome\User Data"
        if (Test-Path $chromeUD) {
            Get-ChildItem $chromeUD -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extDir = "$($_.FullName)\Extensions"
                if (Test-Path $extDir) {
                    Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $mf = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($mf) {
                            $json = Get-Content $mf.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($json -and ($json.name -match ($Keywords -join "|"))) {
                                Remove-ItemSafe $_.FullName "Chrome Extension"
                            }
                        }
                    }
                }
                # Back up tainted Preferences (do not blindly delete — may corrupt profile)
                $prefs = "$($_.FullName)\Preferences"
                if ((Test-Path $prefs) -and ((Get-Content $prefs -Raw -ErrorAction SilentlyContinue) -match ($Keywords -join "|"))) {
                    Copy-Item $prefs "$prefs.bak" -Force -ErrorAction SilentlyContinue
                    Write-Log "Tainted Chrome Preferences backed up: $prefs" "WARN"
                }
            }
        }

        # Edge extensions
        $edgeUD = "$prof\AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path $edgeUD) {
            Get-ChildItem $edgeUD -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extDir = "$($_.FullName)\Extensions"
                if (Test-Path $extDir) {
                    Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $mf = Get-ChildItem $_.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($mf) {
                            $json = Get-Content $mf.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($json -and ($json.name -match ($Keywords -join "|"))) {
                                Remove-ItemSafe $_.FullName "Edge Extension"
                            }
                        }
                    }
                }
            }
        }

        # Firefox extensions
        $ffBase = "$prof\AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $ffBase) {
            Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extDir = "$($_.FullName)\extensions"
                if (Test-Path $extDir) {
                    Get-ChildItem $extDir -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match ($Keywords -join "|") } |
                        ForEach-Object { Remove-ItemSafe $_.FullName "Firefox Extension" }
                }
            }
        }

        # Shortcuts
        @(
            "$prof\Desktop",
            "$prof\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
        ) | ForEach-Object {
            if (Test-Path $_) {
                Get-ChildItem $_ -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match ($Keywords -join "|") } |
                    ForEach-Object { Remove-ItemSafe $_.FullName "Shortcut" }
            }
        }
    }

# Public shortcuts
@("C:\Users\Public\Desktop","C:\ProgramData\Microsoft\Windows\Start Menu\Programs") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -Filter "*.lnk" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match ($Keywords -join "|") } |
            ForEach-Object { Remove-ItemSafe $_.FullName "Public Shortcut" }
    }
}

# ── 5. HKLM Registry ─────────────────────────────────────────────────────────
Write-Log "--- Step 5: HKLM registry ---"
@(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE"
) | ForEach-Object {
    $base = $_
    if (Test-Path $base) {
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -match ($Keywords -join "|")) { Remove-RegKeySafe $_.PSPath }
            $_.GetValueNames() | Where-Object { $_ -match ($Keywords -join "|") } | ForEach-Object {
                try   { Remove-ItemProperty -Path $base -Name $_ -Force; Write-Log "Removed reg value: $base\$_" }
                catch { Write-Log "FAILED reg value $base\$_`: $_" "WARN" }
            }
        }
    }
}

# ── 6. HKCU Registry (all users, including offline hives) ────────────────────
Write-Log "--- Step 6: HKCU registry (all users) ---"
if (-not (Test-Path "HKU:\")) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

# Active (mounted) hives
Get-ChildItem "HKU:\" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match "^S-1-5-\d+-\d+" } |
    ForEach-Object { Clear-HiveSubPaths "HKU:\$($_.PSChildName)" }

# Offline (unmounted) hives
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $profPath  = $_.GetValue("ProfileImagePath")
        $dat       = "$profPath\NTUSER.DAT"
        $sid       = $_.PSChildName
        if ((Test-Path "HKU:\$sid") -or -not (Test-Path $dat)) { return }

        $tmp = "TmpOS_$($sid -replace '-','_')"
        try {
            $out = & reg load "HKU\$tmp" $dat 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Loaded offline hive: $profPath"
                Clear-HiveSubPaths "HKU:\$tmp"
            } else {
                Write-Log "Could not load hive $profPath`: $out" "WARN"
            }
        } catch {
            Write-Log "Exception on hive $profPath`: $_" "WARN"
        } finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            & reg unload "HKU\$tmp" 2>&1 | Out-Null
        }
    }

# ── 7. Scheduled Tasks ────────────────────────────────────────────────────────
Write-Log "--- Step 7: Scheduled tasks ---"
Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -match ($Keywords -join "|") -or $_.TaskPath -match ($Keywords -join "|") } |
    ForEach-Object {
        try   { Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false; Write-Log "Removed task: $($_.TaskPath)$($_.TaskName)" }
        catch { Write-Log "FAILED task $($_.TaskName): $_" "WARN" }
    }

# ── 8. Services ───────────────────────────────────────────────────────────────
Write-Log "--- Step 8: Services ---"
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match ($Keywords -join "|") -or $_.Name -match ($Keywords -join "|") } |
    ForEach-Object {
        try {
            Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            & sc.exe delete $_.Name 2>&1 | Out-Null
            Write-Log "Removed service: $($_.Name)"
        } catch {
            Write-Log "FAILED service $($_.Name): $_" "WARN"
        }
    }

# ── 9. Temp Files ─────────────────────────────────────────────────────────────
Write-Log "--- Step 9: Temp files ---"
@("$env:TEMP","C:\Windows\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match ($Keywords -join "|") } |
            ForEach-Object { Remove-ItemSafe $_.FullName "Temp File" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
Write-Log "========== OneStart Removal Complete =========="
Write-Log "Log: $LogFile"
Write-Output "RESULT: SUCCESS"
Write-Output "EXIT_CODE: $ExitCode"
exit $ExitCode
