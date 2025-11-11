<#
.SYNOPSIS
    Installs the Cisco Secure client and selected modules with an option to hide them from the Add/Remove Programs List.
.EXAMPLE
    PS C:\> Install-CiscoSecureClient.ps1 -Source 'https://downloadpath/CiscoSecureClient.zip' -Dart -Nvm -Posture
        Will install the Diagnostics and Reporting, VPN Posture (HostScan) and Network Visibility Modules.
    PS C:\> Install-CiscoSecureClient.ps1 -Source 'https://downloadpath/CiscoSecureClient.zip' -Core -Umbrella -Dart -Nvm -UserID 1234567 -Fingerprint oash098ashuiue -OrgId 394058
        Will install the Core VPN module (keeping it hidden from the end-user), Umbrella, Diagnostics and Reporting, and Network Visibility Modules.
        Because Umbrella is being installed, the UserID, Fingerprint, and OrgId are required.
    PS C:\> Install-CiscoSecureClient.ps1 -Source 'https://downloadpath/CiscoSecureClient.zip' -Core -ShowVPN -Umbrella -Dart -Nvm -UserID 1234567 -Fingerprint oash098ashuiue -OrgId 394058
        Will install the Core VPN module (Visible to the end-user in the system tray icon), Umbrella, Diagnostics and Reporting, and Network Visibility Modules.
        Because Umbrella is being installed, the UserID, Fingerprint, and OrgId are required.
    PS C:\> Install-CiscoSecureClient.ps1 -Source 'C:\PATH\TO\FILE' -All -UserID 1234567 -Fingerprint oash098ashuiue -OrgId 394058 -ARP
        This will install all Modules, including Umbrella, which require the UserID, Fingerprint, and OrgId to be provided, and hide the installation from the Add/Remove Programs List.
        Programmatically creates a JSON authentication file for access by the Umbrella module.
.PARAMETER Source
    The URL or local filesystem path to the Cisco Secure Client installation package.
.PARAMETER UserID
    Used to Generate the JSON on the endpoint needed by Umbrella. Required by -Umbrella and -All switches. Provided by the end-user from their Cisco dashboard, or their JSON.
.PARAMETER Fingerprint
    Used to Generate the JSON on the endpoint needed by Umbrella. Required by -Umbrella and -All switches. Provided by the end-user from their Cisco dashboard, or their JSON.
.PARAMETER OrgId
    Used to Generate the JSON on the endpoint needed by Umbrella. Required by -Umbrella and -All switches. Provided by the end-user from their Cisco dashboard, or their JSON.
.PARAMETER ShowVPN
    Used for Showing the VPN tray icon. Optional with -Core and -All switches.
.PARAMETER ARP
    Hides the installed Cisco Secure Client modules from the Add/Remove Programs list. Optional.
.PARAMETER Lockdown
    Prevents Cisco Secure Client services from being modified. Administrators are not exempt from this lockdown. Optional.
.PARAMETER All
    Installs all modules. Cannot be combined with specific module selections or Core-Only installation. Requires Client ID, Org ID, and Fingerprint.
.PARAMETER <ModuleName>
    Installs the core VPN Module, along with specified module names.
    The allowed parameter names are:
        Core (The ShowVPN switch reveals the module in the system tray icon after installation; by default, the script keeps it hidden.)
        Sbl
        Dart
        Nam
        Nvm
        IsePosture
        Posture
        Umbrella (Requires Client ID, Org ID, and Fingerprint)
.OUTPUTS
    Install-CiscoSecureClient-log.txt
    Install-CiscoSecureClient-Error.txt
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'All')][switch]$All,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Core,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Sbl,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Dart,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Nam,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Nvm,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Posture,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$IsePosture,
    [Parameter(Mandatory = $false, ParameterSetName = 'Custom')][switch]$Umbrella,
    [Parameter(Mandatory = $false)][switch]$ARP,
    [Parameter(Mandatory = $false)][switch]$Lockdown,
    [Parameter(Mandatory = $true, ParameterSetName = 'All')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Custom')]
    [Alias('DownloadURL')]
    [String]$Source
)

DynamicParam {
    if ($Umbrella -or $All -or $Core) {
        $ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        if ($Umbrella -or $All) {
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $Attributes.Mandatory = $true
            $AttributeCollection.Add($Attributes)
            $fingerprintParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('fingerprint', [string], $AttributeCollection)
            $UserIDParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('UserID', [string], $AttributeCollection)
            $orgIdParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('orgId', [string], $AttributeCollection)
            $ParamDictionary.Add('fingerprint', $fingerprintParameter)
            $ParamDictionary.Add('UserID', $UserIDParameter)
            $ParamDictionary.Add('orgId', $orgIdParameter)
        }
        if ($Core -or $All) {
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $Attributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $Attributes.Mandatory = $false
            $AttributeCollection.Add($Attributes)
            $ShowVPNParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('ShowVPN', [Switch], $AttributeCollection)
            $ParamDictionary.Add('ShowVPN', $ShowVPNParameter)
        }
        return $ParamDictionary
    }
}

Begin {
    ### Region Strapper ###
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    Get-PackageProvider -Name NuGet -ForceBootstrap | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    try {
        Update-Module -Name Strapper -ErrorAction Stop
    } catch {
        Install-Module -Name Strapper -Repository PSGallery -SkipPublisherCheck -Force
        Get-Module -Name Strapper -ListAvailable | Where-Object { $_.Version -ne (Get-InstalledModule -Name Strapper).Version } | ForEach-Object { Uninstall-Module -Name Strapper -MaximumVersion $_.Version }
    }
    (Import-Module -Name 'Strapper') 3>&1 2>&1 1>$null
    Set-StrapperEnvironment
    #endregion

    $appDir = "$env:ProgramData\Cisco\Cisco Secure Client\"

    # Determine if Source is a URL or a local path
    if ($Source -match '^(http|https|ftp)://') {
        Write-Log -Level Information -Text "Downloading installation files from URL: $Source"
        $downloadPath = "$env:TEMP\CiscoInstallerFiles"
        New-Item -Type Directory -Path $downloadPath -Force | Out-Null
        $zipPath = Join-Path -Path $downloadPath -ChildPath 'wininstall.zip'
        try {
            (New-Object System.Net.WebClient).DownloadFile($Source, $zipPath)
            Expand-Archive -Path $zipPath -DestinationPath $downloadPath -Force
            Remove-Item $zipPath
            $installerFiles = Get-ChildItem -Recurse "$downloadPath\"
        } catch {
            Write-Log -Level Error -Text "Failed to download or extract the installation files: $_"
            throw $_
        }
    } elseif (Test-Path $Source -PathType Leaf) {
        if ($Source -like '*.zip') {
            Write-Log -Level Information -Text "Zip file detected: $Source"
            $tempExtractPath = Join-Path -Path $env:TEMP -ChildPath ([System.IO.Path]::GetRandomFileName())
            New-Item -Type Directory -Path $tempExtractPath -Force | Out-Null
            Write-Log -Level Information -Text "Extracting zip file to $tempExtractPath"
            Expand-Archive -Path $Source -DestinationPath $tempExtractPath -Force
            $installerFilesPath = $tempExtractPath
        } else {
            $installerFilesPath = $Source
        }
        if (-not (Test-Path "$installerFilesPath\\cisco-secure-client-win*" -Type Leaf)) {
            Write-Log -Level Error -Text "The specified local path does not contain valid installation files: $installerFilesPath"
            throw 'Invalid local installation files path.'
        }
        $installerFiles = Get-ChildItem -Recurse "$installerFilesPath\\"
    } else {
        Write-Log -Level Fatal -Text 'Source must be a valid URL or a local file path.'
        throw 'Source must be a valid URL or a local file path.'
    }
}

Process {
    if ($All) {
        $targetModules = @('core-vpn', 'sbl', 'dart', 'iseposture', 'nam', 'nvm', 'posture', 'umbrella')
    } else {
        $targetModules = @()
        if ($Core) { $targetModules += 'core-vpn' }
        if ($Sbl) { $targetModules += 'sbl' }
        if ($Dart) { $targetModules += 'dart' }
        if ($IsePosture) { $targetModules += 'iseposture' }
        if ($Nam) { $targetModules += 'nam' }
        if ($Nvm) { $targetModules += 'nvm' }
        if ($Posture) { $targetModules += 'posture' }
        if ($Umbrella) { $targetModules += 'umbrella' }
    }
    foreach ($module in $targetModules) {
        if ($module -eq 'umbrella') {
            # Write JSON based on Client and Organization if Umbrella is being installed.
            $jsonDir = "$appDir\Umbrella"
            Write-Log -Level Information -Text 'Umbrella module selected for installation. Creating directories and JSON file.'
            New-Item -Path $appDir -Name 'Umbrella' -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Remove-Item "$jsonDir\OrgInfo.json" -ErrorAction SilentlyContinue
            @{
                organizationId = "$($orgIdParameter.Value)"
                fingerprint = "$($fingerprintParameter.Value)"
                userId = "$($UserIDParameter.Value)"
            } | ConvertTo-Json | Out-File "$jsonDir\OrgInfo.json"
        }
        $installerFile = $installerFiles | Where-Object { $_.BaseName -match "cisco-secure-client-win*.*-$module-" }
        if ($installerFile) {
            Write-Log -Level Information -Text "Installing $module module."
            # Build the installation command.
            $installArgs = "/i ""$($installerFile.FullName)"" /qn /norestart"
            if ($module -in ('core-vpn', 'umbrella') -and -not $ShowVPNParameter.value.Ispresent) {
                $installArgs += ' PRE_DEPLOY_DISABLE_VPN=1'
            }
            if ($ARP) {
                $installArgs += ' ARPSYSTEMCOMPONENT=1'
            }
            if ($Lockdown) {
                $installArgs += ' LOCKDOWN=1'
            }
            # Execute the installation.
            $exitCode = (Start-Process 'C:\Windows\System32\msiexec.exe' -ArgumentList $installArgs -Wait -PassThru).ExitCode
            if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                Write-Log -Level Error -Text "MSI Installation of module $module failed with exit code $exitCode"
            } elseif ($exitCode -eq 3010) {
                Write-Log -Level Information -Text "Module $module installed, however a reboot is necessary to complete this installation."
            } else {
                Write-Log -Level Information -Text "Module $module installed."
            }
        } else {
            Write-Log -Level Error -Text "Module $module was specified for install but was not found in the source directory. Validate the parameters/source."
        }
    }
}

End { }


# SIG # Begin signature block
# MIIlqQYJKoZIhvcNAQcCoIIlmjCCJZYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBq0Pj+H8Weuu9D
# jUDhzcHYXs+I9iUzEdS9myjMT7Zuj6CCEvMwggXdMIIDxaADAgECAgh7LJvTFoAy
# mTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjAyMTIxNzM5MzlaFw00MTAyMTIxNzM5MzlaMHwxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENv
# cnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkgUlNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/d
# oyt9y9Aq/uxnhabnLhu6d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aU
# nheDhc5W7/IW/QBi9SIJVOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q
# 6Pw/YUjtsAMUHRAOSxngu07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg
# +sglkrRueiLH+B6h47LdkTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qh
# k4jrwZe8jPkd2SKEJHTHBD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmyl
# D0CGfAL0XAJPKMuucZ8POsgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUu
# qfqeLLZRRv2vA9bqYGjqhRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiY
# ohgsQkCz+W84J0tOgPQ9gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZT
# NTX8N+TD9l0WviFz3pIK+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZ
# X5es6+8uyLzXG1k8K8zyGciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumam
# du0bc+sapQ3EIhMglFYKTixsTrH9z5wJuqIz7YcCAwEAAaNjMGEwHQYDVR0OBBYE
# FN0ECQei9Xp9UlMSkpXuOIAlDaZZMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAU3QQJB6L1en1SUxKSle44gCUNplkwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3
# DQEBCwUAA4ICAQAgGBGUKfsmnRweHnBh8ZVyk3EkrWiTWI4yrxuzcAP8JSt0hZA9
# eGr0uYullzu1GJG7Hqf5QFuR+VWZrx4R0Fwdp2bjsZQHDDI5puobsHnYHZxwROOK
# 3cT5lR+KOEM/AYWlR6c9RrK85SJo93uc2Cw+CiHILTOsv8WBmTF0wXVxxb6x8CNF
# 9J1r/BljnaO8BMYYCyW7U4kPs4BQ3kXuRH+rlHhkmNP2KN2H2HBldPsOuRPrpw9h
# qTKWzN677WNMGLupQPegVG4giHF1GOp6tDRy4CMnd1y2kOqGJUCr7zMPy5+CvqIg
# +/a1LRrmwoWxdA/7yGUCpFIBR91JIsG/2OtrrH7e7GMzFbcjCI/GD41BWt2OxbmP
# 5UU/eNu60htAsf5xTT/ggaK6XrTsFeCT3QgffuFVmQsh3pOeCvvmo0m9NjD+53ey
# oHWXtS2BiBdlIPfakACfyVLMMso1fPU9D9gr1/UmbMkGNJYW6nBZGjJ5eQu2iH8P
# Ukg9v2zYokQu0U63cljTiROV/kSr+NeLG26cvCygW9VqAK9fN+HV+hALmJyG5yaP
# zvDsbopXC4DjTrLAoGNhkLpVaDd0araS25+hhiK2ZScO7LafQmDkZ8K12kELxNOL
# YRu8+h+RK9dEB166KazZxenvU0ha64DxKFghzbAGVfsnP1OQcKkEHlcnuTCCBnIw
# ggRaoAMCAQICCGQzUdPHOJ8IMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVT
# MQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NM
# IENvcnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlv
# biBBdXRob3JpdHkgUlNBMB4XDTE2MDYyNDIwNDQzMFoXDTMxMDYyNDIwNDQzMFow
# eDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9u
# MREwDwYDVQQKDAhTU0wgQ29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25p
# bmcgSW50ZXJtZWRpYXRlIENBIFJTQSBSMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAJ+DE3OqsMZtIcvbi3qHdNBx3I6Xcprku4g0tN2AA8YvRaR0mr8e
# D1Dqnm1485/6USapPZ3RspRXPvs5iRuRK1bvZ8vmC+MOOYzGNfSMPd0l6QGsF0J9
# WBZA3PnVKEQdlWQwYTpk8pfXc0x9eyMCbfN161U9b6otxK++dKxd/mq2/OpceekP
# Q5y1UgUP7z6xsY/QSa2m40IZVD/zLw6hy3z+E/kjOdolHLg+AEo6bzIwN2Qex651
# B9hV0hjJDoq8o1zwfAqnhYHCDq+PmVzTYCW8g1ppHCUTzXL165yAm9wsZ8TdyQmY
# 1XPrxCGj5TKOPi9SmMZgN2SMsm9KVHIYzCeH+s11omMhTLU9ZP0rpptVryZMYLS5
# XP6rQ72t0BNmUB8L0omm/9eABvHDEQIzM2EX91Yfji87aOcV8XdWSimeA9rCKyZh
# MlugVuVJKY02p/XHUqJWAyAvOHiAvfYGrkE0y5RFvZvHiRgfC7r/qa5qQJkT3e9Q
# 3wG68gTW0DHfNDheV1vIOB5W1KxIpu3/+bjBO+3CJL5EYKd3zdU9mFm0Q+qqYH3N
# wuUv8ev11CDVlzRuXQRrBRHS05KMCSdE7U81MUZ+dBkFYuyJ4+ojcJjk0S/UihMY
# RpNl5Vhz00w9J3oiP8P4o1W3+eaHguxFHsVuOnyxTrmraPebY9WRQbypAgMBAAGj
# gfswgfgwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV
# 7jiAJQ2mWTAwBggrBgEFBQcBAQQkMCIwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nw
# cy5zc2wuY29tMBEGA1UdIAQKMAgwBgYEVR0gADATBgNVHSUEDDAKBggrBgEFBQcD
# AzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3Jscy5zc2wuY29tL3NzbC5jb20t
# cnNhLVJvb3RDQS5jcmwwHQYDVR0OBBYEFFTC/hCVAJPNavXnwNfZsku4jwzjMA4G
# A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEA9Q8mh3CvmaLK9dbJ8I1m
# PTmC04gj2IK/j1SEJ7bTgwfXnieJTYSOVNEg7mBD21dCPMewlfa+zOqjPY5PBsYr
# WYZ/63MbyuVAJuA9b8z2vXHGzX0OIEA51gXSr5QIv3/CUbcrtXuDIfBj2uWc4Wku
# dR1Oy2Ee9aUz3wKdFdntaZNXukZFLoC8Zb7nEj7eR/+QnBCt9laypNT61vwuvJch
# s3aD0pH6BlDRsYAogP7brQ9n7fh93NlwW3q6aLWzSmYXj+fw51fdaf68XuHVjJ8T
# u5WaFft5K4XVbT5nR24bB1z7VEUPFhEuEcOwvLVuHDNXlB7+QjRGjjFQTtszV5X6
# OOTmEturWC5Ft9kiyvRaR0ksKOhPjEI8ZGjp5kOsGZGpxxOCX/xxCje3nVB7PF33
# olKCNeS159MKb2v+jfmk19UdS+d9Ygj42desmUnbtYRBFC72LmCXU0ua/vGIenS6
# nnXp4NqnycwsO3tMCnjPlPc2YLaDPIpUy04NaCqUEXUmFOogN8zreRd2VXhxbeJJ
# ODM32+RsWccjYua8zi5US/1eAyrI3R5LcUTQdT4xYmWLKabtJOF6HYQ0f6QXfLSs
# fT81WMvDvxrdn1RWbUXlU/OIiisxo8o+UNEANOwnCMNnxlzoaL/PLhZluDxm/zuy
# lauajZ3MlPDteFB/7GRHo50wggaYMIIEgKADAgECAhAZraEDEXkpAS0+li99ndmf
# MA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
# MA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNVBAMMK1NT
# TC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEwHhcNMjQw
# ODEyMTg1NDI0WhcNMjUwOTA2MTg1NDI0WjB/MQswCQYDVQQGEwJVUzEQMA4GA1UE
# CAwHRmxvcmlkYTEaMBgGA1UEBwwRQWx0YW1vbnRlIFNwcmluZ3MxIDAeBgNVBAoM
# F1Byb3ZhbCBUZWNobm9sb2dpZXMgSW5jMSAwHgYDVQQDDBdQcm92YWwgVGVjaG5v
# bG9naWVzIEluYzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAKr0IQn+
# /jLR4pu0N3TPJaAu31BLTo5myZZxgEqw8daUfcUC3/K20pDCwTzjIEe3Rb/5xrs5
# NQhnlCrrVslrLU2vWlWIuDzrdahSapAH66AbHc9fwsHUCdpWRKglgDoaaAo4KDYS
# yR5BkRqlS4Zc/MbH7+T4hYWrmWGd6DiuQuROdyaTLG6mu+TB7clKMSl0aakOccYl
# 23+1RNPN9QIDv3Hv6V6C6mpqPJ/z7wSnHGH/ELiGcexIGDCoWon2H9/su6nbAn/R
# FR+4iwjGeIa9a7oDFs5e6Nk0ulR/PjMHVGhxMAm1dV2Fsd2lrP1pGA15k8GWi/h+
# V6u5C1toJtnFzy8E+q45U/6zyo2PQd4HlPzw9auzy9l6X4tMtMEQD55G8TR/+VYx
# 7ruJa9VCl477XcOY99oPyaWOYiliU7NbqtYcINHNun6xyDSC3pRidNOMHkovEXmn
# 3sAEYOgDLkNo7sljfXdWd/kawVXEOtZ7WqjdKcysZEdE6MrwGRtruufFdQIDAQAB
# o4IBlTCCAZEwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRUwv4QlQCTzWr158DX
# 2bJLuI8M4zB6BggrBgEFBQcBAQRuMGwwSAYIKwYBBQUHMAKGPGh0dHA6Ly9jZXJ0
# LnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJTQS00MDk2LVIxLmNl
# cjAgBggrBgEFBQcwAYYUaHR0cDovL29jc3BzLnNzbC5jb20wUQYDVR0gBEowSDAI
# BgZngQwBBAEwPAYMKwYBBAGCqTABAwMBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8v
# d3d3LnNzbC5jb20vcmVwb3NpdG9yeTATBgNVHSUEDDAKBggrBgEFBQcDAzBNBgNV
# HR8ERjBEMEKgQKA+hjxodHRwOi8vY3Jscy5zc2wuY29tL1NTTGNvbS1TdWJDQS1D
# b2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jcmwwHQYDVR0OBBYEFFD+6iHV3C018c3s
# o1Yy1la03bfgMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEACS71
# 1+k93Ta8cJheWDeZC08n9+K/SmnKCPnp9fKAXZGg0pSpDg3aSUJUoAcDURP4pww4
# 7l8bhg2S8mtQIEKjDsMq3zsafUkP/GIfvQDRsSyCj/DWMn8AZ+1bjq/8uK+nlb3n
# NiRw1MpG8p3gPgCxmz0u++TYBCKGsgixZ02qJgyEqD8fME+fuVL9qNdbQmawixVf
# SuWQoilK0/AVarnTa6X+cr6DGhOE4ry2kIwAVv5/q+PzgxHthqIxI+o7y2KzGcla
# w1LKclFsf0CZe9Abk3BMSLY2DnIYhdCurGHJkemFKKR2SocVzSr/UvxWPIk9Zcs4
# mgxFRKrsCZwkRP6AkPYm1EOgbFATgwRCGGxl6bjZ0OxAbW39bpYeH33FGL6nV8yf
# WNonuvA/BUAqwoGPsBLWhiXcEVL1SpxRXvIwOv34Y9kZ29f+uxhIrP8S3fWkTz7k
# AS6vwXLL7woQsol5vtx1IcjEd9oeh6vlxOOzUFsSRmquH5cdwNeI6+7mz9h7oK7H
# 2hijT2kQdOZ9twkEsvvraqGTyn0C2U9ZLoN+V7tUQDh4dBCw8l1k+ynopjnzZ2aG
# VdSgq47PYPy3hhHfqyxczg+STd4GppaNh1MZb8/5s70ltLuqLhrzEikI3Q6erstb
# 2Ct/iDSjl+H3XK1fA7fZLkH/bbvkxYugmgNp1kgxghIMMIISCAIBATCBjDB4MQsw
# CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
# BgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29tIENvZGUgU2lnbmluZyBJ
# bnRlcm1lZGlhdGUgQ0EgUlNBIFIxAhAZraEDEXkpAS0+li99ndmfMA0GCWCGSAFl
# AwQCAQUAoIGvMBQGCisGAQQBgjcCAQwxBjAEoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAtBgkqhkiG
# 9w0BCTQxIDAeMA0GCWCGSAFlAwQCAQUAoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3
# DQEJBDEiBCAW2RnfAi33av0RYv2dx1eZur2TnYLITjfPg4cq6Syb2jANBgkqhkiG
# 9w0BAQsFAASCAYAoftYUSaGFJ+S6bMxZrYe/CI7CR1WCb/zQlrNLVTGINI3dnjSk
# op2EyA+Zmc1wyLPb0z98mmHWqAVq09M+bgMTV1D5GT+bUsvlKHDwhUEbEySXTSqJ
# rzb3H5dtlY/TDVNLQQkWBK4H/nrCRwrIufJ55SMhw0wwYQGH5gbF7SYVD+ssxXwV
# 1qMLDa08F/ZK08hN3XvI6GsILjFp8XvvUtX59NJ1GbwNj8I5COqd1AUSwqZw94o+
# WDuwYA/rAosdIMAul6L4Uh4oeEQ6gaAQdENcxxlchp/R5iFjuQIFIh0UYXAB3KT1
# IjQsciB9X+koJbWv8wtAv4Gr3ciXUvkcJ0Gn2JkJeb+E/xYJ+/qYgSoa2hMHNn5j
# 0gFiqg8mWKIy9p8/j5zF2oCXrY1HwBYKG9+g6QqwUYsKSfuRFDa7GnC771d1WoFL
# s8wY9WZOwLERi8oDKbD2gu5iZDlALDwQn50o+u3jirHwe84FSr8MTzPlSodB1MGY
# ghg2t7UBGHS5cDKhgg8eMIIPGgYKKwYBBAGCNwMDATGCDwowgg8GBgkqhkiG9w0B
# BwKggg73MIIO8wIBAzENMAsGCWCGSAFlAwQCATB/BgsqhkiG9w0BCRABBKBwBG4w
# bAIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUDBAIBBQAEIKNK3ixSXPK4FbaC
# 1HSw1efH+fthzCGOgHaKBw9rMysfAgh2vnZptdDMDxgPMjAyNDExMTIyMTI4MTRa
# MAMCAQECBgGTIkbtoqCCDAAwggT8MIIC5KADAgECAhBaWqzoGjVutGKGjVd94D3H
# MA0GCSqGSIb3DQEBCwUAMHMxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
# MA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNT
# TC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIFIxMB4XDTI0MDIxOTE2
# MTgxOVoXDTM0MDIxNjE2MTgxOFowbjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRl
# eGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEqMCgGA1UE
# AwwhU1NMLmNvbSBUaW1lc3RhbXBpbmcgVW5pdCAyMDI0IEUxMFkwEwYHKoZIzj0C
# AQYIKoZIzj0DAQcDQgAEp2Fy9TDpesSDFJYFQuPc6J3blG3ZMm9KYstovLdyZUBM
# AO+HIyvIPZkQvBh9XAAFTCK/DNh3WaVYJFdS1wSwfKOCAVowggFWMB8GA1UdIwQY
# MBaAFAydECWOmqcbmYdDzwh+4b2BkPTPMFEGCCsGAQUFBwEBBEUwQzBBBggrBgEF
# BQcwAoY1aHR0cDovL2NlcnQuc3NsLmNvbS9TU0wuY29tLXRpbWVTdGFtcGluZy1J
# LVJTQS1SMS5jZXIwUQYDVR0gBEowSDA8BgwrBgEEAYKpMAEDBgEwLDAqBggrBgEF
# BQcCARYeaHR0cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5MAgGBmeBDAEEAjAW
# BgNVHSUBAf8EDDAKBggrBgEFBQcDCDBGBgNVHR8EPzA9MDugOaA3hjVodHRwOi8v
# Y3Jscy5zc2wuY29tL1NTTC5jb20tdGltZVN0YW1waW5nLUktUlNBLVIxLmNybDAd
# BgNVHQ4EFgQUUE8krO+1PmMTIwmSJuy6OpbkXSIwDgYDVR0PAQH/BAQDAgeAMA0G
# CSqGSIb3DQEBCwUAA4ICAQCYoI8DAJG8q8RkQX9CIeK/q2wgee5U7sFYgupx9n2U
# nIjKIKaks60nlWdniG+b4Y/a0+46ll2Z9NhZ3LOGE6wNUMsSVt+sowuI5ef27BQm
# lrl8xl7dmOiH6f/wN2dLDUzFk0waG5nHjN7Kp6L3V/U6ERT/tva+ckJz3IEUyNj7
# 61Uqi8WPRMpPf9HL4jN1tvWAZdPNBDW5UXLt2PEbH80bVU/9rJ7g6HEcb0WJndEz
# 2jICI9sSCOudUJz6dYYqvcVNAMqLy827IucJUeSKeIv4vPsfh8GCTXrcuXGLXVie
# 7kD+mGmbVv4zaB6e+qjX7avyJUsesRGAUYxQcR0qtn84VEOaAWsJNjrGdo9MDn+6
# uwKowrerf/n25lo6wFmFmRo/0S45banRTwaSCqnYY1SMWhoM1YWhP8RygYOJOA3x
# WZAWCfQVrj/d05vqWlgQ8FyOxYN2pRrG6BK1j1pb8DAJqXiVI3ii2WNuiTy7fWVn
# Hk1VriMro3q6m+SDJnqiyZuYhav0MuGDxsj4qJcOcNZPTnjuBK5kthSr5NXo78OE
# lkfktVclp5LWOONlmqErcQQglVmXTFhXgfhKS/LqEDatTIUrf7CFI1LnZMmSyGzF
# UI4+2+oD15w+pkvBYFoggIbjNWv4YAPuqNbCVosx3ZnKWA4cjc6K3/SlUROoke63
# JjCCBvwwggTkoAMCAQICEG1SGHCH6CNNhWAA0ICPk1YwDQYJKoZIhvcNAQELBQAw
# fDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9u
# MRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9v
# dCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBSU0EwHhcNMTkxMTEzMTg1MDA1WhcN
# MzQxMTEyMTg1MDA1WjBzMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAO
# BgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wu
# Y29tIFRpbWVzdGFtcGluZyBJc3N1aW5nIFJTQSBDQSBSMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAK5REBPS+TwgoCCF3slQHGTJ4f3F6TT/Cn8xSOhy
# WsVeqGH98Yf3UVz7t+bQwcITsD7CY6KoGP04OskBgareubfeMKcdKwIE1YBBjKhq
# 4urwiOqxLUmVcvb2oM0wx3BnxQ3NBLu9ZkwMnjQlIY2mEwZMgDaqfZuiEa2BFzin
# Xf3kRLKlQ5oa8ne3QU0vcG4qZvphy0xxBQXayqigzN3z2HQTq6N28EOjpnA2dajG
# PtiZ9aNJeDfcDka5j3KbhBkzk4RWCjx5vP8H6DKHIIs02GHgxv/jG8JMIxWY1isG
# +IaB09livKbxlvzhNAKZK5fQmUstrpYrVo7qqXAhJtv1tUaHzrp6QpuUL9dE/bSA
# C7UKO9xhyJSA1OsYWDx/wAmBA84JzX8IJ1olJjCEmlJ2F4o6dCARKA2Zhk+EU4Lo
# gpowBReTlTW2NNwUKAW+8Cte0rhrMBZQ47Vjd92V0gEvouOTMtQJgk2QVeqGwFVw
# 8y4HSdQNa8sl8+Kay2MnyUXhLoQLFaeVaLs4SVXBOe3Ua1Gp5j3J2+8Yue1T4V5w
# rsNuocNR3frpSt4yRIG3N68Bz1qqhk+eNUyO8WpXWlg6POZOJUdm0BzzRsB8V7ks
# t8nM8joOe03KqhunBN69Ckeo8M32qo07zeveRrDwD2P4dmJLDYBflwZ1A/SQbS+H
# N+AHAgMBAAGjggGBMIIBfTASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaA
# FN0ECQei9Xp9UlMSkpXuOIAlDaZZMIGDBggrBgEFBQcBAQR3MHUwUQYIKwYBBQUH
# MAKGRWh0dHA6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5L1NTTGNvbVJvb3RDZXJ0
# aWZpY2F0aW9uQXV0aG9yaXR5UlNBLmNydDAgBggrBgEFBQcwAYYUaHR0cDovL29j
# c3BzLnNzbC5jb20wPwYDVR0gBDgwNjA0BgRVHSAAMCwwKgYIKwYBBQUHAgEWHmh0
# dHBzOi8vd3d3LnNzbC5jb20vcmVwb3NpdG9yeTATBgNVHSUEDDAKBggrBgEFBQcD
# CDA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3Jscy5zc2wuY29tL3NzbC5jb20t
# cnNhLVJvb3RDQS5jcmwwHQYDVR0OBBYEFAydECWOmqcbmYdDzwh+4b2BkPTPMA4G
# A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEAkhl1DaZaQs8ZB9ny/JT6
# wJvwFelEllovcTPdUOUTe5mTdw/E+3JtV8u6ppyLRbpIHbYlMy20KJAychU6xdac
# i4BsP9oVNxSRMsEjfHKz7ARqPNdpclhYAINLjsFGMO1iUNbXiAsnF/xboNCgfeMc
# MYbLyQYkU6UMobv9isrtQZ8e0EAQNV7qXJn4W0KyuTt0P8iIv/5DdDpIUBIktDZc
# jz2KEW6B1gvvsKIM1esjYwWylAazBcQAake5pANMdSn8t1HdPKsiwuWfOguyRQaz
# AX8oXz6SlZSIok0Lis9a02vGVtdhEaB0R3HxIyNRMMKWV1yuSeUXFuoexWav3GRP
# ZC0WYb50SrW/l+wgrS8doetaMwyZon2L7ioYlIPSy1h9Dq/Q911PsSkbEZ3zrsB1
# roVnIfBu5BJp0xvQrQ/Q4LavuvCoFR7QFoypNrotbNYi2AGMZw5td4zGZtCqUTPZ
# i0BwSuRm+HRYAEMMThTwbJX/fYV1oC8mBN970yIvadIGKhh7+DmYdRJYBrL8inVF
# CZAK+YX2w1+qWEnCSPL/VTWJtSRMhQFfceDKbJC+pBNksvKzqkva0J1ZyMj1i4vD
# fSuBmbz4rfzsvvJxS+quZDdkmW6MeXevWGBXvqzdbAw+AqTVsAQUyP6tFeKZIL4S
# /fSFdl2rIx2X+KXkqx3S+EYxggJYMIICVAIBATCBhzBzMQswCQYDVQQGEwJVUzEO
# MAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBD
# b3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFtcGluZyBJc3N1aW5nIFJTQSBD
# QSBSMQIQWlqs6Bo1brRiho1XfeA9xzALBglghkgBZQMEAgGgggFhMBoGCSqGSIb3
# DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjQxMTEyMjEyODE0
# WjAoBgkqhkiG9w0BCTQxGzAZMAsGCWCGSAFlAwQCAaEKBggqhkjOPQQDAjAvBgkq
# hkiG9w0BCQQxIgQgC1tLQbY4Ib5D8g0QOS6deys3uUWgI3PfCOqhRBFGYwIwgckG
# CyqGSIb3DQEJEAIvMYG5MIG2MIGzMIGwBCCdcX+Nwjdlqs5eSrDh9XXXmhfUHO7Y
# /a/vA/09vYlH5zCBizB3pHUwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFz
# MRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwm
# U1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEFparOgaNW60
# YoaNV33gPccwCgYIKoZIzj0EAwIERzBFAiEAmTXIpXQXw+EAgP++yTOyFKCtVk7+
# JsEtQ1JBHK627AICIGhonENPf8RKen7r+80o78/UZGO7i384mwF/d5uhUBZI
# SIG # End signature block

