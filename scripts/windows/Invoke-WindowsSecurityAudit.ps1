<#
.SYNOPSIS
Collects a defensive Windows security baseline and writes a JSON report.

.DESCRIPTION
This script gathers common enterprise security posture signals from a local
Windows host. It does not change system configuration.

Run from an elevated PowerShell session for complete results.

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes

.EXAMPLE
.\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\reports\windows-security-audit-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMdd-HHmmss').json",
    [switch]$IncludeHotfixes,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Safe {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [object]$Default = $null
    )

    try {
        & $ScriptBlock
    }
    catch {
        $Default
    }
}

function New-ParentDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $parent = Split-Path -Path $Path -Parent
    if ($parent -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    Invoke-Safe -ScriptBlock {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $item.$Name
    } -Default $null
}

function Get-LocalAdministratorsSafe {
    $members = Invoke-Safe -ScriptBlock {
        Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
            [ordered]@{
                Name        = $_.Name
                ObjectClass = $_.ObjectClass
                PrincipalSource = $_.PrincipalSource
            }
        }
    } -Default $null

    if ($members) {
        return $members
    }

    $raw = Invoke-Safe -ScriptBlock { net localgroup Administrators } -Default @()
    return @($raw | Where-Object { $_ -and $_ -notmatch "command completed|---|Alias name|Comment|Members" })
}

function Get-ListeningPortsSafe {
    Invoke-Safe -ScriptBlock {
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort, LocalAddress | ForEach-Object {
            $connection = $_
            $processName = Invoke-Safe -ScriptBlock {
                (Get-Process -Id $connection.OwningProcess -ErrorAction Stop).ProcessName
            } -Default "unknown"

            [ordered]@{
                LocalAddress = $connection.LocalAddress
                LocalPort    = $connection.LocalPort
                ProcessId    = $connection.OwningProcess
                ProcessName  = $processName
            }
        }
    } -Default @()
}

function Get-PasswordPolicySafe {
    $lines = Invoke-Safe -ScriptBlock { net accounts } -Default @()
    $policy = [ordered]@{}

    foreach ($line in $lines) {
        if ($line -match "^(.+?):\s+(.+)$") {
            $key = ($Matches[1] -replace "\s+", " ").Trim()
            $value = $Matches[2].Trim()
            $policy[$key] = $value
        }
    }

    return $policy
}

function Get-AuditPolicySafe {
    $csv = Invoke-Safe -ScriptBlock { auditpol /get /category:* /r } -Default @()
    if (-not $csv) {
        return @()
    }

    Invoke-Safe -ScriptBlock {
        $csv | ConvertFrom-Csv
    } -Default $csv
}

function Get-SecurityServiceState {
    $serviceNames = @(
        "WinDefend",
        "MpsSvc",
        "wuauserv",
        "BITS",
        "EventLog",
        "WinRM",
        "LanmanServer",
        "LanmanWorkstation"
    )

    foreach ($name in $serviceNames) {
        Invoke-Safe -ScriptBlock {
            $svc = Get-Service -Name $name -ErrorAction Stop
            [ordered]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status.ToString()
                StartType   = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'").StartMode
            }
        } -Default ([ordered]@{
            Name = $name
            DisplayName = $null
            Status = "NotFound"
            StartType = $null
        })
    }
}

$os = Invoke-Safe -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem } -Default $null
$computer = Invoke-Safe -ScriptBlock { Get-CimInstance -ClassName Win32_ComputerSystem } -Default $null

$audit = [ordered]@{
    ReportMetadata = [ordered]@{
        ComputerName      = $env:COMPUTERNAME
        GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString("o")
        User              = "$env:USERDOMAIN\$env:USERNAME"
        IsAdministrator   = Test-IsAdministrator
        ScriptName        = $MyInvocation.MyCommand.Name
    }
    OperatingSystem = [ordered]@{
        Caption          = if ($os) { $os.Caption } else { $null }
        Version          = if ($os) { $os.Version } else { $null }
        BuildNumber      = if ($os) { $os.BuildNumber } else { $null }
        InstallDate      = if ($os) { $os.InstallDate } else { $null }
        LastBootUpTime   = if ($os) { $os.LastBootUpTime } else { $null }
        Domain           = if ($computer) { $computer.Domain } else { $null }
        Manufacturer     = if ($computer) { $computer.Manufacturer } else { $null }
        Model            = if ($computer) { $computer.Model } else { $null }
    }
    FirewallProfiles = Invoke-Safe -ScriptBlock {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, NotifyOnListen
    } -Default @()
    Defender = Invoke-Safe -ScriptBlock {
        Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, AntivirusSignatureLastUpdated
    } -Default $null
    LocalAdministrators = @(Get-LocalAdministratorsSafe)
    PasswordPolicy = Get-PasswordPolicySafe
    AuditPolicy = @(Get-AuditPolicySafe)
    SecurityServices = @(Get-SecurityServiceState)
    ListeningTcpPorts = @(Get-ListeningPortsSafe)
    RemoteAccess = [ordered]@{
        RdpDenyConnections = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        RdpNlaRequired = Get-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        WinRmService = Invoke-Safe -ScriptBlock { (Get-Service -Name WinRM).Status.ToString() } -Default "Unknown"
    }
    CoreSettings = [ordered]@{
        Smb1ServerEnabled = Invoke-Safe -ScriptBlock { (Get-SmbServerConfiguration).EnableSMB1Protocol } -Default $null
        UacEnabled = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
        LlmnrEnabledPolicy = Get-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    BitLocker = Invoke-Safe -ScriptBlock {
        Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod
    } -Default @()
}

if ($IncludeHotfixes) {
    $audit["Hotfixes"] = @(Invoke-Safe -ScriptBlock {
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 60 HotFixID, Description, InstalledBy, InstalledOn
    } -Default @())
}

New-ParentDirectory -Path $OutputPath
$audit | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutputPath -Encoding utf8

if (-not $Quiet) {
    Write-Host "Windows security audit written to: $OutputPath"
    Write-Host "Computer: $env:COMPUTERNAME"
    Write-Host "Administrator: $(Test-IsAdministrator)"
    Write-Host "Listening TCP ports: $(@($audit.ListeningTcpPorts).Count)"
    Write-Host "Local administrators: $(@($audit.LocalAdministrators).Count)"
}
